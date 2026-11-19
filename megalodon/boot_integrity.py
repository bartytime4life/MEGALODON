"""Boot integrity: the kernel, initramfs, bootloader and the settings that start them.

The program-integrity check trusts the package database, but much of what boots
the machine is built on it: the initramfs, the GRUB configuration, the EFI
bootloader copies. A backdoored initramfs or bootloader runs before every
defense (ATT&CK T1542, T1547.006). `megalodon boot` records the boot files and
the kernel's boot-time protections and reports what changes:

* packaged boot files (kernels) are checked against the package database;
* other changes are matched against package-manager activity at that time, so
  an initramfs rebuilt by a kernel update is told apart from one changed with
  no update anywhere near it;
* the running kernel's command line, Secure Boot, kernel lockdown, module
  signature enforcement and module loading are compared with the baseline,
  and parameters that switch protections off are rated HIGH.

Read-only.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

SCHEMA = 'megalodon-boot-integrity-v1'
REPORT_SCHEMA = 'megalodon-boot-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/boot.json'
MAX_FILES = 20000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
FOLDERS = ('/boot', '/etc/grub.d', '/etc/kernel', '/etc/initramfs-tools', '/etc/dracut.conf.d', '/etc/mkinitcpio.d')
FILES = ('/etc/default/grub', '/etc/dracut.conf', '/etc/mkinitcpio.conf')
PACKAGE_LOGS = ('/var/log/dpkg.log', '/var/log/dnf.rpm.log', '/var/log/pacman.log', '/var/log/yum.log')
EXPLAIN_BEFORE = timedelta(minutes=30)
EXPLAIN_AFTER = timedelta(minutes=5)
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
SECURE_BOOT_VAR = 'sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
LOCKDOWN_ORDER = ('none', 'integrity', 'confidentiality')
# Kernel parameters that switch a protection off or hand the boot to something else.
# A parameter stands alone, or at either end of a quoted value such as GRUB_CMDLINE_LINUX="audit=0".
WEAKENING = re.compile(r'(?:^|[\s"\'])(init=[^\s"\']+|rd\.break[^\s"\']*|single|emergency|module\.sig_enforce=0|'
                       r'lockdown=none|apparmor=0|selinux=0|enforcing=0|security=none|audit=0|ima_appraise=off|'
                       r'efi=disable_early_pci_dma[^\s"\']*|nokaslr|mitigations=off|lsm=[^\s"\']*)(?=[\s"\']|$)')
# Kernel protections that, once readable, should stay readable: losing sight of one is reported.
OBSERVED = (('secure_boot', 'Secure Boot'), ('lockdown', 'kernel lockdown'),
            ('sig_enforce', 'module-signature enforcement'), ('modules_disabled', 'the module-loading switch'),
            ('cmdline', 'the kernel command line'))

RULES = {
    'BOOT_PACKAGE_MISMATCH': ('CRITICAL', ['T1542'], 'A packaged boot file, such as a kernel, no longer matches '
                                                     'the package database: it was modified after installation.'),
    'SECURE_BOOT_DISABLED': ('HIGH', ['T1542', 'T1553.006'], 'Secure Boot was on and is now off.'),
    'LOCKDOWN_WEAKENED': ('HIGH', ['T1014'], 'Kernel lockdown is weaker than before.'),
    'MODULE_SIGNATURES_OFF': ('HIGH', ['T1547.006'], 'The kernel enforced module signatures and no longer does.'),
    'CMDLINE_WEAKENED': ('HIGH', ['T1542', 'T1562.001'], 'The kernel now boots with a parameter that switches a '
                                                         'protection off or replaces the first program it runs.'),
    'BOOT_FILE_CHANGED': ('HIGH', ['T1542'], 'A boot file changed with no package update near that time.'),
    'BOOT_FILE_ADDED': ('HIGH', ['T1542'], 'A new boot file appeared with no package update near that time.'),
    'BOOT_CONFIG_CHANGED': ('MEDIUM', ['T1542'], 'Bootloader or initramfs configuration changed with no package '
                                                 'update near that time.'),
    'CMDLINE_CHANGED': ('MEDIUM', ['T1542'], 'The running kernel\'s command line changed.'),
    'BOOT_FILE_REMOVED': ('MEDIUM', ['T1542'], 'A recorded boot file was removed.'),
    'BOOT_UPDATED': ('LOW', ['T1542'], 'A boot file changed while the package manager was installing updates, as '
                                       'kernel and bootloader updates do.'),
}


class BootError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _under(root, path):
    return path if root == '/' else os.path.join(root, path.lstrip('/'))


def _shown(root, real):
    return real if root == '/' else '/' + os.path.relpath(real, root)


def _text(path):
    try:
        with open(path, 'rb') as handle:
            return handle.read(65536).decode('utf-8', 'replace').strip()
    except OSError:
        return None


def _sha256(path):
    digest, read = hashlib.sha256(), 0
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None, None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, None
        md5 = hashlib.md5(usedforsecurity=False)
        while read <= MAX_FILE_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            md5.update(chunk)
            read += len(chunk)
    finally:
        os.close(fd)
    return (digest.hexdigest(), md5.hexdigest()) if read <= MAX_FILE_BYTES else (None, None)


# ------------------------------------------------------------------ what is recorded

def kernel_state(root='/'):
    secure = None
    raw = None
    try:
        with open(_under(root, '/' + SECURE_BOOT_VAR), 'rb') as handle:
            raw = handle.read(8)
    except OSError:
        pass
    if raw and len(raw) >= 5:
        secure = bool(raw[4])            # 4 bytes of attributes, then the value
    lockdown = _text(_under(root, '/sys/kernel/security/lockdown'))
    if lockdown:
        found = re.search(r'\[(\w+)\]', lockdown)
        lockdown = found.group(1) if found else lockdown
    return dict(cmdline=_text(_under(root, '/proc/cmdline')),
                efi=os.path.isdir(_under(root, '/sys/firmware/efi')), secure_boot=secure, lockdown=lockdown,
                sig_enforce=_text(_under(root, '/sys/module/module/parameters/sig_enforce')),
                modules_disabled=_text(_under(root, '/proc/sys/kernel/modules_disabled')))


def _package_md5s(root='/'):
    """{'/boot/...': md5} for boot files the package database lists."""
    found = {}
    for path in glob.glob(_under(root, '/var/lib/dpkg/info/*.md5sums')):
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    digest, _, name = line.strip().partition('  ')
                    if name.startswith('boot/'):
                        found['/' + name] = digest
        except OSError:
            continue
    return found


def snapshot(*, root='/'):
    files, gaps, seen = {}, [], 0
    real_root = os.path.realpath(root)
    candidates = [_under(real_root, f) for f in FILES]
    for folder in FOLDERS:
        base = _under(real_root, folder)
        for current, dirs, names in os.walk(base):
            dirs.sort()
            for name in sorted(names):
                candidates.append(os.path.join(current, name))
    for path in candidates:
        if seen >= MAX_FILES:
            gaps.append(f'only the first {MAX_FILES} boot files were recorded')
            break
        try:
            info = os.lstat(path)
        except OSError:
            continue
        seen += 1
        shown = _shown(real_root, path)
        if stat.S_ISLNK(info.st_mode):
            files[shown] = dict(link=os.readlink(path), mtime=int(info.st_mtime), ctime=int(info.st_ctime))
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        digest, md5 = _sha256(path)
        if digest is None:
            gaps.append(f'{shown} could not be read' + ('; run as root' if os.geteuid() else ''))
            continue
        files[shown] = dict(sha256=digest, md5=md5, size=info.st_size, mtime=int(info.st_mtime),
                            ctime=int(info.st_ctime), mode=oct(stat.S_IMODE(info.st_mode)))
    if not os.path.isdir(_under(real_root, '/boot')) or not any(k.startswith('/boot/') for k in files):
        gaps.append('there are no boot files in /boot here (a container or a machine booted another way)')
    return dict(files=files, kernel=kernel_state(real_root), gaps=gaps)


# ------------------------------------------------------------------ package-manager activity

_DPKG = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ')
_ISO = re.compile(r'^\[?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})([+-]\d{4}|Z)?')


def package_activity(root='/'):
    """Times the package manager was installing or configuring anything, from its logs."""
    times = []
    for log in PACKAGE_LOGS:
        try:
            with open(_under(root, log), encoding='utf-8', errors='replace') as handle:
                lines = handle.readlines()[-200000:]
        except OSError:
            continue
        for line in lines:
            match = _DPKG.match(line)
            if match:
                times.append(datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S').astimezone())
                continue
            match = _ISO.match(line)
            if match:
                stamp = datetime.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S')
                zone = match.group(2)
                if zone and zone != 'Z':
                    offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[3:5])) * (1 if zone[0] == '+' else -1)
                    stamp = stamp.replace(tzinfo=timezone(offset))
                else:
                    stamp = stamp.replace(tzinfo=timezone.utc) if zone else stamp.astimezone()
                times.append(stamp)
    return sorted(times)


def _explained(moment, activity):
    """The package activity time that explains a change at `moment`, or None."""
    for when in activity:
        if moment - EXPLAIN_BEFORE <= when <= moment + EXPLAIN_AFTER:
            return when
    return None


# ------------------------------------------------------------------ baseline and check

def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.boot-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise BootError(f'no boot baseline at {path}; run megalodon boot baseline') from None
    except OSError as exc:
        raise BootError(f'boot baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise BootError(f'boot baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise BootError('boot baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('files')) is not dict:
        raise BootError('boot baseline has an unsupported format')
    return value


def _finding(rule, subject, detail, **extra):
    severity, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


def _is_config(path):
    return path.startswith('/etc/') or path.endswith(('grub.cfg', '.conf', 'grubenv'))


def _weakening(text):
    return sorted(set(m.group(1) for m in WEAKENING.finditer(text or '')))


def compare(old, new, *, activity=(), packaged=None):
    """(findings, explained): changes no update explains, and those the package manager made."""
    findings, explained = [], []
    packaged = packaged or {}
    for path in sorted(set(old['files']) | set(new['files'])):
        before, after = old['files'].get(path), new['files'].get(path)
        if after is not None and path in packaged and after.get('md5') and after['md5'] != packaged[path]:
            findings.append(_finding('BOOT_PACKAGE_MISMATCH', path, f'{path} does not match its package'))
            continue
        if before == after or (before and after and before.get('sha256') == after.get('sha256')
                               and before.get('link') == after.get('link')):
            continue
        if after is None:
            findings.append(_finding('BOOT_FILE_REMOVED', path, f'{path} was removed'))
            continue
        # The change time, which unlike the modification time cannot be set to match an update.
        moment = datetime.fromtimestamp(after.get('ctime', after['mtime']), timezone.utc)
        reason = _explained(moment, activity)
        if reason is not None or (path in packaged and after.get('md5') == packaged[path]):
            why = (f'package activity at {_iso(reason)}' if reason else 'it matches its package')
            explained.append(_finding('BOOT_UPDATED', path, f'{path} {"changed" if before else "appeared"}; '
                                                            f'explained by {why}', explained_by=why))
        else:
            rule = 'BOOT_CONFIG_CHANGED' if _is_config(path) else ('BOOT_FILE_CHANGED' if before else 'BOOT_FILE_ADDED')
            findings.append(_finding(rule, path, f'{path} {"changed" if before else "appeared"} at {_iso(moment)} '
                                                 'with no package update near that time'))
        if path.endswith(('grub.cfg', '/etc/default/grub', '/etc/kernel/cmdline')) or '/loader/entries/' in path:
            text = _text(_under(new.get('root', '/'), path)) or ''
            added = sorted(set(_weakening(text)) - set(old.get('weakening', {}).get(path, [])))
            if added:
                findings.append(_finding('CMDLINE_WEAKENED', path, f'{path} now sets {", ".join(added)}',
                                         parameters=added))
    was, now = old.get('kernel', {}), new['kernel']
    if was.get('cmdline') and now.get('cmdline') and was['cmdline'] != now['cmdline']:
        added = sorted(set(_weakening(now['cmdline'])) - set(_weakening(was['cmdline'])))
        if added:
            findings.append(_finding('CMDLINE_WEAKENED', 'kernel:cmdline',
                                     f'the running kernel booted with {", ".join(added)}', parameters=added))
        else:
            findings.append(_finding('CMDLINE_CHANGED', 'kernel:cmdline', 'the running kernel\'s command line changed',
                                     before=was['cmdline'][:512], after=now['cmdline'][:512]))
    if was.get('secure_boot') is True and now.get('secure_boot') is False:
        findings.append(_finding('SECURE_BOOT_DISABLED', 'kernel:secure_boot', 'Secure Boot is now off'))
    if was.get('lockdown') in LOCKDOWN_ORDER and now.get('lockdown') in LOCKDOWN_ORDER and \
            LOCKDOWN_ORDER.index(now['lockdown']) < LOCKDOWN_ORDER.index(was['lockdown']):
        findings.append(_finding('LOCKDOWN_WEAKENED', 'kernel:lockdown',
                                 f'kernel lockdown went from {was["lockdown"]} to {now["lockdown"]}'))
    if was.get('sig_enforce') == 'Y' and now.get('sig_enforce') == 'N':
        findings.append(_finding('MODULE_SIGNATURES_OFF', 'kernel:sig_enforce',
                                 'the kernel no longer enforces module signatures'))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return findings, explained


def lost_protections(was, now):
    """Gaps for protections the baseline could read and this check cannot: they can no longer be compared."""
    gaps = []
    for key, name in OBSERVED:
        if was.get(key) not in (None, '') and now.get(key) in (None, ''):
            gaps.append(f'{name} was recorded as {was[key]!r} but can no longer be read, so it was not compared'
                        + ('; run as root' if os.geteuid() else ''))
    return gaps


def _weakening_by_file(root, files):
    out = {}
    for path in files:
        if path.endswith(('grub.cfg', '/etc/default/grub', '/etc/kernel/cmdline')) or '/loader/entries/' in path:
            found = _weakening(_text(_under(root, path)))
            if found:
                out[path] = found
    return out


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, root='/'):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise BootError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(root=root)
    packaged = _package_md5s(root)
    mismatched = [_finding('BOOT_PACKAGE_MISMATCH', p, f'{p} does not match its package')
                  for p, entry in sorted(state['files'].items())
                  if p in packaged and entry.get('md5') and entry['md5'] != packaged[p]]
    _write(path, dict(schema=SCHEMA, recorded_at=_iso(_now()), root=os.path.realpath(root),
                      weakening=_weakening_by_file(os.path.realpath(root), state['files']), **state))
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), files=len(state['files']),
                kernel=state['kernel'], findings=mismatched, gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, *, root=None):
    old = _read(manifest)
    root = root or old.get('root', '/')
    new = dict(snapshot(root=root), root=os.path.realpath(root))
    findings, explained = compare(old, new, activity=package_activity(root), packaged=_package_md5s(root))
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_iso(_now()), findings=findings,
                explained=explained,
                kernel=new['kernel'], gaps=new['gaps'] + lost_protections(old.get('kernel', {}), new['kernel']),
                note='After a reviewed kernel or bootloader update, `megalodon boot accept` records the new state.')


def accept(manifest=DEFAULT_MANIFEST, *, root=None):
    old = _read(manifest)
    return dict(baseline(manifest, replace=True, root=root or old.get('root', '/')), action='accept')
