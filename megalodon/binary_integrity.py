"""Detect trojaned system programs and libraries.

An attacker with root can replace ``sshd``, ``sudo``, ``ps`` or ``ls`` with a
backdoored copy, or a PAM module or ``libkeyutils`` with one that steals
passwords, and every other tool would keep trusting them. Two checks find
that:

* ``megalodon binaries verify`` needs no baseline. It compares every installed
  program, and the libraries attackers usually backdoor, with the checksums
  their Debian package recorded (``/var/lib/dpkg/info/*.md5sums``), as
  ``dpkg --verify`` does. A machine that was trojaned before MEGALODON ever ran
  is caught on the first run.
* ``megalodon binaries baseline`` / ``check`` / ``accept`` also record a
  SHA-256 of every program, packaged or not. ``check`` then reports
  unpackaged programs that appear or change, and a program that changed
  together with its package's checksum record without a package upgrade:
  the way to hide from the first check.

Findings:

* ``PACKAGE_MISMATCH`` (T1554; T1014 for tools used to look at the system):
  a packaged file no longer matches its package. CRITICAL for login, SSH,
  sudo, PAM, the loader and the process and file listing tools; HIGH otherwise.
* ``PACKAGE_RECORD_CHANGED`` (T1554): the file and its package's checksum
  record both changed, but the package was not upgraded.
* ``PROGRAM_ADDED`` (T1036.005): an unpackaged program appeared in a system
  program folder (HIGH) or under ``/usr/local`` (MEDIUM).
* ``PROGRAM_CHANGED`` (T1554): an unpackaged program's content changed.
* ``PROGRAM_WRITABLE`` (T1574.010): a program is writable by everyone, or is
  not owned by root.
* ``PACKAGE_FILE_MISSING`` (LOW): a packaged program was removed.

Only metadata and digests are kept. Nothing is changed, removed or restored.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import glob
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

SCHEMA = 'megalodon-binary-manifest-v1'
REPORT_SCHEMA = 'megalodon-binary-check-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/binaries.json'
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_FILES = 200_000
MAX_DB_FILE_BYTES = 64 * 1024 * 1024
RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

# Folders whose programs are recorded, packaged or not (/bin and /sbin are
# often links to /usr; real paths are compared, so each file counts once).
PROGRAM_DIRS = ('/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/usr/local/sbin')
DEEP_DIRS = ('/usr/libexec', '/usr/local/libexec')
PAM_DIRS = ('/usr/lib/*/security', '/lib/*/security', '/usr/lib/security', '/lib/security', '/lib64/security',
            '/usr/lib64/security')
LOCAL_PREFIXES = ('/usr/local/',)
# Packaged files under these are verified when they are programs.
PACKAGED_PREFIXES = ('/usr/', '/bin/', '/sbin/', '/lib/', '/lib64/', '/opt/')
# Libraries backdoors commonly replace (loader, libc, PAM, crypto, keyutils
# as in Ebury, liblzma as in the xz backdoor), verified even without --all-libraries.
CRITICAL_LIBRARIES = ('ld-linux*.so*', 'ld-*.so*', 'libc.so*', 'libpam*.so*', 'libkeyutils.so*', 'libcrypt.so*',
                      'libnss_*.so*', 'libaudit.so*', 'libselinux.so*', 'libsystemd.so*', 'libcrypto.so*',
                      'libssl.so*', 'liblzma.so*', 'libgssapi*.so*', 'libkrb5*.so*', 'libwrap.so*', 'libutil.so*',
                      'libdl.so*', 'libpthread.so*')
# Programs whose compromise gives an attacker logins or hides them.
CRITICAL_PROGRAMS = frozenset({
    'sshd', 'sshd-session', 'sshd-auth', 'ssh', 'sudo', 'su', 'login', 'passwd', 'chsh', 'chfn', 'newgrp',
    'gpasswd', 'unix_chkpwd', 'pkexec', 'polkitd', 'cron', 'crond', 'systemd', 'init', 'bash', 'sh', 'dash',
    'ps', 'ls', 'netstat', 'ss', 'lsof', 'top', 'htop', 'find', 'who', 'w', 'last', 'lastlog', 'pstree',
    'pgrep', 'pkill', 'kill', 'du', 'df', 'stat', 'ip', 'ifconfig', 'strings', 'ldd', 'md5sum', 'sha256sum',
    'dpkg', 'rpm', 'tcpdump', 'iptables', 'nft', 'auditctl', 'journalctl', 'rsyslogd', 'busybox'})
# Tools used to look at a system: replacing them is how a user-space rootkit hides.
LOOKING_TOOLS = frozenset({'ps', 'ls', 'netstat', 'ss', 'lsof', 'top', 'htop', 'find', 'who', 'w', 'last',
                           'lastlog', 'pstree', 'pgrep', 'du', 'df', 'stat', 'ip', 'ifconfig', 'strings',
                           'md5sum', 'sha256sum', 'tcpdump', 'journalctl'})
TECHNIQUE = dict(PACKAGE_MISMATCH='T1554', PACKAGE_RECORD_CHANGED='T1554', PROGRAM_ADDED='T1036.005',
                 PROGRAM_CHANGED='T1554', PROGRAM_WRITABLE='T1574.010', PACKAGE_FILE_MISSING='T1554')


class BinaryIntegrityError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class _Paths:
    """Map between displayed absolute paths and paths under a test root."""

    def __init__(self, root):
        self.root = os.path.realpath(root)

    def real(self, path):
        joined = path if self.root == '/' else os.path.join(self.root, path.lstrip('/'))
        return os.path.realpath(joined)

    def shown(self, real):
        return real if self.root == '/' else '/' + os.path.relpath(real, self.root)


def _read_small(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError('not a regular file')
        data = os.read(fd, MAX_DB_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_DB_FILE_BYTES:
        raise OSError('too large')
    return data.decode('utf-8', 'replace')


def _packages(paths):
    """Installed dpkg packages: {name or name:arch: 'name version'}, or None without a dpkg database."""
    status = paths.real('/var/lib/dpkg/status')
    try:
        text = _read_small(status)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BinaryIntegrityError(f'the dpkg status database cannot be read: {exc}') from None
    installed = {}
    for stanza in text.split('\n\n'):
        fields = {}
        for line in stanza.splitlines():
            if line[:1] not in (' ', '\t') and ':' in line:
                key, _, value = line.partition(':')
                fields[key.strip()] = value.strip()
        if not fields.get('Package') or not fields.get('Status', '').endswith(' installed'):
            continue
        label = f"{fields['Package']} {fields.get('Version', '?')}"
        installed[fields['Package']] = label
        if fields.get('Architecture'):
            installed[f"{fields['Package']}:{fields['Architecture']}"] = label
    return installed


def _diversions(paths):
    """{original path: (diverted-to path, diverting package)} from dpkg's diversion list."""
    try:
        lines = _read_small(paths.real('/var/lib/dpkg/diversions')).splitlines()
    except OSError:
        return {}
    return {lines[i]: (lines[i + 1], lines[i + 2]) for i in range(0, len(lines) - 2, 3)}


def _wanted(real, shown, mode, all_libraries):
    if not shown.startswith(PACKAGED_PREFIXES) or not stat.S_ISREG(mode):
        return False
    name = shown.rsplit('/', 1)[-1]
    if '.so' in name:
        return (all_libraries or '/security/' in shown and name.endswith('.so')
                or any(fnmatch.fnmatch(name, pattern) for pattern in CRITICAL_LIBRARIES))
    return bool(mode & 0o111)


def _missing_matters(shown):
    folder, _, name = shown.rpartition('/')
    return (folder in PROGRAM_DIRS or shown.startswith(tuple(d + '/' for d in DEEP_DIRS))
            or ('.so' in name and ('/security/' in shown
                                   or any(fnmatch.fnmatch(name, pattern) for pattern in CRITICAL_LIBRARIES))))


def _package_files(paths, installed, all_libraries, gaps):
    """{real path: {'md5': {...}, 'package': label}} for packaged files in scope."""
    expected: dict[str, dict] = {}
    diversions = _diversions(paths)
    info = paths.real('/var/lib/dpkg/info')
    unread = 0
    for path in sorted(glob.glob(os.path.join(glob.escape(info), '*.md5sums'))):
        package = os.path.basename(path)[:-len('.md5sums')]
        label = installed.get(package)
        if label is None:
            continue  # Left over from a removed package.
        try:
            lines = _read_small(path).splitlines()
        except OSError:
            unread += 1
            continue
        owner = package.split(':', 1)[0]
        for line in lines:
            digest, _, name = line.partition('  ')
            if len(digest) != 32 or not name:
                continue
            original = '/' + name.lstrip('/')
            target = original
            if original in diversions and diversions[original][1] not in (owner, package):
                target = diversions[original][0]  # Another package diverted this file away.
            real = paths.real(target)
            try:
                mode = os.lstat(real).st_mode
            except FileNotFoundError:
                # Only a missing program or critical library matters: images often strip documentation.
                if _missing_matters(paths.shown(real)):
                    entry = expected.setdefault(real, dict(md5=set(), package=label, missing=True))
                    entry['md5'].add(digest.lower())
                continue
            except OSError:
                continue
            if not _wanted(real, paths.shown(real), mode, all_libraries):
                continue
            entry = expected.setdefault(real, dict(md5=set(), package=label, missing=False))
            entry['md5'].add(digest.lower())
            entry['missing'] = False
    if unread:
        gaps.append(f'{unread} package checksum lists could not be read')
    return expected


class _Budget:
    def __init__(self):
        self.bytes = self.files = 0


def _hash(real, budget):
    """(md5, sha256, size, mode, uid) of a regular file, without following a final link; None if unreadable."""
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            return None
        if budget.bytes + info.st_size > MAX_TOTAL_BYTES or budget.files >= MAX_FILES:
            return 'budget'
        md5, sha256, size = hashlib.md5(usedforsecurity=False), hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
        budget.bytes += size
        budget.files += 1
        return md5.hexdigest(), sha256.hexdigest(), size, stat.S_IMODE(info.st_mode), info.st_uid
    finally:
        os.close(fd)


def _scanned(paths):
    """Real paths of every regular program file in the program folders, packaged or not."""
    found = set()
    for folder in PROGRAM_DIRS:
        base = paths.real(folder)
        try:
            entries = list(os.scandir(base))
        except OSError:
            continue
        for entry in entries:
            if entry.is_file(follow_symlinks=False):
                try:
                    if entry.stat(follow_symlinks=False).st_mode & 0o111:
                        found.add(os.path.realpath(entry.path))
                except OSError:
                    continue
    for folder in DEEP_DIRS:
        base = paths.real(folder)
        for directory, _, files in os.walk(base):
            if directory.count(os.sep) - base.count(os.sep) > 4:
                continue
            for name in files:
                path = os.path.join(directory, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111:
                    found.add(os.path.realpath(path))
    for pattern in PAM_DIRS:
        for folder in glob.glob(paths.real(pattern) if paths.root == '/' else
                                os.path.join(glob.escape(paths.root), pattern.lstrip('/'))):
            for path in glob.glob(os.path.join(glob.escape(folder), '*.so')):
                if os.path.isfile(path) and not os.path.islink(path):
                    found.add(os.path.realpath(path))
    return found


def _severity(shown, rule):
    name = shown.rsplit('/', 1)[-1]
    critical = (name in CRITICAL_PROGRAMS or '/security/' in shown
                or any(fnmatch.fnmatch(name, pattern) for pattern in CRITICAL_LIBRARIES))
    if rule == 'PACKAGE_MISMATCH':
        return 'CRITICAL' if critical else 'HIGH'
    if rule == 'PROGRAM_ADDED':
        return 'MEDIUM' if shown.startswith(LOCAL_PREFIXES) else 'HIGH'
    return dict(PACKAGE_RECORD_CHANGED='HIGH', PROGRAM_CHANGED='MEDIUM', PROGRAM_WRITABLE='HIGH',
                PACKAGE_FILE_MISSING='LOW')[rule]


def _finding(rule, shown, detail=None):
    techniques = [TECHNIQUE[rule]]
    if rule in ('PACKAGE_MISMATCH', 'PACKAGE_RECORD_CHANGED', 'PROGRAM_CHANGED') and \
            shown.rsplit('/', 1)[-1] in LOOKING_TOOLS:
        techniques.append('T1014')
    item = dict(rule_id=rule, severity=_severity(shown, rule), path=shown, techniques=techniques)
    if detail:
        item['detail'] = detail
    return item


def snapshot(*, root='/', all_libraries=False, owner_uid=0):
    """Every program in scope with its digests, package and permissions, plus package verification findings."""
    paths = _Paths(root)
    gaps: list[str] = []
    installed = _packages(paths)
    expected = {} if installed is None else _package_files(paths, installed, all_libraries, gaps)
    if installed is None:
        gaps.append('no dpkg database: packaged programs are not verified (on RPM systems, use rpm -Va)')
    budget = _Budget()
    files, findings, unreadable, skipped = {}, [], 0, 0
    for real in sorted(set(expected) | _scanned(paths)):
        shown = paths.shown(real)
        record = expected.get(real)
        if record and record['missing']:
            findings.append(_finding('PACKAGE_FILE_MISSING', shown, dict(package=record['package'])))
            continue
        result = _hash(real, budget)
        if result is None:
            unreadable += 1
            continue
        if result == 'budget':
            skipped += 1
            continue
        md5, sha256, size, mode, uid = result
        entry = dict(sha256=sha256, size=size, mode=oct(mode), uid=uid)
        if record:
            entry['package'] = record['package']
            entry['package_md5'] = sorted(record['md5'])
            if md5 not in record['md5']:
                findings.append(_finding('PACKAGE_MISMATCH', shown, dict(package=record['package'])))
        if mode & 0o002 or uid != owner_uid:
            findings.append(_finding('PROGRAM_WRITABLE', shown, dict(mode=oct(mode), uid=uid)))
        files[shown] = entry
    if unreadable:
        gaps.append(f'{unreadable} programs could not be read; run as root to cover them')
    if skipped:
        gaps.append(f'{skipped} programs were not hashed: the scan limit was reached')
    packaged = sum(1 for e in files.values() if 'package' in e)
    return dict(files=files, findings=findings, gaps=gaps, packaged=packaged)


def _sorted(findings):
    return sorted(findings, key=lambda f: (-RANK[f['severity']], f['rule_id'], f['path']))


def verify(*, root='/', all_libraries=False, owner_uid=0):
    """Package verification now; no baseline needed."""
    state = snapshot(root=root, all_libraries=all_libraries, owner_uid=owner_uid)
    findings = _sorted(state['findings'])
    return dict(schema=REPORT_SCHEMA, action='verify', checked_at=_now(), files=len(state['files']),
                packaged=state['packaged'], findings=findings, gaps=state['gaps'],
                severity_counts={level: sum(1 for f in findings if f['severity'] == level) for level in RANK},
                note='A package checksum record can be edited by root too; baseline and check catch that.')


def compare(old, new):
    findings, updated = list(new['findings']), []
    reported = {(f['rule_id'], f['path']) for f in findings}
    for shown in sorted(set(old['files']) | set(new['files'])):
        before, after = old['files'].get(shown), new['files'].get(shown)
        if after is None:
            continue  # Removals of packaged files are PACKAGE_FILE_MISSING; others are uninstalls.
        if before is None:
            if 'package' not in after:
                findings.append(_finding('PROGRAM_ADDED', shown, dict(sha256=after['sha256'])))
            continue
        if before['sha256'] == after['sha256']:
            continue
        if ('PACKAGE_MISMATCH', shown) in reported:
            continue
        if 'package' in after:
            if after['package'] != before.get('package'):
                updated.append(dict(path=shown, package=[before.get('package'), after['package']]))
            elif after.get('package_md5') != before.get('package_md5'):
                findings.append(_finding('PACKAGE_RECORD_CHANGED', shown, dict(package=after['package'])))
            else:
                updated.append(dict(path=shown, package=[before.get('package'), after['package']]))
        else:
            findings.append(_finding('PROGRAM_CHANGED', shown, dict(size=[before['size'], after['size']])))
    return _sorted(findings), updated


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.binaries-', dir=path.parent)
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
        raise BinaryIntegrityError(f'no program baseline at {path}; run megalodon binaries baseline') from None
    except OSError as exc:
        raise BinaryIntegrityError(f'program baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise BinaryIntegrityError(f'program baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BinaryIntegrityError('program baseline is too large')
    try:
        value = json.loads(raw)
    except ValueError:
        raise BinaryIntegrityError('program baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('files')) is not dict:
        raise BinaryIntegrityError('program baseline has an unsupported format')
    return value


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, **options):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise BinaryIntegrityError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(**options)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), user=os.geteuid(), files=state['files']))
    findings = _sorted(state['findings'])
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), files=len(state['files']),
                packaged=state['packaged'], findings=findings, gaps=state['gaps'],
                note='Findings at baseline time are already wrong: review them before trusting this baseline.'
                if findings else 'Every packaged program matched its package.')


def check(manifest=DEFAULT_MANIFEST, **options):
    old = _read(manifest)
    new = snapshot(**options)
    findings, updated = compare(old, new)
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), files=len(new['files']),
                findings=findings, updated=updated, gaps=new['gaps'],
                severity_counts={level: sum(1 for f in findings if f['severity'] == level) for level in RANK},
                note='Review each finding; accept records the reviewed state. Nothing was changed.')


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)  # Only an existing, private baseline can be replaced.
    return dict(baseline(manifest, replace=True, **options), action='accept')
