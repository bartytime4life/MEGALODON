"""Known-vulnerable software: security fixes waiting, kernels not booted, old code still running, and what is exposed.

Most break-ins use a flaw that already has a fix the machine has not taken.
`megalodon vulns check` reads, from the package manager's own local data and
without fetching anything:

* the security updates waiting to be installed (apt's lists through a
  simulated upgrade that changes nothing, or dnf's cached update notices);
* a newer kernel installed than the one running, or a reboot the system
  asked for, so a fix on disk is not in effect;
* programs still running code from a library or program an update already
  replaced, so a fix on disk is not in effect for them until they restart;

and joins them to the services that listen beyond this machine, so the one
fix that matters most comes first: a service anyone can reach, running code
with a known flaw (ATT&CK T1190, T1210).

The lists are only as fresh as the last `apt update` or `dnf makecache`: the
check says how old they are. Nothing is installed, restarted or fetched.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

SCHEMA = 'megalodon-vulns-report-v1'
STALE_DAYS = 7
MAX_PROCESSES = 65536
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
SYSTEM_DIRS = ('/usr/', '/lib/', '/lib64/', '/lib32/', '/bin/', '/sbin/')
_APT = re.compile(r'^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.+?)(?: \[([^\]]*)\])?\)(?: \[[^\]]*\])?\s*$')
_DNF = re.compile(r'^(\S+)\s+(\S+)/Sec\.\s+(\S+)\s*$')

RULES = {
    'VULNERABLE_EXPOSED_SERVICE': ('CRITICAL', ['T1190'],
                                   'A service that listens beyond this machine runs code with a security fix '
                                   'waiting: the most likely way in.'),
    'FIX_NOT_RUNNING_EXPOSED': ('HIGH', ['T1190'],
                                'A service that listens beyond this machine still runs code an update replaced: '
                                'the fix is on disk but not in effect until it restarts.'),
    'KERNEL_FIX_NOT_RUNNING': ('HIGH', ['T1068'], 'A newer kernel is installed than the one running, or the system '
                                                  'asked for a reboot: kernel fixes are not in effect.'),
    'SECURITY_UPDATES_PENDING': ('HIGH', ['T1068', 'T1190'], 'Security updates are waiting to be installed.'),
    'FIX_NOT_RUNNING': ('MEDIUM', ['T1068'], 'A program still runs code an update replaced; it needs a restart.'),
    'PACKAGE_LISTS_STALE': ('MEDIUM', [], 'The package lists have not been refreshed for a week or more, so '
                                          'newer fixes are not known here.'),
}


def _now():
    return datetime.now(timezone.utc)


def _run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False,
                                env=dict(os.environ, LC_ALL='C', LANG='C'))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    return result.stdout, (result.stderr.strip() if result.returncode else '')


# ------------------------------------------------------------------ pending updates

def apt_updates(text):
    """{package: {name, arch, installed, available, security, origins}} from `apt-get -s dist-upgrade` output.

    A package of a foreign architecture keeps its ':arch' in the key, as apt prints it: libssl3:i386 and libssl3 are
    separate packages on a multiarch machine, and only the one with the fix waiting is vulnerable.
    """
    found = {}
    for line in (text or '').splitlines():
        match = _APT.match(line)
        if not match:
            continue
        origins = [o.strip() for o in match.group(4).split(',')]
        security = any('-security' in o or 'Debian-Security' in o or '/security' in o for o in origins)
        name, _, suffix = match.group(1).partition(':')
        found[match.group(1)] = dict(name=name, arch=suffix or match.group(5), installed=match.group(2),
                                     available=match.group(3), security=security, origins=origins)
    return found


def _rpm_name(nevra):
    base = nevra.rsplit('.', 1)[0]                       # drop .arch
    return base.rsplit('-', 2)[0] if base.count('-') >= 2 else base


def dnf_updates(text):
    """{package: {available, security, advisory, severity}} from `dnf updateinfo list --security` output."""
    found = {}
    for line in (text or '').splitlines():
        match = _DNF.match(line.strip())
        if match:
            found[_rpm_name(match.group(3))] = dict(available=match.group(3), security=True,
                                                    advisory=match.group(1), severity=match.group(2))
    return found


def pending(root='/', run=_run):
    """(updates, manager, lists_age_days, gaps)."""
    if Path(root, 'var/lib/dpkg/status').exists() and (run is not _run or shutil.which('apt-get')):
        text, error = run(['apt-get', '-s', '-o', 'Debug::NoLocking=true', '-o', 'APT::Get::Show-Versions=true',
                           'dist-upgrade'])
        lists = Path(root, 'var/lib/apt/lists')
        try:
            age = (time.time() - max(p.stat().st_mtime for p in lists.iterdir() if p.name.endswith('Release'))) / 86400
        except (OSError, ValueError):
            age = None
        return apt_updates(text), 'apt', age, ([f'apt-get could not simulate an upgrade: {error}'] if error else [])
    if run is not _run or shutil.which('dnf'):
        text, error = run(['dnf', '-q', '--cacheonly', 'updateinfo', 'list', '--security', '--available'])
        cache = Path(root, 'var/cache/dnf')
        try:
            age = (time.time() - max(p.stat().st_mtime for p in cache.rglob('repomd.xml'))) / 86400
        except (OSError, ValueError):
            age = None
        return dnf_updates(text), 'dnf', age, ([f'dnf could not read its cache: {error}'] if error else [])
    return {}, None, None, ['no supported package manager (apt or dnf) was found']


# ------------------------------------------------------------------ what runs and what listens

def owners_dpkg(root='/'):
    """{path: package} from dpkg's file lists; 'name:arch' for packages installed per architecture."""
    found = {}
    info = Path(root, 'var/lib/dpkg/info')
    try:
        lists = sorted(p for p in info.iterdir() if p.name.endswith('.list'))
    except OSError:
        return found
    for path in lists:
        package = path.name[:-5]
        try:
            for line in path.read_text('utf-8', 'replace').splitlines():
                found.setdefault(line, package)
        except OSError:
            continue
    return found


def _fixes(package, security):
    """The waiting security updates for an installed package, matched by name and architecture."""
    name, _, arch = package.partition(':')
    return [key for key, update in security.items() if update.get('name', key) == name
            and (not arch or update.get('arch') in (None, arch, 'all'))]


def _usr_merged(path):
    """dpkg lists /lib/... where the running program shows /usr/lib/... on merged-/usr systems, and the reverse."""
    for short, full in (('/lib/', '/usr/lib/'), ('/bin/', '/usr/bin/'), ('/sbin/', '/usr/sbin/'),
                        ('/lib64/', '/usr/lib64/')):
        if path.startswith(full):
            return short + path[len(full):]
        if path.startswith(short):
            return full + path[len(short):]
    return path


def processes(root='/'):
    """{pid: {program, files, stale}}: the program and libraries each process maps, and those an update replaced."""
    out, unreadable = {}, 0
    proc = Path(root, 'proc')
    try:
        pids = sorted(int(p.name) for p in proc.iterdir() if p.name.isdigit())[:MAX_PROCESSES]
    except OSError:
        return out, 1
    for pid in pids:
        try:
            maps = (proc / str(pid) / 'maps').read_text('utf-8', 'replace')
            exe = os.readlink(proc / str(pid) / 'exe')
        except OSError:
            unreadable += 1
            continue
        files, stale = set(), set()
        for line in maps.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6 or not parts[5].startswith('/'):
                continue
            path = parts[5]
            deleted = path.endswith(' (deleted)')
            path = path.removesuffix(' (deleted)')
            # Code only: programs and libraries. A replaced data file, such as the locale archive, needs no restart.
            if path.startswith(SYSTEM_DIRS) and ('.so' in path or 'x' in parts[1]):
                files.add(path)
                if deleted:
                    stale.add(path)
        out[pid] = dict(program=exe.removesuffix(' (deleted)'), files=files, stale=stale)
    return out, unreadable


def listeners(root='/'):
    """{pid: [address:port]} for sockets that listen beyond loopback."""
    from .listener_watch import _listening
    found, _ = _listening(root)
    wanted = {inode: (address, port) for inode, (_, address, port) in found.items()
              if not ipaddress.ip_address(address).is_loopback}
    out = {}
    proc = Path(root, 'proc')
    try:
        entries = [e for e in os.scandir(proc) if e.name.isdigit()]
    except OSError:
        return out
    for entry in entries:
        try:
            descriptors = os.listdir(Path(entry.path, 'fd'))
        except OSError:
            continue
        for fd in descriptors:
            try:
                target = os.readlink(Path(entry.path, 'fd', fd))
            except OSError:
                continue
            if target.startswith('socket:[') and target[8:-1].isdigit() and int(target[8:-1]) in wanted:
                address, port = wanted[int(target[8:-1])]
                out.setdefault(int(entry.name), set()).add(f'{address}:{port}')
    return {pid: sorted(v) for pid, v in out.items()}


# ------------------------------------------------------------------ the kernel

def _version_key(text):
    return tuple(int(n) for n in re.findall(r'\d+', text))


def kernel(root='/', release=None):
    """(running, newest installed, reboot asked for, packages that asked)."""
    running = release or platform.release()
    images = [p.name[len('vmlinuz-'):] for p in Path(root, 'boot').glob('vmlinuz-*')]
    newest = max(images, key=_version_key) if images else None
    asked = Path(root, 'var/run/reboot-required').exists() or Path(root, 'run/reboot-required').exists()
    packages = []
    for name in ('var/run/reboot-required.pkgs', 'run/reboot-required.pkgs'):
        try:
            packages = sorted(set(Path(root, name).read_text().split()))
            break
        except OSError:
            continue
    return running, newest, asked, packages


# ------------------------------------------------------------------ the check

def _finding(rule, subject, detail, **extra):
    severity, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


def check(root='/', *, run=_run, release=None):
    updates, manager, age, gaps = pending(root, run)
    security = {name: u for name, u in updates.items() if u['security']}
    findings = []
    if age is not None and age >= STALE_DAYS:
        findings.append(_finding('PACKAGE_LISTS_STALE', f'packages:{manager}',
                                 f'the {manager} lists were last refreshed {int(age)} days ago'))
    if security:
        names = sorted(security)
        findings.append(_finding('SECURITY_UPDATES_PENDING', f'packages:{manager}',
                                 f'{len(names)} security updates are waiting: ' + ', '.join(names[:12])
                                 + (' and more' if len(names) > 12 else ''), packages=names))
    running, newest, asked, asking = kernel(root, release)
    if (newest and _version_key(newest) > _version_key(running)) or asked:
        findings.append(_finding('KERNEL_FIX_NOT_RUNNING', 'kernel',
                                 f'running {running}' + (f', installed {newest}' if newest and newest != running
                                                         else '')
                                 + ('; a reboot was asked for' + (f' by {", ".join(asking[:6])}' if asking else '')
                                    if asked else ''), running=running, installed=newest))
    owner = owners_dpkg(root) if manager == 'apt' else {}
    procs, unreadable = processes(root)
    exposed = listeners(root)
    if unreadable and os.geteuid():
        gaps.append(f'{unreadable} processes could not be read; run as root to see every service')
    for pid, info in sorted(procs.items()):
        packages = {owner.get(p) or owner.get(_usr_merged(p)) for p in info['files'] | {info['program']}} - {None}
        vulnerable = sorted({key for package in packages for key in _fixes(package, security)})
        where = exposed.get(pid)
        evidence = dict(processes=[dict(pid=pid, program=info['program'])])
        if where and vulnerable:
            findings.append(_finding('VULNERABLE_EXPOSED_SERVICE', f'process:{pid}',
                                     f"{info['program']} (pid {pid}) listens on {', '.join(where[:4])} and runs code "
                                     f"from {', '.join(vulnerable[:6])}, which has a security fix waiting",
                                     packages=vulnerable, listening=where, evidence=evidence))
        if info['stale']:
            rule = 'FIX_NOT_RUNNING_EXPOSED' if where else 'FIX_NOT_RUNNING'
            stale = sorted(info['stale'])
            findings.append(_finding(rule, f'process:{pid}',
                                     f"{info['program']} (pid {pid})" + (f" listens on {', '.join(where[:4])} and"
                                                                         if where else '')
                                     + f" still runs replaced code: {', '.join(stale[:4])}; restart it",
                                     files=stale, evidence=evidence))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return dict(schema=SCHEMA, action='check', checked_at=_now().strftime('%Y-%m-%dT%H:%M:%SZ'), manager=manager,
                lists_age_days=round(age, 1) if age is not None else None, updates=len(updates),
                security_updates=len(security), kernel=dict(running=running, newest_installed=newest,
                                                            reboot_requested=asked),
                findings=findings, gaps=gaps,
                note='Install the updates (apt upgrade or dnf upgrade --security), restart the services named, and '
                     'reboot for a new kernel. Nothing was changed.')
