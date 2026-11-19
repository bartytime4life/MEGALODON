"""Credential access: which program opened an SSH key, a browser password store or a cloud token.

Info-stealers are the most common malware on desktops and developer machines:
they read SSH keys, browser password and cookie stores, cloud and developer
tokens, keyrings and wallets, and ship them out (ATT&CK T1552, T1555, T1539).
Canaries catch reads of decoys; this watches the real files.

As root, the kernel's file-access notifications (fanotify) name the process
behind every open, and the kernel's process events remember programs that exit
at once. Without root, opens are seen through inotify and matched to a process
only while it still holds the file. Each kind of file has its expected readers
(`ssh` for keys, the browser for its own stores, `sudo` for /etc/shadow), and
only when installed in a system folder; anything else is a finding.

Read-only: nothing is blocked. The contents of the files are never read.
"""
from __future__ import annotations

from collections import OrderedDict
import ctypes
import errno
import fnmatch
import glob
import json
import os
from pathlib import Path
import pwd
import select
import stat
import struct
import tempfile
import time

from .egress_watch import _proc_info, script
from .process_network import TEMPORARY

SCHEMA = 'megalodon-credential-watch-v1'
DEFAULT_ALLOW = '~/.config/megalodon/credential-allow.json'
MAX_TRACKED = 65536
COOLDOWN_SECONDS = 3600
SWEEP_WINDOW = 120
REFRESH_SECONDS = 30
SYSTEM_PREFIXES = ('/usr/', '/bin/', '/sbin/', '/lib/', '/lib64/', '/opt/', '/snap/')

_BROWSERS = ('google-chrome', 'google-chrome-beta', 'chromium', 'BraveSoftware/Brave-Browser', 'microsoft-edge',
             'vivaldi', 'opera')
CATEGORIES = {
    'ssh': dict(
        home=['.ssh/id_*', '.ssh/*_rsa', '.ssh/*_ecdsa', '.ssh/*_ed25519', '.ssh/*.pem'],
        readers={'ssh', 'ssh-add', 'ssh-agent', 'ssh-keygen', 'scp', 'sftp', 'ssh-copy-id', 'sshd', 'sshd-session',
                 'gpg-agent', 'gnome-keyring-daemon', 'seahorse'}),
    'browser': dict(
        home=['.mozilla/firefox/*/logins.json', '.mozilla/firefox/*/key4.db', '.mozilla/firefox/*/cookies.sqlite',
              '.mozilla/firefox/*/formhistory.sqlite']
        + [f'.config/{b}/{p}' for b in _BROWSERS for p in ('*/Login Data', '*/Cookies', '*/Network/Cookies',
                                                           '*/Web Data', 'Local State')],
        readers={'firefox', 'firefox-bin', 'firefox-esr', 'chrome', 'google-chrome', 'chromium', 'chromium-browser',
                 'brave', 'msedge', 'vivaldi-bin', 'opera', 'plugin-container'}),
    'cloud': dict(
        home=['.aws/credentials', '.aws/config', '.aws/sso/cache/*', '.config/gcloud/credentials.db',
              '.config/gcloud/access_tokens.db', '.config/gcloud/application_default_credentials.json',
              '.azure/msal_token_cache.json', '.azure/accessTokens.json', '.kube/config', '.docker/config.json',
              '.git-credentials', '.netrc', '.npmrc', '.pypirc', '.config/gh/hosts.yml',
              '.terraform.d/credentials.tfrc.json'],
        readers={'aws', 'aws_completer', 'gcloud', 'gsutil', 'bq', 'az', 'kubectl', 'helm', 'k9s', 'kubelogin',
                 'docker', 'dockerd', 'docker-credential-desktop', 'podman', 'terraform', 'gh', 'git',
                 'git-remote-https', 'git-credential-store', 'git-credential-cache--daemon', 'npm', 'npx', 'yarn',
                 'pnpm', 'npm-cli', 'npx-cli', 'pip', 'pip3', 'twine', 'curl', 'wget', 'ftp', 'lftp'}),
    'keyring': dict(
        home=['.local/share/keyrings/*', '.gnupg/private-keys-v1.d/*', '.gnupg/secring.gpg',
              '.local/share/kwalletd/*'],
        readers={'gnome-keyring-daemon', 'gpg-agent', 'gpg', 'gpg2', 'seahorse', 'kwalletd5', 'kwalletd6',
                 'ksecretd', 'pass', 'keepassxc'}),
    'wallet': dict(
        home=['.bitcoin/wallet.dat', '.bitcoin/wallets/*', '.electrum/wallets/*', '.ethereum/keystore/*',
              '.config/Exodus/exodus.wallet/*', '.config/atomic/Local Storage/leveldb/*'],
        readers={'bitcoind', 'bitcoin-qt', 'electrum', 'geth', 'exodus', 'atomic', 'monero-wallet-gui'}),
    'system': dict(
        absolute=['/etc/shadow', '/etc/gshadow', '/etc/shadow-', '/etc/gshadow-', '/etc/security/opasswd',
                  '/etc/ssh/ssh_host_*_key'],
        readers={'sshd', 'sshd-session', 'sshd-auth', 'login', 'passwd', 'su', 'sudo', 'unix_chkpwd',
                 'unix_update', 'chage', 'chpasswd', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod',
                 'groupdel', 'gpasswd', 'newusers', 'vipw', 'pwck', 'grpck', 'expiry', 'systemd-logind',
                 'systemd-userdbd', 'systemd-homed', 'cron', 'crond', 'atd', 'polkit-agent-helper-1',
                 'gdm-session-worker', 'lightdm', 'sddm-helper', 'accounts-daemon', 'cockpit-session', 'dpkg',
                 'vsftpd', 'dovecot', 'pam_timestamp_check', 'shadowconfig', 'pwconv', 'grpconv'}),
}
_SUFFIX_SKIP = ('.pub', '-cert.pub')

RULES = {
    'CREDENTIAL_SWEEP': ('CRITICAL', ['T1555', 'T1552.001', 'T1539'],
                         'One process opened credentials of several kinds, as an info-stealer collecting everything '
                         'it can find does.'),
    'CREDENTIAL_READ_BY_DROPPED_TOOL': ('CRITICAL', ['T1552.001', 'T1555'],
                                        'A program run from a temporary folder, a deleted file or memory opened a '
                                        'credential file.'),
    'CREDENTIAL_READ': ('HIGH', ['T1552.001', 'T1555'],
                        'A program that is not an expected reader opened a credential file. Backups and '
                        'migration tools also do this; allow them after review.'),
}


class CredentialError(ValueError):
    pass


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ------------------------------------------------------------------ what is watched

def homes(root='/'):
    """Every user's home as root (UID 0 and 1000+); otherwise only your own."""
    if os.geteuid() != 0:
        return [str(Path.home())]
    found = []
    for entry in pwd.getpwall():
        if (entry.pw_uid == 0 or entry.pw_uid >= 1000) and entry.pw_dir not in ('/', '/nonexistent'):
            path = os.path.join(root, entry.pw_dir.lstrip('/')) if root != '/' else entry.pw_dir
            if os.path.isdir(path) and path not in found:
                found.append(path)
    return found


def patterns(home_dirs, root='/'):
    """[(category, absolute glob pattern)] for every home and the system files."""
    out = []
    for category, spec in CATEGORIES.items():
        for home in home_dirs:
            out += [(category, os.path.join(home, p)) for p in spec.get('home', [])]
        out += [(category, os.path.join(root, p.lstrip('/')) if root != '/' else p) for p in spec.get('absolute', [])]
    return out


def classify(path, watched):
    """The category of a credential file, or None."""
    if path.endswith(_SUFFIX_SKIP):
        return None
    for category, pattern in watched:
        if fnmatch.fnmatchcase(path, pattern):
            return category
    return None


def aliases(watched):
    """{resolved path: (credential path, category)} for credentials that are symbolic links. The kernel names the
    file a descriptor really opened, so a linked key is reported under its target unless it is mapped back."""
    found = {}
    for category, pattern in watched:
        for match in glob.glob(pattern):
            if match.endswith(_SUFFIX_SKIP):
                continue
            real = os.path.realpath(match)
            if real != match and os.path.isfile(real):
                found[real] = (match, category)
    return found


def resolve(path, watched, linked):
    """(category, credential path) for an opened path, through the symlink map; (None, path) otherwise."""
    category = classify(path, watched)
    if category:
        return category, path
    if path in linked:
        return linked[path][1], linked[path][0]
    return None, path


def targets(watched):
    """Existing files to mark, and folders to mark for files created later."""
    files, folders = set(), set()
    for _category, pattern in watched:
        folder = os.path.dirname(pattern)
        for match in glob.glob(folder):
            if os.path.isdir(match):
                folders.add(match)
        for match in glob.glob(pattern):
            if os.path.isfile(match) and not match.endswith(_SUFFIX_SKIP):
                files.add(match)
    return sorted(files), sorted(folders)


# ------------------------------------------------------------------ who may read

def _load_allow(path):
    if path is None:
        return set()
    path = Path(path).expanduser()
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return set()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise CredentialError(f'{path} must be a regular file owned by you and writable only by you')
    try:
        return {(e['program'], e['category']) for e in json.loads(path.read_text('utf-8')).get('allow', [])}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise CredentialError(f'{path} is not a valid allow list') from None


def allow(path, program, category='any'):
    if category != 'any' and category not in CATEGORIES:
        raise CredentialError(f'category must be any or one of {", ".join(CATEGORIES)}')
    entries = _load_allow(path) | {(program, category)}
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, temporary = tempfile.mkstemp(prefix='.credential-allow-', dir=path.parent)
    with os.fdopen(handle, 'w', encoding='utf-8') as out:
        os.fchmod(out.fileno(), 0o600)
        json.dump(dict(schema=SCHEMA + '-allow', allow=[dict(program=p, category=c) for p, c in sorted(entries)]),
                  out, indent=2)
    os.replace(temporary, path)
    return len(entries)


def _names(info):
    names = {os.path.basename(info['path'])}
    run = script(info)
    if run and run.startswith('/'):
        names.add(os.path.basename(run).removesuffix('.py').removesuffix('.js'))
    return names


def _dropped(info):
    run = script(info) or ''
    path = info['path']
    return info['deleted'] or path.startswith(TEMPORARY) or path.startswith('/memfd:') or run.startswith(TEMPORARY)


def _installed(info):
    run = script(info)
    places = [info['path']] + ([run] if run and run.startswith('/') else [])
    return all(p.startswith(SYSTEM_PREFIXES) for p in places)


class Judge:
    def __init__(self, allowed=frozenset(), *, own_pid=None):
        self.allowed = set(allowed)
        self.own_pid = own_pid if own_pid is not None else os.getpid()
        self.last: dict = {}
        self.touched: OrderedDict = OrderedDict()      # (pid, start) -> [(time, category, path)]
        self.swept: set = set()

    def judge(self, pid, info, path, category, now):
        if pid == self.own_pid or info is None:
            return []
        identity = info['path'] + (f" {script(info)}" if script(info) else '')
        if (identity, category) in self.allowed or (identity, 'any') in self.allowed:
            return []
        dropped = _dropped(info)
        if not dropped and _installed(info) and _names(info) & CATEGORIES[category]['readers']:
            return []                  # an expected reader, installed where packages put programs
        found = []
        key = (pid, info['start'])
        history = self.touched.setdefault(key, [])
        history.append((now, category, path))
        self.touched.move_to_end(key)
        while len(self.touched) > MAX_TRACKED:
            self.touched.popitem(last=False)
        recent = [h for h in history if now - h[0] <= SWEEP_WINDOW]
        history[:] = recent
        kinds = {c for _, c, _ in recent}
        if len(kinds) >= 2 and key not in self.swept:
            self.swept.add(key)
            found.append(self._finding('CREDENTIAL_SWEEP', pid, info, identity, path, category,
                                       f'{identity} (pid {pid}) opened {", ".join(sorted(kinds))} credentials within '
                                       f'{SWEEP_WINDOW} s: ' + ', '.join(sorted({p for _, _, p in recent})[:6]),
                                       files=sorted({p for _, _, p in recent})[:20]))
        rule = 'CREDENTIAL_READ_BY_DROPPED_TOOL' if dropped else 'CREDENTIAL_READ'
        mark = (rule, identity, path)
        if now - self.last.get(mark, -1e18) >= COOLDOWN_SECONDS:
            self.last[mark] = now
            if len(self.last) > MAX_TRACKED:
                self.last.clear()
            found.append(self._finding(rule, pid, info, identity, path, category,
                                       f'{identity} (pid {pid}) opened {category} credential {path}'))
        return found

    @staticmethod
    def _finding(rule, pid, info, identity, path, category, detail, files=None):
        severity, techniques, summary = RULES[rule]
        return dict(schema=SCHEMA, rule_id=rule, severity=severity, techniques=techniques, detected_at=_now(),
                    program=identity, category=category, path=path, detail=detail, summary=summary,
                    files=files or [path],
                    evidence=dict(processes=[dict(program=info['path'], pid=pid, start=info['start'])],
                                  argv=info['argv'][:8]))


# ------------------------------------------------------------------ one look: credentials held open now

def check(*, root='/', home_dirs=None, allow_path=DEFAULT_ALLOW):
    watched = patterns(home_dirs if home_dirs is not None else homes(root), root)
    linked = aliases(watched)
    judge = Judge(_load_allow(allow_path))
    findings, gaps, unreadable = [], [], 0
    base = Path(root, 'proc')
    for entry in os.scandir(base):
        if not entry.name.isdigit():
            continue
        try:
            fds = os.scandir(base / entry.name / 'fd')
        except OSError:
            unreadable += 1
            continue
        with fds:
            for fd in fds:
                try:
                    target = os.readlink(fd.path)
                except OSError:
                    continue
                category, shown = resolve(target, watched, linked) if target.startswith('/') else (None, target)
                if category:
                    findings += judge.judge(int(entry.name), _proc_info(base / entry.name), shown, category,
                                            time.monotonic())
    if unreadable and os.geteuid():
        gaps.append(f'{unreadable} processes of other accounts could not be read; run as root to see every process')
    findings.sort(key=lambda f: (('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').index(f['severity']), f['path']))
    return dict(schema=SCHEMA, action='check', checked_at=_now(), findings=findings, gaps=gaps,
                note='Only files held open right now are seen; `watch` sees every open as it happens.')


# ------------------------------------------------------------------ live: fanotify (root) or inotify

FAN_CLOEXEC, FAN_NONBLOCK, FAN_CLASS_NOTIF = 0x1, 0x2, 0x0
FAN_MARK_ADD, FAN_OPEN, FAN_EVENT_ON_CHILD, FAN_Q_OVERFLOW = 0x1, 0x20, 0x08000000, 0x4000
O_LARGEFILE = 0o100000
_EVENT = struct.Struct('=IBBHQii')
IN_OPEN, IN_Q_OVERFLOW, IN_NONBLOCK, IN_CLOEXEC = 0x20, 0x4000, 0o4000, 0o2000000


class Fanotify:
    mode = 'file-access notifications'

    def __init__(self, files, folders):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        self.libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int,
                                            ctypes.c_char_p]
        self.fd = self.libc.fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_NOTIF, os.O_RDONLY | O_LARGEFILE)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'fanotify is not available')
        self.marked, self.paths = 0, set()
        self.add(files, folders)

    def add(self, files, folders):
        """Mark more files and folders; marks follow symbolic links to the file itself."""
        for path, mask in [(f, FAN_OPEN) for f in files] + [(d, FAN_OPEN | FAN_EVENT_ON_CHILD) for d in folders]:
            if path in self.paths:
                continue
            if self.libc.fanotify_mark(self.fd, FAN_MARK_ADD, mask, -100, path.encode()) == 0:
                self.paths.add(path)
                self.marked += 1

    def fileno(self):
        return self.fd

    def read(self):
        """[(pid, path)] of the opens queued now; ('lost', None) when the kernel dropped some."""
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        out, offset = [], 0
        while offset + _EVENT.size <= len(data):
            length, _version, _, _, mask, fd, pid = _EVENT.unpack_from(data, offset)
            if length < _EVENT.size:
                break
            if mask & FAN_Q_OVERFLOW:
                out.append(('lost', None))
            if fd >= 0:
                try:
                    out.append((pid, os.readlink(f'/proc/self/fd/{fd}')))
                except OSError:
                    pass
                finally:
                    os.close(fd)
            offset += length
        return out

    def close(self):
        os.close(self.fd)


class Inotify:
    """Without root: opens are seen, and matched to a process only while it still holds the file."""
    mode = 'inotify (without root, a program is named only while it still holds the file open)'

    def __init__(self, files, folders):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = self.libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify is not available')
        self.watches, self.marked = {}, 0
        self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.add(files, folders)

    def add(self, files, folders):
        known = set(self.watches.values())
        for path in list(folders) + list(files):
            if path in known:
                continue
            wd = self.libc.inotify_add_watch(self.fd, path.encode(), IN_OPEN)
            if wd >= 0:
                self.watches[wd] = path
                self.marked += 1

    def fileno(self):
        return self.fd

    def read(self):
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        out, offset = [], 0
        while offset + 16 <= len(data):
            wd, mask, _cookie, length = struct.unpack_from('=iIII', data, offset)
            name = data[offset + 16:offset + 16 + length].split(b'\0', 1)[0].decode('utf-8', 'surrogateescape')
            offset += 16 + length
            if mask & IN_Q_OVERFLOW:
                out.append(('lost', None))
                continue
            base = self.watches.get(wd)
            if base is not None:
                out.append((None, os.path.join(base, name) if name else base))
        return out

    def close(self):
        os.close(self.fd)


def _holders(path):
    """Processes that hold `path` open now (for the inotify fallback). Descriptors name the resolved file, so a
    credential that is a symbolic link is matched by its target too."""
    wanted = {path, os.path.realpath(path)}
    found = []
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():
            continue
        try:
            with os.scandir(f'/proc/{entry.name}/fd') as fds:
                if any(_link(fd.path) in wanted for fd in fds):
                    found.append(int(entry.name))
        except OSError:
            continue
    return found


def _link(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


class Watcher:
    def __init__(self, emit, *, home_dirs=None, allow_path=DEFAULT_ALLOW, source=None, processes=None,
                 clock=time.monotonic):
        self.home_dirs = home_dirs
        self.watched = patterns(home_dirs if home_dirs is not None else homes())
        self.files, self.folders = targets(self.watched)
        self.linked = aliases(self.watched)
        self.judge = Judge(_load_allow(allow_path))
        self.emit, self.clock = emit, clock
        self.cache: OrderedDict = OrderedDict()
        self.stats = dict(opens=0, findings=0, unattributed=0, lost=0)
        if source is None:
            try:
                source = Fanotify(self.files, self.folders)
            except OSError:
                source = Inotify(self.files, self.folders)
        self.source = source
        # Process events name readers that already exited; only fanotify reports who opened a file.
        if processes is None and getattr(source, 'mode', '') == 'file-access notifications':
            try:
                from .process_ancestry import ProcEvents
                processes = ProcEvents()
            except OSError:
                processes = None
        self.processes = processes
        self.mode = source.mode
        self.refreshed = clock()

    def refresh(self):
        """Pick up credential folders and files created since the watch started (a first `aws configure`, a
        new browser profile, a new user's home)."""
        self.watched = patterns(self.home_dirs if self.home_dirs is not None else homes())
        files, folders = targets(self.watched)
        self.linked = aliases(self.watched)
        if hasattr(self.source, 'add'):
            self.source.add(files, folders)
        self.files, self.folders = files, folders
        self.refreshed = self.clock()

    def _remember(self, pid):
        info = _proc_info(Path('/proc', str(pid)))
        if info is not None:
            self.cache[pid] = info
            self.cache.move_to_end(pid)
            while len(self.cache) > MAX_TRACKED:
                self.cache.popitem(last=False)

    def handle(self, pid, path):
        if pid == 'lost':
            self.stats['lost'] += 1
            return []
        category, shown = resolve(path, self.watched, self.linked)
        if category is None:
            return []
        self.stats['opens'] += 1
        pids = [pid] if pid is not None else _holders(path)
        if not pids:
            self.stats['unattributed'] += 1
            return []
        out = []
        for one in pids:
            # Live if it is still running; otherwise as it was when it started (from the process events).
            info = _proc_info(Path('/proc', str(one))) or self.cache.get(one)
            if info is None:
                self.stats['unattributed'] += 1
                continue
            for found in self.judge.judge(one, info, shown, category, self.clock()):
                self.stats['findings'] += 1
                out.append(found)
                self.emit(found)
        return out

    def run(self, stop, timeout=0.5):
        while not stop.is_set():
            if self.clock() - self.refreshed >= REFRESH_SECONDS:
                self.refresh()
            ready, _, _ = select.select([self.source.fileno()] + ([self.processes.sock] if self.processes else []),
                                        [], [], timeout)
            if self.processes is not None:
                # Programs that start are remembered at once, so a reader that exits before its open event is
                # handled is still named. Every queued process event is read before the opens.
                for _ in range(10000):
                    batch = self.processes.events(0)
                    if not batch:
                        break
                    for kind, pid, _parent in batch:
                        if kind == 'exec':
                            self._remember(pid)
            if self.source.fileno() in ready:
                for pid, path in self.source.read():
                    self.handle(pid, path)

    def close(self):
        self.source.close()
        if self.processes is not None:
            self.processes.close()
