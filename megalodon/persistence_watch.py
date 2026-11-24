"""Baseline and check the places attackers use to survive reboots and password changes.

``megalodon persistence baseline`` records the state of each persistence
location into an owner-private manifest. ``megalodon persistence check``
compares the current state and reports every entry that was added, changed or
removed, each mapped to its ATT&CK technique:

* **systemd** units, timers and enablement links: system and user (T1543.002, T1053.006)
* **cron** tables and the hourly, daily, weekly and monthly folders (T1053.003)
* **at** jobs (T1053.002)
* **autostart** desktop entries (T1547.013)
* **shell startup** files: user and system (T1546.004)
* **SSH** ``authorized_keys`` and the server configuration (T1098.004)
* **dynamic-linker preload** files (T1574.006)
* **sudoers** (T1548.003) and **PAM** (T1556.003)
* **init scripts**: rc.local, init.d and udev rules (T1037.004, T1546)
* **kernel modules**: loaded, and configured to load (T1547.006)
* **setuid/setgid programs** in system program folders (T1548.001)
* **local accounts**: new accounts, a new UID 0, a login shell given to a
  service account (T1136.001)

Only metadata is kept: content digests, sizes, modes, owners, link targets and
line counts. For SSH keys, the key type, a SHA-256 fingerprint and the comment
are kept; for accounts, name, UID, GID, home and shell. File contents are
never copied into the manifest or the report. Locations the current user
cannot read are listed as coverage gaps, never silently skipped. Nothing is
changed or removed: ``accept`` records the reviewed state as the new baseline.

Locations under ``~/`` are in the home of the account running the check. Run
as root, they are also read in every other account's home, from
``/etc/passwd``, and recorded as ``~NAME/...``: an SSH key added for another
account is reported like one added for root.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import fnmatch
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile

SCHEMA = 'megalodon-persistence-manifest-v1'
REPORT_SCHEMA = 'megalodon-persistence-check-v1'
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_SETUID_WALK = 400_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
DEFAULT_MANIFEST = '~/.config/megalodon/persistence.json'
SETUID_DIRS = ('/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/usr/local/sbin', '/usr/lib',
               '/usr/libexec', '/opt')
_SHELLS_NOLOGIN = ('nologin', 'false', 'sync', 'shutdown', 'halt')
MAX_HOMES = 2000
# Account names as a home key (~NAME/): what useradd accepts, plus the $ of machine accounts.
ACCOUNT_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}\$?')
# Homes that are not homes: nothing an account keeps there is its own startup file.
NOT_HOMES = ('/', '/nonexistent', '/proc', '/sys', '/dev', '/run')

# (category, ATT&CK technique, severity when added/changed, glob patterns; ~ is the home folder)
LOCATIONS = (
    ('systemd', 'T1543.002', 'MEDIUM', (
        '/etc/systemd/system/*', '/etc/systemd/system/*/*', '/usr/local/lib/systemd/system/*',
        '/etc/systemd/user/*', '/etc/systemd/user/*/*', '~/.config/systemd/user/*', '~/.config/systemd/user/*/*')),
    ('cron', 'T1053.003', 'MEDIUM', (
        '/etc/crontab', '/etc/cron.d/*', '/etc/cron.hourly/*', '/etc/cron.daily/*', '/etc/cron.weekly/*',
        '/etc/cron.monthly/*', '/var/spool/cron/*', '/var/spool/cron/crontabs/*', '/etc/anacrontab')),
    ('at', 'T1053.002', 'MEDIUM', ('/var/spool/cron/atjobs/*', '/var/spool/at/*')),
    ('autostart', 'T1547.013', 'MEDIUM', ('/etc/xdg/autostart/*', '~/.config/autostart/*')),
    ('shell_startup', 'T1546.004', 'MEDIUM', (
        '~/.bashrc', '~/.bash_profile', '~/.bash_login', '~/.profile', '~/.bash_logout', '~/.zshrc', '~/.zprofile',
        '~/.zshenv', '~/.zlogin', '~/.config/fish/config.fish', '/etc/profile', '/etc/profile.d/*',
        '/etc/bash.bashrc', '/etc/bashrc', '/etc/zsh/*', '/etc/environment')),
    ('ssh', 'T1098.004', 'HIGH', (
        '~/.ssh/authorized_keys', '~/.ssh/authorized_keys2', '~/.ssh/rc', '/etc/ssh/sshd_config',
        '/etc/ssh/sshd_config.d/*', '/etc/ssh/sshrc', '/root/.ssh/authorized_keys')),
    ('preload', 'T1574.006', 'CRITICAL', ('/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d/*')),
    ('sudoers', 'T1548.003', 'HIGH', ('/etc/sudoers', '/etc/sudoers.d/*')),
    ('pam', 'T1556.003', 'HIGH', ('/etc/pam.d/*', '/etc/security/pam_env.conf')),
    ('init', 'T1037.004', 'MEDIUM', ('/etc/rc.local', '/etc/init.d/*', '/etc/udev/rules.d/*')),
    ('module_config', 'T1547.006', 'MEDIUM', ('/etc/modules', '/etc/modules-load.d/*', '/etc/modprobe.d/*')),
)
TECHNIQUES = {category: technique for category, technique, _, _ in LOCATIONS} | {
    'kernel_module': 'T1547.006', 'setuid': 'T1548.001', 'account': 'T1136.001'}
SEVERITY = {category: severity for category, _, severity, _ in LOCATIONS} | {
    'kernel_module': 'HIGH', 'setuid': 'HIGH', 'account': 'MEDIUM'}
RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


class PersistenceError(ValueError):
    pass


# ------------------------------------------------------------------ signs of an intruder's entry
#
# What a startup file, job or service runs is read for a few signs that are rare in legitimate entries and
# common in an intruder's. They are labels with a line number: no content is stored. Only the lines an entry
# runs are read (a unit's Exec lines, a crontab's commands, a script's lines), never comments.

TEMPORARY_FOLDERS = ('/tmp/', '/var/tmp/', '/dev/shm/')
SYSTEM_PREFIXES = ('/usr/', '/var/', '/etc/', '/opt/', '/lib', '/bin/', '/sbin/', '/srv/', '/boot/')
INTERPRETERS = re.compile(r'(?:ba|da|z|k|mk|a)?sh|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|lua')
LAUNCHERS = frozenset({'sudo', 'nohup', 'setsid', 'exec', 'env', 'nice', 'ionice', 'command', 'builtin', 'time',
                       'chrt', 'taskset', 'stdbuf', 'flock'})
FETCHERS = r'(?:curl|wget|fetch|lwp-download|aria2c)'
SHELL_NAME = r'(?:/\S*/)?(?:(?:ba|da|z|k)?sh|python[0-9.]*|perl[0-9.]*)'
SHELL = rf'(?:sudo\s+)?{SHELL_NAME}\b'
SUBSTITUTED = rf'(?:\$\(|`)\s*{FETCHERS}\b'
PATTERNS = (
    ('download_into_shell', re.compile(rf'\b{FETCHERS}\b[^|;&\n]*\|\s*{SHELL}')),
    # A download substituted where its output is run: as the command itself, by eval or exec, by sh -c, or fed to
    # source or a shell as a file. One only assigned to a variable or passed as an argument is not run.
    ('download_into_shell', re.compile(rf'(?:^|[;&|]|\b(?:then|do|else))\s*["\']?{SUBSTITUTED}')),
    ('download_into_shell', re.compile(rf'\b(?:eval|exec)\s+["\']?{SUBSTITUTED}')),
    ('download_into_shell', re.compile(rf'\b{SHELL_NAME}\s+(?:-\S+\s+)*-c\s+["\']?{SUBSTITUTED}')),
    ('download_into_shell', re.compile(
        rf'(?:\b(?:source|{SHELL_NAME})|(?:^|[;&|])\s*\.)\s+(?:-\S+\s+)*<\(\s*{FETCHERS}\b')),
    ('decoded_into_shell', re.compile(rf'\bbase(?:64|32)\s+(?:-d|--decode|-D)\b[^;&\n]*\|\s*{SHELL}')),
    ('shell_network_redirect', re.compile(r'/dev/(?:tcp|udp)/[^/\s]+/\d+')),
)
SIGN_SEVERITY = {'runs_from_temporary': 'HIGH', 'runs_from_hidden_folder': 'HIGH', 'download_into_shell': 'HIGH',
                 'decoded_into_shell': 'HIGH', 'shell_network_redirect': 'CRITICAL', 'preload_library': 'CRITICAL',
                 'second_uid_0': 'CRITICAL'}
SYSTEM_CRONTABS = ('/etc/crontab', '/etc/cron.d/')
PLAIN_PATH = re.compile(r'/[A-Za-z0-9_./+@:-]+')
MAX_SIGNS = 20


def _commands(text, category, path):
    """(line number, command text) for what an entry runs; comments and settings are left out."""
    name = os.path.basename(path)
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if category == 'systemd' or (category == 'autostart' and name.endswith('.desktop')):
            key, _, value = line.partition('=')
            if re.fullmatch(r'Exec[A-Za-z]*|TryExec', key.strip()):
                yield number, value.strip().lstrip('@-:+!|')
            continue
        if category == 'init' and name.endswith('.rules'):
            for value in re.findall(r'\bRUN\{?[a-z]*\}?\s*\+?=\s*"([^"]*)"', line):
                yield number, value
            continue
        if category == 'cron' and not path.startswith(('/etc/cron.hourly/', '/etc/cron.daily/', '/etc/cron.weekly/',
                                                       '/etc/cron.monthly/')):
            fields = line.split()  # A setting (MAILTO=, PATH=) has no command fields.
            if name == 'anacrontab':
                command = fields[3:]
            elif fields[0].startswith('@'):
                command = fields[1:]
            else:
                command = fields[5:]
            if command and path.startswith(SYSTEM_CRONTABS) and not command[0].startswith(('/', '$', '~', '.')):
                command = command[1:]  # The user field of a system crontab.
            yield number, ' '.join(command)
            continue
        yield number, line  # A script, an at job, a shell startup file, ~/.ssh/rc.


def _tokens(command):
    """Shell words and separators, quotes respected; a whitespace split if the quoting does not balance."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|()<>`')
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        return list(lexer)
    except ValueError:
        return command.split()


def _run_words(command, depth=0):
    """The programs and scripts a command line starts: each segment's first word, a script handed to an
    interpreter, and what an interpreter's ``-c`` runs."""
    segment, inputs, redirect = [], [], None
    for token in _tokens(command) + [';']:
        if redirect:
            if redirect == 'in':
                inputs.append(token)  # A file on standard input: a script, if a shell reads it.
            redirect = None
        elif token and set(token) <= set(';&|()<>`') and ('<' in token or '>' in token) and not set(token) & set('()'):
            redirect = 'in' if '<' in token and '>' not in token else 'out'  # The next word is a file, not a command.
        elif token and set(token) <= set(';&|()<>`'):
            yield from _segment_words(segment, depth, inputs)
            segment, inputs = [], []
        else:
            segment.append(token)


def _segment_words(words, depth, inputs=()):
    while words and (words[0] in LAUNCHERS or words[0] in ('{', '}', '!', 'then', 'do', 'else', 'if', 'while')
                     or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', words[0]) or words[0].startswith('-')):
        words = words[1:]
    if not words:
        return
    yield words[0]
    if INTERPRETERS.fullmatch(os.path.basename(words[0])):
        rest = words[1:]
        if '-c' in rest and rest.index('-c') + 1 < len(rest) and depth < 2:
            yield from _run_words(rest[rest.index('-c') + 1], depth + 1)
        elif '-e' not in rest:
            scripts = [word for word in rest if not word.startswith('-')]
            if scripts:
                yield scripts[0]
            elif inputs:
                yield inputs[0]  # sh < /tmp/script


def _signs(text, category, path):
    """Signs of an intruder's entry in what it runs, as {sign, line}."""
    found = []
    for number, command in _commands(text, category, path):
        for word in _run_words(command):
            if not PLAIN_PATH.fullmatch(word):
                continue  # A pattern, a variable or a quoted fragment, not a program it runs.
            if word.startswith(TEMPORARY_FOLDERS):
                found.append(dict(sign='runs_from_temporary', line=number))
            elif word.startswith(SYSTEM_PREFIXES) and any(
                    part.startswith('.') and part not in ('.', '..') for part in word.split('/')):
                found.append(dict(sign='runs_from_hidden_folder', line=number))
        for sign, pattern in PATTERNS:
            if pattern.search(command):
                found.append(dict(sign=sign, line=number))
    unique = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique[:MAX_SIGNS]


def _preload_libraries(text):
    return [dict(sign='preload_library', line=number) for number, raw in enumerate(text.splitlines(), 1)
            if raw.strip() and not raw.strip().startswith('#')][:MAX_SIGNS]


SIGN_CATEGORIES = ('systemd', 'cron', 'at', 'autostart', 'shell_startup', 'init')


# Categories whose entries are services, jobs or startup files; the others are not something to disable.
DISABLE_CATEGORIES = ('systemd', 'cron', 'at', 'autostart', 'shell_startup', 'ssh', 'preload', 'sudoers', 'pam',
                      'init', 'module_config')


def why_not_disabled(category, location):
    """Why an entry cannot be disabled by moving it aside, or None. Only locations this watch covers qualify."""
    if category not in DISABLE_CATEGORIES:
        return 'not a service, job or startup entry'
    parts = location.split('/')
    if any(part in ('', '.', '..') for part in parts[1:]) or not (location.startswith('/') or
                                                                  location.startswith('~/') or _owner(location)):
        return 'not a plain path'
    patterns = next(p for c, _t, _s, p in LOCATIONS if c == category)
    # ~NAME/... is the same location in another account's home: it matches the pattern's ~/....
    first = '~' if _owner(location) else parts[0]
    if not any(len(pattern.split('/')) == len(parts) and
               all(fnmatch.fnmatchcase(part, piece) for part, piece in zip([first, *parts[1:]], pattern.split('/')))
               for pattern in patterns):
        return 'not a location the persistence watch covers'
    if os.path.basename(location).startswith('megalodon'):
        return "MEGALODON's own: disabling it would turn off a watch"
    return None


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _owner(location):
    """The account NAME of a ~NAME/... location, or None."""
    head, slash, _ = location.partition('/')
    if slash and head.startswith('~') and ACCOUNT_NAME.fullmatch(head[1:]):
        return head[1:]
    return None


def home_folder(home, root='/'):
    """Where an account's home is on this machine, or None when it is not a home to watch."""
    # normpath keeps a leading //, which is still /.
    plain = '/' + os.path.normpath(home).lstrip('/') if home.startswith('/') else None
    if plain is None or plain in NOT_HOMES or plain.startswith(tuple(f'{h}/' for h in NOT_HOMES[1:])):
        return None
    path = _expand(plain, root, '')
    return path if os.path.isdir(path) else None


def other_homes(root, accounts, own_home):
    """(name, folder) for every account whose home is a real folder other than this account's own, once each."""
    seen = {os.path.realpath(own_home)}
    found = []
    for name, account in sorted((accounts or {}).items(), key=lambda item: (item[1]['uid'], item[0])):
        if not ACCOUNT_NAME.fullmatch(name):
            continue
        folder = home_folder(account['home'], root)
        if folder is None or os.path.realpath(folder) in seen:
            continue
        seen.add(os.path.realpath(folder))
        found.append((name, folder))
        if len(found) >= MAX_HOMES:
            break
    return sorted(found)


def _expand(pattern, root, home):
    if pattern.startswith('~/'):
        return os.path.join(home, pattern[2:])
    return os.path.join(root, pattern.lstrip('/')) if root != '/' else pattern


def _display(path, root, home):
    """A stable key for a path: ~/... under the home folder, otherwise its system path."""
    if path == home or path.startswith(home.rstrip('/') + '/'):
        return '~/' + os.path.relpath(path, home)
    return '/' + os.path.relpath(path, root) if root != '/' else path


def _ssh_keys(data):
    """(type, SHA256 fingerprint, comment) for each key line; options are not kept."""
    keys = []
    for line in data.decode('utf-8', 'replace').splitlines():
        parts = line.strip().split()
        for i, part in enumerate(parts):
            if part.startswith(('ssh-', 'ecdsa-', 'sk-')) and i + 1 < len(parts):
                try:
                    blob = base64.b64decode(parts[i + 1], validate=True)
                except ValueError:
                    break
                fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
                keys.append(dict(type=part, fingerprint='SHA256:' + fingerprint,
                                 comment=' '.join(parts[i + 2:])[:80]))
                break
    return keys


def _describe(path, category, shown=None):
    """Metadata for one path, never following links; None if absent; 'unreadable' if not readable.

    ``shown`` is the path as reports show it (``/etc/cron.d/job``), which decides how a file is read for signs."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return 'unreadable'
    entry = dict(mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid)
    if stat.S_ISLNK(info.st_mode):
        try:
            entry.update(kind='link', target=os.readlink(path)[:1024])
        except OSError:
            return 'unreadable'
        if category in SIGN_CATEGORIES and entry['target'].startswith(TEMPORARY_FOLDERS):
            entry['signs'] = [dict(sign='runs_from_temporary', line=0)]
        return entry
    if stat.S_ISDIR(info.st_mode):
        return None  # Folders are covered by the patterns that list their files.
    if not stat.S_ISREG(info.st_mode):
        entry.update(kind='special')
        return entry
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except PermissionError:
        return 'unreadable'
    except OSError:
        return None
    try:
        data = os.read(fd, MAX_FILE_BYTES)
    finally:
        os.close(fd)
    entry.update(kind='file', size=info.st_size, sha256=hashlib.sha256(data).hexdigest(),
                 lines=data.count(b'\n') + (1 if data and not data.endswith(b'\n') else 0))
    if category == 'ssh' and os.path.basename(path).startswith('authorized_keys'):
        entry['keys'] = _ssh_keys(data)
    text = data.decode('utf-8', 'replace')
    if category in SIGN_CATEGORIES or (category == 'ssh' and os.path.basename(path) in ('rc', 'sshrc')):
        signs = _signs(text, category, shown or path)
    elif category == 'preload' and os.path.basename(path) == 'ld.so.preload':
        signs = _preload_libraries(text)
    else:
        signs = []
    if signs:
        entry['signs'] = signs
    return entry


def _accounts(root):
    try:
        lines = Path(_expand('/etc/passwd', root, '')).read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return None
    accounts = {}
    for line in lines[:MAX_ENTRIES]:
        parts = line.split(':')
        if len(parts) >= 7 and parts[0] and not parts[0].startswith(('#', '+', '-')):
            try:
                accounts[parts[0]] = dict(uid=int(parts[2]), gid=int(parts[3]), home=parts[5][:256],
                                          shell=parts[6][:256])
            except ValueError:
                continue
    return accounts


def _modules(root):
    try:
        text = Path(_expand('/proc/modules', root, '')).read_text(encoding='ascii', errors='replace')
    except OSError:
        return None
    return sorted({line.split()[0] for line in text.splitlines() if line.split()})[:MAX_ENTRIES]


def _setuid(root, directories):
    found, walked = {}, 0
    for directory in directories:
        top = _expand(directory, root, '')
        for folder, dirs, files in os.walk(top, followlinks=False):
            for name in files:
                walked += 1
                if walked > MAX_SETUID_WALK:
                    return found, True
                path = os.path.join(folder, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    described = _describe(path, 'setuid')
                    if isinstance(described, dict):
                        found[_display(path, root, '/nonexistent-home')] = described
    return found, False


def snapshot(*, root='/', home=None, setuid_dirs=SETUID_DIRS, all_homes=None):
    """The current state of every location, and the locations that could not be read.

    With `all_homes` (the default for root), each ~/ location is also read in every other account's home.
    """
    home = home or str(Path.home())
    all_homes = os.geteuid() == 0 if all_homes is None else all_homes
    entries, gaps = {}, []
    accounts = _accounts(root)
    if accounts is None:
        gaps.append(dict(category='account', location='/etc/passwd'))
    homes = other_homes(root, accounts, home) if all_homes else []

    def record(category, pattern, folder, prefix):
        expanded = _expand(pattern, root, folder)
        parent = os.path.dirname(expanded)
        shown = prefix + pattern[2:] if prefix else pattern
        if any(ch in expanded for ch in '*?[') and os.path.isdir(parent) and not os.access(parent, os.R_OK | os.X_OK):
            gaps.append(dict(category=category, location=shown))
            return
        matches = glob.glob(expanded) if any(ch in expanded for ch in '*?[') else [expanded]
        for path in sorted(matches)[:2000]:
            described = _describe(path, category, _display(path, root, folder))
            if described is None:
                continue
            key = _display(path, root, folder)
            if prefix and key.startswith('~/'):
                key = prefix + key[2:]
            if described == 'unreadable':
                gaps.append(dict(category=category, location=key))
                continue
            entries[f'{category}:{key}'] = dict(described, category=category)
            if len(entries) > MAX_ENTRIES:
                raise PersistenceError('too many persistence entries to record')

    for category, _, _, patterns in LOCATIONS:
        for pattern in patterns:
            record(category, pattern, home, None)
            if pattern.startswith('~/'):
                for name, folder in homes:
                    record(category, pattern, folder, f'~{name}/')
    if not all_homes:
        gaps.append(dict(category='home', location="other accounts' homes: run as root to read them"))
    modules = _modules(root)
    if modules is None:
        gaps.append(dict(category='kernel_module', location='/proc/modules'))
    setuid, truncated = _setuid(root, setuid_dirs)
    if truncated:
        gaps.append(dict(category='setuid', location='walk limit reached'))
    return dict(entries=entries, accounts=accounts or {}, modules=modules or [], setuid=setuid, gaps=gaps,
                all_homes=bool(all_homes), homes={name: accounts[name]['home'] for name, _ in homes})


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.persistence-', dir=path.parent)
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
        raise PersistenceError(f'no persistence baseline at {path}; run megalodon persistence baseline') from None
    except OSError as exc:
        raise PersistenceError(f'persistence baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PersistenceError(f'persistence baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise PersistenceError('persistence baseline is too large')
    try:
        value = json.loads(raw)
    except ValueError:
        raise PersistenceError('persistence baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA:
        raise PersistenceError('persistence baseline has an unsupported format')
    return value


def _worst(signs):
    return max((SIGN_SEVERITY[item['sign']] for item in signs), key=RANK.__getitem__)


def suspicious(state):
    """Entries in a snapshot that carry signs of an intruder's, most severe first: what a baseline must not
    record as normal without saying so."""
    found = []
    for key, entry in state['entries'].items():
        if entry.get('signs'):
            category, location = key.split(':', 1)
            found.append(dict(category=category, location=location, technique=TECHNIQUES[category],
                              severity=_worst(entry['signs']), signs=entry['signs']))
    for name, account in state['accounts'].items():
        if account['uid'] == 0 and name != 'root':
            found.append(dict(category='account', location=name, technique=TECHNIQUES['account'],
                              severity='CRITICAL', signs=[dict(sign='second_uid_0', line=0)]))
    found.sort(key=lambda item: (-RANK[item['severity']], item['category'], item['location']))
    return found


SUSPICIOUS_NOTE = ('These entries carry signs of an intruder\'s: review each one before trusting the baseline. '
                   'Nothing was changed.')


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, **options):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise PersistenceError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(**options)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), user=os.geteuid(), signs_reviewed=True, **state))
    report = dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), entries=len(state['entries']),
                  accounts=len(state['accounts']), modules=len(state['modules']), setuid=len(state['setuid']),
                  homes=sorted(state['homes']), gaps=state['gaps'], suspicious=suspicious(state))
    if report['suspicious']:
        report['note'] = SUSPICIOUS_NOTE
    return report


def scan(**options):
    """Entries with signs of an intruder's in the current state; no baseline is read or written."""
    state = snapshot(**options)
    found = suspicious(state)
    return dict(schema=REPORT_SCHEMA, action='scan', checked_at=_now(), entries=len(state['entries']),
                suspicious=found, gaps=state['gaps'], note=SUSPICIOUS_NOTE if found else 'Nothing was changed.')


def _finding(change, category, location, severity, detail=None):
    item = dict(change=change, category=category, location=location, technique=TECHNIQUES[category],
                severity=severity if change != 'removed' else 'LOW')
    if detail:
        item['detail'] = detail
    return item


def _compare_entry(key, old, new):
    category, location = key.split(':', 1)
    severity = SEVERITY[category]
    if old is None:
        detail = {'kind': new.get('kind')}
        if new.get('keys'):
            detail['keys_added'] = new['keys'][:20]
        if new.get('kind') == 'link':
            detail['target'] = new['target']
        if new.get('signs'):
            detail['signs'] = new['signs']
            severity = max(severity, _worst(new['signs']), key=RANK.__getitem__)
        return _finding('added', category, location, severity, detail)
    if new is None:
        return _finding('removed', category, location, severity)
    changes = {k: [old.get(k), new.get(k)] for k in ('kind', 'sha256', 'mode', 'uid', 'target') if old.get(k) != new.get(k)}
    if not changes:
        return None
    detail = dict(changed=sorted(changes))
    if 'sha256' in changes:
        detail['lines'] = [old.get('lines'), new.get('lines')]
    if 'mode' in changes or 'uid' in changes:
        detail.update({k: changes[k] for k in ('mode', 'uid') if k in changes})
    if 'target' in changes:
        detail['target'] = changes['target']
    if new.get('keys') is not None:
        before = {k['fingerprint'] for k in old.get('keys', [])}
        added = [k for k in new['keys'] if k['fingerprint'] not in before]
        if added:
            detail['keys_added'] = added[:20]
            severity = 'CRITICAL'
    if new.get('signs'):
        detail['signs'] = new['signs']
        severity = max(severity, _worst(new['signs']), key=RANK.__getitem__)
    return _finding('changed', category, location, severity, detail)


def _interactive(shell):
    return bool(shell) and not os.path.basename(shell).startswith(_SHELLS_NOLOGIN)


def _in_other_home(key):
    return _owner(key.split(':', 1)[1]) is not None


def newly_watched(old, new):
    """Homes this check reads that the baseline was not taken over: a baseline from before every account's home was
    watched, or one taken without root. Their entries are listed, not reported as added."""
    if old.get('all_homes') is True or not new.get('all_homes'):
        return []
    found = {}
    for key, entry in new['entries'].items():
        name = _owner(key.split(':', 1)[1])
        if name is None:
            continue
        item = found.setdefault(name, dict(account=name, home=new.get('homes', {}).get(name), entries=0, keys=[]))
        item['entries'] += 1
        item['keys'] += [k['fingerprint'] for k in entry.get('keys', [])][:20]
    return [found[name] for name in sorted(found)]


def compare(old, new):
    findings = []
    keys = set(old['entries']) | set(new['entries'])
    if not new.get('all_homes') or old.get('all_homes') is not True:
        # Other accounts' homes are compared only when both sides read them: without root they cannot be read
        # (that is a gap, not a removal), and a baseline that never read them has nothing to compare with.
        keys = {key for key in keys if not _in_other_home(key)}
    for key in sorted(keys):
        item = _compare_entry(key, old['entries'].get(key), new['entries'].get(key))
        if item:
            findings.append(item)
    for path in sorted(set(old['setuid']) | set(new['setuid'])):
        before, after = old['setuid'].get(path), new['setuid'].get(path)
        if before is None:
            findings.append(_finding('added', 'setuid', path, 'HIGH', dict(mode=after['mode'], uid=after['uid'])))
        elif after is None:
            findings.append(_finding('removed', 'setuid', path, 'HIGH'))
        elif any(before.get(k) != after.get(k) for k in ('sha256', 'mode', 'uid')):
            # A new owner changes whose privileges a setuid program runs with.
            findings.append(_finding('changed', 'setuid', path, 'HIGH', {
                k: [before.get(k), after.get(k)] for k in ('mode', 'uid') if before.get(k) != after.get(k)}
                | ({'content': 'changed'} if before.get('sha256') != after.get('sha256') else {})))
    for name in sorted(set(new['modules']) - set(old['modules'])):
        findings.append(_finding('added', 'kernel_module', name, 'HIGH'))
    for name in sorted(set(old['accounts']) | set(new['accounts'])):
        before, after = old['accounts'].get(name), new['accounts'].get(name)
        if before is None:
            findings.append(_finding('added', 'account', name, 'CRITICAL' if after['uid'] == 0 else 'MEDIUM',
                                     dict(uid=after['uid'], shell=after['shell'])))
        elif after is None:
            findings.append(_finding('removed', 'account', name, 'MEDIUM'))
        elif before != after:
            severity = ('CRITICAL' if after['uid'] == 0 and before['uid'] != 0 else
                        'HIGH' if _interactive(after['shell']) and not _interactive(before['shell']) else 'MEDIUM')
            findings.append(_finding('changed', 'account', name, severity,
                                     {k: [before[k], after[k]] for k in before if before[k] != after.get(k)}))
    findings.sort(key=lambda item: (-RANK[item['severity']], item['category'], item['location']))
    return findings


def check(manifest=DEFAULT_MANIFEST, **options):
    old = _read(manifest)
    new = snapshot(**options)
    findings = compare(old, new)
    counts = {level: sum(1 for f in findings if f['severity'] == level) for level in RANK}
    report = dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                  baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), findings=findings,
                  severity_counts=counts, gaps=new['gaps'],
                  note='Review each change; accept records the reviewed state. Nothing was changed.')
    if not old.get('signs_reviewed'):
        # A baseline from before entries were read for signs: what it recorded was never reviewed for them.
        report['suspicious'] = suspicious(new)
        if report['suspicious']:
            report['note'] += (f' The baseline was taken before entries were read for signs of an intruder\'s; '
                               f'{len(report["suspicious"])} are listed under suspicious. Review them, then run accept.')
    watched = newly_watched(old, new)
    if watched:
        report['newly_watched'] = watched
        report['note'] = ('Review each change; accept records the reviewed state. Nothing was changed. '
                          f'{len(watched)} other accounts\' homes are read now but were not in the baseline: their '
                          'entries are listed under newly_watched, not compared. Review them, then run accept to '
                          'start watching them.')
    return report


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)  # Only an existing, private baseline can be replaced.
    return dict(baseline(manifest, replace=True, **options), action='accept')
