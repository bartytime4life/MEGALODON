"""Exposed secrets: keys, tokens and passwords other people can read.

Secrets are meant to sit where only their owner can read them. They leak when:
- a private key or credential file can be read by other accounts;
- a token sits in a file, or a shell history, that others can read;
- a password is passed on a command line, which every local user can see;
- a copy of a configuration file, a database dump, an `.env` file or a `.git`
  folder is left under a web root, where a server may hand it to anyone.

Intruders look for exactly these (ATT&CK T1552.001, T1552.003, T1552.004).
`megalodon secrets` finds them and reports where each one is and who can read
it.

Read-only. A file is read only when someone other than its owner can reach and
read it, or when it is under a web root. Secret values never appear in a
report: a finding names the kind of secret, where it is, its length and, for
tokens, a short fingerprint.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

SCHEMA = 'megalodon-secrets-scan-v1'
REPORT_SCHEMA = 'megalodon-secrets-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/secrets.json'
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_READ = 1024 * 1024
MAX_FILES = 500_000
MAX_SECONDS = 120
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
# Where secrets are kept, and where they are left behind.
SEARCH = ('/etc', '/home', '/root', '/srv', '/opt', '/var/www', '/usr/local/etc', '/var/backups', '/var/lib/jenkins',
          '/tmp', '/var/tmp', '/dev/shm')
WEB_ROOTS = ('/var/www', '/srv/www', '/srv/http', '/usr/share/nginx/html', '/var/lib/tomcat*/webapps',
             '/opt/tomcat*/webapps')
# Installed code, caches and test data: libraries and SDKs ship sample keys and example passwords by the hundred.
SKIP_DIRS = frozenset({'node_modules', '__pycache__', 'site-packages', 'dist-packages', '.cache', '.npm', '.cargo',
                       '.rustup', '.venv', 'venv', '.tox', 'vendor', '.git', '.svn', '.hg', 'gems', 'third_party',
                       'tests', 'test', 'testdata', 'test_data', 'fixtures', 'spec', 'examples', 'doc', 'docs',
                       '.rbenv', '.pyenv', '.nvm', 'go', '.gradle', '.m2'})
# A password in a URL is reported in these, not in library code and documentation, where examples are everywhere.
CONFIG_TYPES = ('.env', '.conf', '.cfg', '.ini', '.yml', '.yaml', '.json', '.toml', '.properties', '.xml', '.txt',
                '.sh', '.bash', '.zsh', '.cnf', '.rc', '.tfvars', '.service', '.timer', '.netrc', '.npmrc', '.pypirc')
EXAMPLE_HOSTS = re.compile(r'(?:^|\.)(?:example\.(?:com|org|net)|example|host|hostname|server|domain\.tld)$', re.I)
# Groups whose members are meant to read these files: shadow for the password files, ssl-cert for TLS keys.
DESIGNED_GROUPS = frozenset({'shadow', 'ssl-cert'})

HOME_CREDENTIALS = ('.ssh/id_*', '.aws/credentials', '.docker/config.json', '.kube/config', '.netrc', '.pgpass',
                    '.my.cnf', '.git-credentials', '.npmrc', '.pypirc', '.vault-token',
                    '.config/gcloud/credentials.db', '.config/gcloud/application_default_credentials.json',
                    '.config/gh/hosts.yml', '.azure/accessTokens.json', '.azure/msal_token_cache.json',
                    '.terraform.d/credentials.tfrc.json')
SYSTEM_CREDENTIALS = ('/etc/shadow', '/etc/shadow-', '/etc/gshadow', '/etc/gshadow-', '/var/backups/shadow.bak',
                      '/var/backups/gshadow.bak', '/etc/ssh/ssh_host_*_key', '/etc/NetworkManager/system-connections/*',
                      '/etc/wpa_supplicant/*.conf', '/etc/ppp/chap-secrets', '/etc/ppp/pap-secrets',
                      '/etc/ipsec.secrets', '/etc/wireguard/*.conf', '/etc/openvpn/*.key', '/etc/openvpn/*/*.key',
                      '/etc/letsencrypt/archive/*/privkey*.pem', '/etc/letsencrypt/keys/*', '/etc/krb5.keytab',
                      '/etc/ldap.secret', '/etc/pam_ldap.secret', '/etc/ssl/private/*', '/etc/mysql/debian.cnf',
                      '/etc/rancher/k3s/k3s.yaml', '/etc/kubernetes/admin.conf', '/etc/kubernetes/pki/*.key')

# Token shapes that are specific enough to report on sight.
TOKENS = (
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('GitHub token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36}\b')),
    ('GitHub token', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b')),
    ('GitLab token', re.compile(r'\bglpat-[A-Za-z0-9_-]{20}\b')),
    ('Slack token', re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}')),
    ('Slack webhook', re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}')),
    ('Stripe live key', re.compile(r'\b[rs]k_live_[A-Za-z0-9]{24,}')),
    # Often public by design (browser and SDK client keys); see LOOSE.
    ('Google API key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('Anthropic API key', re.compile(r'\bsk-ant-[a-z0-9]+-[A-Za-z0-9_-]{32,}')),
    ('npm token', re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),
    ('PyPI token', re.compile(r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}')),
)
# Reported only in configuration files and histories: program code ships these as examples and public client keys.
LOOSE = frozenset({'Google API key', 'password in a URL'})
# Text each token shape must contain: a pattern is only run over a file that has it, which is most of the cost saved.
MARKERS = {'AWS access key': ('AKIA', 'ASIA'), 'GitHub token': ('gh', 'github_pat_'), 'GitLab token': ('glpat-',),
           'Slack token': ('xox',), 'Slack webhook': ('hooks.slack.com',), 'Stripe live key': ('_live_',),
           'Google API key': ('AIza',), 'Anthropic API key': ('sk-ant-',), 'npm token': ('npm_',),
           'PyPI token': ('pypi-',)}
PRIVATE_KEY = re.compile(r'-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----\s*'
                         r'([\s\S]{0,16384}?)-----END')
KEY_HEADER = re.compile(r'^[A-Za-z-]+: .*$')
URL_PASSWORD = re.compile(r'\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@\'"]{1,64}:([^\s/@\'"]{3,128})@([A-Za-z0-9.-]+)')
PLACEHOLDERS = frozenset({'password', 'passwd', 'pass', 'secret', 'changeme', 'change_me', 'example', 'xxx', 'xxxx',
                          'yourpassword', 'your_password', 'redacted', 'none', 'null', 'test', 'token'})
# Command-line options that take a secret as their value.
SECRET_OPTIONS = frozenset({'--password', '--passwd', '--pass', '--token', '--api-key', '--apikey', '--api-token',
                            '--secret', '--client-secret', '--access-token', '--auth-token'})
PASSWORD_DASH_P = frozenset({'mysql', 'mysqldump', 'mariadb', 'mariadb-dump', 'mysqladmin'})
# Under a web root, anything but a server-side script may be handed out as it is.
SCRIPTS = ('.php', '.py', '.rb', '.jsp', '.asp', '.aspx', '.cgi', '.pl')
COPY_SUFFIXES = ('.bak', '.old', '.orig', '.save', '.swp', '~', '.backup', '.copy', '.1', '.tmp')
CONFIG_NAMES = ('config', 'settings', 'database', 'wp-config', 'local_settings', 'configuration', '.env')

RULES = {
    'SECRET_FILE_IN_WEB_ROOT': ('CRITICAL', ['T1552.001'],
                                'A file that holds secrets is under a web root, where a server may hand it to '
                                'anyone: an .env file, a copy of a configuration script, a database dump or a key.'),
    'VERSION_CONTROL_IN_WEB_ROOT': ('CRITICAL', ['T1552.001'],
                                    'A .git, .svn or .hg folder is under a web root: anyone who can fetch it gets the '
                                    'source code, its history and the secrets ever committed.'),
    'SECRET_IN_WEB_ROOT': ('CRITICAL', ['T1552.001'],
                           'A token or private key is in a file a web server may hand out as it is.'),
    'PRIVATE_KEY_EXPOSED': ('CRITICAL', ['T1552.004'], 'A private key can be read by other accounts.'),
    'CREDENTIAL_FILE_EXPOSED': ('CRITICAL', ['T1552.001'],
                                'A password file or credential store can be read by other accounts.'),
    'SECRET_IN_COMMAND_LINE': ('HIGH', ['T1552'],
                               'A password or token was passed on a command line, which every local user can see.'),
    'SECRET_IN_EXPOSED_FILE': ('HIGH', ['T1552.001', 'T1552.003'],
                               'A token or password is in a file, or a shell history, that other accounts can read.'),
}


class SecretsError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _finding(rule, subject, detail, severity=None, **extra):
    default, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity or default, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


def _a(text):
    return ('an ' if text[:1].lower() in 'aeiou' else 'a ') + text


def _lower(severity):
    return RANK[min(RANK.index(severity) + 1, len(RANK) - 1)]


# ------------------------------------------------------------------ what a secret looks like, without showing it

def _placeholder(value):
    plain = value.strip('\'"').lower()
    return (plain in PLACEHOLDERS or 'example' in plain or len(set(plain)) < 4
            or re.fullmatch(r'[x*.#-]+|\$\{?[\w.]+\}?|<[^>]*>|%\(?\w+\)?s?|\{\{.*\}\}|\$\(.*\)', plain) is not None)


def _fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _shown(kind, value, *, token):
    """What a report says about a secret: its kind and length, and for tokens a fingerprint.

    A password's fingerprint would let anyone holding the report test guesses against it, so passwords get none.
    """
    text = f'{kind} ({len(value)} characters'
    return text + (f', sha256 {_fingerprint(value)})' if token else ')')


def _openssh_encrypted(body):
    try:
        data = base64.b64decode(''.join(body.split()), validate=False)
    except ValueError:
        return None
    if not data.startswith(b'openssh-key-v1\x00') or len(data) < 19:
        return None
    size = int.from_bytes(data[15:19], 'big')
    return data[19:19 + size] != b'none'


def _key_body(body):
    """Whether a private key block holds key material: base64 lines, not a header string in code or documentation."""
    lines = [line.strip() for line in body.strip().splitlines() if line.strip()]
    data = ''.join(line for line in lines if not KEY_HEADER.match(line))
    return len(data) >= 64 and re.fullmatch(r'[A-Za-z0-9+/=]+', data) is not None


def secrets_in(text, *, passwords=True):
    """[(kind, shown, fingerprint or None, line)] for every secret in a text; tokens only are fingerprinted.

    passwords=False leaves out the LOOSE kinds: library code and documentation are full of example passwords in
    URLs, and SDKs ship Google API keys that are public by design.
    """
    found = []

    def line_of(index):
        return text.count('\n', 0, index) + 1
    for match in PRIVATE_KEY.finditer(text) if 'PRIVATE KEY' in text else ():
        label, body = match.group(1), match.group(2)
        if not _key_body(body):
            continue
        encrypted = 'ENCRYPTED' in label or 'Proc-Type: 4,ENCRYPTED' in body or bool(
            label.startswith('OPENSSH') and _openssh_encrypted(body))
        kind = ('encrypted ' if encrypted else '') + 'private key'
        found.append((kind, kind, None, line_of(match.start())))
    tokens = []
    for kind, pattern in TOKENS:
        if kind in LOOSE and not passwords or not any(marker in text for marker in MARKERS[kind]):
            continue
        for match in pattern.finditer(text):
            value = match.group(0)
            tokens.append(value)
            if not _placeholder(value[4:]):
                found.append((kind, _shown(kind, value, token=True), _fingerprint(value), line_of(match.start())))
    for match in URL_PASSWORD.finditer(text) if passwords and '://' in text and '@' in text else ():
        # A token used as the password in a URL is one secret, already reported as the token.
        if any(token in match.group(1) for token in tokens):
            continue
        if not _placeholder(match.group(1)) and not EXAMPLE_HOSTS.search(match.group(2)):
            found.append(('password in a URL', _shown('password in a URL', match.group(1), token=False), None,
                          line_of(match.start())))
    return found


# ------------------------------------------------------------------ who can read a file

class _Accounts:
    """The accounts on the machine scanned and the groups each is in, from its passwd and group files."""

    def __init__(self, root):
        self.names, people = {}, []
        for line in _text(root, '/etc/passwd').splitlines():
            fields = line.split(':')
            if len(fields) > 3 and fields[2].isdigit() and fields[3].isdigit():
                people.append((fields[0], int(fields[2]), int(fields[3])))
        members = {}
        for line in _text(root, '/etc/group').splitlines():
            fields = line.split(':')
            if len(fields) > 3 and fields[2].isdigit():
                self.names[int(fields[2])] = fields[0]
                for name in fields[3].split(','):
                    if name:
                        members.setdefault(name, set()).add(int(fields[2]))
        # (name, uid, every group the account is in)
        self.people = [(name, uid, frozenset({gid} | members.get(name, set()))) for name, uid, gid in people]

    def name(self, gid):
        return self.names.get(gid, str(gid))


def _text(root, path):
    try:
        return Path(root, path.lstrip('/')).read_text('utf-8', 'replace')
    except OSError:
        return ''


class _Reach:
    """Who other than a file's owner and root can reach and read it.

    Every account is judged the way the kernel judges it: by the owner bits if it owns a file or folder, by the
    group bits if it is in its group, and by the other bits otherwise. That covers a world-readable file inside a
    folder only one group can enter, as well as a file readable by its own group.
    """

    def __init__(self, root, accounts):
        self.root, self.accounts, self.stats, self.through = root, accounts, {}, {}

    def _stat(self, path):
        if path not in self.stats:
            try:
                self.stats[path] = os.stat(os.path.join(self.root, path.lstrip('/')))
            except OSError:
                self.stats[path] = None
        return self.stats[path]

    @staticmethod
    def _allowed(info, uid, groups, bit):
        if uid == info.st_uid:
            return bool(info.st_mode & (bit << 6))
        if info.st_gid in groups:
            return bool(info.st_mode & (bit << 3))
        return bool(info.st_mode & bit)

    def _can_enter(self, folder, uid, groups):
        """Whether the account can pass through this folder and every one above it."""
        key = (folder, uid)
        if key not in self.through:
            info = self._stat(folder)
            above = True if folder == '/' else self._can_enter(os.path.dirname(folder), uid, groups)
            self.through[key] = above and info is not None and self._allowed(info, uid, groups, 0o1)
        return self.through[key]

    def who(self, path, info):
        """'everyone', 'accounts A, B', or None."""
        if not info.st_mode & 0o044:
            return None
        folder = os.path.dirname(path)
        # Any account in none of the groups involved: the other bits, all the way down.
        if info.st_mode & 0o004 and self._can_enter(folder, -1, frozenset()):
            return 'everyone'
        readers = []
        for name, uid, groups in self.accounts.people:
            if uid in (0, info.st_uid) or not self._allowed(info, uid, groups, 0o4):
                continue
            # Members of shadow and ssl-cert are meant to read the password files and TLS keys.
            if info.st_gid in groups and self.accounts.name(info.st_gid) in DESIGNED_GROUPS:
                continue
            if self._can_enter(folder, uid, groups):
                readers.append(name)
        if not readers:
            return None
        readers.sort()
        return 'accounts ' + ', '.join(readers[:4]) + (f' and {len(readers) - 4} more' if len(readers) > 4 else '')


def _severity(rule, who, encrypted=False):
    severity = RULES[rule][0] if who == 'everyone' else _lower(RULES[rule][0])
    return _lower(severity) if encrypted else severity


# ------------------------------------------------------------------ the scan

def _web_roots(root):
    found = []
    for pattern in WEB_ROOTS:
        for path in sorted(glob.glob(os.path.join(root, pattern.lstrip('/')))):
            if os.path.isdir(path) and not os.path.islink(path):
                shown = _shown_path(path, root)
                if shown not in found:
                    found.append(shown)
    return found


def _shown_path(path, root):
    """The path as it is on the machine scanned: relative to the root, with a leading slash."""
    relative = os.path.relpath(path, root)
    return '/' if relative == '.' else '/' + relative


def _sensitive_name(name):
    """Why a file name under a web root holds secrets, or None."""
    lower = name.lower()
    if lower == '.env' or lower.startswith('.env.') or lower.endswith('.env'):
        return 'an environment file'
    if lower in ('.htpasswd', '.git-credentials', '.netrc', '.pgpass', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'):
        return 'a credential file'
    if lower.endswith(('.p12', '.pfx', '.ppk', '.jks', '.keystore', '.kdbx')):
        return 'a key store'
    if lower.endswith(('.sql', '.sql.gz', '.sql.bz2', '.sql.xz', '.sqlite', '.sqlite3', '.db', '.dump')):
        return 'a database file or dump'
    for suffix in COPY_SUFFIXES:
        if lower.endswith(suffix) and len(lower) > len(suffix):
            base = lower[:-len(suffix)]
            if base.endswith(SCRIPTS) or os.path.splitext(base)[0] in CONFIG_NAMES or base in CONFIG_NAMES:
                return 'a copy of a script or configuration file, served as plain text'
    if ('backup' in lower or 'dump' in lower) and lower.endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.7z', '.rar')):
        return 'a backup archive'
    return None


def _read(path):
    """Up to MAX_READ bytes of a regular file as text, without following a symlink; None if binary or unreadable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, MAX_READ)
    except OSError:
        return None
    finally:
        os.close(fd)
    if b'\x00' in data[:8192]:
        return None
    return data.decode('utf-8', 'replace')


def _history(name):
    return name in ('.bash_history', '.zsh_history', '.sh_history', '.history', '.python_history', '.psql_history',
                    '.mysql_history', '.sqlite_history', '.node_repl_history', '.lesshst', '.viminfo')


def scan_files(root='/', *, search=SEARCH, budget=MAX_SECONDS):
    """Findings for files, and gaps."""
    real = os.path.realpath(root)
    accounts = _Accounts(real)
    reach = _Reach(real, accounts)
    findings, gaps, seen, done = [], [], 0, set()
    web = _web_roots(real)
    started = time.monotonic()

    def under_web(shown):
        return next((w for w in web if shown == w or shown.startswith(w + '/')), None)

    def look(shown, info):
        name = os.path.basename(shown)
        served = under_web(shown)
        if served:
            why = _sensitive_name(name)
            if why:
                findings.append(_finding('SECRET_FILE_IN_WEB_ROOT', f'file:{shown}',
                                         f'{shown} is {why}, under the web root {served}',
                                         'HIGH' if name.lower() == '.htpasswd' else None, path=shown))
        who = reach.who(shown, info)
        handed_out = bool(served) and not name.lower().endswith(SCRIPTS)
        if not who and not handed_out:
            return
        text = _read(os.path.join(real, shown.lstrip('/')))
        if text is None:
            return
        lower = name.lower()
        configuration = lower.endswith(CONFIG_TYPES) or _history(name) or '.' not in lower.lstrip('.') \
            or _sensitive_name(name) is not None
        reported = set()
        for kind, said, fingerprint, line in secrets_in(text, passwords=configuration):
            # One finding per secret kind and file: a dump with a hundred keys is one exposure to fix.
            if (kind, fingerprint) in reported:
                continue
            reported.add((kind, fingerprint))
            key = kind.endswith('private key')
            if handed_out:
                findings.append(_finding('SECRET_IN_WEB_ROOT', f'file:{shown}',
                                         f'{shown} line {line} holds {_a(said)}, under the web root {served}',
                                         path=shown, line=line, kind=kind, fingerprint=fingerprint))
            elif who and key:
                findings.append(_finding('PRIVATE_KEY_EXPOSED', f'file:{shown}',
                                         f'{shown} holds {_a(said)} that {who} can read',
                                         _severity('PRIVATE_KEY_EXPOSED', who, 'encrypted' in kind),
                                         path=shown, line=line, kind=kind, readable_by=who))
            elif who:
                where = 'a shell history' if _history(name) else 'a file'
                findings.append(_finding('SECRET_IN_EXPOSED_FILE', f'file:{shown}:{line}',
                                         f'{shown} ({where}) line {line} holds {_a(said)} that {who} can read',
                                         _severity('SECRET_IN_EXPOSED_FILE', who), path=shown, line=line, kind=kind,
                                         fingerprint=fingerprint, readable_by=who))

    # Credential files by name: their whole content is the secret.
    homes = {'/root'} | {line.split(':')[5] for line in _text(real, '/etc/passwd').splitlines()
                         if line.count(':') >= 6 and line.split(':')[5].startswith('/home/')}
    try:
        homes |= {f'/home/{n}' for n in os.listdir(os.path.join(real, 'home'))}
    except OSError:
        pass
    named = [p for h in sorted(homes) for pattern in HOME_CREDENTIALS
             for p in glob.glob(os.path.join(real, h.lstrip('/'), pattern)) if not p.endswith('.pub')]
    named += [p for pattern in SYSTEM_CREDENTIALS for p in glob.glob(os.path.join(real, pattern.lstrip('/')))]
    for path in sorted(set(named)):
        shown = _shown_path(path, real)
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        done.add(shown)
        who = reach.who(shown, info)
        if who:
            text = _read(path) or ''
            key = next((m for m in PRIVATE_KEY.finditer(text) if _key_body(m.group(2))), None)
            if key:
                encrypted = 'ENCRYPTED' in key.group(1) or bool(
                    key.group(1).startswith('OPENSSH') and _openssh_encrypted(key.group(2)))
                findings.append(_finding('PRIVATE_KEY_EXPOSED', f'file:{shown}',
                                         f'{shown} holds {"an encrypted" if encrypted else "a"} private key that {who} '
                                         f'can read', _severity('PRIVATE_KEY_EXPOSED', who, encrypted), path=shown,
                                         readable_by=who))
            else:
                findings.append(_finding('CREDENTIAL_FILE_EXPOSED', f'file:{shown}',
                                         f'{shown} can be read by {who}',
                                         _severity('CREDENTIAL_FILE_EXPOSED', who), path=shown, readable_by=who))

    # Every other file in the folders searched and the web roots.
    for start in dict.fromkeys([*web, *search]):
        top = os.path.join(real, start.lstrip('/'))
        if not os.path.isdir(top) or os.path.islink(top):
            continue
        for folder, dirs, files in os.walk(top, followlinks=False):
            shown_folder = _shown_path(folder, real)
            if under_web(shown_folder):
                for d in dirs:
                    if d in ('.git', '.svn', '.hg'):
                        found = os.path.join(shown_folder, d)
                        findings.append(_finding('VERSION_CONTROL_IN_WEB_ROOT', f'file:{found}',
                                                 f'{found} is under the web root {under_web(shown_folder)}',
                                                 path=found))
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                seen += 1
                if seen > MAX_FILES or time.monotonic() - started > budget:
                    gaps.append(f'only part of the folders were searched ({seen - 1} files in '
                                f'{int(time.monotonic() - started)} s)')
                    return _unique(findings), gaps
                shown = os.path.join(shown_folder, name)
                if shown in done:
                    continue
                done.add(shown)
                try:
                    info = os.lstat(os.path.join(folder, name))
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_size:
                    look(shown, info)
    return _unique(findings), gaps


def _unique(findings):
    out, keys = [], set()
    for f in findings:
        # Two tokens of one kind in one file are two secrets: each keeps its fingerprint.
        key = (f['rule_id'], f['subject'], f.get('kind'), f.get('fingerprint'))
        if key not in keys:
            keys.add(key)
            out.append(f)
    return out


def _hidden_processes(root):
    for line in _text(root, '/proc/mounts').splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[1] == '/proc' and fields[2] == 'proc':
            return any(o in ('hidepid=1', 'hidepid=2', 'hidepid=noaccess', 'hidepid=invisible')
                       for o in fields[3].split(','))
    return False


def command_line_secrets(argv):
    """[(kind, shown, fingerprint or None, argument index)] in one command line."""
    found = []
    program = os.path.basename(argv[0]) if argv else ''
    for index, arg in enumerate(argv[1:], 1):
        option, sep, inline = arg.partition('=')
        value = None
        if option in SECRET_OPTIONS:
            value = inline if sep else (argv[index + 1] if index + 1 < len(argv) else None)
            kind = f'value of {option}'
        elif program in PASSWORD_DASH_P and arg.startswith('-p') and len(arg) > 2 and not arg.startswith('--'):
            value, kind = arg[2:], 'password given with -p'
        elif program == 'sshpass' and arg == '-p' and index + 1 < len(argv):
            value, kind = argv[index + 1], 'password given with sshpass -p'
        elif option in ('-u', '--user') and program in ('curl', 'wget') and index + 1 < len(argv) \
                and ':' in argv[index + 1]:
            value, kind = argv[index + 1].split(':', 1)[1], 'password given with --user'
        if value and not _placeholder(value):
            found.append((kind, _shown(kind, value, token=False), None, index))
        for kind, said, fingerprint, _line in secrets_in(arg):
            found.append((kind, said, fingerprint, index))
    return found


def scan_processes(root='/'):
    """Findings for secrets on command lines, and gaps."""
    if _hidden_processes(root):
        return [], ['process command lines are hidden from other users (hidepid); they were not checked']
    findings = []
    proc = Path(root, 'proc')
    try:
        pids = sorted(int(p.name) for p in proc.iterdir() if p.name.isdigit())
    except OSError:
        return [], ['/proc could not be read']
    for pid in pids:
        try:
            argv = [a.decode('utf-8', 'replace') for a in (proc / str(pid) / 'cmdline').read_bytes().split(b'\0') if a]
        except OSError:
            continue
        if not argv:
            continue
        try:
            program = os.readlink(proc / str(pid) / 'exe')
        except OSError:
            program = argv[0]
        for kind, said, fingerprint, index in command_line_secrets(argv):
            findings.append(_finding('SECRET_IN_COMMAND_LINE', f'process:{pid}',
                                     f'{program} (pid {pid}) argument {index} holds {_a(said)}; anyone on this machine '
                                     f'can read it with ps', program=program, argument=index, kind=kind,
                                     fingerprint=fingerprint, identity=f'{program}:{index}:{kind}:{fingerprint}',
                                     evidence=dict(processes=[dict(pid=pid, program=program)])))
    return _unique(findings), []


def scan(root='/', *, search=SEARCH, budget=MAX_SECONDS):
    files, gaps = scan_files(root, search=search, budget=budget)
    processes, more = scan_processes(root)
    findings = sorted(files + processes, key=lambda f: (RANK.index(f['severity']), f['subject']))
    if os.geteuid() and root in ('/', ''):
        gaps.append('not run as root: other accounts\' home folders could not be searched')
    return findings, gaps + more


# ------------------------------------------------------------------ baseline, check and accept

def _identity(finding):
    """What stays the same about a finding between scans: never a process ID, never a secret's value."""
    if finding.get('identity'):
        where = finding['identity']
    else:
        # A file's secrets keep their identity when lines above them are added or removed.
        where = f"{finding.get('path')}|{finding.get('kind', '')}|{finding.get('fingerprint') or ''}|" \
                f"{finding.get('readable_by', '')}"
    return hashlib.sha256(f"{finding['rule_id']}|{where}".encode()).hexdigest()


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.secrets-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _load(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise SecretsError(f'no secrets baseline at {path}; run megalodon secrets baseline') from None
    except OSError as exc:
        raise SecretsError(f'secrets baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SecretsError(f'secrets baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise SecretsError('secrets baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('accepted')) is not list:
        raise SecretsError('secrets baseline has an unsupported format')
    return value


def report(findings, gaps, action, **extra):
    return dict(schema=REPORT_SCHEMA, action=action, checked_at=_now(), findings=findings, gaps=gaps,
                counts={s: sum(1 for f in findings if f['severity'] == s) for s in RANK}, **extra,
                note='Move each secret where only its owner can read it, or out of the web root, and replace '
                     '(rotate) any that others could have read: removing access does not undo a copy already taken.')


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, root='/', search=SEARCH, budget=MAX_SECONDS):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise SecretsError(f'{path} exists; use accept to record the reviewed state')
    findings, gaps = scan(root, search=search, budget=budget)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), root=os.path.realpath(root), search=list(search),
                      accepted=sorted({_identity(f) for f in findings})))
    # Everything found is reported now: an exposed secret is never normal, only reviewed.
    return report(findings, gaps, 'baseline', manifest=str(path))


def check(manifest=DEFAULT_MANIFEST, *, root=None, budget=MAX_SECONDS):
    old = _load(manifest)
    findings, gaps = scan(root or old.get('root', '/'), search=tuple(old.get('search') or SEARCH), budget=budget)
    accepted = set(old['accepted'])
    new = [f for f in findings if _identity(f) not in accepted]
    return report(new, gaps, 'check', manifest=str(Path(manifest).expanduser()),
                  baseline_recorded_at=old.get('recorded_at'), still_present=len(findings) - len(new))


def accept(manifest=DEFAULT_MANIFEST, *, root=None, budget=MAX_SECONDS):
    old = _load(manifest)
    return dict(baseline(manifest, replace=True, root=root or old.get('root', '/'),
                         search=tuple(old.get('search') or SEARCH), budget=budget), action='accept')
