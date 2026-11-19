"""Package sources and signing keys: where updates come from and who may sign them.

Every package the machine installs is checked against a signing key, and comes
from a source the package manager is told about. An intruder who can add a key,
point a source at their own server, or turn signature checks off gets their own
code installed as root by the next routine update; one who adds a package
manager hook gets a command run as root on every install (ATT&CK T1195.002,
T1553, T1546.016). `megalodon packages` records the sources, keys and hooks and
reports:

* sources whose signatures are not checked, or are checked less strictly:
  apt's `trusted=yes` and allow-insecure options, dnf and yum's `gpgcheck=0`,
  and the same switches set for every source in the configuration;
* signing keys added, and keys moved to where apt trusts them for every source;
* sources added, and sources pointed at a different server or key;
* package manager hooks (apt's Pre-Invoke and Post-Invoke commands, dnf's
  post-transaction actions) added, and hooks that run from a temporary folder or
  fetch from the network;
* source lists, keyrings and their folders that an ordinary account can change.

Read-only: files are only read. Keys are read from the keyring files directly,
not with gpg, which would create files in a home folder. On rpm systems the
imported keys are listed with `rpm -q`, which only reads.
"""
from __future__ import annotations

import base64
import configparser
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

SCHEMA = 'megalodon-package-sources-v1'
REPORT_SCHEMA = 'megalodon-package-sources-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/packages.json'
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILES = 4096
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
TRUSTED_UID, TRUSTED_GID = 0, 0
TEMPORARY = ('/tmp/', '/var/tmp/', '/dev/shm/')

# apt reads keys in these for every source that does not name its own key.
APT_GLOBAL_KEYRINGS = ('etc/apt/trusted.gpg',)
APT_GLOBAL_KEY_FOLDERS = ('etc/apt/trusted.gpg.d',)
# Keys here are used only by sources that name them with signed-by.
APT_NAMED_KEY_FOLDERS = ('etc/apt/keyrings', 'usr/share/keyrings')
RPM_KEY_FOLDERS = ('etc/pki/rpm-gpg',)
# Who can change these decides what gets installed.
GUARDED = ('etc/apt', 'etc/apt/sources.list.d', 'etc/apt/apt.conf.d', 'etc/apt/preferences.d', 'etc/apt/trusted.gpg.d',
           'etc/apt/keyrings', 'usr/share/keyrings', 'etc/yum.repos.d', 'etc/dnf', 'etc/dnf/plugins',
           'etc/pki/rpm-gpg')

# apt configuration names (lower case) that weaken signature checks, by how much.
APT_WEAKENING = {
    'apt::get::allowunauthenticated': ('PACKAGE_SIGNATURES_OFF', 'installs packages whose signatures do not verify'),
    'acquire::allowinsecurerepositories': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'accepts sources with no signature'),
    'acquire::allowdowngradetoinsecurerepositories': ('PACKAGE_SIGNATURE_CHECK_WEAKENED',
                                                       'accepts a signed source that stops being signed'),
    'acquire::allowweakrepositories': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'accepts signatures made with weak '
                                                                           'algorithms'),
    'acquire::check-valid-until': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'accepts old signed lists, so updates can be '
                                                                       'held back'),
    'acquire::https::verify-peer': ('PACKAGE_TRANSPORT_WEAKENED', 'does not check the HTTPS certificate'),
    'acquire::https::verify-host': ('PACKAGE_TRANSPORT_WEAKENED', 'does not check the HTTPS host name'),
}
# A false value is the weak one for these; a true value for the rest.
APT_WEAK_WHEN_FALSE = frozenset({'acquire::check-valid-until', 'acquire::https::verify-peer',
                                 'acquire::https::verify-host'})
# apt options on a single source.
SOURCE_WEAKENING = {
    'trusted': ('PACKAGE_SIGNATURES_OFF', 'is trusted without a signature', 'yes'),
    'allow-insecure': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'is accepted with no signature', 'yes'),
    'allow-downgrade-to-insecure': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'is accepted if it stops being signed', 'yes'),
    'allow-weak': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'is accepted with weak signatures', 'yes'),
    'check-valid-until': ('PACKAGE_SIGNATURE_CHECK_WEAKENED', 'is accepted with old signed lists', 'no'),
}
# apt hooks: each value is a command run as root.
APT_HOOKS = ('dpkg::pre-invoke', 'dpkg::post-invoke', 'dpkg::post-invoke-success', 'dpkg::pre-install-pkgs',
             'apt::update::pre-invoke', 'apt::update::post-invoke', 'apt::update::post-invoke-success',
             'acquire::http::proxy-auto-detect', 'acquire::https::proxy-auto-detect',
             # Which programs apt runs in place of dpkg, gpgv and its download methods.
             'dir::bin')
# Where apt reads its sources and keys from; set anywhere, they move what apt trusts out of sight.
APT_LOCATIONS = frozenset({'dir', 'dir::etc', 'dir::etc::trusted', 'dir::etc::trustedparts', 'dir::etc::sourcelist',
                           'dir::etc::sourceparts', 'dir::etc::main', 'dir::etc::parts'})
DNF_ACTION_FOLDERS = ('etc/dnf/plugins/post-transaction-actions.d', 'etc/dnf/libdnf5-plugins/actions.d')
FETCHERS = re.compile(r'(?:^|[\s;&|(`/])(?:curl|wget|nc|ncat|socat|telnet)(?=[\s;&|)`]|$)|/dev/(?:tcp|udp)/')

RULES = {
    'PACKAGE_SIGNATURES_OFF': ('CRITICAL', ['T1553', 'T1195.002'],
                               'Packages are installed without a signature check: whoever can answer for the '
                               'source decides what runs as root.'),
    'PACKAGE_CONFIG_WRITABLE': ('HIGH', ['T1195.002', 'T1546.016'],
                                'A source list, keyring, package manager setting or their folder can be changed by '
                                'an ordinary account.'),
    'SIGNING_KEY_ADDED': ('HIGH', ['T1553', 'T1195.002'],
                          'A package signing key was added. Adding a vendor\'s source does this; so does an intruder '
                          'who wants their own packages accepted.'),
    'PACKAGE_SOURCE_REDIRECTED': ('HIGH', ['T1195.002'], 'A package source now points at a different server.'),
    'PACKAGE_CONFIG_REDIRECTED': ('HIGH', ['T1553', 'T1195.002'],
                                  'apt is told to read its sources, keys or settings from somewhere else.'),
    'PACKAGE_SOURCE_CHANGED': ('HIGH', ['T1553', 'T1195.002'], 'A package source now trusts a different key.'),
    'PACKAGE_MANAGER_HOOK_ADDED': ('HIGH', ['T1546.016'],
                                   'A command now runs as root whenever packages are installed or lists refreshed.'),
    'PACKAGE_MANAGER_HOOK_SUSPICIOUS': ('HIGH', ['T1546.016'],
                                        'A package manager hook runs from a temporary folder or fetches from the '
                                        'network.'),
    'PACKAGE_SIGNATURE_CHECK_WEAKENED': ('HIGH', ['T1553', 'T1195.002'],
                                         'Signatures are checked less strictly than the default.'),
    'PACKAGE_SOURCE_ADDED': ('MEDIUM', ['T1195.002'], 'A package source was added.'),
    'PACKAGE_TRANSPORT_WEAKENED': ('MEDIUM', ['T1557'],
                                   'The connection to a source is not verified. Signatures still protect packages, '
                                   'but a keys or lists download is open to whoever is in the middle.'),
    'WEAK_SIGNING_KEY': ('MEDIUM', ['T1553'], 'A trusted signing key is too short or uses an old algorithm.'),
}


class PackageSourcesError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _finding(rule, subject, detail, severity=None, **extra):
    default, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity or default, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


# ------------------------------------------------------------------ reading files under a root

def _under(root, path):
    return os.path.join(root, path.lstrip('/'))


def _read(root, path, gaps):
    try:
        with open(_under(root, path), 'rb') as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        gaps.append(f'{path} could not be read: {exc.strerror}')
        return None
    if len(raw) > MAX_FILE_BYTES:
        gaps.append(f'{path} is larger than {MAX_FILE_BYTES // 1024 // 1024} MB and was not read')
        return None
    return raw


def _listing(root, folder, gaps, suffixes=None):
    try:
        names = sorted(os.listdir(_under(root, folder)))
    except FileNotFoundError:
        return []
    except OSError as exc:
        gaps.append(f'/{folder} could not be listed: {exc.strerror}')
        return []
    if len(names) > MAX_FILES:
        gaps.append(f'/{folder} has {len(names)} entries; only the first {MAX_FILES} were read')
        names = names[:MAX_FILES]
    return ['/' + folder + '/' + n for n in names if suffixes is None or n.endswith(suffixes)]


# ------------------------------------------------------------------ OpenPGP keys

ALGORITHMS = {1: 'RSA', 2: 'RSA', 3: 'RSA', 16: 'ElGamal', 17: 'DSA', 18: 'ECDH', 19: 'ECDSA', 22: 'EdDSA',
              27: 'Ed25519', 28: 'X25519', 29: 'Ed448', 30: 'X448'}


def _dearmor(text):
    """The binary packets of every armored block in `text`."""
    blocks = []
    for match in re.finditer(r'-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----', text,
                             re.S):
        body = match.group(1).strip('\r\n').splitlines()
        # Armor headers (Version:, Comment:) end at the first blank line.
        if any(not line.strip() for line in body):
            body = body[next(i for i, line in enumerate(body) if not line.strip()) + 1:]
        data = ''.join(line.strip() for line in body if line.strip() and not line.strip().startswith('='))
        try:
            blocks.append(base64.b64decode(data, validate=True))
        except ValueError:
            raise ValueError('an armored key block is not valid base64') from None
    return blocks


def _packets(data):
    """(tag, body) for each OpenPGP packet; raises ValueError on a malformed one."""
    at = 0
    while at < len(data):
        first = data[at]
        if not first & 0x80:
            raise ValueError('not an OpenPGP keyring')
        at += 1
        if first & 0x40:
            tag = first & 0x3F
            if at >= len(data):
                raise ValueError('truncated packet')
            octet = data[at]
            if octet < 192:
                length, at = octet, at + 1
            elif octet < 224:
                if at + 1 >= len(data):
                    raise ValueError('truncated packet')
                length, at = ((octet - 192) << 8) + data[at + 1] + 192, at + 2
            elif octet == 255:
                length, at = int.from_bytes(data[at + 1:at + 5], 'big'), at + 5
            else:
                raise ValueError('a key packet with a partial length')
        else:
            tag, kind = (first >> 2) & 0x0F, first & 0x03
            if kind == 3:
                length = len(data) - at
            else:
                size = (1, 2, 4)[kind]
                length, at = int.from_bytes(data[at:at + size], 'big'), at + size
        if at + length > len(data):
            raise ValueError('truncated packet')
        yield tag, data[at:at + length]
        at += length


def _key(body):
    """{fingerprint, version, algorithm, bits, created} for a public key packet body."""
    version = body[0] if body else 0
    if version == 4 and len(body) >= 6:
        fingerprint = hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest()
        algorithm, material = body[5], body[6:]
    elif version in (5, 6) and len(body) >= 10:
        fingerprint = hashlib.sha256((b'\x9a' if version == 5 else b'\x9b') + len(body).to_bytes(4, 'big')
                                     + body).hexdigest()
        algorithm, material = body[5], body[10:]
    elif version in (2, 3) and len(body) >= 8:
        # Version 3 keys are fingerprinted with MD5 over the key numbers; they are weak whatever their size.
        fingerprint = hashlib.md5(body[8:]).hexdigest()
        algorithm, material = body[7], body[8:]
    else:
        raise ValueError(f'a version {version} key')
    bits = None
    if ALGORITHMS.get(algorithm) in ('RSA', 'DSA', 'ElGamal') and len(material) >= 2:
        bits = int.from_bytes(material[:2], 'big')
    elif algorithm in (27, 28):
        bits = 256
    elif algorithm in (29, 30):
        bits = 448
    created = int.from_bytes(body[1:5], 'big')
    return dict(fingerprint=fingerprint.upper(), version=version, algorithm=ALGORITHMS.get(algorithm, str(algorithm)),
                bits=bits, created=datetime.fromtimestamp(created, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))


def read_keys(raw):
    """Primary keys in a keyring file, armored or binary, each with its first user ID."""
    if raw[:6] == b'-----B' or b'-----BEGIN PGP PUBLIC KEY BLOCK-----' in raw[:4096]:
        blocks = _dearmor(raw.decode('ascii', 'replace'))
    elif raw[8:12] == b'KBXf':
        raise ValueError('a GnuPG keybox, which apt cannot read')
    else:
        blocks = [raw]
    keys, current = [], None
    for block in blocks:
        for tag, body in _packets(block):
            if tag == 6:
                current = dict(_key(body), uid='')
                keys.append(current)
            elif tag == 13 and current is not None and not current['uid']:
                current['uid'] = body[:256].decode('utf-8', 'replace')
    return keys


def weak(key):
    if key['version'] < 4:
        return f"a version {key['version']} key"
    if key['algorithm'] in ('RSA', 'DSA', 'ElGamal') and (key['bits'] or 0) < 2048:
        return f"{key['algorithm']} {key['bits']} bits"
    return None


# ------------------------------------------------------------------ apt

def _tokens(text):
    """apt configuration tokens, with comments removed."""
    pattern = re.compile(r'"([^"]*)"|(/\*.*?\*/)|((?://|#)[^\n]*)|([{};])|([^\s{};"]+)', re.S)
    for match in pattern.finditer(text):
        quoted, _block, comment, punct, word = match.groups()
        if quoted is not None:
            yield 'string', quoted
        elif punct:
            yield punct, punct
        elif word:
            yield 'word', word


def apt_options(text):
    """[(name in lower case, value)] for every value an apt configuration file sets, list items included."""
    found, scope, name, value = [], [], None, None
    for kind, token in _tokens(text):
        if kind == 'word':
            if name is None:
                name = token
            elif value is None:
                value = token
        elif kind == 'string':
            if name is None:
                # A bare value inside a list block, such as DPkg::Post-Invoke { "command"; };
                found.append(('::'.join(scope).lower(), token))
            else:
                value = token
        elif kind == '{':
            scope.append(name or '')
            name, value = None, None
        elif kind == ';':
            if name is not None and value is not None:
                found.append(('::'.join(scope + [name]).lower(), value))
            name, value = None, None
        elif kind == '}':
            if scope:
                scope.pop()
            name, value = None, None
    return found


def _apt_conf_files(root, gaps):
    files = ['/etc/apt/apt.conf']
    for path in _listing(root, 'etc/apt/apt.conf.d', gaps):
        name = path.rsplit('/', 1)[1]
        # apt reads names of letters, digits, '_', '-' and '.', and skips package manager leftovers.
        if re.fullmatch(r'[A-Za-z0-9_.-]+', name) and not re.search(
                r'\.(?:disabled|bak|dpkg-[a-z]+|ucf-[a-z]+|save|orig)$', name):
            files.append(path)
    return files


def _true(value):
    return str(value).strip().lower() in ('1', 'yes', 'true', 'on', 'enable')


def _false(value):
    return str(value).strip().lower() in ('0', 'no', 'false', 'off', 'disable')


def _one_line_sources(text, path):
    sources = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split('#', 1)[0].strip()
        match = re.match(r'(deb|deb-src)\s+(?:\[([^\]]*)\]\s+)?(\S+)\s+(\S+)\s*(.*)$', line)
        if not match:
            continue
        options = {}
        for item in (match.group(2) or '').split():
            key, _, value = item.partition('=')
            options[key.lower().rstrip('+-')] = value
        sources.append(dict(file=path, line=number, type=match.group(1), uris=[match.group(3)],
                            suites=[match.group(4)], components=match.group(5).split(), options=options))
    return sources


def _deb822_sources(text, path):
    sources = []
    for number, stanza in enumerate(re.split(r'\n\s*\n', text), 1):
        fields, last = {}, None
        for line in stanza.splitlines():
            if line.startswith('#'):
                continue
            if line[:1] in (' ', '\t') and last:
                fields[last] += '\n' + line.strip()
                continue
            key, sep, value = line.partition(':')
            if sep:
                last = key.strip().lower()
                fields[last] = value.strip()
        if 'uris' not in fields or _false(fields.get('enabled', 'yes')):
            continue
        options = {k: v for k, v in fields.items() if k not in ('types', 'uris', 'suites', 'components', 'enabled')}
        for kind in fields.get('types', 'deb').split():
            sources.append(dict(file=path, line=number, type=kind, uris=fields['uris'].split(),
                                suites=fields.get('suites', '').split(), components=fields.get('components', '').split(),
                                options=options))
    return sources


def apt_sources(root, gaps):
    files = ['/etc/apt/sources.list'] + _listing(root, 'etc/apt/sources.list.d', gaps, ('.list', '.sources'))
    found = []
    for path in files:
        raw = _read(root, path, gaps)
        if raw is None:
            continue
        text = raw.decode('utf-8', 'replace')
        found += _deb822_sources(text, path) if path.endswith('.sources') else _one_line_sources(text, path)
    return found


# ------------------------------------------------------------------ dnf and yum

def _ini(raw):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(raw.decode('utf-8', 'replace'))
    return parser


def dnf_sources(root, gaps):
    main = {}
    for path in ('/etc/dnf/dnf.conf', '/etc/yum.conf'):
        raw = _read(root, path, gaps)
        if raw is None:
            continue
        try:
            parser = _ini(raw)
        except configparser.Error:
            gaps.append(f'{path} could not be parsed')
            continue
        if parser.has_section('main'):
            main.setdefault('path', path)
            for key in ('gpgcheck', 'sslverify', 'localpkg_gpgcheck'):
                if parser.has_option('main', key):
                    main.setdefault(key, parser.get('main', key))
    found = []
    for path in _listing(root, 'etc/yum.repos.d', gaps, ('.repo',)):
        raw = _read(root, path, gaps)
        if raw is None:
            continue
        try:
            parser = _ini(raw)
        except configparser.Error:
            gaps.append(f'{path} could not be parsed')
            continue
        for section in parser.sections():
            repo = parser[section]
            if not _true(repo.get('enabled', '1')):
                continue
            uris = (repo.get('baseurl', '') or '').split() or [repo.get('metalink') or repo.get('mirrorlist') or '']
            found.append(dict(file=path, line=section, type='rpm', uris=[u for u in uris if u], suites=[section],
                              components=[], options={k: repo.get(k) for k in ('gpgcheck', 'sslverify', 'gpgkey')
                                                      if repo.get(k) is not None}))
    return found, main


def _rpm_keys(runner, gaps):
    try:
        output = runner(['rpm', '-q', 'gpg-pubkey', '--qf', '%{DESCRIPTION}\n'])
    except (OSError, subprocess.SubprocessError) as exc:
        gaps.append(f'rpm could not list the imported keys: {exc}')
        return []
    if 'is not installed' in output and 'BEGIN PGP' not in output:
        return []
    try:
        return read_keys(output.encode())
    except ValueError as exc:
        gaps.append(f'rpm\'s imported keys could not be read: {exc}')
        return []


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False,
                          env=dict(os.environ, LC_ALL='C')).stdout


# ------------------------------------------------------------------ snapshot

def _source_id(manager, source, uri, suite):
    return f'{manager} {source["type"]} {uri} {suite}'


def _writable(info):
    return info.st_uid != TRUSTED_UID or bool(info.st_mode & 0o002) or \
        bool(info.st_mode & 0o020 and info.st_gid != TRUSTED_GID)


def _who(info):
    if info.st_mode & 0o002:
        return 'everyone'
    if info.st_uid != TRUSTED_UID:
        return f'its owner, UID {info.st_uid}'
    return f'group {info.st_gid}'


def _guarded_writable(root, extra):
    found = {}
    paths = set()
    for folder in GUARDED:
        if not os.path.isdir(_under(root, folder)):
            continue
        # The folder, every folder above it, and the files in it.
        current = '/' + folder
        while current != '/':
            paths.add(current)
            current = os.path.dirname(current)
        try:
            names = sorted(os.listdir(_under(root, folder)))[:MAX_FILES]
        except OSError:
            continue
        paths.update(f'/{folder}/{name}' for name in names)
    paths.update(p for p in extra if p.startswith('/'))
    paths.update(('/etc/apt/sources.list', '/etc/apt/apt.conf', '/etc/apt/trusted.gpg', '/etc/dnf/dnf.conf',
                  '/etc/yum.conf'))
    for path in sorted(paths):
        try:
            info = os.stat(_under(root, path))
        except OSError:
            continue
        if (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and _writable(info):
            found[path] = dict(writable_by=_who(info), folder=stat.S_ISDIR(info.st_mode))
    return found


def _hook_id(path, option, command):
    return f'{path}|{option}|{hashlib.sha256(command.encode()).hexdigest()[:16]}'


def _suspicious(command):
    return any(t in command for t in TEMPORARY) or bool(FETCHERS.search(command))


def snapshot(*, root='/', runner=None):
    gaps, weakenings, hooks, keys, sources = [], {}, {}, {}, {}
    runner = runner or _run

    def weaken(rule, subject, detail, path, severity=None):
        weakenings[f'{rule}|{subject}'] = dict(rule=rule, subject=subject, detail=detail, path=path,
                                               severity=severity or RULES[rule][0])

    def add_key(key, path, scope):
        entry = keys.setdefault(key['fingerprint'], dict(algorithm=key['algorithm'], bits=key['bits'],
                                                         version=key['version'], created=key['created'],
                                                         uid=key['uid'], files=[], scope='named', used_by=[]))
        if path not in entry['files']:
            entry['files'].append(path)
        if scope == 'all':
            entry['scope'] = 'all'
        return entry

    def keyring(path, scope):
        raw = _read(root, path, gaps)
        if raw is None:
            return []
        try:
            found = read_keys(raw)
        except ValueError as exc:
            gaps.append(f'{path}: {exc}')
            return []
        return [add_key(k, path, scope) for k in found]

    # apt: the settings and hooks.
    has_apt = os.path.isdir(_under(root, 'etc/apt'))
    for path in _apt_conf_files(root, gaps) if has_apt else []:
        raw = _read(root, path, gaps)
        if raw is None:
            continue
        for name, value in apt_options(raw.decode('utf-8', 'replace')):
            name = name.rstrip(':')
            # A setting for one host, such as Acquire::https::example.com::Verify-Peer, weakens that host.
            host = re.fullmatch(r'acquire::https::(.+)::(verify-peer|verify-host)', name)
            if host:
                name = f'acquire::https::{host.group(2)}'
            if name in APT_WEAKENING:
                rule, effect = APT_WEAKENING[name]
                if (_false(value) if name in APT_WEAK_WHEN_FALSE else _true(value)):
                    scope = f'for {host.group(1)}' if host else 'for every source'
                    weaken(rule, f'apt:{name}' + (f':{host.group(1)}' if host else ''),
                           f'{path} sets {name} "{value}": apt {effect} {scope}', path)
            elif name in APT_LOCATIONS:
                weaken('PACKAGE_CONFIG_REDIRECTED', f'apt:{name}', f'{path} sets {name} "{value}"', path)
            elif name in APT_HOOKS or any(name.startswith(h + '::') for h in APT_HOOKS):
                hooks[_hook_id(path, name, value)] = dict(file=path, option=name, command=value[:4096])

    # apt: sources and the keys they trust.
    for path in [*APT_GLOBAL_KEYRINGS, *(p.lstrip('/') for f in APT_GLOBAL_KEY_FOLDERS
                                         for p in _listing(root, f, gaps, ('.gpg', '.asc')))] if has_apt else []:
        keyring('/' + path, 'all')
    for folder in APT_NAMED_KEY_FOLDERS if has_apt else ():
        for path in _listing(root, folder, gaps, ('.gpg', '.asc', '.pgp')):
            keyring(path, 'named')
    for source in apt_sources(root, gaps) if has_apt else []:
        options = source['options']
        signed_by = (options.get('signed-by') or '').strip()
        trusts = []
        if 'BEGIN PGP PUBLIC KEY BLOCK' in signed_by:
            # deb822 writes an empty line inside a field as a lone '.'.
            text = '\n'.join('' if line == '.' else line for line in signed_by.split('\n'))
            try:
                for key in read_keys(text.encode()):
                    add_key(key, f'{source["file"]} (inline)', 'named')
                    trusts.append(key['fingerprint'])
            except ValueError as exc:
                gaps.append(f'{source["file"]}: the inline key: {exc}')
            signed_by = 'inline key'
        elif signed_by:
            for item in re.split(r'[\s,]+', signed_by):
                if item.startswith('/'):
                    if not any(item in entry['files'] for entry in keys.values()):
                        keyring(item, 'named')
                    trusts += [fp for fp, entry in keys.items() if item in entry['files']]
                elif re.fullmatch(r'[0-9A-Fa-f]{16,64}!?', item):
                    trusts.append(item.rstrip('!').upper())
        for uri in source['uris']:
            for suite in source['suites'] or ['']:
                sid = _source_id('apt', source, uri, suite)
                sources[sid] = dict(file=source['file'], manager='apt', uri=uri, suite=suite,
                                    signed_by=signed_by or 'every key apt trusts', keys=sorted(set(trusts)))
                for fingerprint in trusts:
                    if fingerprint in keys and sid not in keys[fingerprint]['used_by']:
                        keys[fingerprint]['used_by'].append(sid)
        for option, (rule, effect, weak_value) in SOURCE_WEAKENING.items():
            value = options.get(option)
            if value is not None and (_true(value) if weak_value == 'yes' else _false(value)):
                for uri in source['uris']:
                    weaken(rule, f'apt-source:{uri}', f'{uri} in {source["file"]} {effect} ({option}={value})',
                           source['file'])

    # dnf and yum.
    repos, main = dnf_sources(root, gaps)
    for path in [p for f in RPM_KEY_FOLDERS for p in _listing(root, f, gaps)]:
        keyring(path, 'named')
    if repos and root in ('/', '') and shutil.which('rpm'):
        for key in _rpm_keys(runner, gaps):
            add_key(key, 'rpm database', 'all')
    main_gpgcheck = main.get('gpgcheck')
    if main_gpgcheck is not None and _false(main_gpgcheck):
        weaken('PACKAGE_SIGNATURES_OFF', 'dnf:gpgcheck', f'{main["path"]} sets gpgcheck={main_gpgcheck}: '
                                                         'packages from sources that do not set it are not checked',
               main['path'])
    for repo in repos:
        options = repo['options']
        gpgcheck = options.get('gpgcheck', main_gpgcheck)
        name = repo['suites'][0]
        if gpgcheck is None or _false(gpgcheck):
            said = f'gpgcheck={gpgcheck}' if gpgcheck is not None else 'no gpgcheck setting, and dnf does not check ' \
                                                                        'by default'
            weaken('PACKAGE_SIGNATURES_OFF', f'dnf-repo:{name}', f'source {name} in {repo["file"]} has {said}',
                   repo['file'])
        sslverify = options.get('sslverify', main.get('sslverify'))
        if sslverify is not None and _false(sslverify):
            weaken('PACKAGE_TRANSPORT_WEAKENED', f'dnf-repo:{name}:sslverify',
                   f'source {name} in {repo["file"]} sets sslverify={sslverify}', repo['file'])
        for url in (options.get('gpgkey') or '').split():
            if url.startswith(('http://', 'ftp://')):
                weaken('PACKAGE_SIGNATURE_CHECK_WEAKENED', f'dnf-repo:{name}:gpgkey',
                       f'source {name} in {repo["file"]} fetches its signing key over an unverified connection '
                       f'({url})', repo['file'])
        trusts = []
        for url in (options.get('gpgkey') or '').split():
            if url.startswith('file:///'):
                local = url[len('file://'):]
                if not any(local in entry['files'] for entry in keys.values()):
                    keyring(local, 'named')
                trusts += [fp for fp, entry in keys.items() if local in entry['files']]
        for uri in repo['uris'] or ['']:
            sid = _source_id('dnf', repo, uri, name)
            sources[sid] = dict(file=repo['file'], manager='dnf', uri=uri, suite=name,
                                signed_by=options.get('gpgkey', 'every key rpm trusts'), keys=sorted(set(trusts)))
            for fingerprint in trusts:
                if sid not in keys[fingerprint]['used_by']:
                    keys[fingerprint]['used_by'].append(sid)
    for folder in DNF_ACTION_FOLDERS:
        for path in _listing(root, folder, gaps, ('.action', '.actions')):
            raw = _read(root, path, gaps)
            for line in (raw or b'').decode('utf-8', 'replace').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    hooks[_hook_id(path, 'action', line)] = dict(file=path, option='action', command=line[:4096])

    signed_files = [p for s in sources.values() for p in re.split(r'[\s,]+', s['signed_by']) if p.startswith('/')]
    writable = _guarded_writable(root, signed_files)
    for entry in keys.values():
        entry['files'].sort()
        entry['used_by'].sort()
    return dict(sources=sources, keys=keys, hooks=hooks, weakenings=weakenings, writable=writable, gaps=gaps)


# ------------------------------------------------------------------ baseline, check and accept

def compare(old, new):
    """Findings for what changed since `old`; with old None, what is already a hole."""
    findings = []
    first = old is None
    old = old or dict(sources={}, keys={}, hooks={}, weakenings={}, writable={})
    for wid, entry in sorted(new['weakenings'].items()):
        if wid not in old['weakenings']:
            findings.append(_finding(entry['rule'], entry['subject'], entry['detail'], entry['severity'],
                                     path=entry['path']))
    for path, entry in sorted(new['writable'].items()):
        if path not in old['writable']:
            findings.append(_finding('PACKAGE_CONFIG_WRITABLE', f'file:{path}',
                                     f"{path} can be changed by {entry['writable_by']}",
                                     'CRITICAL' if entry['writable_by'] == 'everyone' else None, path=path))
    for hid, entry in sorted(new['hooks'].items()):
        suspicious = _suspicious(entry['command'])
        text = f"{entry['file']} runs {entry['command']!r} ({entry['option']})"
        if first:
            if suspicious:
                findings.append(_finding('PACKAGE_MANAGER_HOOK_SUSPICIOUS', f'hook:{hid}', text, path=entry['file']))
        elif hid not in old['hooks']:
            findings.append(_finding('PACKAGE_MANAGER_HOOK_ADDED', f'hook:{hid}', text,
                                     'CRITICAL' if suspicious else None, path=entry['file']))
    for fingerprint, entry in sorted(new['keys'].items()):
        was = old['keys'].get(fingerprint)
        trusted = entry['scope'] == 'all' or entry['used_by']
        where = 'trusted for every source' if entry['scope'] == 'all' else \
            (f"trusted by {', '.join(entry['used_by'][:3])}" if entry['used_by'] else 'not named by any source yet')
        label = f"{fingerprint} {entry['uid'] or '(no user ID)'} in {', '.join(entry['files'][:3])}"
        if not first and was is None:
            findings.append(_finding('SIGNING_KEY_ADDED', f'key:{fingerprint}', f'{label}: {where}',
                                     None if trusted else 'MEDIUM', path=entry['files'][0], fingerprint=fingerprint))
        elif not first and was.get('scope') != 'all' and entry['scope'] == 'all':
            findings.append(_finding('SIGNING_KEY_ADDED', f'key:{fingerprint}',
                                     f'{label}: now trusted for every source', path=entry['files'][0],
                                     fingerprint=fingerprint))
        weakness = weak(entry)
        if weakness and trusted and (first or was is None or not (was.get('scope') == 'all' or was.get('used_by'))):
            findings.append(_finding('WEAK_SIGNING_KEY', f'weak-key:{fingerprint}', f'{label}: {weakness}, {where}',
                                     path=entry['files'][0], fingerprint=fingerprint))
    if not first:
        removed = {sid: entry for sid, entry in old['sources'].items() if sid not in new['sources']}
        for sid, entry in sorted(new['sources'].items()):
            was = old['sources'].get(sid)
            if was is None:
                replaced = next((r for r in removed.values() if r['file'] == entry['file']
                                 and r['suite'] == entry['suite'] and r['manager'] == entry['manager']), None)
                if replaced:
                    findings.append(_finding('PACKAGE_SOURCE_REDIRECTED', f'source:{sid}',
                                             f"{entry['suite'] or 'a source'} in {entry['file']}: {replaced['uri']} → "
                                             f"{entry['uri']}", path=entry['file']))
                else:
                    findings.append(_finding('PACKAGE_SOURCE_ADDED', f'source:{sid}',
                                             f"{entry['uri']} {entry['suite']} in {entry['file']}, signed by "
                                             f"{entry['signed_by']}", path=entry['file']))
            elif was.get('signed_by') != entry['signed_by'] or was.get('keys') != entry['keys']:
                findings.append(_finding('PACKAGE_SOURCE_CHANGED', f'source:{sid}',
                                         f"{entry['uri']} {entry['suite']} in {entry['file']}: signed by "
                                         f"{was.get('signed_by')} → {entry['signed_by']}", path=entry['file']))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return findings


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.packages-', dir=path.parent)
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
        raise PackageSourcesError(f'no package sources baseline at {path}; run megalodon packages baseline') from None
    except OSError as exc:
        raise PackageSourcesError(f'package sources baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PackageSourcesError(f'package sources baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise PackageSourcesError('package sources baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or any(
            type(value.get(k)) is not dict for k in ('sources', 'keys', 'hooks', 'weakenings', 'writable')):
        raise PackageSourcesError('package sources baseline has an unsupported format')
    return value


def _counts(state):
    return dict(sources=len(state['sources']), keys=len(state['keys']), hooks=len(state['hooks']),
                trusted_for_every_source=sum(1 for k in state['keys'].values() if k['scope'] == 'all'))


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, root='/', runner=None):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise PackageSourcesError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(root=root, runner=runner)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), root=os.path.realpath(root),
                      **{k: v for k, v in state.items() if k != 'gaps'}))
    # Signature checks already off, and files anyone can change, are reported now, not recorded as normal.
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), findings=compare(None, state),
                **_counts(state), gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, *, root=None, runner=None):
    old = _load(manifest)
    new = snapshot(root=root or old.get('root', '/'), runner=runner)
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_now(),
                baseline_recorded_at=old.get('recorded_at'), findings=compare(old, new),
                removed=dict(sources=sorted(set(old['sources']) - set(new['sources'])),
                             keys=sorted(set(old['keys']) - set(new['keys'])),
                             hooks=sorted(set(old['hooks']) - set(new['hooks']))),
                **_counts(new), gaps=new['gaps'],
                note='After review, `megalodon packages accept` records the current state.')


def accept(manifest=DEFAULT_MANIFEST, *, root=None, runner=None):
    old = _load(manifest)
    return dict(baseline(manifest, replace=True, root=root or old.get('root', '/'), runner=runner), action='accept')
