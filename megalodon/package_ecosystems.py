"""Package sources beyond apt and dnf: pip, npm, flatpak and snap.

Each of these installs code from a server its settings name, with checks its settings can turn off, so an
intruder who changes the settings gets their code installed by the next routine install or update:

* **pip** installs from `index-url`, and from every `extra-index-url` too, taking whichever offers the
  higher version. A public index next to a private one is how a package with an internal name gets
  replaced (dependency confusion). pip packages are not signed: TLS is their only check, so a
  `trusted-host` or a plain-HTTP index is as good as no check.
* **npm** installs from `registry` and from a registry per scope (`@company:registry`). Its packages are
  checked only by TLS too, so `strict-ssl=false` or a plain-HTTP registry leaves them unchecked.
* **flatpak** installs from remotes whose summaries and commits are signed by the keys in the remote's
  trusted keyring, unless `gpg-verify` or `gpg-verify-summary` is turned off.
* **snap** installs from the Snap Store, signed by its assertions. `snap install --dangerous` skips that
  (the revision then starts with `x`), and snapd can be pointed at another store through its environment.

The settings are read the way each tool reads them: system files first, then each account's own, the last
value winning. Accounts without settings of their own use the system ones and are not listed separately.
"""
from __future__ import annotations

import configparser
import os
import re

PIP_SYSTEM = ('/etc/pip.conf', '/etc/xdg/pip/pip.conf')
PIP_USER = ('.config/pip/pip.conf', '.pip/pip.conf')
PIP_PROGRAMS = ('usr/bin/pip', 'usr/bin/pip3', 'usr/local/bin/pip', 'usr/local/bin/pip3')
PYPI = 'https://pypi.org/simple'
# npm reads its own built-in settings, then the global file under its prefix, then the account's own.
NPM_SYSTEM = ('/usr/lib/node_modules/npm/npmrc', '/usr/local/lib/node_modules/npm/npmrc', '/etc/npmrc',
              '/usr/etc/npmrc', '/usr/local/etc/npmrc')
NPM_USER = ('.npmrc',)
NPM_PROGRAMS = ('usr/bin/npm', 'usr/local/bin/npm')
NPM_DEFAULT = 'https://registry.npmjs.org/'
FLATPAK_SYSTEM = '/var/lib/flatpak/repo'
FLATPAK_USER = '.local/share/flatpak/repo'
SNAP_FOLDER = '/var/lib/snapd/snaps'
SNAPD_DROPINS = '/etc/systemd/system/snapd.service.d'
# snapd's own variables that send it to another store or stop it checking what it installs.
SNAPD_REDIRECTS = ('SNAPPY_FORCE_API_URL', 'SNAPPY_FORCE_CPI_URL', 'SNAPPY_FORCE_SAS_URL', 'SNAPPY_FORCE_AUTH_URL',
                   'SNAPPY_USE_STAGING_STORE', 'SNAPPY_TESTING')
TLS_ONLY = 'nothing but TLS: packages are not signed'


def _homes(root):
    """(account, home) for root and every folder in /home, inside the root scanned."""
    found = [('root', '/root')]
    try:
        names = sorted(os.listdir(os.path.join(root, 'home')))
    except OSError:
        names = []
    found += [(name, f'/home/{name}') for name in names if os.path.isdir(os.path.join(root, 'home', name))]
    return found


def _exists(root, path):
    return os.path.exists(os.path.join(root, path.lstrip('/')))


def _false(value):
    return str(value).strip().lower() in ('false', 'no', 'off', '0')


def _ini(raw):
    parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=('=', ':'))
    parser.optionxform = lambda name: name.strip().lower().replace('_', '-')
    parser.read_string(raw.decode('utf-8', 'replace'))
    return parser


def _plain(uri):
    return uri.lower().startswith(('http://', 'ftp://'))


# ------------------------------------------------------------------ pip

def _pip_settings(read, paths, gaps):
    """index-url, extra-index-url, trusted-host and where each was set, the last file winning."""
    found = {}
    for path in paths:
        raw = read(path)
        if raw is None:
            continue
        try:
            parser = _ini(raw)
        except configparser.Error as exc:
            gaps.append(f'{path} is not a valid pip configuration: {exc.__class__.__name__}')
            continue
        for section in ('global', 'install'):
            if not parser.has_section(section):
                continue
            for name in ('index-url', 'extra-index-url', 'trusted-host'):
                if parser.has_option(section, name):
                    found[name] = (parser.get(section, name).split(), path)
    return found


def _pip(root, read, gaps, weaken, add_source):
    system = [p for p in PIP_SYSTEM if _exists(root, p)]
    accounts = [(account, [f'{home}/{p}' for p in PIP_USER if _exists(root, f'{home}/{p}')])
                for account, home in _homes(root)]
    if not system and not any(files for _a, files in accounts) and \
            not any(_exists(root, p) for p in PIP_PROGRAMS):
        return
    scopes = [('the system', system)] + [(f'account {a}', system + files) for a, files in accounts if files]
    for scope, paths in scopes:
        label = f'pip for {scope}'
        settings = _pip_settings(read, paths, gaps)
        index, where = settings.get('index-url', ([PYPI], '(default)'))
        add_source('pip', label, (index or [PYPI])[0], 'index-url', TLS_ONLY, where)
        extras, extras_where = settings.get('extra-index-url', ([], None))
        for uri in extras:
            add_source('pip', label, uri, 'extra-index-url', TLS_ONLY, extras_where)
            weaken('PACKAGE_INDEX_MIXED', f'pip:{scope}:extra-index-url',
                   f'{label} installs from {uri} as well as {index[0] if index else PYPI}, set in {extras_where}: '
                   f'pip takes whichever index offers the higher version', extras_where, value=uri)
        for uri in (index or []) + extras:
            if _plain(uri):
                weaken('PACKAGE_TRANSPORT_WEAKENED', f'pip:{scope}:plain:{uri}',
                       f'{label} installs from {uri} over an unencrypted connection: pip packages are not signed, '
                       f'so nothing checks them', where if uri in (index or []) else extras_where, 'HIGH')
        hosts, hosts_where = settings.get('trusted-host', ([], None))
        for host in hosts:
            weaken('PACKAGE_TRANSPORT_WEAKENED', f'pip:{scope}:trusted-host:{host}',
                   f'{label} trusts {host} without checking its certificate, set in {hosts_where}: pip packages '
                   f'are not signed, so TLS is their only check', hosts_where, 'HIGH')


# ------------------------------------------------------------------ npm

def _npm_settings(read, paths):
    found = {}
    for path in paths:
        raw = read(path)
        for line in (raw or b'').decode('utf-8', 'replace').splitlines():
            line = line.strip()
            if not line or line.startswith((';', '#')) or '=' not in line:
                continue
            name, value = (part.strip() for part in line.split('=', 1))
            name = name.lower()
            if name in ('registry', 'strict-ssl') or re.fullmatch(r'@[^:\s]+:registry', name):
                found[name] = (value.strip('"\''), path)
    return found


def _npm(root, read, gaps, weaken, add_source):
    system = [p for p in NPM_SYSTEM if _exists(root, p)]
    accounts = [(account, [f'{home}/{p}' for p in NPM_USER if _exists(root, f'{home}/{p}')])
                for account, home in _homes(root)]
    if not system and not any(files for _a, files in accounts) and \
            not any(_exists(root, p) for p in NPM_PROGRAMS):
        return
    scopes = [('the system', system)] + [(f'account {a}', system + files) for a, files in accounts if files]
    for scope, paths in scopes:
        label = f'npm for {scope}'
        settings = _npm_settings(read, paths)
        registry, where = settings.get('registry', (NPM_DEFAULT, '(default)'))
        add_source('npm', label, registry, 'registry', TLS_ONLY, where)
        registries = [(registry, where)]
        for name, (uri, path) in sorted(settings.items()):
            if name.endswith(':registry'):
                add_source('npm', label, uri, name, TLS_ONLY, path)
                registries.append((uri, path))
        for uri, path in registries:
            if _plain(uri):
                weaken('PACKAGE_TRANSPORT_WEAKENED', f'npm:{scope}:plain:{uri}',
                       f'{label} installs from {uri} over an unencrypted connection, set in {path}: npm packages '
                       f'are not signed, so nothing checks them', path, 'HIGH')
        strict, path = settings.get('strict-ssl', ('true', None))
        if _false(strict):
            weaken('PACKAGE_TRANSPORT_WEAKENED', f'npm:{scope}:strict-ssl',
                   f'{label} does not check registry certificates (strict-ssl={strict}), set in {path}: npm '
                   f'packages are not signed, so TLS is their only check', path, 'HIGH')


# ------------------------------------------------------------------ flatpak

def _flatpak(root, read, gaps, weaken, add_source, keyring):
    repos = [('the system', FLATPAK_SYSTEM)] + [(f'account {a}', f'{home}/{FLATPAK_USER}')
                                                for a, home in _homes(root)]
    for scope, repo in repos:
        config = f'{repo}/config'
        raw = read(config)
        if raw is None:
            continue
        try:
            parser = _ini(raw)
        except configparser.Error as exc:
            gaps.append(f'{config} is not a valid flatpak configuration: {exc.__class__.__name__}')
            continue
        for section in parser.sections():
            match = re.fullmatch(r'remote\s+"(.+)"', section.strip())
            if not match:
                continue
            name, options = match.group(1), parser[section]
            if options.get('disable', 'false').strip().lower() in ('true', 'yes', '1'):
                continue                    # a disabled remote installs nothing
            uri = options.get('url', '')
            keys_file = f'{repo}/{name}.trustedkeys.gpg'
            trusted = keyring(keys_file) if _exists(root, keys_file) else []
            verify = options.get('gpg-verify', 'true')
            signed_by = keys_file if trusted else ('signature checks off' if _false(verify) else
                                                   'the keys flatpak was given for it')
            add_source('flatpak', config, uri, name, signed_by, config, trusts=trusted)
            if _false(verify):
                weaken('PACKAGE_SIGNATURES_OFF', f'flatpak:{scope}:{name}:gpg-verify',
                       f'flatpak remote {name} ({uri}) for {scope} sets gpg-verify={verify} in {config}: what it '
                       f'installs is not checked', config)
            summary = options.get('gpg-verify-summary', 'true')
            if _false(summary):
                weaken('PACKAGE_SIGNATURE_CHECK_WEAKENED', f'flatpak:{scope}:{name}:gpg-verify-summary',
                       f'flatpak remote {name} ({uri}) for {scope} sets gpg-verify-summary={summary} in {config}: '
                       f'its list of apps and versions is not checked', config)


# ------------------------------------------------------------------ snap

def _snap(root, read, gaps, weaken, listing):
    if not _exists(root, '/var/lib/snapd'):
        return
    for path in listing(SNAP_FOLDER.lstrip('/'), ('.snap',)):
        match = re.fullmatch(r'(.+)_(x\d+)\.snap', os.path.basename(path))
        if match:
            weaken('PACKAGE_SIGNATURES_OFF', f'snap:{match.group(1)}',
                   f'snap {match.group(1)} revision {match.group(2)} was installed with --dangerous: its signature '
                   f'and the store assertions were not checked', path, value=match.group(2))
    for path in listing(SNAPD_DROPINS.lstrip('/'), ('.conf',)):
        raw = read(path)
        for line in (raw or b'').decode('utf-8', 'replace').splitlines():
            for name in SNAPD_REDIRECTS:
                found = re.search(rf'\b{name}=("?)([^"\s]*)\1', line)
                if found and not line.lstrip().startswith('#'):
                    weaken('PACKAGE_CONFIG_REDIRECTED', f'snapd:{name}',
                           f'{path} sets {name}={found.group(2)} for snapd: it is sent to another store or stops '
                           f'checking what it installs', path, value=found.group(2))


def collect(root, gaps, *, read, listing, weaken, add_source, keyring):
    """Record the sources and weakened settings of pip, npm, flatpak and snap; returns the system-wide files
    whose write access matters (accounts' own files are theirs to change)."""
    _pip(root, read, gaps, weaken, add_source)
    _npm(root, read, gaps, weaken, add_source)
    _flatpak(root, read, gaps, weaken, add_source, keyring)
    _snap(root, read, gaps, weaken, listing)
    guarded = [*PIP_SYSTEM, *NPM_SYSTEM, f'{FLATPAK_SYSTEM}/config', SNAPD_DROPINS,
               *(f'/root/{p}' for p in PIP_USER + NPM_USER)]
    try:
        guarded += [f'{FLATPAK_SYSTEM}/{n}' for n in os.listdir(os.path.join(root, FLATPAK_SYSTEM.lstrip('/')))
                    if n.endswith('.trustedkeys.gpg')]
    except OSError:
        pass
    return [p for p in guarded if _exists(root, p)]
