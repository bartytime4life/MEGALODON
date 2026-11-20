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

# Environment variables override pip's and npm's own files. They are read where a login sets them: the system's
# environment and shell startup files, then each account's own. Values are taken as written: one built from other
# variables or commands cannot be known without running the shell, and is listed as a gap.
ENV_SYSTEM = ('/etc/environment', '/etc/environment.d/', '/etc/profile', '/etc/profile.d/', '/etc/bash.bashrc',
              '/etc/zsh/zshenv')
ENV_USER = ('.pam_environment', '.config/environment.d/', '.profile', '.bash_profile', '.bashrc', '.zshenv', '.zshrc')
PIP_ENV = {'PIP_INDEX_URL': 'index-url', 'PIP_EXTRA_INDEX_URL': 'extra-index-url', 'PIP_TRUSTED_HOST': 'trusted-host'}
NPM_ENV = {'npm_config_registry': 'registry', 'npm_config_strict_ssl': 'strict-ssl'}
# Variables that point pip or npm at another configuration file, read as if it were theirs.
PIP_CONFIG_ENV = 'PIP_CONFIG_FILE'
NPM_CONFIG_ENV = ('npm_config_userconfig', 'npm_config_globalconfig')
_ASSIGNMENT = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
_WANTED = {name.lower() for name in (*PIP_ENV, *NPM_ENV, PIP_CONFIG_ENV, *NPM_CONFIG_ENV)}


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


# ------------------------------------------------------------------ environment variables

def _env_files(root, listing, places, home=''):
    files = []
    for place in places:
        path = f'{home}/{place}' if home else place
        if path.endswith('/'):
            files += sorted(listing(path.strip('/'), ('.conf', '.sh')) if _exists(root, path) else [])
        elif _exists(root, path):
            files.append(path)
    return files


def _environment(root, read, listing, gaps, home=''):
    """{variable: (value, file)} for the pip and npm variables a login sets, the last assignment winning.

    npm reads its variables in any letter case; pip's are upper case. Both are kept as written, matched by name.
    """
    found = {}
    for path in _env_files(root, listing, ENV_USER if home else ENV_SYSTEM, home):
        for line in (read(path) or b'').decode('utf-8', 'replace').splitlines():
            match = _ASSIGNMENT.match(line)
            if not match or match.group(1).lower() not in _WANTED:
                continue
            name, value = match.group(1), match.group(2).strip()
            value = value.split(' #', 1)[0].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            if any(mark in value for mark in ('$', '`')):
                gaps.append(f'{name} in {path} is built from other variables or commands: its value is not known')
                continue
            canonical = name if name.isupper() and name.startswith('PIP_') else name.lower()
            found[canonical] = (value, path)
    return found


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


def _with_environment(settings, env, names, split=True):
    """Settings from files, overridden by the environment variables that set the same thing."""
    out = dict(settings)
    for variable, name in names.items():
        if variable in env:
            value, path = env[variable]
            out[name] = (value.split() if split else value, f'{path} ({variable})')
    return out


def _pip(root, read, gaps, weaken, add_source, listing=None):
    listing = listing or (lambda folder, suffixes: [])
    system = [p for p in PIP_SYSTEM if _exists(root, p)]
    system_env = _environment(root, read, listing, gaps)
    accounts = [(account, [f'{home}/{p}' for p in PIP_USER if _exists(root, f'{home}/{p}')],
                 _environment(root, read, listing, gaps, home))
                for account, home in _homes(root)]
    accounts = [(a, files, {k: v for k, v in env.items() if k.startswith('PIP_')}) for a, files, env in accounts]
    system_env = {k: v for k, v in system_env.items() if k.startswith('PIP_')}
    if not system and not system_env and not any(files or env for _a, files, env in accounts) and \
            not any(_exists(root, p) for p in PIP_PROGRAMS):
        return
    scopes = [('the system', system, system_env)] + [
        (f'account {a}', system + files, {**system_env, **env}) for a, files, env in accounts if files or env]
    for scope, paths, env in scopes:
        label = f'pip for {scope}'
        if PIP_CONFIG_ENV in env:
            # PIP_CONFIG_FILE names one more file, read after the others.
            extra, where = env[PIP_CONFIG_ENV]
            if extra.startswith('/') and _exists(root, extra):
                paths = paths + [extra]
            elif extra:
                gaps.append(f'{PIP_CONFIG_ENV} in {where} names {extra}, which could not be read')
        settings = _with_environment(_pip_settings(read, paths, gaps), env, PIP_ENV)
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


def _npm(root, read, gaps, weaken, add_source, listing=None):
    listing = listing or (lambda folder, suffixes: [])
    system = [p for p in NPM_SYSTEM if _exists(root, p)]
    system_env = {k: v for k, v in _environment(root, read, listing, gaps).items() if k.startswith('npm_')}
    accounts = [(account, [f'{home}/{p}' for p in NPM_USER if _exists(root, f'{home}/{p}')],
                 {k: v for k, v in _environment(root, read, listing, gaps, home).items() if k.startswith('npm_')})
                for account, home in _homes(root)]
    if not system and not system_env and not any(files or env for _a, files, env in accounts) and \
            not any(_exists(root, p) for p in NPM_PROGRAMS):
        return
    scopes = [('the system', system, system_env)] + [
        (f'account {a}', system + files, {**system_env, **env}) for a, files, env in accounts if files or env]
    for scope, paths, env in scopes:
        label = f'npm for {scope}'
        for variable in NPM_CONFIG_ENV:
            if variable in env:
                extra, where = env[variable]
                if extra.startswith('/') and _exists(root, extra):
                    paths = paths + [extra]
                elif extra:
                    gaps.append(f'{variable} in {where} names {extra}, which could not be read')
        settings = _with_environment(_npm_settings(read, paths), env, NPM_ENV, split=False)
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
    _pip(root, read, gaps, weaken, add_source, listing)
    _npm(root, read, gaps, weaken, add_source, listing)
    gaps[:] = list(dict.fromkeys(gaps))     # pip and npm read the same login files: each gap once
    _flatpak(root, read, gaps, weaken, add_source, keyring)
    _snap(root, read, gaps, weaken, listing)
    guarded = [*PIP_SYSTEM, *NPM_SYSTEM, f'{FLATPAK_SYSTEM}/config', SNAPD_DROPINS,
               *(f'/root/{p}' for p in PIP_USER + NPM_USER),
               # Whoever can change the system's environment or login scripts can point every install elsewhere.
               *_env_files(root, listing, ENV_SYSTEM)]
    try:
        guarded += [f'{FLATPAK_SYSTEM}/{n}' for n in os.listdir(os.path.join(root, FLATPAK_SYSTEM.lstrip('/')))
                    if n.endswith('.trustedkeys.gpg')]
    except OSError:
        pass
    return [p for p in guarded if _exists(root, p)]
