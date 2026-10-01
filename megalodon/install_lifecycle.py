"""Verified user-service handoff and bounded, manifest-owned release retirement."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request


def selected_extras(paths):
    """Carry only supported extras forward; never clone an arbitrary environment."""
    extras = ['geo']
    if paths.current.exists():
        if any((paths.current / 'venv/lib').glob('python*/site-packages/scapy-*.dist-info')):
            extras.append('capture')
    return extras


def service_running(paths):
    from .hud_autostart import unit_path, unit_contents
    from .local_install import _regular_owned_file, InstallError
    unit = unit_path(paths)
    if not unit.exists():
        return False
    if _regular_owned_file(unit, maximum=8192) != unit_contents(paths):
        raise InstallError('Preserve and review the modified HUD service before upgrading')
    loaded = subprocess.run(['systemctl', '--user', 'show', '--property=FragmentPath', '--value',
                             'megalodon-hud.service'], capture_output=True, text=True, timeout=15, check=False)
    if loaded.returncode != 0 or loaded.stdout.strip() != str(unit):
        return False
    result = subprocess.run(['systemctl', '--user', 'is-active', '--quiet', 'megalodon-hud.service'],
                            timeout=15, check=False)
    return result.returncode == 0


def service_action(action):
    from .local_install import InstallError
    if action not in {'start', 'stop'}:
        raise InstallError('Unsupported service transition')
    try:
        subprocess.run(['systemctl', '--user', action, 'megalodon-hud.service'], check=True, timeout=90)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError('The HUD service could not complete its upgrade transition') from exc


def verify_running(paths, expected, timeout=30):
    from .config import load_settings
    from .local_install import InstallError
    settings = load_settings(paths.settings).dashboard
    if settings.host not in {'127.0.0.1', '::1'}:
        raise InstallError('Upgrade verification requires a loopback HUD')
    host = '[' + settings.host + ']' if ':' in settings.host else settings.host
    url = f'http://{host}:{settings.port}/healthz'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with opener.open(url, timeout=1) as response:
                value = json.loads(response.read(1025))
                if response.status == 200 and value == {'status': 'ready', 'package_sha256': expected}:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(.2)
    raise InstallError('New HUD did not confirm the installed package; restoring the previous release')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def retire_releases(paths, manifest):
    """Keep current/previous plus recent releases; refuse uncertain process use.

    Only manifest-listed, private trees are eligible. Untracked directories and
    data outside releases are never candidates. Interrupted deletion remains in
    the manifest and is safe to retry.
    """
    from .local_install import _expected_release, _owned_directory, _atomic_write
    protected = {manifest['active_release'], manifest['previous_release']}
    protected.update(row['id'] for row in manifest['releases'][-4:])
    retired = []
    for row in manifest['releases']:
        if row['id'] in protected:
            continue
        path = _expected_release(paths, row['id'])
        if path.exists():
            _owned_directory(path, private=True)
            used = False
            for process in Path('/proc').iterdir():
                if not process.name.isdigit():
                    continue
                try:
                    if process.stat().st_uid != os.getuid():
                        continue
                    command = (process / 'cmdline').read_bytes()
                    if str(path).encode() in command or str(path).encode() in (process / 'maps').read_bytes():
                        used = True
                        break
                except FileNotFoundError:
                    continue
                except OSError:
                    used = True
                    break
            if used:
                continue
            # rmtree does not follow interior symlinks (venv interpreter links
            # are expected). The private release root itself was validated.
            shutil.rmtree(path)
        retired.append(row)
    if retired:
        manifest['releases'] = [r for r in manifest['releases'] if r not in retired]
        _atomic_write(paths.manifest, (json.dumps(manifest, sort_keys=True, separators=(',', ':'))+'\n').encode(), 0o600)
    return manifest
