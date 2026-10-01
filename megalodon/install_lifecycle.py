"""Verified user-service handoff and bounded, manifest-owned release retirement."""
import json
import ipaddress
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


def _listener_pid(port, host):
    """Prove the managed user service owns this TCP listener, not just its URL."""
    try:
        result=subprocess.run(['systemctl','--user','show','--property=MainPID','--value',
                               'megalodon-hud.service'],capture_output=True,text=True,timeout=5,check=False)
        pid=int(result.stdout.strip())
        if result.returncode or pid<=0:return None
        process=Path('/proc')/str(pid)
        if process.stat().st_uid!=os.getuid():return None
        sockets={p.readlink().as_posix()[8:-1] for p in (process/'fd').iterdir()
                 if p.readlink().as_posix().startswith('socket:[')}
        # IPv4 loopback is the supported HUD listener. /proc/<pid>/net is the
        # process's network namespace; ownership additionally requires its fd.
        for row in (process/'net/tcp').read_text().splitlines()[1:]:
            fields=row.split()
            address,hexport=fields[1].split(':')
            if (fields[3]=='0A' and int(hexport,16)==port and fields[9] in sockets
                    and str(ipaddress.ip_address(bytes.fromhex(address)[::-1]))==host):
                return pid
    except (OSError,ValueError,IndexError,subprocess.SubprocessError):
        pass
    return None


def verify_running(paths, expected, timeout=30):
    from .config import load_settings
    from .local_install import InstallError
    settings = load_settings(paths.settings).dashboard
    host='127.0.0.1' if settings.host=='localhost' else settings.host
    try:address=ipaddress.ip_address(host)
    except ValueError:address=None
    if address is None or address.version!=4 or not address.is_loopback:
        raise InstallError('Upgrade verification requires a loopback HUD')
    url = f'http://{host}:{settings.port}/healthz'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            pid=_listener_pid(settings.port,host)
            if pid is None:
                time.sleep(.2)
                continue
            with opener.open(url, timeout=1) as response:
                value = json.loads(response.read(1025))
                if (response.status == 200 and value == {'status': 'ready', 'package_sha256': expected}
                        and _listener_pid(settings.port,host)==pid):
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
                    descriptors=[]
                    for descriptor in (process/'fd').iterdir():
                        try:descriptors.append(str(descriptor.readlink()))
                        except FileNotFoundError:continue
                    marker=any(value.startswith(str(paths.releases)+'/') and value.endswith('/megalodon') for value in descriptors)
                    # Older runtimes may use the mutable alias without a
                    # release descriptor. Keep uncertain releases intact.
                    ambiguous=str(paths.current).encode() in command and not marker
                    if (ambiguous or str(path).encode() in command or str(path).encode() in (process / 'maps').read_bytes()
                            or any(value.startswith(str(path)+'/') for value in descriptors)):
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
