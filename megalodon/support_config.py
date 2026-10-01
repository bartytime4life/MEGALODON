"""Fixed local companion configuration actions; no browser-selected commands."""
from __future__ import annotations
import argparse
from copy import deepcopy
from dataclasses import replace
from http.client import HTTPConnection
from ipaddress import ip_network
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
from threading import Lock, Thread
import time

from .companion_automation import _run_fixed
from .managed_capture import ManagedCapture, now
from .live_geography import Geography
from .live_connections import LiveConnections
from .background_monitor import BackgroundMonitor
from .support_sensors import SupportSensors, zeek_binary
from .support_services import QWEN_LOCAL_SCRIPT, SURICATA_SCRIPT


def _owned_directory(path, *, private):
    from .local_install import _owned_directory as owned_directory
    return owned_directory(path, private=private)


def _regular_owned_file(path, *, maximum):
    from .local_install import _regular_owned_file as regular_owned_file
    return regular_owned_file(path, maximum=maximum)


def _atomic_write(path, value, mode):
    from .local_install import _atomic_write as atomic_write
    return atomic_write(path, value, mode)

SCHEMA = 'megalodon-support-config-v1'
COMMAND = '~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.support_config'
ACTION_FIELDS = {
    'capture_permissions': {'interface'}, 'capture_start': {'interface'}, 'capture_stop': set(),
    'wireshark_open': {'interface'}, 'wireshark_stop': set(),
    'nmap_configure': {'nmap_target'}, 'clamav_configure': {'scan_folder'},
    'signature_update': set(), 'osquery_configure': set(), 'qwen_check': set(),
    'zeek_check': set(), 'suricata_check': set(),
    'background_start': {'interface'}, 'background_stop': set(),
    'geography_refresh': set(), 'geography_disable': set(),
    'qwen_configure': set(), 'suricata_configure': {'interface'},
}
TOOL_NAMES = {'wireshark':'Wireshark / capture access', 'capture':'HUD packet metadata',
              'nmap':'Nmap / Zenmap', 'clamav':'ClamAV / ClamTk', 'osquery':'osquery',
              'qwen':'Ollama / Qwen', 'zeek':'Zeek', 'suricata':'Suricata',
              'background':'Background traffic', 'geography':'IP geography'}
# Only a root-owned packaged capture helper gains two packet capabilities.
# PKEXEC_UID is supplied by pkexec, never by an HTTP parameter. ACL access is
# immediate for this user, so a desktop logout/group refresh is unnecessary.
PERMISSION_SCRIPT = r'''set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
case "${PKEXEC_UID:-}" in ''|*[!0-9]*) exit 2;; esac
[ "$PKEXEC_UID" -gt 0 ]
[ -f /usr/bin/dumpcap ] && [ ! -L /usr/bin/dumpcap ]
[ "$(stat -c %u /usr/bin/dumpcap)" = 0 ]
[ -z "$(find /usr/bin/dumpcap -maxdepth 0 -perm /022 -print)" ]
dpkg-query -S /usr/bin/dumpcap | /usr/bin/grep -q '^wireshark-common:'
/usr/bin/chmod u-s,g-s /usr/bin/dumpcap
/usr/bin/setfacl -m "u:${PKEXEC_UID}:r-x,m::r-x,o::---" /usr/bin/dumpcap
/usr/sbin/setcap cap_net_raw,cap_net_admin=ep /usr/bin/dumpcap
'''


class ConfigBusy(Exception):
    pass


def interfaces():
    default = ''
    try:
        for row in Path('/proc/net/route').read_text().splitlines()[1:]:
            fields = row.split()
            if len(fields) >= 4 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                default = fields[0]
                break
    except (OSError, ValueError):
        pass
    values = []
    for _, name in socket.if_nameindex()[:32]:
        if not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,15}', name):
            continue
        try:
            up = (Path('/sys/class/net') / name / 'operstate').read_text().strip() == 'up'
        except OSError:
            up = False
        values.append(dict(name=name, default=name == default, up=up))
    return sorted(values, key=lambda row: (not row['default'], not row['up'], row['name']))


def valid_interface(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,15}', value) or value not in {row['name'] for row in interfaces()}:
        raise ValueError('Choose an existing local network interface.')
    return value


def valid_target(value):
    if type(value) is not str or len(value) > 32:
        raise ValueError('Choose a private IPv4 target or range of at most 256 addresses.')
    network = ip_network(value, strict=False)
    allowed = [ip_network(item) for item in ('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if network.version != 4 or network.num_addresses > 256 or not any(network.subnet_of(item) for item in allowed):
        raise ValueError('Choose a private IPv4 target or range of at most 256 addresses.')
    return str(network)


def capture_tools_available():
    return all(Path(path).is_file() for path in ('/usr/bin/dumpcap', '/usr/bin/tshark'))


def local_qwen_models():
    """Bounded retries while a freshly restarted daemon binds its local socket."""
    for attempt in range(20):
        connection = HTTPConnection('127.0.0.1',11434,timeout=2)
        try:
            connection.request('GET','/api/tags')
            response = connection.getresponse()
            raw = response.read(32769)
            if response.status != 200 or len(raw)>32768:
                raise ValueError('Local model inventory unavailable.')
            models = json.loads(raw).get('models')
            if type(models) is not list or len(models)>256:
                raise ValueError('Invalid local model inventory.')
            return models
        except OSError:
            if attempt==19:
                raise ValueError('Ollama has not become available on this PC; retry its configuration.') from None
            time.sleep(.5)
        finally:
            connection.close()


def validate_action(value):
    if type(value) is not dict or type(value.get('action')) is not str or value['action'] not in ACTION_FIELDS:
        raise ValueError('Choose a supported configuration action.')
    action = value['action']
    if set(value) != {'action'} | ACTION_FIELDS[action]:
        raise ValueError('Unexpected configuration fields.')
    if 'interface' in value:
        valid_interface(value['interface'])
    if 'nmap_target' in value:
        valid_target(value['nmap_target'])
    if 'scan_folder' in value and (type(value['scan_folder']) is not str or value['scan_folder'] not in {'Downloads','Documents'}):
        raise ValueError('Choose Downloads or Documents for the file scan.')
    return dict(value)


class SupportConfiguration:
    def __init__(self, settings, companions=None, startup=None, on_ready=None, *, home=None, run=_run_fixed):
        self.settings, self.companions, self.startup = settings, companions, startup
        self.home = Path.home() if home is None else Path(home)
        self.run = run
        self.root = self.home / '.local/share/megalodon/support'
        self.profile = self.home / '.config/megalodon/support-config.json'
        self.token = secrets.token_urlsafe(24)
        self._lock = Lock()
        self._thread = None
        self._cancel_capture_start = False
        choices = interfaces()
        self._settings = dict(interface=next((r['name'] for r in choices if r['default']), ''),
                              nmap_target='127.0.0.1/32', scan_folder='Downloads')
        self._configured = set()
        self._background_enabled = False
        self._geography_enabled = False
        self._tools = {}
        self._job = dict(state='idle', action=None, message='Choose an app to configure.', started_at=None, finished_at=None)
        self.geography = Geography(self.home)
        self.connections = LiveConnections(self.geography)
        self.capture = ManagedCapture(settings, self.root / 'analyzer', on_ready, connections=self.connections)
        self.background = BackgroundMonitor(self.capture, self.geography, lambda:self._geography_enabled)
        self.sensors = SupportSensors(self.home)
        self.qwen_status = dict(state='needs_setup',message='Configure local Qwen to enable bounded background advice.',updated_at=None,metrics=[])
        self.evidence = None
        self.flow_ingestor = None
        try:
            self._load()
        except (OSError, ValueError):
            self._job.update(state='failed', message='Saved setup could not be validated. Review the private support configuration file.')
        self._load_qwen()

    def _load_qwen(self):
        from .config import AISettings
        if not os.path.lexists(self.home/'.config/megalodon/qwen-profile.json'):
            return
        try:
            raw = _regular_owned_file(self.home/'.config/megalodon/qwen-profile.json',maximum=1024)
            value = json.loads(raw)
            if (set(value) != {'model','model_digest'} or value['model_digest'] != AISettings.model_digest
                    or type(value['model']) is not str or not re.fullmatch(r'qwen[A-Za-z0-9._:-]{1,91}',value['model'])):
                raise ValueError('Unrecognized Qwen profile')
            ai = replace(self.settings.ai,enabled=True,**value)
            self.settings = replace(self.settings,ai=ai)
            if self.companions:
                self.companions.ai = ai
            self.qwen_status.update(state='ready',message='Pinned local model configured; a completed response is required to confirm advice.',updated_at=now())
        except FileNotFoundError:
            pass
        except (OSError,ValueError,TypeError):
            self.qwen_status.update(state='needs_setup',message='Saved Qwen profile could not be validated; configure local Qwen again.')

    def _paths(self):
        _owned_directory(self.root, private=True)
        _owned_directory(self.root / 'analyzer', private=True)
        _owned_directory(self.profile.parent, private=True)

    def _load(self):
        if not os.path.lexists(self.profile):
            return
        from .ai_provider import _strict_pairs
        value = json.loads(_regular_owned_file(self.profile, maximum=2048), object_pairs_hook=_strict_pairs)
        if (type(value) is not dict or not {'schema','settings','configured'} <= set(value)
                or set(value)-{'schema','settings','configured','background_enabled','geography_enabled'} or value['schema'] != SCHEMA):
            raise ValueError('saved profile')
        enabled = value.get('background_enabled',False)
        if type(enabled) is not bool:
            raise ValueError('saved background mode')
        geography_enabled = value.get('geography_enabled',False)
        if type(geography_enabled) is not bool:
            raise ValueError('saved geography mode')
        settings = value['settings']
        if type(settings) is not dict or set(settings) != set(self._settings):
            raise ValueError('saved settings')
        valid_target(settings['nmap_target'])
        if settings['scan_folder'] not in {'Downloads','Documents'} or type(settings['interface']) is not str or not re.fullmatch(r'[A-Za-z0-9_.:@-]{0,15}', settings['interface']):
            raise ValueError('saved scope')
        configured = value['configured']
        if type(configured) is not list or len(configured) > 3 or any(type(item) is not str or item not in {'nmap','clamav','osquery'} for item in configured):
            raise ValueError('saved collectors')
        self._settings = dict(settings)
        self._configured = set(configured)
        self._background_enabled = enabled
        self._geography_enabled = geography_enabled
        if self.companions:
            updates = self._collector_updates()
            self.companions.configure(updates)

    def _collector_updates(self):
        updates = {}
        if 'nmap' in self._configured:
            updates['nmap_target'] = self._settings['nmap_target']
        if 'clamav' in self._configured:
            folder = self.home / self._settings['scan_folder']
            if folder.is_symlink() or not folder.is_dir():
                raise ValueError('saved scan folder unavailable')
            updates['clamav_paths'] = (folder,)
        if 'osquery' in self._configured:
            updates['osquery_enabled'] = True
        return updates

    def _save(self, settings=None, configured=None):
        self._paths()
        if os.path.lexists(self.profile):
            _regular_owned_file(self.profile, maximum=2048)
        value = dict(schema=SCHEMA, settings=self._settings if settings is None else settings,
                     configured=sorted(self._configured if configured is None else configured),
                     background_enabled=self._background_enabled, geography_enabled=self._geography_enabled)
        _atomic_write(self.profile, json.dumps(value, sort_keys=True).encode(), 0o600)

    def snapshot(self, include_token=False):
        with self._lock:
            value = dict(schema=SCHEMA, interfaces=interfaces(), settings=dict(self._settings),
                         job=dict(self._job), capture=self.capture.snapshot(), background=self.background.snapshot(),
                         geography_enabled=self._geography_enabled,
                         tools=deepcopy(list(self._tools.values())), command=COMMAND)
            if include_token:
                value['token'] = self.token
            return value

    def start(self, request):
        request = validate_action(request)
        if request['action'] in {'capture_stop','background_stop'}:
            with self._lock:
                self._cancel_capture_start = True
                was_enabled = self._background_enabled
                self._background_enabled = False
            self.background.stop()
            self.sensors.stop()
            if was_enabled:
                self._save()
            self._tool('capture', 'ready', 'HUD capture stopped; stored metadata remains available.')
            with self._lock:
                if self._job['state'] != 'running':
                    self._job.update(state='finished',action=request['action'],message='Background and HUD traffic capture stopped; stored metadata remains available.',started_at=now(),finished_at=now())
            return self.snapshot()
        with self._lock:
            if self._job['state'] == 'running' or (self.startup and self.startup.snapshot()['state'] == 'running'):
                raise ConfigBusy('Another support action is running.')
            self._job.update(state='running', action=request['action'], message='Applying the selected configuration…', started_at=now(), finished_at=None)
            if request['action'] in {'capture_start','background_start'}:
                self._cancel_capture_start = False
            self._thread = Thread(target=self._work, args=(request,), daemon=True, name='megalodon-support-config')
            self._thread.start()
        return self.snapshot()

    def _tool(self, identifier, state, message):
        with self._lock:
            self._tools[identifier] = dict(id=identifier, name=TOOL_NAMES[identifier], state=state,
                                          message=message, checked_at=now())

    def _execute(self, argv, timeout=30):
        raw, code = self.run(argv, 8192, timeout)
        if code != 0:
            raise ValueError('The tool did not complete successfully. Check its installed configuration or system authorization prompt.')
        return raw

    def _gui(self, action, interface=None):
        unit = 'megalodon-wireshark-capture.service'
        if action == 'stop':
            self._execute(['systemctl','--user','stop',unit])
            return 'Managed Wireshark window stopped; manually opened windows are unchanged.'
        _, code = self.run(['systemctl','--user','is-active','--quiet',unit], 8192, 5)
        if code == 0:
            raise ValueError('The managed Wireshark window is already open. Stop it before selecting another interface.')
        self._paths()
        directory = self.home / '.config/wireshark/profiles/MEGALODON'
        _owned_directory(directory, private=True)
        preferences = b'# Managed MEGALODON capture profile\ncapture.prom_mode: FALSE\nnameres.network_name: FALSE\n'
        path = directory / 'preferences'
        if os.path.lexists(path) and _regular_owned_file(path, maximum=4096) != preferences:
            raise ValueError('The MEGALODON Wireshark profile was edited; preserve it and review it before launch.')
        _atomic_write(path, preferences, 0o600)
        self._execute(['systemd-run','--user','--collect','--unit='+unit,'--property=Type=exec','--',
                       '/usr/bin/wireshark','-C','MEGALODON','-i',interface,'-k','-n','-p','-s','256',
                       '-a','duration:900','-c','50000'])
        return 'Live Wireshark launch requested for the selected interface (15 minutes / 50,000 packets). Its own capture buffer is separate from HUD metadata.'

    def _work(self, request):
        action = request['action']
        tool = 'capture' if action.startswith('capture_') else action.split('_')[0]
        tool = {'signature':'clamav','wireshark':'wireshark'}.get(tool, tool)
        failed = False
        try:
            if action in {'capture_permissions','capture_start','wireshark_open','background_start','suricata_configure'}:
                valid_interface(request['interface'])
                with self._lock:
                    self._settings['interface'] = request['interface']
                self._save()
            if action == 'capture_permissions':
                self._execute(['/usr/bin/pkexec','/bin/sh','-c',PERMISSION_SCRIPT], 90)
                self._execute(['/usr/bin/dumpcap','-i',request['interface'],'-L'], 10)
                message = 'Capture permissions configured for this user and interface access verified. Wireshark and the HUD run as your normal user.'
                tool = 'wireshark'
            elif action == 'capture_start':
                if self.background.snapshot()['enabled']:
                    raise ValueError('Background monitoring already owns traffic collection. Stop monitoring before starting a manual session.')
                with self._lock:
                    if self._cancel_capture_start:
                        raise ValueError('Capture start was cancelled.')
                    if not capture_tools_available():
                        raise ValueError('Install Wireshark / TShark before starting HUD capture.')
                    self.capture.start(request['interface'])
                message = 'HUD capture requested. Watch accepted metadata counts to confirm the data connection.'
            elif action == 'background_start':
                if not capture_tools_available():
                    raise ValueError('Install Wireshark / TShark before starting background traffic.')
                self.background.stop()
                self.sensors.stop()
                with self._lock:
                    if self._cancel_capture_start:
                        raise ValueError('Background start was cancelled.')
                    self._background_enabled = True
                    self.background.start(request['interface'])
                    self.sensors.start(request['interface'])
                self._save()
                if self.companions:
                    self.companions.request_collection()
                message = 'Background traffic enabled and configured inventory collectors queued. Monitoring resumes automatically with the local HUD.'
            elif action == 'geography_refresh':
                self._geography_enabled = True
                self._save()
                self.background.refresh_geography()
                message = 'Location refresh requested. Peer addresses stay on this PC; the public internet address lookup identifies this connection only.'
            elif action == 'geography_disable':
                self._geography_enabled = False
                self._save()
                message = 'Automatic location updates disabled. Saved local location data remains available.'
            elif action == 'capture_stop':
                self.capture.stop()
                message = 'HUD capture stopped; stored metadata remains available.'
            elif action == 'wireshark_open':
                message = self._gui('open', request['interface'])
            elif action == 'wireshark_stop':
                message = self._gui('stop')
            elif action in {'nmap_configure','clamav_configure','osquery_configure'}:
                if self.companions is None:
                    raise ValueError('Automatic companions are disabled in this HUD. Enable them at the next launch.')
                proposed = dict(self._settings)
                if action == 'nmap_configure':
                    proposed['nmap_target'] = valid_target(request['nmap_target'])
                    updates = {'nmap_target':proposed['nmap_target']}
                elif action == 'clamav_configure':
                    proposed['scan_folder'] = request['scan_folder']
                    folder = self.home / request['scan_folder']
                    _owned_directory(folder, private=False)
                    updates = {'clamav_paths':(folder,)}
                else:
                    updates = {'osquery_enabled':True}
                configured = self._configured | {tool}
                self.companions.configure(updates, before_apply=lambda: self._save(proposed, configured))
                with self._lock:
                    self._settings = proposed
                    self._configured = configured
                states = self.companions.request_collection({tool})
                message = f'Configuration saved. Collector {states[tool]}; results appear in its HUD panel.'
            elif action == 'signature_update':
                self._execute(['pkexec','/usr/bin/systemctl','start','clamav-freshclam.service'],90)
                self._execute(['systemctl','is-active','--quiet','clamav-freshclam.service'])
                message = 'ClamAV signature updater is active. Updated signatures are available to the next file scan.'
            elif action == 'qwen_configure':
                from .config import AISettings
                from .ai_provider import status
                self._execute(['/usr/bin/pkexec','/bin/sh','-c',QWEN_LOCAL_SCRIPT],90)
                models = local_qwen_models()
                matches = [r for r in models if type(r) is dict and r.get('digest')==AISettings.model_digest
                           and type(r.get('name')) is str and re.fullmatch(r'qwen[A-Za-z0-9._:-]{1,91}',r['name'])]
                if not matches:
                    raise ValueError('The supported pinned Qwen model is not installed. Existing models were preserved.')
                chosen = sorted(matches,key=lambda r:r['name'] != AISettings.model)[0]
                value = dict(model=chosen['name'],model_digest=AISettings.model_digest)
                self._paths()
                path = self.home/'.config/megalodon/qwen-profile.json'
                if os.path.lexists(path):
                    _regular_owned_file(path,maximum=1024)
                _atomic_write(path,json.dumps(value).encode(),0o600)
                self._load_qwen()
                result = status(self.settings.ai,probe=True)
                verified = result['inference_verified']
                message = ('Local Qwen generated a verified response; completed collector summaries can receive bounded advice.' if verified
                           else 'Local-only Qwen configured; model response is not verified yet ('+result['state']+'). Collectors will retry advice after completion.')
                self.qwen_status.update(state='connected' if verified else 'ready',message=message,updated_at=now())
            elif action == 'suricata_configure':
                self._execute(['/usr/bin/pkexec','/bin/sh','-c',SURICATA_SCRIPT,'megalodon-suricata',request['interface']],90)
                message = 'Passive Suricata service configured for the selected interface; the HUD reads bounded recent EVE summaries while monitoring runs.'
            elif action == 'qwen_check':
                connection = HTTPConnection('127.0.0.1',11434,timeout=3)
                try:
                    connection.request('GET','/api/tags')
                    response = connection.getresponse()
                    raw = response.read(32769)
                    if response.status != 200 or len(raw) > 32768:
                        raise ValueError('Local Ollama model inventory is unavailable.')
                    data = json.loads(raw)
                    models = data.get('models',[])
                    qwen = [row for row in models if type(row) is dict and str(row.get('name','')).startswith('qwen')]
                    message = f'Local Ollama responded; {len(qwen)} Qwen model(s) installed. HUD advisory still uses its configured model and digest.'
                finally:
                    connection.close()
            elif action == 'zeek_check':
                binary = zeek_binary(self.home)
                if binary is None:
                    raise ValueError('Zeek was not found on PATH or in the verified local installation location.')
                self._execute([binary,'--version'])
                self._paths()
                _owned_directory(self.root / 'zeek', private=True)
                message = 'Zeek CLI checked. Background monitoring automatically samples bounded traffic and presents separate flow summaries in Apps.'
            elif action == 'suricata_check':
                self._paths()
                logs = self.root / 'suricata-check'
                _owned_directory(logs, private=True)
                self._execute(['suricata','-T','-c','/etc/suricata/suricata.yaml','-l',str(logs)],60)
                message = 'Installed Suricata configuration passed its native validation. Start support apps can start the configured service; HUD evidence intake is separate.'
            else:
                raise ValueError('Unsupported setup action.')
            self._tool(tool, 'ready', message)
        except (OSError, ValueError, ConfigBusy, subprocess.SubprocessError) as exc:
            failed = True
            message = str(exc)[:512] if isinstance(exc, (ValueError, ConfigBusy)) else 'This setup action could not complete. Check the installed tool and system authorization.'
            self._tool(tool, 'needs_setup', message)
        except Exception:
            failed = True
            message = 'Setup stopped unexpectedly. Completed settings are preserved; check the local service.'
            self._tool(tool, 'failed', message)
        finally:
            with self._lock:
                self._job.update(state='failed' if failed else 'finished', message=message, finished_at=now())

    def close(self):
        self.sensors.stop()
        self.background.stop()
        self.geography.close()

    def resume(self):
        if self._background_enabled:
            try:
                self._paths()
                self.background.start(valid_interface(self._settings['interface']))
                self.sensors.start(self._settings['interface'])
            except (OSError,ValueError):
                self._tool('background','needs_setup','Saved monitoring could not resume; review interface and private paths.')

    def live_snapshot(self):
        result=self.connections.snapshot(self.capture.snapshot(),self.background.snapshot())
        result['recording_mode']=self.evidence.recording_mode if self.evidence is not None else 'packet_metadata'
        return result

    def start_background_tools(self):
        """Shared startup action, with no desktop processes or caller commands."""
        with self._lock:
            if self._job['state']=='running':
                raise ConfigBusy('Configuration is already running.')
            if self.background.snapshot()['enabled'] and self.background.snapshot()['state']!='failed':
                if self.sensors.snapshot().get('zeek',{}).get('state')=='error':
                    self.sensors.stop()
                    self.sensors.start(self._settings['interface'])
                return self.capture.snapshot()
            self._cancel_capture_start = False
            self._job.update(state='running',action='background_start',started_at=now(),finished_at=None)
        self._work(dict(action='background_start',interface=self._settings['interface']))
        if self._job['state']=='failed':
            raise ValueError(self._job['message'])
        return self.capture.snapshot()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Configure local MEGALODON support apps through the running HUD')
    parser.add_argument('action', nargs='?', choices=['status',*ACTION_FIELDS], default='status')
    parser.add_argument('--interface')
    parser.add_argument('--nmap-target')
    parser.add_argument('--scan-folder', choices=['Downloads','Documents'])
    parser.add_argument('--config', type=Path)
    args = parser.parse_args(argv)
    from .config import load_settings
    from .dashboard import loopback_host
    try:
        path = args.config or Path.home()/'.config/megalodon/settings.toml'
        settings = load_settings(path)
        host = loopback_host(settings.dashboard.host)
        origin = f'http://{host}:{settings.dashboard.port}'
        def call(method='GET', value=None, token=None):
            connection = HTTPConnection(host,settings.dashboard.port,timeout=5)
            headers = {'X-Megalodon-Check':'1'}
            if method == 'POST':
                headers.update({'Origin':origin,'Content-Type':'application/json','X-Megalodon-Config-Token':token})
            try:
                connection.request(method,'/api/support-config',body=json.dumps(value) if value else None,headers=headers)
                response = connection.getresponse()
                raw = response.read(65537)
                if len(raw)>65536 or response.status not in (200,202):
                    raise ValueError('Open the local HUD and check setup status (or use its button if sign-in is enabled).')
                data = json.loads(raw)
                if data.get('schema') != SCHEMA:
                    raise ValueError('Update the local HUD before configuring apps.')
                return data
            finally:
                connection.close()
        value = call()
        if args.action != 'status':
            body = {'action':args.action}
            for field in ACTION_FIELDS[args.action]:
                body[field] = getattr(args, field)
            validate_action(body)
            value = call('POST',body,value['token'])
            deadline = time.monotonic()+125
            print('Applying setup. A system authorization prompt may appear.',flush=True)
            while value['job']['state'] == 'running' and time.monotonic()<deadline:
                time.sleep(.5)
                value = call()
        print(value['job']['message'])
        print('HUD capture:',value['capture']['state'],'—',value['capture']['accepted'],'accepted metadata rows')
        for item in value['tools']:
            print(f"- {item['name']}: {item['message']}")
        return 1 if value['job']['state'] in {'failed','running'} else 0
    except (OSError, ValueError, TypeError) as exc:
        print('Support configuration unavailable:',str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
