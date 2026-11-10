"""Explicit startup setup; polling reads cached observations and starts nothing."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from . import execution_boundary, hud_autostart
from .companion_automation import _run_fixed
from .local_install import InstallError
from .support_startup import _trusted_system_executable

# Fixed installed services only. Never accept a unit or command from a request.
SERVICES = {
    'qwen': ('Ollama', ('ollama', 'snap.ollama.listener')),
    'suricata': ('Suricata', ('suricata',)),
    'signatures': ('ClamAV signature updater', ('clamav-freshclam',)),
}


def service_observation(identifier, run=_run_fixed):
    execution_boundary.require_effects_allowed()
    name, units = SERVICES[identifier]
    systemctl = _trusted_system_executable('systemctl')
    observed = []
    unknown = False
    if systemctl:
        for unit in units:
            try:
                raw, code = run([systemctl, 'show', '--property=LoadState,ActiveState,UnitFileState', unit+'.service'], 2048, 3)
                values = dict(line.split('=', 1) for line in raw.decode('utf-8').splitlines() if '=' in line)
                if code == 0 and set(values)=={'LoadState','ActiveState','UnitFileState'} and values.get('LoadState') in {'loaded','masked'} and values.get('ActiveState') in {'active','inactive','failed'}:
                    observed.append((unit, values))
                elif values != {'LoadState':'not-found','ActiveState':'inactive','UnitFileState':''}:
                    unknown = True
            except execution_boundary.Stage0Denied:
                raise
            except (OSError, ValueError, UnicodeError, RuntimeError):
                unknown = True
    active = [item for item in observed if item[1].get('ActiveState') == 'active']
    selected = None if unknown else active[0] if len(active) == 1 else observed[0] if len(observed) == 1 else None
    if selected is None:
        return dict(id=identifier, name=name, unit=None, active='unknown', enabled='unknown',
                    message='Multiple installed services need review.' if len(observed)>1 else 'No supported service could be confirmed.')
    unit, value = selected
    enabled = {'enabled':'enabled', 'disabled':'disabled', 'masked':'masked',
               'enabled-runtime':'temporary', 'static':'static'}.get(value.get('UnitFileState'), 'unknown')
    return dict(id=identifier, name=name, unit=unit, active='running' if value.get('ActiveState')=='active' else 'stopped',
                enabled=enabled, message='Service state observed. Model and sensor readiness are checked separately.')


class StartupPolicy:
    def __init__(self, *, run=_run_fixed):
        execution_boundary.require_effects_allowed()
        self.run = run
        self._lock = Lock()
        self._value = dict(checked_at=None, login='unchecked', services=[],
                           message='Check startup to see what will resume after you sign in.')

    def snapshot(self):
        with self._lock:
            return deepcopy(self._value)

    def check(self):
        execution_boundary.require_effects_allowed()
        login = 'unavailable'
        try:
            managed = hud_autostart.validate_unit()
            state = hud_autostart._service_state()
            if state is not None and not hud_autostart.loaded_elsewhere(state, hud_autostart.unit_path(), managed) and not hud_autostart.loaded_dropins(state):
                systemctl = _trusted_system_executable('systemctl')
                if managed and systemctl:
                    raw, code = self.run([systemctl, '--user', 'is-enabled', hud_autostart.UNIT], 256, 3)
                    result = raw.decode('ascii').strip()
                    login = 'enabled' if code == 0 and result == 'enabled' else 'disabled' if result == 'disabled' else 'unavailable'
                elif not managed:
                    login = 'disabled'
        except execution_boundary.Stage0Denied:
            raise
        except (InstallError, OSError, ValueError, UnicodeError, RuntimeError):
            pass
        services = [service_observation(key, self.run) for key in SERVICES]
        with self._lock:
            self._value = dict(checked_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
                               login=login, services=services,
                               message='Startup settings checked. Enabled services start at boot; the HUD resumes at user sign-in.')
        return self.snapshot()

    def login(self, enabled):
        execution_boundary.require_effects_allowed()
        try:
            if enabled:
                hud_autostart.enable()
            else:
                hud_autostart.disable_login()
        finally:
            self.check()
        expected = 'enabled' if enabled else 'disabled'
        if self.snapshot()['login'] != expected:
            raise ValueError('The requested login setting could not be confirmed. Check startup before retrying.')
        return 'HUD startup at sign-in is '+('on.' if enabled else 'off. The current HUD keeps running.')

    def enable_services(self, *, clamav_configured=False):
        execution_boundary.require_effects_allowed()
        systemctl = _trusted_system_executable('systemctl')
        pkexec = _trusted_system_executable('pkexec')
        if not systemctl or not pkexec:
            raise ValueError('System authorization is unavailable. Configure service startup in your Linux service manager.')
        pending = []
        for key in SERVICES:
            if key == 'signatures' and not clamav_configured:
                continue
            # Do not enable an arbitrary pre-existing Suricata capture profile.
            if key == 'suricata' and not Path('/etc/systemd/system/suricata.service.d/zz-megalodon-passive.conf').is_file():
                continue
            row = service_observation(key, self.run)
            if row['unit'] and row['enabled'] in {'enabled','disabled','temporary'}:
                pending.append(row['unit']+'.service')
        if not pending:
            self.check()
            raise ValueError('No eligible service found. Configure Ollama or passive Suricata, or save a ClamAV scan folder first.')
        try:
            _, code = self.run([pkexec, systemctl, 'enable', '--now', *pending], 2048, 90)
        finally:
            self.check()
        rows = [r for r in self.snapshot()['services'] if r['unit'] and r['unit']+'.service' in pending]
        if code or len(rows)!=len(pending) or any(r['enabled']!='enabled' or r['active']!='running' for r in rows):
            raise ValueError('Some service startup settings were not confirmed. Completed changes remain; review each service below.')
        return 'Eligible services are running and enabled at boot. Review skipped or unavailable services below.'
