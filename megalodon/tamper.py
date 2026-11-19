"""Tamper detection: notice when MEGALODON itself is switched off, changed or blinded.

An intruder's first move is often to silence the defenses (ATT&CK T1562.001):
stop the timers, edit a baseline so a backdoor looks normal, point the alerts
somewhere else, or replace the sensor's own code. This module has two halves:

* `tamper baseline|check|accept` records MEGALODON's code, its scheduled
  units and their systemd state, and its configuration (alert settings,
  response policy, allow lists, every watch's baseline), and reports changes.
* `heartbeat send` posts a signed, numbered heartbeat off the machine, with a
  digest of that state and any tamper findings. `heartbeat monitor`, run on
  another machine, reports a heartbeat that went silent, was replayed, has a
  bad signature, or whose state changed. A machine that stops talking is the
  one case local checks cannot report themselves.

A root intruder can change the local baseline and, with the key, forge
heartbeats: the off-machine record of the state digest and of silence is
what such an intruder cannot take back.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import tempfile
import tomllib
import urllib.request

SCHEMA = 'megalodon-tamper-v1'
REPORT_SCHEMA = 'megalodon-tamper-report-v1'
HEARTBEAT_SCHEMA = 'megalodon-heartbeat-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/tamper.json'
DEFAULT_HEARTBEAT = '~/.config/megalodon/heartbeat.json'
DEFAULT_SEQUENCE = '~/.local/state/megalodon/heartbeat-sequence.json'
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
CONFIG_DIR = '~/.config/megalodon'

# What each recorded configuration file is, by name; anything else in the folder is a watch's baseline.
CONFIG_KINDS = {
    'settings.toml': ('ALERTS_CONFIG_CHANGED', 'HIGH', 'the settings, including where alerts go'),
    'response-policy.toml': ('POLICY_CHANGED', 'MEDIUM', 'the response policy'),
    'ancestry-allow.json': ('ALLOW_LIST_CHANGED', 'HIGH', 'the process ancestry allow list'),
    'credential-allow.json': ('ALLOW_LIST_CHANGED', 'HIGH', 'the credential reader allow list'),
    'heartbeat.json': ('HEARTBEAT_CONFIG_CHANGED', 'HIGH', 'the heartbeat destination and key'),
    'enforce.toml': ('ENFORCEMENT_CHANGED', 'HIGH', 'which response actions are carried out'),
}
# The files that decide what MEGALODON reports. Other files there (the HUD's own settings) change in normal use.
BASELINES = ('canary.json', 'listeners.json', 'persistence.json', 'binaries.json', 'log-integrity.json',
             'devices.json', 'webroot.json', 'egress.json', 'logins.json', 'boot.json',
             'ebpf.json', 'containers.json', 'hardening.json', 'packages.json')
WATCHED = tuple(CONFIG_KINDS) + BASELINES
RULE_FOLDER = 'yara-rules'

RULES = {
    'SENSOR_CODE_CHANGED': ('CRITICAL', 'MEGALODON\'s own program files changed. Upgrades do this; so does an '
                                        'intruder blinding the sensor.'),
    'SENSOR_CODE_ADDED': ('HIGH', 'A new file appeared among MEGALODON\'s own program files.'),
    'SENSOR_CODE_REMOVED': ('HIGH', 'One of MEGALODON\'s own program files was removed.'),
    'SCHEDULE_REMOVED': ('HIGH', 'A scheduled MEGALODON timer or service was removed.'),
    'SCHEDULE_CHANGED': ('HIGH', 'A scheduled MEGALODON unit file changed, for example its command.'),
    'WATCH_DISABLED': ('HIGH', 'A scheduled MEGALODON timer or service is no longer enabled.'),
    'WATCH_STOPPED': ('HIGH', 'A scheduled MEGALODON timer or service is not running.'),
    'WATCH_OVERDUE': ('HIGH', 'A scheduled MEGALODON check has not run for several of its intervals.'),
    'ALERTS_CONFIG_CHANGED': ('HIGH', 'The settings changed, including where alerts are sent.'),
    'ALLOW_LIST_CHANGED': ('HIGH', 'An allow list changed, so something is no longer reported.'),
    'HEARTBEAT_CONFIG_CHANGED': ('HIGH', 'The heartbeat destination or key changed.'),
    'ENFORCEMENT_CHANGED': ('HIGH', 'The enforcement policy changed: which response actions are carried out.'),
    'DETECTION_RULES_CHANGED': ('HIGH', 'A YARA rule file changed, so different files are flagged.'),
    'POLICY_CHANGED': ('MEDIUM', 'The response policy changed.'),
    'BASELINE_CHANGED': ('MEDIUM', 'A watch\'s baseline changed. `accept` does this after review; so does an '
                                   'intruder making a backdoor look normal.'),
    'CONFIG_REMOVED': ('HIGH', 'A MEGALODON baseline or configuration file was removed.'),
    'CONFIG_ADDED': ('LOW', 'A new MEGALODON baseline or configuration file.'),
    # Reported by the off-machine monitor.
    'HEARTBEAT_SILENT': ('CRITICAL', 'No heartbeat arrived within the allowed gap: the machine, its network or '
                                     'MEGALODON stopped.'),
    'HEARTBEAT_FORGED': ('CRITICAL', 'A heartbeat\'s signature does not match the key.'),
    'HEARTBEAT_REPLAYED': ('HIGH', 'A heartbeat repeated or went back in sequence: a replay, or a reset sender.'),
    'TAMPER_BASELINE_LOST': ('HIGH', 'The machine stopped reporting a tamper baseline after earlier heartbeats '
                                     'had one: the local check was switched off.'),
    'HEARTBEAT_REPORTS_TAMPER': ('HIGH', 'The machine\'s own tamper check reported findings.'),
    'SENSOR_STATE_CHANGED': ('MEDIUM', 'The state digest in the heartbeats changed.'),
    'HEARTBEAT_GAP': ('MEDIUM', 'Heartbeats are missing from the sequence: lost deliveries, or a sender that was '
                                'stopped and restarted.'),
}


class TamperError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _sha256(path):
    digest, read = hashlib.sha256(), 0
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        while read <= MAX_FILE_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest() if read <= MAX_FILE_BYTES else None


# ------------------------------------------------------------------ state

def _code(package):
    files = {}
    for folder, dirs, names in os.walk(package):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in sorted(names):
            if name.endswith(('.py', '.toml', '.json', '.js', '.css', '.html')):
                path = os.path.join(folder, name)
                files[os.path.relpath(path, package)] = _sha256(path)
    return files


def _alert_secrets(folder):
    """The URL and token files the alert settings point to: where alerts really go. Hashes only."""
    try:
        data = tomllib.loads(Path(folder, 'settings.toml').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    destinations = data.get('alerts', {}).get('destination', []) if isinstance(data.get('alerts'), dict) else []
    found = {}
    for destination in destinations if isinstance(destinations, list) else []:
        if not isinstance(destination, dict):
            continue
        for key in ('url_file', 'token_file'):
            value = destination.get(key)
            if isinstance(value, str) and value:
                path = os.path.expanduser(value)
                found[f'secret:{value}'] = _sha256(path) if os.path.lexists(path) else None
    return found


def _configs(folder):
    files = _alert_secrets(folder)
    for name in WATCHED:
        path = os.path.join(folder, name)
        if os.path.lexists(path):
            files[name] = _sha256(path)
    try:
        rules = sorted(os.listdir(os.path.join(folder, RULE_FOLDER)))
    except OSError:
        rules = []
    for name in rules:
        if name.endswith(('.yar', '.yara')):
            files[f'{RULE_FOLDER}/{name}'] = _sha256(os.path.join(folder, RULE_FOLDER, name))
    return files


def _units(unit_dir):
    from .schedule import MARKER, PREFIX
    units = {}
    try:
        names = sorted(os.listdir(unit_dir))
    except OSError:
        return units
    for name in names:
        if not name.startswith(PREFIX):
            continue
        path = os.path.join(unit_dir, name)
        try:
            text = Path(path).read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if MARKER in text:
            units[name] = hashlib.sha256(text.encode()).hexdigest()
    return units


def _systemctl(system, *args):
    return subprocess.run(['systemctl', *([] if system else ['--user']), *args], check=False, capture_output=True,
                          text=True, timeout=30)


def _uptime(root='/'):
    try:
        return float(Path(root, 'proc/uptime').read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def unit_states(units, system, runner=None, uptime=None):
    """{unit: {enabled, active, last_run_age}} from systemd, for the recorded units that are enabled entries."""
    from .schedule import JOBS, PREFIX
    runner = runner or _systemctl
    intervals = {f'{PREFIX}{j.name}.timer': j.interval for j in JOBS if j.calendar}
    intervals.update({f'{PREFIX}{j.name}.service': None for j in JOBS if not j.calendar})
    wanted = [u for u in units if u in intervals]
    states = {}
    for unit in wanted:
        result = runner(system, 'show', unit, '-p', 'UnitFileState', '-p', 'ActiveState',
                        '-p', 'LastTriggerUSecMonotonic')
        values = dict(line.split('=', 1) for line in (result.stdout or '').splitlines() if '=' in line)
        last = values.get('LastTriggerUSecMonotonic', '')
        age = None
        if last.isdigit() and int(last) > 0 and uptime is not None:
            age = max(0.0, uptime - int(last) / 1e6)
        states[unit] = dict(enabled=values.get('UnitFileState', ''), active=values.get('ActiveState', ''),
                            last_run_age=age, interval=intervals[unit])
    return states


def snapshot(*, package=None, config_dir=CONFIG_DIR, unit_dir=None, system=None):
    from . import schedule
    package = package or os.path.dirname(os.path.abspath(__file__))
    system = schedule._system_mode(system)
    unit_dir = unit_dir or schedule.unit_dir(system)
    return dict(package=str(package), code=_code(package), config_dir=str(Path(config_dir).expanduser()),
                configs=_configs(Path(config_dir).expanduser()), unit_dir=str(unit_dir), system=system,
                units=_units(unit_dir))


def state_digest(state):
    """One SHA-256 over the code, configuration and units: what the heartbeat carries off the machine."""
    canonical = json.dumps({k: state[k] for k in ('code', 'configs', 'units')}, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ------------------------------------------------------------------ baseline and check

def _write(path, value, mode=0o600):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.megalodon-', dir=path.parent)
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, indent=1)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path, schema, what):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise TamperError(f'no {what} at {path}') from None
    except OSError as exc:
        raise TamperError(f'{what} {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise TamperError(f'{what} {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise TamperError(f'{what} {path} is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != schema:
        raise TamperError(f'{what} {path} has an unsupported format')
    return value


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, **options):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise TamperError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(**options)
    _write(path, dict(schema=SCHEMA, recorded_at=_iso(_now()), **state))
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), code_files=len(state['code']),
                configs=sorted(state['configs']), units=sorted(state['units']), state_digest=state_digest(state))


def _finding(rule, subject, detail):
    severity, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=['T1562.001'], subject=subject, detail=detail,
                summary=summary)


def compare(old, new, states=None):
    findings = []
    for name in sorted(set(old['code']) | set(new['code'])):
        before, after = old['code'].get(name), new['code'].get(name)
        if before == after:
            continue
        rule = ('SENSOR_CODE_ADDED' if before is None else 'SENSOR_CODE_REMOVED' if name not in new['code']
                else 'SENSOR_CODE_CHANGED')
        findings.append(_finding(rule, f'code:{name}', f'{name} in {new["package"]}'))
    for name in sorted(set(old['configs']) | set(new['configs'])):
        before, after = old['configs'].get(name), new['configs'].get(name)
        if before == after:
            continue
        if name.startswith('secret:'):
            # Only its digest is recorded; the report never shows what the file holds.
            what = 'removed' if name not in new['configs'] or after is None else 'changed'
            findings.append(_finding('ALERTS_CONFIG_CHANGED', f'config:{name}',
                                     f'the alert destination file {name[7:]} {what}'))
        elif name not in new['configs']:
            findings.append(_finding('CONFIG_REMOVED', f'config:{name}', f'{name} was removed'))
        elif name not in old['configs']:
            findings.append(_finding('CONFIG_ADDED', f'config:{name}', f'{name} is new'))
        else:
            rule, _, what = CONFIG_KINDS.get(name, ('BASELINE_CHANGED', '', f'the baseline {name}'))
            if name.startswith(RULE_FOLDER + '/'):
                rule, what = 'DETECTION_RULES_CHANGED', f'the YARA rule file {name}'

            findings.append(_finding(rule, f'config:{name}', f'{what} changed ({name})'))
    for name in sorted(set(old['units']) | set(new['units'])):
        if name not in new['units']:
            findings.append(_finding('SCHEDULE_REMOVED', f'unit:{name}', f'{name} was removed'))
        elif name in old['units'] and old['units'][name] != new['units'][name]:
            findings.append(_finding('SCHEDULE_CHANGED', f'unit:{name}', f'{name} changed'))
    for unit, state in sorted((states or {}).items()):
        if state['enabled'] and state['enabled'] != 'enabled':
            findings.append(_finding('WATCH_DISABLED', f'unit:{unit}', f'{unit} is {state["enabled"]}'))
        if state['active'] and state['active'] != 'active':
            findings.append(_finding('WATCH_STOPPED', f'unit:{unit}', f'{unit} is {state["active"]}'))
        interval, age = state.get('interval'), state.get('last_run_age')
        if interval and age is not None and age > 3 * interval + 300:
            findings.append(_finding('WATCH_OVERDUE', f'unit:{unit}',
                                     f'{unit} last ran {int(age // 60)} minutes ago; it runs every '
                                     f'{max(1, interval // 60)} minutes'))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return findings


def check(manifest=DEFAULT_MANIFEST, *, runner=None, uptime=None, **options):
    old = _read(manifest, SCHEMA, 'tamper baseline')
    options.setdefault('package', old.get('package'))
    options.setdefault('config_dir', old.get('config_dir', CONFIG_DIR))
    options.setdefault('unit_dir', old.get('unit_dir'))
    options.setdefault('system', old.get('system'))
    new = snapshot(**options)
    states, gaps = {}, []
    if new['units']:
        try:
            states = unit_states(new['units'], new['system'], runner=runner,
                                 uptime=uptime if uptime is not None else _uptime())
        except (OSError, subprocess.SubprocessError) as exc:
            gaps.append(f'systemd could not be asked about the scheduled units: {exc}')
    findings = compare(old, new, states)
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_iso(_now()), findings=findings,
                units=states, state_digest=state_digest(new), gaps=gaps,
                note='After an upgrade or a reviewed change, `megalodon tamper accept` records the new state.')


def accept(manifest=DEFAULT_MANIFEST, **options):
    old = _read(manifest, SCHEMA, 'tamper baseline')
    for key in ('package', 'unit_dir', 'system'):
        options.setdefault(key, old.get(key))
    options.setdefault('config_dir', old.get('config_dir', CONFIG_DIR))
    return dict(baseline(manifest, replace=True, **options), action='accept')


# ------------------------------------------------------------------ heartbeat

def init_heartbeat(url, config=DEFAULT_HEARTBEAT, *, replace=False):
    """Record where heartbeats go and a new signing key; the key is printed once for the receiver."""
    from .alerts import AlertConfigError, check_url
    try:
        check_url(url, 'heartbeat')
    except AlertConfigError as exc:
        raise TamperError(str(exc)) from None
    path = Path(config).expanduser()
    if path.exists() and not replace:
        raise TamperError(f'{path} exists; pass --replace to set a new destination and key')
    key = secrets.token_hex(32)
    _write(path, dict(schema=HEARTBEAT_SCHEMA + '-config', url=url, key=key, sensor=socket.gethostname()[:253]))
    return dict(config=str(path), url=url, key=key,
                note='Give this key to the machine that runs `megalodon heartbeat monitor`; it is not shown again.')


def _sign(key, body):
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(bytes.fromhex(key), canonical, hashlib.sha256).hexdigest()


def _sender_state(path):
    path = Path(path).expanduser()
    try:
        return _read(path, HEARTBEAT_SCHEMA + '-sequence', 'heartbeat sequence')
    except TamperError:
        if path.exists():
            raise
        return dict(schema=HEARTBEAT_SCHEMA + '-sequence', sequence=0)


def heartbeat(config=DEFAULT_HEARTBEAT, *, manifest=DEFAULT_MANIFEST, sequence_path=DEFAULT_SEQUENCE, now=None,
              runner=None, uptime=None, **options):
    """One signed heartbeat: sequence, time, state digest and the tamper check's findings."""
    settings = _read(config, HEARTBEAT_SCHEMA + '-config', 'heartbeat configuration')
    sender = _sender_state(sequence_path)
    report = None
    if Path(manifest).expanduser().exists():
        sender['baseline_seen'] = True
        try:
            report = check(manifest, runner=runner, uptime=uptime, **options)
        except TamperError as exc:
            report = dict(findings=[_finding('CONFIG_REMOVED', 'config:tamper.json', str(exc))], state_digest=None)
    elif sender.get('baseline_seen'):
        # A baseline that existed and is gone switches every baseline check off: that is a finding, not silence.
        report = dict(findings=[_finding('CONFIG_REMOVED', 'config:tamper.json',
                                         f'the tamper baseline {Path(manifest).expanduser()} was removed')],
                      state_digest=None)
    sender['sequence'] += 1
    _write(sequence_path, sender)
    body = dict(schema=HEARTBEAT_SCHEMA, sensor=settings.get('sensor', ''), sequence=sender['sequence'],
                sent_at=_iso(now or _now()),
                state_digest=(report or {}).get('state_digest') or state_digest(snapshot(**options)),
                tamper_baseline=Path(manifest).expanduser().exists(),
                findings=[dict(rule_id=f['rule_id'], severity=f['severity'], subject=f['subject'])
                          for f in (report or {}).get('findings', [])][:20])
    body['mac'] = _sign(settings['key'], body)
    return settings, body


def send(settings, body, *, opener=None, timeout=10):
    data = json.dumps(body, sort_keys=True).encode()
    request = urllib.request.Request(settings['url'], data=data, method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'User-Agent': 'MEGALODON-heartbeat/1'})
    opener = opener or urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=timeout) as response:
        return response.status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# ------------------------------------------------------------------ the off-machine monitor

def _parse_time(value):
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def monitor(lines, key, *, max_gap=900, now=None, sensor=None):
    """Findings over received heartbeats (JSON lines, oldest first) from one sensor."""
    now = now or _now()
    findings, last, last_time, digest, refused, reported = [], None, None, None, 0, frozenset()
    had_baseline = False
    for line in lines:
        if len(line) > MAX_LINE_BYTES:
            refused += 1
            continue
        try:
            body = json.loads(line)
        except ValueError:
            refused += 1
            continue
        if type(body) is not dict or body.get('schema') != HEARTBEAT_SCHEMA:
            refused += 1
            continue
        if sensor and body.get('sensor') != sensor:
            continue
        mac = body.pop('mac', '')
        try:
            valid = isinstance(mac, str) and hmac.compare_digest(mac, _sign(key, body))
        except (ValueError, TypeError):
            valid = False
        sequence, sent = body.get('sequence'), _parse_time(body.get('sent_at'))
        if not valid or type(sequence) is not int or sent is None:
            findings.append(_finding('HEARTBEAT_FORGED', f'heartbeat:{sequence}',
                                     f'heartbeat {sequence} from {body.get("sensor")!r} has a bad signature'))
            continue
        # Checked for every signed heartbeat, replayed or not: wiping the sender's sequence record as well as
        # its baseline makes every later heartbeat look replayed.
        if body.get('tamper_baseline') is True:
            had_baseline = True
        elif had_baseline:
            # Seen from outside, so it holds even if the sender's own record was wiped too.
            findings.append(_finding('TAMPER_BASELINE_LOST', f'heartbeat:{sequence}',
                                     f'heartbeat {sequence} has no tamper baseline; earlier ones did'))
            had_baseline = False
        if last is not None and sequence <= last:
            findings.append(_finding('HEARTBEAT_REPLAYED', f'heartbeat:{sequence}',
                                     f'heartbeat {sequence} arrived after {last}'))
            continue
        if last is not None and sequence > last + 1:
            findings.append(_finding('HEARTBEAT_GAP', f'heartbeat:{last + 1}-{sequence - 1}',
                                     f'heartbeats {last + 1} to {sequence - 1} never arrived'))
        if digest is not None and body.get('state_digest') != digest:
            findings.append(_finding('SENSOR_STATE_CHANGED', f'heartbeat:{sequence}',
                                     f'the state digest changed at heartbeat {sequence}'))
        current = frozenset((f.get('rule_id'), f.get('subject')) for f in body.get('findings') or []
                            if isinstance(f, dict))
        if current and current != reported:      # each new set once, not every heartbeat that repeats it
            listed = ', '.join(f"{f.get('rule_id')} {f.get('subject')}" for f in body['findings'][:5])
            findings.append(_finding('HEARTBEAT_REPORTS_TAMPER', f'heartbeat:{sequence}',
                                     f'heartbeat {sequence} reports: {listed}'))
        reported = current
        last, last_time, digest = sequence, sent, body.get('state_digest')
    if last_time is None:
        findings.append(_finding('HEARTBEAT_SILENT', 'heartbeat:none', 'no valid heartbeat has been received'))
    elif (now - last_time).total_seconds() > max_gap:
        minutes = int((now - last_time).total_seconds() // 60)
        findings.append(_finding('HEARTBEAT_SILENT', f'heartbeat:{last}',
                                 f'the last heartbeat ({last}) was {minutes} minutes ago'))
    findings.sort(key=lambda f: RANK.index(f['severity']))
    return dict(schema=REPORT_SCHEMA, action='monitor', checked_at=_iso(now), last_sequence=last,
                last_sent_at=_iso(last_time) if last_time else None, findings=findings, refused_lines=refused)
