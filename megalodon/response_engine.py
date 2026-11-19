"""Automated response engine, shadow mode: decide what would be done, record it, do nothing.

``megalodon respond`` turns findings into response decisions under an
owner-written policy, so the decisions can be reviewed for weeks before any
action is ever allowed to run:

1. **Collect** findings from the network audit store, the process-network
   review (reverse shells, programs run from memory or temporary folders),
   and the listener, persistence, program-integrity, log and canary checks.
   Other findings, such as the ransomware watch's, can be piped in.
2. **Correlate** them into incidents by what they share: an address, a
   program, a file, a port, a persistence location or an account.
3. **Match** each new finding against the policy's playbooks.
4. **Plan** each playbook's actions against concrete targets, and run every
   plan through the guards: never-touch lists, the gateway and DNS servers,
   this machine's own addresses, system folders, rate limits and maximum
   durations.
5. **Record** each decision in an append-only, owner-only ledger, with the
   policy's SHA-256, as ``would_apply`` or ``refused`` with the guard's reason.

Shadow mode is the only mode. This module cannot act: it starts no process,
sends no signal, changes no firewall, file or account. ``mode = "enforce"`` is
refused until enforcement exists as separate, reviewed code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import sqlite3
import stat
import tempfile
import tomllib

SCHEMA = 'megalodon-response-decision-v1'
REPORT_SCHEMA = 'megalodon-response-run-v1'
DEFAULT_POLICY = '~/.config/megalodon/response-policy.toml'
DEFAULT_LEDGER = '~/.local/state/megalodon/response-shadow.jsonl'
DEFAULT_STATE = '~/.local/state/megalodon/response-state.json'
RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
MAX_POLICY_BYTES = 256 * 1024
MAX_PLAYBOOKS = 64
MAX_LEDGER_BYTES = 16 * 1024 * 1024
# The state's own bounds (seen keys, incidents, recent actions) keep it far below this.
MAX_STATE_BYTES = 64 * 1024 * 1024
MAX_SEEN = 20_000
MAX_INCIDENTS = 2_000
MAX_DB_ROWS = 5_000
MAX_INGEST_LINES = 10_000
SEEN_HOURS = 24

# The closed action set. Shadow mode only describes them; nothing here performs one.
ACTIONS = {
    'collect_evidence': dict(entity=None, effect='Save a hashed, read-only snapshot of the involved programs, '
                                                 'sockets and files before anything else happens',
                             reversible=True),
    'notify': dict(entity=None, effect='Send a summary to the off-machine alert destinations', reversible=True),
    'block_address': dict(entity='address', effect='Drop traffic to and from this address for a limited time',
                          reversible=True),
    # Targets are processes ('pid@start:program'), so a shared program such as a shell is never paused
    # everywhere. A program-wide target is planned only for an unshared program outside system folders.
    'suspend_process': dict(entity='process', effect='Pause (SIGSTOP) this process, or the processes running this '
                                                     'program, keeping them for investigation', reversible=True),
    'quarantine_file': dict(entity='file', effect='Move the file aside with no permissions, recording its hash',
                            reversible=True),
    'disable_persistence': dict(entity='persistence', effect='Disable this service, job or startup entry without '
                                                             'deleting it', reversible=True),
    'lock_account': dict(entity='account', effect='Lock this account\'s password and logins', reversible=True),
}
# 'peer' links incidents but is never an action target (a finding's other addresses).
# 'process_id' is 'pid@start:program': the PID with its start time names one process, not a reused PID.
ENTITY_KINDS = ('address', 'peer', 'process', 'process_id', 'file', 'port', 'persistence', 'account')
PROCESS_ID = re.compile(r'([0-9]{1,10})@([0-9]{1,20}):(/.{0,4095})', re.S)
SOURCES = ('network', 'process_review', 'ancestry', 'rootkit', 'listeners', 'persistence', 'binaries', 'logwatch',
           'devices', 'webroot', 'canary', 'ingest')
# Never acted on whatever a policy says: losing these cuts the machine off or breaks it.
SYSTEM_PROGRAMS = frozenset({'/sbin/init', '/usr/sbin/init', '/lib/systemd/systemd', '/usr/lib/systemd/systemd',
                             '/usr/lib/systemd/systemd-journald', '/usr/lib/systemd/systemd-logind',
                             '/usr/sbin/sshd', '/usr/sbin/dbus-daemon', '/usr/bin/dbus-daemon'})
SYSTEM_FOLDERS = ('/usr/', '/bin/', '/sbin/', '/lib/', '/lib64/', '/etc/', '/boot/', '/var/log/', '/var/lib/', '/proc/',
                  '/sys/', '/dev/')
DEFAULT_QUARANTINE_ROOTS = ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/root/', '/srv/', '/opt/', '/var/www/')
PROCESS_SEVERITY = {'STDIO_SHELL_ON_NETWORK': 'HIGH', 'SHELL_HOLDS_SOCKET': 'HIGH', 'PIPED_TO_SHELL': 'HIGH',
                    'EXECUTABLE_IN_MEMORY': 'HIGH', 'STDIO_ON_NETWORK': 'MEDIUM', 'EXECUTABLE_DELETED': 'MEDIUM',
                    'EXECUTABLE_IN_TEMPORARY': 'MEDIUM'}

DEFAULT_POLICY_TEXT = '''# MEGALODON response policy (shadow mode). Decisions are recorded, never carried out.
# Review `megalodon respond report` for a few weeks before trusting any playbook.
[response]
mode = "shadow"
correlation_minutes = 30
max_actions_per_hour = 20
max_actions_per_target_per_day = 3
max_block_minutes = 60
# Never acted on, in addition to the gateway, DNS servers, this machine's own
# addresses, init, systemd, sshd and dbus, root and the account running MEGALODON.
never_touch_addresses = []
never_touch_programs = []
never_touch_accounts = []
# Files outside these folders are never quarantined.
quarantine_roots = ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/srv/", "/opt/", "/var/www/"]

[response.sources]
# The network audit store; use an absolute path when running from a timer. "" turns a source off.
audit_db = "data/megalodon.db"
process_review = true
# Services starting shells or attack tools; the allow file is from `megalodon ancestry allow`.
ancestry_allow_file = "~/.config/megalodon/ancestry-allow.json"
# Rootkit cross-checks (processes, modules, folders, preloaded libraries). The port check briefly binds every
# free port, so it is off here; turn it on with rootkit_ports = true or run `megalodon rootkit check`.
rootkit_check = true
rootkit_ports = false
listeners_manifest = "~/.config/megalodon/listeners.json"
persistence_manifest = "~/.config/megalodon/persistence.json"
binaries_manifest = "~/.config/megalodon/binaries.json"
logwatch_manifest = "~/.config/megalodon/log-integrity.json"
devices_manifest = "~/.config/megalodon/devices.json"
webroot_manifest = "~/.config/megalodon/webroot.json"
canary_manifest = ""

[[response.playbook]]
name = "reverse-shell"
rules = ["STDIO_SHELL_ON_NETWORK", "SHELL_HOLDS_SOCKET", "PIPED_TO_SHELL"]
min_severity = "MEDIUM"
actions = ["collect_evidence", "suspend_process", "block_address", "notify"]
block_minutes = 15

[[response.playbook]]
name = "ransomware"
rules = ["RANSOMWARE_ENCRYPTION", "RANSOMWARE_MASS_WRITE"]
min_severity = "HIGH"
actions = ["collect_evidence", "suspend_process", "notify"]

[[response.playbook]]
name = "bind-shell-or-dropped-listener"
rules = ["NEW_LISTENER", "LISTENER_PROGRAM_CHANGED"]
min_severity = "HIGH"
actions = ["collect_evidence", "suspend_process", "notify"]

[[response.playbook]]
name = "web-shell-or-exploited-service"
rules = ["SERVICE_SPAWNED_SHELL", "SERVICE_SPAWNED_TOOL"]
min_severity = "HIGH"
actions = ["collect_evidence", "suspend_process", "notify"]

[[response.playbook]]
name = "rootkit"
rules = ["HIDDEN_PROCESS", "HIDDEN_MODULE", "HIDDEN_PORT", "HIDDEN_DIRECTORY", "HIDDEN_FILE", "PRELOAD_LIBRARY"]
min_severity = "HIGH"
# A machine that hides things from itself cannot be trusted to clean itself: preserve and escalate.
actions = ["collect_evidence", "notify"]

[[response.playbook]]
name = "web-shell-file"
rules = ["SCRIPT_IN_UPLOAD_FOLDER", "CODE_IN_NON_SCRIPT_FILE", "WEB_SHELL_PATTERN"]
min_severity = "HIGH"
actions = ["collect_evidence", "quarantine_file", "notify"]

[[response.playbook]]
name = "new-hardware"
rules = ["NEW_USB_KEYBOARD", "NEW_NETWORK_ADAPTER", "NEW_THUNDERBOLT_DEVICE", "DEVICE_GAINED_FUNCTIONS"]
min_severity = "HIGH"
# Only you know whether you plugged it in.
actions = ["notify"]

[[response.playbook]]
name = "program-from-memory"
rules = ["EXECUTABLE_IN_MEMORY"]
min_severity = "HIGH"
actions = ["collect_evidence", "notify"]

[[response.playbook]]
name = "attacker-at-the-door"
rules = ["BRUTE_FORCE", "HOST_SWEEP", "DECOY_TOUCH", "SYN_FLOOD", "PORT_SCAN"]
min_severity = "HIGH"
actions = ["block_address", "notify"]
block_minutes = 30

[[response.playbook]]
name = "command-and-control-or-exfiltration"
rules = ["BEACONING", "DATA_EXFILTRATION", "IOC_MATCH", "DGA_DOMAIN", "DNS_TUNNELING", "DNS_TUNNEL_CHURN"]
min_severity = "HIGH"
# Act only when a second, independent source agrees, such as a host finding about the same address.
require_corroboration = true
actions = ["collect_evidence", "block_address", "notify"]
block_minutes = 60

[[response.playbook]]
name = "new-backdoor-account"
rules = ["PERSISTENCE_ADDED", "PERSISTENCE_CHANGED"]
categories = ["account"]
min_severity = "CRITICAL"
actions = ["collect_evidence", "lock_account", "notify"]

[[response.playbook]]
name = "trojaned-program-or-wiped-log"
rules = ["PACKAGE_MISMATCH", "PACKAGE_RECORD_CHANGED", "LOG_DELETED", "LOG_TRUNCATED", "LOG_REWRITTEN",
         "CANARY_MODIFIED", "CANARY_REMOVED", "CANARY_READ"]
min_severity = "HIGH"
actions = ["collect_evidence", "notify"]
'''


class ResponseError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ------------------------------------------------------------------ policy

@dataclass(frozen=True)
class Playbook:
    name: str
    rules: frozenset
    min_severity: str
    actions: tuple
    block_minutes: int = 15
    require_corroboration: bool = False
    sources: frozenset = frozenset()
    categories: frozenset = frozenset()


@dataclass(frozen=True)
class Policy:
    digest: str
    playbooks: tuple
    correlation_minutes: int = 30
    max_actions_per_hour: int = 20
    max_actions_per_target_per_day: int = 3
    max_block_minutes: int = 60
    never_touch_addresses: frozenset = frozenset()
    never_touch_programs: frozenset = frozenset()
    never_touch_accounts: frozenset = frozenset()
    quarantine_roots: tuple = DEFAULT_QUARANTINE_ROOTS
    sources: dict = field(default_factory=dict)


def _strings(value, name, limit=256):
    if not isinstance(value, list) or len(value) > limit or not all(isinstance(v, str) and 0 < len(v) <= 512
                                                                     for v in value):
        raise ResponseError(f'{name} must be a list of up to {limit} strings')
    return value


def _integer(table, name, default, low, high):
    value = table.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ResponseError(f'response.{name} must be an integer from {low} to {high}')
    return value


def _playbook(raw, index):
    known = {'name', 'rules', 'min_severity', 'actions', 'block_minutes', 'require_corroboration', 'sources',
             'categories'}
    if not isinstance(raw, dict) or set(raw) - known:
        raise ResponseError(f'playbook {index} has unsupported settings: {", ".join(sorted(set(raw) - known))}')
    name = raw.get('name')
    if not isinstance(name, str) or not 0 < len(name) <= 64:
        raise ResponseError(f'playbook {index} needs a name')
    rules = _strings(raw.get('rules', []), f'playbook {name} rules')
    if not rules:
        raise ResponseError(f'playbook {name} must list at least one rule')
    severity = raw.get('min_severity', 'HIGH')
    if severity not in RANK:
        raise ResponseError(f'playbook {name} min_severity must be LOW, MEDIUM, HIGH or CRITICAL')
    actions = _strings(raw.get('actions', []), f'playbook {name} actions', 16)
    unknown = [a for a in actions if a not in ACTIONS]
    if not actions or unknown:
        raise ResponseError(f'playbook {name} actions must come from {", ".join(ACTIONS)}'
                            + (f'; unknown: {", ".join(unknown)}' if unknown else ''))
    sources = _strings(raw.get('sources', []), f'playbook {name} sources', 8)
    if set(sources) - set(SOURCES):
        raise ResponseError(f'playbook {name} sources must come from {", ".join(SOURCES)}')
    minutes = raw.get('block_minutes', 15)
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 1440:
        raise ResponseError(f'playbook {name} block_minutes must be 1 to 1440')
    corroboration = raw.get('require_corroboration', False)
    if not isinstance(corroboration, bool):
        raise ResponseError(f'playbook {name} require_corroboration must be true or false')
    return Playbook(name, frozenset(rules), severity, tuple(dict.fromkeys(actions)), minutes, corroboration,
                    frozenset(sources), frozenset(_strings(raw.get('categories', []), f'playbook {name} categories')))


def _private_file(path, what, limit=MAX_POLICY_BYTES):
    """Bytes of a regular file owned by this account and writable by no one else."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise ResponseError(f'no {what} at {path}') from None
    except OSError as exc:
        raise ResponseError(f'{what} {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ResponseError(f'{what} {path} must be a regular file owned by you and writable only by you')
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, min(1 << 20, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b''.join(chunks)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ResponseError(f'{what} {path} is too large')
    return data


def load_policy(path=DEFAULT_POLICY):
    path = Path(path).expanduser()
    data = _private_file(path, 'response policy')
    try:
        document = tomllib.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ResponseError(f'response policy {path} is not valid TOML: {exc}') from None
    if set(document) - {'response'} or not isinstance(document.get('response'), dict):
        raise ResponseError('the response policy must contain only a [response] table')
    table = document['response']
    known = {'mode', 'correlation_minutes', 'max_actions_per_hour', 'max_actions_per_target_per_day',
             'max_block_minutes', 'never_touch_addresses', 'never_touch_programs', 'never_touch_accounts',
             'quarantine_roots', 'sources', 'playbook'}
    if set(table) - known:
        raise ResponseError('response has unsupported settings: ' + ', '.join(sorted(set(table) - known)))
    mode = table.get('mode', 'shadow')
    if mode != 'shadow':
        raise ResponseError(f'response mode "{mode}" is not available: only shadow mode exists, which records '
                            'decisions and carries none of them out')
    playbooks = table.get('playbook', [])
    if not isinstance(playbooks, list) or len(playbooks) > MAX_PLAYBOOKS:
        raise ResponseError(f'up to {MAX_PLAYBOOKS} [[response.playbook]] entries are allowed')
    parsed = tuple(_playbook(raw, i) for i, raw in enumerate(playbooks, 1))
    if len({p.name for p in parsed}) != len(parsed):
        raise ResponseError('playbook names must be distinct')
    try:
        addresses = frozenset(str(ipaddress.ip_network(a, strict=False))
                              for a in _strings(table.get('never_touch_addresses', []), 'never_touch_addresses'))
    except ValueError:
        raise ResponseError('never_touch_addresses contains an invalid address or network') from None
    roots = tuple(r if r.endswith('/') else r + '/'
                  for r in _strings(table.get('quarantine_roots', list(DEFAULT_QUARANTINE_ROOTS)), 'quarantine_roots'))
    if any(not r.startswith('/') for r in roots):
        raise ResponseError('quarantine_roots must be absolute folders')
    sources = table.get('sources', {})
    allowed = {'audit_db', 'process_review', 'ancestry_allow_file', 'rootkit_check', 'rootkit_ports',
               'listeners_manifest', 'persistence_manifest', 'binaries_manifest', 'logwatch_manifest',
               'devices_manifest', 'webroot_manifest', 'canary_manifest'}
    switches = ('process_review', 'rootkit_check', 'rootkit_ports')
    if not isinstance(sources, dict) or set(sources) - allowed:
        raise ResponseError('response.sources has unsupported settings')
    for name, value in sources.items():
        if name in switches and not isinstance(value, bool):
            raise ResponseError(f'response.sources.{name} must be true or false')
        if name not in switches and (not isinstance(value, str) or len(value) > 1024):
            raise ResponseError(f'response.sources.{name} must be a path')
    return Policy(
        digest=hashlib.sha256(data).hexdigest(), playbooks=parsed,
        correlation_minutes=_integer(table, 'correlation_minutes', 30, 1, 1440),
        max_actions_per_hour=_integer(table, 'max_actions_per_hour', 20, 1, 1000),
        max_actions_per_target_per_day=_integer(table, 'max_actions_per_target_per_day', 3, 1, 100),
        max_block_minutes=_integer(table, 'max_block_minutes', 60, 1, 1440),
        never_touch_addresses=addresses,
        never_touch_programs=frozenset(_strings(table.get('never_touch_programs', []), 'never_touch_programs')),
        never_touch_accounts=frozenset(_strings(table.get('never_touch_accounts', []), 'never_touch_accounts')),
        quarantine_roots=roots, sources=dict(sources))


def write_default_policy(path=DEFAULT_POLICY, *, replace=False):
    path = Path(path).expanduser()
    if path.exists() and not replace:
        raise ResponseError(f'{path} exists; edit it, or pass --replace to start again from the defaults')
    _atomic_write(path, DEFAULT_POLICY_TEXT.encode('utf-8'))
    return dict(action='init', policy=str(path), playbooks=len(load_policy(path).playbooks),
                note='Shadow mode: decisions are recorded, never carried out. Review the playbooks before use.')


def _atomic_write(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.response-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


# ------------------------------------------------------------------ signals

@dataclass
class Signal:
    key: str
    source: str
    rule_id: str
    severity: str
    observed_at: str
    summary: str
    entities: dict
    category: str = ''

    def to_dict(self):
        return dict(key=self.key, source=self.source, rule_id=self.rule_id, severity=self.severity,
                    observed_at=self.observed_at, summary=self.summary[:300], category=self.category,
                    entities={k: sorted(v)[:16] for k, v in self.entities.items() if v})


def _entities(**values):
    out = {kind: set() for kind in ENTITY_KINDS}
    for kind, items in values.items():
        for item in items:
            if not item:
                continue
            if kind in ('address', 'peer'):
                try:
                    parsed = ipaddress.ip_address(str(item))
                except ValueError:
                    continue
                if parsed.is_unspecified:
                    continue
                item = str(parsed.ipv4_mapped or parsed) if parsed.version == 6 else str(parsed)
            out[kind].add(str(item)[:512])
    return out


def _host(endpoint):
    """The address of 'ip:port' or '[ip]:port'."""
    host = endpoint.rsplit(':', 1)[0] if endpoint.count(':') == 1 or endpoint.startswith('[') else endpoint
    host = host.strip('[]')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _severity(value):
    return value if value in RANK else 'MEDIUM'


def network_signals(db_path, cursor, now):
    """Unsuppressed network detections after `cursor`, read-only."""
    path = Path(db_path).expanduser()
    if not path.is_file():
        raise ResponseError(f'no audit store at {path}')
    connection = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True, timeout=5)
    try:
        rows = connection.execute(
            'SELECT id, detected_at, rule_id, severity, src_ip, dst_ip, message, evidence_json FROM detections '
            'WHERE id > ? AND suppressed_reason IS NULL ORDER BY id LIMIT ?', (cursor, MAX_DB_ROWS)).fetchall()
    finally:
        connection.close()
    signals = []
    for row_id, detected_at, rule, severity, src, dst, message, evidence_json in rows:
        try:
            evidence = json.loads(evidence_json)
        except ValueError:
            evidence = {}
        target = evidence.get('response_target') if isinstance(evidence, dict) else None
        signals.append(Signal(f'network:{row_id}', 'network', rule, _severity(severity), detected_at, message,
                              _entities(address=[target or src], peer=[src, dst])))
    return signals, (rows[-1][0] if rows else cursor)


def process_signals(review):
    signals = []
    for row in review.get('programs', []):
        for flag in row.get('flags', []):
            if flag not in PROCESS_SEVERITY:
                continue
            remotes = [_host(r) for r in row.get('remotes', [])]
            exe = row.get('executable', '')
            ids = [f'{i}:{exe}' for i in row.get('flag_processes', {}).get(flag, [])] if exe.startswith('/') else []
            signals.append(Signal(
                f'process:{flag}:{exe}:{",".join(sorted(r for r in remotes if r))}', 'process_review', flag,
                PROCESS_SEVERITY[flag], review.get('reviewed_at', ''),
                f"{row.get('program', '?')} ({exe}) {flag.lower().replace('_', ' ')}",
                _entities(process=[exe], process_id=ids, address=remotes)))
    return signals


def ancestry_signals(report):
    signals = []
    for f in report.get('findings', []):
        evidence = f.get('evidence', {})
        program, service = evidence.get('program', ''), evidence.get('service', {}).get('program', '')
        ids = [f"{evidence['pid']}@{evidence['start']}:{program}"] if (
            isinstance(evidence.get('pid'), int) and isinstance(evidence.get('start'), int)
            and program.startswith('/')) else []
        signals.append(Signal(f"ancestry:{f['rule_id']}:{service}:{ids[0] if ids else program}", 'ancestry',
                              f['rule_id'], _severity(f.get('severity')), report.get('checked_at', ''),
                              f.get('message', ''), _entities(process=[program], process_id=ids)))
    return signals


def rootkit_signals(report):
    signals = []
    for f in report.get('findings', []):
        program = f.get('program') or ''
        signals.append(Signal(f"rootkit:{f['rule_id']}:{f.get('subject', '')}", 'rootkit', f['rule_id'],
                              _severity(f.get('severity')), report.get('checked_at', ''), f.get('detail', ''),
                              _entities(process=[program] if program.startswith('/') else [],
                                        port=[f['subject']] if f['rule_id'] == 'HIDDEN_PORT' else [],
                                        file=[f['subject']] if f['rule_id'] == 'HIDDEN_FILE' else [])))
    return signals


def listener_signals(report):
    signals = []
    for f in report.get('findings', []):
        programs = [p.get('path', '') for p in f.get('programs', [])]
        signals.append(Signal(f"listeners:{f['rule_id']}:{f['listener']}:{','.join(sorted(programs))}", 'listeners',
                              f['rule_id'], _severity(f.get('severity')), report.get('checked_at', ''),
                              f"{f['rule_id']} {f['listener']} ({', '.join(programs) or 'owner unknown'})",
                              _entities(process=programs, port=[f['listener']])))
    return signals


def persistence_signals(report):
    signals = []
    for f in report.get('findings', []):
        rule = f"PERSISTENCE_{f.get('change', 'changed').upper()}"
        location, category = f.get('location', ''), f.get('category', '')
        entities = _entities(persistence=[f'{category}:{location}'],
                             account=[location] if category == 'account' else [],
                             file=[location] if location.startswith('/') else [])
        signals.append(Signal(f'persistence:{rule}:{category}:{location}', 'persistence', rule,
                              _severity(f.get('severity')), report.get('checked_at', ''),
                              f'{f.get("change")} {category} {location}', entities, category))
    return signals


def path_signals(report, source, key_field):
    signals = []
    for f in report.get('findings', []):
        path = f.get(key_field, '')
        signals.append(Signal(f"{source}:{f['rule_id']}:{path}", source, f['rule_id'], _severity(f.get('severity')),
                              report.get('checked_at', ''), f"{f['rule_id']} {path}", _entities(file=[path])))
    return signals


def ingest_signals(lines, now):
    """Findings piped in as JSON lines, such as `megalodon ransomware watch` output."""
    signals, refused = [], 0
    for number, line in enumerate(lines):
        if number >= MAX_INGEST_LINES:
            break
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            refused += 1
            continue
        if not isinstance(item, dict) or not isinstance(item.get('rule_id'), str):
            refused += 1
            continue
        evidence = item.get('evidence') if isinstance(item.get('evidence'), dict) else {}
        processes = [p.get('program') for p in evidence.get('processes', []) if isinstance(p, dict)]
        # A process named with its start time (as the ancestry watch writes it) is a suspension target.
        ids = [f"{p['pid']}@{p['start']}:{p['program']}" for p in evidence.get('processes', [])
               if isinstance(p, dict) and type(p.get('pid')) is int and type(p.get('start')) is int
               and isinstance(p.get('program'), str) and p['program'].startswith('/')]
        folder = evidence.get('folder')
        detected = item.get('detected_at') if isinstance(item.get('detected_at'), str) else _iso(now)
        digest = hashlib.sha256(line.encode()).hexdigest()[:16]
        signals.append(Signal(f"ingest:{item['rule_id']}:{digest}", 'ingest', item['rule_id'][:64],
                              _severity(item.get('severity')), detected, str(item.get('message', ''))[:300],
                              _entities(process=processes, process_id=ids,
                                        file=[folder] if isinstance(folder, str) else [],
                                        address=[item.get('src_ip'), item.get('dst_ip')])))
    return signals, refused


def collect(policy, state, now, *, root='/'):
    """Signals from every configured source, and the gaps of those that could not be read."""
    signals, gaps = [], []
    sources = policy.sources
    if sources.get('audit_db', 'data/megalodon.db'):
        try:
            found, state['cursor'] = network_signals(sources.get('audit_db', 'data/megalodon.db'),
                                                     state.get('cursor', 0), now)
            signals += found
        except (ResponseError, sqlite3.Error, OSError) as exc:
            gaps.append(f'network: {exc}')
    if sources.get('process_review', True):
        try:
            from . import process_network
            review = process_network.review(root, with_pids=True)
            signals += process_signals(review)
            gaps += [f'process_review: {gap}' for gap in review.get('gaps', [])]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            gaps.append(f'process_review: {exc}')
    if sources.get('ancestry_allow_file', '~/.config/megalodon/ancestry-allow.json'):
        from . import process_ancestry
        try:
            report = process_ancestry.check(
                root, allow_path=Path(sources.get('ancestry_allow_file',
                                                  '~/.config/megalodon/ancestry-allow.json')).expanduser())
            signals += ancestry_signals(report)
            gaps += [f'ancestry: {gap}' for gap in report.get('gaps', [])]
        except (process_ancestry.AncestryError, OSError) as exc:
            gaps.append(f'ancestry: {exc}')
    if sources.get('rootkit_check', True):
        from . import rootkit_check
        try:
            report = rootkit_check.check(root, ports=sources.get('rootkit_ports', False))
            signals += rootkit_signals(report)
            gaps += [f'rootkit: {gap}' for gap in report.get('gaps', [])]
        except (rootkit_check.RootkitError, OSError) as exc:
            gaps.append(f'rootkit: {exc}')
    checks = (('listeners_manifest', 'listener_watch', 'ListenerError', listener_signals),
              ('persistence_manifest', 'persistence_watch', 'PersistenceError', persistence_signals),
              ('binaries_manifest', 'binary_integrity', 'BinaryIntegrityError',
               lambda r: path_signals(r, 'binaries', 'path')),
              ('logwatch_manifest', 'log_integrity', 'LogIntegrityError',
               lambda r: path_signals(r, 'logwatch', 'log')),
              ('devices_manifest', 'device_watch', 'DeviceError', lambda r: path_signals(r, 'devices', 'device')),
              ('webroot_manifest', 'webroot_watch', 'WebrootError', lambda r: path_signals(r, 'webroot', 'path')))
    import importlib
    for setting, module_name, error_name, convert in checks:
        manifest = sources.get(setting, '')
        if not manifest:
            continue
        module = importlib.import_module(f'.{module_name}', __package__)
        try:
            report = module.check(Path(manifest).expanduser())
            signals += convert(report)
            # A check that ran but could not see everything says so; keep that in the run's gaps.
            gaps += [f'{setting.removesuffix("_manifest")}: {gap}' for gap in report.get('gaps', [])]
        except (getattr(module, error_name), OSError) as exc:
            gaps.append(f'{setting.removesuffix("_manifest")}: {exc}')
    if sources.get('canary_manifest'):
        from . import canary
        try:
            report = canary.check(str(Path(sources['canary_manifest']).expanduser()))
            signals += path_signals(dict(report, checked_at=_iso(now)), 'canary', 'path')
        except (ValueError, OSError) as exc:
            gaps.append(f'canary: {exc}')
    return signals, gaps


# ------------------------------------------------------------------ guards

def _protected_addresses(root='/'):
    """This machine's gateways, DNS servers and own addresses: blocking them cuts the machine off."""
    found = set()
    try:
        for line in Path(root, 'proc/net/route').read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 2 and fields[1] == '00000000' and fields[2] != '00000000':
                found.add(str(ipaddress.IPv4Address(int(fields[2], 16).to_bytes(4, 'little'))))
    except (OSError, ValueError):
        pass
    try:
        for line in Path(root, 'etc/resolv.conf').read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver':
                found.add(str(ipaddress.ip_address(parts[1].split('%')[0])))
    except (OSError, ValueError):
        pass
    try:
        for line in Path(root, 'proc/net/if_inet6').read_text().splitlines():
            hexed = line.split()[0]
            found.add(str(ipaddress.IPv6Address(bytes.fromhex(hexed))))
    except (OSError, ValueError, IndexError):
        pass
    try:
        lines = Path(root, 'proc/net/fib_trie').read_text().splitlines()
        for previous, line in zip(lines, lines[1:]):
            if line.strip() == '/32 host LOCAL':
                found.add(str(ipaddress.IPv4Address(previous.split()[-1])))
    except (OSError, ValueError, IndexError):
        pass
    return found


class Guards:
    def __init__(self, policy, state, now, *, root='/', protected=None):
        self.policy, self.state, self.now = policy, state, now
        self.protected = set(protected if protected is not None else _protected_addresses(root))
        self.networks = [ipaddress.ip_network(n) for n in policy.never_touch_addresses]
        self.me = {'root', _account_name()}
        day = now - timedelta(days=1)
        state['recent_actions'] = [r for r in state.get('recent_actions', [])
                                   if datetime.fromisoformat(r['at'].replace('Z', '+00:00')) >= day][-10_000:]

    def check(self, action, target):
        """None when the plan may proceed, else the guard's reason."""
        policy = self.policy
        if action == 'block_address':
            try:
                address = ipaddress.ip_address(target)
            except ValueError:
                return 'not an address'
            if not address.is_global:
                return 'not a public address: local attackers need switch-level controls'
            if target in self.protected:
                return 'this machine\'s gateway, DNS server or own address'
            if any(address in network for network in self.networks):
                return 'listed in never_touch_addresses'
        elif action == 'suspend_process':
            match = PROCESS_ID.fullmatch(target)
            program = match.group(3) if match else target
            if program in SYSTEM_PROGRAMS or program in policy.never_touch_programs:
                return 'a system program or listed in never_touch_programs'
            if match and int(match.group(1)) <= 1:
                return 'the init process'
            if not program.startswith('/'):
                return 'program path unknown'
            if not match:
                from .process_network import _program_kind
                if _program_kind(program, '') or program.startswith(SYSTEM_FOLDERS):
                    return ('a shared program: pausing it would pause every process running it, and the finding '
                            'names no specific process')
        elif action == 'quarantine_file':
            if target.startswith(SYSTEM_FOLDERS):
                return 'a system file: reinstall the package or restore it instead'
            if not target.startswith(policy.quarantine_roots):
                return 'outside quarantine_roots'
        elif action == 'lock_account':
            if target in self.me or target in policy.never_touch_accounts:
                return 'root, the account running MEGALODON, or listed in never_touch_accounts'
        elif action == 'disable_persistence':
            if target.split(':', 1)[0] in ('kernel_module', 'setuid', 'account'):
                return 'not a service, job or startup entry'
        return self._rate(action, target)

    def _rate(self, action, target):
        if action in ('collect_evidence', 'notify'):
            return None
        recent = [r for r in self.state.get('recent_actions', [])
                  if self.now - datetime.fromisoformat(r['at'].replace('Z', '+00:00')) < timedelta(days=1)]
        last_hour = [r for r in recent if self.now - datetime.fromisoformat(r['at'].replace('Z', '+00:00'))
                     < timedelta(hours=1)]
        if len(last_hour) >= self.policy.max_actions_per_hour:
            return f'rate limit: {self.policy.max_actions_per_hour} actions in the last hour'
        if sum(1 for r in recent if (r['action'], r['target']) == (action, target)) >= \
                self.policy.max_actions_per_target_per_day:
            return f'rate limit: {self.policy.max_actions_per_target_per_day} times on this target today'
        return None

    def count(self, action, target):
        if action not in ('collect_evidence', 'notify'):
            self.state.setdefault('recent_actions', []).append(dict(at=_iso(self.now), action=action, target=target))


def _account_name():
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError):
        return ''


# ------------------------------------------------------------------ correlation and decisions

def correlate(state, signals, now, window_minutes):
    """Attach each signal to an open incident sharing an entity, or open a new one. Returns {key: incident}."""
    incidents = state.setdefault('incidents', [])
    cutoff = now - timedelta(minutes=window_minutes)
    open_ = [i for i in incidents if datetime.fromisoformat(i['last_seen'].replace('Z', '+00:00')) >= cutoff]
    assigned = {}
    for signal in signals:
        # An address links incidents whichever role it had in each finding.
        keys = {f"{'address' if kind == 'peer' else kind}:{value}"
                for kind, values in signal.entities.items() for value in values}
        matches = [i for i in open_ if keys & set(i['entities'])]
        if matches:
            incident = matches[0]
            for other in matches[1:]:  # One signal links two incidents: merge them.
                incident['entities'] = sorted(set(incident['entities']) | set(other['entities']))
                incident['sources'] = sorted(set(incident['sources']) | set(other['sources']))
                incident['signals'] = list(dict.fromkeys(incident['signals'] + other['signals']))[-64:]
                open_.remove(other)
                incidents.remove(other)
                for key, previous in assigned.items():
                    if previous is other:
                        assigned[key] = incident
        else:
            incident = dict(id=hashlib.sha256(f'{signal.key}{_iso(now)}'.encode()).hexdigest()[:12],
                            opened_at=_iso(now), entities=[], sources=[], signals=[])
            incidents.append(incident)
            open_.append(incident)
        incident['entities'] = sorted(set(incident['entities']) | keys)[:256]
        incident['sources'] = sorted(set(incident['sources']) | {signal.source})
        incident['signals'] = list(dict.fromkeys(incident['signals'] + [signal.key]))[-64:]
        incident['last_seen'] = _iso(now)
        assigned[signal.key] = incident
    del incidents[:-MAX_INCIDENTS]
    return assigned


def _targets(action, signal, incident):
    entity = ACTIONS[action]['entity']
    if entity is None:
        return [None]
    if action == 'suspend_process' and signal.entities.get('process_id'):
        # The processes behind the finding, rather than every process running the same program.
        return sorted(signal.entities['process_id'])[:8]
    return sorted(signal.entities.get(entity, ()))[:8]


def decide(policy, state, signals, now, *, guards=None):
    """Shadow decisions for the signals not decided in the last day."""
    guards = guards or Guards(policy, state, now)
    seen = state.setdefault('seen', {})
    cutoff = now - timedelta(hours=SEEN_HOURS)
    for key in [k for k, at in seen.items() if datetime.fromisoformat(at.replace('Z', '+00:00')) < cutoff]:
        del seen[key]
    current = list({s.key: s for s in signals}.values())
    # Every current observation keeps its incident alive; only new ones are decided.
    assigned = correlate(state, current, now, policy.correlation_minutes)
    fresh = [s for s in current if s.key not in seen]
    decisions = []
    for signal in fresh:
        seen[signal.key] = _iso(now)
        incident = assigned[signal.key]
        playbook = next((p for p in policy.playbooks
                         if signal.rule_id in p.rules and RANK[signal.severity] >= RANK[p.min_severity]
                         and (not p.sources or signal.source in p.sources)
                         and (not p.categories or signal.category in p.categories)), None)
        if playbook is None:
            continue
        corroborated = len(incident['sources']) >= 2
        plans = []
        for action in playbook.actions:
            targets = _targets(action, signal, incident)
            if not targets:
                plans.append(dict(action=action, target=None, status='refused',
                                  guard=f'the finding names no {ACTIONS[action]["entity"]}'))
                continue
            for target in targets:
                plan = dict(action=action, target=target, effect=ACTIONS[action]['effect'],
                            reversible=ACTIONS[action]['reversible'])
                if action == 'block_address':
                    plan['minutes'] = min(playbook.block_minutes, policy.max_block_minutes)
                reason = None
                if playbook.require_corroboration and not corroborated and action not in ('collect_evidence', 'notify'):
                    reason = 'needs a second, independent source in the same incident'
                reason = reason or (guards.check(action, target) if target else None)
                if reason:
                    plan.update(status='refused', guard=reason)
                else:
                    plan['status'] = 'would_apply'
                    guards.count(action, target)
                plans.append(plan)
        decisions.append(dict(
            schema=SCHEMA, decided_at=_iso(now), mode='shadow', policy_sha256=policy.digest,
            playbook=playbook.name, signal=signal.to_dict(),
            incident=dict(id=incident['id'], sources=incident['sources'], signals=len(incident['signals']),
                          corroborated=corroborated),
            actions=plans, carried_out=False))
    seen_items = sorted(seen.items(), key=lambda kv: kv[1])
    state['seen'] = dict(seen_items[-MAX_SEEN:])
    return decisions


# ------------------------------------------------------------------ ledger and state

def _read_state(path):
    path = Path(path).expanduser()
    if not path.exists():
        return {}
    try:
        value = json.loads(_private_file(path, 'response state', MAX_STATE_BYTES))
    except ValueError:
        raise ResponseError(f'response state {path} is not valid JSON') from None
    return value if isinstance(value, dict) else {}


def _append_ledger(path, decisions):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > MAX_LEDGER_BYTES:
        os.replace(path, path.with_name(path.name + '.1'))
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ResponseError(f'response ledger {path} must be a mode-600 file owned by you')
        for decision in decisions:
            os.write(fd, (json.dumps(decision, sort_keys=True, separators=(',', ':')) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _summary(decisions, signals, gaps, policy, extra=None):
    actions = [a for d in decisions for a in d['actions']]
    return dict(schema=REPORT_SCHEMA, mode='shadow', policy_sha256=policy.digest, signals=len(signals),
                decisions=len(decisions), would_apply=sum(1 for a in actions if a['status'] == 'would_apply'),
                refused=sum(1 for a in actions if a['status'] == 'refused'), gaps=gaps,
                carried_out=0, note='Shadow mode: nothing was carried out.', **(extra or {}),
                latest=[dict(playbook=d['playbook'], rule_id=d['signal']['rule_id'],
                             actions=[f"{a['action']} {a['target'] or ''}".strip() + f" [{a['status']}]"
                                      for a in d['actions']]) for d in decisions[:10]])


def run(*, policy_path=DEFAULT_POLICY, ledger=DEFAULT_LEDGER, state_path=DEFAULT_STATE, now=None, root='/',
        signals=None, protected=None):
    """One shadow pass over every source (or the given signals)."""
    now = now or _now()
    policy = load_policy(policy_path)
    state = _read_state(state_path)
    gaps = []
    if signals is None:
        signals, gaps = collect(policy, state, now, root=root)
    decisions = decide(policy, state, signals, now, guards=Guards(policy, state, now, root=root, protected=protected))
    _append_ledger(ledger, decisions)
    _atomic_write(Path(state_path).expanduser(), json.dumps(state, sort_keys=True).encode())
    return _summary(decisions, signals, gaps, policy)


def ingest(lines, **options):
    now = options.pop('now', None) or _now()
    signals, refused = ingest_signals(lines, now)
    result = run(signals=signals, now=now, **options)
    result['refused_lines'] = refused
    return result


def report(*, ledger=DEFAULT_LEDGER, hours=168, now=None):
    """What the engine would have done over the last `hours`."""
    now = now or _now()
    path = Path(ledger).expanduser()
    decisions = []
    if path.exists():
        cutoff = now - timedelta(hours=hours)
        for line in _private_file_lines(path):
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if datetime.fromisoformat(item['decided_at'].replace('Z', '+00:00')) >= cutoff:
                decisions.append(item)
    by_playbook, by_action, guards, targets = {}, {}, {}, {}
    for d in decisions:
        by_playbook[d['playbook']] = by_playbook.get(d['playbook'], 0) + 1
        for a in d['actions']:
            key = f"{a['action']} {a['status']}"
            by_action[key] = by_action.get(key, 0) + 1
            if a['status'] == 'refused':
                guards[a['guard']] = guards.get(a['guard'], 0) + 1
            elif a['target']:
                targets[f"{a['action']} {a['target']}"] = targets.get(f"{a['action']} {a['target']}", 0) + 1
    top = sorted(targets.items(), key=lambda kv: -kv[1])[:10]
    return dict(schema='megalodon-response-report-v1', mode='shadow', hours=hours, decisions=len(decisions),
                by_playbook=dict(sorted(by_playbook.items())), actions=dict(sorted(by_action.items())),
                refused_by=dict(sorted(guards.items(), key=lambda kv: -kv[1])), top_targets=dict(top),
                policies=sorted({d['policy_sha256'] for d in decisions}),
                note='Shadow mode: every action listed here was recorded, none was carried out.')


def _private_file_lines(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ResponseError(f'response ledger {path} must be a mode-600 file owned by you')
        data = os.read(fd, MAX_LEDGER_BYTES + 1024 * 1024)
    finally:
        os.close(fd)
    return data.decode('utf-8', 'replace').splitlines()
