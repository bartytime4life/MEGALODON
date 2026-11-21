"""A view across machines: one collector receives every machine's heartbeats and alerts.

Each MEGALODON machine already sends signed heartbeats (`megalodon heartbeat
send`) and alerts (webhook destinations). `megalodon fleet` is the other end:

* `enroll NAME --heartbeat-key KEY` records a machine and its heartbeat key, and
  prints a new token for its alert destination;
* `serve` receives heartbeats at /heartbeat and alerts at /alert, checks each
  against the machine it claims to come from, and keeps them per machine;
* `status` shows every machine: when it was last heard from, whether its
  heartbeats are signed, in sequence and on time, and its recent alerts. The
  same view is served at /status (JSON) and / (a page), to this machine only;
* `serve` also receives each machine's incident timeline at /events, signed
  with its heartbeat key (`megalodon timeline push`), and `timeline` tells
  incidents across machines: one machine's incident is joined to another's
  when both involve the same address within a day, as an attacker moving
  between machines, or reaching several, does;
* `serve` also receives each machine's command log lines and evidence bundles
  at /evidence (`megalodon evidence push`), keeps the first copy of each, and
  reports any later copy that differs; `evidence` lists and checks them.

Heartbeats are checked with the same rules as `megalodon heartbeat monitor`: a
machine that goes silent, a forged or replayed heartbeat, or a machine whose
tamper check reports findings is shown. Off loopback, `serve` needs TLS.
Nothing is sent to the machines; the collector only listens.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import tempfile
import threading

from . import tamper

SCHEMA = 'megalodon-fleet-v1'
REPORT_SCHEMA = 'megalodon-fleet-report-v1'
DEFAULT_DATA = '~/.local/share/megalodon/fleet'
MAX_BODY = 64 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MACHINES = 4096
WINDOW_HOURS = 24
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
BATCH_SCHEMA = 'megalodon-timeline-batch-v1'
EVENT_KINDS = frozenset({'finding', 'decision', 'action', 'undo', 'merge'})
MAX_BATCH_EVENTS = 2000
LINK_HOURS = 24
_RECEIVING = threading.Lock()
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}')


class FleetError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ------------------------------------------------------------------ enrolled machines

def _registry(data):
    return Path(data).expanduser() / 'machines.json'


def machines(data=DEFAULT_DATA):
    path = _registry(data)
    if not path.exists():
        return {}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise FleetError(f'{path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise FleetError(f'{path} must be a mode-600 file owned by you: it holds every machine\'s keys')
        raw = os.read(fd, 16 * 1024 * 1024)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise FleetError(f'{path} is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('machines')) is not dict:
        raise FleetError(f'{path} has an unsupported format')
    return value['machines']


def _save(data, registry):
    folder = Path(data).expanduser()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.machines-', dir=folder)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(dict(schema=SCHEMA, machines=registry), stream, sort_keys=True, indent=1)
        os.replace(temporary, _registry(data))
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def enroll(name, heartbeat_key, *, sensor=None, data=DEFAULT_DATA, replace=False):
    """Record a machine with the key its `heartbeat init` printed; returns a new token for its alerts."""
    if not _NAME.fullmatch(name or ''):
        raise FleetError('a machine name is letters, digits, dots, hyphens and underscores')
    if not re.fullmatch(r'[0-9a-f]{64}', heartbeat_key or ''):
        raise FleetError('the heartbeat key is the 64 hexadecimal characters `megalodon heartbeat init` printed')
    registry = machines(data)
    if name in registry and not replace:
        raise FleetError(f'{name} is already enrolled; pass --replace to give it a new key and token')
    claimed = sensor or name
    other = next((n for n, m in registry.items() if n != name and m['sensor'] == claimed), None)
    if other:
        raise FleetError(f'the sensor name {claimed!r} already belongs to {other}; heartbeats name one machine')
    if name not in registry and len(registry) >= MAX_MACHINES:
        raise FleetError(f'at most {MAX_MACHINES} machines can be enrolled')
    token = secrets.token_urlsafe(32)
    if name in registry:
        # Heartbeats signed with the old key would all look forged under the new one: set them aside, kept.
        folder = Path(data).expanduser() / 'machines' / name
        stamp = _now().strftime('%Y%m%dT%H%M%SZ')
        for kind in ('heartbeats.1.jsonl', 'heartbeats.jsonl'):
            if (folder / kind).exists():
                os.replace(folder / kind, folder / f'{kind.split(".")[0]}-before-{stamp}.{kind.split(".", 1)[1]}')
    registry[name] = dict(sensor=sensor or name, heartbeat_key=heartbeat_key, enrolled_at=_iso(_now()),
                          alert_token_sha256=hashlib.sha256(token.encode()).hexdigest())
    _save(data, registry)
    return dict(machine=name, sensor=sensor or name, alert_token=token, registry=str(_registry(data)),
                note='On that machine, add a webhook alert destination with format = "json": its token_file holds '
                     'alert_token alone and its url_file holds https://THIS-COLLECTOR:8650/alert, each a mode-600 '
                     'file. The token is not shown again; only its SHA-256 is kept here.')


def remove(name, *, data=DEFAULT_DATA):
    registry = machines(data)
    if registry.pop(name, None) is None:
        raise FleetError(f'{name} is not enrolled')
    _save(data, registry)
    return dict(machine=name, removed=True, note='Its received heartbeats and alerts are kept.')


# ------------------------------------------------------------------ receiving

def _append(data, name, kind, value):
    folder = Path(data).expanduser() / 'machines' / name
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = folder / f'{kind}.jsonl'
    line = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    try:
        if path.stat().st_size + len(line) > MAX_FILE:
            os.replace(path, folder / f'{kind}.1.jsonl')       # keep the previous file, drop the one before
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def _lines(data, name, kind):
    folder = Path(data).expanduser() / 'machines' / name
    out = []
    for path in (folder / f'{kind}.1.jsonl', folder / f'{kind}.jsonl'):
        try:
            out += path.read_bytes().decode('utf-8', 'replace').splitlines()
        except OSError:
            continue
    return out


def receive_heartbeat(body, *, data=DEFAULT_DATA, now=None):
    """(status, message) for one posted heartbeat; stored when it names an enrolled machine."""
    if type(body) is not dict or body.get('schema') != tamper.HEARTBEAT_SCHEMA:
        return 400, 'not a MEGALODON heartbeat'
    registry = machines(data)
    name = next((n for n, m in registry.items() if m['sensor'] == body.get('sensor')), None)
    if name is None:
        return 403, 'this sensor is not enrolled'
    # Stored exactly as it came, so its signature can be checked again, and whether or not that signature holds:
    # a forged heartbeat is itself something to show.
    _append(data, name, 'heartbeats', body)
    unsigned = {k: v for k, v in body.items() if k != 'mac'}
    try:
        valid = hmac.compare_digest(str(body.get('mac', '')), tamper._sign(registry[name]['heartbeat_key'], unsigned))
    except (ValueError, TypeError):
        valid = False
    return (200, 'ok') if valid else (401, 'the signature does not match this machine\'s key')


def receive_alert(body, token, *, data=DEFAULT_DATA, now=None):
    """(status, message) for one posted alert, authenticated by its machine's token."""
    if not token:
        return 401, 'an alert needs its machine\'s token'
    digest = hashlib.sha256(token.encode()).hexdigest()
    registry = machines(data)
    name = next((n for n, m in registry.items() if hmac.compare_digest(m['alert_token_sha256'], digest)), None)
    if name is None:
        return 401, 'the token belongs to no enrolled machine'
    if type(body) is not dict or not isinstance(body.get('rule_id'), str) or body.get('severity') not in RANK:
        return 400, 'not a MEGALODON alert (format = "json")'
    kept = {k: body[k] for k in ('rule_id', 'severity', 'detected_at', 'attack', 'summary', 'src_ip', 'dst_ip',
                                 'message', 'digest', 'suppressed_before') if k in body}
    # The machine is who the token says, not what the alert claims.
    _append(data, name, 'alerts', dict(kept, machine=name, claimed_sensor=str(body.get('sensor', ''))[:253],
                                       received_at=_iso(now or _now())))
    return 200, 'ok'


def _sequence_path(data, name):
    return Path(data).expanduser() / 'machines' / name / 'events-sequence.json'


def receive_events(body, *, data=DEFAULT_DATA, now=None):
    """(status, message) for one posted timeline batch, signed with its machine's heartbeat key."""
    if type(body) is not dict or body.get('schema') != BATCH_SCHEMA or type(body.get('events')) is not list \
            or type(body.get('sequence')) is not int or len(body['events']) > MAX_BATCH_EVENTS:
        return 400, 'not a MEGALODON timeline batch'
    registry = machines(data)
    name = next((n for n, m in registry.items() if m['sensor'] == body.get('sensor')), None)
    if name is None:
        return 403, 'this sensor is not enrolled'
    unsigned = {k: v for k, v in body.items() if k != 'mac'}
    try:
        valid = hmac.compare_digest(str(body.get('mac', '')), tamper._sign(registry[name]['heartbeat_key'], unsigned))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        return 401, 'the signature does not match this machine\'s key'
    with _RECEIVING:
        path = _sequence_path(data, name)
        try:
            last = json.loads(path.read_text()).get('sequence', 0)
        except (OSError, ValueError):
            last = 0
        # A batch sent again, by a replay or a retry that already arrived, adds nothing.
        if body['sequence'] <= last:
            return 409, 'this batch, or a later one, was already received'
        received = _iso(now or _now())
        for event in body['events']:
            if type(event) is dict and event.get('kind') in EVENT_KINDS and isinstance(event.get('event_id'), str):
                _append(data, name, 'events', dict(event, machine=name, received_at=received))
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix='.sequence-', dir=path.parent)
        with os.fdopen(handle, 'w') as stream:
            json.dump(dict(sequence=body['sequence'], at=received), stream)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    return 200, 'ok'


# ------------------------------------------------------------------ the timeline across machines

def fleet_events(*, data=DEFAULT_DATA):
    """Every received timeline event, once each, oldest first, with the machine it came from."""
    out, seen = [], set()
    for name in sorted(machines(data)):
        for line in _lines(data, name, 'events'):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            key = (name, event.get('event_id'))
            if type(event) is dict and key not in seen:
                seen.add(key)
                out.append(dict(event, machine=name))
    out.sort(key=lambda e: str(e.get('at') or ''))
    return out


def _parse(text):
    try:
        return datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    except ValueError:
        return None


# Program and file paths that link incidents on different machines: a dropped tool's own place. Ordinary paths, such
# as /usr/bin/curl or /etc/passwd, are on every machine and would join unrelated incidents.
DROPPED = ('/tmp/', '/var/tmp/', '/dev/shm/', '/memfd:')


def _link_key(key):
    """The key that joins this entity across machines ('address:...', 'name:...', 'file:...'), or None."""
    kind, _, value = key.partition(':')
    if kind == 'address' or (kind == 'name' and value):
        return key
    if kind in ('process', 'file'):
        path = value[:-len(' (deleted)')] if value.endswith(' (deleted)') else value
        if any(path.startswith(prefix) and path[len(prefix):].strip('/') for prefix in DROPPED):
            return f'file:{path}'               # a program and a file at the same place are the same thing
    return None


def fleet_groups(*, data=DEFAULT_DATA):
    """{fleet incident ID: events}: each machine's incidents, joined across machines by what they share.

    They are joined by an address, a watchlisted or generated-looking domain name, or a program or file in a
    temporary folder or memory, seen by two machines within a day."""
    from .timeline import _entity_keys
    every = fleet_events(data=data)
    # A machine merges two of its incidents after it sent their events: the merge joins them here too.
    merges = [e for e in every if e.get('kind') == 'merge']
    every = [e for e in every if e.get('kind') != 'merge']
    parent = {}

    def node(event):
        return (event['machine'], event.get('incident') or f"event:{event.get('event_id')}")

    def find(item):
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(a, b):
        parent[find(a)] = find(b)
    for merge in merges:
        if isinstance(merge.get('incident'), str) and isinstance(merge.get('merged'), str):
            union((merge['machine'], merge['merged']), (merge['machine'], merge['incident']))
    by_address = {}
    for event in every:
        find(node(event))
        for key in {_link_key(k) for k in _entity_keys(event.get('entities'))} - {None}:
            by_address.setdefault(key, []).append((_parse(event.get('at')), node(event)))
    window = timedelta(hours=LINK_HOURS)
    linked = {}
    for key, sightings in by_address.items():
        recent = {}                                    # node -> its latest sighting, oldest first
        for moment, item in sorted((s for s in sightings if s[0]), key=lambda s: s[0]):
            for other in [n for n, seen_at in recent.items() if moment - seen_at > window]:
                del recent[other]
            for other in recent:
                if other[0] != item[0]:
                    union(item, other)
                    # Addresses are listed bare, as before; other links say what they are.
                    linked.setdefault(frozenset((item, other)), set()).add(
                        key.partition(':')[2] if key.startswith('address:') else key)
            recent.pop(item, None)
            recent[item] = moment
    groups = {}
    for event in every:
        groups.setdefault(find(node(event)), []).append(event)
    named = {}
    for root, items in groups.items():
        first = min(items, key=lambda e: str(e.get('at') or ''))
        identifier = hashlib.sha256(f"{node(first)[0]}/{node(first)[1]}".encode()).hexdigest()[:12]
        nodes = {node(e) for e in items}
        shared = sorted({a for pair, addresses in linked.items() if pair <= nodes for a in addresses})
        named[identifier] = dict(events=items, linked_by=shared)
    return named


def fleet_timeline(*, data=DEFAULT_DATA, hours=168, now=None):
    """Incidents across every machine with activity in the last `hours`, worst and most recent first."""
    from .timeline import RANK as LEVELS, SCHEMA as TIMELINE_SCHEMA, summarize
    now = now or _now()
    cutoff = now - timedelta(hours=hours)
    rows = []
    for identifier, group in fleet_groups(data=data).items():
        row = summarize(identifier, group['events'])
        if not row['last'] or _parse(row['last']) < cutoff:
            continue
        row.update(machines=sorted({e['machine'] for e in group['events']}), linked_by=group['linked_by'],
                   machine_incidents=sorted({f"{e['machine']}/{e['incident']}" for e in group['events']
                                             if e.get('incident')}))
        rows.append(row)
    rows.sort(key=lambda r: r['last'], reverse=True)
    rows.sort(key=lambda r: LEVELS.index(r['severity']))
    return dict(schema=TIMELINE_SCHEMA, action='list', scope='fleet', hours=hours, incidents=rows)


def fleet_show(incident=None, *, entity=None, data=DEFAULT_DATA):
    """One fleet incident in order, or every event across machines that involved an entity."""
    from .timeline import SCHEMA as TIMELINE_SCHEMA, TimelineError, _matches, summarize
    if not incident and not entity:
        raise TimelineError('give a fleet incident ID, or --entity KIND:VALUE such as address:203.0.113.7')
    if entity and ':' not in entity:
        raise TimelineError('an entity is KIND:VALUE, such as address:203.0.113.7 or file:/tmp/x')
    groups = fleet_groups(data=data)
    if incident:
        chosen = [i for i in groups if i.startswith(incident)]
        if len(chosen) != 1:
            raise TimelineError(f'no fleet incident {incident} was received' if not chosen else
                                f'{incident} is the start of {len(chosen)} incidents; give more of it')
        identifiers = chosen
    else:
        identifiers = [i for i, g in groups.items() if any(_matches(e, entity) for e in g['events'])]
        if not identifiers:
            raise TimelineError(f'nothing received involves {entity}')
    events = sorted((e for i in identifiers for e in groups[i]['events']), key=lambda e: str(e.get('at') or ''))
    summaries = []
    for identifier in identifiers:
        row = summarize(identifier, groups[identifier]['events'])
        row.update(machines=sorted({e['machine'] for e in groups[identifier]['events']}),
                   linked_by=groups[identifier]['linked_by'])
        summaries.append(row)
    return dict(schema=TIMELINE_SCHEMA, action='show', scope='fleet', incident=identifiers[0] if incident else None,
                entity=entity, incidents=summaries, events=events, truncated=False)


# ------------------------------------------------------------------ the view

def status(*, data=DEFAULT_DATA, max_gap=900, hours=WINDOW_HOURS, now=None):
    """Every enrolled machine: heartbeat state, recent alerts, and what needs attention."""
    from . import evidence_shipping
    now = now or _now()
    since = now - timedelta(hours=hours)
    rows, findings = [], []
    for name, machine in sorted(machines(data).items()):
        beats = tamper.monitor(_lines(data, name, 'heartbeats'), machine['heartbeat_key'], max_gap=max_gap, now=now,
                               sensor=machine['sensor'])
        alerts = []
        for line in _lines(data, name, 'alerts'):
            try:
                alert = json.loads(line)
                when = datetime.strptime(alert['received_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            except (ValueError, KeyError, TypeError):
                continue
            if when >= since:
                alerts.append(alert)
        counts = {level: sum(a.get('severity') == level for a in alerts) for level in RANK}
        problems = [dict(f, machine=name, subject=f'{name}:{f["subject"]}', detail=f'{name}: {f["detail"]}')
                    for f in beats['findings']]
        problems += evidence_shipping.findings(data, name)
        findings += problems
        state = ('silent' if any(f['rule_id'] == 'HEARTBEAT_SILENT' for f in problems) else
                 'attention' if problems or counts['CRITICAL'] or counts['HIGH'] else 'ok')
        rows.append(dict(machine=name, sensor=machine['sensor'], state=state, last_heartbeat=beats['last_sent_at'],
                         last_sequence=beats['last_sequence'], heartbeat_findings=[f['rule_id'] for f in problems],
                         evidence=evidence_shipping.summary(data, name),
                         alerts=counts,
                         recent=[{k: a.get(k) for k in ('received_at', 'severity', 'rule_id', 'message')}
                                 for a in sorted(alerts, key=lambda a: a['received_at'], reverse=True)[:5]]))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return dict(schema=REPORT_SCHEMA, action='status', checked_at=_iso(now), window_hours=hours, machines=rows,
                findings=findings,
                summary={s: sum(r['state'] == s for r in rows) for s in ('ok', 'attention', 'silent')})


def page(report):
    """The status as one self-contained HTML page (no scripts, nothing fetched)."""
    e = html.escape
    colour = dict(ok='#1a7f37', attention='#9a6700', silent='#cf222e')
    rows = []
    for row in report['machines']:
        alerts = ', '.join(f'{n} {s.lower()}' for s, n in row['alerts'].items() if n) or 'none'
        recent = '<br>'.join(f"{e(a['received_at'] or '')} {e(a['severity'] or '')} {e(a['rule_id'] or '')}"
                             for a in row['recent'])
        rows.append(f"<tr><td>{e(row['machine'])}</td>"
                    f"<td style=\"color:{colour[row['state']]};font-weight:600\">{e(row['state'])}</td>"
                    f"<td>{e(row['last_heartbeat'] or 'never')}</td>"
                    f"<td>{e(', '.join(row['heartbeat_findings']) or '-')}</td><td>{e(alerts)}</td>"
                    f"<td>{recent or '-'}</td></tr>")
    summary = ', '.join(f'{n} {s}' for s, n in report['summary'].items())
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="refresh" content="60"><title>MEGALODON fleet</title>'
            '<style>body{font:14px system-ui,sans-serif;margin:16px;color:#1f2328;background:#fff}'
            'table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #d0d7de;padding:6px;'
            'text-align:left;vertical-align:top}th{background:#f6f8fa}'
            '@media(prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}th{background:#161b22}'
            'td,th{border-color:#30363d}}</style></head><body>'
            f'<h1>MEGALODON fleet</h1><p>{e(summary)} &middot; checked {e(report["checked_at"])} &middot; '
            f'alerts from the last {report["window_hours"]} hours</p>'
            '<table><tr><th>Machine</th><th>State</th><th>Last heartbeat</th><th>Heartbeat findings</th>'
            '<th>Alerts</th><th>Latest</th></tr>' + ''.join(rows) + '</table></body></html>')


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'MEGALODON-fleet/1'
    sys_version = ''
    data = DEFAULT_DATA
    max_gap = 900
    view = False                                   # a view listener answers GET and nothing else

    def log_message(self, format, *args):          # noqa: A002 - quiet; nothing secret is logged
        pass

    def _reply(self, code, body, kind='application/json'):
        data = body.encode() if isinstance(body, str) else json.dumps(body, sort_keys=True).encode()
        self.send_response(code)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(data)

    def _local(self):
        try:
            return ipaddress.ip_address(self.client_address[0].split('%')[0]).is_loopback
        except ValueError:
            return False

    def do_GET(self):                              # noqa: N802
        if not self.view:
            # The receiving listener never shows the view: a proxy in front of it may forward from loopback.
            return self._reply(404, dict(error='not found'))
        if not self._local():
            return self._reply(403, dict(error='the view is served to this machine only; use an SSH tunnel'))
        try:
            report = status(data=self.data, max_gap=self.max_gap)
        except FleetError as exc:
            return self._reply(500, dict(error=str(exc)))
        if self.path == '/status':
            return self._reply(200, report)
        if self.path in ('/timeline', '/timeline.json') or re.fullmatch(r'/timeline/[0-9a-f]{4,12}', self.path):
            from . import timeline
            try:
                if self.path.startswith('/timeline/'):
                    result = fleet_show(self.path.rsplit('/', 1)[1], data=self.data)
                    return self._reply(200, timeline.page(result), 'text/html')
                result = fleet_timeline(data=self.data)
            except (timeline.TimelineError, FleetError) as exc:
                return self._reply(404, dict(error=str(exc)))
            if self.path == '/timeline.json':
                return self._reply(200, result)
            return self._reply(200, timeline.list_page(result), 'text/html')
        if self.path in ('/', '/index.html'):
            return self._reply(200, page(report), 'text/html')
        return self._reply(404, dict(error='not found'))

    def do_POST(self):                             # noqa: N802
        if self.view:
            return self._reply(404, dict(error='not found'))
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            return self._reply(411, dict(error='a length is needed'))
        from . import evidence_shipping
        # Evidence arrives in larger pieces than heartbeats and alerts; everything else keeps the small limit.
        limit = evidence_shipping.MAX_BODY if self.path == '/evidence' else MAX_BODY
        if length < 0 or length > limit:
            return self._reply(413, dict(error=f'at most {limit} bytes'))
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return self._reply(400, dict(error='not JSON'))
        try:
            if self.path == '/heartbeat':
                code, message = receive_heartbeat(body, data=self.data)
            elif self.path == '/events':
                code, message = receive_events(body, data=self.data)
            elif self.path == '/evidence':
                code, answer = evidence_shipping.receive(body, data=self.data)
                return self._reply(code, answer)
            elif self.path == '/alert':
                auth = self.headers.get('Authorization', '')
                code, message = receive_alert(body, auth[7:] if auth.startswith('Bearer ') else '', data=self.data)
            else:
                code, message = 404, 'not found'
        except (FleetError, OSError) as exc:
            code, message = 500, str(exc)
        self._reply(code, dict(result=message))


def server(host='127.0.0.1', port=8650, *, data=DEFAULT_DATA, certificate=None, private_key=None, max_gap=900,
           plain_http=False):
    """A ready (not yet serving) collector. Off loopback, TLS is required unless plain_http says otherwise."""
    local = ipaddress.ip_address(host).is_loopback if re.fullmatch(r'[0-9a-fA-F:.]+', host) else host == 'localhost'
    if not local and not certificate and not plain_http:
        raise FleetError('listening beyond this machine needs --certificate and --private-key: alert tokens '
                         'would cross the network in the clear')
    machines(data)                                  # refuse to start on an unreadable or shared registry
    handler = type('FleetHandler', (Handler,), dict(data=data, max_gap=max_gap))
    httpd = http.server.ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    if certificate:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, private_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def view_server(host='127.0.0.1', port=8651, *, data=DEFAULT_DATA, max_gap=900):
    """The view (/ and /status) on its own listener, on loopback only."""
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == 'localhost'
    if not local:
        raise FleetError('the view listens on loopback only; reach it through an SSH tunnel')
    machines(data)
    handler = type('FleetViewHandler', (Handler,), dict(data=data, max_gap=max_gap, view=True))
    httpd = http.server.ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def serve_in_background(httpd):
    thread = threading.Thread(target=httpd.serve_forever, daemon=True, name='megalodon-fleet')
    thread.start()
    return thread
