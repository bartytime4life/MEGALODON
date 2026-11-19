"""A view across machines: one collector receives every machine's heartbeats and alerts.

Each MEGALODON machine already sends signed heartbeats (`megalodon heartbeat
send`) and alerts (webhook destinations). `megalodon fleet` is the other end:

* `enroll NAME --heartbeat-key KEY` records a machine and its heartbeat key, and
  prints a new token for its alert destination;
* `serve` receives heartbeats at /heartbeat and alerts at /alert, checks each
  against the machine it claims to come from, and keeps them per machine;
* `status` shows every machine: when it was last heard from, whether its
  heartbeats are signed, in sequence and on time, and its recent alerts. The
  same view is served at /status (JSON) and / (a page), to this machine only.

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
    if name not in registry and len(registry) >= MAX_MACHINES:
        raise FleetError(f'at most {MAX_MACHINES} machines can be enrolled')
    token = secrets.token_urlsafe(32)
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


# ------------------------------------------------------------------ the view

def status(*, data=DEFAULT_DATA, max_gap=900, hours=WINDOW_HOURS, now=None):
    """Every enrolled machine: heartbeat state, recent alerts, and what needs attention."""
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
        findings += problems
        state = ('silent' if any(f['rule_id'] == 'HEARTBEAT_SILENT' for f in problems) else
                 'attention' if problems or counts['CRITICAL'] or counts['HIGH'] else 'ok')
        rows.append(dict(machine=name, sensor=machine['sensor'], state=state, last_heartbeat=beats['last_sent_at'],
                         last_sequence=beats['last_sequence'], heartbeat_findings=[f['rule_id'] for f in problems],
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
        if not self._local():
            return self._reply(403, dict(error='the view is served to this machine only; use an SSH tunnel'))
        try:
            report = status(data=self.data, max_gap=self.max_gap)
        except FleetError as exc:
            return self._reply(500, dict(error=str(exc)))
        if self.path == '/status':
            return self._reply(200, report)
        if self.path in ('/', '/index.html'):
            return self._reply(200, page(report), 'text/html')
        return self._reply(404, dict(error='not found'))

    def do_POST(self):                             # noqa: N802
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            return self._reply(411, dict(error='a length is needed'))
        if length < 0 or length > MAX_BODY:
            return self._reply(413, dict(error=f'at most {MAX_BODY} bytes'))
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return self._reply(400, dict(error='not JSON'))
        try:
            if self.path == '/heartbeat':
                code, message = receive_heartbeat(body, data=self.data)
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


def serve_in_background(httpd):
    thread = threading.Thread(target=httpd.serve_forever, daemon=True, name='megalodon-fleet')
    thread.start()
    return thread
