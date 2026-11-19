"""Opt-in off-machine alerts for committed findings: webhooks and syslog.

Findings are forwarded only after their audit bundle is saved, from background
threads, so delivery never delays or fails packet processing. Each destination
has its own bounded queue, rate limit and retry budget: a dead SIEM does not
hold back a phone push. Webhook URLs and tokens are read from owner-private
files and never logged. Payloads carry rule, severity, time and (by default)
the two addresses; the finding message, which can name a domain, is sent only
with ``detail = "full"``. An alert is a notice, not evidence and not authority:
the saved finding in the local store stays the record.
"""
from __future__ import annotations

import atexit
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import re
import socket
import stat
from threading import Condition, Lock, Thread
import time
import urllib.error
import urllib.parse
import urllib.request

from . import rule_catalog

SCHEMA = 'megalodon-alert-v1'
SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
DETAILS = ('minimal', 'standard', 'full')
KINDS = ('webhook', 'syslog')
FORMATS = ('json', 'slack', 'discord', 'ntfy')
PROTOCOLS = ('udp', 'tcp')
FACILITIES = {f'local{i}': 16 + i for i in range(8)} | {'user': 1, 'daemon': 3, 'auth': 4, 'security': 4}
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')
HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
MAX_DESTINATIONS = 8
MAX_QUEUE = 256
MAX_SECRET_BYTES = 4096
TIMEOUT_SECONDS = 5
RETRY_DELAYS = (0, 2, 8)
SYSLOG_PRIORITY = {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 4, 'LOW': 5}
NTFY_PRIORITY = {'CRITICAL': '5', 'HIGH': '4', 'MEDIUM': '3', 'LOW': '2'}
# 32473 is the IANA example enterprise number (RFC 5612), used for structured data.
SD_ID = 'megalodon@32473'

log = logging.getLogger('megalodon.alerts')


class AlertConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AlertDestination:
    name: str
    kind: str
    format: str = 'json'
    url_file: str = ''
    token_file: str = ''
    host: str = ''
    port: int = 514
    protocol: str = 'udp'
    facility: str = 'local0'

    def __post_init__(self):
        if type(self.name) is not str or not NAME.fullmatch(self.name):
            raise AlertConfigError('alert destination names use a-z, 0-9, dash or underscore (max 32)')
        if self.kind not in KINDS:
            raise AlertConfigError(f'alert destination {self.name}: kind must be webhook or syslog')
        if self.kind == 'webhook':
            if self.format not in FORMATS:
                raise AlertConfigError(f'alert destination {self.name}: format must be one of {", ".join(FORMATS)}')
            if type(self.url_file) is not str or not self.url_file:
                raise AlertConfigError(f'alert destination {self.name}: a webhook needs url_file '
                                       '(an owner-private file holding the URL)')
        else:
            if type(self.host) is not str or not HOST.fullmatch(self.host):
                raise AlertConfigError(f'alert destination {self.name}: syslog needs a host name or address')
            if type(self.port) is not int or not 1 <= self.port <= 65535:
                raise AlertConfigError(f'alert destination {self.name}: port must be 1-65535')
            if self.protocol not in PROTOCOLS or self.facility not in FACILITIES:
                raise AlertConfigError(f'alert destination {self.name}: protocol must be udp or tcp '
                                       'and facility a syslog facility such as local0')


@dataclass(frozen=True)
class AlertSettings:
    enabled: bool = False
    min_severity: str = 'HIGH'
    detail: str = 'standard'
    sensor_name: str = ''
    max_per_minute: int = 10
    destinations: tuple[AlertDestination, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if self.min_severity not in SEVERITIES:
            raise AlertConfigError('alerts.min_severity must be LOW, MEDIUM, HIGH or CRITICAL')
        if self.detail not in DETAILS:
            raise AlertConfigError('alerts.detail must be minimal, standard or full')
        if type(self.max_per_minute) is not int or not 1 <= self.max_per_minute <= 120:
            raise AlertConfigError('alerts.max_per_minute must be 1-120')
        if self.sensor_name and not HOST.fullmatch(self.sensor_name):
            raise AlertConfigError('alerts.sensor_name must be a host-name-like label')
        if len(self.destinations) > MAX_DESTINATIONS:
            raise AlertConfigError(f'alerts allows at most {MAX_DESTINATIONS} destinations')
        names = [d.name for d in self.destinations]
        if len(set(names)) != len(names):
            raise AlertConfigError('alert destination names must be unique')
        if self.enabled and not self.destinations:
            raise AlertConfigError('alerts.enabled needs at least one [[alerts.destination]]')


def parse_settings(raw):
    """Typed [alerts] table; unknown keys refuse rather than being ignored."""
    if type(raw) is not dict:
        raise AlertConfigError('alerts must be a TOML table')
    known = {'enabled', 'min_severity', 'detail', 'sensor_name', 'max_per_minute', 'destination'}
    if set(raw) - known:
        raise AlertConfigError('alerts contains unsupported settings: ' + ', '.join(sorted(set(raw) - known)))
    items = raw.get('destination', [])
    if type(items) is not list or not all(type(item) is dict for item in items):
        raise AlertConfigError('alerts.destination must be an array of tables ([[alerts.destination]])')
    fields_ = set(AlertDestination.__dataclass_fields__)
    destinations = []
    for item in items:
        if set(item) - fields_:
            raise AlertConfigError('alerts.destination contains unsupported settings: '
                                   + ', '.join(sorted(set(item) - fields_)))
        for key, value in item.items():
            if (key == 'port') != (type(value) is int):
                raise AlertConfigError(f'alerts.destination.{key} has the wrong type')
        destinations.append(AlertDestination(**item))
    enabled = raw.get('enabled', False)
    if type(enabled) is not bool:
        raise AlertConfigError('alerts.enabled must be true or false')
    severity, detail, sensor = (raw.get('min_severity', 'HIGH'), raw.get('detail', 'standard'),
                                raw.get('sensor_name', ''))
    if not all(type(v) is str for v in (severity, detail, sensor)):
        raise AlertConfigError('alerts.min_severity, detail and sensor_name must be strings')
    return AlertSettings(enabled=enabled, min_severity=severity.upper(), detail=detail, sensor_name=sensor,
                         max_per_minute=raw.get('max_per_minute', 10), destinations=tuple(destinations))


def read_secret(path):
    """One line from an owner-private regular file; never a link, FIFO or shared file."""
    path = os.path.expanduser(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise AlertConfigError(f'alert secret file {path} cannot be opened ({exc.strerror})') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AlertConfigError(f'alert secret file {path} is not a regular file')
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise AlertConfigError(f'alert secret file {path} must be owned by you with mode 600')
        data = os.read(fd, MAX_SECRET_BYTES + 1)
    finally:
        os.close(fd)
    try:
        lines = [line.strip() for line in data.decode('utf-8').splitlines() if line.strip()]
    except UnicodeDecodeError:
        raise AlertConfigError(f'alert secret file {path} is not UTF-8 text') from None
    if len(data) > MAX_SECRET_BYTES or len(lines) != 1 or any(ord(c) < 33 or ord(c) == 127 for c in lines[0]):
        raise AlertConfigError(f'alert secret file {path} must hold exactly one line with no spaces')
    return lines[0]


def check_url(url, name):
    """HTTPS anywhere; plain HTTP only to a literal loopback or private address."""
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or not parts.hostname:
        raise AlertConfigError(f'alert destination {name}: the URL must have a host and no user:password part')
    if parts.scheme == 'https':
        return url
    if parts.scheme == 'http':
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            address = None
        if address is not None and (address.is_loopback or address.is_private) and not address.is_link_local:
            return url
    raise AlertConfigError(f'alert destination {name}: use https, or http only to a literal private or loopback address')


# ---------------------------------------------------------------- payloads

@dataclass(frozen=True)
class HostNotice:
    """A host-side finding (no address pair), e.g. from the ransomware watch."""
    rule_id: str
    severity: str
    detected_at: datetime
    message: str
    attack: tuple[str, ...] = ()
    summary: str = ''
    # A SHA-256 the receiver must see whatever the detail level, e.g. an evidence manifest's.
    digest: str = ''
    src_ip: None = None
    dst_ip: None = None


def record(detection, detail='standard', sensor='', suppressed=0):
    rule = rule_catalog.BY_ID.get(detection.rule_id)
    attack = list(rule.attack) if rule else list(getattr(detection, 'attack', ()))
    summary = rule.summary if rule else getattr(detection, 'summary', '')
    value = dict(schema=SCHEMA, sensor=sensor or socket.gethostname()[:253] or 'megalodon',
                 rule_id=detection.rule_id, severity=detection.severity,
                 detected_at=detection.detected_at.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                 attack=attack, summary=summary, suppressed_before=suppressed)
    if detail in ('standard', 'full') and detection.src_ip is not None:
        value.update(src_ip=detection.src_ip, dst_ip=detection.dst_ip)
    if detail == 'full':
        value['message'] = detection.message
    digest = getattr(detection, 'digest', '')
    if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest):
        value['digest'] = digest
    return value


def text(value):
    line = f"MEGALODON {value['severity']} {value['rule_id']} on {value['sensor']} at {value['detected_at']}"
    if 'src_ip' in value:
        line += f": {value['src_ip']} -> {value['dst_ip']}"
    if 'message' in value:
        line += f". {value['message']}"
    if 'digest' in value:
        line += f". SHA-256 {value['digest']}"
    if value['suppressed_before']:
        line += f" (+{value['suppressed_before']} earlier findings not sent: rate limit or full queue)"
    return line + '. Review the evidence in the MEGALODON HUD.'


def webhook_request(destination, url, token, value):
    """(body, headers) for one webhook format. Mentions and markup are neutralized."""
    headers = {'User-Agent': 'MEGALODON-alerts/1'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    line = text(value)
    if destination.format == 'json':
        body, headers['Content-Type'] = json.dumps(value, separators=(',', ':')), 'application/json'
    elif destination.format == 'slack':
        safe = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        body, headers['Content-Type'] = json.dumps({'text': safe}), 'application/json'
    elif destination.format == 'discord':
        body = json.dumps({'content': line[:2000], 'allowed_mentions': {'parse': []}})
        headers['Content-Type'] = 'application/json'
    else:  # ntfy: plain text body, metadata in headers
        body, headers['Content-Type'] = line, 'text/plain; charset=utf-8'
        headers.update(Title=f"MEGALODON {value['severity']} {value['rule_id']}",
                       Priority=NTFY_PRIORITY[value['severity']], Tags='warning')
    return body.encode('utf-8'), headers


def syslog_message(destination, value, now=None):
    """RFC 5424 with structured data; plain ASCII values, escaped per the RFC."""
    pri = FACILITIES[destination.facility] * 8 + SYSLOG_PRIORITY[value['severity']]
    stamp = (now or datetime.now(timezone.utc)).strftime('%Y-%m-%dT%H:%M:%SZ')
    host = re.sub(r'[^!-~]', '-', value['sensor'])[:255] or '-'

    def param(v):
        return str(v).replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')
    params = [('rule', value['rule_id']), ('severity', value['severity']), ('detected', value['detected_at'])]
    params += [(k, value[k]) for k in ('src_ip', 'dst_ip', 'digest') if k in value]
    if value['suppressed_before']:
        params.append(('suppressed', value['suppressed_before']))
    data = f'[{SD_ID} ' + ' '.join(f'{k}="{param(v)}"' for k, v in params) + ']'
    return f'<{pri}>1 {stamp} {host} megalodon - {value["rule_id"]} {data} {text(value)}'.encode('utf-8')


# ---------------------------------------------------------------- transports

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # A redirect is a failure: the URL could otherwise move a secret.


def post(url, body, headers, timeout=TIMEOUT_SECONDS):
    request = urllib.request.Request(url, data=body, headers=headers, method='POST')
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        response.read(65536)
        if not 200 <= response.status < 300:
            raise OSError(f'HTTP {response.status}')


def send_syslog(destination, message, timeout=TIMEOUT_SECONDS):
    family = socket.SOCK_DGRAM if destination.protocol == 'udp' else socket.SOCK_STREAM
    infos = socket.getaddrinfo(destination.host, destination.port, type=family)
    error = None
    for af, kind, proto, _, address in infos:
        try:
            with socket.socket(af, kind, proto) as sock:
                sock.settimeout(timeout)
                if destination.protocol == 'udp':
                    sock.sendto(message[:2048], address)
                else:
                    # RFC 6587 octet counting, so a message never splits on newlines.
                    sock.connect(address)
                    sock.sendall(str(len(message)).encode() + b' ' + message)
            return
        except OSError as exc:
            error = exc
    raise error or OSError('no address')


class Channel:
    """One destination: its bounded queue, rate limit, retries and counters."""

    def __init__(self, destination, settings, *, transport=None, clock=time.monotonic, sleep=time.sleep):
        self.destination, self.settings = destination, settings
        self.url = self.token = None
        if destination.kind == 'webhook':
            self.url = check_url(read_secret(destination.url_file), destination.name)
            self.token = read_secret(destination.token_file) if destination.token_file else None
        self.transport = transport or self._send
        self.clock, self.sleep = clock, sleep
        self.queue = deque()
        self.condition = Condition()
        self.closed = False
        self.tokens, self.refilled = float(settings.max_per_minute), clock()
        self.suppressed = 0
        self.stats = dict(sent=0, failed=0, dropped=0, rate_limited=0, last_error=None)
        self.thread = None

    def _send(self, value):
        if self.destination.kind == 'webhook':
            body, headers = webhook_request(self.destination, self.url, self.token, value)
            post(self.url, body, headers)
        else:
            send_syslog(self.destination, syslog_message(self.destination, value))

    def start(self):
        self.thread = Thread(target=self._run, name=f'megalodon-alerts-{self.destination.name}', daemon=True)
        self.thread.start()

    def offer(self, detection):
        with self.condition:
            if self.closed:
                return
            if len(self.queue) >= MAX_QUEUE:
                self.stats['dropped'] += 1
                self.suppressed += 1
                return
            self.queue.append(detection)
            self.condition.notify()

    def _allow(self):
        now = self.clock()
        rate = self.settings.max_per_minute / 60
        self.tokens = min(float(self.settings.max_per_minute), self.tokens + (now - self.refilled) * rate)
        self.refilled = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    def _count(self, **changes):
        # offer() runs on the capture thread; every counter change shares its lock.
        with self.condition:
            for name, amount in changes.items():
                if name == 'suppressed':
                    self.suppressed += amount
                else:
                    self.stats[name] += amount

    def deliver(self, detection):
        """Send one finding now, with retries; True when the destination accepted it."""
        with self.condition:
            reported = self.suppressed
        value = record(detection, self.settings.detail, self.settings.sensor_name, reported)
        for delay in RETRY_DELAYS:
            if delay:
                self.sleep(delay)
            try:
                self.transport(value)
            except (OSError, ValueError, urllib.error.URLError) as exc:
                # Only the error class: messages can echo the URL and its token.
                self.stats['last_error'] = type(exc).__name__
                continue
            # Clear only what this alert reported; drops counted meanwhile stay for the next one.
            self._count(sent=1, suppressed=-reported)
            return True
        self._count(failed=1, suppressed=1)
        log.warning('alert destination %s did not accept a finding (%s)', self.destination.name,
                    self.stats['last_error'])
        return False

    def _run(self):
        while True:
            with self.condition:
                while not self.queue and not self.closed:
                    self.condition.wait()
                if not self.queue:
                    return
                detection = self.queue.popleft()
            if not self._allow():
                self._count(rate_limited=1, suppressed=1)
                continue
            self.deliver(detection)

    def close(self, timeout):
        with self.condition:
            self.closed = True
            self.condition.notify_all()
        if self.thread is not None:
            self.thread.join(timeout)


class AlertDispatcher:
    def __init__(self, settings, *, transport=None, start=True, clock=time.monotonic, sleep=time.sleep):
        self.settings = settings
        self.channels = [Channel(d, settings, transport=transport, clock=clock, sleep=sleep)
                         for d in settings.destinations]
        self.minimum = SEVERITIES.index(settings.min_severity)
        if start:
            for channel in self.channels:
                channel.start()

    def submit(self, detections, *, any_severity=False):
        """Queue committed findings at or above the minimum severity; never blocks or raises.
        any_severity is for a notice the operator asked for by name, such as an evidence digest."""
        for detection in detections:
            if not any_severity and SEVERITIES.index(detection.severity) < self.minimum:
                continue
            for channel in self.channels:
                channel.offer(detection)

    def snapshot(self):
        return {c.destination.name: dict(kind=c.destination.kind, queued=len(c.queue), **c.stats)
                for c in self.channels}

    def close(self, timeout=10):
        deadline = time.monotonic() + timeout
        for channel in self.channels:
            channel.close(max(0, deadline - time.monotonic()))


_shared, _shared_lock = {}, Lock()


def dispatcher_for(settings):
    """One process-wide dispatcher per alert configuration, so repeated HUD
    capture runs share rate limits and threads. Refuses startup when a
    configured secret file is missing or unsafe."""
    if not settings.enabled:
        return None
    with _shared_lock:
        if settings not in _shared:
            _shared[settings] = AlertDispatcher(settings)
        return _shared[settings]


@atexit.register
def _drain():
    # Short runs (megalodon run on a file) still deliver what they found.
    with _shared_lock:
        dispatchers = list(_shared.values())
    deadline = time.monotonic() + 10
    for dispatcher in dispatchers:
        dispatcher.close(max(0, deadline - time.monotonic()))


def test_destinations(settings, *, transport=None, now=None):
    """Send one synthetic LOW finding to every destination synchronously."""
    from .models import DetectionResult
    probe = DetectionResult(now or datetime.now(timezone.utc), 'IOC_MATCH', 'LOW', '192.0.2.10', '198.51.100.20',
                            'MEGALODON alert test. No finding occurred.')
    results = {}
    for destination in settings.destinations:
        try:
            channel = Channel(destination, settings, transport=transport, sleep=lambda _s: None)
        except AlertConfigError as exc:
            results[destination.name] = dict(ok=False, error=str(exc))
            continue
        ok = channel.deliver(probe)
        results[destination.name] = dict(ok=ok, error=None if ok else channel.stats['last_error'])
    return results
