"""Scheduled refresh of operator-chosen threat feeds into one local watchlist.

``megalodon feeds refresh`` downloads each configured source over HTTPS, using
conditional requests so unchanged feeds cost a 304. It parses the content
strictly as untrusted text: one indicator per line, validated by the watchlist
parser, so broad networks and bare TLDs are refused. It then writes one
owner-private watchlist atomically: the operator's own base list first, then
each feed's indicators labeled ``feed:<name>``. Point
``[threat_detection] watchlist_path`` at that output. The service reads it
when a run or HUD capture starts.

A source that fails (network, HTTP error, oversize, or content that is not
the declared format) keeps its last good copy and is reported stale. A bad
download never empties the watchlist. Nothing is evaluated or executed, and
an indicator is a reason to look, not a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from .alerts import AlertConfigError, check_url, read_secret
from .validation import ValidationError, parse_ja3
from .watchlist import (MAX_INDICATORS, MAX_WATCHLIST_BYTES, _label, _read_private, parse_domain,
                        parse_indicator, parse_lines, render, write_private)

SCHEMA = 'megalodon-feed-state-v1'
FORMATS = ('ip', 'domain', 'hosts', 'ja3')
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')
HEADER = re.compile(r'[A-Za-z0-9-]{1,40}')
# Headers the client sets itself; a secret under one of these would be overwritten or forwarded.
RESERVED_HEADERS = frozenset({'accept', 'accept-encoding', 'connection', 'content-length', 'content-type', 'host',
                              'if-modified-since', 'if-none-match', 'transfer-encoding', 'user-agent'})
MAX_SOURCES = 16
MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_LINE_CHARS = 512
TIMEOUT_SECONDS = 20
MAX_REDIRECTS = 3
DEFAULT_OUTPUT = '~/.config/megalodon/feeds.watchlist'
DEFAULT_STATE = '~/.local/state/megalodon/feeds'
_HOSTS_SINKS = frozenset({'0.0.0.0', '127.0.0.1', '::', '::1'})
_HOSTS_SKIP = frozenset({'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost',
                         'ip6-loopback', '0.0.0.0'})


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class FeedSource:
    name: str
    url: str
    format: str = 'ip'
    max_entries: int = 50000
    header_name: str = ''
    token_file: str = ''

    def __post_init__(self):
        if type(self.name) is not str or not NAME.fullmatch(self.name):
            raise FeedError('feed source names use a-z, 0-9, dash or underscore (max 32)')
        if self.format not in FORMATS:
            raise FeedError(f'feed {self.name}: format must be one of {", ".join(FORMATS)}')
        if type(self.url) is not str or len(self.url) > 2048:
            raise FeedError(f'feed {self.name}: url must be text')
        try:
            check_url(self.url, self.name)
        except AlertConfigError as exc:
            raise FeedError(str(exc).replace('alert destination', 'feed')) from None
        if type(self.max_entries) is not int or not 1 <= self.max_entries <= MAX_INDICATORS:
            raise FeedError(f'feed {self.name}: max_entries must be 1-{MAX_INDICATORS}')
        if bool(self.header_name) != bool(self.token_file):
            raise FeedError(f'feed {self.name}: header_name and token_file go together')
        if self.header_name and (not HEADER.fullmatch(self.header_name)
                                 or self.header_name.lower() in RESERVED_HEADERS):
            raise FeedError(f'feed {self.name}: header_name must be an HTTP header name the client does not set itself')


@dataclass(frozen=True)
class FeedSettings:
    output: str = DEFAULT_OUTPUT
    base: str = ''
    state_dir: str = DEFAULT_STATE
    stale_hours: int = 48
    sources: tuple[FeedSource, ...] = field(default_factory=tuple)

    def __post_init__(self):
        for name in ('output', 'base', 'state_dir'):
            if type(getattr(self, name)) is not str or len(getattr(self, name)) > 1024:
                raise FeedError(f'feeds.{name} must be a path')
        if not self.output or not self.state_dir:
            raise FeedError('feeds.output and feeds.state_dir must not be empty')
        if type(self.stale_hours) is not int or not 1 <= self.stale_hours <= 8760:
            raise FeedError('feeds.stale_hours must be 1-8760')
        if len(self.sources) > MAX_SOURCES:
            raise FeedError(f'feeds allows at most {MAX_SOURCES} sources')
        names = [s.name for s in self.sources]
        if len(set(names)) != len(names):
            raise FeedError('feed source names must be unique')


def parse_settings(raw):
    """Typed [feeds] table; unknown keys refuse rather than being ignored."""
    if type(raw) is not dict:
        raise FeedError('feeds must be a TOML table')
    known = {'output', 'base', 'state_dir', 'stale_hours', 'source'}
    if set(raw) - known:
        raise FeedError('feeds contains unsupported settings: ' + ', '.join(sorted(set(raw) - known)))
    items = raw.get('source', [])
    if type(items) is not list or not all(type(item) is dict for item in items):
        raise FeedError('feeds.source must be an array of tables ([[feeds.source]])')
    allowed = set(FeedSource.__dataclass_fields__)
    sources = []
    for item in items:
        if set(item) - allowed:
            raise FeedError('feeds.source contains unsupported settings: ' + ', '.join(sorted(set(item) - allowed)))
        for key, value in item.items():
            if (key == 'max_entries') != (type(value) is int):
                raise FeedError(f'feeds.source.{key} has the wrong type')
        if 'url' not in item or 'name' not in item:
            raise FeedError('each [[feeds.source]] needs a name and a url')
        sources.append(FeedSource(**item))
    values = {k: raw[k] for k in ('output', 'base', 'state_dir', 'stale_hours') if k in raw}
    return FeedSettings(sources=tuple(sources), **values)


# ---------------------------------------------------------------- parsing

def _first_token(line):
    text = line.split('#', 1)[0].split(';', 1)[0].strip()
    return text.split()[0].split(',')[0] if text else ''


def parse_feed(text, fmt):
    """(indicators, invalid line count) from untrusted feed text in one format."""
    found, invalid = [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in '#;!/' or line.lower().startswith(('ja3_md5', 'ip,', 'domain,')):
            continue
        if len(line) > MAX_LINE_CHARS:
            invalid += 1
            continue
        try:
            if fmt == 'ip':
                value = parse_indicator(_first_token(line))
            elif fmt == 'domain':
                value = parse_domain(_first_token(line))
            elif fmt == 'hosts':
                parts = line.split('#', 1)[0].split()
                if len(parts) == 1:
                    name = parts[0]
                elif len(parts) >= 2 and parts[0] in _HOSTS_SINKS:
                    name = parts[1]
                else:
                    raise ValidationError('not a hosts-file line')
                if name.lower() in _HOSTS_SKIP:
                    continue
                value = parse_domain(name)
            else:
                value = ('ja3', parse_ja3(_first_token(line)))
        except (ValidationError, ValueError, IndexError):
            invalid += 1
            continue
        found.append(value)
    return found, invalid


def _key(indicator):
    if isinstance(indicator, tuple):
        return f'{indicator[0]}:{indicator[1]}'
    if isinstance(indicator, str):
        return indicator
    return indicator.with_prefixlen if indicator.num_addresses > 1 else str(indicator.network_address)


# ---------------------------------------------------------------- fetching

class _Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # Follow only to HTTPS (or to a private literal over HTTP); never send the token on.
        check_url(newurl, 'redirect')
        new = super().redirect_request(request, fp, code, msg, headers, newurl)
        if new is not None:
            for name in list(new.headers):
                if name.lower() not in ('user-agent', 'accept'):
                    del new.headers[name]
        return new


def fetch(source, previous=None, *, timeout=TIMEOUT_SECONDS):
    """(status, body bytes or None, etag, last_modified); 304 returns body None."""
    headers = {'User-Agent': 'MEGALODON-feeds/1', 'Accept': 'text/plain, text/csv, */*'}
    if previous:
        if previous.get('etag'):
            headers['If-None-Match'] = previous['etag']
        if previous.get('last_modified'):
            headers['If-Modified-Since'] = previous['last_modified']
    request = urllib.request.Request(source.url, headers=headers)
    if source.token_file:
        # Unredirected: urllib never copies these onto a redirect, whatever the header name.
        request.add_unredirected_header(source.header_name.capitalize(), read_secret(source.token_file))
    opener = urllib.request.build_opener(_Redirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.headers.get('Content-Encoding', 'identity') not in ('identity', ''):
                raise FeedError('compressed responses are not accepted')
            length = response.headers.get('Content-Length')
            if length and length.isdigit() and int(length) > MAX_FEED_BYTES:
                raise FeedError('feed exceeds 16 MiB')
            body = bytearray()
            deadline = time.monotonic() + timeout * 3
            while True:
                part = response.read(65536)
                if not part:
                    break
                body += part
                if len(body) > MAX_FEED_BYTES:
                    raise FeedError('feed exceeds 16 MiB')
                if time.monotonic() > deadline:
                    raise FeedError('feed download took too long')
            return response.status, bytes(body), response.headers.get('ETag'), response.headers.get('Last-Modified')
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, None, None
        raise FeedError(f'HTTP {exc.code}') from None


# ---------------------------------------------------------------- state

def _private_dir(path):
    path = Path(path).expanduser()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise FeedError(f'feed state folder {path} must be a private directory owned by you')
    return path


def _write_atomic(path, data):
    handle, temporary = tempfile.mkstemp(prefix='.feed-', dir=path.parent)
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


def _read_state(directory, source):
    """A source's cached copy, only if it was fetched from this URL in this format."""
    try:
        meta = json.loads((directory / f'{source.name}.json').read_text(encoding='utf-8'))
        lines = (directory / f'{source.name}.txt').read_text(encoding='utf-8').splitlines()
    except (OSError, ValueError):
        return None, []
    if (type(meta) is not dict or meta.get('schema') != SCHEMA
            or meta.get('url') != source.url or meta.get('format') != source.format):
        # A renamed URL or format must not reuse another endpoint's indicators or validators.
        return None, []
    try:
        entries = [value for value, _ in parse_lines(lines)]
    except ValidationError:
        return None, []
    return meta, entries


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _age_hours(stamp, now=None):
    try:
        then = datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return ((now or datetime.now(timezone.utc)) - then).total_seconds() / 3600


# ---------------------------------------------------------------- refresh

def refresh(settings, *, fetcher=fetch, only_if_older_minutes=None):
    """Refresh every source, then rebuild the output watchlist. Returns a report."""
    if not settings.sources:
        raise FeedError('no [[feeds.source]] is configured')
    state = _private_dir(settings.state_dir)
    report = dict(schema='megalodon-feed-refresh-v1', refreshed_at=_now(), sources={})
    for source in settings.sources:
        meta, entries = _read_state(state, source)
        item = dict(format=source.format, url_host=urllib.parse.urlsplit(source.url).hostname)
        if (only_if_older_minutes is not None and meta
                and (_age_hours(meta.get('checked_at')) or 1e9) * 60 < only_if_older_minutes):
            item.update(status='skipped_recent', indicators=len(entries), fetched_at=meta.get('fetched_at'),
                        validated_at=meta.get('validated_at'))
            report['sources'][source.name] = item
            continue
        try:
            status, body, etag, modified = fetcher(source, meta)
            if status == 304:
                if meta is None:
                    raise FeedError('server reported no change but no earlier copy exists')
                stamp = _now()
                meta = dict(meta, checked_at=stamp, validated_at=stamp)
                item.update(status='not_modified', indicators=len(entries))
            else:
                try:
                    text = body.decode('utf-8-sig')
                except UnicodeDecodeError:
                    raise FeedError('feed is not UTF-8 text') from None
                parsed, invalid = parse_feed(text, source.format)
                if not parsed or invalid > len(parsed):
                    raise FeedError(f'content does not look like a {source.format} feed '
                                    f'({len(parsed)} indicators, {invalid} unreadable lines)')
                unique = list({_key(v): v for v in parsed}.values())
                truncated = max(0, len(unique) - source.max_entries)
                entries = unique[:source.max_entries]
                stamp = _now()
                meta = dict(schema=SCHEMA, url=source.url, format=source.format, fetched_at=stamp, checked_at=stamp,
                            validated_at=stamp, etag=etag, last_modified=modified,
                            sha256=hashlib.sha256(body).hexdigest(), indicators=len(entries), invalid_lines=invalid,
                            truncated=truncated)
                _write_atomic(state / f'{source.name}.txt',
                              render(((v, '') for v in entries), f'feed {source.name}').encode('utf-8'))
                item.update(status='updated', indicators=len(entries), invalid_lines=invalid, truncated=truncated)
            _write_atomic(state / f'{source.name}.json', json.dumps(meta, sort_keys=True).encode('utf-8'))
            item.update(fetched_at=meta.get('fetched_at'), validated_at=meta.get('validated_at'))
        except (FeedError, AlertConfigError, OSError, urllib.error.URLError) as exc:
            # Keep the last good copy; a failed download never empties coverage.
            reason = str(exc) if isinstance(exc, (FeedError, AlertConfigError)) else type(exc).__name__
            item.update(status='failed', error=reason[:200], indicators=len(entries),
                        fetched_at=meta.get('fetched_at') if meta else None,
                        validated_at=meta.get('validated_at') if meta else None)
        age = _age_hours(item.get('validated_at'))
        item['stale'] = age is None or age > settings.stale_hours
        report['sources'][source.name] = item
    report['output'] = build_output(settings)
    return report


def build_output(settings):
    """Base list first, then each feed in order, deduplicated and capped; atomic write."""
    state = _private_dir(settings.state_dir)
    entries, seen, dropped = [], set(), 0
    # The service refuses a watchlist over 8 MiB, so the output stays well inside it.
    budget = MAX_WATCHLIST_BYTES - 4096

    def add(indicator, label):
        nonlocal dropped, budget
        key = _key(indicator)
        if key in seen:
            return
        size = len(key.encode()) + (len(label.encode()) + 4 if label else 0) + 1
        if len(seen) >= MAX_INDICATORS or size > budget:
            dropped += 1
            return
        budget -= size
        seen.add(key)
        entries.append((indicator, label))
    base = 0
    if settings.base:
        # The base list gets the same owner-private checks the service applies.
        try:
            text = _read_private(str(Path(settings.base).expanduser())).decode('utf-8')
        except UnicodeDecodeError:
            raise FeedError('the base watchlist must be UTF-8 text') from None
        for indicator, label in parse_lines(text.splitlines()):
            add(indicator, label)
        base = len(entries)
    counts = {}
    for source in settings.sources:
        _, items = _read_state(state, source)
        before = len(entries)
        for indicator in items:
            add(indicator, _label(f'feed:{source.name}'))
        counts[source.name] = len(entries) - before
    output = Path(settings.output).expanduser()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    text = render(entries, f'MEGALODON feeds watchlist, generated {_now()}; edit the base list, not this file')
    parse_lines(text.splitlines())  # The output must load exactly as the service will read it.
    write_private(output, text, replace=True)
    return dict(path=str(output), indicators=len(entries), from_base=base, from_feeds=counts,
                dropped_over_limit=dropped)


def status(settings):
    state = Path(settings.state_dir).expanduser()
    result = dict(schema='megalodon-feed-status-v1', output=str(Path(settings.output).expanduser()), sources={})
    for source in settings.sources:
        meta, entries = _read_state(state, source) if state.is_dir() else (None, [])
        age = _age_hours(meta.get('validated_at')) if meta else None
        result['sources'][source.name] = dict(
            format=source.format, indicators=len(entries), fetched_at=meta.get('fetched_at') if meta else None,
            checked_at=meta.get('checked_at') if meta else None,
            validated_at=meta.get('validated_at') if meta else None,
            stale=age is None or age > settings.stale_hours)
    return result
