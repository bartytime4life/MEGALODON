"""Evidence off the machine: the command log and evidence bundles, copied to the fleet collector as they appear.

On the machine they protect, the command log and the evidence bundles are only as safe as root is. An intruder
with root can delete them, or cut the log short. `megalodon evidence push` sends what is new to the fleet
collector, signed with the machine's heartbeat key, as soon as it is written. That covers:
- command log lines, exactly as signed by the recorder;
- each evidence bundle's manifest, then every file it lists, in pieces.
The scheduler runs it every five minutes.

The collector keeps the first copy it receives of everything, and never takes a different one in its place. A
line or bundle sent again with other content is kept aside and reported (SHIPPED_COMMANDS_REWRITTEN,
SHIPPED_EVIDENCE_CHANGED): an intruder who gets root later can stop the copying, but cannot change what already
left. `megalodon fleet evidence verify MACHINE --key-file FILE` checks the collector's copy of the command log
with the key from `commands init`, up to the line the last heartbeat named, and each bundle against the
manifest digest recorded when it arrived.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request

from . import command_log, evidence

SCHEMA = 'megalodon-evidence-shipping-v1'
BATCH_SCHEMA = 'megalodon-evidence-batch-v1'
DEFAULT_CURSOR = '~/.local/state/megalodon/evidence-push.json'
CHUNK = 384 * 1024                          # bytes of a file per piece, before base64
MAX_BATCH_BYTES = 640 * 1024                # one request's items, as JSON
MAX_BODY = 1024 * 1024                      # what the collector takes at /evidence
DEFAULT_BUDGET = 64 * 1024 * 1024           # bytes sent by one push; the rest goes on the next
MAX_REQUESTS = 400
MAX_LINES = 2000
MAX_STORED = 64 * 1024 * 1024 * 1024        # per machine, on the collector
MAX_CONFLICTS = 8 * 1024 * 1024
MAX_REJECTED = 64 * 1024 * 1024             # refused lines and manifests kept for comparison
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
_BUNDLE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,200}')
_PART = re.compile(r'[A-Za-z0-9._-]{1,255}')
_KEY_ID = re.compile(r'[0-9a-f]{16}')

RULES = {
    'SHIPPED_COMMANDS_REWRITTEN': (
        'CRITICAL', 'A command log line the collector already holds was sent again with other content, or a line '
                    'missing from the copy was sent later: the log on the machine was rewritten.'),
    'SHIPPED_EVIDENCE_CHANGED': (
        'CRITICAL', 'An evidence bundle the collector already holds was sent again with other content, or a file '
                    'did not match the manifest it was sent with: the bundle on the machine was changed.'),
    'SHIPPED_COMMANDS_GAP': (
        'HIGH', 'Command log lines were already missing when the machine sent the lines after them: they were '
                'removed before they left the machine.'),
}


class ShippingError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _safe_file(name):
    """A bundle-relative path made only of plain parts: nothing absolute, no `..`, no hidden tricks."""
    if not isinstance(name, str) or not name or len(name) > 1024 or name.startswith('/'):
        return False
    return all(_PART.fullmatch(p) and p not in ('.', '..') for p in name.split('/'))


# ------------------------------------------------------------------ on the machine

def _read_cursor(path):
    path = Path(path).expanduser()
    if not path.exists():
        return dict(commands={}, bundles={})
    try:
        value = json.loads(command_log._private_read(path, 'evidence push record'))
    except (ValueError, command_log.CommandLogError) as exc:
        raise ShippingError(f'{path}: {exc}') from None
    if type(value) is not dict:
        raise ShippingError(f'{path} has an unsupported format')
    return dict(commands=dict(value.get('commands') or {}), bundles=dict(value.get('bundles') or {}))


def _write_private(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.evidence-push-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _command_lines(log, cursor):
    """Lines not yet sent, oldest first, read only from the files that can hold them."""
    files = command_log.log_files(log)
    sent = cursor['commands']
    # With one log, a rotated file whose successor starts at or before the next line to send holds nothing new.
    floor = next(iter(sent.values())) if len(sent) == 1 else 0
    out = []
    for index, path in enumerate(files):
        following = files[index + 1] if index + 1 < len(files) else None
        if floor and following is not None and following.name.rsplit('.', 1)[-1].isdigit() \
                and int(following.name.rsplit('.', 1)[-1]) <= floor + 1:
            continue
        for line in command_log._private_read(path, 'command log').splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue                # not a record: never sent as if it were one
            if type(entry) is not dict or type(entry.get('seq')) is not int or not isinstance(entry.get('mac'), str) \
                    or not _KEY_ID.fullmatch(str(entry.get('key_id'))):
                continue
            if entry['seq'] > sent.get(entry['key_id'], 0):
                out.append(entry)
    return out


def _bundles(root):
    """(name, folder, manifest bytes, manifest) for every sealed bundle, oldest first."""
    base = Path(root).expanduser()
    if not base.is_dir():
        return []
    out = []
    for folder in sorted(base.iterdir()):
        if not _BUNDLE.fullmatch(folder.name) or folder.is_symlink() or not folder.is_dir():
            continue
        try:
            raw = (folder / 'manifest.json').read_bytes()
            manifest = json.loads(raw)
        except (OSError, ValueError):
            continue                    # still being written, or not a bundle
        if type(manifest) is dict and manifest.get('schema') == evidence.SCHEMA:
            out.append((folder.name, folder, raw, manifest))
    return out


def _listed(manifest):
    return [f for f in manifest.get('files') or []
            if type(f) is dict and _safe_file(f.get('file')) and type(f.get('size')) is int
            and isinstance(f.get('sha256'), str)]


def _events_url(settings, url=None):
    if url:
        return url
    base = settings['url']
    return base[:-len('/heartbeat')] + '/evidence' if base.endswith('/heartbeat') else base.rstrip('/') + '/evidence'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(settings, body, *, timeout=30):
    """POST one batch; the collector's answer says, item by item, how far it got."""
    request = urllib.request.Request(settings['url'], data=json.dumps(body, sort_keys=True).encode(), method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'User-Agent': 'MEGALODON-evidence/1'})
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout) as response:
        return json.loads(response.read(MAX_BODY) or b'{}')


def _size(item):
    return len(json.dumps(item, sort_keys=True))


def push(*, config=None, cursor_path=DEFAULT_CURSOR, log=command_log.DEFAULT_LOG, evidence_root=evidence.DEFAULT_ROOT,
         url=None, send=None, now=None, budget=DEFAULT_BUDGET, dry_run=False):
    """Send command log lines and evidence bundles not yet sent, signed with this machine's heartbeat key."""
    from . import tamper
    settings = tamper._read(config or tamper.DEFAULT_HEARTBEAT, tamper.HEARTBEAT_SCHEMA + '-config',
                            'heartbeat configuration')
    settings = dict(settings, url=_events_url(settings, url))
    send = send or globals()['send']
    with _PushLock(cursor_path):
        return _push(settings, send, cursor_path, log, evidence_root, now, budget, dry_run)


class _PushLock:
    """One push at a time: two would send the same pieces and race over the record of what was sent."""

    def __init__(self, cursor_path):
        path = Path(cursor_path).expanduser()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fd = os.open(path.with_name(path.name + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600)

    def __enter__(self):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise ShippingError('another evidence push is running') from None
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def _push(settings, send, cursor_path, log, evidence_root, now, budget, dry_run):
    from . import tamper
    cursor = _read_cursor(cursor_path)
    try:
        lines = _command_lines(log, cursor)
    except command_log.CommandLogError:
        lines = []                      # no command log here
    bundles = _bundles(evidence_root)
    totals = dict(lines=0, manifests=0, bytes=0, files=0, requests=0)
    # Most valuable first: the log, then every manifest (its digest is what proves a bundle), then the files,
    # newest bundle first, so the latest incident's evidence leaves first.
    items = []
    for key_id in dict.fromkeys(e['key_id'] for e in lines):
        group, size = [], 0
        for entry in (e for e in lines if e['key_id'] == key_id):
            length = _size(entry)
            if group and (size + length > MAX_BATCH_BYTES // 2 or len(group) >= MAX_LINES):
                items.append(dict(kind='commands', key_id=key_id, lines=group))
                group, size = [], 0
            group.append(entry)
            size += length
        if group:
            items.append(dict(kind='commands', key_id=key_id, lines=group))
    for name, _folder, raw, _manifest in bundles:
        digest = hashlib.sha256(raw).hexdigest()
        if cursor['bundles'].get(name, {}).get('manifest') != digest:
            items.append(dict(kind='manifest', bundle=name, sha256=digest, data=_b64(raw)))

    def pieces():
        for name, folder, raw, manifest in reversed(bundles):
            record = cursor['bundles'].get(name, {})
            if record.get('manifest') != hashlib.sha256(raw).hexdigest() or record.get('done'):
                continue
            for listed in _listed(manifest):
                offset = record.get('files', {}).get(listed['file'], 0)
                path = folder / listed['file']
                while offset < listed['size']:
                    try:
                        with open(path, 'rb') as stream:
                            stream.seek(offset)
                            data = stream.read(CHUNK)
                    except OSError:
                        break           # gone, or unreadable: the collector shows the bundle as incomplete
                    if not data:
                        break
                    yield dict(kind='chunk', bundle=name, file=listed['file'], offset=offset, size=listed['size'],
                               sha256=listed['sha256'], data=_b64(data)), len(data)
                    # Where the collector says the file now stands; no progress means it takes no more for now.
                    reached = cursor['bundles'].get(name, {}).get('files', {}).get(listed['file'], offset)
                    if reached <= offset:
                        break
                    offset = reached

    blocked = set()                     # logs with a batch the collector did not take this run

    def deliver(batch):
        moment = now or _now()
        body = dict(schema=BATCH_SCHEMA, sensor=settings.get('sensor', ''),
                    sequence=int(moment.timestamp() * 1000) + totals['requests'], sent_at=_iso(moment), items=batch)
        body['mac'] = tamper._sign(settings['key'], body)
        answer = dict(items=[dict(ok=True) for _ in batch]) if dry_run else send(settings, body)
        totals['requests'] += 1
        results = answer.get('items') if isinstance(answer, dict) else None
        if not isinstance(results, list) or len(results) != len(batch):
            raise ShippingError('the collector did not answer for each item it was sent')
        for item, result in zip(batch, results):
            result = result if isinstance(result, dict) else {}
            if item['kind'] == 'commands':
                last = max(e['seq'] for e in item['lines'])
                # Lines are acknowledged only up to the first batch not taken: later ones accepted past it
                # would leave lines the push record says were sent, and the collector never got.
                if result.get('ok') and item['key_id'] not in blocked:
                    totals['lines'] += len(item['lines'])
                    cursor['commands'][item['key_id']] = max(last, cursor['commands'].get(item['key_id'], 0))
                else:
                    blocked.add(item['key_id'])
            elif item['kind'] == 'manifest':
                if result.get('ok'):
                    totals['manifests'] += 1
                    cursor['bundles'][item['bundle']] = dict(manifest=item['sha256'], files={}, done=False)
            else:
                record = cursor['bundles'].setdefault(item['bundle'], dict(files={}))
                have = result.get('have')
                if type(have) is int and have >= 0:
                    # The collector says how much of the file it holds: resume from there, wherever that is.
                    record.setdefault('files', {})[item['file']] = have
                    if result.get('ok'):
                        totals['bytes'] += len(base64.b64decode(item['data']))
                        totals['files'] += have >= item['size']
        if not dry_run:
            _write_private(cursor_path, cursor)

    batch, size, too_large = [], 0, 0
    for item in items:
        if item['kind'] == 'commands' and item['key_id'] in blocked:
            continue                    # an earlier batch of this log was not taken: the rest waits for it
        length = _size(item)
        if length > MAX_BATCH_BYTES:
            too_large += 1              # counted, never blocks the rest (a manifest listing thousands of files)
            continue
        if batch and size + length > MAX_BATCH_BYTES:
            if totals['requests'] >= MAX_REQUESTS:
                break
            deliver(batch)
            batch, size = [], 0
        batch.append(item)
        size += length
    if batch and totals['requests'] < MAX_REQUESTS:
        deliver(batch)
    if not dry_run:
        # Files the manifest names, once the manifest is there; a bundle is done when every file is.
        for item, length in pieces():
            if totals['requests'] >= MAX_REQUESTS or totals['bytes'] + length > budget:
                break
            deliver([item])
        for name, _folder, raw, manifest in bundles:
            record = cursor['bundles'].get(name)
            if record and record.get('manifest') == hashlib.sha256(raw).hexdigest():
                record['done'] = all(record.get('files', {}).get(f['file'], 0) >= f['size']
                                     for f in _listed(manifest))
        _write_private(cursor_path, cursor)
    waiting = sum(1 for name, _f, raw, _m in bundles
                  if not cursor['bundles'].get(name, {}).get('done'))
    return dict(schema=SCHEMA, action='dry_run' if dry_run else 'push', url=settings['url'],
                command_lines=totals['lines'], manifests=totals['manifests'], file_bytes=totals['bytes'],
                files_completed=totals['files'], requests=totals['requests'], bundles_incomplete=waiting,
                too_large=too_large)


# ------------------------------------------------------------------ on the collector

def _store(data, name):
    return Path(data).expanduser() / 'machines' / name / 'shipped'


def _private_write(path, raw, *, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.shipped-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _load(path, default):
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return default


def _append_line(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
    finally:
        os.close(fd)


def _conflict(store, rule, subject, detail, received):
    """Recorded once: the same rewrite sent again on every push is still one finding."""
    path = store / 'conflicts.jsonl'
    try:
        if path.stat().st_size > MAX_CONFLICTS:
            return                      # a machine sending rewrite after rewrite cannot fill the collector
        for line in path.read_bytes().splitlines():
            known = json.loads(line)
            if (known.get('rule_id'), known.get('subject'), known.get('detail')) == (rule, subject, detail):
                return
    except (OSError, ValueError):
        pass
    _append_line(path, dict(rule_id=rule, subject=subject, detail=detail, received_at=received))


class _Usage:
    def __init__(self, store):
        self.path, self.value = store / 'usage.json', _load(store / 'usage.json', dict(bytes=0))

    def room(self, length):
        return self.value.get('bytes', 0) + length <= MAX_STORED

    def add(self, length):
        self.value['bytes'] = self.value.get('bytes', 0) + length
        _private_write(self.path, json.dumps(self.value).encode())


def _canonical(entry):
    return json.dumps(entry, sort_keys=True, separators=(',', ':'))


def _stored_lines(folder, wanted):
    """{seq: the whole line as first kept} for the copy's lines among `wanted`, read from every file of it."""
    found = {}
    for path in command_log.log_files(folder / 'commands.jsonl'):
        for line in path.read_bytes().splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if type(entry) is dict and entry.get('seq') in wanted:
                found[entry['seq']] = _canonical(entry)
    return found


def _take_commands(store, item, received, usage):
    key_id, lines = item.get('key_id'), item.get('lines')
    if not _KEY_ID.fullmatch(str(key_id)) or type(lines) is not list or len(lines) > MAX_LINES or not all(
            type(e) is dict and type(e.get('seq')) is int and e['seq'] > 0 and isinstance(e.get('mac'), str)
            and e.get('key_id') == key_id for e in lines):
        return dict(ok=False, error='not command log lines')
    folder = store / 'commands' / key_id
    state = _load(folder / 'received.json', dict(last=0, lines=0, first=None, current_first=None, gaps=[]))
    lines = sorted(lines, key=lambda e: e['seq'])
    again = {e['seq'] for e in lines if e['seq'] <= state['last']}
    stored = _stored_lines(folder, again) if again else {}
    new = []
    for entry in lines:
        sequence = entry['seq']
        if sequence <= state['last'] or any(e['seq'] == sequence for e in new):
            # The same line again (a retry, or a machine that lost its record) must match in every field: the
            # batch's signature proves only who sent it, and a matching line signature can be copied.
            if stored.get(sequence) == _canonical(entry) or any(
                    e['seq'] == sequence and _canonical(e) == _canonical(entry) for e in new):
                continue
            detail = (f'line {sequence} arrived again with other content' if sequence in stored else
                      f'line {sequence} arrived after line {state["last"]}, where the copy has none')
            _conflict(store, 'SHIPPED_COMMANDS_REWRITTEN', f'commands:{key_id}:{sequence}', detail, received)
            _keep_rejected(store, folder / 'rewritten.jsonl', dict(entry, received_at=received), usage)
            continue
        previous = new[-1]['seq'] if new else state['last']
        # A log's first copy starting after line 1 is a gap too: its first lines were removed before any left.
        if sequence > previous + 1:
            state['gaps'] = (state['gaps'] + [[previous + 1, sequence - 1]])[-100:]
            _conflict(store, 'SHIPPED_COMMANDS_GAP', f'commands:{key_id}:{previous + 1}-{sequence - 1}',
                      f'lines {previous + 1} to {sequence - 1} were missing when line {sequence} was sent', received)
        new.append(entry)
    if new:
        raw = b''.join(json.dumps(e, sort_keys=True, separators=(',', ':')).encode() + b'\n' for e in new)
        if not usage.room(len(raw)):
            return dict(ok=False, error='the collector holds as much as it keeps for this machine', last=state['last'])
        path = folder / 'commands.jsonl'
        if path.exists() and path.stat().st_size + len(raw) > command_log.ROTATE_BYTES and state['current_first']:
            # Rotated the way the machine rotates, so `commands verify` reads the copy as it reads the log.
            os.replace(path, folder / f'commands.jsonl.{state["current_first"]:012d}')
            state['current_first'] = None
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        usage.add(len(raw))
        state.update(last=new[-1]['seq'], lines=state['lines'] + len(new), last_at=new[-1].get('at'),
                     first=state['first'] or new[0]['seq'], current_first=state['current_first'] or new[0]['seq'],
                     received_at=received)
        _private_write(folder / 'received.json', json.dumps(state, sort_keys=True).encode())
    return dict(ok=True, last=state['last'])


def _keep_rejected(store, path, value, usage):
    """Keep what was refused, for comparison, within its own allowance: rejections cannot fill the collector."""
    raw = value if isinstance(value, bytes) else _canonical(value).encode() + b'\n'
    if usage.value.get('rejected', 0) + len(raw) > MAX_REJECTED or not usage.room(len(raw)):
        return
    if isinstance(value, bytes):
        if path.exists():
            return
        _private_write(path, raw)
    else:
        _append_line(path, value)
    usage.value['rejected'] = usage.value.get('rejected', 0) + len(raw)
    usage.add(len(raw))


def _take_manifest(store, item, received, usage):
    name = item.get('bundle')
    try:
        raw = base64.b64decode(str(item.get('data', '')), validate=True)
        manifest = json.loads(raw)
    except ValueError:
        return dict(ok=False, error='not a manifest')
    if not _BUNDLE.fullmatch(str(name)) or type(manifest) is not dict or manifest.get('schema') != evidence.SCHEMA \
            or type(manifest.get('files')) is not list or len(_listed(manifest)) != len(manifest['files']) \
            or any(f['file'] == 'manifest.json' for f in _listed(manifest)):
        return dict(ok=False, error='not an evidence manifest with plain file names')
    digest = hashlib.sha256(raw).hexdigest()
    record_path = store / 'evidence-state' / f'{name}.json'
    record = _load(record_path, None)
    if record:
        if record.get('manifest_sha256') == digest:
            return dict(ok=True)
        _conflict(store, 'SHIPPED_EVIDENCE_CHANGED', f'evidence:{name}:manifest.json',
                  f'bundle {name} was sent again with another manifest; the first one is kept', received)
        _keep_rejected(store, store / 'evidence-rejected' / name / f'manifest-{digest[:16]}.json', raw, usage)
        return dict(ok=False, error='a different manifest for this bundle is already held')
    if not usage.room(len(raw)):
        return dict(ok=False, error='the collector holds as much as it keeps for this machine')
    _private_write(store / 'evidence' / name / 'manifest.json', raw, mode=0o400)
    usage.add(len(raw))
    _private_write(record_path, json.dumps(dict(manifest_sha256=digest, received_at=received,
                                                collected_at=manifest.get('collected_at'),
                                                kind=manifest.get('kind', 'snapshot'),
                                                files={f['file']: dict(size=f['size'], sha256=f['sha256'])
                                                       for f in _listed(manifest)}), sort_keys=True).encode())
    # An empty file has no pieces to send: it is placed here, if the manifest says it is empty.
    for listed in _listed(manifest):
        if listed['size'] == 0:
            if listed['sha256'] == EMPTY_SHA256:
                _private_write(store / 'evidence' / name / listed['file'], b'', mode=0o400)
            else:
                _conflict(store, 'SHIPPED_EVIDENCE_CHANGED', f"evidence:{name}:{listed['file']}",
                          f"{listed['file']} of bundle {name} is listed as empty with the digest of other content",
                          received)
    return dict(ok=True)


def _take_chunk(store, item, received, usage):
    name, file = item.get('bundle'), item.get('file')
    record = _load(store / 'evidence-state' / f'{name}.json', None) if _BUNDLE.fullmatch(str(name)) else None
    if not record:
        return dict(ok=False, error='the manifest of this bundle has not arrived')
    listed = record['files'].get(file) if _safe_file(file) else None
    offset = item.get('offset')
    try:
        data = base64.b64decode(str(item.get('data', '')), validate=True)
    except ValueError:
        return dict(ok=False, error='not base64')
    if listed is None or type(offset) is not int or offset < 0 or len(data) > CHUNK \
            or offset + len(data) > listed['size']:
        return dict(ok=False, error='not a piece of a file the manifest lists')
    final, partial = store / 'evidence' / name / file, store / 'evidence-partial' / name / file
    done = final.exists() or (store / 'evidence-rejected' / name / file).exists()
    have = listed['size'] if done else (partial.stat().st_size if partial.exists() else 0)
    if offset < have:
        # Sent before: it must match what arrived first.
        source = final if final.exists() else partial
        if source.exists():
            with open(source, 'rb') as stream:
                stream.seek(offset)
                before = stream.read(min(len(data), have - offset))
            if before != data[:len(before)]:
                _conflict(store, 'SHIPPED_EVIDENCE_CHANGED', f'evidence:{name}:{file}',
                          f'{file} of bundle {name} was sent again with other content at byte {offset}', received)
        return dict(ok=True, have=have)
    if offset > have:
        return dict(ok=False, have=have, error='pieces arrive in order')
    if not usage.room(len(data)):
        return dict(ok=False, have=have, error='the collector holds as much as it keeps for this machine')
    partial.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(partial, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    usage.add(len(data))
    have += len(data)
    if have == listed['size']:
        if evidence._file_digest(partial) == listed['sha256']:
            final.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(partial, 0o400)
            os.replace(partial, final)
        else:
            rejected = store / 'evidence-rejected' / name / file
            rejected.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(partial, rejected)
            _conflict(store, 'SHIPPED_EVIDENCE_CHANGED', f'evidence:{name}:{file}',
                      f'{file} of bundle {name} does not match its manifest: it was changed on the machine after '
                      f'the bundle was sealed', received)
    return dict(ok=True, have=have)


def receive(body, *, data, now=None):
    """(status, answer) for one posted evidence batch, signed with its machine's heartbeat key."""
    from . import fleet, tamper
    if type(body) is not dict or body.get('schema') != BATCH_SCHEMA or type(body.get('items')) is not list \
            or type(body.get('sequence')) is not int:
        return 400, dict(result='not a MEGALODON evidence batch')
    registry = fleet.machines(data)
    name = next((n for n, m in registry.items() if m['sensor'] == body.get('sensor')), None)
    if name is None:
        return 403, dict(result='this sensor is not enrolled')
    unsigned = {k: v for k, v in body.items() if k != 'mac'}
    try:
        valid = hmac.compare_digest(str(body.get('mac', '')), tamper._sign(registry[name]['heartbeat_key'], unsigned))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        return 401, dict(result='the signature does not match this machine\'s key')
    received = _iso(now or _now())
    store = _store(data, name)
    with fleet._RECEIVING:
        sequence_path = store / 'sequence.json'
        last = _load(sequence_path, dict(sequence=0)).get('sequence', 0)
        if body['sequence'] <= last:
            return 409, dict(result='this batch, or a later one, was already received')
        usage = _Usage(store)
        answers = []
        refused = set()                 # logs with a batch not taken in this request
        for item in body['items']:
            kind = item.get('kind') if type(item) is dict else None
            take = dict(commands=_take_commands, manifest=_take_manifest, chunk=_take_chunk).get(kind)
            if kind == 'commands' and str(item.get('key_id')) in refused:
                # Taking a later batch past one not taken would open a gap that could never be filled.
                answers.append(dict(ok=False, error='an earlier batch of this log was not taken'))
                continue
            answer = take(store, item, received, usage) if take else dict(ok=False, error='unknown item')
            if kind == 'commands' and not answer.get('ok'):
                refused.add(str(item.get('key_id')))
            answers.append(answer)
        _private_write(sequence_path, json.dumps(dict(sequence=body['sequence'], at=received)).encode())
    return 200, dict(result='ok', items=answers)


# ------------------------------------------------------------------ what the collector holds

def _finding(rule, machine, subject, detail):
    severity, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, machine=machine, subject=f'{machine}:{subject}',
                detail=f'{machine}: {detail}', summary=summary, techniques=['T1070', 'T1565.001'])


def findings(data, name):
    out = []
    path = _store(data, name) / 'conflicts.jsonl'
    try:
        raw = path.read_bytes()
    except OSError:
        return out
    for line in raw.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if type(record) is dict and record.get('rule_id') in RULES:
            out.append(dict(_finding(record['rule_id'], name, record.get('subject', ''), record.get('detail', '')),
                            received_at=record.get('received_at')))
    return out


def held(data, name):
    """What the collector holds for one machine: its command log copies and evidence bundles."""
    store = _store(data, name)
    logs = []
    for folder in sorted((store / 'commands').glob('*')) if (store / 'commands').is_dir() else []:
        state = _load(folder / 'received.json', {})
        logs.append(dict(key_id=folder.name, lines=state.get('lines', 0), first=state.get('first'),
                         last=state.get('last'), last_at=state.get('last_at'), received_at=state.get('received_at'),
                         gaps=state.get('gaps', []), path=str(folder / 'commands.jsonl')))
    bundles = []
    for path in sorted((store / 'evidence-state').glob('*.json')) if (store / 'evidence-state').is_dir() else []:
        record = _load(path, {})
        folder = store / 'evidence' / path.stem
        complete = [f for f in record.get('files', {}) if (folder / f).is_file()]
        bundles.append(dict(bundle=path.stem, kind=record.get('kind'), collected_at=record.get('collected_at'),
                            received_at=record.get('received_at'), manifest_sha256=record.get('manifest_sha256'),
                            files=len(record.get('files', {})), files_received=len(complete),
                            bytes=sum(record['files'][f]['size'] for f in complete), path=str(folder)))
    return dict(machine=name, command_logs=logs, bundles=bundles, findings=findings(data, name),
                stored_bytes=_load(store / 'usage.json', {}).get('bytes', 0))


def summary(data, name):
    """A line's worth for the fleet status: what reached the collector, and when last."""
    report = held(data, name)
    logs = report['command_logs']
    return dict(command_lines=sum(c['lines'] for c in logs), last_line=logs[-1]['last'] if logs else None,
                last_received=max([c['received_at'] or '' for c in logs] +
                                  [b['received_at'] or '' for b in report['bundles']], default='') or None,
                bundles=len(report['bundles']),
                bundles_complete=sum(b['files_received'] == b['files'] for b in report['bundles']))


def verify(data, name, *, key_hex=None, now=None, from_sequence=1):
    """Check the collector's copies: the command log with its key, from line 1 (or from_sequence, a boundary
    only the operator sets) up to the line the last heartbeat named, and every complete bundle against the
    manifest digest recorded when it arrived."""
    from . import fleet, tamper
    registry = fleet.machines(data)
    if name not in registry:
        raise ShippingError(f'{name} is not enrolled')
    report = held(data, name)
    problems = list(report['findings'])
    commands = None
    if key_hex is not None:
        try:
            seed = bytes.fromhex(key_hex.strip())
        except ValueError:
            raise ShippingError('the key must be the 64 hexadecimal digits that `commands init` printed') from None
        key_id = command_log._key_id(seed)
        copy = next((c for c in report['command_logs'] if c['key_id'] == key_id), None)
        if copy is None:
            raise ShippingError(f'no command log started with this key has reached the collector from {name}')
        beats = tamper.monitor(fleet._lines(data, name, 'heartbeats'), registry[name]['heartbeat_key'], now=now,
                               sensor=registry[name]['sensor'])
        expect = beats.get('command_log_sequence') if beats.get('command_log_key_id') == key_id else None
        commands = command_log.verify(key_hex, log=copy['path'], expect_sequence=expect,
                                      from_sequence=from_sequence)
        problems += [dict(f, machine=name, subject=f'{name}:{f["subject"]}', detail=f'{name}: {f["detail"]}')
                     for f in commands['findings']]
    checked = []
    for bundle in report['bundles']:
        if bundle['files_received'] < bundle['files']:
            checked.append(dict(bundle=bundle['bundle'], intact=None,
                                note=f"{bundle['files_received']} of {bundle['files']} files have arrived"))
            continue
        try:
            result = evidence.verify(bundle['path'], expected=bundle['manifest_sha256'])
        except evidence.EvidenceError as exc:
            # A copy that cannot even be read is a finding about that bundle, not the end of the check.
            result = dict(intact=False, problems=[dict(file='manifest.json', problem=str(exc))])
        checked.append(dict(bundle=bundle['bundle'], intact=result['intact'], problems=result['problems']))
        if not result['intact']:
            problems.append(_finding('SHIPPED_EVIDENCE_CHANGED', name, f"evidence:{bundle['bundle']}",
                                     f"the collector's copy of {bundle['bundle']} does not match its manifest: "
                                     + ', '.join(f"{p['file']} {p['problem']}" for p in result['problems'][:5])))
    problems.sort(key=lambda f: RANK.index(f['severity']))
    return dict(schema=SCHEMA, action='verify', machine=name, commands=commands, bundles=checked, findings=problems)
