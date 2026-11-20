"""Incident timeline: one incident's findings, decisions and actions, in the order they happened.

Every scheduled check feeds the response engine, which ties findings that share an address, process, file,
port, persistence location or account into incidents. `megalodon timeline` reads what the engine and enforcement
recorded and tells each incident as one story:

* **findings**, from every check, with what each one named;
* **decisions**: the playbook that matched, and each action it would take or why a guard refused it;
* **actions** carried out by enforcement, refused or failed, the evidence bundles it collected, and undos.

It can also follow one address, process, file or account across every incident.

Read-only. It reads the mode-600 files the engine and enforcement write: the observation log and the shadow
ledger beside it, and the enforcement journal. Their rotated copies (`.1`) are read too, so older history is
kept for as long as they are.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import tempfile

from . import response_engine as engine

SCHEMA = 'megalodon-timeline-v1'
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
MAX_EVENTS = 5000


class TimelineError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _parse(text):
    try:
        return datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    except ValueError:
        return None


def _lines(path):
    """Every line of an owner-only file, read as a stream: the enforcement journal is not rotated and grows."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise engine.ResponseError(f'{path} must be a mode-600 file owned by you')
        stream = os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        for line in stream:
            yield line


def _records(path):
    """The JSON records of a private log and its rotated copy, oldest first; [] when neither exists."""
    path = Path(path).expanduser()
    out = []
    for candidate in (path.with_name(path.name + '.1'), path):
        if not candidate.exists():
            continue
        for line in _lines(candidate):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                out.append(record)
    return out


def _severity(value):
    return value if value in RANK else 'INFO'


def _entity_keys(entities):
    """'kind:value' for each entity, with a peer counted as the address it is."""
    return {f"{'address' if kind == 'peer' else kind}:{value}" for kind, values in (entities or {}).items()
            for value in values}


def events(*, ledger=engine.DEFAULT_LEDGER, observations=None, journal=None):
    """Every recorded event, oldest first, each with the incident it belongs to."""
    return _load(ledger=ledger, observations=observations, journal=journal)[0]


def _load(*, ledger=engine.DEFAULT_LEDGER, observations=None, journal=None):
    """(events, final): the events, and a function giving the incident an incident ID was merged into."""
    from . import enforcement
    observations = observations or engine.observations_path(ledger)
    journal = journal or enforcement.DEFAULT_JOURNAL
    observed, decided, enforced = _records(observations), _records(ledger), _records(journal)
    # Incidents merged later keep one story: every ID leads to the incident it ended up in.
    merged_into = {r['merged']: r['incident'] for r in observed if r.get('kind') == 'merge' and r.get('merged')}

    def final(identifier):
        seen = set()
        while identifier in merged_into and identifier not in seen:
            seen.add(identifier)
            identifier = merged_into[identifier]
        return identifier

    out, found = [], set()
    for record in observed:
        if record.get('kind') != 'finding' or not isinstance(record.get('signal'), dict):
            continue
        signal = record['signal']
        found.add((final(record.get('incident')), signal.get('key')))
        out.append(dict(at=record.get('at'), kind='finding', incident=final(record.get('incident')),
                        source=signal.get('source'), rule_id=signal.get('rule_id'),
                        severity=_severity(signal.get('severity')), summary=signal.get('summary', ''),
                        observed_at=signal.get('observed_at'), entities=signal.get('entities') or {},
                        key=signal.get('key')))
    decisions = {}
    for record in decided:
        signal, incident = record.get('signal') or {}, final((record.get('incident') or {}).get('id'))
        # A ledger written before the observation log still tells its findings.
        if (incident, signal.get('key')) not in found:
            found.add((incident, signal.get('key')))
            out.append(dict(at=record.get('decided_at'), kind='finding', incident=incident,
                            source=signal.get('source'), rule_id=signal.get('rule_id'),
                            severity=_severity(signal.get('severity')), summary=signal.get('summary', ''),
                            observed_at=signal.get('observed_at'), entities=signal.get('entities') or {},
                            key=signal.get('key')))
        # Older journals are matched to decisions by when, which rule and playbook, and which action on what.
        for plan in record.get('actions', []):
            key = (record.get('decided_at'), signal.get('rule_id'), record.get('playbook'), plan.get('action'),
                   plan.get('target'))
            decisions.setdefault(key, set()).add(incident)
        out.append(dict(at=record.get('decided_at'), kind='decision', incident=incident,
                        playbook=record.get('playbook'), rule_id=signal.get('rule_id'),
                        severity=_severity(signal.get('severity')), entities=signal.get('entities') or {},
                        corroborated=(record.get('incident') or {}).get('corroborated'),
                        actions=[dict(action=a.get('action'), target=a.get('target'), status=a.get('status'),
                                      guard=a.get('guard')) for a in record.get('actions', [])]))
    applied = {}
    for record in enforced:
        incident = final(record.get('incident')) if record.get('incident') else None
        if record.get('status') == 'undone':
            incident = incident or applied.get(record.get('undo_of'))
            out.append(dict(at=record.get('at'), kind='undo', incident=incident, action=record.get('action'),
                            target=record.get('target'), undo_of=record.get('undo_of'),
                            **({'expired': True} if record.get('reason') == 'expired' else {})))
            continue
        # A journal written before records carried their incident is matched to its decision. A match that two
        # incidents share is left unassigned rather than given to either: it still shows in --entity views.
        if not incident:
            matched = decisions.get((record.get('decided_at'), record.get('rule_id'), record.get('playbook'),
                                     record.get('action'), record.get('target')), set())
            incident = next(iter(matched)) if len(matched) == 1 else None
        applied[record.get('id')] = incident
        event = dict(at=record.get('at'), kind='action', incident=incident, action=record.get('action'),
                     target=record.get('target'), status=record.get('status'), reason=record.get('reason'),
                     playbook=record.get('playbook'), rule_id=record.get('rule_id'), id=record.get('id'))
        undo = record.get('undo') if isinstance(record.get('undo'), dict) else {}
        if record.get('action') == 'collect_evidence':
            event['evidence'] = [b for b in [undo.get('bundle'), *(undo.get('memory') or [])] if b]
        out.append(event)
    order = {'finding': 0, 'decision': 1, 'action': 2, 'undo': 3}
    out.sort(key=lambda e: (_parse(e.get('at')) or datetime.min.replace(tzinfo=timezone.utc),
                            order.get(e['kind'], 9)))
    return out, final


def _matches(event, entity):
    if entity in _entity_keys(event.get('entities')):
        return True
    kind, _, value = entity.partition(':')
    return event.get('target') == value or any(a.get('target') == value for a in event.get('actions', []))


def summarize(identifier, items):
    """One incident at a glance: when, how bad, which checks saw it, what it involved and what was done."""
    findings = [e for e in items if e['kind'] == 'finding']
    times = [t for t in (_parse(e.get('at')) for e in items) if t]
    entities = {}
    for event in findings:
        for key in _entity_keys(event.get('entities')):
            kind, _, value = key.partition(':')
            entities.setdefault(kind, set()).add(value)
    done = [e for e in items if e['kind'] == 'action' and e.get('status') == 'applied']
    return dict(incident=identifier,
                first=min(times).strftime('%Y-%m-%dT%H:%M:%SZ') if times else None,
                last=max(times).strftime('%Y-%m-%dT%H:%M:%SZ') if times else None,
                severity=min((e['severity'] for e in findings), key=RANK.index, default='INFO'),
                sources=sorted({e['source'] for e in findings if e.get('source')}),
                rules=sorted({e['rule_id'] for e in findings if e.get('rule_id')}),
                findings=len(findings), decisions=sum(1 for e in items if e['kind'] == 'decision'),
                actions_applied=len(done), undone=sum(1 for e in items if e['kind'] == 'undo'),
                evidence=[b for e in done for b in e.get('evidence', [])],
                entities={kind: sorted(values)[:20] for kind, values in sorted(entities.items())})


def incidents(*, hours=168, now=None, **paths):
    """Incidents with activity in the last `hours`, worst and most recent first."""
    now = now or _now()
    cutoff = now - timedelta(hours=hours)
    grouped = {}
    for event in events(**paths):
        if event.get('incident'):
            grouped.setdefault(event['incident'], []).append(event)
    rows = [summarize(i, items) for i, items in grouped.items()]
    rows = [r for r in rows if r['last'] and _parse(r['last']) >= cutoff]
    rows.sort(key=lambda r: r['last'], reverse=True)
    rows.sort(key=lambda r: RANK.index(r['severity']))
    return dict(schema=SCHEMA, action='list', hours=hours, incidents=rows)


def show(incident=None, *, entity=None, **paths):
    """The events of one incident, or of every incident that involved one entity."""
    if not incident and not entity:
        raise TimelineError('give an incident ID, or --entity KIND:VALUE such as address:203.0.113.7')
    if entity and ':' not in entity:
        raise TimelineError('an entity is KIND:VALUE, such as address:203.0.113.7 or file:/tmp/x')
    every, final = _load(**paths)
    if incident:
        incident = final(incident)        # an incident merged into another is told as part of it
        chosen = [e for e in every if e.get('incident') == incident]
        if not chosen:
            prefix = [i for i in {e.get('incident') for e in every} if i and i.startswith(incident)]
            if len(prefix) == 1:
                incident, chosen = prefix[0], [e for e in every if e.get('incident') == prefix[0]]
        if not chosen:
            raise TimelineError(f'no incident {incident} was recorded')
    else:
        involved = {e.get('incident') for e in every if _matches(e, entity)}
        chosen = [e for e in every if e.get('incident') in involved and e.get('incident')
                  or _matches(e, entity)]
        if not chosen:
            raise TimelineError(f'nothing recorded involves {entity}')
    chosen = chosen[-MAX_EVENTS:]
    ids = sorted({e['incident'] for e in chosen if e.get('incident')})
    return dict(schema=SCHEMA, action='show', incident=incident, entity=entity,
                incidents=[summarize(i, [e for e in chosen if e.get('incident') == i]) for i in ids],
                events=chosen, truncated=len(chosen) == MAX_EVENTS)


# ------------------------------------------------------------------ text and HTML

def _line(event):
    kind = event['kind']
    if kind == 'finding':
        names = ', '.join(sorted(_entity_keys(event.get('entities'))))[:160]
        return (f"{event['severity']:<8} {event.get('source') or '?'}: {event.get('rule_id')} - "
                f"{event.get('summary', '')}" + (f"  [{names}]" if names else ''))
    if kind == 'decision':
        parts = [f"{a['action']} {a.get('target') or ''}".strip() + f" ({a['status']}"
                 + (f": {a['guard']}" if a.get('guard') else '') + ')' for a in event.get('actions', [])]
        return f"decided by playbook {event.get('playbook')}: " + ('; '.join(parts) or 'no actions')
    if kind == 'action':
        text = f"{event.get('status')}: {event.get('action')} {event.get('target') or ''}".rstrip()
        if event.get('reason'):
            text += f" ({event['reason']})"
        if event.get('evidence'):
            text += ' -> ' + ', '.join(event['evidence'])
        return text + (f"  [id {event['id']}]" if event.get('id') else '')
    what = 'ended on time' if event.get('expired') else 'undone'
    return f"{what}: {event.get('action')} {event.get('target') or ''}".rstrip() + f"  [undo of {event.get('undo_of')}]"


def text(result):
    lines = []
    if result['action'] == 'list':
        if not result['incidents']:
            return f"No incidents in the last {result['hours']} hours.\n"
        for row in result['incidents']:
            where = f" on {', '.join(row['machines'])}" if row.get('machines') else ''
            lines.append(f"{row['incident']}  {row['severity']:<8} {row['first']} .. {row['last']}  "
                         f"{row['findings']} findings from {', '.join(row['sources']) or '-'}{where}; "
                         f"{row['actions_applied']} actions carried out"
                         + (f"; joined by {', '.join(row['linked_by'][:4])}" if row.get('linked_by') else ''))
        return '\n'.join(lines) + '\n'
    for row in result['incidents']:
        lines.append(f"Incident {row['incident']} ({row['severity']}), {row['first']} .. {row['last']}")
        lines.append(f"  seen by: {', '.join(row['sources']) or '-'}")
        if row.get('machines'):
            lines.append(f"  machines: {', '.join(row['machines'])}"
                         + (f" (joined by {', '.join(row['linked_by'])})" if row.get('linked_by') else ''))
        for kind, values in row['entities'].items():
            lines.append(f"  {kind}: {', '.join(values)}")
    lines.append('')
    for event in result['events']:
        machine = f"{event['machine']:<14} " if event.get('machine') else ''
        tag = machine + ('' if result.get('incident') else f"{(event.get('incident') or '-')[:12]:<12} ")
        lines.append(f"{event.get('at') or '?':<20} {tag}{event['kind']:<8} {_line(event)}")
    return '\n'.join(lines) + '\n'


def page(result):
    """A static HTML page: no scripts, nothing loaded from elsewhere."""
    e = html.escape
    title = f"Incident {result.get('incident')}" if result.get('incident') else f"Timeline of {result.get('entity')}"
    rows = ''.join(f"<tr class=\"{e(ev['kind'])}\"><td>{e(str(ev.get('at') or ''))}</td>"
                   f"<td>{e((ev['machine'] + '/') if ev.get('machine') else '')}{e(str(ev.get('incident') or ''))}</td>"
                   f"<td>{e(ev['kind'])}</td>"
                   f"<td>{e(ev.get('severity', ''))}</td><td>{e(_line(ev))}</td></tr>" for ev in result['events'])
    heads = ''.join(f"<li><b>{e(r['incident'])}</b> {e(r['severity'])}, {e(str(r['first']))} to {e(str(r['last']))}: "
                    f"{r['findings']} findings from {e(', '.join(r['sources']))}; {r['actions_applied']} actions "
                    f"carried out</li>" for r in result['incidents'])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
body{{font:14px/1.4 system-ui,sans-serif;margin:16px;background:#fff;color:#111}}
table{{border-collapse:collapse;width:100%}}td{{border-bottom:1px solid #ddd;padding:4px 6px;vertical-align:top}}
tr.decision td{{color:#444}}tr.action td{{background:#fff6e0}}tr.undo td{{background:#e9f5ff}}
@media (prefers-color-scheme: dark){{body{{background:#111;color:#eee}}td{{border-color:#333}}
tr.action td{{background:#3a2e10}}tr.undo td{{background:#10283a}}tr.decision td{{color:#bbb}}}}
</style></head><body>
<h1>{e(title)}</h1><ul>{heads}</ul>
<table><tr><td><b>When</b></td><td><b>Incident</b></td><td><b>What</b></td><td><b>Severity</b></td><td><b>Detail</b></td></tr>
{rows}</table></body></html>
"""


def list_page(result):
    """Incidents as a static HTML page, each linking to its own page on the fleet view."""
    e = html.escape
    rows = ''.join(f"<tr><td><a href=\"/timeline/{e(r['incident'])}\">{e(r['incident'])}</a></td>"
                   f"<td>{e(r['severity'])}</td><td>{e(str(r['first']))}</td><td>{e(str(r['last']))}</td>"
                   f"<td>{e(', '.join(r.get('machines', [])))}</td><td>{e(', '.join(r['sources']))}</td>"
                   f"<td>{r['findings']}</td><td>{r['actions_applied']}</td>"
                   f"<td>{e(', '.join(r.get('linked_by', [])))}</td></tr>" for r in result['incidents'])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Fleet incidents</title>
<style>body{{font:14px/1.4 system-ui,sans-serif;margin:16px;background:#fff;color:#111}}
table{{border-collapse:collapse;width:100%}}td{{border-bottom:1px solid #ddd;padding:4px 6px}}
a{{color:#0645ad}}@media (prefers-color-scheme: dark){{body{{background:#111;color:#eee}}td{{border-color:#333}}
a{{color:#8ab4f8}}}}</style></head><body><h1>Fleet incidents, last {result.get('hours')} hours</h1>
<table><tr><td><b>Incident</b></td><td><b>Severity</b></td><td><b>First</b></td><td><b>Last</b></td>
<td><b>Machines</b></td><td><b>Seen by</b></td><td><b>Findings</b></td><td><b>Actions</b></td>
<td><b>Joined by</b></td></tr>{rows}</table></body></html>
"""


def write_private(path, content):
    """Write an export mode 600: it names addresses, programs, files and accounts."""
    path = Path(path).expanduser()
    if path.exists() and (path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode)):
        raise TimelineError(f'{path} exists and is not a regular file')
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.timeline-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            stream.write(content)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return str(path)


# ------------------------------------------------------------------ sending the timeline to the fleet collector

BATCH_SCHEMA = 'megalodon-timeline-batch-v1'
DEFAULT_CURSOR = '~/.local/state/megalodon/timeline-push.json'
MAX_BATCH_BYTES = 56 * 1024          # under the collector's 64 KiB limit, with room for the envelope
MAX_BATCHES = 50


def event_id(event):
    """A stable identity for an event: its content, without the incident it is filed under (that can merge)."""
    canonical = json.dumps({k: v for k, v in event.items() if k != 'incident'}, sort_keys=True,
                           separators=(',', ':'), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:24]


def _cursor(path):
    path = Path(path).expanduser()
    if not path.exists():
        return dict(last_at='', ids=[])
    try:
        return json.loads(b''.join(_lines(path)))
    except ValueError:
        raise TimelineError(f'{path} is not valid JSON') from None


def _events_url(settings, url=None):
    if url:
        return url
    base = settings['url']
    return base[:-len('/heartbeat')] + '/events' if base.endswith('/heartbeat') else base.rstrip('/') + '/events'


def _merges(ledger):
    """The engine's merge records as events: the collector applies them to events it already holds."""
    return [dict(at=r.get('at'), kind='merge', incident=r['incident'], merged=r['merged'])
            for r in _records(engine.observations_path(ledger))
            if r.get('kind') == 'merge' and isinstance(r.get('incident'), str) and isinstance(r.get('merged'), str)]


def pending(cursor, *, ledger=engine.DEFAULT_LEDGER, journal=None):
    """Events not yet sent, oldest first: those after the last one sent, by time and identity.

    Merges are sent too. An event already sent keeps the incident it was sent under, so the collector
    needs to hear when two incidents became one."""
    sent_at, sent = cursor.get('last_at', ''), set(cursor.get('ids', []))
    out = []
    every = events(ledger=ledger, journal=journal) + _merges(ledger)
    every.sort(key=lambda e: str(e.get('at') or ''))
    for event in every:
        identity = event_id(event)
        at = str(event.get('at') or '')
        if at > sent_at or (at == sent_at and identity not in sent):
            out.append(dict(event, event_id=identity))
    return out


def push(*, config=None, cursor_path=DEFAULT_CURSOR, ledger=engine.DEFAULT_LEDGER, journal=None, url=None,
         send=None, now=None, dry_run=False):
    """Send events not yet sent to the fleet collector, signed with this machine's heartbeat key."""
    from . import tamper
    settings = tamper._read(config or tamper.DEFAULT_HEARTBEAT, tamper.HEARTBEAT_SCHEMA + '-config',
                            'heartbeat configuration')
    settings = dict(settings, url=_events_url(settings, url))
    cursor = _cursor(cursor_path)
    queue = pending(cursor, ledger=ledger, journal=journal)
    sent, batches, skipped = 0, 0, 0
    send = send or tamper.send
    while queue and batches < MAX_BATCHES:
        batch, size = [], 0
        while queue:
            line = len(json.dumps(queue[0], sort_keys=True, default=str))
            if line > MAX_BATCH_BYTES:
                skipped += 1           # one event too large to send alone: counted, never blocks the rest
                queue.pop(0)
                continue
            if batch and size + line > MAX_BATCH_BYTES:
                break
            batch.append(queue.pop(0))
            size += line
        if not batch:
            break
        moment = now or _now()
        # The sequence is the time in milliseconds: it only grows, even if this machine's cursor is deleted.
        body = dict(schema=BATCH_SCHEMA, sensor=settings.get('sensor', ''), sequence=int(moment.timestamp() * 1000)
                    + batches, sent_at=moment.strftime('%Y-%m-%dT%H:%M:%SZ'), events=batch)
        body['mac'] = tamper._sign(settings['key'], body)
        if dry_run:
            sent, batches = sent + len(batch), batches + 1
            continue
        send(settings, body)
        sent, batches = sent + len(batch), batches + 1
        last = max(str(e.get('at') or '') for e in batch)
        ids = [e['event_id'] for e in batch if str(e.get('at') or '') == last]
        if last == cursor.get('last_at'):
            ids = sorted(set(cursor.get('ids', [])) | set(ids))
        cursor = dict(last_at=last, ids=ids)
        write_private(cursor_path, json.dumps(cursor, sort_keys=True))
    return dict(schema=SCHEMA, action='dry_run' if dry_run else 'push', url=settings['url'], sent=sent,
                batches=batches, remaining=len(queue), too_large=skipped)
