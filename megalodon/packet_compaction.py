"""Resumable, bounded summaries of closed packet-metadata segments.

The source remains authoritative until its summary is complete and checked.
Each batch and its cursor commit in the same SQLite transaction; an interrupted
build resumes without replaying a committed batch. No packet payload is read.
"""
from __future__ import annotations

from collections import defaultdict
import json

from .evidence_storage import epoch, utc
from .packet_qualification import qualified_event_ids

EVENT_BATCH = 1024
MAX_LINKED_FINDINGS = 4096
MAX_RECORD_BYTES = 32768
MAX_BATCH_BYTES = 8 * 1024**2
BUCKET_SECONDS = 300


def _encoded(value):
    raw = json.dumps(value, separators=(',', ':'), sort_keys=True, allow_nan=False)
    if len(raw.encode()) > MAX_RECORD_BYTES:
        raise ValueError('A flagged event exceeds the compact evidence bound; the original segment remains protected.')
    return raw


def _read_checkpoint(manager, target):
    with manager._db(target) as db:
        row = db.execute("SELECT value FROM checkpoints WHERE key='packet_compaction'").fetchone()
    return json.loads(row[0]) if row else dict(stage='events', cursor=0, processed_count=0,
                                                processed_bytes=0, finding_count=0, action_count=0, run_count=0)


def _write(manager, target, rows, progress):
    raw_rows = [(observed, utc(manager.clock()), source, _encoded(data))
                for observed, source, data in rows]
    size=sum(len(row[3].encode()) for row in raw_rows)
    if size>MAX_BATCH_BYTES:
        raise ValueError('A compact evidence batch exceeds its write bound; the original segment remains protected.')
    manager._ensure_space(max(16 * 1024**2, size * 3))
    with manager._writer_db(target) as db:
        db.executemany('INSERT INTO records(observed_at,recorded_at,source,data) VALUES(?,?,?,?)', raw_rows)
        db.execute("INSERT OR REPLACE INTO checkpoints(key,value) VALUES('packet_compaction',?)",
                   (json.dumps(progress, separators=(',', ':'), sort_keys=True),))
        db.commit()
    manager._write_metrics['commits'] += 1


def _event_rows(manager, source, cursor):
    with manager._db(source) as db:
        events = [dict(row) for row in db.execute('SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?',
                                                   (cursor, EVENT_BATCH)).fetchall()]
        if not events:
            return [], [], [], []
        last = events[-1]['id']
        qualified = qualified_event_ids(db,cursor,last)
        if any(event['id'] not in qualified for event in events):
            return None, [], [], []
        findings = [dict(row) for row in db.execute(
            'SELECT * FROM detections WHERE event_id>? AND event_id<=? ORDER BY id LIMIT ?',
            (cursor, last, MAX_LINKED_FINDINGS + 1)).fetchall()]
        if len(findings) > MAX_LINKED_FINDINGS:
            raise ValueError('Finding density exceeds a bounded compaction batch; original evidence remains protected.')
        links = [tuple(row) for row in db.execute(
            'SELECT l.detection_id,l.action_id FROM detection_actions l JOIN detections d ON d.id=l.detection_id '
            'WHERE d.event_id>? AND d.event_id<=? ORDER BY l.detection_id', (cursor, last)).fetchall()]
    return events, findings, links, [event['id'] for event in events]


def _group(events, source_id):
    groups = {}
    for event in events:
        stamp = epoch(event['observed_at'])
        bucket = utc(int(stamp // BUCKET_SECONDS) * BUCKET_SECONDS)
        key = (bucket, event['interface'], event['src_ip'], event['dst_ip'],
               event['protocol'], event['src_port'], event['dst_port'])
        group = groups.get(key)
        if group is None:
            group = groups[key] = dict(kind='conversation_v1', source_segment=source_id,
                                      bucket_start=bucket, interface=event['interface'],
                                      src_ip=event['src_ip'], dst_ip=event['dst_ip'],
                                      protocol=event['protocol'], src_port=event['src_port'],
                                      dst_port=event['dst_port'], first_at=event['observed_at'],
                                      last_at=event['observed_at'], first_event_id=event['id'],
                                      last_event_id=event['id'], packet_count=0, byte_count=0)
        group['first_at'] = min(group['first_at'], event['observed_at'])
        group['last_at'] = max(group['last_at'], event['observed_at'])
        group['first_event_id'] = min(group['first_event_id'], event['id'])
        group['last_event_id'] = max(group['last_event_id'], event['id'])
        group['packet_count'] += 1
        group['byte_count'] += event['byte_count']
    return [(item['first_at'], 'packet-conversation-summary', item) for item in groups.values()]


def step(manager, source, target):
    """Process one source batch. Return True only after complete verification."""
    progress = _read_checkpoint(manager, target)
    if progress['stage'] == 'events':
        events, findings, links, _ = _event_rows(manager, source, progress['cursor'])
        if events is None:
            return 'ineligible'
        if events:
            rows = _group(events, source['id'])
            by_event = {event['id']: event for event in events}
            linked = defaultdict(list)
            for detection_id, action_id in links:
                linked[detection_id].append(action_id)
            for finding in findings:
                data = dict(kind='finding_v1', source_segment=source['id'],
                            original_reference=source['id'] + ':' + str(finding['event_id']),
                            original_finding_id=finding['id'], event=by_event[finding['event_id']],
                            detection=finding, action_ids=linked[finding['id']])
                rows.append((by_event[finding['event_id']]['observed_at'], 'preserved-packet-finding', data))
            next_progress = dict(progress, cursor=events[-1]['id'],
                                 processed_count=progress['processed_count'] + len(events),
                                 processed_bytes=progress['processed_bytes'] + sum(e['byte_count'] for e in events),
                                 finding_count=progress['finding_count'] + len(findings))
            _write(manager, target, rows, next_progress)
            return False
        progress = dict(progress, stage='actions', cursor=0)
        _write(manager, target, [], progress)
        return False
    if progress['stage'] == 'actions':
        with manager._db(source) as db:
            actions = [dict(row) for row in db.execute('SELECT * FROM actions WHERE id>? ORDER BY id LIMIT ?',
                                                      (progress['cursor'], EVENT_BATCH)).fetchall()]
        if actions:
            rows = [(action['created_at'], 'preserved-packet-action',
                     dict(kind='action_v1', source_segment=source['id'], original_action_id=action['id'],
                          original_reference=source['id'] + ':action:' + str(action['id']), action=action))
                    for action in actions]
            progress = dict(progress, cursor=actions[-1]['id'],
                            action_count=progress['action_count'] + len(actions))
            _write(manager, target, rows, progress)
            return False
        progress = dict(progress, stage='runs', cursor=0)
        _write(manager, target, [], progress)
        return False
    if progress['stage'] == 'runs':
        with manager._db(source) as db:
            runs = [dict(row) for row in db.execute('SELECT * FROM ingestion_runs WHERE id>? ORDER BY id LIMIT ?',
                                                   (progress['cursor'], EVENT_BATCH)).fetchall()]
        if runs:
            rows = [(run['started_at'], 'preserved-capture-receipt',
                     dict(kind='run_v1', source_segment=source['id'], original_run_id=run['id'],
                          receipt=run)) for run in runs]
            progress = dict(progress, cursor=runs[-1]['id'], run_count=progress['run_count']+len(runs))
            _write(manager, target, rows, progress)
            return False
        progress = dict(progress, stage='verify')
        _write(manager, target, [], progress)
        return False
    if progress['stage'] == 'verify':
        with manager._db(source) as db:
            count, byte_count = db.execute('SELECT COUNT(*),COALESCE(SUM(byte_count),0) FROM events').fetchone()
            findings = db.execute('SELECT COUNT(*) FROM detections').fetchone()[0]
            actions = db.execute('SELECT COUNT(*) FROM actions').fetchone()[0]
            runs = db.execute('SELECT COUNT(*) FROM ingestion_runs').fetchone()[0]
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('Original evidence integrity needs review; it remains protected.')
        if (count != source['records'] or count != progress['processed_count']
                or byte_count != progress['processed_bytes'] or findings != progress['finding_count']
                or actions != progress['action_count'] or runs != progress['run_count']):
            raise ValueError('Compact evidence totals did not match the original; it remains protected.')
        with manager._db(target) as db:
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise ValueError('Compact evidence integrity needs review; the original segment remains protected.')
            rows = db.execute('SELECT source,COUNT(*),MIN(observed_at),MAX(observed_at) FROM records GROUP BY source').fetchall()
        saved = {row[0]: row[1] for row in rows}
        if (saved.get('preserved-packet-finding', 0) != findings
                or saved.get('preserved-packet-action', 0) != actions
                or saved.get('preserved-capture-receipt', 0) != runs
                or (count and not saved.get('packet-conversation-summary', 0))):
            raise ValueError('Compact evidence records did not match the original; it remains protected.')
        if manager._size(target) >= manager._size(source):
            return 'inefficient'
        progress = dict(progress, stage='done')
        _write(manager, target, [], progress)
        return True
    if progress['stage'] == 'done':
        return True
    raise ValueError('Compact evidence checkpoint needs review.')
