"""Retained hourly record-count receipts; no learned counts or comparison adoption."""
from hashlib import sha256
import json
import math
import sqlite3
import time

from .ai_context import build_context, INPUT_SCHEMA, MAX_SOURCES
from .endpoint_context import _project
from .evidence_storage import epoch
from .packet_qualification import qualified_event_ids
from .retained_history import RetainedEvidenceReader
from .security_patterns import MAX_GROUPS, MAX_RECORDS, stable

SCHEMA = 'megalodon-endpoint-hour-count-v1'
SOURCE = 'endpoint-hour-count-v1'


def _unavailable(reason):
    return dict(state='unavailable', reason=reason, summaries=[])


def _bindings(evidence, sources, now):
    bindings = []
    with evidence.lock:
        live = {entry['id']: entry for entry in evidence._catalog['entries']}
        for entry, watermark in sources:
            current = live.get(entry['id'])
            if (current is None or current['state'] not in {'open', 'closed'}
                    or current.get('compacted_to') or not evidence.derived_available(current)):
                raise ValueError('Source unavailable')
            expires = int(epoch(current.get('first_at') or current['created_at']) + evidence.retention_days * 86400)
            if expires <= now:
                return None
            binding = dict(id=entry['id'], kind=entry['category'], watermark=watermark, expires_at=expires)
            if entry['kind'] == 'core':
                with evidence._db(entry) as db:
                    qualified = qualified_event_ids(db, 0, watermark)
                    total = db.execute('SELECT COUNT(*) FROM events WHERE id<=?', (watermark,)).fetchone()[0]
                if len(qualified) != total:
                    raise ValueError('Unqualified packet records')
                binding['qualification_sha256'] = sha256(json.dumps(sorted(qualified)).encode()).hexdigest()
            bindings.append(binding)
    return sorted(bindings, key=lambda value: value['id'])


def read_hour_counts(evidence, start, *, clock=None, check=None):
    """Count all admitted records at fixed watermarks for one completed UTC hour.

    Eligibility certifies a bounded, stable retained read, not complete sensor
    capture. Empty reads never invent zero summaries. Open sources may be used,
    but an append, retirement, expiry or qualification change during the read
    withholds every summary. The final checks remain sequential, not atomic.
    """
    clock = clock or evidence.clock
    now = clock()
    if (type(start) not in {int, float} or not math.isfinite(start) or start != int(start)
            or start < 0 or start % 3600 or start + 3600 > int(now // 3600) * 3600):
        return _unavailable('incomplete_hours')
    start = int(start)
    end = start + 3600
    if not evidence.enabled:
        return _unavailable('no_baseline')
    deadline = time.monotonic() + 8
    def bounded_check():
        if time.monotonic() > deadline:
            raise ValueError('Bounded count read expired')
        if check is not None:
            check()
    reader = RetainedEvidenceReader(evidence)
    reader._check = bounded_check
    try:
        sources, gaps = reader._sources(start, end, categories={'packets', 'flows'})
        if gaps:
            return _unavailable('incomplete_hours')
        if len(sources) > MAX_SOURCES or sum(watermark for _, watermark in sources) > MAX_RECORDS:
            return _unavailable('truncated')
        bindings = _bindings(evidence, sources, now)
        if bindings is None:
            return _unavailable('source_expired')
        if not sources:
            return _unavailable('no_baseline')
        groups, digests = {}, {}
        scanned = 0
        for entry, watermark in sorted(sources, key=lambda value: value[0]['id']):
            dependency = next(value for value in bindings if value['id'] == entry['id'])
            digests[entry['id']] = sha256()
            for page, count in reader._pages(entry, watermark, start, end):
                scanned += count
                if scanned > MAX_RECORDS:
                    return _unavailable('truncated')
                bounded_check()
                for index, row in enumerate(page):
                    if index % 64 == 0:
                        bounded_check()
                    projected = _project(row)
                    # Use the same per-record admission as the endpoint context.
                    build_context(dict(schema=INPUT_SCHEMA, subject=projected['src_ip'],
                        window=dict(start=start, end=end), as_of=int(now),
                        sources=[{key: dependency[key] for key in ('id', 'kind', 'expires_at')}],
                        records=[projected], coverage=dict(truncated=False, missing=[]),
                        comparison=dict(state='unavailable', reason='not_requested'), references=[]))
                    digests[entry['id']].update(json.dumps(projected, sort_keys=True, separators=(',', ':')).encode() + b'\n')
                    # A loopback/self exchange counts once for this subject.
                    for subject in sorted({projected['src_ip'], projected['dst_ip']}):
                        key = subject, projected['source'], projected['kind'], projected['scope_id']
                        if key not in groups:
                            if len(groups) >= MAX_GROUPS:
                                return _unavailable('truncated')
                            groups[key] = 0
                        groups[key] += 1
        bounded_check()
        final_sources, gaps = reader._sources(start, end, categories={'packets', 'flows'})
        if gaps or len(final_sources) > MAX_SOURCES or sum(w for _, w in final_sources) > MAX_RECORDS:
            return _unavailable('incomplete_hours')
        final_now = clock()
        final = _bindings(evidence, final_sources, final_now)
        if final is None:
            return _unavailable('source_expired')
        if bindings != final:
            return _unavailable('incomplete_hours')
        bounded_check()
        # Refresh the clock after the final database/qualification checks.
        final_now = clock()
        if final_now < now or end > int(final_now // 3600) * 3600:
            return _unavailable('incomplete_hours')
        if any(binding['expires_at'] <= final_now for binding in final):
            return _unavailable('source_expired')
        if not groups:
            return _unavailable('no_baseline')
        snapshot = sha256(json.dumps(dict(start=start, end=end, bindings=bindings,
            records={key: value.hexdigest() for key, value in sorted(digests.items())}),
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        summaries = []
        for (subject, source, kind, scope), count in sorted(groups.items()):
            value = dict(schema=SCHEMA, subject=subject, source=source, kind=kind, scope_id=scope,
                start=start, end=end, as_of=int(final_now), count=count, basis='retained_record_count',
                eligible=True, capture_complete=False, read_sources=bindings,
                source_segments=[binding['id'] for binding in bindings], read_sha256=snapshot)
            value['id'] = stable([subject, source, kind, scope, start, end, snapshot])
            summaries.append(value)
        bounded_check()
        return_now = clock()
        if return_now < final_now:
            return _unavailable('incomplete_hours')
        if any(binding['expires_at'] <= return_now for binding in final):
            return _unavailable('source_expired')
        for value in summaries:
            value['as_of'] = int(return_now)
        return dict(state='available', summaries=summaries)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, sqlite3.Error):
        return _unavailable('incomplete_hours')
