"""Bounded retained finding review; model interpretation never grants action authority.

The feed reads finding records, rather than the newest traffic page. Selected
facts, review jobs and impact previews share an exact context identity. Existing
Defense remains the only authority for all host effects.
"""
from collections import OrderedDict
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sqlite3
from threading import Event, RLock, Thread
import time

from . import ai_provider
from .evidence_storage import epoch, utc
from .intelligence import SELECTED_EXPLANATION_CONTRACT, explain
from .packet_qualification import QUALIFIED_RUN_SQL
from .retained_history import RetainedEvidenceReader
from .security_patterns import CONTEXT

SCHEMA = 'megalodon-findings-v1'
REVIEW_SOURCE = 'selected-finding-review-v1'
FEEDBACK_SOURCE = 'selected-finding-feedback-v1'
MAX_SEGMENTS = 128
MAX_CANDIDATES = 4096
MAX_REVIEWS = 128
MAX_FACT_BYTES = 1800
KINDS = {'all', 'detector', 'sensor', 'pattern'}
SEVERITIES = ('critical', 'high', 'medium', 'low', 'unknown')
IDENTIFIER = re.compile(r'(?:detector|sensor):[a-f0-9]{32}:[1-9][0-9]{0,18}|pattern:[a-f0-9]{32}')
HEX = re.compile(r'[a-f0-9]{64}')


class FindingsBusy(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _text(value, maximum=240, fallback='Unknown'):
    return value[:maximum] if type(value) is str and value and value.isprintable() else fallback


def _address(value):
    try:
        if type(value) is not str or '%' in value:
            return None
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _number(value, maximum=2**53-1):
    return value if type(value) is int and 0 <= value <= maximum else None


def _sql_text(column, maximum):
    # All callers pass source-owned column names and integer bounds.
    return (f"CASE WHEN typeof({column})='text' AND length(CAST({column} AS BLOB))<= {maximum} "
            f"THEN {column} ELSE NULL END")


def _bounded(value, depth=0):
    """Small data-only view. No raw payloads, paths, commands or arbitrary keys."""
    if depth > 3:
        return None
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return _number(value)
    if type(value) is float:
        return value if 0 <= value <= 2**53-1 else None
    if type(value) is str:
        return _text(value, 160, '')
    if type(value) is list:
        return [_bounded(v, depth+1) for v in value[:8]]
    if type(value) is dict:
        forbidden = ('payload', 'raw', 'command', 'path', 'content', 'url', 'prompt')
        return {k: _bounded(v, depth+1) for k, v in list(value.items())[:16]
                if type(k) is str and re.fullmatch(r'[A-Za-z0-9_ -]{1,40}', k)
                and not any(part in k.casefold() for part in forbidden)}
    return None


def _facts(facts):
    """The displayed fact packet is exactly the packet sent to local AI."""
    value = deepcopy(facts)
    evidence = value.get('recorded_evidence')
    if evidence is not None and len(json.dumps(value, ensure_ascii=True).encode()) > MAX_FACT_BYTES:
        value['recorded_evidence'] = {'state': 'omitted', 'reason': 'Recorded details exceed the selected-context limit.'}
    if len(json.dumps(value, ensure_ascii=True).encode()) > MAX_FACT_BYTES:
        raise ValueError('Selected finding context exceeds its bound')
    return value


def validate_action(body):
    fields = {
        'analyze': {'finding_id', 'context_sha256'},
        'cancel': set(),
        'feedback': {'finding_id', 'context_sha256', 'choice'},
        'plan_containment': {'finding_id', 'context_sha256', 'target_ip'},
        'apply_containment': {'plan_id', 'acknowledge_disruption'},
        'release_containment': {'ip'},
    }
    if type(body) is not dict or type(body.get('action')) is not str or body['action'] not in fields:
        raise ValueError('Choose a fixed findings action')
    if set(body) != {'action'} | fields[body['action']]:
        raise ValueError('Unexpected findings action fields')
    if 'finding_id' in body and (type(body['finding_id']) is not str or not IDENTIFIER.fullmatch(body['finding_id'])):
        raise ValueError('Choose a qualified finding')
    if 'context_sha256' in body and (type(body['context_sha256']) is not str or not HEX.fullmatch(body['context_sha256'])):
        raise ValueError('Choose an exact selected context')
    if 'choice' in body and (type(body['choice']) is not str or body['choice'] not in {'expected', 'investigate', 'incorrect'}):
        raise ValueError('Choose a review assessment')
    if 'plan_id' in body and (type(body['plan_id']) is not str or not re.fullmatch(r'[a-f0-9]{32}', body['plan_id'])):
        raise ValueError('Choose an existing impact preview')
    if 'acknowledge_disruption' in body and body['acknowledge_disruption'] is not True:
        raise ValueError('Explicit disruption acknowledgment is required')
    for key in ('target_ip', 'ip'):
        if key in body and (_address(body[key]) is None or _address(body[key]) != body[key]):
            raise ValueError('Use one canonical address')
    return dict(body)


class FindingsReview(RetainedEvidenceReader):
    def __init__(self, evidence, intelligence, knowledge, configuration, defense, *, clock=None, model=None):
        super().__init__(evidence)
        self.intelligence, self.knowledge = intelligence, knowledge
        self.configuration, self.defense = configuration, defense
        self.clock, self.model = clock or evidence.clock, model
        self.token = secrets.token_hex(16)
        self._cursor_key = secrets.token_bytes(32)
        self.lock = RLock()
        self.cancel_event = Event()
        self.worker = None
        self.reviews, self.feedback = OrderedDict(), {}
        self.plan_bindings, self.pending_plan = {}, None
        self.job = dict(id=None, state='idle', finding_id=None, message='Select retained evidence to review.')
        self.restore_gaps = []
        self._read_cache = None
        self._restore()

    def _restore(self):
        if not self.evidence.enabled:
            return
        first, last = self.clock()-self.evidence.retention_days*86400, self.clock()+1
        try:
            sources, gaps = self._sources(first, last, categories={'intelligence'})
            self.restore_gaps = gaps[:4]
            scanned = 0
            for entry, _ in sorted(sources, key=lambda v: v[0]['created_at'], reverse=True)[:16]:
                with self.evidence.lock, self.evidence._db(entry) as db:
                    rows = db.execute('SELECT source,'+_sql_text('data', 32768)+' AS data FROM records WHERE source IN (?,?) ORDER BY id DESC LIMIT 257',
                                      (REVIEW_SOURCE, FEEDBACK_SOURCE)).fetchall()
                for row in rows[:256]:
                    scanned += 1
                    if type(row['data']) is not str:
                        continue
                    data = json.loads(row['data'])
                    if type(data) is not dict:
                        continue
                    key = data.get('finding_id')
                    if not isinstance(key, str) or not IDENTIFIER.fullmatch(key):
                        continue
                    if row['source'] == REVIEW_SOURCE and key not in self.reviews:
                        if type(data.get('analysis')) is not dict:
                            continue
                        if data['analysis'].get('state') == 'running':
                            data = dict(data, analysis=dict(data['analysis'], state='failed',
                                explanation=None, citations=[], references=[],
                                message='The previous HUD stopped before a verified review outcome was saved. Request a fresh review.'))
                        self.reviews[key] = data
                    elif row['source'] == FEEDBACK_SOURCE and key not in self.feedback:
                        self.feedback[key] = data
                    if scanned >= 512:
                        break
                if scanned >= 512:
                    break
            while len(self.reviews) > MAX_REVIEWS:
                self.reviews.popitem()
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
            self.restore_gaps.append('Some saved selected-finding reviews were unavailable.')

    def _settings_identity(self):
        return digest(asdict(self.configuration.settings.ai))

    def _record(self, summary, facts, dependencies, gaps):
        facts = dict(facts, coverage=[_text(g, 180) for g in gaps[:2]])
        facts = _facts(facts)
        identity = digest(dict(id=summary['id'], facts=facts, evidence_refs=summary['evidence_refs']))
        with self.lock:
            feedback = self.feedback.get(summary['id'])
        if feedback and feedback.get('context_sha256') == identity:
            summary['review_state'] = feedback['choice']
        return dict(finding=summary, facts=facts, context_sha256=identity,
                    evidence_refs=summary['evidence_refs'], gaps=list(dict.fromkeys(gaps))[:8],
                    source_segments=sorted(set(dependencies)), source_start=summary['observed_at'])

    def _packet(self, segment, detection, event, *, compacted=False, receipt=None):
        rule = _text(detection.get('rule_id'), 64)
        finding_id = _number(detection.get('id'))
        event_id = _number(event.get('id'))
        if not finding_id or not event_id:
            raise ValueError('Invalid finding linkage')
        observed = utc(epoch(detection['detected_at']))
        severity = str(detection.get('severity', '')).lower()
        severity = severity if severity in SEVERITIES else 'unknown'
        evidence = detection.get('evidence_json', {})
        if type(evidence) is str:
            if len(evidence.encode()) > 32768:
                raise ValueError('Recorded finding details exceed the read bound')
            evidence = json.loads(evidence, object_pairs_hook=ai_provider._strict_pairs)
        evidence = _bounded(evidence)
        source, destination = _address(event.get('src_ip')), _address(event.get('dst_ip'))
        gaps = ['Detector version is not recorded; current settings do not establish historical thresholds.',
                'One linked record is not the detector’s complete evaluation window.']
        if not evidence:
            gaps.append('No recorded detector measurement or threshold is available.')
        facts = dict(rule=rule, observed_at=observed, event_observed_at=utc(epoch(event['observed_at'])),
                     src_ip=source, dst_ip=destination, src_port=_number(event.get('src_port'), 65535),
                     dst_port=_number(event.get('dst_port'), 65535), protocol=_text(event.get('protocol'), 32),
                     byte_count=_number(event.get('byte_count')), recorded_evidence=evidence)
        if receipt:
            facts['ingestion'] = {k: receipt.get(k) for k in ('source', 'status', 'termination_reason')}
        role = 'Recorded fixed-rule detection' + (' preserved through compaction' if compacted else '')
        if receipt and receipt.get('source') == 'jsonl':
            role += '; JSONL provenance is operator-declared'
        summary = dict(id=f'detector:{segment}:{finding_id}', kind='detector', source='MEGALODON detector',
                       source_role=role,
                       title=rule.replace('_', ' ').title(), severity=severity, severity_basis='Recorded detector severity',
                       observed_at=observed, subject=source, summary='Recorded '+rule+' activity requires evidence review; intent is unknown.',
                       review_state='unreviewed', evidence_refs=[f'{segment}:finding:{finding_id}', f'{segment}:{event_id}'])
        return self._record(summary, facts, [segment], gaps)

    def _core(self, entry, start, end, cap, deadline, *, finding_id=None):
        # Closed SQL keeps qualification and finding/event/run linkage in one
        # statement. Packet volume cannot push detections out of the read page.
        query = f'''SELECT d.id,d.event_id,{_sql_text('d.detected_at', 40)} AS detected_at,
                   {_sql_text('d.rule_id', 64)} AS rule_id,{_sql_text('d.severity', 8)} AS severity,
                   CASE WHEN length(CAST(d.evidence_json AS BLOB))<=32768 THEN d.evidence_json ELSE NULL END AS evidence_json,
                   {_sql_text('e.observed_at', 40)} AS event_observed_at,
                   {_sql_text('e.src_ip', 45)} AS src_ip,{_sql_text('e.dst_ip', 45)} AS dst_ip,e.src_port,e.dst_port,
                   {_sql_text('e.protocol', 32)} AS protocol,e.byte_count,
                   {_sql_text('r.source', 12)} AS run_source,{_sql_text('r.status', 24)} AS run_status,
                   {_sql_text('r.termination_reason', 28)} AS termination_reason
                   FROM detections d JOIN events e ON e.id=d.event_id
                   JOIN ingestion_run_events l ON l.event_id=e.id JOIN ingestion_runs r ON r.id=l.run_id
                   WHERE ''' + QUALIFIED_RUN_SQL + ''' AND julianday(d.detected_at)>=julianday(?) AND julianday(d.detected_at)<=julianday(?)
                   ORDER BY d.id DESC LIMIT ?'''
        if finding_id is not None:
            query = query.replace('ORDER BY d.id DESC', 'AND d.id=? ORDER BY d.id DESC')
        stamp = lambda v: datetime.fromtimestamp(v, timezone.utc).isoformat()
        parameters = (stamp(start), stamp(end), *(() if finding_id is None else (finding_id,)), cap+1)
        with self.evidence.lock, self.evidence._db(entry) as db:
            db.set_progress_handler(lambda: 1 if self.stop_event.is_set() or time.monotonic() > deadline else 0, 10000)
            try:
                rows = db.execute(query, parameters).fetchall()
            finally:
                db.set_progress_handler(None, 0)
        result, invalid = [], 0
        for raw in rows[:cap]:
            try:
                row = dict(raw)
                event = dict(row, id=row['event_id'], observed_at=row['event_observed_at'])
                result.append(self._packet(entry['id'], row, event,
                    receipt=dict(source=row['run_source'], status=row['run_status'], termination_reason=row['termination_reason'])))
            except (ValueError, KeyError, TypeError):
                invalid += 1
        return result, len(rows) > cap, len(rows[:cap]), invalid

    def _generic(self, entry, maximum, start, end, cap, deadline, *, record_id=None, finding_id=None):
        if entry['category'] == 'packet_rollups':
            # The shared reader verifies receipts/compaction totals before a
            # preserved finding is admitted, including older compact formats.
            if maximum is None:
                with self.evidence.lock, self.evidence._db(entry) as db:
                    maximum = db.execute('SELECT MAX(id) FROM records').fetchone()[0] or 0
            pages = self._pages(entry, maximum, start, end, page_size=1)
            try:
                next(pages, None)
            finally:
                pages.close()
        with self.evidence.lock, self.evidence._db(entry) as db:
            source_clause = "AND source='preserved-packet-finding'" if entry['category'] == 'packet_rollups' else ''
            parameters = (utc(start), utc(end))
            if record_id is not None:
                source_clause += ' AND id=?'
                parameters += (record_id,)
            if finding_id is not None:
                source_clause += " AND CASE WHEN typeof(data)='text' AND length(CAST(data AS BLOB))<=32768 THEN CASE WHEN json_valid(data) THEN json_extract(data,'$.original_finding_id') ELSE NULL END ELSE NULL END=?"
                parameters += (finding_id,)
            if time.monotonic() > deadline or self.stop_event.is_set():
                raise ValueError('Selected finding read exceeded its deadline')
            db.set_progress_handler(lambda: 1 if self.stop_event.is_set() or time.monotonic() > deadline else 0, 10000)
            try:
                rows = db.execute('SELECT id,'+_sql_text('observed_at', 40)+' AS observed_at,'+_sql_text('source', 96)+' AS source,CASE WHEN length(CAST(data AS BLOB))<=32768 THEN data ELSE NULL END AS data FROM records WHERE observed_at>=? AND observed_at<=? '
                                  + source_clause + ' ORDER BY id DESC LIMIT ?', (*parameters, cap+1)).fetchall()
            finally:
                db.set_progress_handler(None, 0)
        result, invalid = [], 0
        for row in rows[:cap]:
            try:
                if type(row['data']) is not str or len(row['data'].encode()) > 32768:
                    raise ValueError('Recorded finding details exceed the read bound')
                data = json.loads(row['data'], object_pairs_hook=ai_provider._strict_pairs)
                if type(data) is not dict:
                    raise ValueError('Invalid source record')
                if entry['category'] == 'packet_rollups':
                    if (data.get('kind') != 'finding_v1' or data.get('source_segment') != entry.get('source_segment')
                            or type(data.get('original_finding_id')) is not int
                            or data.get('original_finding_id') != data['detection'].get('id')
                            or data['detection'].get('event_id') != data['event'].get('id')
                            or data.get('original_reference') != data['source_segment']+':'+str(data['event'].get('id'))):
                        raise ValueError('Preserved finding linkage is invalid')
                    result.append(self._packet(data['source_segment'], data['detection'], data['event'], compacted=True))
                else:
                    result.append(self._sensor_record(entry, row, data))
            except (ValueError, TypeError, KeyError):
                invalid += 1
                continue
        return result, len(rows) > cap, len(rows[:cap]), invalid

    def _sensor_record(self, entry, row, data):
        severity = data.get('severity')
        level = {1: 'high', 2: 'medium', 3: 'low', 4: 'low'}.get(severity, 'unknown') if type(severity) is int else 'unknown'
        observed = utc(epoch(row['observed_at']))
        source, destination = _address(data.get('src_ip')), _address(data.get('dst_ip'))
        summary = dict(id=f"sensor:{entry['id']}:{row['id']}", kind='sensor', source=_text(row['source'], 96),
            source_role='Separate sensor alert; not a MEGALODON detector finding', title=_text(data.get('signature'), 256, 'Recorded sensor alert'),
            severity=level, severity_basis='Sensor severity '+str(severity)+'; 1 high, 2 medium, 3–4 low; not an incident risk score.',
            observed_at=observed, subject=source, summary='A sensor reported this alert; compare its recorded metadata with expected activity.',
            review_state='unreviewed', evidence_refs=[f"{entry['id']}:{row['id']}"])
        facts = dict(rule=str(data['signature_id']) if _number(data.get('signature_id')) is not None else 'Sensor signature', signature=summary['title'], observed_at=observed,
            src_ip=source, dst_ip=destination, src_port=_number(data.get('src_port'), 65535), dst_port=_number(data.get('dst_port'), 65535),
            protocol=_text(data.get('protocol'), 32), sensor_severity=severity if type(severity) is int else None,
            observed_service_hint=_text(data.get('app_proto'), 40, 'Not recorded'))
        return self._record(summary, facts, [entry['id']], ['A sensor alert is evidence to review, not proof of compromise.'])

    def _patterns(self, start, end, *, identifier=None):
        result = []
        if self.intelligence is None:
            return result
        with self.intelligence.lock:
            values = ([deepcopy(self.intelligence.reviews[identifier])] if identifier in self.intelligence.reviews else []) if identifier is not None else deepcopy(list(self.intelligence.reviews.values())[:1024])
            feedback = dict(getattr(self.intelligence, 'feedback', {}))
        available = self._available()
        for item in values[:1024]:
            if item.get('endpoint_context') or not self.intelligence._valid(item, available):
                continue  # Endpoint summaries are not selected-finding analyses.
            observed = epoch(item['end'])
            if not start <= observed <= end:
                continue
            identifier = item.get('id')
            if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{32}', identifier):
                continue
            summary = dict(id='pattern:'+identifier, kind='pattern', source=_text(item.get('sensor'), 96),
                source_role='Review-only measured pattern; not a detector finding', title=_text(item.get('rule'), 64).replace('_', ' ').title(),
                severity='unknown', severity_basis='This pattern has no recorded incident severity.', observed_at=utc(observed),
                subject=_address(item.get('device')), summary=_text(item.get('what_happened'), 240),
                review_state={'Expected activity': 'expected', 'Investigate': 'investigate', 'Incorrect match': 'incorrect'}.get(feedback.get(identifier), 'unreviewed'),
                evidence_refs=[_text(v, 120) for v in item.get('evidence_refs', [])[:8]])
            facts = dict(rule=_text(item.get('rule'), 64), device=summary['subject'],
                start=_text(item.get('start'), 40), end=summary['observed_at'], measurement=_text(item.get('measurement'), 96),
                sensor=_text(item.get('sensor'), 96), what_happened=summary['summary'], recorded_evidence=_bounded(item.get('facts', {})))
            gaps = list(item.get('missing_information', [])[:4])
            if item.get('facts', {}).get('preserved_finding'):
                gaps.insert(0, 'Only a preserved finding reference is recorded; original detector counts, thresholds and window are unavailable.')
            record = self._record(summary, facts, item.get('source_segments', []), gaps)
            record['source_start'] = item.get('source_start', item['start'])
            result.append(record)
        return result

    def _collect(self, start, end, kind='all', *, fresh=False):
        if not self.evidence.enabled:
            return [], ['Managed evidence storage is not enabled.'], False
        key = (start, end, kind)
        with self.lock:
            cached = self._read_cache
        available = self._available()
        if (not fresh and cached and cached['key'] == key and time.monotonic()-cached['at'] < 2
                and all(self._valid(record, available) for record in cached['records'])):
            return deepcopy(cached['records']), list(cached['gaps']), cached['truncated']
        categories = {'packets', 'packet_rollups', 'findings'} if kind == 'all' else {'packets', 'packet_rollups'} if kind == 'detector' else {'findings'} if kind == 'sensor' else set()
        records, gaps, scanned, truncated = [], list(self.restore_gaps), 0, False
        deadline = time.monotonic()+4
        if categories:
            sources, missing = self._sources(start, end, categories=categories, watermarks=False)
            gaps.extend(missing)
            sources.sort(key=lambda row: row[0].get('last_at') or row[0]['created_at'], reverse=True)
            if len(sources) > MAX_SEGMENTS:
                gaps.append('The bounded finding read visits at most 128 source segments. Narrow the time range.'); truncated = True
            for entry, maximum in sources[:MAX_SEGMENTS]:
                if time.monotonic() > deadline or self.stop_event.is_set():
                    gaps.append('The bounded finding read paused. Narrow the time range to inspect additional sources.'); truncated = True; break
                if entry['id'] not in available:
                    gaps.append('An expired source segment was excluded.'); truncated = True; continue
                cap = min(512, MAX_CANDIDATES-scanned)
                if cap <= 0:
                    gaps.append('The 4,096 finding-candidate work limit was reached. Narrow the time range.'); truncated = True; break
                try:
                    rows, limited, count, invalid = self._core(entry, start, end, cap, deadline) if entry['kind'] == 'core' else self._generic(entry, maximum, start, end, cap, deadline)
                    records.extend(rows); scanned += count
                    if invalid:
                        gaps.append('Some invalid or oversized finding records were withheld; valid records remain shown.'); truncated = True
                    if limited:
                        gaps.append('One source exceeded the 512-finding page read limit. Narrow the time range.'); truncated = True
                except (OSError, ValueError, sqlite3.Error, KeyError, TypeError):
                    gaps.append('A source segment or finding was expired, unqualified or unreadable.'); truncated = True
        if kind in {'all', 'pattern'}:
            records.extend(self._patterns(start, end))
        unique = {row['finding']['id']: row for row in records}
        ordered = sorted(unique.values(), key=lambda row: (SEVERITIES.index(row['finding']['severity']), -epoch(row['finding']['observed_at']), row['finding']['id']))
        gaps = list(dict.fromkeys(gaps))[:12]
        with self.lock:
            self._read_cache = dict(key=key, at=time.monotonic(), records=deepcopy(ordered), gaps=gaps, truncated=truncated)
        return ordered, gaps, truncated

    def _resolve(self, identifier):
        if type(identifier) is not str or not IDENTIFIER.fullmatch(identifier):
            raise ValueError('Choose a qualified finding')
        # A selected immutable ID is not a list query. Resolve its exact catalog
        # source before every listing cap, then query only its qualified row.
        first, last = self.clock()-self.evidence.retention_days*86400, self.clock()+1
        deadline = time.monotonic()+4
        kind, source, *number = identifier.split(':')
        if number and int(number[0]) > 2**63-1:
            raise ValueError('Selected finding ID exceeds the storage bound')
        if kind == 'pattern':
            rows = self._patterns(first, last, identifier=source)
        else:
            available = self._available()
            with self.evidence.lock:
                entries = deepcopy(self.evidence._catalog['entries'])
            original = next((e for e in entries if e['id'] == source and e['id'] in available
                             and e['state'] in {'open', 'closed'}), None)
            entry = original
            if kind == 'detector':
                compacted = [e for e in entries if e['category'] == 'packet_rollups' and e['state'] == 'closed'
                    and e.get('source_segment') == source and e['id'] in available
                    and (original is None or original.get('compacted_to') == e['id'])]
                if len(compacted) > 1:
                    raise ValueError('Preserved finding source is ambiguous')
                entry = compacted[0] if compacted else original
            if entry is None or not self.evidence.derived_available(entry):
                raise ValueError('Selected evidence source expired or is unavailable')
            if kind == 'detector' and entry['kind'] == 'core' and entry['category'] == 'packets':
                rows, limited, _, invalid = self._core(entry, first, last, 1, deadline, finding_id=int(number[0]))
            elif kind == 'detector' and entry['category'] == 'packet_rollups':
                rows, limited, _, invalid = self._generic(entry, None, first, last, 1, deadline, finding_id=int(number[0]))
            elif kind == 'sensor' and entry['category'] == 'findings' and entry['kind'] == 'generic':
                rows, limited, _, invalid = self._generic(entry, None, first, last, 1, deadline, record_id=int(number[0]))
            else:
                raise ValueError('Selected finding source role does not match its ID')
            if limited or invalid:
                raise ValueError('Selected finding linkage is ambiguous or invalid')
        record = next((row for row in rows if row['finding']['id'] == identifier), None)
        if record is None or time.monotonic() > deadline or not self._valid(record):
            raise ValueError('Selected evidence expired or is outside the bounded retained read')
        return record

    def _available(self):
        with self.evidence.lock:
            entries = [e for e in self.evidence._catalog['entries'] if e['state'] in {'open', 'closed'}
                       and epoch(e.get('first_at') or e['created_at'])+self.evidence.retention_days*86400 > self.clock()]
            return self.evidence.available_sources(entries)

    def _valid(self, record, sources=None):
        try:
            if sources is None:
                sources = self._available()
            return (self.evidence.enabled and bool(record['source_segments'])
                    and set(record['source_segments']) <= sources
                    and self.clock()-self.evidence.retention_days*86400 <= epoch(record['source_start']) <= self.clock()+60)
        except (ValueError, KeyError, TypeError):
            return False

    def _analysis(self, record):
        with self.lock:
            saved = deepcopy(self.reviews.get(record['finding']['id']))
            job = dict(self.job)
        identity = record['context_sha256']
        empty = dict(state='not_requested', explanation=None, alternative=None, missing=None, citations=[], references=[],
                     model=None, model_digest=None, context_sha256=identity, message='Ask the selected local model to review these exact facts.')
        if job['finding_id'] == record['finding']['id'] and job['state'] == 'running':
            return dict(empty, state='running', message=job['message'])
        if not saved:
            return empty
        if (saved.get('context_sha256') != identity or saved.get('settings_identity') != self._settings_identity()
                or not self._valid(saved)):
            return dict(empty, state='invalidated', message='Evidence or model selection changed. Request a fresh review.')
        try:
            current_refs = self._references(saved['reference_rule'])
            if saved.get('references_identity') != digest(current_refs):
                raise ValueError('References changed')
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
            return dict(empty, state='invalidated', message='Reference evidence changed. Request a fresh review.')
        analysis = saved.get('analysis')
        if type(analysis) is not dict or analysis.get('state') not in {'ready', 'failed', 'cancelled'}:
            return dict(empty, state='invalidated', message='The saved review could not be validated. Request a fresh review.')
        if analysis.get('state') == 'ready' and analysis.get('explanation_contract') != SELECTED_EXPLANATION_CONTRACT:
            return dict(empty, state='invalidated', message='The selected-evidence review contract changed. Request a fresh review.')
        allowed = {record['finding']['id'], *(r['id'] for r in current_refs)}
        citations = analysis.get('citations', [])
        if (type(citations) is not list or len(citations) > 4 or any(type(v) is not str or v not in allowed for v in citations)
                or (analysis['state'] == 'ready' and record['finding']['id'] not in citations)):
            return dict(empty, state='invalidated', message='Saved evidence citations are unavailable. Request a fresh review.')
        projected = {k: analysis.get(k) for k in ('state', 'model', 'model_digest', 'workflow', 'created_at', 'error_code') if k in analysis}
        for key, maximum in [('explanation', 400), ('alternative', 240), ('missing', 240), ('message', 240)]:
            projected[key] = _text(analysis.get(key), maximum, '') if analysis.get(key) is not None else None
        projected.update(citations=citations, references=[r for r in current_refs if r['id'] in citations],
                         action_status='not_attempted', approval_required=True, context_sha256=identity)
        return projected

    def _references(self, rule):
        values = self.knowledge.for_pattern(rule)[:1] if self.knowledge is not None else []
        return [dict(r, excerpt=_text(r.get('excerpt'), 160, '')) for r in values]

    def impact(self, record):
        facts = record['facts']
        addresses = list(dict.fromkeys(v for v in [facts.get('src_ip'), facts.get('dst_ip'), record['finding']['subject']] if _address(v)))[:2]
        targets = []
        for address in addresses:
            eligible, reason, observed = False, 'Current response eligibility is unavailable.', {}
            try:
                observed = self.defense._target(address)
                eligible, reason = True, 'Current observed public peer passes the existing local containment guards.'
            except ValueError as exc:
                reason = str(exc)[:240]
            except (OSError, TypeError, KeyError):
                pass
            targets.append(dict(ip=address, eligible=eligible, reason=reason,
                observed_ports=[{k: p.get(k) for k in ('protocol', 'port', 'hint')} for p in observed.get('ports', [])[:12]],
                observed_services=[_bounded(v) for v in observed.get('services', [])[:8]],
                observed_peers=[v for v in addresses if v != address]))
        return dict(effect='Drop communication to and from one eligible public IP on this PC only.', duration_seconds=300, preview_seconds=60,
            caution=['All applications using the selected address can lose connectivity, including shared cloud services.',
                     'A finding or AI recommendation is not proof of compromise. Review expected activity before acting.',
                     'OS authorization is still required. Automatic kernel expiry or Release removes this managed block.'],
            unknowns=['Complete application dependencies and service ownership are unknown. Selected retained peer observations may be historical.',
                      'Impact on remote devices and traffic outside this PC is unknown. Ports and labels do not identify applications.'], targets=targets)

    def _cursor(self, value):
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip('=') + '.' + hmac.new(self._cursor_key, raw, hashlib.sha256).hexdigest()

    def _decode_cursor(self, value):
        try:
            if type(value) is not str or len(value) > 1024:
                raise ValueError()
            encoded, signature = value.split('.')
            raw = base64.urlsafe_b64decode(encoded+'='*((-len(encoded)) % 4))
            if not hmac.compare_digest(signature, hmac.new(self._cursor_key, raw, hashlib.sha256).hexdigest()):
                raise ValueError()
            result = json.loads(raw)
            if set(result) != {'scope', 'offset', 'listing', 'expires'} or type(result['offset']) is not int or not 0 <= result['offset'] <= 8192 or not self.clock() < result['expires'] <= self.clock()+301:
                raise ValueError()
            return result
        except (ValueError, TypeError, KeyError):
            raise ValueError('Finding page expired or changed. Restart this time range.') from None

    def snapshot(self, **query):
        if set(query)-{'start', 'end', 'source', 'severity', 'limit', 'cursor', 'selected'}:
            raise ValueError('Unsupported findings query')
        cursor = self._decode_cursor(query['cursor']) if query.get('cursor') else None
        now = self.clock()
        if ('start' in query) != ('end' in query):
            raise ValueError('Choose both time boundaries')
        start = epoch(query['start']) if 'start' in query else epoch(cursor['scope']['start']) if cursor else now-86400
        end = epoch(query['end']) if 'end' in query else epoch(cursor['scope']['end']) if cursor else now
        if start > end or end-start > 31*86400 or end > now+60:
            raise ValueError('Choose an ordered UTC range of at most 31 days')
        source = query.get('source', cursor['scope']['source'] if cursor else 'all')
        severity = query.get('severity', cursor['scope']['severity'] if cursor else 'all')
        if source not in KINDS or severity not in {'all', *SEVERITIES}:
            raise ValueError('Choose a known source and severity')
        limit = query.get('limit', '25')
        if type(limit) is not str or not re.fullmatch(r'[1-9][0-9]?', limit) or not 1 <= int(limit) <= 50:
            raise ValueError('Choose 1–50 findings per page')
        limit = int(limit)
        scope = dict(start=utc(start), end=utc(end), source=source, severity=severity)
        if cursor and scope != cursor['scope']:
            raise ValueError('Finding page scope changed. Restart this time range.')
        records, gaps, truncated = self._collect(start, end, source)
        candidate_count = len(records)
        if severity != 'all':
            records = [r for r in records if r['finding']['severity'] == severity]
        listing = digest([[r['finding']['id'], r['context_sha256']] for r in records])
        if cursor and cursor['listing'] != listing:
            raise ValueError('Finding evidence changed. Restart this time range.')
        offset = cursor['offset'] if cursor else 0
        next_cursor = self._cursor(dict(scope=scope, offset=offset+limit, listing=listing, expires=now+300)) if offset+limit < len(records) else None
        selected, message = None, None
        if query.get('selected'):
            if not IDENTIFIER.fullmatch(query['selected']):
                raise ValueError('Choose a qualified selected finding')
            row = next((r for r in records if r['finding']['id'] == query['selected']), None)
            if row and self._valid(row):
                selected = {k: deepcopy(row[k]) for k in ('finding', 'facts', 'context_sha256', 'evidence_refs', 'gaps')}
                selected.update(analysis=self._analysis(row), impact=self.impact(row))
            else:
                message = 'The selected finding is no longer in this retained scope. Select a current row.'
        self._bind_completed_preview()
        state = 'unavailable' if not self.evidence.enabled else 'partial' if truncated or gaps else 'available' if records else 'empty'
        with self.lock:
            job = dict(self.job)
        settings = self.configuration.settings.ai
        return dict(schema=SCHEMA, generated_at=utc(now), state=state, token=self.token, scope=scope,
            model=dict(name=settings.model, digest=settings.model_digest, settings_sha256=self._settings_identity()),
            items=[deepcopy(r['finding']) for r in records[offset:offset+limit]],
            page=dict(limit=limit, returned=len(records[offset:offset+limit]), next_cursor=next_cursor,
                      candidate_count=candidate_count, truncated=bool(truncated or next_cursor)), gaps=gaps,
            selected=selected, selection_message=message, job=job, defense=self.defense.snapshot(include_token=True))

    def _persist(self, record, source, data):
        if not self._valid(record):
            raise ValueError('Selected evidence expired before saving the review')
        payload = dict(data, finding_id=record['finding']['id'], context_sha256=record['context_sha256'],
                       source_segments=record['source_segments'], source_start=record['source_start'])
        if self.evidence.append_records('intelligence', [dict(observed_at=record['source_start'], source=source, data=payload)]) != 1:
            raise ValueError('Selected review could not be retained')
        return payload

    def _binding(self, body):
        record = self._resolve(body['finding_id'])
        if not hmac.compare_digest(record['context_sha256'], body['context_sha256']):
            raise ValueError('Selected evidence changed. Refresh before acting.')
        return record

    def _bind_completed_preview(self):
        with self.lock:
            pending = deepcopy(self.pending_plan)
        if not pending:
            return
        job = self.defense.snapshot()['job']
        if job.get('request_id') != pending['request_id']:
            with self.lock:
                self.pending_plan = None
            return
        if job['state'] == 'running':
            return
        if job['state'] == 'finished' and job.get('action') == 'plan_containment':
            plan = job.get('result') or {}
            if plan.get('ip') == pending['target_ip'] and re.fullmatch(r'[a-f0-9]{32}', str(plan.get('id', ''))):
                with self.lock:
                    self.plan_bindings[plan['id']] = dict(pending, expires_at=plan['expires_at'])
                    self.plan_bindings = {k: v for k, v in self.plan_bindings.items() if epoch(v['expires_at']) > self.clock()}
        with self.lock:
            self.pending_plan = None

    def _defense_start(self, body):
        from .defense import DefenseBusy
        try:
            return self.defense.start(body)
        except DefenseBusy as exc:
            raise FindingsBusy('A local response workflow is already running') from exc

    def action(self, body):
        body = validate_action(body)
        if self.stop_event.is_set():
            raise ValueError('The selected-finding service is closing')
        action = body['action']
        if action == 'cancel':
            with self.lock:
                self.cancel_event.set()
                if self.job['state'] == 'running':
                    ai_provider.cancel_current(owner=self.job['id'])
        elif action == 'analyze':
            record = self._binding(body)
            with self.lock:
                if self.job['state'] == 'running':
                    raise FindingsBusy('A selected-finding review is already running')
                settings = self.configuration.settings.ai
                rule = record['facts'].get('rule')
                rule = rule if rule in CONTEXT else 'OBSERVED_ACTIVITY'
                opening = dict(state='running', explanation=None, alternative=None, missing=None, citations=[], references=[],
                    model=settings.model, model_digest=settings.model_digest, created_at=utc(self.clock()),
                    message='A selected-finding review was requested; its outcome is not yet recorded.',
                    action_status='not_attempted', approval_required=True)
                self.reviews[body['finding_id']] = self._persist(record, REVIEW_SOURCE,
                    dict(analysis=opening, settings_identity=self._settings_identity(), reference_rule=rule,
                         references_identity=digest(self._references(rule))))
                self.cancel_event.clear()
                self.job = dict(id='finding-'+secrets.token_hex(16), state='running', finding_id=body['finding_id'],
                                message='Reviewing the selected retained facts with your saved local model.')
                self.worker = Thread(target=self._explain, args=(record, self.job['id']), name='megalodon-finding-review', daemon=True)
                try:
                    self.worker.start()
                except RuntimeError:
                    self.job.update(state='failed', message='The selected review worker could not start. No model outcome is assumed.')
                    raise ValueError('Selected review worker unavailable') from None
        elif action == 'feedback':
            record = self._binding(body)
            saved = self._persist(record, FEEDBACK_SOURCE, dict(choice=body['choice']))
            with self.lock:
                self.feedback[body['finding_id']] = saved
                while len(self.feedback) > MAX_REVIEWS:
                    self.feedback.pop(next(iter(self.feedback)))
                self._read_cache = None
        elif action == 'plan_containment':
            settings_identity = self._settings_identity()
            record = self._binding(body)
            target = next((r for r in self.impact(record)['targets'] if r['ip'] == body['target_ip']), None)
            if target is None or not target['eligible']:
                raise ValueError('This selected target does not pass current containment guards')
            response = self._defense_start(dict(action='plan_containment', ip=target['ip']))
            with self.lock:
                self.pending_plan = dict(finding_id=body['finding_id'], context_sha256=body['context_sha256'],
                    target_ip=target['ip'], request_id=response['job']['request_id'], settings_identity=settings_identity)
            self._bind_completed_preview()
        elif action == 'apply_containment':
            self._bind_completed_preview()
            with self.lock:
                binding = deepcopy(self.plan_bindings.get(body['plan_id']))
            if not binding or epoch(binding['expires_at']) <= self.clock():
                raise ValueError('Selected-finding impact preview expired. Create a fresh preview.')
            if binding.get('settings_identity') != self._settings_identity():
                raise ValueError('Saved model settings changed. Create a fresh impact preview.')
            record = self._binding(binding)
            self.defense._target(binding['target_ip'])
            self._defense_start(dict(action='apply_containment', plan_id=body['plan_id']))
            with self.lock:
                self.plan_bindings.pop(body['plan_id'], None)
        else:
            self._defense_start(dict(action='release_containment', ip=body['ip']))
        with self.lock:
            job = dict(self.job)
        return dict(schema='megalodon-findings-action-v1', job=job, defense=self.defense.snapshot(include_token=True))

    def _explain(self, record, owner):
        settings = self.configuration.settings.ai
        settings_identity = digest(asdict(settings))
        rule = record['facts'].get('rule')
        rule = rule if rule in CONTEXT else 'OBSERVED_ACTIVITY'
        references = []
        try:
            current = self._resolve(record['finding']['id'])
            if self.cancel_event.is_set() or current['context_sha256'] != record['context_sha256']:
                raise ValueError('Selected evidence changed')
            references = self._references(rule)
            item = dict(id=record['finding']['id'], rule=rule, device=record['finding']['subject'] or 'Unknown',
                        measurement='Selected finding evidence', sensor=record['finding']['source'], endpoint_context=True,
                        selected_finding=True, facts=record['facts'], missing_information=record['gaps'])
            result = explain(item, references, settings, model=self.model, owner=owner)
            current = self._resolve(record['finding']['id'])
            if self.cancel_event.is_set() or self.stop_event.is_set():
                raise ValueError('Selected review cancelled')
            if (current['context_sha256'] != record['context_sha256'] or self.configuration.settings.ai != settings
                    or references != self._references(rule)):
                raise ValueError('Selected evidence or model changed')
            result['message'] = 'Local AI interpretation of this selected evidence. No action was executed.'
        except (ValueError, OSError, RuntimeError, sqlite3.Error, TypeError, KeyError) as exc:
            result = dict(state='cancelled' if self.cancel_event.is_set() else 'failed', explanation=None, alternative=None, missing=None,
                          citations=[], references=[], model=settings.model, model_digest=settings.model_digest,
                          message='Review cancelled; recorded facts remain available.' if self.cancel_event.is_set() else
                                  'The selected local AI could not complete a verified review. Recorded facts remain available.',
                          error_code=getattr(exc, 'code', 'REVIEW_UNAVAILABLE'), action_status='not_attempted', approval_required=True)
        result['created_at'] = utc(self.clock())
        try:
            if self.configuration.settings.ai != settings or self._resolve(record['finding']['id'])['context_sha256'] != record['context_sha256']:
                raise ValueError('Selected context changed')
            saved = self._persist(record, REVIEW_SOURCE, dict(analysis=result, settings_identity=settings_identity,
                reference_rule=rule, references_identity=digest(references)))
            with self.lock:
                self.reviews[record['finding']['id']] = saved
                self.reviews.move_to_end(record['finding']['id'])
                while len(self.reviews) > MAX_REVIEWS:
                    self.reviews.popitem(last=False)
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
            result = dict(result, state='failed', message='Evidence or model changed, or the review could not be saved. Refresh the selected facts.')
        with self.lock:
            if self.job['id'] == owner:
                self.job.update(state=result['state'], message=result['message'])

    def close(self):
        self.stop_event.set(); self.cancel_event.set()
        with self.lock:
            if self.job['state'] == 'running':
                ai_provider.cancel_current(owner=self.job['id'])
        if self.worker:
            self.worker.join(3)
            if self.worker.is_alive():
                with self.lock:
                    self.job['message'] = 'Shutdown cancellation requested; the review worker is still finishing. No completed outcome is assumed.'
