"""Bounded, local visual reports over retained evidence; no external requests.

Reports are immutable aggregates saved as bounded managed records. Their source
clock, not generation time, controls expiry. The scheduler lives with the HUD.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import csv
import hashlib
import html
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import Event, RLock, Thread
import time
from uuid import uuid4
from zoneinfo import ZoneInfo

from .evidence_storage import epoch, utc
from .local_install import _atomic_write, _regular_owned_file

SCHEMA = 'megalodon-reports-v1'
MAX_RECORDS = 20_000_000
MAX_SECONDS = 180
MAX_SEGMENTS = 2048
MAX_BODY = 8 * 1024 * 1024
MAX_FINDINGS = 5000
MAX_KEYS = 4096
MAX_FLOWS = 100_000
CHUNK_BYTES = 16 * 1024
REPORT_CSS = """
:root{color-scheme:dark;--ink:#e6f2f5;--muted:#aec5ce;--line:#31505e;--cyan:#81e5de;--gold:#f0c575}
*{box-sizing:border-box}body{margin:0;background:#0a1922;color:var(--ink);font:15px/1.6 system-ui,sans-serif}
main{max-width:1440px;margin:auto;padding:30px}h1{font-size:clamp(28px,4vw,42px);line-height:1.12;margin:12px 0}h2{font-size:21px;margin:28px 0 10px}h3{font-size:16px;margin:18px 0 8px}p{max-width:90ch}.eyebrow{color:var(--cyan);letter-spacing:.14em;font-size:12px;font-weight:700}.muted,small{color:var(--muted)}.hero{border-top:3px solid var(--cyan);border-bottom:1px solid var(--line);padding:18px 0}.stats{display:flex;gap:30px;flex-wrap:wrap;padding:15px 0}.stat strong{display:block;font-size:27px;color:var(--cyan)}.notice{border-left:3px solid var(--gold);padding:10px 16px;background:#142b35}.chart{width:100%;height:auto;display:block;margin:12px 0;background:#102832;border-bottom:1px solid var(--line)}.chart-scroll{overflow-x:auto}.chart-scroll:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}.chart-scroll .chart{min-width:640px}.chart-scroll .topology-chart{min-width:960px}.chart-hint{font-size:12px}.chart text{fill:var(--muted);font:12px system-ui}.category-chart{height:auto}.topology-chart{height:auto;min-height:240px}.bar{fill:#65cec7}.line{fill:none;stroke:var(--cyan);stroke-width:2}.send{stroke:var(--gold)}.chart-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}section{min-width:0}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--cyan);font-weight:650}summary{cursor:pointer;padding:10px 0;font-weight:650}details{border-top:1px solid var(--line);margin-top:14px}a{color:var(--cyan)}li{margin:5px 0}.mono{font-family:ui-monospace,monospace;font-size:12px}footer{margin-top:32px;padding-top:16px;border-top:1px solid var(--line)}@media(max-width:1380px){.chart-grid{grid-template-columns:1fr}}@media(max-width:680px){main{padding:18px}.chart-grid{grid-template-columns:1fr}.stats{gap:18px}.chart,.category-chart,.topology-chart{height:auto}table{min-width:480px}}@media print{:root{color-scheme:light;--ink:#12252d;--muted:#425965;--line:#b9c9ce;--cyan:#006d68;--gold:#87601b}body{background:white;color:var(--ink);font-size:11px}main{padding:0;max-width:none}.hero{break-inside:avoid}h1{font-size:28px}h2,h3{break-after:avoid}.chart,.category-chart,.topology-chart{background:#edf7f7;height:auto;min-height:0;break-inside:avoid}.chart-scroll{overflow:visible}.chart-scroll .chart,.chart-scroll .topology-chart{min-width:0;height:auto}.chart-hint{display:none}.notice{background:#f4f5ed}details>*{display:block!important}details>summary{display:block}details::details-content{content-visibility:visible}.scroll{overflow:visible}table{font-size:10px;min-width:0}tr{break-inside:avoid}.chart-grid{display:block}.stat strong{font-size:22px}@page{margin:16mm}}
"""


def local_zone():
    try:
        path = Path('/etc/localtime')
        target = str(path.resolve())
        if '/zoneinfo/' in target:
            return ZoneInfo(target.split('/zoneinfo/', 1)[1])
        with path.open('rb') as stream:
            return ZoneInfo.from_file(stream, key='System local time')
    except (OSError, ValueError):
        return datetime.now().astimezone().tzinfo


def schedule_value(value):
    if type(value) is not dict or set(value) - {'enabled', 'time', 'frequency', 'weekday'}:
        raise ValueError('Choose automatic reports, a time, and daily or weekly.')
    if (type(value.get('enabled')) is not bool or type(value.get('time')) is not str
            or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', value['time'])
            or value.get('frequency') not in {'daily', 'weekly'}
            or type(value.get('weekday', 0)) is not int or not 0 <= value.get('weekday', 0) <= 6):
        raise ValueError('Invalid report schedule.')
    return dict(enabled=value['enabled'], time=value['time'], frequency=value['frequency'], weekday=value.get('weekday', 0))


def latest_slot(schedule, now, zone):
    """First fold for ambiguous local time; forward-normalize nonexistent time."""
    local = datetime.fromtimestamp(now, zone)
    hour, minute = map(int, schedule['time'].split(':'))
    day = local.date()
    if schedule['frequency'] == 'weekly':
        day -= timedelta(days=(day.weekday() - schedule['weekday']) % 7)
    def at(date):
        value = datetime(date.year, date.month, date.day, hour, minute, tzinfo=zone, fold=0)
        return datetime.fromtimestamp(value.timestamp(), zone)
    slot = at(day)
    if slot.timestamp() > now:
        slot = at(day - timedelta(days=7 if schedule['frequency'] == 'weekly' else 1))
    identity = f"{schedule['frequency']}:{schedule['weekday']}:{schedule['time']}:{slot.date().isoformat()}"
    return identity, slot.timestamp()


def _number(value):
    return float(value) if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def _label(value, maximum=256):
    return str(value)[:maximum] if value is not None else 'Unavailable'


def _counter(counter, key, amount=1):
    key = _label(key)
    if key in counter or len(counter) < MAX_KEYS:
        counter[key] += amount
    else:
        counter['Other / grouping limit'] += amount


class Cancelled(Exception):
    pass


from .retained_history import RetainedEvidenceReader


class ReportService(RetainedEvidenceReader):
    def __init__(self, evidence, *, clock=None, monotonic=time.monotonic, zone=None):
        self.evidence = evidence
        self.clock = clock or evidence.clock
        self.monotonic = monotonic
        self._system_zone = zone is None
        self.zone = zone or local_zone()
        self.token = secrets.token_urlsafe(24)
        self.lock = RLock()
        self.stop_event = Event()
        self.cancel_event = Event()
        self._operator_cancel = False
        self.thread = None
        self.worker = None
        self.path = evidence.root / 'report-settings.json'
        self.settings = dict(version=1, schedule=dict(enabled=True, time='09:00', frequency='daily', weekday=0),
                             completed_slot=None, completed_at=0, pending=None, last_error=None)
        if self.path.exists():
            value = json.loads(_regular_owned_file(self.path, maximum=8192))
            if type(value) is not dict or value.get('version') != 1:
                raise ValueError('Report schedule settings need review.')
            value['schedule'] = schedule_value(value['schedule'])
            if type(value.get('completed_at', 0)) not in (int, float) or not math.isfinite(value.get('completed_at', 0)):
                raise ValueError('Report schedule time needs review.')
            self.settings.update(value)
        # The report manifest and completion checkpoint commit atomically. This
        # covers a crash after that commit but before the settings-file rename.
        with evidence.lock:
            done = evidence._catalog.get('checkpoints', {}).get('reports_schedule', {})
            last_done = evidence._catalog.get('checkpoints', {}).get('reports_last_completed', {})
        if done.get('slot') and done.get('at', 0) >= self.settings['completed_at']:
            self.settings.update(completed_slot=done['slot'], completed_at=done['at'], pending=None)
        self.job = dict(id=None, state='idle', progress=0, processed_records=0, error=None, report_id=None)
        prior_job = self.settings.get('last_job')
        if (type(prior_job) is dict and prior_job.get('state') == 'running'
                and prior_job.get('id') not in {done.get('report_id'), last_done.get('report_id')}):
            self.job.update(id=prior_job.get('id'), state='failed', error='A report was interrupted before completion. Make a new report; saved reports are unchanged.')
        self._retry_at = 0

    def _save_settings(self):
        with self.evidence.lock:
            _atomic_write(self.path, json.dumps(self.settings, separators=(',', ':'), allow_nan=False).encode(), 0o600)
            descriptor=os.open(self.evidence.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)

    def configure(self, value):
        parsed = schedule_value(value)
        with self.lock:
            prior = self.settings['schedule']
            self.settings['schedule'] = parsed
            try:self._save_settings()
            except (OSError,ValueError):
                self.settings['schedule'] = prior
                raise
        return self.snapshot()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = Thread(target=self._loop, name='megalodon-reports', daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                self.tick()
            except (OSError, ValueError, sqlite3.Error):
                with self.lock:
                    self.settings['last_error'] = 'Automatic reports could not run; review managed storage.'
            self.stop_event.wait(30)

    def tick(self):
        with self.lock:
            if self._system_zone:self.zone = local_zone()
            schedule = self.settings['schedule']
            if not schedule['enabled'] or not self.evidence.enabled or self.job['state'] == 'running' or self.clock() < self._retry_at:
                return
            identity, stamp = latest_slot(schedule, self.clock(), self.zone)
            if identity in {self.settings['completed_slot'], self.settings.get('cancelled_slot')} or stamp <= self.settings['completed_at']:
                return
            self.settings['pending'] = dict(slot=identity, at=stamp)
            self._save_settings()
            self.create(dict(start=utc(stamp - (7 if schedule['frequency'] == 'weekly' else 1) * 86400), end=utc(stamp)), scheduled=self.settings['pending'])

    def create(self, value, *, scheduled=None):
        if type(value) is not dict or set(value) not in (set(), {'start', 'end'}):
            raise ValueError('Choose a start and end time.')
        start = epoch(value['start']) if value else self.clock() - 86400
        end = epoch(value['end']) if value else self.clock()
        if not start < end <= self.clock() + 60 or end - start > 30 * 86400:
            raise ValueError('Choose an interval up to 30 days ending no later than now.')
        if not self.evidence.enabled:
            raise ValueError('Enable managed storage before making a saved report.')
        with self.lock:
            if self.job['state'] == 'running':
                if ((not value and self.job.get('default_range')) or (self.job.get('start') == utc(start) and self.job.get('end') == utc(end))):
                    return dict(self.job)
                raise ValueError('A report is already being made. Wait or cancel it first.')
            self.cancel_event.clear()
            self._operator_cancel = False
            prior_job = self.job
            prior_setting = self.settings.get('last_job')
            identifier = uuid4().hex
            self.job = dict(id=identifier, state='running', progress=0, processed_records=0, error=None,
                            report_id=None, start=utc(start), end=utc(end), default_range=not value)
            self.settings['last_job'] = dict(self.job)
            try:self._save_settings()
            except (OSError,ValueError):
                self.job = prior_job
                self.settings['last_job'] = prior_setting
                raise
            self.worker = Thread(target=self._run, args=(identifier, start, end, deepcopy(scheduled)), name='megalodon-report-build', daemon=True)
            self.worker.start()
            return dict(self.job)

    def cancel(self):
        with self.lock:
            if self.job['state'] == 'running':
                self._operator_cancel = True
                self.cancel_event.set()
            return dict(self.job)

    def close(self):
        self.stop_event.set()
        self.cancel_event.set()
        for worker in (self.thread, self.worker):
            if worker and worker.is_alive():
                worker.join(timeout=10)
        if self.worker and self.worker.is_alive():
            raise ValueError('Report job is still finishing a bounded evidence read.')

    def _check(self):
        if self.cancel_event.is_set() or self.stop_event.is_set():
            raise Cancelled()

    def _aggregate(self, identifier, start, end):
        sources, gaps = self._sources(start, end)
        sources=[(entry,maximum) for entry,maximum in sources if entry['category'] not in {'baselines','intelligence'}]
        result = dict(schema='megalodon-visual-report-v1', id=identifier, created_at=utc(self.clock()), start=utc(start), end=utc(end),
                      title='Your network report', timezone=str(self.zone), summary=dict(packet_records=0, packet_bytes=0, finding_count=0, resource_samples=0, network_samples=0, response_count=0),
                      packet_protocols=Counter(), endpoints=Counter(), finding_severities=Counter(), findings=[], responses=[], timeline=[0] * 48,
                      resources=[], network=None, source_counts=Counter(), flow_sources=[], coverage={})
        processed = 0
        matched = 0
        first = last = None
        begin = self.monotonic()
        flows = {}
        resource_bins = {}
        response_ids = set()
        finding_overflow = False
        flow_overflow = False
        compacted_records = 0
        compacted_segments = set()
        compacted_edge = False
        bounds_reached = False
        total_rows = max(1, sum(maximum for _, maximum in sources))
        for index, (entry, maximum) in enumerate(sources):
            try:
                for records, scanned in self._pages(entry, maximum, start, end):
                    processed += scanned
                    if processed > MAX_RECORDS or self.monotonic() - begin > MAX_SECONDS:
                        gaps.append('Report work limit reached; the selected interval is only partially aggregated.')
                        bounds_reached = True
                        break
                    for row in records:
                        stamp = epoch(row['observed_at'])
                        first = stamp if first is None else min(first, stamp)
                        last = stamp if last is None else max(last, stamp)
                        matched += 1
                        data, source, category = row['data'], row['source'], row['category']
                        _counter(result['source_counts'], source)
                        if category == 'packets':
                            result['summary']['packet_records'] += 1
                            result['summary']['packet_bytes'] += int(_number(data.get('byte_count')) or 0)
                            result['timeline'][min(47, int((stamp-start)/(end-start)*48))] += 1
                            _counter(result['packet_protocols'], data.get('protocol', 'Unknown'))
                            for key in ('src_ip', 'dst_ip'):
                                _counter(result['endpoints'], data.get(key, 'Unknown'))
                            for finding in data.get('findings', []):
                                result['summary']['finding_count'] += 1
                                _counter(result['finding_severities'], 'MEGALODON / '+_label(finding.get('severity')))
                                if len(result['findings']) < MAX_FINDINGS:
                                    result['findings'].append(dict(id=entry['id']+':finding:'+str(finding['id']), observed_at=row['observed_at'], source='MEGALODON detector', title=_label(finding.get('message', finding.get('rule_id', 'Detector finding'))), severity=_label(finding.get('severity')), src_ip=data.get('src_ip'), dst_ip=data.get('dst_ip'), evidence_reference=row['id']))
                                else:
                                    finding_overflow = True
                            for action in data.get('actions', []):
                                key = entry['id']+':action:'+str(action['id'])
                                if key not in response_ids and len(response_ids) < MAX_FINDINGS:
                                    response_ids.add(key)
                                    result['responses'].append(dict(id=key, observed_at=row['observed_at'], source='MEGALODON action record', state=_label(action.get('status', action.get('outcome', 'Recorded outcome unavailable'))), detail=_label(action.get('action_type', action.get('action', 'Recorded response')))))
                        elif category == 'packet_rollups':
                            kind=data.get('kind')
                            if kind=='partial_interval':
                                compacted_edge=True
                                continue
                            compacted_segments.add(entry['id'])
                            if kind=='conversation_v1':
                                count=data.get('packet_count',0)
                                byte_count=data.get('byte_count',0)
                                if type(count) is not int or count<1 or type(byte_count) is not int or byte_count<0:
                                    gaps.append('A compact conversation count was invalid and excluded.')
                                    continue
                                compacted_records+=count
                                result['summary']['packet_records']+=count
                                result['summary']['packet_bytes']+=byte_count
                                result['timeline'][min(47,int((stamp-start)/(end-start)*48))]+=count
                                _counter(result['packet_protocols'],data.get('protocol','Unknown'),count)
                                for key in ('src_ip','dst_ip'):_counter(result['endpoints'],data.get(key,'Unknown'),count)
                            elif kind=='finding_v1':
                                finding=data.get('detection',{})
                                event=data.get('event',{})
                                result['summary']['finding_count']+=1
                                _counter(result['finding_severities'],'MEGALODON / '+_label(finding.get('severity')))
                                if len(result['findings'])<MAX_FINDINGS:
                                    result['findings'].append(dict(id=row['id'],observed_at=row['observed_at'],source='MEGALODON detector · compact history',
                                        title=_label(finding.get('message',finding.get('rule_id','Detector finding'))),severity=_label(finding.get('severity')),
                                        src_ip=event.get('src_ip'),dst_ip=event.get('dst_ip'),evidence_reference=row['id'],
                                        original_reference=data.get('original_reference')))
                                else:finding_overflow=True
                            elif kind=='action_v1':
                                action=data.get('action',{})
                                key=row['id']
                                if key not in response_ids and len(response_ids)<MAX_FINDINGS:
                                    response_ids.add(key)
                                    result['responses'].append(dict(id=key,observed_at=row['observed_at'],source='MEGALODON action record · compact history',
                                        state=_label(action.get('status','Recorded outcome unavailable')),
                                        detail=_label(action.get('action','Recorded response'))))
                        elif category == 'flows':
                            key = (source, str(data.get('source_id')), data.get('first_seen'), data.get('byte_basis', 'unknown'))
                            if key not in flows and len(flows) >= MAX_FLOWS:
                                flow_overflow = True
                                continue
                            previous = flows.setdefault(key, dict(sent_bytes=None, received_bytes=None, updates=0, protocol=_label(data.get('protocol', 'Unknown'))))
                            previous['updates'] += 1
                            for field in ('sent_bytes', 'received_bytes'):
                                value = _number(data.get(field))
                                if value is not None:
                                    previous[field] = max(previous[field] or 0, value)
                        elif category == 'findings':
                            result['summary']['finding_count'] += 1
                            _counter(result['finding_severities'], source+' / '+_label(data.get('severity')))
                            if len(result['findings']) < MAX_FINDINGS:
                                result['findings'].append(dict(id=row['id'], observed_at=row['observed_at'], source=source, title=_label(data.get('signature', 'Sensor finding')), severity=_label(data.get('severity')), src_ip=data.get('src_ip'), dst_ip=data.get('dst_ip'), evidence_reference=row['id']))
                            else:
                                finding_overflow = True
                        elif category == 'resources':
                            result['summary']['resource_samples'] += 1
                            bucket = min(47, int((stamp-start)/(end-start)*48))
                            resource_bins.setdefault(bucket, []).append(data)
                            # Keep at most one minute's sample array per bin; fold
                            # into running means immediately to bound memory.
                            if len(resource_bins[bucket]) > 16:
                                resource_bins[bucket] = [_resource_mean(resource_bins[bucket])]
                        elif category == 'network':
                            result['summary']['network_samples'] += 1
                            if result['network'] is None or row['observed_at'] > result['network']['observed_at']:
                                # Capture a bounded topology snapshot, preserving
                                # source fields and truthful observation labels.
                                encoded = json.dumps(data, allow_nan=False)
                                if len(encoded.encode()) <= 32768:
                                    result['network'] = dict(observed_at=row['observed_at'], source=source, data=data)
                        elif category == 'audit' and data.get('state') != 'not_attempted':
                            key = source+':'+str(data.get('receipt_id', row['id']))
                            if key not in response_ids and len(response_ids) < MAX_FINDINGS:
                                response_ids.add(key)
                                result['responses'].append(dict(id=row['id'], observed_at=row['observed_at'], source=source, state=_label(data.get('state')), detail=_label(data.get('message', data.get('action', 'Recorded advisory or response receipt')))))
                    with self.lock:
                        self.job.update(progress=min(95, int(95*processed/total_rows)), processed_records=processed)
                if bounds_reached:
                    break
            except (OSError, ValueError, sqlite3.Error):
                gaps.append('An evidence segment expired or could not be read during report generation.')
        grouped = {}
        for (source, identity, first_seen, basis), value in flows.items():
            group = grouped.setdefault((source, basis), dict(source=source, byte_basis=basis, records=0, connections=0, sent_bytes=0, received_bytes=0, unknown_counters=0, protocols=Counter()))
            group['connections'] += 1
            _counter(group['protocols'], value['protocol'])
            group['records'] += value['updates']
            for field in ('sent_bytes', 'received_bytes'):
                if value[field] is None:
                    group['unknown_counters'] += 1
                else:
                    group[field] += int(value[field])
        for group in grouped.values():
            group['protocols'] = dict(group['protocols'])
        result['flow_sources'] = list(grouped.values())
        result['summary']['flow_sources'] = result['flow_sources']
        result['summary']['response_count'] = len(result['responses'])
        result['resources'] = [dict(bin=bucket, **_resource_mean(values)) for bucket, values in sorted(resource_bins.items())]
        result['packet_protocols'] = dict(result['packet_protocols'])
        result['finding_severities'] = dict(result['finding_severities'])
        result['endpoints'] = dict(result['endpoints'].most_common(30))
        result['source_counts'] = dict(result['source_counts'])
        if len(response_ids) >= MAX_FINDINGS:
            gaps.append('Response detail is bounded to 5,000 distinct records; additional response outcomes may be omitted.')
        if finding_overflow:
            gaps.append('Finding details are limited to 5,000 rows; finding totals include every processed finding.')
        if flow_overflow:
            gaps.append('The 100,000-connection flow aggregation limit was reached; flow totals are incomplete.')
        if compacted_records:
            gaps.append('Some packet metadata is represented by five-minute, directional conversation summaries. Individual packet details are unavailable for those intervals.')
        if compacted_edge:
            gaps.append('A compact conversation crossed the requested interval boundary; that entire summary was excluded from counts.')
        if not matched:
            gaps.append('No retained evidence was available in this selected interval; this does not establish inactivity.')
        if first is not None and first > start + 120:
            gaps.append('Retained evidence begins after the requested start; earlier coverage is unavailable.')
        if last is not None and last < end - 120:
            gaps.append('Retained evidence ends before the requested end; later coverage is unavailable.')
        if result['network'] is None:
            gaps.append('A retained local-network topology snapshot was unavailable.')
        if not result['resources']:
            gaps.append('Historical interface speeds and resource measurements were unavailable.')
        aggregation_limited = bounds_reached or finding_overflow or flow_overflow or any('could not' in g or 'limit' in g or 'excluded' in g for g in gaps)
        gaps.append('Sensor continuity and unobserved traffic are not established by retained records.')
        result['coverage'] = dict(partial=True, aggregation_complete=not aggregation_limited and not compacted_edge,
                                  gaps=list(dict.fromkeys(gaps)), oldest_at=utc(first) if first is not None else None,
                                  newest_at=utc(last) if last is not None else None, processed_records=processed,
                                  matched_records=matched, source_history=True, finding_details_truncated=finding_overflow,
                                  flow_totals_truncated=flow_overflow, compacted_packet_records=compacted_records,
                                  compacted_segments=len(compacted_segments))
        status = self.evidence.snapshot()
        result['storage'] = {k: status.get(k) for k in ('policy', 'used_bytes', 'oldest_at', 'newest_at', 'estimated_days', 'warnings')}
        intelligence=getattr(self,'intelligence',None)
        if intelligence is not None:
            result['intelligence']=intelligence.report_context(start,end)
            if result['intelligence']['truncated']:
                result['coverage']['gaps'].append('Pattern explanations have bounded or incomplete coverage; see their details.')
            anchors=[v['source_start'] for v in result['intelligence']['reviews']]
            if anchors:result['retention_source_at']=min(anchors+[result['coverage']['oldest_at']] if result['coverage']['oldest_at'] else anchors)
        return result

    def _run(self, identifier, start, end, scheduled):
        try:
            # Workspace is memory-only; reserve its eventual managed allocation
            # before aggregation so output cannot bypass evidence capacity.
            with self.evidence.working_reservation(MAX_BODY):
                result = self._aggregate(identifier, start, end)
                self._check()
                raw = json.dumps(result, separators=(',', ':'), sort_keys=True, allow_nan=False).encode()
                if len(raw) > MAX_BODY:
                    raise ValueError('Report exceeds its bounded output size; choose a shorter interval.')
                # A report with no source still expires by its selected start.
                source_at = result.get('retention_source_at') or result['coverage']['oldest_at'] or utc(max(start, self.clock()-self.evidence.retention_days*86400+1))
                if epoch(source_at) < self.clock()-self.evidence.retention_days*86400+1:
                    raise ValueError('The source interval expired while the report was being made.')
                chunks = [raw[i:i+CHUNK_BYTES] for i in range(0, len(raw), CHUNK_BYTES)]
                references = []
                for offset in range(0, len(chunks), 128):
                    self._check()
                    rows = [dict(observed_at=source_at, source='report-chunk', data=dict(kind='chunk', report_id=identifier, index=index, content=base64.b64encode(chunks[index]).decode())) for index in range(offset, min(offset+128, len(chunks)))]
                    with self.evidence.lock:
                        self.evidence.append_records('reports', rows,dependencies=result.get('intelligence',{}).get('dependencies',[]))
                        entry = self.evidence._generic['reports']
                        with self.evidence._db(entry) as db:
                            last_id = db.execute('SELECT MAX(id) FROM records').fetchone()[0]
                        references.append(dict(segment=entry['id'], first=last_id-len(rows)+1, last=last_id))
                manifest = dict(id=identifier, kind='manifest', state='incomplete' if not result['coverage']['aggregation_complete'] else 'ready', created_at=result['created_at'], start=result['start'], end=result['end'], title=result['title'], source_at=source_at, coverage=result['coverage'], summary=result['summary'], chunks=len(chunks), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), references=references)
                manifest['derived_dependencies']=result.get('intelligence',{}).get('dependencies',[])
                checkpoint = ('reports_schedule', dict(slot=scheduled['slot'], at=scheduled['at'], report_id=identifier)) if scheduled else ('reports_last_completed', dict(report_id=identifier))
                self._check()
                self.evidence.append_records('reports', [dict(observed_at=source_at, source='report-manifest', data=manifest)], checkpoint=checkpoint,dependencies=manifest['derived_dependencies'])
            with self.lock:
                if scheduled:
                    self.settings.update(completed_slot=scheduled['slot'], completed_at=scheduled['at'], pending=None, last_error=None)
                self.job.update(state='ready', progress=100, report_id=identifier, error=None)
                self.settings['last_job'] = dict(self.job)
                try:self._save_settings()
                except (OSError,ValueError):
                    self.job['error'] = 'Report saved. Schedule confirmation will recover from its evidence checkpoint on restart.'
        except Cancelled:
            with self.lock:
                self.job.update(state='cancelled', error='Report cancelled; previously completed reports are unchanged.')
                if scheduled and self._operator_cancel:
                    self.settings.update(cancelled_slot=scheduled['slot'], pending=None)
                self._retry_at = self.clock()+300
                self.settings['last_job'] = dict(self.job)
                try:self._save_settings()
                except (OSError,ValueError):pass
        except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, sqlite3.Error):
            with self.lock:
                self.job.update(state='failed', error='Report could not be saved. Review storage coverage and try a shorter interval.')
                self.settings['last_error'] = self.job['error']
                self.settings['last_job'] = dict(self.job)
                self._retry_at = self.clock()+300
                try:self._save_settings()
                except (OSError,ValueError):pass

    def _report_entries(self):
        with self.evidence.lock:
            return deepcopy([e for e in self.evidence._catalog['entries'] if e['category']=='reports' and e['state'] in {'open','closed'}])

    def _manifest_values(self):
        found = []
        for entry in reversed(self._report_entries()):
            try:
                with self.evidence.lock, self.evidence._db(entry) as db:
                    rows = db.execute("SELECT data FROM records WHERE source='report-manifest' ORDER BY id DESC LIMIT 100").fetchall()
                for row in rows:
                    value = json.loads(row[0])
                    if re.fullmatch(r'[a-f0-9]{32}', value.get('id', '')):
                        found.append(value)
                if len(found) >= 100:
                    break
            except (OSError, ValueError, sqlite3.Error):
                continue
        return sorted(found, key=lambda v:v['created_at'], reverse=True)[:100]

    def manifests(self):
        entries = {e['id'] for e in self._report_entries()}
        cutoff = self.clock()-self.evidence.retention_days*86400
        result = []
        for raw in self._manifest_values():
            value = {k:v for k,v in raw.items() if k not in {'kind','sha256','chunks','bytes','references'}}
            if epoch(raw['source_at']) < cutoff or any(ref['segment'] not in entries for ref in raw['references']) or not self._derived_available(raw):
                value['state'] = 'expired'
            value.update(html_url=f"/api/reports/{value['id']}/html", json_url=f"/api/reports/{value['id']}/json", csv_url=f"/api/reports/{value['id']}/csv")
            result.append(value)
        return result

    def _derived_available(self,manifest):
        with self.evidence.lock:
            entries=[e for e in self.evidence._catalog['entries'] if e['state'] in {'open','closed'}]
        available={e['id'] for e in entries}|{e['source_segment'] for e in entries if e['category']=='packet_rollups' and e['state']=='closed' and e.get('source_segment')}
        return set(manifest.get('derived_dependencies',[]))<=available

    def snapshot(self):
        reports = self.manifests()
        with self.lock:
            schedule = dict(self.settings['schedule'])
            _, last = latest_slot(schedule, self.clock(), self.zone)
            # Query tomorrow's local slot (or next week's), keeping wall time
            # stable through DST transitions rather than adding 86400 seconds.
            date = datetime.fromtimestamp(last, self.zone).date() + timedelta(days=7 if schedule['frequency']=='weekly' else 1)
            h, m = map(int, schedule['time'].split(':'))
            next_at = datetime(date.year, date.month, date.day, h, m, tzinfo=self.zone).timestamp()
            schedule.update(timezone=str(self.zone), next_at=utc(next_at) if schedule['enabled'] else None, last_error=self.settings['last_error'])
            return dict(schema=SCHEMA, operator_token=self.token, available=self.evidence.enabled, reports=reports, job=dict(self.job), schedule=schedule, local_only=True)

    def report(self, identifier):
        if type(identifier) is not str or not re.fullmatch(r'[a-f0-9]{32}', identifier):
            raise ValueError('Invalid saved report identity.')
        chunks = {}
        manifest = next((row for row in self._manifest_values() if row['id']==identifier), None)
        if manifest is None:
            raise ValueError('Saved report expired or is unavailable.')
        entries = {e['id']:e for e in self._report_entries()}
        references = manifest.get('references')
        if type(references) is not list or len(references)>8:
            raise ValueError('Saved report references need review.')
        for ref in references:
            entry = entries.get(ref['segment'])
            if entry is None or type(ref['first']) is not int or type(ref['last']) is not int or not 0<ref['first']<=ref['last'] or ref['last']-ref['first']>=128:
                raise ValueError('Saved report expired or references are invalid.')
            with self.evidence.lock, self.evidence._db(entry) as db:
                rows = db.execute('SELECT source,data FROM records WHERE id>=? AND id<=? ORDER BY id LIMIT 128',(ref['first'],ref['last'])).fetchall()
            for source, raw in rows:
                value = json.loads(raw)
                if source!='report-chunk' or value.get('report_id')!=identifier or type(value.get('index')) is not int or not 0<=value['index']<MAX_BODY//CHUNK_BYTES+1:
                    raise ValueError('Saved report chunk identity changed.')
                chunks[value['index']] = value['content']
                if len(chunks)>MAX_BODY//CHUNK_BYTES+1:
                    raise ValueError('Saved report exceeds read bounds.')
        if manifest is None or len(chunks)!=manifest['chunks'] or manifest['bytes']>MAX_BODY:
            raise ValueError('Saved report expired or is incomplete; make a new report.')
        if epoch(manifest['source_at']) < self.clock()-self.evidence.retention_days*86400 or not self._derived_available(manifest):
            raise ValueError('Saved report source history has expired.')
        raw = b''.join(base64.b64decode(chunks[index], validate=True) for index in range(manifest['chunks']))
        if len(raw)!=manifest['bytes'] or hashlib.sha256(raw).hexdigest()!=manifest['sha256']:
            raise ValueError('Saved report integrity needs review.')
        return json.loads(raw)

    def findings(self, identifier, *, offset=0, limit=50):
        if type(offset) is not int or not 0<=offset<=MAX_FINDINGS or type(limit) is not int or not 1<=limit<=100:
            raise ValueError('Invalid finding page.')
        value = self.report(identifier)
        records = value['findings']
        return dict(records=records[offset:offset+limit], total=value['summary']['finding_count'], retained_details=len(records), offset=offset, limit=limit, truncated=offset+limit<len(records) or value['coverage']['finding_details_truncated'])

    def download(self, identifier, kind):
        value = self.report(identifier)
        if kind == 'html':
            return 'text/html; charset=utf-8', render_html(value).encode()
        if kind == 'json':
            return 'application/json; charset=utf-8', json.dumps(value, indent=2, allow_nan=False).encode()
        if kind == 'csv':
            stream = io.StringIO(newline='')
            writer = csv.writer(stream)
            writer.writerow(['Report coverage', 'Partial' if value.get('coverage', {}).get('partial') else 'Returned evidence'])
            writer.writerow(['Finding total', value.get('summary', {}).get('finding_count', len(value['findings']))])
            writer.writerow(['Included finding detail rows', len(value['findings'])])
            for gap in value.get('coverage', {}).get('gaps', []):
                writer.writerow(['Coverage note', _csv_safe(gap)])
            writer.writerow([])
            writer.writerow(['observed_at', 'source', 'finding', 'severity', 'source_ip', 'destination_ip', 'evidence_reference'])
            for row in value['findings']:
                writer.writerow([_csv_safe(row.get(k, '')) for k in ('observed_at','source','title','severity','src_ip','dst_ip','evidence_reference')])
            return 'text/csv; charset=utf-8', stream.getvalue().encode()
        raise ValueError('Choose HTML, JSON or CSV.')


def _csv_safe(value):
    value = '' if value is None else str(value)
    return "'"+value if re.match(r'^[\x00-\x1f]|^[\s\x00-\x1f\ufeff]*[=+@-]', value) else value


def _resource_mean(values):
    # Running weighted means preserve sampling counts after bounded compaction.
    result = dict(samples=0, system_cpu_percent=None, suite_cpu_percent=None, suite_memory_percent=None, interfaces={}, metric_samples={})
    totals = Counter()
    counts = Counter()
    interfaces = {}
    for value in values:
        weight = value.get('samples', 1)
        result['samples'] += weight
        for key, raw in [('system_cpu_percent', value.get('system_cpu_percent', value.get('system', {}).get('cpu_percent'))),
                         ('suite_cpu_percent', value.get('suite_cpu_percent', value.get('suite', {}).get('cpu_percent'))),
                         ('suite_memory_percent', value.get('suite_memory_percent', value.get('suite', {}).get('memory_percent')))]:
            number = _number(raw)
            if number is not None:
                count = value.get('metric_samples', {}).get(key, weight)
                totals[key] += number*count
                counts[key] += count
        source = value.get('interfaces')
        if source is None:
            network = value.get('network', {})
            source = {r.get('name', 'Unknown'): r for r in network.get('interfaces', [])} if type(network) is dict else {}
        for name, row in list(source.items())[:32]:
            item = interfaces.setdefault(name, dict(receive_total=0, send_total=0, receive_samples=0, send_samples=0))
            for direction, fields in [('receive', ('receive_bytes_per_second','rx_bytes_per_second','rx_bps')), ('send', ('send_bytes_per_second','tx_bytes_per_second','tx_bps'))]:
                number = _number(next((row.get(k) for k in fields if row.get(k) is not None), None))
                n = row.get(direction+'_samples', weight)
                if number is not None:
                    item[direction+'_total'] += number*n
                    item[direction+'_samples'] += n
    for key in totals:
        result[key] = round(totals[key]/counts[key], 3)
        result['metric_samples'][key] = counts[key]
    for name, row in interfaces.items():
        result['interfaces'][name] = {direction+'_bytes_per_second': row[direction+'_total']/row[direction+'_samples'] if row[direction+'_samples'] else None for direction in ('receive','send')}
        result['interfaces'][name].update({direction+'_samples':row[direction+'_samples'] for direction in ('receive','send')})
    return result


def _friendly(value, zone='UTC', *, short=False):
    if value is None:return 'Unavailable'
    try:
        tz=ZoneInfo(zone)
    except (ValueError,KeyError):tz=timezone.utc
    try:stamp=datetime.fromtimestamp(epoch(value),tz)
    except (ValueError,TypeError,OverflowError):return 'Unavailable'
    return stamp.strftime('%b %d, %H:%M %Z' if short else '%b %d, %Y at %I:%M %p %Z')


def _size_label(value):
    if _number(value) is None:return 'Unavailable'
    for unit,divisor in [('TiB',1024**4),('GiB',1024**3),('MiB',1024**2),('KiB',1024)]:
        if value>=divisor:return f'{value/divisor:,.1f} {unit}'
    return f'{value:,.0f} bytes'


def _metric(value):
    if value is None:return 'Unavailable'
    return f'{value:,.0f}' if value>=100 else f'{value:,.2f}'.rstrip('0').rstrip('.')


def _table(headers, rows, empty='No records were available for this section.'):
    rows=list(rows)
    if not rows:return '<p class="muted">'+html.escape(empty)+'</p>'
    esc=lambda value:html.escape(_label(value,2048))
    return '<div class="scroll"><table><thead><tr>'+''.join('<th scope="col">'+esc(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def _categories(values, title, unit='records'):
    pairs=sorted(values.items(),key=lambda x:x[1],reverse=True)
    if not pairs or not any(v>0 for _,v in pairs):
        return '<p class="notice">No '+html.escape(unit)+' were returned for '+html.escape(title.lower())+'. Missing collection coverage remains unknown.</p>'
    maximum=max(v for _,v in pairs);total=sum(v for _,v in pairs)
    height=55+len(pairs[:12])*36
    items=['<text x="215" y="18">'+html.escape(unit)+' · count and share of returned values</text>']
    for i,(name,value) in enumerate(pairs[:12]):
        y=43+i*36
        items += [f'<text x="5" y="{y+5}">'+html.escape(_label(name,28))+'</text>',f'<rect class="bar" x="215" y="{y-11}" width="{max(1,value/maximum*285):.2f}" height="22"/>',f'<text x="510" y="{y+5}">'+html.escape(f'{value:,} ({value/total:.0%})')+'</text>']
    return '<svg class="chart category-chart" viewBox="0 0 640 '+str(height)+'" role="img" aria-label="'+html.escape(title,quote=True)+'">'+''.join(items)+'</svg>'+('<p class="muted">Chart shows the 12 leading categories; the table contains the returned breakdown.</p>' if len(pairs)>12 else '')


def _traffic_chart(values,start,end,zone):
    if not values or not any(values):return '<p class="notice">No packet records were returned for this time range. A quiet network and missing collection cannot be distinguished from this report alone.</p>'
    maximum=max(values);width=570/len(values)
    parts=[]
    for fraction in (0,.5,1):
        y=160-fraction*130
        parts += [f'<line x1="60" y1="{y}" x2="630" y2="{y}" stroke="var(--line)"/>',f'<text x="50" y="{y+4}" text-anchor="end">{_metric(maximum*fraction)}</text>']
    parts += ['<text x="60" y="16">Packet records per interval</text>']
    for i,value in enumerate(values):
        parts += [f'<rect class="bar" x="{60+i*width+1:.2f}" y="{160-value/maximum*130:.2f}" width="{max(1,width-2):.2f}" height="{value/maximum*130:.2f}"/>']
    parts += ['<text x="60" y="188">'+html.escape(_friendly(start,zone,short=True))+'</text>','<text x="630" y="188" text-anchor="end">'+html.escape(_friendly(end,zone,short=True))+'</text>']
    return '<svg class="chart" viewBox="0 0 640 205" role="img" aria-label="Packet records by time interval, with count scale">'+''.join(parts)+'</svg>'


def _speed_chart(rows,start,end,zone):
    known=[v for row in rows for v in row[1:] if v is not None]
    if not known:return '<p class="notice">No measured receive or send speeds were retained for this interface.</p>'
    maximum=max(known) or 1
    parts=[]
    for fraction in (0,.5,1):
        y=160-fraction*130
        parts += [f'<line x1="60" y1="{y}" x2="630" y2="{y}" stroke="var(--line)"/>',f'<text x="50" y="{y+4}" text-anchor="end">{_metric(maximum*fraction*8/1e6)}</text>']
    parts += ['<text x="60" y="16">Mbps · average of retained samples in each interval</text>']
    for column,color in [(1,'var(--cyan)'),(2,'var(--gold)')]:
        previous=None
        for row in rows:
            if row[column] is None:previous=None;continue
            x=60+row[0]/47*570;y=160-row[column]/maximum*130
            if previous and row[0]==previous[0]+1:
                parts += [f'<line x1="{previous[1]:.2f}" y1="{previous[2]:.2f}" x2="{x:.2f}" y2="{y:.2f}" stroke="{color}" stroke-width="2"/>']
            parts += [f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3" fill="{color}"/>']
            previous=(row[0],x,y)
    parts += ['<text x="60" y="188">'+html.escape(_friendly(start,zone,short=True))+'</text>','<text x="630" y="188" text-anchor="end">'+html.escape(_friendly(end,zone,short=True))+'</text>']
    return '<svg class="chart" viewBox="0 0 640 205" role="img" aria-label="Receive and send speed in Mbps over time">'+''.join(parts)+'</svg>'+('<p class="muted">All known speed samples were zero. Missing samples remain unknown.</p>' if not max(known) else '')


def _network_chart(data):
    nodes=data.get('nodes',[]);edges=data.get('edges',[])
    if type(nodes) is not list or type(edges) is not list:return '<p class="muted">Topology measurements unavailable.</p>'
    nodes=[n for n in nodes if type(n) is dict and type(n.get('id')) is str][:16]
    positions={n['id']:(120+(i%4)*240,55+(i//4)*90) for i,n in enumerate(nodes)}
    if not nodes:return '<p class="muted">No retained topology nodes.</p>'
    content=[]
    for edge in edges[:1024]:
        if type(edge) is not dict:continue
        source,target=positions.get(edge.get('source')),positions.get(edge.get('target'))
        if source and target:
            dash='' if edge.get('kind')=='observed' else ' stroke-dasharray="6 6"'
            content.append(f'<line x1="{source[0]}" y1="{source[1]}" x2="{target[0]}" y2="{target[1]}" stroke="var(--cyan)" opacity=".55"'+dash+'/>')
    for node in nodes:
        x,y=positions[node['id']]
        content.append(f'<rect x="{x-105}" y="{y-24}" width="210" height="52" rx="4" fill="#16303c" stroke="var(--cyan)"/>')
        content.append(f'<text x="{x}" y="{y-5}" text-anchor="middle">'+html.escape(_label(node.get('name',node.get('ip')),28))+'</text>')
        content.append(f'<text x="{x}" y="{y+14}" text-anchor="middle">'+html.escape(_label(node.get('interface'),16)+' · '+_label(node.get('role'),16))+'</text>')
    return '<svg class="chart topology-chart" viewBox="0 0 960 365" role="img" aria-label="Retained local network schematic">'+''.join(content)+'</svg><p class="muted">Solid: observed connection · Dashed: routing or discovery relationship. This is a logical map, not physical cable placement.</p>'


def render_html(value):
    e=lambda v:html.escape(_label(v,2048))
    summary=value['summary'];coverage=value['coverage'];zone=value.get('timezone','UTC')
    start,end=value['start'],value['end']
    interval=lambda i:_friendly(utc(epoch(start)+(epoch(end)-epoch(start))*i/48),zone,short=True)
    severities=value.get('finding_severities',{})
    urgent=sum(count for label,count in severities.items() if label in {'MEGALODON / HIGH','MEGALODON / CRITICAL','suricata-eve / 1'})
    attention=(f'{urgent:,} high-priority '+('finding needs' if urgent==1 else 'findings need')+' review. Start with the finding details below.' if urgent else f'{summary["finding_count"]:,} findings were returned. Review their source and severity below.' if summary['finding_count'] else 'No findings were returned. This does not establish that all activity was safe.')
    parts=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MEGALODON network report</title><style>'+REPORT_CSS+'</style></head><body><main><header class="hero"><div class="eyebrow">MEGALODON / LOCAL REPORT</div><h1>Your network, explained.</h1><p>'+e(_friendly(start,zone))+' → '+e(_friendly(end,zone))+'</p><p>'+e(attention)+'</p><div class="stats">'+''.join('<div class="stat"><strong>'+e(v)+'</strong>'+e(k)+'</div>' for k,v in [('Packet records',f"{summary['packet_records']:,}"),('Reported packet data',_size_label(summary['packet_bytes'])),('Findings',f"{summary['finding_count']:,}"),('Resource samples',f"{summary['resource_samples']:,}")])+'</div></header>']
    parts+=['<section><h2>What needs attention</h2><p>'+e(attention)+'</p>'+_categories(severities,'Findings by source and severity','findings')+_table(['Source / recorded severity','Findings'],severities.items(),empty='No finding severity labels were returned.')+'<details><summary>What this report could and could not see</summary><p>'+('All available source rows within the report work limits were processed.' if coverage.get('aggregation_complete') else 'Some source rows or details could not be processed. This report is incomplete.')+'</p><ul>'+''.join('<li>'+e(g)+'</li>' for g in coverage['gaps'])+'</ul></details></section>']
    parts+=['<div class="chart-grid"><section><h2>Traffic over time</h2><p class="muted">Packet records in 48 equal time intervals. Empty intervals do not prove uninterrupted capture.</p>',_traffic_chart(value['timeline'],start,end,zone),'<details><summary>Traffic chart table</summary>',_table(['Interval begins','Packet records'],[(interval(i),n) for i,n in enumerate(value['timeline'])]),'</details></section><section><h2>Recorded protocol mix</h2>',_categories(value['packet_protocols'],'Packet protocols','packet records'),'<details><summary>Protocol chart table</summary>',_table(['Protocol','Packet records'],value['packet_protocols'].items()),'</details></section></div>']
    parts+=['<section><h2>Connection summaries</h2><p class="muted">Each source is shown separately. Repeated updates to a connection count once. Its largest retained byte counters may include traffic before this report began. These totals are not added to packet totals.</p>',_table(['Source','Counter meaning','Connections','Updates','To responder','To originator','Unknown counters'],[(r['source'],r['byte_basis'].replace('_',' '),r['connections'],r['records'],_size_label(r['sent_bytes']),_size_label(r['received_bytes']),r['unknown_counters']) for r in value['flow_sources']],empty='No connection summaries were retained. Packet charts may still contain data.')]
    for group in value['flow_sources']:
        parts+=['<h3>'+e(group['source'])+' / connection protocols</h3>',_categories(group.get('protocols',{}),'Connection protocols','connections'),'<details><summary>Connection protocol table</summary>',_table(['Protocol','Source connections'],group.get('protocols',{}).items()),'</details>']
    parts+=['</section><section><h2>Download, upload and PC resources</h2><p class="muted">Receive means data arriving on an interface; send means data leaving it. Both include local-network traffic. VPNs and bridges can count the same traffic, so interfaces stay separate.</p>']
    names=sorted({name for row in value['resources'] for name in row['interfaces']})
    if not names:parts+=['<p class="notice">No historical interface speeds were retained for this period.</p>']
    for name in names:
        rows=[(r['bin'],r['interfaces'].get(name,{}).get('receive_bytes_per_second'),r['interfaces'].get(name,{}).get('send_bytes_per_second')) for r in value['resources']]
        rx=[r[1] for r in rows if r[1] is not None];tx=[r[2] for r in rows if r[2] is not None]
        parts+=['<h3>'+e(name)+'</h3><p><strong>Peak interval receive: '+e(_metric(max(rx)*8/1e6) if rx else 'Unavailable')+' Mbps</strong> · Peak interval send: '+e(_metric(max(tx)*8/1e6) if tx else 'Unavailable')+' Mbps</p>',_speed_chart(rows,start,end,zone),'<p class="muted">Teal: receive / download · Amber: send / upload. Points are interval averages; lines connect adjacent known intervals only.</p><details><summary>Speed chart table</summary>',_table(['Interval begins','Receive Mbps','Send Mbps'],[(interval(i),_metric(rx*8/1e6) if rx is not None else 'Unavailable',_metric(tx*8/1e6) if tx is not None else 'Unavailable') for i,rx,tx in rows]),'</details>']
    parts+=['<h3>PC resource use</h3><p class="muted">Percent of total PC capacity, averaged over retained samples. Activity occurring together does not prove that traffic caused resource use.</p>',_table(['Interval begins','Whole PC CPU %','MEGALODON CPU %','MEGALODON RAM %'],[(interval(r['bin']),_metric(r['system_cpu_percent']),_metric(r['suite_cpu_percent']),_metric(r['suite_memory_percent'])) for r in value['resources']],empty='No historical CPU or memory measurements were retained.'),'</section><section><h2>Local network and leading endpoints</h2><p class="muted">These addresses appeared in recorded packets. A count is an appearance, not a risk score or proof of device ownership.</p>',_categories(value['endpoints'],'Leading endpoints','appearances'),'<details><summary>Endpoint ranking table</summary>',_table(['Address','Observed appearances'],value['endpoints'].items()),'</details>']
    network=value.get('network')
    if network:
        data=network['data'];nodes=data.get('nodes',[])
        if type(nodes) is not list:nodes=[]
        nodes=[n for n in nodes if type(n) is dict]
        parts+=['<h3>Latest retained network map</h3><p>'+e(_friendly(network['observed_at'],zone))+'</p>',_network_chart(data),'<details><summary>Device table and observation source</summary>',_table(['Device / address','Role','Source','Last seen'],[(n.get('name',n.get('ip',n.get('id'))),n.get('role'),n.get('source'),_friendly(n.get('last_seen'),zone)) for n in nodes[:100]]),'<p class="muted">The table includes up to 100 nodes; the map includes the first 16. Discovery does not reveal traffic between other devices.</p></details>']
    else:parts+=['<p class="notice">No retained local-network map was available for this period.</p>']
    parts+=['</section><section><h2>Recorded response outcomes</h2><p class="muted">A proposed action has not run. Failed or unknown outcomes must not be treated as successful protection. Advisory notes are shown as notes, not performed actions.</p>',_table(['Time','Source','Recorded state','Action or note'],[(_friendly(r['observed_at'],zone),r['source'],r['state'],r['detail']) for r in value['responses']],empty='No response actions or advisory receipts were returned.'),'<details><summary>Finding details and evidence references</summary>',_table(['Time','Source','Finding','Severity','Source → destination','Evidence reference'],[(_friendly(r['observed_at'],zone),r['source'],r['title'],r['severity'],str(r.get('src_ip'))+' → '+str(r.get('dst_ip')),r['evidence_reference']) for r in value['findings']],empty='No finding details were retained.'),'</details></section>']
    intelligence=value.get('intelligence',{})
    parts+=['<section><h2>Patterns and local AI reviews</h2><p>'+e(intelligence.get('coverage','No pattern reviews were included in this report.'))+'</p>']
    for review in intelligence.get('reviews',[]):
        analysis=review.get('analysis',{})
        parts+=['<article><h3>'+e(review['device'])+' · '+e(review['label'])+'</h3>',
                '<h4>What happened</h4><p>'+e(review['what_happened'])+'</p><h4>Why it matters</h4><p>'+e(review['why_it_matters'])+'</p>',
                '<h4>What you can do</h4><p>'+e(review['what_you_can_do'])+' · Approval is required for device or connection changes.</p>',
                '<p>'+e(analysis.get('explanation',analysis.get('message','AI explanation has not been generated.')))+'</p>',
                '<details><summary>Measurements, alternatives and references</summary>',
                _table(['Field','Value'],[(k,json.dumps(v)) for k,v in review['facts'].items()]),
                '<p>'+e(analysis.get('alternative',''))+'</p><p>'+e(analysis.get('missing',''))+'</p>',
                _table(['Reference','Source'],[(r['id'],r['url']) for r in analysis.get('references',[])]),
                _table(['Evidence reference'],[(r,) for r in review['evidence_refs']]),
                '<p>'+e(' '.join(review['missing_information']))+'</p></details></article>']
    parts+=['</section>']
    storage=value.get('storage',{});policy=storage.get('policy') or {}
    modes={'packet_metadata':'detailed packet metadata','connection_summaries':'connection summaries'}
    policy_text=(str(policy['retention_days'])+' days · '+_size_label(policy.get('cap_bytes'))+' maximum · '+modes.get(policy.get('recording_mode'),'recording detail unavailable')) if policy.get('retention_days') else 'Storage policy unavailable'
    parts+=['<section><h2>Storage and history</h2><p><strong>'+e(policy_text)+'</strong></p>',_table(['Measure','Value'],[('Managed space in use',_size_label(storage.get('used_bytes'))),('Oldest evidence processed',_friendly(coverage['oldest_at'],zone)),('Newest evidence processed',_friendly(coverage['newest_at'],zone)),('Source rows reviewed',f"{coverage['processed_records']:,}")]),'<p class="muted">The chosen history is a maximum. Space limits can remove older evidence sooner. This report follows the age of its source evidence while it remains managed by MEGALODON.</p></section><details><summary>Exact times, sources and methodology</summary>',_table(['Measure','Exact value'],[('Start, inclusive',start),('End, exclusive',end),('Generated',value['created_at']),('Reported packet bytes',summary['packet_bytes']),('Managed bytes',storage.get('used_bytes')),('Oldest processed evidence',coverage['oldest_at']),('Newest processed evidence',coverage['newest_at'])]),'<p>Retained segments intersecting the selected interval are read in bounded pages at fixed row watermarks. Later records are excluded. Missing evidence, expiry, collection gaps and work limits remain visible. Saved cases and previous reports are excluded from traffic totals. Unknown locations remain unknown.</p>',_table(['Source','Returned records'],value['source_counts'].items()),'</details><footer><p>Made '+e(_friendly(value['created_at'],zone))+' · Local only</p><p class="mono">Report '+e(value['id'])+'</p><p class="muted">This saved copy contains local network metadata. MEGALODON does not upload it. Personal exported copies are outside automatic cleanup.</p></footer></main></body></html>']
    document = ''.join(parts)
    document = re.sub(r'(<svg class="chart[^>]*>.*?</svg>)', lambda m:'<div class="chart-scroll" tabindex="0" role="region" aria-label="Report chart; scroll horizontally on a narrow screen">'+m.group(1)+'</div><p class="chart-hint muted">On a narrow screen, scroll the chart sideways or open its data table.</p>', document, flags=re.S)
    return document
