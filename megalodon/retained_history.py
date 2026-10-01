"""Shared bounded, source-qualified reads for visual reports and HUD history."""
from copy import deepcopy
import json
import sqlite3
import re
from threading import Event
from .evidence_storage import epoch, utc

MAX_SEGMENTS = 2048

class RetainedEvidenceReader:
    def __init__(self, evidence):
        self.evidence = evidence
        self.stop_event = Event()
        self.read_cursor = 0

    def _check(self):
        return None

    def history_page(self, start, end, cursor=None):
        from .dashboard_traffic import history_parameters
        history_parameters(start, end)
        first, last = epoch(start), epoch(end)
        sources, gaps = self._sources(first, last)
        sources = sorted([(e, maximum) for e, maximum in sources
                          if e['category'] in {'packets','packet_rollups','flows','findings'}],
                         key=lambda row:(row[0]['created_at'],row[0]['id']))
        after = 0
        if cursor is not None:
            if not isinstance(cursor,str) or not re.fullmatch(r'[a-f0-9]{32}:[0-9]{1,19}',cursor):
                raise ValueError('Invalid retained-history cursor')
            segment, position = cursor.split(':')
            index = next((i for i,(e,_) in enumerate(sources) if e['id']==segment),None)
            if index is None:
                return dict(schema='megalodon-traffic-history-v2', records=[], next_cursor=None,
                            range=dict(start=utc(first),end=utc(last)), candidate_count=0,
                            truncated=True, gaps=['The requested segment expired; restart this interval.'], source_segments=[])
            sources=sources[index:];after=int(position)
        records=[];scanned=0;visited=[];next_cursor=None;response_bytes=0
        for index,(entry,maximum) in enumerate(sources[:32]):
            visited.append(entry['id'])
            if index:after=0
            self.read_cursor=after
            try:
                pages=self._pages(entry,maximum,first,last,after=after,page_size=128)
                page,count=next(pages,([],0));pages.close()
                for row in page:
                    data=row['data']
                    # Do not expose unbounded original metadata or detector JSON.
                    if row['category']=='packets':
                        if len(data.get('findings',[]))>32:
                            gaps.append('Additional linked findings are available in Reports; this chart caps each event at 32.')
                        findings=[{k:f.get(k) for k in ('id','rule_id','severity')} for f in data.get('findings',[])[:32]]
                        data={k:data.get(k) for k in ('src_ip','dst_ip','src_port','dst_port','protocol','byte_count','interface')}
                        data['packet_count']=1
                        data['kind']='packet_v1'
                        data['findings']=findings
                    elif row['category']=='packet_rollups' and data.get('kind')=='finding_v1':
                        finding=data.get('detection',{})
                        data=dict(kind='finding_v1',severity=finding.get('severity'),rule_id=finding.get('rule_id'),
                                  original_reference=data.get('original_reference'))
                    row=dict(row,data=data)
                    size=len(json.dumps(row).encode())
                    if size>8192:
                        gaps.append('An oversized source record was withheld from this bounded chart page.');continue
                    if response_bytes+size>220000:
                        self.read_cursor=int(row['id'].rsplit(':',1)[1])-1
                        break
                    response_bytes+=size
                    records.append(row)
                scanned+=count
            except (OSError,ValueError,sqlite3.Error):
                gaps.append('A source segment expired or could not be read.');self.read_cursor=maximum
            if self.read_cursor < maximum:
                next_cursor=entry['id']+':'+str(self.read_cursor);break
            if records or scanned>=128:
                if index+1<len(sources):next_cursor=sources[index+1][0]['id']+':0'
                break
        else:
            if len(sources)>32:next_cursor=sources[32][0]['id']+':0'
        return dict(schema='megalodon-traffic-history-v2',records=records,next_cursor=next_cursor,
                    range=dict(start=utc(first),end=utc(last)),candidate_count=scanned,
                    truncated=bool(next_cursor or gaps),gaps=list(dict.fromkeys(gaps)),source_segments=visited)

    def _sources(self, start, end):
        sources, gaps = [], []
        with self.evidence.lock:
            entries = deepcopy(self.evidence._catalog['entries'])
        packet_by_id = {e['id']:e for e in entries if e['category']=='packets' and e['state'] in {'open','closed'}}
        verified_rollups = {e['source_segment']:e['id'] for e in entries if e['category']=='packet_rollups'
                            and e['state']=='closed' and e.get('source_segment')
                            and (e['source_segment'] not in packet_by_id or
                                 packet_by_id[e['source_segment']].get('compacted_to')==e['id'])}
        candidates = [e for e in entries if e['category'] not in {'reports', 'cases'} and e['state'] in {'open', 'closed'}
                      and not (e['category']=='packets' and e['id'] in verified_rollups)
                      and not (e['category']=='packet_rollups' and verified_rollups.get(e.get('source_segment'))!=e['id'])
                      and (not e.get('last_at') or epoch(e['last_at']) >= start)
                      and (not e.get('first_at') or epoch(e['first_at']) < end)]
        if any(e['state'] == 'needs_review' for e in entries):
            gaps.append('Protected evidence requiring recovery review was excluded.')
        if len(candidates) > MAX_SEGMENTS:
            gaps.append('The 2,048-segment report limit was reached; the result is incomplete.')
        for entry in candidates[:MAX_SEGMENTS]:
            self._check()
            try:
                with self.evidence.lock, self.evidence._db(entry) as db:
                    table, key = ('events', 'id') if entry['kind'] == 'core' else ('ai_receipt_events', 'sequence') if entry['kind'] == 'receipt' else ('records', 'id')
                    maximum = db.execute(f'SELECT MAX({key}) FROM {table}').fetchone()[0] or 0
                sources.append((entry, maximum))
                if entry.get('recovered_incomplete'):
                    gaps.append('An interrupted capture contributes committed evidence; capture coverage is incomplete.')
                if entry.get('source_incomplete'):
                    gaps.append('A compacted source has an incomplete capture receipt; unobserved traffic remains unknown.')
            except (OSError, ValueError, sqlite3.Error):
                gaps.append('A source segment expired or could not be read before aggregation.')
        return sources, gaps

    def _pages(self, entry, maximum, start, end, *, after=0, page_size=512):
        last = after
        while last < maximum:
            self._check()
            with self.evidence.lock, self.evidence._db(entry) as db:
                table, key = ('events', 'id') if entry['kind'] == 'core' else ('ai_receipt_events', 'sequence') if entry['kind'] == 'receipt' else ('records', 'id')
                rows = db.execute(f'SELECT * FROM {table} WHERE {key}>? AND {key}<=? ORDER BY {key} LIMIT ?', (last, maximum, page_size)).fetchall()
                if not rows:
                    return
                linked = {}
                if entry['kind'] == 'core':
                    qualified = {r[0] for r in db.execute("SELECT l.event_id FROM ingestion_run_events l JOIN ingestion_runs r ON r.id=l.run_id WHERE l.event_id>? AND l.event_id<=? AND r.source IN ('jsonl','scapy') AND r.receipt_version=3 AND ((r.status='running' AND r.termination_reason IS NULL) OR (r.status='completed' AND r.termination_reason='source_exhausted') OR (r.status='incomplete' AND r.termination_reason='event_limit_reached') OR (r.status='failed' AND r.termination_reason IN ('failed','interrupted')))", (last, rows[-1]['id']))}
                    # No per-event query loop: findings and their verified action
                    # relationships are selected once for this fixed event page.
                    for item in db.execute('SELECT * FROM detections WHERE event_id>? AND event_id<=? ORDER BY id', (last, rows[-1]['id'])):
                        item = dict(item)
                        linked.setdefault(item['event_id'], []).append(item)
                    actions = [dict(r) for r in db.execute('SELECT a.*, d.event_id FROM actions a JOIN detection_actions l ON l.action_id=a.id JOIN detections d ON d.id=l.detection_id WHERE d.event_id>? AND d.event_id<=?', (last, rows[-1]['id']))]
                else:
                    actions = []
            output = []
            for row in rows:
                row = dict(row)
                stamp = row['observed_at'] if entry['kind'] != 'receipt' else row['timestamp']
                if entry['kind'] == 'core':
                    if row['id'] not in qualified:continue
                    if not start <= epoch(stamp) < end:continue
                    row.pop('metadata_json', None)
                    row['findings'] = linked.get(row['id'], [])
                    row['actions'] = [a for a in actions if a['event_id'] == row['id']]
                    source, data = 'accepted packet metadata', row
                elif entry['kind'] == 'receipt':
                    if not start <= epoch(stamp) < end:continue
                    source, data = 'legacy receipt ledger', json.loads(row['payload_json'])
                else:
                    source, data = row['source'], json.loads(row['data'])
                    if entry['category']=='packet_rollups' and data.get('kind')=='conversation_v1':
                        first,last=epoch(data['first_at']),epoch(data['last_at'])
                        if last<start or first>=end:continue
                        if first<start or last>=end:
                            data=dict(kind='partial_interval')
                            stamp=utc(max(start,first))
                    elif not start <= epoch(stamp) < end:continue
                output.append(dict(id=entry['id'] + ':' + str(row[key]), category=entry['category'], observed_at=stamp, source=source, data=data))
            last = rows[-1][key]
            self.read_cursor = last
            yield output, len(rows)
            # Yield the writer between pages; reports never hold a long read
            # transaction that blocks checkpoint reclamation.
            if self.stop_event.wait(.001):
                self._check()
                return
