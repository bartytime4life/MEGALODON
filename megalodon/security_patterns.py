"""Source-separated, review-only pattern checks over committed evidence.

No observations imply complete visibility or AI attribution. Thresholds and
workflow permissions are code, never values supplied by a reference update.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json

from .evidence_storage import epoch, utc
from .models import PacketEvent
from .offline.analysis import candidates as offline_candidates
from .offline.common import Batch, OfflineError

MAX_GROUPS = 128
MAX_RECORDS = 20000
MAX_GROUP_RECORDS = 2048
MIN_SAMPLES = 24
MAX_DEPENDENCIES = 256
REFERENCE_LINKS = {
    'PORT_SCAN': [('attack','T1046')],
    'SYN_FLOOD': [('attack','T1498')],
    'DNS_TUNNELING': [('attack','T1071.004')],
    'NEW_DESTINATION_PORT': [('d3fend','NetworkTrafficAnalysis'),('attack','T1046')],
    'PROTOCOL_SHIFT': [('d3fend','NetworkTrafficAnalysis')],
    'SERVICE_SHIFT': [('d3fend','NetworkTrafficAnalysis')],
    'REGULAR_INTERVAL': [('attack','T1071')],
    'PORT_53_BURST': [('attack','T1071.004')],
    'INVENTORY_CHANGE': [('attack','T1046')],
    'AI_MODEL_CHANGE': [('owasp','LLM04'),('owasp','LLM05')],
    'AI_EXPOSURE': [('owasp','LLM03')],
    'AI_FAILURES': [('owasp','LLM06')],
    'REJECTED_TOOL': [('owasp','LLM01'),('atlas','AML.T0051')],
    'OBSERVED_ACTIVITY': [('d3fend','NetworkTrafficAnalysis')],
}

WORKFLOWS = {
    'evidence_summary': dict(title='Collect an evidence summary', permission='read', effect='Read retained observations and their coverage.', verification='Source-qualified references are shown.', recovery='No device changes.'),
    'device_changes': dict(title='Review this device', permission='read', effect='Compare observed ports, protocols and inventory.', verification='Compare compatible sensor and interface measurements.', recovery='No device changes.'),
    'ai_readiness': dict(title='Check local AI readiness', permission='read', effect='Check the configured local model and listener.', verification='A local response or a specific unavailable state.', recovery='No device changes.'),
    'refresh_inventory': dict(title='Refresh configured inventory', permission='approval', effect='Run the configured inventory scope only.', verification='Existing inventory receipt records the actual outcome.', recovery='No persistent device changes; stop the job if needed.'),
    'scan_files': dict(title='Scan the configured folder', permission='approval', effect='Read files in the already configured scan folder.', verification='Existing scan receipt records errors and matches.', recovery='Scan does not delete or quarantine files.'),
    'contain': dict(title='Review temporary local containment', permission='approval', effect='Preview a five-minute block for one eligible public IP on this PC.', verification='Existing defense workflow verifies the firewall entry.', recovery='Automatic timeout or remove the exact entry through the existing rollback control.'),
}
for _key, _row in WORKFLOWS.items():
    _row.update(id=_key,version=1,prerequisites=('Retained evidence' if _row['permission']=='read' else 'Configured scope, local operator approval and existing OS authorization'))

CONTEXT = {
    'OBSERVED_ACTIVITY': ('This address appeared in committed observations.', 'These are sensor-visible exchanges; observation alone does not establish malicious activity.', 'network traffic analysis', 'evidence_summary'),
    'PORT_SCAN': ('Several ports were probed.', 'Inventory tools and health checks can also probe ports.', 'network service discovery scan', 'device_changes'),
    'SYN_FLOOD': ('The existing detector reported a SYN traffic burst.', 'A burst may overload a listener; retransmissions and load tests are alternatives.', 'network denial service flood', 'evidence_summary'),
    'DNS_TUNNELING': ('The existing detector reported unusual DNS query length.', 'Long names can also belong to legitimate services. Payload and resolver context matter.', 'DNS tunneling exfiltration', 'evidence_summary'),
    'NEW_DESTINATION_PORT': ('A destination port was absent from the learned comparison hours.', 'New software, updates or a changed service can explain this. A port does not identify an application.', 'network service discovery', 'device_changes'),
    'PROTOCOL_SHIFT': ('The share of an observed protocol changed.', 'Backups, streaming and upgrades can change the traffic mix.', 'network traffic analysis', 'device_changes'),
    'SERVICE_SHIFT': ('The share of a sensor-reported service changed.', 'A sensor label is an observation, not proof of the installed application.', 'network traffic analysis service', 'device_changes'),
    'REGULAR_INTERVAL': ('Connections recur at similar intervals.', 'Scheduled tasks, health checks and updates commonly do this; timing alone does not establish a beacon.', 'command control application layer protocol', 'device_changes'),
    'PORT_53_BURST': ('Many observations used destination port 53 in one minute.', 'This counts observations, not confirmed DNS queries. Streaming, updates and retries can cause bursts.', 'DNS traffic analysis', 'evidence_summary'),
    'INVENTORY_CHANGE': ('A device or reported service changed in the observed inventory.', 'Discovery can miss sleeping or inaccessible devices; absence is not proof that a device left.', 'asset inventory network discovery', 'device_changes'),
    'AI_MODEL_CHANGE': ('The configured local model identity changed.', 'A deliberate model selection may explain the change.', 'AI model supply chain integrity', 'ai_readiness'),
    'AI_EXPOSURE': ('The local AI admission check could not verify local-only operation.', 'Review which processes and devices can reach the AI service.', 'excessive agency access control', 'ai_readiness'),
    'AI_FAILURES': ('Local AI requests repeatedly failed.', 'Memory pressure, busy models and timeouts are common causes.', 'unbounded consumption resource denial', 'ai_readiness'),
    'REJECTED_TOOL': ('The AI broker rejected a tool request.', 'The permission boundary held. Review the request context before attributing intent.', 'prompt injection excessive agency', 'ai_readiness'),
}


def stable(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:32]


def candidate(rule, key, start, end, facts, references, segments, *, gaps=(), source_start=None):
    if len(set(segments))>MAX_DEPENDENCIES:raise ValueError('Pattern source dependency limit exceeded')
    happened, matters, query, workflow = CONTEXT[rule]
    return dict(id=stable([rule,key,start,facts]), fingerprint=stable([rule,key,facts.get('port'),facts.get('protocol')]),
        rule=rule,label='Unusual activity to review', device=key[0], interface=key[1],sensor=key[2],measurement=key[3],
        start=utc(start),end=utc(end),source_start=utc(start if source_start is None else source_start),
        what_happened=happened,why_it_matters=matters,what_you_can_do=WORKFLOWS[workflow]['title'],
        workflow=workflow,knowledge_query=query,facts=facts,evidence_refs=references[:24],source_segments=sorted(set(segments)),
        missing_information=list(dict.fromkeys(gaps))[:16]+['This sensor cannot establish all traffic between other devices.', 'Traffic patterns do not establish AI involvement.'],
        required_measurements={'PORT_53_BURST':'Per-observation timestamps and destination ports',
            'REGULAR_INTERVAL':'At least five distinct connection start times',
            'NEW_DESTINATION_PORT':'At least 24 compatible, finding-free hourly samples',
            'PROTOCOL_SHIFT':'At least 24 compatible, finding-free hourly samples',
            'SERVICE_SHIFT':'Sensor service labels in at least 24 compatible hourly samples'}.get(rule,'Committed source-qualified observations'),
        state='unreviewed',action_status='not_attempted')


def analyze_hour(rows, start, end, previous, *, gaps=()):
    """Return compact baselines and bounded candidates, never host actions."""
    groups={}; findings=[]; all_gaps=list(gaps)
    # Periodic updates of a flow retain one identity and one connection start.
    unique={};other=[]
    for row in rows[:MAX_RECORDS]:
        data=row['data']
        if row['category']=='flows' and data.get('source_id') is not None and data.get('first_seen'):
            key=(row['source'],data.get('interface'),str(data['source_id']),data['first_seen'],data.get('src_ip'),data.get('dst_ip'))
            if key not in unique or row['observed_at']>unique[key]['observed_at']:unique[key]=row
        else:other.append(row)
    for row in other+list(unique.values()):
        data=row['data'];category=row['category'];source=row['source']
        if category not in {'packets','flows','packet_rollups','findings','network','audit'}:continue
        compacted=category=='packet_rollups' and data.get('kind')=='conversation_v1'
        if category=='packet_rollups' and not compacted:
            if data.get('kind')=='finding_v1':
                rule=data.get('detection',{}).get('rule_id')
                if rule in CONTEXT:
                    event=data.get('event',{})
                    findings.append(candidate(rule,(event.get('src_ip','unknown'),event.get('interface','unreported'),'accepted packet metadata','finding'),start,end,{'preserved_finding':True},[row['id']],[row['id'].split(':')[0]],gaps=all_gaps))
            elif data.get('kind')=='partial_interval':all_gaps.append('Compacted evidence crosses the comparison boundary.')
            continue
        if category in {'network','audit'}:continue
        try:
            device=str(ipaddress.ip_address(data['src_ip']))
            peer=str(ipaddress.ip_address(data['dst_ip']))
        except (KeyError,ValueError,TypeError):
            all_gaps.append('Some source records lack endpoint addresses.');continue
        kind='packet' if category=='packets' or compacted else 'flow' if category=='flows' else 'finding'
        if compacted:source='accepted packet metadata'
        key=(device,str(data.get('interface') or 'unreported'),source,kind)
        if key not in groups:
            if len(groups)>=MAX_GROUPS:
                all_gaps.append('Device grouping limit reached.');continue
            groups[key]=dict(records=[],refs=[],segments=set(),ports=Counter(),protocols=Counter(),services=Counter(),finding=False,times=[])
        group=groups[key]
        if row['id'].split(':')[0] not in group['segments'] and len(group['segments'])>=MAX_DEPENDENCIES:
            all_gaps.append('Source dependency limit reached.');continue
        group['segments'].add(row['id'].split(':')[0]);group['refs'].append(row['id']) if len(group['refs'])<24 else None
        group['times'].append(epoch(row['observed_at']))
        amount=data.get('packet_count',0) if compacted else 1
        if type(amount) is not int or not 1<=amount<=2**53:
            all_gaps.append('Invalid compact packet counter.');continue
        if compacted:
            group['times'].append(epoch(data['last_at']))
            group['timing_limited']=True
        protocol=str(data.get('protocol','unknown')).upper()
        if protocol not in group['protocols'] and len(group['protocols'])>=128:
            all_gaps.append('Protocol grouping limit reached.');continue
        group['protocols'][protocol]+=amount
        port=data.get('dst_port')
        if type(port) is int and 0<=port<=65535 and protocol in {'TCP','UDP'}:
            label=f'{protocol}:{port}'
            if label not in group['ports'] and len(group['ports'])>=256:all_gaps.append('Port grouping limit reached.')
            else:group['ports'][label]+=amount
        service=data.get('app_proto')
        if isinstance(service,str) and len(service)<=64:
            if service in group['services'] or len(group['services'])<128:group['services'][service]+=amount
            else:all_gaps.append('Service grouping limit reached.')
        linked=data.get('findings',[]) if category=='packets' else [data] if category=='findings' else []
        for finding in linked[:32]:
            group['finding']=True
            rule=finding.get('rule_id')
            if rule in CONTEXT and len(findings)<64:
                findings.append(candidate(rule,key,start,end,{'detector':rule,'severity':finding.get('severity')},[row['id']],group['segments'],gaps=all_gaps))
        # Existing pure offline checks take a bounded normalized observation;
        # packet/flow identity remains in the group key and final result.
        if kind=='flow' and (not data.get('source_id') or not data.get('first_seen')):
            all_gaps.append('Connection identity or start time unavailable; cadence cannot be checked.');group['timing_limited']=True
        elif not compacted and len(group['records'])<MAX_GROUP_RECORDS:
            try:
                group['records'].append(PacketEvent(datetime.fromtimestamp(epoch(data['first_seen'] if kind=='flow' else row['observed_at']),timezone.utc),device,peer,protocol,
                    dst_port=port,src_port=data.get('src_port'),byte_count=0))
            except (KeyError,TypeError,ValueError):all_gaps.append('Incomplete port or protocol fields were excluded.')
        else:group['timing_limited']=True
    if len(rows)>MAX_RECORDS:all_gaps.append('Hourly read limit reached.')
    all_gaps=list(dict.fromkeys(all_gaps))[:16]
    baselines=[];results=findings[:64]
    affected={key[0] for key,g in groups.items() if g['finding']}|{f['device'] for f in findings}
    for key,group in groups.items():
        key=list(key)
        compatible=[p for p in previous if p.get('key')==key and p.get('eligible')
                    and start-7*86400<=p['start']<start]
        # Deduplicate a repeated import or interrupted hourly pass.
        compatible=list({p['start']:p for p in compatible}.values())
        samples=len(compatible)
        count=sum(group['protocols'].values())
        contaminated=key[0] in affected
        eligible=not all_gaps and not contaminated and count>=20 and max(group['times'])-min(group['times'])>=3000
        baseline=dict(id=stable([key,start]),key=key,start=start,end=end,eligible=eligible,
            count=count,protocols=dict(group['protocols']),ports=dict(group['ports']),services=dict(group['services']),
            source_segments=sorted(group['segments']),gaps=all_gaps,
            exclusion='Finding-associated hour' if contaminated else 'Insufficient coverage' if not eligible else None)
        if len(json.dumps(baseline).encode())>28000:
            baseline.update(eligible=False,ports={},protocols={},services={},exclusion='Baseline size limit')
            all_gaps.append('An oversized distribution was omitted from learning.')
        baselines.append(baseline)
        batch=Batch('retained-'+key[3],key[3],tuple(group['records']),count,0,0,'v1','committed evidence')
        try:checks=[] if group.get('timing_limited') else offline_candidates(batch)
        except OfflineError:
            checks=[];all_gaps.append('Heuristic candidate limit reached; existing findings remain available.')
            baseline['eligible']=False;baseline['exclusion']='Heuristic work limit'
        for check in checks:
            # Packet timing often measures ACK/retry cadence, not connection
            # starts. Require connection summaries for beacon-like cadence.
            if check['rule']=='REGULAR_INTERVAL' and key[3]!='flow':continue
            if len(results)>=64:break
            results.append(candidate(check['rule'],key,start,end,check['evidence'],group['refs'],group['segments'],gaps=all_gaps))
        if samples<MIN_SAMPLES or not baseline['eligible']:continue
        known={port for sample in compatible for port in sample['ports']}
        source_start=min(p['start'] for p in compatible)
        segments=set(group['segments'])|{s for p in compatible for s in p['source_segments']}
        if len(segments)>MAX_DEPENDENCIES:
            all_gaps.append('Comparison source dependency limit reached.');continue
        for port,n in group['ports'].items():
            if port not in known and n>=5 and len(results)<64:
                protocol,number=port.split(':')
                results.append(candidate('NEW_DESTINATION_PORT',key,start,end,dict(protocol=protocol,port=int(number),observations=n,eligible_hours=samples),
                    group['refs'],segments,source_start=source_start))
        for field,rule in [('protocols','PROTOCOL_SHIFT'),('services','SERVICE_SHIFT')]:
            prior=Counter()
            for sample in compatible:prior.update(sample.get(field,{}))
            total=sum(prior.values());current=sum(group[field].values())
            if not total or not current:continue
            for label,n in group[field].items():
                shift=round(100*(n/current-prior[label]/total),1)
                if n>=5 and abs(shift)>=20 and len(results)<64:
                    results.append(candidate(rule,key,start,end,dict(label=label,share_change_points=shift,observations=n,eligible_hours=samples),
                        group['refs'],segments,source_start=source_start))
    all_gaps=list(dict.fromkeys(all_gaps))[:16]
    for baseline in baselines:baseline['gaps']=all_gaps
    return baselines,results,all_gaps


def inventory_hour(rows,start,end,previous):
    """Compare observed inventory snapshots; never infer departure or traffic."""
    groups={};baselines=[];changes=[]
    for row in rows:
        if row['category']!='network':continue
        node=row['data'].get('node',{});address=node.get('ip')
        try:address=str(ipaddress.ip_address(address))
        except (TypeError,ValueError):continue
        key=('inventory',node.get('interface','unreported'),row['source'],'inventory')
        if key not in groups:
            if len(groups)>=32:continue
            groups[key]=dict(devices={},segments=set(),limited=False)
        group=groups[key]
        if address not in group['devices'] and len(group['devices'])>=128:
            group['limited']=True;continue
        services=sorted({str(v.get('name',''))[:64] for v in node.get('services',[]) if isinstance(v,dict)})[:16]
        group['devices'][address]=dict(services=services,reference=row['id'])
        group['segments'].add(row['id'].split(':')[0])
    for key,group in groups.items():
        priors=[p for p in previous if p['key']==list(key) and start-7200<=p['start']<start and 'devices' in p]
        prior=max(priors,key=lambda p:p['start']) if priors else None
        if len(group['segments'])>MAX_DEPENDENCIES:continue
        segments=sorted(group['segments'])
        base=dict(id=stable([key,start]),key=list(key),start=start,end=end,eligible=False,count=len(group['devices']),
                  devices=group['devices'],source_segments=segments,ports={},protocols={},services={},gaps=['Inventory snapshots do not measure all device traffic.'])
        # Keep each managed row bounded on large networks. A truncated group
        # remains useful as inventory but cannot generate change candidates.
        if len(json.dumps(base).encode())>28000:continue
        baselines.append(base)
        if not prior or group['limited']:continue
        dependencies=sorted(set(segments)|set(prior['source_segments']))
        if len(dependencies)>MAX_DEPENDENCIES:continue
        for address,current in group['devices'].items():
            old=prior['devices'].get(address)
            if old is None or old['services']!=current['services']:
                facts=dict(change='Newly observed device' if old is None else 'Observed service labels changed',
                           previous_services=old['services'] if old else [],observed_services=current['services'])
                changes.append(candidate('INVENTORY_CHANGE',(address,key[1],key[2],key[3]),start,end,facts,
                    [current['reference']]+([old['reference']] if old else []),dependencies,
                    source_start=prior['start'],gaps=['Discovery and service observations can be incomplete.']))
                if len(changes)>=32:break
    return baselines,changes
