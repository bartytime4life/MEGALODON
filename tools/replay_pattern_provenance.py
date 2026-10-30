#!/usr/bin/env python3
"""Synthetic, finite timing-review replay; no model, collector or host effects."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.evidence_storage import utc
from megalodon.security_patterns import analyze_hour

START = 1790812800
SEGMENT = 'a' * 32


def rows(count, *, port, offset, first_number=1):
    return [dict(id=f'{SEGMENT}:{first_number+i}', category='flows',
        source='synthetic-sensor', observed_at=utc(START+max(0,offset)+i),
        data=dict(src_ip='192.0.2.1',dst_ip='198.51.100.1',protocol='TCP',
            src_port=40000,dst_port=port,interface='fixture0',
            source_id=f'flow-{first_number+i}',first_seen=utc(START+offset+i))) for i in range(count)]


def main():
    results=[]
    for rule,port,count in [('REGULAR_INTERVAL',443,5),('PORT_53_BURST',53,20)]:
        old=rows(count,port=port,offset=-3600)
        noise=rows(30,port=80,offset=0,first_number=101)
        for i,value in enumerate(noise):
            value['observed_at']=value['data']['first_seen']=utc(START+i*i)
        support=rows(count,port=port,offset=1800,first_number=201)
        for name,values,expected in [('old starts updated now',old,[]),
                ('late supported activity',noise+support,[r['id'] for r in support]),
                ('old and current activity',old+support,[r['id'] for r in support])]:
            checks=analyze_hour(values,START,START+3600,[])[1]
            checks=[c for c in checks if c['rule']==rule]
            assert len(checks)==bool(expected)
            if expected:
                assert checks[0]['evidence_refs']==expected
                assert checks[0]['facts']['first_seen']==utc(START+1800)
                assert checks[0]['action_status']=='not_attempted'
            results.append(dict(rule=rule,scenario=name,status='passed'))
    print(json.dumps(dict(schema='megalodon-pattern-provenance-replay-v1',results=results,
        limitation='Synthetic evidence-link checks; no measured detection accuracy or operational acceptance.'),indent=2))


if __name__=='__main__':
    main()
