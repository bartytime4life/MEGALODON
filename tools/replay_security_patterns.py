#!/usr/bin/env python3
"""Finite synthetic pattern adapter replay; no sockets, files or attack execution."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from megalodon.evidence_storage import utc
from megalodon.security_patterns import analyze_hour

START=1790726400
SEGMENT='a'*32

def observations(start=START, *, port=443, category='flows', protocol='TCP', regular=True, count=60):
    return [dict(id=f'{SEGMENT}:{i+1}',category=category,source='synthetic-sensor',observed_at=utc(start+i*59),
        data=dict(src_ip='192.0.2.1',dst_ip='198.51.100.1',interface='fixture0',protocol=protocol,
                  src_port=45000,dst_port=port,source_id=str(i),first_seen=utc(start+i*59 if regular else start+i*i)))
        for i in range(count)]

def main():
    history=[]
    for h in range(24):
        base,_,_=analyze_hour(observations(START+h*3600,regular=False),START+h*3600,START+(h+1)*3600,[])
        history+=base
    current=START+24*3600
    scenarios=[('ordinary backup','ordinary',observations(current),[]),
        ('ordinary streaming packets','ordinary',observations(current,category='packets'),[]),
        ('ordinary software update using a new port','ordinary',observations(current,port=8443,regular=False),history),
        ('ordinary scheduled health check','ordinary',observations(current),[]),
        ('suspicious recurring connections','suspicious',observations(current),[]),
        ('suspicious new destination port','suspicious',observations(current,port=4444,regular=False),history)]
    # These fixtures verify transport of existing detector findings, not the
    # accuracy of the packet detector that originally produced those findings.
    for rule in ('PORT_SCAN','SYN_FLOOD','DNS_TUNNELING'):
        rows=observations(current,category='packets');rows[0]['data']['findings']=[dict(rule_id=rule,severity='HIGH')]
        scenarios.append(('existing '+rule,'finding adapter',rows,[]))
    output=[]
    for name,label,rows,prior in scenarios:
        _,reviews,gaps=analyze_hour(rows,current,current+3600,prior)
        output.append(dict(scenario=name,label=label,rules=sorted({r['rule'] for r in reviews}),
                           candidate_count=len(reviews),coverage_gaps=gaps))
        assert all(r['action_status']=='not_attempted' for r in reviews)
    ordinary=[r for r in output if r['label']=='ordinary']
    print(json.dumps(dict(scenarios=output,ordinary_flagged=sum(bool(r['rules']) for r in ordinary),ordinary_total=len(ordinary),
        limit='Hand-built cases, not a representative dataset. Candidate flags are not attack verdicts; this does not estimate production false-positive or detection rates.'),indent=2))

if __name__=='__main__':main()
