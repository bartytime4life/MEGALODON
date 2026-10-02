from datetime import datetime,timezone,timedelta
import json
from types import SimpleNamespace

import pytest
from megalodon.config import Settings
from megalodon.live_connections import LiveConnections
from megalodon.models import PacketEvent
from megalodon.operations import Operations,recent_context,address_scope


def test_observed_endpoint_directions_flags_timeline_and_storage(tmp_path):
    geo=SimpleNamespace(snapshot=lambda:{'anchor':None},lookup=lambda ip:None)
    cache=LiveConnections(geo)
    cache._local={'10.0.0.2'}
    for src,dst,sport,dport,size in [('10.0.0.2','1.1.1.1',54321,443,100),('1.1.1.1','10.0.0.2',443,54321,250)]:
        cache.observe(PacketEvent(datetime.now(timezone.utc),src,dst,'TCP',sport,dport,byte_count=size,tcp_flags=frozenset({'ACK'})))
    config=SimpleNamespace(settings=Settings(db_path=tmp_path/'absent.db'),live_snapshot=lambda:cache.snapshot({'state':'running'},{}))
    operations=Operations(config,context_reader=lambda:{})
    result=operations.snapshot()
    assert result['summary']['sent_bytes']==100 and result['summary']['received_bytes']==250
    assert result['summary']['packets']==2
    assert sum(p['packets'] for p in result['timeline'])==2
    remote=operations.endpoint('1.1.1.1')
    assert remote['sent_bytes']==250 and remote['received_bytes']==100
    assert remote['flags']==['ACK'] and remote['ports']==[dict(protocol='TCP',port=443,hint='HTTPS')]
    assert remote['location'] is None
    assert result['coverage']['unmapped']==1


def test_dns_questions_do_not_attribute_names_to_dns_server(tmp_path):
    path=tmp_path/'eve'
    stamp=datetime.now(timezone.utc).isoformat()
    rows=[dict(timestamp=stamp,event_type='dns',src_ip='10.0.0.2',dest_ip='1.1.1.1',dns={'rrname':'site.example','type':'query'}),
          dict(timestamp=stamp,event_type='dns',dns={'answers':[{'rrtype':'A','rrname':'site.example','rdata':'8.8.8.8'}]}),
          dict(timestamp=stamp,event_type='tls',dest_ip='8.8.8.8',tls={'sni':'secure.example'}),
          dict(timestamp=stamp,event_type='tls',dest_ip='8.8.4.4',tls={'sni':'<script>bad</script>'}),
          dict(timestamp=(datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat(),event_type='tls',dest_ip='4.4.4.4',tls={'sni':'old.example'})]
    path.write_text('\n'.join(json.dumps(r) for r in rows)+'\n')
    context=recent_context(path)
    assert not context['1.1.1.1']['names'] and context['1.1.1.1']['services'][0]['name']=='dns'
    assert '4.4.4.4' not in context and '8.8.4.4' not in context
    assert {n['name'] for n in context['8.8.8.8']['names']}=={'site.example','secure.example'}
    assert all(n['observed_at'].endswith('Z') for n in context['8.8.8.8']['names'])
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(OSError):recent_context(link)


def test_source_qualified_summary_protocol_reaches_endpoint_without_inventing_app(tmp_path):
    from megalodon.flow_ingestion import normalize_zeek
    stamp=datetime.now(timezone.utc).timestamp()-1
    row={'ts':stamp,'uid':'one','id.orig_h':'10.0.0.2','id.resp_h':'10.0.0.3',
         'id.orig_p':54321,'id.resp_p':443,'proto':'tcp','service':'ssl','duration':0,
         'orig_bytes':100,'resp_bytes':250,'orig_pkts':1,'resp_pkts':2}
    cache=LiveConnections(SimpleNamespace(snapshot=lambda:{'anchor':None},lookup=lambda ip:None))
    cache._local={'10.0.0.3'}
    cache.observe_summary(normalize_zeek(row)[1])
    config=SimpleNamespace(settings=Settings(db_path=tmp_path/'absent.db'),live_snapshot=lambda:cache.snapshot({'state':'running'},{}))
    result=Operations(config,context_reader=lambda:{}).snapshot()
    assert result['summary']['bytes']==350
    for endpoint in result['endpoints']:
        assert endpoint['services'][0]['name']=='ssl'
        assert 'zeek' in endpoint['services'][0]['source']
        assert endpoint['services'][0]['role']=='observed endpoint'
        assert not endpoint['names']


@pytest.mark.parametrize('ip,scope',[('224.0.0.1','Multicast'),('::1','Loopback'),('fe80::1','Link local'),('0.0.0.0','Unspecified'),('10.0.0.1','Private / reserved'),('1.1.1.1','Public')])
def test_address_classification_is_not_a_threat_rating(ip,scope):
    assert address_scope(ip)==scope
