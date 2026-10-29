"""Conflicting synthetic connection identities cannot manufacture reviews."""
from copy import deepcopy
import json
from unittest.mock import patch

import pytest

from megalodon.evidence_storage import utc
from megalodon.security_patterns import analyze_hour

START = 1790812800
SEGMENT = 'a' * 32


def rows(count=16, *, source='synthetic-sensor', interface='fixture0', device='192.0.2.1'):
    return [dict(id=f'{SEGMENT}:{i+1}', category='flows', source=source,
                 observed_at=utc(START+i), data=dict(src_ip=device,
                     dst_ip=f'198.51.100.{i+1}', src_port=40000, dst_port=445,
                     protocol='TCP', interface=interface, source_id=f'flow{i}',
                     first_seen=utc(START+i))) for i in range(count)]


def analyze(values):
    return analyze_hour(values, START, START+3600, [])


def fanout(values):
    return [item for item in analyze(values)[1] if item['rule']=='HOST_FANOUT']


def colliding():
    values=rows()
    for row in values:
        row['data'].update(source_id='same-connection',first_seen=utc(START))
    return values


def test_one_identity_with_sixteen_peers_is_not_sixteen_connections():
    values=colliding()
    before=deepcopy(values)
    baselines,reviews,gaps=analyze(values)
    assert not reviews
    assert not baselines
    assert any('Conflicting connection identities' in gap for gap in gaps)
    assert values==before


@pytest.mark.parametrize('field,value', [('src_ip','192.0.2.2'), ('dst_ip','198.51.100.250'),
    ('src_port',40001), ('dst_port',443), ('protocol','UDP')])
@pytest.mark.parametrize('reverse', [False,True])
def test_all_versions_of_a_conflicting_tuple_are_excluded(field,value,reverse):
    values=rows()
    duplicate=deepcopy(values[0])
    duplicate['id']=SEGMENT+':changed'
    duplicate['observed_at']=utc(START+100)
    duplicate['data'][field]=value
    values.append(duplicate)
    if reverse:values.reverse()
    baselines,_,gaps=analyze(values)
    assert not fanout(values)
    assert sum(base['count'] for base in baselines)==15
    assert all(not base['eligible'] for base in baselines)
    assert any('Conflicting connection identities' in gap for gap in gaps)


def test_a_conflict_never_trains_the_hour_but_other_supported_reviews_survive():
    values=colliding()
    healthy=rows(60,device='192.0.2.2')
    for i,row in enumerate(healthy):
        row['id']=SEGMENT+':healthy'+str(i)
        row['data']['source_id']='healthy'+str(i)
        row['observed_at']=utc(START+i*59)
    values+=healthy
    baselines,reviews,gaps=analyze(values)
    assert baselines and all(not base['eligible'] for base in baselines)
    review=next(item for item in reviews if item['rule']=='HOST_FANOUT')
    assert review['device']=='192.0.2.2'
    assert review['action_status']=='not_attempted'
    assert any('Conflicting connection identities' in gap for gap in review['missing_information'])
    assert set(review['evidence_refs'])=={row['id'] for row in healthy[:16]}


def test_periodic_counters_and_service_refinement_do_not_change_identity():
    values=rows()
    updates=deepcopy(values)
    for i,row in enumerate(updates):
        row['id']=SEGMENT+':updated'+str(i)
        row['observed_at']=utc(START+100)
        row['data'].update(sent_bytes=10000,received_bytes=20000,completed=True,
                           last_seen=utc(START+100),app_proto='tls')
    baselines,reviews,gaps=analyze(values+updates)
    assert not gaps
    assert sum(base['count'] for base in baselines)==16
    review=next(item for item in reviews if item['rule']=='HOST_FANOUT')
    assert set(review['evidence_refs'])=={row['id'] for row in updates}


def test_identity_is_scoped_to_sensor_interface_and_connection_start():
    original=rows(1)[0]
    values=[original]
    for field,value in [('source','another-sensor'),('interface','another0'),
                        ('first_seen',utc(START+1))]:
        item=deepcopy(original)
        item['id']=SEGMENT+':'+field
        item['data']['dst_ip']='198.51.100.250'
        (item if field=='source' else item['data'])[field]=value
        values.append(item)
    baselines,_,gaps=analyze(values)
    assert not gaps
    assert sum(base['count'] for base in baselines)==4


def test_equivalent_utc_spelling_and_normalized_tuple_are_one_identity():
    original=rows(1)[0]
    original['data'].update(src_ip='2001:db8::1',dst_ip='2001:db8::2')
    update=deepcopy(original)
    update['id']=SEGMENT+':update'
    update['observed_at']=utc(START+10)
    update['data'].update(first_seen='2026-09-30T19:00:00-05:00',
                          src_ip='2001:0DB8:0:0:0:0:0:1',protocol='tcp')
    baselines,_,gaps=analyze([original,update])
    assert not gaps
    assert sum(base['count'] for base in baselines)==1


@pytest.mark.parametrize('identity', [[],{},True,1.5,-1,2**64,'',' '*4,'x'*65,'line\nbreak'])
def test_invalid_identity_cannot_complete_a_fanout(identity):
    values=rows()
    values[0]['data']['source_id']=identity
    assert not fanout(values)
    assert analyze(values)[2]


@pytest.mark.parametrize('first_seen', [[],{},['unhashable'],{'unhashable':True},
                                      'bad-time','2026-10-01T00:00:00',
                                      '2026-10-01T00:00:00Z'+'x'*64])
def test_invalid_start_time_is_bounded_refusal_not_a_crash(first_seen):
    values=rows()
    values[0]['data']['first_seen']=first_seen
    assert not fanout(values)
    assert analyze(values)[2]


def test_conflict_processing_has_no_external_work_or_diagnostic_data_leak():
    values=colliding()
    def forbidden(*args,**kwargs):raise AssertionError('external work attempted')
    with patch('socket.socket',forbidden),patch('socket.getaddrinfo',forbidden), \
         patch('subprocess.Popen',forbidden),patch('sqlite3.connect',forbidden), \
         patch('builtins.open',forbidden),patch('os.open',forbidden):
        _,reviews,gaps=analyze(values)
    assert not reviews
    encoded=json.dumps(gaps)
    for private in ['same-connection','192.0.2.1','198.51.100.1',SEGMENT]:
        assert private not in encoded


def test_existing_packet_detector_evidence_survives_conflicting_flows():
    values=colliding()
    packet=rows(1)[0]
    packet.update(category='packets',source='accepted packet metadata',id=SEGMENT+':packet')
    packet['data']['findings']=[dict(rule_id='PORT_SCAN',severity='MEDIUM')]
    _,reviews,gaps=analyze(values+[packet])
    assert [item['rule'] for item in reviews]==['PORT_SCAN']
    assert reviews[0]['evidence_refs']==[packet['id']]
    assert reviews[0]['action_status']=='not_attempted' and gaps


def test_same_time_consistent_updates_choose_the_same_reference_in_both_orders():
    original=rows(1)[0]
    update=deepcopy(original)
    update['id']=SEGMENT+':z-update'
    for values in ([original,update],[update,original]):
        baselines,_,gaps=analyze(values)
        assert not gaps and baselines[0]['count']==1
    # Full fanout references exercise deterministic representative selection.
    rest=rows()[1:]
    assert fanout([original,update]+rest)==fanout([update,original]+rest)


@pytest.mark.parametrize('conflict',[True,False])
def test_identity_warning_survives_a_full_incoming_warning_budget(conflict):
    values=colliding() if conflict else rows()
    if not conflict:values[0]['data']['source_id']='x'*65
    baselines,_,gaps=analyze_hour(values,START,START+3600,[],
        gaps=[f'Existing source gap {i}' for i in range(16)])
    expected='Conflicting connection identities' if conflict else 'Invalid connection identities'
    assert gaps[0].startswith(expected) and len(gaps)<=16
    assert all(not base['eligible'] for base in baselines)
