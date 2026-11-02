"""Only observations inside the exact displayed connections may name a program."""
import json
import time
import os
from pathlib import Path
import socket

import pytest

from megalodon.connection_program import ConnectionPrograms
from megalodon.evidence_storage import utc
from megalodon.flow_ingestion import FlowIngestor, normalize_zeek, normalize_suricata
from megalodon.intelligence import IntelligenceService
from test_findings_review import service


def zeek(start, i):
    return {'ts': start, 'duration': 1, 'uid': f'C{i}', 'proto': 'tcp',
            'id.orig_h': '127.0.0.1', 'id.orig_p': 50000 + i, 'id.resp_h': '127.0.0.1',
            'id.resp_p': 8000, 'local_tcp_holder': {'name': 'spoofed', 'begin': utc(start), 'end': utc(start+1)}}


def test_exact_tuple_lifetime_clock_and_holder_are_all_required():
    now = time.time()
    source = ConnectionPrograms()
    record = normalize_zeek(zeek(now-5, 0))[1]['data']
    assert 'local_tcp_holder' not in record
    key = ('127.0.0.1', 50000, '127.0.0.1', 8000)
    def sample(at, cookie=1, names=('python',)):
        source.samples.append((at, at+.05, {key:(cookie,names)}))
    sample(now-4.7)
    assert source.match(record)['name'] == 'python'
    for change in ({'src_port':50001}, {'dst_ip':'127.0.0.2'}, {'last_seen':utc(now-4.8)},
                   {'first_seen':utc(now-4.6)}, {'protocol':'UDP'}):
        assert source.match({**record, **change}) is None
    sample(now-4.4, 2)
    assert source.match(record) is None
    source.clear()
    sample(now-4.7, names=('python','other'))
    assert source.match(record) is None
    source.clear()
    sample(now-150)
    assert source.match({**record,'first_seen':utc(now-200)}) is None
    assert normalize_suricata(dict(timestamp=utc(now), event_type='flow', proto='TCP',
        src_ip=key[0], src_port=key[1], dest_ip=key[2], dest_port=key[3], flow_id=1,
        local_tcp_holder={'name':'forged'}, flow=dict(start=utc(now-5), end=utc(now),
        bytes_toserver=0, bytes_toclient=0, pkts_toserver=1, pkts_toclient=1)))[1]['data'].get('local_tcp_holder') is None


def test_stored_flow_to_selected_finding_survives_missing_observation(service, monkeypatch):
    start = int(service.clock()//3600-1)*3600
    service.evidence.apply(service.evidence.preview(dict(profile='server',retention_days=14,cap_bytes=1024**3))['preview_id'])
    programs = ConnectionPrograms()
    now = start+30
    monkeypatch.setattr('megalodon.connection_program.time.time',lambda:now)
    records = []
    for i in range(5):
        raw = zeek(start+3*i, i)
        row = normalize_zeek(raw)[1]
        records.append(row)
        key = (raw['id.orig_h'],raw['id.orig_p'],raw['id.resp_h'],raw['id.resp_p'])
        t = raw['ts'] + (.2 if i<4 else 1.1)
        programs.samples.append((t,t+.05,{key:(i,('python',))}))
    ingestor = FlowIngestor(service.evidence, programs=programs)
    ingestor._commit('zeek','flows',records,{'offset':1})
    programs.clear()
    intel = IntelligenceService(service.evidence,None,service.configuration,clock=service.clock)
    service.intelligence=intel
    try:
        intel.process_hour(start)
        finding = next(item for item in service.snapshot()['items'] if item['title']=='Regular Interval')
        result = service.snapshot(selected=finding['id'])['selected']
        assert result['cadence_connection'] == dict(destination='127.0.0.1', programs={'python':4}, checked=5)
        assert result['facts']['recorded_evidence']['median_interval_us'] == 3000000
        assert 'python' not in json.dumps(result['facts'])
        assert not service.defense.calls
    finally:
        intel.close()


@pytest.mark.skipif(os.environ.get('MEGALODON_TEST_NATIVE_HOLDER')!='1', reason='explicit native Linux socket check')
def test_linux_open_socket_through_sensor_storage_and_findings(service, private_tmp_path):
    # Hold real sockets open during checks 1–4. Check the fifth only after close.
    # These sensor-format rows use the fixture's actual local addresses, ports and clocks.
    assert os.getuid() != 0
    remaining = 3600-time.time()%3600
    if remaining<18:time.sleep(remaining+.1)
    service.evidence.apply(service.evidence.preview(dict(profile='server',retention_days=14,cap_bytes=1024**3))['preview_id'])
    programs = ConnectionPrograms()
    worker = FlowIngestor(service.evidence, programs=programs)
    worker.paths['zeek'] = private_tmp_path/'conn.log'
    observed = []
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1',0))
        listener.listen(1)
        listener.settimeout(2)
        origin=time.monotonic()
        for i in range(5):
            time.sleep(max(0,origin+3*i-time.monotonic()))
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(listener.getsockname())
                peer, (address, port) = listener.accept()
                with peer:
                    begin=time.time()
                    if i<4:programs.sample()
                    end=time.time()
                row=zeek(begin,i)
                row.update({'duration':end-begin,'id.orig_h':address,'id.orig_p':port,
                            'id.resp_p':listener.getsockname()[1]})
                observed.append(row)
            if i==4:programs.sample()
    worker.paths['zeek'].write_text(''.join(json.dumps(row)+'\n' for row in observed))
    assert worker.poll('zeek')==5
    programs.clear()
    # Move only the disposable analysis clock forward to close the measured hour.
    start=int(observed[0]['ts']//3600)*3600
    service.test_clock[0]=start+3601
    intel=IntelligenceService(service.evidence,None,service.configuration,clock=service.clock)
    service.intelligence=intel
    try:
        intel.process_hour(start)
        alert=next(item for item in service.snapshot()['items'] if item['title']=='Regular Interval')
        detail=service.snapshot(selected=alert['id'])['selected']
        name=Path('/proc/self/exe').resolve().name
        assert detail['cadence_connection']==dict(destination='127.0.0.1',programs={name:4},checked=5)
        assert detail['facts']['recorded_evidence']['unique_observations']==5
        assert not service.defense.calls
        print(f'Findings: {name} observed on 4 of 5 local TCP connections; program unknown on the fifth.')
    finally:
        intel.close()
