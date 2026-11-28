from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from megalodon import support_sensors as sensor
from megalodon.support_workflows import snapshot


def test_zeek_counts_stay_flows_and_reverse_observations():
    rows=[dict(ts=1,proto='tcp',orig_pkts=5,resp_pkts=3),dict(ts=2,proto='udp',orig_pkts=1,resp_pkts=0)]
    metrics=sensor.summarize_zeek(b'\n'.join(json.dumps(r).encode() for r in rows))
    assert [m['value'] for m in metrics]==[2,1,1,1]
    with pytest.raises(ValueError): sensor.summarize_zeek(b'x'*(sensor.MAX_LOG+1))


@pytest.mark.parametrize('row', [
    dict(ts=1,proto=[]), dict(ts=1,proto={}), dict(ts=1,proto=1),
    dict(ts=1,proto=None), dict(ts=1,proto=True),
    dict(ts=float('nan'),proto='tcp'), dict(ts=float('inf'),proto='tcp'),
    dict(ts=float('-inf'),proto='tcp'), dict(ts=-1,proto='tcp'),
    dict(ts=10**100,proto='tcp'), dict(ts=True,proto='tcp'),
])
def test_zeek_summary_refuses_malformed_fields(row):
    with pytest.raises(ValueError):
        sensor.summarize_zeek(json.dumps(row).encode())


def test_zeek_summary_refuses_deep_json_as_a_data_error():
    with pytest.raises(ValueError):
        sensor.summarize_zeek(b'['*10000+b'0'+b']'*10000)


def test_zeek_summary_checks_row_bound_before_parsing(monkeypatch):
    def forbidden(*args,**kwargs):
        pytest.fail('Oversized row count reached the JSON parser')
    monkeypatch.setattr(sensor.json,'loads',forbidden)
    with pytest.raises(ValueError):
        sensor.summarize_zeek(b'{}\n'*4001)


def test_zeek_summary_preserves_other_protocols_and_missing_packet_counts():
    rows=[dict(ts=0,proto='icmp'),dict(ts=1,proto='other'),dict(ts=253402300799),
          dict(ts=2.5,proto='tcp',orig_pkts=1,resp_pkts=1)]
    metrics=sensor.summarize_zeek(b'\n'.join(json.dumps(row).encode() for row in rows))
    assert [metric['value'] for metric in metrics]==[4,1,1,0]
    assert [metric['value'] for metric in sensor.summarize_zeek(b'')]==[0,0,0,0]


@pytest.mark.parametrize('corrupt', [
    json.dumps(dict(ts=1,proto=[])).encode(),
    json.dumps(dict(ts=float('nan'),proto='tcp')).encode(),
    b'['*10000+b'0'+b']'*10000,
],ids=['protocol-shape','nonfinite-time','deep-json'])
def test_zeek_bad_sample_reports_error_cleans_up_and_allows_explicit_retry(tmp_path,monkeypatch,corrupt):
    sampler=sensor.SupportSensors(tmp_path)
    sampler.root.mkdir(parents=True)
    sampler._publish('zeek',state='connected',updated_at='old sample',metrics=[sensor.metric('Old',1)])
    forwarded=[];retained=[];reservations=[];waited=[]
    valid=json.dumps(dict(ts=1,proto='tcp',orig_pkts=1,resp_pkts=1)).encode()
    # A valid prefix must not escape from a sample whose later row is corrupt.
    samples=iter((valid+b'\n'+corrupt,valid))
    @contextmanager
    def reserve(amount):
        reservations.append('enter')
        try:yield
        finally:reservations.append('exit')
    sampler.evidence=SimpleNamespace(enabled=True,working_reservation=reserve,
        append_records=lambda *args:retained.append(args))
    sampler.flow_ingestor=SimpleNamespace(ingest_zeek_sample=lambda *args,**kw:forwarded.append((args,kw)))
    monkeypatch.setattr(sensor,'zeek_binary',lambda home:'/fake/zeek')
    monkeypatch.setattr(sensor,'_run_fixed',lambda *args:(b'bounded pcap header data!!',0))
    monkeypatch.setattr(sampler._stop,'wait',lambda interval:True)
    class Process:
        returncode=0
        def __init__(self,argv,**kwargs):self.directory=Path(kwargs['cwd'])
        def communicate(self,**kwargs):(self.directory/'conn.log').write_bytes(next(samples))
        def poll(self):return 0
        def wait(self):waited.append(self.directory);return 0
    monkeypatch.setattr(sensor.subprocess,'Popen',Process)

    sampler._zeek('eth0')
    failed=sampler.snapshot()['zeek']
    assert failed['state']=='error' and failed['metrics']==[] and failed['updated_at'] is None
    assert 'Retry background tools' in failed['message']
    assert not forwarded and not retained
    assert sampler._decoder is None and not list(sampler.root.iterdir())
    assert reservations==['enter','exit'] and len(waited)==1

    # The existing explicit background-tools retry starts a fresh worker after error.
    sampler._zeek('eth0')
    recovered=sampler.snapshot()['zeek']
    assert recovered['state']=='connected' and recovered['updated_at'] is not None
    assert [metric['value'] for metric in recovered['metrics']]==[1,1,1,0]
    assert len(forwarded)==len(retained)==1 and forwarded[0][0][0]==valid
    assert sampler._decoder is None and not list(sampler.root.iterdir())
    assert reservations==['enter','exit','enter','exit'] and len(waited)==2


def test_eve_tail_excludes_stale_future_and_incomplete_records(tmp_path):
    path=tmp_path/'eve.json'
    now=datetime.now(timezone(timedelta(hours=-5)))
    def row(delta,kind):
        return json.dumps(dict(timestamp=(now+timedelta(seconds=delta)).isoformat(),event_type=kind))+'\n'
    path.write_text(row(0,'alert')+row(-300,'alert')+row(300,'flow')+row(0,'dns')+'{"partial":')
    stamp,metrics=sensor.read_eve(path)
    assert stamp.endswith('Z') and [m['value'] for m in metrics][:4]==[2,1,0,1]
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(OSError): sensor.read_eve(link)


def test_eve_tail_skips_a_deeply_nested_line(tmp_path):
    path=tmp_path/'eve.json'
    now=datetime.now(timezone.utc).isoformat()
    # One corrupt line must not end the summary thread with a stale "connected".
    path.write_text(json.dumps(dict(timestamp=now,event_type='alert'))+'\n'+'['*200000+'\n')
    stamp,metrics=sensor.read_eve(path)
    assert stamp is not None and metrics[0]['value']==1


def test_zeek_pipeline_is_bounded_headless_and_does_not_save_raw_capture(tmp_path,monkeypatch):
    sampler=sensor.SupportSensors(tmp_path)
    sampler.root.mkdir(parents=True)
    monkeypatch.setattr(sensor,'zeek_binary',lambda home:'/known/zeek')
    commands=[];forwarded=[];retained=[];reservation=[]
    @contextmanager
    def reserve(amount):
        reservation.append(('enter',amount))
        try:yield
        finally:reservation.append(('exit',amount))
    sampler.evidence=SimpleNamespace(enabled=True,working_reservation=reserve,append_records=lambda category,rows:retained.append((category,rows)))
    sampler.flow_ingestor=SimpleNamespace(ingest_zeek_sample=lambda raw,**scope:forwarded.append((raw,scope)))
    def capture(argv,limit,timeout,cancel):
        commands.append(argv)
        assert limit==2*1024*1024 and timeout==15
        return b'bounded pcap header data!!',0
    monkeypatch.setattr(sensor,'_run_fixed',capture)
    class Process:
        returncode=0
        def __init__(self,argv,**kw):
            commands.append(argv); self.directory=Path(kw['cwd'])
            assert kw['env']['HOME']==kw['cwd']
        def communicate(self,input,timeout):
            assert input==b'bounded pcap header data!!' and timeout==20
            (self.directory/'conn.log').write_text(json.dumps(dict(ts=1,proto='tcp',orig_pkts=1,resp_pkts=1)))
        def poll(self): return 0
        def wait(self): return 0
    monkeypatch.setattr(sensor.subprocess,'Popen',Process)
    monkeypatch.setattr(sampler._stop,'wait',lambda interval:True)
    sampler._zeek('eth0')
    assert sampler.snapshot()['zeek']['state']=='connected'
    assert not list(sampler.root.iterdir())
    assert commands[0][0]=='/usr/bin/dumpcap' and '-p' in commands[0]
    assert commands[1][1:3]==['-r','-']
    assert len(forwarded)==1 and json.loads(forwarded[0][0])['proto']=='tcp'
    assert forwarded[0][1]['interface']=='eth0' and len(forwarded[0][1]['sample_id'])==32
    assert forwarded[0][1]['started_at']<=forwarded[0][1]['finished_at']
    assert b'bounded pcap' not in forwarded[0][0]
    assert reservation==[('enter',4*1024**2),('exit',4*1024**2)]
    assert retained[0][0]=='sensor_logs' and retained[0][1][0]['source']=='zeek-sample'
    assert retained[0][1][0]['data']['coverage']['continuous'] is False


def test_workflow_read_is_passive_and_separates_readiness_from_data():
    idle=dict(state='stopped',message='No sample',updated_at=None,metrics=[])
    config=SimpleNamespace(capture=SimpleNamespace(snapshot=lambda:dict(state='running',accepted=0,skipped=0,started_at=None,message='Waiting')),
        sensors=SimpleNamespace(snapshot=lambda:dict(zeek=idle,suricata=idle)),qwen_status=dict(idle))
    v=snapshot(config,None)
    rows={r['id']:r for r in v['tools']}
    assert len(rows)==12 and rows['tshark']['state']=='collecting'
    assert rows['scapy']['state']==rows['nftables']['state']=='standby'
    assert rows['qwen']['state']=='stopped'
    assert 'token' not in json.dumps(v)


def test_old_qwen_advice_does_not_override_current_failure():
    idle=dict(state='needs_setup',message='Provider unavailable',updated_at=None,metrics=[])
    config=SimpleNamespace(capture=SimpleNamespace(snapshot=lambda:dict(state='stopped',accepted=0,skipped=0,started_at=None,message='Stopped')),
        sensors=SimpleNamespace(snapshot=lambda:dict(zeek=idle,suricata=idle)),qwen_status=dict(idle))
    companions=SimpleNamespace(snapshot=lambda:dict(results={},status={},advisory={'nmap':'Saved old advice','clamav':'Local AI unavailable (PROVIDER_ERROR).','osquery':'Local AI advice queued; collection is complete.'}))
    row=next(r for r in snapshot(config,companions)['tools'] if r['id']=='qwen')
    assert row['state']=='needs_setup' and row['message']=='Provider unavailable'
    assert row['metrics'][-1]['label']=='Available summaries with advice'

    assert row['metrics'][-1]['value']==1


@pytest.mark.parametrize('history', ['saved', 'failed', 'disabled'])
def test_available_advice_does_not_claim_history_persistence(monkeypatch, history):
    from megalodon.config import AISettings
    from megalodon.companion_automation import CompanionAutomation, CompanionConfig
    from megalodon.storage import StorageCapacityError

    config = CompanionConfig(3600, None, (), False, None, None, None, None, True)
    worker = CompanionAutomation(config, AISettings(enabled=True))
    writes = []

    def append_records(*args, **kwargs):
        writes.append(args)
        if history == 'failed':
            raise StorageCapacityError('Insufficient disk reserve')

    worker.evidence = SimpleNamespace(
        enabled=history != 'disabled', append_records=append_records
    )
    monkeypatch.setattr(
        'megalodon.ai_provider.generate',
        lambda *args, **kwargs: 'Counts are not proof of safety.',
    )
    worker._explain('nmap', {'count': 1})

    idle = dict(state='stopped', message='Idle', updated_at=None, metrics=[])
    hud = SimpleNamespace(
        capture=SimpleNamespace(snapshot=lambda: dict(
            state='stopped', accepted=0, skipped=0, started_at=None, message='Stopped'
        )),
        sensors=SimpleNamespace(snapshot=lambda: dict(zeek=idle, suricata=idle)),
        qwen_status=dict(idle),
    )
    row = next(r for r in snapshot(hud, worker)['tools'] if r['id'] == 'qwen')
    advice = worker.snapshot()['advisory']['nmap']
    assert advice.endswith('(Not saved to managed history.)') == (history == 'failed')
    assert len(writes) == (0 if history == 'disabled' else 1)
    assert row['state'] == 'stopped'
    assert row['metrics'][-1]['label'] == 'Available summaries with advice'
    assert row['metrics'][-1]['value'] == 1


def test_a_rejected_run_marks_a_prior_companion_result_stale():
    idle=dict(state='stopped',message='No sample',updated_at=None,metrics=[])
    config=SimpleNamespace(capture=SimpleNamespace(snapshot=lambda:dict(state='stopped',accepted=0,skipped=0,started_at=None,message='Stopped')),
        sensors=SimpleNamespace(snapshot=lambda:dict(zeek=idle,suricata=idle)),qwen_status=dict(idle))
    result=dict(scanned_files=4,infected_files=0,errors=0,exported_at='2026-10-16T12:00:00Z')

    def state(message):
        companions=SimpleNamespace(snapshot=lambda:dict(results={'clamav':result},status={'clamav':message},advisory={}))
        return next(r for r in snapshot(config,companions)['tools'] if r['id']=='clamav')['state']

    assert state('clamscan text report · completed; saved aggregate')=='connected'
    assert state('Scanning configured files; previous aggregate retained until complete')=='collecting'
    # The old clean count must not read as an available result after a rejection.
    assert state('ClamAV reported matches, but its report was rejected; the prior aggregate is stale.')=='error'

