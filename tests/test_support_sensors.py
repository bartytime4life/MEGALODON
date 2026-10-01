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
    assert len(rows)==10 and rows['tshark']['state']=='collecting'
    assert rows['scapy']['state']==rows['nftables']['state']=='standby'
    assert rows['qwen']['state']=='stopped'
    assert 'token' not in json.dumps(v)


def test_old_qwen_advice_does_not_override_current_failure():
    idle=dict(state='needs_setup',message='Provider unavailable',updated_at=None,metrics=[])
    config=SimpleNamespace(capture=SimpleNamespace(snapshot=lambda:dict(state='stopped',accepted=0,skipped=0,started_at=None,message='Stopped')),
        sensors=SimpleNamespace(snapshot=lambda:dict(zeek=idle,suricata=idle)),qwen_status=dict(idle))
    companions=SimpleNamespace(snapshot=lambda:dict(results={},status={},advisory={'nmap':'Saved old advice','clamav':'Local AI unavailable (PROVIDER_ERROR).','osquery':'Qwen unavailable (DISABLED).'}))
    row=next(r for r in snapshot(config,companions)['tools'] if r['id']=='qwen')
    assert row['state']=='needs_setup' and row['message']=='Provider unavailable'
    assert row['metrics'][-1]['label']=='Saved summaries with advice'

    assert row['metrics'][-1]['value']==1
