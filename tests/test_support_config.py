"""Fixed setup permissions, request boundaries, persistence and capture-to-chart flow."""
from dataclasses import replace
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
from types import SimpleNamespace

import pytest

from megalodon import dashboard, support_config as config
from megalodon.config import Settings, AISettings, DashboardSettings
from megalodon.companion_automation import CompanionAutomation, local_default_config
from megalodon.managed_capture import ManagedCapture, capture_commands
from megalodon.offline.tshark import FIELDS


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(config, 'interfaces', lambda:[dict(name='eth0',default=True,up=True)])
    monkeypatch.setattr(config, 'capture_tools_available', lambda:True)
    monkeypatch.setattr(dashboard, '_tool_management_user', lambda:True)
    monkeypatch.setattr(config, 'SupportSensors', lambda home: SimpleNamespace(start=lambda interface:None,stop=lambda:None,snapshot=lambda:{}))
    home=tmp_path/'home'
    home.mkdir(mode=0o700)
    worker=CompanionAutomation(local_default_config(home),AISettings())
    value=config.SupportConfiguration(Settings(db_path=home/'data/events.db'),worker,home=home,
                                     run=lambda *a:(b'',0))
    return value


@pytest.mark.parametrize('body', [
    None, [], {'action':'shell'}, {'action':'capture_start','interface':'eth0','command':'id'},
    {'action':'capture_start','interface':'any'}, {'action':'capture_start','interface':'eth0;id'},
    {'action':'capture_start','interface':[]}, {'action':'capture_start'},
    {'action':'nmap_configure','nmap_target':'8.8.8.8'}, {'action':'nmap_configure','nmap_target':'10.0.0.0/8'},
    {'action':'nmap_configure','nmap_target':'::1'}, {'action':'clamav_configure','scan_folder':'/'},
    {'action':'clamav_configure','scan_folder':'../Downloads'}, {'action':'qwen_check','url':'http://remote'},
    {'action':'geography_disable','url':'http://remote'},
])
def test_only_fixed_actions_and_bounded_scopes(manager,body):
    with pytest.raises(ValueError):
        manager.start(body)
    assert manager.snapshot()['job']['state']=='idle'


def test_selected_tool_directory_is_saved_without_running_tool(manager,private_tmp_path):
    directory = private_tmp_path / 'custom/bin'
    directory.mkdir(parents=True)
    executable = directory / 'zeek'
    executable.write_text('inert')
    executable.chmod(0o700)
    manager.run = lambda *args: pytest.fail('Saving a directory must not run tools')
    manager.start({'action':'tool_directory_set','tool_id':'zeek','directory':str(directory)})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state'] == 'finished'
    assert manager.snapshot()['tool_directories'] == {'zeek':str(directory)}
    manager.start({'action':'tool_directory_set','tool_id':'zeek','directory':''})
    manager._thread.join(2)
    assert manager.snapshot()['tool_directories'] == {}
    with pytest.raises(ValueError):
        manager.start({'action':'tool_directory_set','tool_id':'bash','directory':str(directory)})


def test_background_tools_retry_zeek_after_missing_location(manager,monkeypatch):
    calls = []
    monkeypatch.setattr(manager.background, 'snapshot', lambda: {'enabled':True,'state':'running'})
    manager.sensors = SimpleNamespace(snapshot=lambda:{'zeek':{'state':'needs_setup'}},
                                      stop=lambda:calls.append('stop'),
                                      start=lambda interface:calls.append(('start',interface)))
    manager.start_background_tools()
    assert calls == ['stop', ('start','eth0')]


def test_unsafe_tool_directory_profile_is_not_reported_as_ready(manager):
    from megalodon.tool_locations import profile_path
    path = profile_path(manager.home)
    path.parent.mkdir(parents=True)
    path.write_text('invalid')
    path.chmod(0o644)
    snapshot = manager.snapshot()
    assert snapshot['tool_directories_status'] == 'unavailable'
    assert snapshot['tool_directories'] == {}


def test_qwen_configuration_pins_existing_model_and_restores_background_advice(manager,monkeypatch):
    monkeypatch.setattr(config,'local_qwen_models',lambda:[dict(name='qwen2.5:trusted',digest=AISettings.model_digest)])
    monkeypatch.setattr('megalodon.ai_provider.status',lambda *a,**k:dict(inference_verified=True,state='model_ready'))
    commands=[]
    manager.run=lambda argv,*a:commands.append(argv) or (b'',0)
    manager.start({'action':'qwen_configure'});manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='finished'
    assert manager.companions.ai.enabled and manager.companions.ai.model=='qwen2.5:trusted'
    assert commands[0][:3]==['/usr/bin/pkexec','/bin/sh','-c']
    assert 'OLLAMA_HOST=127.0.0.1:11434' in commands[0][3]
    other=config.SupportConfiguration(manager.settings,home=manager.home)
    assert other.settings.ai.enabled and other.settings.ai.model_digest==AISettings.model_digest


def test_qwen_retry_waits_for_newly_restarted_local_socket(monkeypatch):
    calls=[]
    class Connection:
        def __init__(self,host,port,timeout): assert host=='127.0.0.1' and port==11434
        def request(self,*a):
            calls.append(True)
            if len(calls)==1: raise ConnectionRefusedError()
        def getresponse(self): return SimpleNamespace(status=200,read=lambda size:b'{"models":[]}')
        def close(self): pass
    monkeypatch.setattr(config,'HTTPConnection',Connection)
    monkeypatch.setattr(config.time,'sleep',lambda seconds:None)
    assert config.local_qwen_models()==[] and len(calls)==2


def test_suricata_configuration_is_fixed_passive_cli_and_bounded_interface(manager):
    commands=[]
    manager.run=lambda argv,*a:commands.append(argv) or (b'',0)
    manager.start({'action':'suricata_configure','interface':'eth0'});manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='finished'
    assert commands[0][-2:]==['megalodon-suricata','eth0']
    assert '--runmode single' in commands[0][3] and '--af-packet=$1' in commands[0][3]
    assert 'ExecStart=/usr/bin/suricata' in commands[0][3]
    with pytest.raises(ValueError):
        manager.start({'action':'suricata_configure','interface':'eth0;id'})


def test_saved_collector_settings_are_loaded_and_report_watchers_preserved(manager,monkeypatch):
    requested=[]
    monkeypatch.setattr(manager.companions,'request_collection',
                        lambda selected:requested.append(selected) or {'nmap':'queued'})
    before=manager.companions.config.watch_nmap_xml
    manager.start({'action':'nmap_configure','nmap_target':'192.168.2.22'})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='finished'
    assert manager.companions.config.nmap_target=='192.168.2.22/32'
    assert manager.companions.config.watch_nmap_xml==before
    assert requested==[{'nmap'}]
    assert os.stat(manager.profile).st_mode & 0o777 == 0o600
    other=config.SupportConfiguration(manager.settings, CompanionAutomation(local_default_config(manager.home),AISettings()),home=manager.home)
    assert other.companions.config.nmap_target=='192.168.2.22/32'


def test_failed_profile_write_does_not_change_active_collector(manager,monkeypatch):
    original = manager.companions.config
    def fail_save(*args):
        raise OSError('test-only write failure')
    monkeypatch.setattr(manager,'_save',fail_save)
    manager.start({'action':'nmap_configure','nmap_target':'192.168.2.22'})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='failed'
    assert manager.companions.config==original
    assert manager.snapshot()['settings']['nmap_target']=='127.0.0.1/32'
    assert manager._configured==set()
    assert manager.companions._requested==set()


def test_active_scan_prevents_scope_change(manager):
    manager.companions._active.add('nmap')
    manager.start({'action':'nmap_configure','nmap_target':'10.1.1.1'})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='failed'
    assert manager.companions.config.nmap_target=='127.0.0.1/32'
    assert not manager.profile.exists()


def test_scan_folder_symlink_is_rejected(manager,tmp_path):
    (manager.home/'Downloads').symlink_to(tmp_path,target_is_directory=True)
    manager.start({'action':'clamav_configure','scan_folder':'Downloads'})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='failed'
    assert not manager.companions.config.clamav_paths


def test_permissions_only_target_packaged_dumpcap(manager):
    calls=[]
    manager.run=lambda argv,*a:calls.append(argv) or (b'',0)
    manager.start({'action':'capture_permissions','interface':'eth0'})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='finished'
    assert calls==[['/usr/bin/pkexec','/bin/sh','-c',config.PERMISSION_SCRIPT],['/usr/bin/dumpcap','-i','eth0','-L']]
    assert 'PKEXEC_UID' in config.PERMISSION_SCRIPT
    assert 'cap_net_raw,cap_net_admin=ep /usr/bin/dumpcap' in config.PERMISSION_SCRIPT
    assert 'dpkg-query -S /usr/bin/dumpcap' in config.PERMISSION_SCRIPT
    assert 'python' not in config.PERMISSION_SCRIPT and '777' not in config.PERMISSION_SCRIPT
    assert 'sudoers' not in config.PERMISSION_SCRIPT and 'chmod +s' not in config.PERMISSION_SCRIPT


def test_cancelled_authorization_is_not_success(manager):
    manager.run=lambda *a:(b'',126)
    manager.start({'action':'capture_permissions','interface':'eth0'})
    manager._thread.join(2)
    assert manager.snapshot()['job']['state']=='failed'
    assert manager.snapshot()['tools'][0]['state']=='needs_setup'


def test_managed_wireshark_is_bounded_and_stops_only_own_unit(manager):
    calls=[]
    def run(argv,*a):
        calls.append(argv)
        return b'',3 if 'is-active' in argv else 0
    manager.run=run
    manager.start({'action':'wireshark_open','interface':'eth0'})
    manager._thread.join(2)
    command=calls[-1]
    assert command[:4]==['systemd-run','--user','--collect','--unit=megalodon-wireshark-capture.service']
    assert '-k' in command and 'duration:900' in command and '50000' in command
    assert 'pkexec' not in command
    manager.start({'action':'wireshark_stop'})
    manager._thread.join(2)
    assert calls[-1]==['systemctl','--user','stop','megalodon-wireshark-capture.service']


def test_capture_stop_remains_available_while_setup_is_busy(manager,monkeypatch):
    stopped=[]
    monkeypatch.setattr(manager.capture,'stop',lambda:stopped.append(True))
    manager._job['state']='running'
    manager.start({'action':'capture_stop'})
    assert stopped==[True]
    assert manager.snapshot()['job']['state']=='running'


@pytest.fixture
def endpoint(manager,monkeypatch):
    calls=[]
    monkeypatch.setattr(manager,'start',lambda request:calls.append(request) or manager.snapshot())
    handler=type('ConfigurationHandler',(dashboard.DashboardHandler,),{'support_config':manager})
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    thread=Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
    thread.start()
    try:
        yield server,manager,calls,handler
    finally:
        server.shutdown();server.server_close();thread.join(2)


def request(endpoint,method='POST',body=b'{"action":"qwen_check"}',extra=(),omit=(),path='/api/support-config'):
    server,manager,_,_=endpoint
    origin=f'http://127.0.0.1:{server.server_port}'
    values=[('Host',origin[7:]),('Origin',origin),('Content-Type','application/json'),
            ('Content-Length',str(len(body))),('X-Megalodon-Check','1'),('X-Megalodon-Config-Token',manager.token)]
    client=HTTPConnection('127.0.0.1',server.server_port,timeout=3)
    try:
        client.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
        for key,value in values:
            if key not in omit:client.putheader(key,value)
        for key,value in extra:client.putheader(key,value)
        client.endheaders(body)
        response=client.getresponse()
        return response.status,json.loads(response.read())
    finally:client.close()


def test_get_is_read_only_and_action_requires_no_installer_token(endpoint):
    code,value=request(endpoint,method='GET',body=b'')
    assert code==200 and value['token']==endpoint[1].token and endpoint[2]==[]
    assert request(endpoint)[0]==202 and endpoint[2]==[{'action':'qwen_check'}]
    assert endpoint[3].install_operator_token is None


@pytest.mark.parametrize('extra,omit,code',[
    ((),('X-Megalodon-Config-Token',),403),
    ((('X-Megalodon-Config-Token','x'*32),),(),403),
    ((('Origin','http://evil.invalid'),),('Origin',),403),
    ((('Content-Type','text/plain'),),('Content-Type',),403),
    ((('Transfer-Encoding','chunked'),),(),403),
    ((('Content-Encoding','gzip'),),(),403),
    ((('Content-Length','22'),),(),400),
    ((('Content-Length','9999'),),('Content-Length',),400),
    ((('Host','evil.invalid'),),('Host',),400),
])
def test_http_ambiguous_requests_cannot_configure(endpoint,extra,omit,code):
    assert request(endpoint,extra=extra,omit=omit)[0]==code
    assert endpoint[2]==[]


@pytest.mark.parametrize('body',[b'{"action":"qwen_check","action":"capture_stop"}',b'{"action":"qwen_check","command":"id"}',b'null',b'\xff'])
def test_duplicate_and_unknown_body_rejected(endpoint,body):
    assert request(endpoint,body=body)[0]==400 and endpoint[2]==[]


def test_alias_optional_signin_and_non_root_gates(endpoint,monkeypatch):
    assert request(endpoint,path='/api/support-config?x=1')[0]==405
    assert request(endpoint,method='GET',path='/api/support-config?x=1',body=b'')[0]==400
    assert request(endpoint,method='GET',omit=('X-Megalodon-Check',),body=b'')[0]==403
    endpoint[3].http_read_password='test-only'
    assert request(endpoint)[0]==401
    endpoint[3].http_read_password=None
    monkeypatch.setattr(dashboard,'_tool_management_user',lambda:False)
    assert request(endpoint)[0]==403
    assert endpoint[2]==[]


def field_row():
    fields={'frame.time_epoch':'1788710400.123456','ip.src':'192.0.2.10','ip.dst':'198.51.100.20',
            'ip.proto':'6','tcp.srcport':'40000','tcp.dstport':'443','tcp.flags':'0x0012','frame.len':'60'}
    return '\t'.join(fields.get(key,'') for key in FIELDS)


def test_controlled_capture_feeds_qualified_existing_chart_reader(manager):
    commands=[]
    def spawn(argv,**kwargs):
        commands.append(argv)
        code = 'pass' if argv[0].endswith('dumpcap') else 'print('+repr(field_row())+')\nprint("invalid")'
        return subprocess.Popen([sys.executable,'-c',code],**kwargs)
    reader=dashboard.UnconfiguredDashboardReader(manager.settings.db_path)
    ready=[]
    capture=ManagedCapture(manager.settings,manager.home,on_ready=lambda:ready.append(True),popen=spawn)
    capture.start('eth0')
    capture._thread.join(5)
    value=capture.snapshot()
    assert value['state']=='stopped',value
    assert (value['received'],value['accepted'],value['skipped'])==(2,1,1)
    projection=reader.traffic()
    assert projection['status']=='available' and len(projection['events'])==1
    assert projection['events'][0]['protocol']=='TCP'
    assert reader.ingestion_runs()[0]['source']=='jsonl'
    assert ready==[True]
    assert commands==list(capture_commands('eth0'))
    assert commands[0][-2:]==['-w','-'] and commands[1][3:5]==['-r','-']
    assert not list(manager.home.rglob('*.pcap*'))


def test_failed_capture_marks_receipt_and_cleans_up(manager):
    def spawn(argv,**kwargs):
        return subprocess.Popen([sys.executable,'-c','raise SystemExit(1)'],**kwargs)
    capture=ManagedCapture(manager.settings,manager.home,popen=spawn)
    capture.start('eth0');capture._thread.join(5)
    assert capture.snapshot()['state']=='failed'
    reader=dashboard.UnconfiguredDashboardReader(manager.settings.db_path)
    assert reader.ingestion_runs()[0]['failure_code']=='CAPTURE_ERROR'


def test_capture_storage_limit_is_actionable_and_preserves_failure_receipt(manager,monkeypatch):
    from megalodon import managed_capture
    from megalodon.storage import StorageCapacityError
    def full(*args,**kwargs):
        raise StorageCapacityError('STORAGE_CAPACITY:HIGH_WATER')
    monkeypatch.setattr(managed_capture.BufferedRecording,'process',full)
    def spawn(argv,**kwargs):
        code='pass' if argv[0].endswith('dumpcap') else 'print('+repr(field_row())+')'
        return subprocess.Popen([sys.executable,'-c',code],**kwargs)
    capture=ManagedCapture(manager.settings,manager.home,popen=spawn)
    capture.start('eth0');capture._thread.join(5)
    assert capture.snapshot()['state']=='failed'
    assert capture.snapshot()['message'].startswith('Packet storage limit reached.')
    reader=dashboard.UnconfiguredDashboardReader(manager.settings.db_path)
    assert reader.ingestion_runs()[0]['failure_code']=='CAPTURE_ERROR'


def test_reordered_capture_row_is_rejected_without_stopping_live_feed(manager):
    rows=[field_row(),field_row().replace('1788710400.123456','1788710399.123456'),field_row().replace('1788710400.123456','1788710401.123456')]
    def spawn(argv,**kwargs):
        code='pass' if argv[0].endswith('dumpcap') else '\n'.join('print('+repr(row)+')' for row in rows)
        return subprocess.Popen([sys.executable,'-c',code],**kwargs)
    capture=ManagedCapture(manager.settings,manager.home,popen=spawn)
    capture.start('eth0');capture._thread.join(5)
    value=capture.snapshot()
    assert value['state']=='stopped'
    assert (value['accepted'],value['skipped'],value['timestamp_rejected'])==(2,1,1)
    reader=dashboard.UnconfiguredDashboardReader(manager.settings.db_path)
    assert reader.ingestion_runs()[0]['processed_count']==2


def test_stop_cancels_a_start_still_preparing_its_settings(manager,monkeypatch):
    from threading import Event
    waiting,release=Event(),Event()
    started=[]
    def save():
        waiting.set();release.wait(2)
    monkeypatch.setattr(manager,'_save',save)
    monkeypatch.setattr(manager.capture,'start',lambda interface:started.append(interface))
    manager.start({'action':'capture_start','interface':'eth0'})
    assert waiting.wait(1)
    manager.start({'action':'capture_stop'})
    release.set();manager._thread.join(2)
    assert started==[]
    assert 'cancelled' in manager.snapshot()['job']['message']


def test_background_setting_persists_but_does_not_enable_external_geography(manager,monkeypatch):
    starts=[]
    monkeypatch.setattr(manager.background,'start',lambda interface:starts.append(interface))
    manager.start({'action':'background_start','interface':'eth0'})
    manager._thread.join(3)
    assert starts==['eth0']
    assert manager._background_enabled and not manager._geography_enabled
    saved=json.loads(manager.profile.read_text())
    assert saved['background_enabled'] and not saved['geography_enabled']
    restored=config.SupportConfiguration(manager.settings,home=manager.home)
    monkeypatch.setattr(restored.background,'start',lambda interface:starts.append(interface))
    restored.resume()
    assert starts==['eth0','eth0']
    restored.start({'action':'background_stop'})
    assert json.loads(manager.profile.read_text())['background_enabled'] is False


def test_explicit_geography_action_persists_its_separate_online_opt_in(manager,monkeypatch):
    calls=[]
    starts=[]
    monkeypatch.setattr(manager.background,'start',lambda interface:starts.append(interface))
    monkeypatch.setattr(manager.background,'refresh_geography',lambda:calls.append(True))
    manager.start({'action':'background_start','interface':'eth0'})
    manager._thread.join(3)
    manager.start({'action':'geography_refresh'})
    manager._thread.join(3)
    assert calls==[True]
    assert json.loads(manager.profile.read_text())['geography_enabled'] is True

    manager.start({'action':'geography_disable'})
    manager._thread.join(3)
    assert manager.snapshot()['geography_enabled'] is False
    assert json.loads(manager.profile.read_text())['geography_enabled'] is False
    restored=config.SupportConfiguration(manager.settings,home=manager.home)
    monkeypatch.setattr(restored.background,'start',lambda interface:starts.append(interface))
    restored.resume()
    assert starts==['eth0','eth0']
    assert restored._background_enabled is True
    assert restored._geography_enabled is False
    assert restored.background.geography_enabled() is False


def test_missing_capture_tools_fail_closed(manager,monkeypatch):
    monkeypatch.setattr(config,'capture_tools_available',lambda:False)
    started=[]
    monkeypatch.setattr(manager.capture,'start',lambda interface:started.append(interface))
    monkeypatch.setattr(manager.background,'start',lambda interface:started.append(interface))
    for action in ('capture_start','background_start'):
        manager.start({'action':action,'interface':'eth0'})
        manager._thread.join(3)
        assert manager.snapshot()['job']['state']=='failed'
    assert started==[]
    assert not manager._background_enabled


def test_live_endpoint_is_read_only_bounded_and_uses_existing_local_gates(endpoint,monkeypatch):
    code,value=request(endpoint,method='GET',body=b'',path='/api/live-connections')
    assert code==200 and value['schema']=='megalodon-live-connections-v1'
    assert value['connections']==[] and endpoint[2]==[]
    assert request(endpoint,method='GET',body=b'',path='/api/live-connections?limit=9999')[0]==400
    assert request(endpoint,method='GET',body=b'',path='/api/live-connections',omit=('X-Megalodon-Check',))[0]==403
    monkeypatch.setattr(dashboard,'_tool_management_user',lambda:False)
    assert request(endpoint,method='GET',body=b'',path='/api/live-connections')[0]==403


def test_workflow_endpoint_observes_without_model_or_service_execution(endpoint,monkeypatch):
    idle=dict(state='stopped',message='Not started',updated_at=None,metrics=[])
    monkeypatch.setattr(endpoint[1].sensors,'snapshot',lambda:dict(zeek=idle,suricata=idle))
    code,value=request(endpoint,method='GET',body=b'',path='/api/support-workflows')
    assert code==200 and value['schema']=='megalodon-support-workflows-v1'
    assert len(value['tools'])==10 and endpoint[2]==[]
    assert request(endpoint,method='GET',body=b'',path='/api/support-workflows?start=true')[0]==400
    assert request(endpoint,method='GET',body=b'',path='/api/support-workflows',omit=('X-Megalodon-Check',))[0]==403


@pytest.mark.parametrize('configured,expected', [('localhost','127.0.0.1'), ('127.0.0.2','127.0.0.2')])
def test_terminal_configuration_uses_configured_loopback(monkeypatch,configured,expected):
    requests=[]
    payload={'schema':config.SCHEMA,'token':'x'*32,
             'job':{'state':'finished','message':'Ready.'},
             'capture':{'state':'idle','accepted':0},'tools':[]}
    class Connection:
        def __init__(self,host,port,timeout):
            assert host==expected
        def request(self,method,path,**kwargs):
            requests.append((method,kwargs.get('headers',{}).get('Origin')))
        def getresponse(self):
            return SimpleNamespace(status=200,read=lambda limit:json.dumps(payload).encode())
        def close(self):
            pass
    monkeypatch.setattr('megalodon.config.load_settings',
                        lambda path:Settings(dashboard=DashboardSettings(host=configured)))
    monkeypatch.setattr(config,'HTTPConnection',Connection)
    assert config.main(['qwen_check'])==0
    assert requests==[('GET',None),('POST',f'http://{expected}:8787')]
