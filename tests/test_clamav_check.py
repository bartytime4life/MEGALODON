"""Offline scanner-check boundaries and the protected action-to-Sensors path."""
from hashlib import sha256
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
from threading import Event, Thread

import pytest

from megalodon import clamav_check as check, dashboard
from megalodon.companion_automation import _run_fixed
from megalodon.support_config import ConfigBusy, validate_action
from megalodon.support_sensors import SupportSensors
from test_clamav_summary import report
from test_support_config import manager, request


def source(home, blob):
    folder = home/'Downloads'
    folder.mkdir(exist_ok=True)
    (folder/'eicar.com').write_bytes(blob)


# Unit fixtures are inert bytes. The real check accepts only the published EICAR digest.
def simulated(home, monkeypatch, *, mode='recognized'):
    data = b'x'*68
    source(home, data)
    monkeypatch.setattr(check, 'EICAR_SHA256', sha256(data).hexdigest())
    versions = []
    def run(argv, limit, timeout):
        assert argv[0] == '/usr/bin/clamscan'
        if argv[1:] == ['--version']:
            versions.append(1)
            version = b'42' if mode!='changed' or len(versions)==1 else b'43'
            return b'ClamAV 1.4.3/'+version+b'/Mon Nov 2 01:00:00 2026\n', 0
        assert argv[1:3] == ['--infected','--'] and len(argv)==4
        p=Path(argv[3])
        ordinary=p.name=='ordinary.txt'
        assert p.parent.stat().st_mode & 0o077 == 0
        assert p.read_bytes() == (check.CONTROL if ordinary else data)
        if mode=='intercepted' and not ordinary:p.unlink()
        hit=(ordinary and mode=='control') or (not ordinary and mode!='missed')
        name='Unexpected.Sig' if mode=='other' else 'Eicar-Test-Signature'
        header=(str(p)+': '+name+' FOUND\n').encode() if hit else b''
        raw=header+report(int(hit)).partition(b'\n')[2].replace(b'directories: 2',b'directories: 0').replace(b'files: 10',b'files: 1')
        if mode=='no_signatures':raw=raw.replace(b'Known viruses: 8000000',b'Known viruses: 0')
        if mode=='empty' and not ordinary:raw=raw.replace(b'Scanned files: 1',b'Scanned files: 0')
        return raw, 2 if mode=='error' else int(hit)
    return run


@pytest.mark.parametrize('mode,outcome',[('recognized','recognized'),('missed','missed'),('changed','unavailable'),
    ('control','unavailable'),('no_signatures','unavailable'),('other','unavailable'),('intercepted','unavailable'),('empty','unavailable'),('error','unavailable')])
def test_control_and_exact_reference_results(tmp_path,monkeypatch,mode,outcome):
    result=check.run_check(tmp_path,simulated(tmp_path,monkeypatch,mode=mode))
    assert result['state']==outcome
    assert str(tmp_path) not in json.dumps(result)
    if outcome in ('missed','recognized'):
        assert result['clean']==dict(scanned=1,matched=0)
        assert result['test']==dict(scanned=1,matched=int(outcome=='recognized'))
        assert (result['engine'],result['database'])==('1.4.3','42')


def test_unapproved_inputs_never_reach_scanner(tmp_path):
    def refused(*args):pytest.fail('unexpected invocation')
    assert check.run_check(tmp_path,refused)['state']=='unavailable'
    source(tmp_path,b'ordinary content')
    assert check.run_check(tmp_path,refused)['state']=='unavailable'
    p=tmp_path/'Downloads/eicar.com'
    p.unlink();p.symlink_to(tmp_path/'other')
    assert check.run_check(tmp_path,refused)['state']=='unavailable'
    p.unlink();os.mkfifo(p)
    assert check.run_check(tmp_path,refused)['state']=='unavailable'


def test_running_check_suppresses_previous_verdict_and_overlapping_request(manager,monkeypatch):
    scanner=simulated(manager.home,monkeypatch)
    pause,release=Event(),Event()
    def wait(*args):
        pause.set();release.wait(5);return scanner(*args)
    manager.run=wait
    body={'action':'clamav_self_check'}
    with pytest.raises(ValueError):validate_action({**body,'path':'/tmp/other'})
    manager.start(body)
    try:
        assert pause.wait(2)
        assert manager.scanner_check_status()['state']=='running'
        with pytest.raises(ConfigBusy):manager.start(body)
    finally:
        release.set();manager._thread.join(5)
    assert manager.scanner_check_status()['state']=='recognized'
    (manager.home/'Downloads/eicar.com').unlink()
    manager.start(body);manager._thread.join(5)
    assert manager.scanner_check_status()['state']=='unavailable'
    assert manager.scanner_check_status()['test'] is None


def http_journey(manager, run):
    manager.run=run
    manager.sensors=SupportSensors(manager.home)
    handler=type('ScannerCheckHandler',(dashboard.DashboardHandler,),{'support_config':manager})
    with ThreadingHTTPServer(('127.0.0.1',0),handler) as server:
        thread=Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
        thread.start()
        endpoint=server,manager,[],handler
        try:
            def status():
                code,payload=request(endpoint,method='GET',path='/api/support-workflows',body=b'')
                assert code==200
                return payload['scanner_check']
            assert status()['state']=='idle'
            action=b'{"action":"clamav_self_check"}'
            assert request(endpoint,body=action,omit=('X-Megalodon-Config-Token',))[0]==403
            assert status()['state']=='idle'
            code,admission=request(endpoint,body=action)
            assert code==202
            manager._thread.join(260)
            result=status()
            assert result['run_id']==admission['scanner_check_id']
            assert result['state']=='recognized', result
            assert result['clean']=={'scanned':1,'matched':0} and result['test']=={'scanned':1,'matched':1}
            assert manager.companions.snapshot()['results'].get('clamav') is None
            return result
        finally:
            server.shutdown();thread.join(2)


def test_protected_action_returns_its_own_result_in_sensors(manager,monkeypatch):
    http_journey(manager,simulated(manager.home,monkeypatch))


@pytest.mark.skipif(not os.environ.get('MEGALODON_TEST_EICAR_FILE'),reason='requires a locally prepared official 68-byte file and installed ClamAV')
def test_installed_clamav_through_protected_sensors_action(manager):
    with Path(os.environ['MEGALODON_TEST_EICAR_FILE']).open('rb') as stream:
        data=stream.read(69)
    assert len(data)==68 and sha256(data).hexdigest()==check.EICAR_SHA256
    source(manager.home,data)
    result=http_journey(manager,_run_fixed)
    print(f"ClamAV {result['engine']} / signatures {result['database']}: ordinary 0/1, EICAR 1/1")
