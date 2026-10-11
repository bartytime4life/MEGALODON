"""Selectable local artifacts retain admission, atomic settings and truthful status."""
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from megalodon import ai_provider as provider, support_config
from megalodon.config import AISettings, Settings, valid_model_name
from megalodon.model_telemetry import ModelTelemetry


@pytest.fixture
def model_provider(monkeypatch):
    provider._observations.clear()
    model='llama3.2:3b';digest='b'*64;requests=[]
    settings=AISettings(enabled=True,model=model,model_digest=digest)
    state=dict(details={'details':{'format':'gguf'},'capabilities':['completion']},reply='READY',digest=digest)
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda **_:{'listening':'yes','loopback_only':True})
    def request(path,method,body,timeout,*,deadline=None):
        data=json.loads(body) if body else None;requests.append((path,method,data))
        if path=='/api/tags':return json.dumps({'models':[dict(name=model,digest=state['digest'],size=2**30,details={'format':'gguf'})]}).encode()
        if path=='/api/show':return json.dumps(state['details']).encode()
        if path=='/api/ps':return json.dumps({'models':[]}).encode()
        return json.dumps(dict(model=model,response=state['reply'],done=True,done_reason='stop')).encode()
    monkeypatch.setattr(provider,'_request',request)
    yield settings,state,requests
    provider._observations.clear()


def test_other_local_model_uses_template_and_bounded_cpu_response(model_provider):
    settings,state,requests=model_provider
    assert provider.generate(settings,'Return READY',max_tokens=32)=='READY'
    body=requests[-1][2]
    assert body['raw'] is False and body['options']['num_gpu']==0
    assert body['options']['num_predict']==32 and body['keep_alive']==0
    assert provider.last_observation(settings)['last_response_at']
    assert provider.last_observation(replace(settings,model_digest='c'*64))=={}
    provider.generate(replace(settings,compute_mode='auto'),'Return READY',max_tokens=32)
    assert requests[-1][2]['options']['num_gpu']==-1


@pytest.mark.parametrize('details',[
    {'details':{'format':'gguf'},'capabilities':['embedding']},
    {'details':{'format':'gguf'},'capabilities':['completion'],'remote_host':'https://ollama.com'},
    {'details':{'format':'gguf'},'capabilities':['completion'],'remote_model':'cloud/model'},
    {},
])
def test_remote_and_non_completion_models_never_receive_prompt(model_provider,details):
    settings,state,requests=model_provider;state['details']=details
    with pytest.raises(provider.AIProviderError,match='MODEL_NOT_LOCAL'):provider.generate(settings,'PRIVATE EVIDENCE')
    assert all(path!='/api/generate' and 'PRIVATE EVIDENCE' not in str(body) for path,_,body in requests)


def test_changed_artifact_does_not_receive_prompt(model_provider):
    settings,state,requests=model_provider;state['digest']='a'*64
    with pytest.raises(provider.AIProviderError,match='MODEL_MISMATCH'):provider.generate(settings,'PRIVATE EVIDENCE')
    assert all(path!='/api/generate' for path,_,_ in requests)


def test_passive_status_is_shared_cached_and_failed_response_is_not_green(model_provider):
    settings,state,requests=model_provider
    telemetry=ModelTelemetry(lambda:settings)
    telemetry.snapshot();telemetry._thread.join(2)
    observed=telemetry.snapshot();n=len(requests)
    assert observed['model']==settings.model and observed['state']=='ready' and observed['loaded'] is False
    assert not observed['inference_verified'] and observed['options'][0]['name']==settings.model
    telemetry.snapshot();assert len(requests)==n
    assert all(path!='/api/generate' for path,_,_ in requests)
    provider.generate(settings,'READY');assert telemetry.snapshot()['state']=='connected'
    state['reply']=''
    with pytest.raises(provider.AIProviderError):provider.generate(settings,'READY')
    observed=telemetry.snapshot();assert observed['state']=='error' and observed['last_response_at'] and not observed['inference_verified']


@pytest.mark.parametrize('name',['../file','/tmp/model','a//b','a;id','model:','https://evil','x\ny','a'*97])
def test_names_are_inventory_identifiers_not_commands_or_paths(name):
    assert not valid_model_name(name)


def test_past_or_future_response_does_not_claim_current_ai_readiness(model_provider):
    settings,_,_=model_provider
    telemetry=ModelTelemetry(lambda:settings)
    telemetry.snapshot();telemetry._thread.join(2)
    provider.generate(settings,'READY')
    assert telemetry.snapshot()['state']=='connected'
    key=(settings.model,settings.model_digest,settings.compute_mode)
    for timestamp in ('2020-01-01T00:00:00Z','2999-01-01T00:00:00Z'):
        provider._observations[key]['last_response_at']=timestamp
        observed=telemetry.snapshot()
        assert observed['state']=='ready' and not observed['inference_verified']
        assert observed['last_response_at']==timestamp
        assert 'verify again' in observed['message']


def test_selector_persists_exact_identity_and_restarts(model_provider,tmp_path,monkeypatch):
    settings,state,requests=model_provider
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    manager=support_config.SupportConfiguration(Settings(db_path=tmp_path/'data/events.db'),home=tmp_path)
    request=dict(action='model_select',model=settings.model,model_digest=settings.model_digest,compute_mode='cpu')
    manager.start(request);manager._thread.join(3)
    assert manager.snapshot()['job']['state']=='finished'
    assert manager.settings.ai.model==settings.model and manager.settings.ai.enabled
    persisted=json.loads((tmp_path/'.config/megalodon/qwen-profile.json').read_text())
    assert persisted['schema']=='megalodon-local-model-v2'
    restarted=support_config.SupportConfiguration(Settings(db_path=tmp_path/'data/events.db'),home=tmp_path)
    assert restarted.settings.ai.model==settings.model and restarted.settings.ai.model_digest==settings.model_digest
    prior=manager.settings
    state['digest']='d'*64
    manager.start(request);manager._thread.join(3)
    assert manager.snapshot()['job']['state']=='failed' and manager.settings==prior
    assert json.loads((tmp_path/'.config/megalodon/qwen-profile.json').read_text())==persisted


def test_profile_write_failure_preserves_active_selection(model_provider,tmp_path,monkeypatch):
    settings,_,_=model_provider
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    manager=support_config.SupportConfiguration(Settings(db_path=tmp_path/'data/events.db'),home=tmp_path)
    before=manager.settings
    monkeypatch.setattr(support_config,'_atomic_write',lambda *a,**k:(_ for _ in ()).throw(OSError('disk full')))
    manager.start(dict(action='model_select',model=settings.model,model_digest=settings.model_digest,compute_mode='auto'));manager._thread.join(3)
    assert manager.snapshot()['job']['state']=='failed' and manager.settings==before


def test_failed_challenge_is_not_a_verified_response(model_provider):
    settings,state,_=model_provider
    state['reply']='Not READY'
    assert provider.status(settings)['inference_verified'] is False
    observation=provider.last_observation(settings)
    assert observation['error_code']=='INVALID_RESPONSE' and not observation['last_response_at']
    state['reply']='READY'
    assert provider.status(settings)['inference_verified'] is True
    assert provider.last_observation(replace(settings,compute_mode='auto'))=={}


def test_busy_metadata_check_is_not_reported_as_offline(model_provider):
    settings,_,_=model_provider
    def busy():raise provider.AIProviderError('CONCURRENCY_LIMIT_REACHED')
    telemetry=ModelTelemetry(lambda:settings,catalog=busy)
    telemetry.snapshot();telemetry._thread.join(2)
    assert telemetry.snapshot()['model_state']=='model_loading'


def test_ollama_access_configuration_preserves_non_qwen_selection(model_provider,tmp_path,monkeypatch):
    settings,_,_=model_provider
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    monkeypatch.setattr(support_config,'local_qwen_models',lambda:[dict(name=settings.model,digest=settings.model_digest)])
    manager=support_config.SupportConfiguration(Settings(ai=settings,db_path=tmp_path/'data/events.db'),home=tmp_path,run=lambda *a:(b'',0))
    manager.start(dict(action='qwen_configure'));manager._thread.join(3)
    assert manager.snapshot()['job']['state']=='finished'
    assert manager.settings.ai.model==settings.model


@pytest.mark.parametrize('chunked',[False,True])
def test_metadata_has_separate_bounded_body_without_relaxing_generated_output(chunked):
    import io,time
    from megalodon import qwen_advisory as transport
    class Socket:
        def __init__(self,raw):self.raw=raw
        def makefile(self,*a):return io.BytesIO(self.raw)
    class Connection:
        sock=None
    def read(response_class,size):
        body=b'x'*size
        framing=(b'Transfer-Encoding: chunked\r\n\r\n'+format(size,'x').encode()+b'\r\n'+body+b'\r\n0\r\n\r\n' if chunked else b'Content-Length: '+str(size).encode()+b'\r\n\r\n'+body)
        response=response_class(Socket(b'HTTP/1.1 200 OK\r\n'+framing));response.begin()
        return transport._read_provider_body(response,Connection(),time.monotonic()+2,None)
    assert len(read(provider._ModelMetadataResponse,50_280))==50_280
    with pytest.raises(transport._ProviderResponseInvalid):read(provider._ModelMetadataResponse,256*1024+1)
    with pytest.raises(transport._ProviderResponseInvalid):read(transport._BoundedHTTPResponse,transport.MAX_PROVIDER_ENVELOPE_BYTES+1)


@pytest.mark.parametrize('reason,expected',[(None,'OLLAMA_UNAVAILABLE'),('PROVIDER_TIMEOUT','REQUEST_TIMEOUT')])
def test_deadline_socket_close_is_reported_as_timeout(monkeypatch,reason,expected):
    class Connection:
        def __init__(self,*a,**kw):pass
        def request(self,*a,**kw):raise OSError('closed by deadline')
        def close(self):pass
    class Guard:
        def __init__(self,*a):pass
        def start(self):pass
        def finish(self):return reason
    monkeypatch.setattr(provider.transport,'_LiteralLoopbackHTTPConnection',Connection)
    monkeypatch.setattr(provider.transport,'_InvocationGuard',Guard)
    monkeypatch.setattr(provider.transport,'_acquire_process_invocation_lock',lambda:None)
    with pytest.raises(provider.AIProviderError,match=expected):provider._request('/api/generate','POST',b'{}',1)


def test_deadline_during_partial_body_is_a_timeout_not_invalid_response(monkeypatch):
    import socket,threading,time
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
    stop=threading.Event()
    def serve():
        try:
            client,_=listener.accept()
        except OSError:return
        with client:
            client.settimeout(3)
            data=b''
            while b'\r\n\r\n' not in data:data+=client.recv(4096)
            client.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n')
            try:
                while not stop.wait(0.02):client.sendall(b' ')
            except OSError:pass
    server=threading.Thread(target=serve,daemon=True);server.start()
    monkeypatch.setattr(provider.transport,'LOOPBACK_PORT',listener.getsockname()[1])
    monkeypatch.setattr(provider.transport,'_acquire_process_invocation_lock',lambda:None)
    # Only the shared watchdog ends the read, as when it wins the race with the socket timeout.
    def generous_timeout(connection,deadline):
        connection.timeout=3
        if connection.sock is not None:connection.sock.settimeout(3)
    monkeypatch.setattr(provider.transport,'_set_connection_timeout',generous_timeout)
    started=time.monotonic()
    try:
        with pytest.raises(provider.AIProviderError,match='REQUEST_TIMEOUT'):provider._request('/api/tags','GET',None,0.5)
    finally:
        stop.set();server.join(3);listener.close()
    assert time.monotonic()-started<2.5


def test_manual_request_waits_briefly_for_a_metadata_read(monkeypatch):
    import threading,time
    class Connection:
        def __init__(self,*a,**kw):pass
        def request(self,*a,**kw):raise OSError('no listener')
        def close(self):pass
    class Guard:
        def __init__(self,*a):pass
        def start(self):pass
        def finish(self):return None
    monkeypatch.setattr(provider.transport,'_LiteralLoopbackHTTPConnection',Connection)
    monkeypatch.setattr(provider.transport,'_InvocationGuard',Guard)
    monkeypatch.setattr(provider.transport,'_acquire_process_invocation_lock',lambda:None)
    lock=provider.transport._INVOCATION_LOCK
    assert lock.acquire(blocking=False)
    threading.Timer(0.2,lock.release).start()
    # The slot frees within the bounded wait, so the request reaches the transport.
    with pytest.raises(provider.AIProviderError,match='OLLAMA_UNAVAILABLE'):provider._request('/api/tags','GET',None,3)
    assert lock.acquire(blocking=False)
    try:
        started=time.monotonic()
        with pytest.raises(provider.AIProviderError,match='CONCURRENCY_LIMIT_REACHED'):provider._request('/api/tags','GET',None,3)
        assert 0.9<=time.monotonic()-started<2
        started=time.monotonic()
        with pytest.raises(provider.AIProviderError,match='CONCURRENCY_LIMIT_REACHED'):
            provider._request('/api/tags','GET',None,3,deadline=time.monotonic()+0.2)
        assert time.monotonic()-started<0.6
    finally:
        lock.release()


def test_long_budget_keeps_metadata_fast_and_rejects_unbounded_requests(model_provider,monkeypatch):
    settings,_,_=model_provider
    assert settings.timeout_seconds==300
    seen=[];original=provider._request
    def request(path,method,body,timeout,*,deadline=None):
        seen.append((path,timeout));return original(path,method,body,timeout,deadline=deadline)
    monkeypatch.setattr(provider,'_request',request)
    assert provider.generate(replace(settings,timeout_seconds=1800),'READY')=='READY'
    assert all(seconds<=3 for path,seconds in seen if path!='/api/generate')
    assert seen[-1][1]>1790
    for value in (0,1801,True,1.5):
        count=len(seen)
        with pytest.raises(provider.AIProviderError,match='POLICY_REJECTION'):
            provider.generate(replace(settings,timeout_seconds=value),'READY')
        assert len(seen)==count


def test_long_generation_exposes_progress_cancels_and_releases_lock(model_provider,monkeypatch):
    from threading import Event,Thread
    settings,_,_=model_provider;entered=Event();errors=[]
    def slow(*args,**kwargs):
        entered.set()
        assert provider._request_context.cancel.wait(2)
        raise provider.AIProviderError('REQUEST_CANCELLED')
    monkeypatch.setattr(provider,'_generate',slow)
    def run():
        try:provider.generate(settings,'READY')
        except provider.AIProviderError as exc:errors.append(exc.code)
    thread=Thread(target=run);thread.start();assert entered.wait(1)
    assert provider.last_observation(settings)['running']
    with pytest.raises(provider.AIProviderError,match='CONCURRENCY_LIMIT_REACHED'):provider.generate(settings,'duplicate')
    provider.cancel_current();thread.join(2)
    assert not thread.is_alive() and errors==['REQUEST_CANCELLED']
    value=provider.last_observation(settings)
    assert not value['running'] and value['error_code']=='REQUEST_CANCELLED'
    assert not value.get('last_response_at')


def test_timeout_selection_survives_restart(model_provider,tmp_path,monkeypatch):
    settings,_,_=model_provider;monkeypatch.setattr(support_config,'interfaces',lambda:[])
    manager=support_config.SupportConfiguration(Settings(db_path=tmp_path/'events.db'),home=tmp_path)
    manager.start(dict(action='model_select',model=settings.model,model_digest=settings.model_digest,compute_mode='cpu',timeout_seconds=900));manager._thread.join(3)
    assert manager.settings.ai.timeout_seconds==900
    restarted=support_config.SupportConfiguration(Settings(db_path=tmp_path/'events.db'),home=tmp_path)
    assert restarted.settings.ai.timeout_seconds==900
    for value in (0,1801,True):
        with pytest.raises(ValueError):support_config.validate_action(dict(action='model_select',model=settings.model,model_digest=settings.model_digest,compute_mode='cpu',timeout_seconds=value))


def _drift_snapshot(settings, rows, state):
    telemetry = ModelTelemetry(lambda: settings, inspect=lambda _s: {'state': state},
                               loaded=lambda _s: {}, catalog=lambda: [dict(row) for row in rows])
    telemetry.snapshot()
    if telemetry._thread is not None:
        telemetry._thread.join(2)
    return telemetry.snapshot()


def test_drift_reports_an_updated_copy_of_the_pinned_model_without_inference():
    from megalodon.config import AISettings
    settings = AISettings(enabled=True, model='qwen2.5:7b', model_digest='a' * 64)
    rows = [dict(name='qwen2.5:7b', digest='b' * 64, size_bytes=1), dict(name='llama3:8b', digest='c' * 64, size_bytes=1)]
    observed = _drift_snapshot(settings, rows, 'policy_rejection')
    assert observed['drift'] == 'digest_changed' and observed['installed_digest'] == 'b' * 64
    assert 'aaaaaaaaaaaa' in observed['message'] and 'bbbbbbbbbbbb' in observed['message']
    assert observed['selected_digest'] == 'a' * 64  # Nothing is re-pinned without the operator.


def test_drift_reports_a_removed_model_and_none_when_in_sync():
    from megalodon.config import AISettings
    settings = AISettings(enabled=True, model='qwen2.5:7b', model_digest='a' * 64)
    removed = _drift_snapshot(settings, [dict(name='llama3:8b', digest='c' * 64, size_bytes=1)], 'model_missing')
    assert removed['drift'] == 'missing' and removed['installed_digest'] is None
    assert 'no longer installed' in removed['message']
    in_sync = _drift_snapshot(settings, [dict(name='qwen2.5:7b', digest='a' * 64, size_bytes=1)], 'model_available')
    assert in_sync['drift'] is None and in_sync['installed_digest'] is None
    disabled = _drift_snapshot(AISettings(), [dict(name='llama3:8b', digest='c' * 64, size_bytes=1)], 'disabled')
    assert disabled['drift'] is None
    # A pinned tag that still exists but is filtered from the local catalog
    # (remote-backed or non-GGUF) keeps its real state; it is not "removed".
    filtered = _drift_snapshot(settings, [dict(name='llama3:8b', digest='c' * 64, size_bytes=1)], 'model_not_local')
    assert filtered['drift'] is None and 'no longer installed' not in filtered['message']


def test_disabled_model_inventory_requires_explicit_setup_refresh(tmp_path, monkeypatch):
    calls = []
    row = dict(name='llama3.2:3b', digest='b' * 64, size_bytes=2**30)

    def catalog():
        calls.append('catalog')
        return [dict(row)]

    monkeypatch.setattr(provider, 'model_catalog', catalog)
    monkeypatch.setattr(support_config, 'interfaces', lambda: [])
    manager = support_config.SupportConfiguration(
        Settings(db_path=tmp_path / 'events.db'), home=tmp_path
    )
    assert manager.snapshot()['model']['options'] == []
    assert calls == []

    manager.start(dict(action='model_refresh'))
    manager._thread.join(3)
    observed = manager.snapshot()
    assert observed['job']['state'] == 'finished'
    assert observed['model']['options'] == [row]
    assert not manager.settings.ai.enabled
    assert calls == ['catalog']
    manager.snapshot()
    assert calls == ['catalog']


@pytest.mark.parametrize('posture,expected', [
    ({'listening': 'no', 'loopback_only': None}, 'OLLAMA_UNAVAILABLE'),
    ({'listening': 'unknown', 'loopback_only': None}, 'POLICY_REJECTION'),
    ({'listening': 'yes', 'loopback_only': False}, 'POLICY_REJECTION'),
    (OSError('proc unreadable'), 'POLICY_REJECTION'),
    (ValueError('PROVIDER_CONTAINMENT:INVALID_TARGET'), 'POLICY_REJECTION'),
])
def test_catalog_and_admission_share_one_listener_verdict(monkeypatch, posture, expected):
    def observe(**_):
        if isinstance(posture, Exception):
            raise posture
        return posture
    monkeypatch.setattr(provider, 'qwen_provider_posture', observe)
    monkeypatch.setattr(provider, '_request', lambda *a, **k: pytest.fail('posture failure reached Ollama'))
    with pytest.raises(provider.AIProviderError) as catalog:
        provider.model_catalog()
    with pytest.raises(provider.AIProviderError) as admitted:
        provider._admitted(AISettings(enabled=True))
    assert catalog.value.code == admitted.value.code == expected


def test_stopped_ollama_reads_as_unavailable_in_hud_and_setup_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(provider, 'qwen_provider_posture', lambda **_: {'listening': 'no', 'loopback_only': None})
    settings = AISettings(enabled=True, model='llama3.2:3b', model_digest='b' * 64)
    telemetry = ModelTelemetry(lambda: settings, inspect=lambda value: provider.status(value, probe=False))
    telemetry.snapshot(); telemetry._thread.join(2)
    assert telemetry.snapshot()['model_state'] == 'ollama_unavailable'
    monkeypatch.setattr(support_config, 'interfaces', lambda: [])
    manager = support_config.SupportConfiguration(Settings(db_path=tmp_path / 'events.db'), home=tmp_path)
    manager.start(dict(action='model_refresh')); manager._thread.join(3)
    job = manager.snapshot()['job']
    assert job['state'] == 'failed' and 'Ollama is unavailable' in job['message']
    assert 'stopped unexpectedly' not in job['message']
