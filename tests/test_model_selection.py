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
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda:{'listening':'yes','loopback_only':True})
    def request(path,method,body,timeout):
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


def test_long_budget_keeps_metadata_fast_and_rejects_unbounded_requests(model_provider,monkeypatch):
    settings,_,_=model_provider
    assert settings.timeout_seconds==300
    seen=[];original=provider._request
    def request(path,method,body,timeout):
        seen.append((path,timeout));return original(path,method,body,timeout)
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
    telemetry.snapshot(); telemetry._thread.join(2)
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
