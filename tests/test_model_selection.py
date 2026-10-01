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


def test_selector_persists_exact_identity_and_restarts(model_provider,tmp_path,monkeypatch):
    settings,state,requests=model_provider
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    manager=support_config.SupportConfiguration(Settings(db_path=tmp_path/'data/events.db'),home=tmp_path)
    request=dict(action='model_select',model=settings.model,model_digest=settings.model_digest,compute_mode='cpu')
    manager.start(request);manager._thread.join(3)
    assert manager.snapshot()['job']['state']=='finished'
    assert manager.settings.ai.model==settings.model and manager.settings.ai.enabled
    persisted=json.loads((tmp_path/'.config/megalodon/qwen-profile.json').read_text())
    assert persisted['schema']=='megalodon-local-model-v1'
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
