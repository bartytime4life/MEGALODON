"""A fixed manual response test cannot grant general model admission."""
from dataclasses import replace
import json
from threading import Event
from types import SimpleNamespace
import sys

import pytest

from megalodon import ai_provider as provider, local_model_runtime
from megalodon.config import AISettings
from megalodon.model_telemetry import ModelTelemetry
from megalodon.model_test import ModelTest
from test_qwen_zero_effect import no_effects


@pytest.fixture
def wire(monkeypatch):
    settings=AISettings(enabled=True,model='qwen3:4b',model_digest='b'*64)
    state=dict(reply='READY',digest=settings.model_digest,details=dict(details={'format':'gguf'},capabilities=['completion']))
    calls=[]
    def request(path,method,body,timeout,**kwargs):
        test=kwargs['model_test']
        assert provider._test_request_allowed(test,path,method,body,timeout)
        calls.append((path,method,json.loads(body) if body else None))
        if path=='/api/tags':return json.dumps(dict(models=[dict(name=settings.model,digest=state['digest'],**state.get('tag',{}))])).encode()
        if path=='/api/show':return json.dumps(state['details']).encode()
        assert path=='/api/generate'
        if state.get('cancel'): state['cancel'].set()
        return json.dumps(dict(model=settings.model,done=True,response=state['reply'],done_reason=state.get('reason','stop'))).encode()
    monkeypatch.setattr(provider,'_request',request)
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda **_:dict(listening='yes',loopback_only=True))
    return settings,state,calls


@pytest.mark.parametrize('compute,gpu',[('cpu',0),('auto',-1)])
def test_fixed_test_uses_saved_compute_and_does_not_promote_runtime(wire,compute,gpu):
    settings,_,calls=wire
    settings=replace(settings,compute_mode=compute)
    before=provider.last_observation(settings)
    provider.test_selected_model(settings)
    assert [row[0] for row in calls]==['/api/tags','/api/show','/api/tags','/api/generate','/api/tags']
    payload=calls[3][2]
    assert payload==dict(model=settings.model,prompt=provider.MODEL_TEST_PROMPT,stream=False,think=False,raw=False,
        keep_alive=60,options=dict(temperature=0,num_ctx=512,num_batch=32,num_gpu=gpu,num_predict=32))
    assert provider.last_observation(settings)==before
    assert local_model_runtime.binding_failure()=='OWNER_MODEL_BINDING_NOT_RECORDED'
    assert provider.status(settings)['state']=='unbound'
    with pytest.raises(provider.AIProviderError,match='OWNER_MODEL_BINDING_NOT_RECORDED'):
        provider.generate(settings,'caller prompt')


@pytest.mark.parametrize('change,code',[
    ({'reply':'not READY'},'INVALID_RESPONSE'),({'reason':'length'},'INVALID_RESPONSE'),
    ({'digest':'c'*64},'MODEL_MISMATCH'),
    ({'details':dict(details={'format':'gguf'},capabilities=['completion'],remote_host='https://outside.invalid')},'MODEL_NOT_LOCAL'),
    ({'details':dict(details={'format':'safetensors'},capabilities=['completion'])},'MODEL_NOT_LOCAL'),
    ({'details':dict(details={'format':'gguf'},capabilities=['embedding'])},'MODEL_NOT_LOCAL'),
    ({'tag':dict(remote_host='https://outside.invalid')},'MODEL_NOT_LOCAL'),
])
def test_bad_identity_locality_or_response_cannot_pass(wire,change,code):
    settings,state,calls=wire
    state.update(change)
    with pytest.raises(provider.AIProviderError,match='^'+code+'$'):provider.test_selected_model(settings)
    if code in {'MODEL_MISMATCH','MODEL_NOT_LOCAL'}:assert all(c[0]!='/api/generate' for c in calls)


def test_cancel_before_start_and_after_reply_are_not_lost(wire):
    settings,state,calls=wire
    event=Event();event.set()
    with pytest.raises(provider.AIProviderError,match='REQUEST_CANCELLED'):
        provider.test_selected_model(settings,cancel_event=event)
    assert not calls
    event.clear();state['cancel']=event
    with pytest.raises(provider.AIProviderError,match='REQUEST_CANCELLED'):
        provider.test_selected_model(settings,cancel_event=event)
    assert provider._generation_lock.acquire(blocking=False)
    provider._generation_lock.release()


@pytest.mark.parametrize('phase',['/api/show','/api/generate'])
def test_changed_tag_during_probe_is_rejected(wire,monkeypatch,phase):
    settings,state,calls=wire
    original=provider._request
    def request(path,*a,**kw):
        if path==phase:state['digest']='c'*64
        return original(path,*a,**kw)
    monkeypatch.setattr(provider,'_request',request)
    with pytest.raises(provider.AIProviderError,match='MODEL_MISMATCH'):provider.test_selected_model(settings)
    if phase=='/api/show':assert all(row[0]!='/api/generate' for row in calls)


@pytest.mark.parametrize('change', [dict(enabled=False),dict(endpoint='http://outside.invalid'),
    dict(model='../model'),dict(model_digest='bad'),dict(compute_mode='cuda'),dict(timeout_seconds=True)])
def test_disabled_or_invalid_probe_denies_before_effects(wire,monkeypatch,change):
    settings,_,calls=wire
    with no_effects(monkeypatch),pytest.raises(provider.AIProviderError):
        provider.test_selected_model(replace(settings,**change))
    assert not calls


@pytest.mark.parametrize('posture',[dict(listening='no',loopback_only=None),dict(listening='yes',loopback_only=False),dict(listening='unknown',loopback_only=None)])
def test_listener_unavailable_wildcard_or_unknown_refuses_before_requests(wire,monkeypatch,posture):
    settings,_,calls=wire
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda **_:posture)
    with pytest.raises(provider.AIProviderError):provider.test_selected_model(settings)
    assert not calls


@pytest.mark.parametrize('mutation', ['prompt','options','tools','model','keep_alive','endpoint','path','method','duration','mixed'])
def test_low_level_exception_rejects_arbitrary_prompts_options_or_paths(monkeypatch,mutation):
    request=provider._request
    permit=provider._ModelTest('qwen3:4b','b'*64,'cpu')
    body=permit.payload();path='/api/generate';method='POST';timeout=30;kwargs=dict(model_test=permit)
    if mutation=='prompt':body['prompt']='arbitrary prompt'
    elif mutation=='options':body['options']['num_predict']=1000
    elif mutation=='tools':body['tools']=['anything']
    elif mutation=='model':body['model']='another:tag'
    elif mutation=='keep_alive':body['keep_alive']=-1
    elif mutation=='endpoint':path='http://outside.invalid/api/generate'
    elif mutation=='path':path='/api/pull'
    elif mutation=='method':method='GET'
    elif mutation=='duration':timeout=301
    else:kwargs['catalog_read']=True
    with no_effects(monkeypatch),pytest.raises(provider.AIProviderError,match='POLICY_REJECTION'):
        request(path,method,provider._encoded(body),timeout,**kwargs)


def test_same_shape_without_explicit_probe_permit_remains_unbound(monkeypatch):
    request=provider._request
    permit=provider._ModelTest('qwen3:4b','b'*64,'cpu')
    with no_effects(monkeypatch),pytest.raises(provider.AIProviderError,match='OWNER_MODEL_BINDING_NOT_RECORDED'):
        request('/api/generate','POST',provider._encoded(permit.payload()),30)


def test_tracker_invalidates_result_when_selection_changes_and_sanitizes_errors(wire,monkeypatch):
    settings,_,_=wire
    selected=[settings]
    test=ModelTest(lambda:selected[0])
    test.prepare();test.run()
    assert test.snapshot()['state']=='passed'
    selected[0]=replace(settings,compute_mode='auto')
    assert test.snapshot()['state']=='idle'
    monkeypatch.setattr(provider,'test_selected_model',lambda *_a,**_k:(_ for _ in ()).throw(RuntimeError('private URL or prompt')))
    test.prepare()
    with pytest.raises(ValueError):test.run()
    assert test.snapshot()['error_code']=='PROVIDER_ERROR'
    assert 'private' not in json.dumps(test.snapshot())


def test_successful_explicit_catalog_is_connection_evidence_only(monkeypatch):
    model=ModelTelemetry(lambda:AISettings(enabled=True),choices=lambda:[])
    assert model.snapshot()['connection_state']=='unchecked'
    model.refresh_installed_models()
    value=model.snapshot()
    assert value['connection_state']=='reachable' and value['inference_verified'] is False
    assert value['binding_status']=='UNBOUND' and value['loaded'] is None
    def offline():raise provider.AIProviderError('OLLAMA_UNAVAILABLE')
    model.choices=offline
    with pytest.raises(provider.AIProviderError):model.refresh_installed_models()
    assert model.snapshot()['connection_state']=='unavailable'


@pytest.mark.parametrize('service,expected',[('running','green'),('stopped','amber'),('unknown','grey')])
def test_heartbeat_separates_reachable_ollama_from_unbound_model(monkeypatch,service,expected):
    from megalodon import tool_heartbeat
    monkeypatch.setattr(tool_heartbeat,'heartbeat_report',lambda *_:dict(tools=[dict(id='qwen',installed='yes',service=service,
        expects_service=True,light='amber',model='unknown')]))
    observed=dict(model='qwen3:4b',model_present=False,state='needs_setup',message=local_model_runtime.MESSAGE,
        updated_at=None,last_response_at=None,binding_status='UNBOUND',connection_state='reachable')
    result=json.loads(tool_heartbeat.Heartbeat(model_observer=lambda:observed).snapshot())['tools'][0]
    assert result['light']==expected and result['model']=='unknown'
    assert result['selected_model']['binding_status']=='UNBOUND'


@pytest.mark.parametrize('extra',[dict(prompt='anything'),dict(model='other:tag'),dict(url='https://outside.invalid'),dict(options={}),dict(enabled=True)])
def test_http_action_never_accepts_test_prompt_model_or_options(extra):
    from megalodon.support_config import validate_action
    with pytest.raises(ValueError):validate_action(dict(action='model_test',**extra))


@pytest.mark.skipif(sys.platform!='linux',reason='Native Linux literal-loopback/lock acceptance')
@pytest.mark.parametrize('outcome',['success','cancel'])
def test_native_fixed_probe_wire_and_cancellation(private_tmp_path,monkeypatch,outcome):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    settings=AISettings(enabled=True,model='qwen3:4b',model_digest='b'*64,timeout_seconds=5)
    event=Event();entered=Event();release=Event();calls=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def send(self,value):
            data=json.dumps(value).encode()
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)));self.end_headers()
            try:self.wfile.write(data)
            except (OSError,ConnectionError):pass
        def do_GET(self):
            calls.append((self.path,None))
            self.send(dict(models=[dict(name=settings.model,digest=settings.model_digest)]))
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append((self.path,body))
            if self.path=='/api/show':self.send(dict(details={'format':'gguf'},capabilities=['completion']))
            else:
                entered.set()
                if outcome=='cancel':release.wait(3)
                self.send(dict(model=settings.model,done=True,response='READY',done_reason='stop'))
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    monkeypatch.setattr(provider.transport,'LOOPBACK_PORT',server.server_port)
    monkeypatch.setattr(provider.transport,'_PROCESS_LOCK_DIRECTORY',str(private_tmp_path))
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda **_:dict(listening='yes',loopback_only=True))
    def cancel():
        if entered.wait(3):event.set()
    canceller=Thread(target=cancel,daemon=True)
    if outcome=='cancel':canceller.start()
    try:
        if outcome=='cancel':
            with pytest.raises(provider.AIProviderError,match='REQUEST_CANCELLED'):
                provider.test_selected_model(settings,cancel_event=event)
        else:provider.test_selected_model(settings)
    finally:
        release.set();server.shutdown();server.server_close();thread.join(2)
        if outcome=='cancel':canceller.join(2)
    assert all(path in {'/api/tags','/api/show','/api/generate'} for path,_ in calls)
    bodies=[body for path,body in calls if path=='/api/generate']
    assert len(bodies)==1 and bodies[0]['prompt']==provider.MODEL_TEST_PROMPT
    assert provider.status(settings)['state']=='unbound'
