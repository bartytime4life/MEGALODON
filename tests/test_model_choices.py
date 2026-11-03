"""Explicit local model choices grant no model execution or acceptance."""
import json
from types import SimpleNamespace

import pytest

from megalodon import ai_provider as provider, local_model_runtime, support_config
from megalodon.config import AISettings, Settings
from megalodon.model_telemetry import ModelTelemetry
from test_qwen_zero_effect import no_effects


def row(name='llama3.2:3b', digest='b'*64):
    return dict(name=name, digest=digest, size_bytes=2**30)


def test_catalog_exception_only_permits_exact_bodyless_tags_get(monkeypatch):
    request=provider._request
    for path,method,body,timeout,flag in [
        ('/api/generate','POST',None,3,True), ('/api/show','POST',None,3,True),
        ('/api/ps','GET',None,3,True), ('/api/tags','GET',b'prompt',3,True),
        ('/api/tags','POST',None,3,True), ('/api/tags','GET',None,4,True),
        ('/api/tags','GET',None,float('nan'),True), ('/api/tags','GET',None,3,1),
        ('http://outside.invalid/api/tags','GET',None,3,True)]:
        with no_effects(monkeypatch), pytest.raises(provider.AIProviderError,match='^POLICY_REJECTION$'):
            request(path,method,body,timeout,catalog_read=flag)


def test_real_catalog_transport_sends_only_one_fixed_loopback_get(monkeypatch):
    calls=[]
    data=json.dumps({'models':[
        dict(name='llama3.2:3b',digest='b'*64,size=2**30,details={'format':'gguf'}),
        dict(name='nemotron:120b',digest='c'*64,size=2**36,details={'format':'gguf'}),
        dict(name='remote:cloud',digest='d'*64,size=100,details={'format':'gguf'},remote_host='https://remote.invalid'),
        dict(name='unsupported:tag',digest='e'*64,size=100,details={'format':'safetensors'}),
    ]}).encode()
    class Connection:
        def __init__(self,host,port,**kwargs):
            assert (host,port)==('127.0.0.1',11434)
        def request(self,method,path,*,body,headers):
            calls.append((method,path,body))
        def getresponse(self):
            return SimpleNamespace(status=200,getheader=lambda name,default=None: 'application/json' if name=='Content-Type' else default)
        def close(self):
            pass
    class Guard:
        def __init__(self,*args): pass
        def start(self): pass
        def finish(self): return None
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda **_:dict(listening='yes',loopback_only=True))
    monkeypatch.setattr(provider.transport,'_LiteralLoopbackHTTPConnection',Connection)
    monkeypatch.setattr(provider.transport,'_InvocationGuard',Guard)
    monkeypatch.setattr(provider.transport,'_acquire_process_invocation_lock',lambda:None)
    monkeypatch.setattr(provider.transport,'_read_provider_body',lambda *_:data)
    assert provider.model_choices()==[row(),row('nemotron:120b','c'*64)|{'size_bytes':2**36}]
    assert calls==[('GET','/api/tags',None)]
    assert local_model_runtime.binding_failure()=='OWNER_MODEL_BINDING_NOT_RECORDED'


@pytest.mark.parametrize('posture', [dict(listening='no',loopback_only=None),
    dict(listening='yes',loopback_only=False),dict(listening='unknown',loopback_only=None)])
def test_discovery_refuses_unavailable_or_exposed_listener_before_request(monkeypatch,posture):
    monkeypatch.setattr(provider,'qwen_provider_posture',lambda **_:posture)
    with no_effects(monkeypatch),pytest.raises(provider.AIProviderError):
        provider.model_choices()


def test_failed_explicit_refresh_clears_old_choices_and_never_relabels_runtime(monkeypatch):
    calls=[]
    def choices():
        calls.append('explicit')
        if len(calls)>1: raise provider.AIProviderError('OLLAMA_UNAVAILABLE')
        return [row()]
    monitor=ModelTelemetry(lambda:AISettings(enabled=True),choices=choices)
    with no_effects(monkeypatch):
        assert monitor.snapshot()['options']==[] and calls==[]
        monitor.refresh_installed_models()
        assert monitor.snapshot()['options']==[row()]
        with pytest.raises(provider.AIProviderError):monitor.refresh_installed_models()
        value=monitor.snapshot()
        assert monitor.snapshot()==value
    assert value['options']==[] and value['updated_at'] is None
    assert value['inference_verified'] is False and value['loaded'] is None
    assert value['binding_status']=='UNBOUND'
    assert 'unavailable' in value['message'] and len(calls)==2


@pytest.mark.parametrize('change', [lambda x:x.update(models='invalid'),
    lambda x:x['models'].append(dict(x['models'][0]))])
def test_malformed_or_ambiguous_catalog_refused(change):
    value={'models':[dict(name='llama3.2:3b',digest='b'*64,size=1,details={'format':'gguf'})]}
    change(value)
    with pytest.raises(provider.AIProviderError,match='^INVALID_RESPONSE$'):provider._catalog_rows(value)


@pytest.fixture
def manager(tmp_path,monkeypatch):
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    monkeypatch.setattr(provider,'model_choices',lambda:[row(),row('nemotron:120b','c'*64)])
    value=support_config.SupportConfiguration(Settings(db_path=tmp_path/'events.db'),home=tmp_path)
    def forbidden(*_a,**_k):pytest.fail('choice attempted model admission, load or inference')
    monkeypatch.setattr(provider,'_admitted',forbidden)
    monkeypatch.setattr(provider,'status',forbidden)
    monkeypatch.setattr(value.model_lifecycle,'request',forbidden)
    return value


@pytest.mark.parametrize('name,digest,compute', [('llama3.2:3b','b'*64,'cpu'),('nemotron:120b','c'*64,'auto')])
def test_unbound_choice_survives_restart_without_loading(manager,tmp_path,name,digest,compute):
    manager._work(dict(action='model_select',model=name,model_digest=digest,compute_mode=compute,timeout_seconds=600))
    assert manager._job['state']=='finished',manager._job['message']
    assert 'No model was loaded' in manager._job['message']
    profile=tmp_path/'.config/megalodon/qwen-profile.json'
    assert profile.stat().st_mode&0o777==0o600
    saved=json.loads(profile.read_text())
    assert saved==dict(schema='megalodon-local-model-v2',model=name,model_digest=digest,compute_mode=compute,timeout_seconds=600)
    reopened=support_config.SupportConfiguration(Settings(db_path=tmp_path/'events.db'),home=tmp_path)
    assert (reopened.settings.ai.model,reopened.settings.ai.model_digest,reopened.settings.ai.compute_mode)==(name,digest,compute)
    assert reopened.qwen_status['state']=='needs_setup'
    assert reopened.model_telemetry.snapshot()['inference_verified'] is False
    assert reopened.model_lifecycle.snapshot()['state']=='unbound'
    assert local_model_runtime.binding_failure()=='OWNER_MODEL_BINDING_NOT_RECORDED'


@pytest.mark.parametrize('name,digest',[('missing:tag','b'*64),('llama3.2:3b','c'*64)])
def test_changed_or_missing_choice_cannot_change_saved_preferences(manager,tmp_path,name,digest):
    before=manager.settings
    manager._work(dict(action='model_select',model=name,model_digest=digest,compute_mode='auto'))
    assert manager._job['state']=='failed'
    assert manager.settings==before
    assert not (tmp_path/'.config/megalodon/qwen-profile.json').exists()


def test_preference_write_failure_preserves_active_choice(manager,monkeypatch):
    before=manager.settings
    writes=[]
    monkeypatch.setattr(manager,'_paths',lambda:None)
    def failed_write(*args):
        writes.append(args)
        raise OSError('disk unavailable')
    monkeypatch.setattr(support_config,'_atomic_write',failed_write)
    manager._work(dict(action='model_select',model='llama3.2:3b',model_digest='b'*64,compute_mode='auto'))
    assert manager._job['state']=='failed' and manager.settings==before and len(writes)==1
