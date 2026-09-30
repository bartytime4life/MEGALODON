from copy import deepcopy
from types import SimpleNamespace
import json
import pytest

from megalodon.config import Settings,AISettings
from megalodon.defense import Defense,validate_request
from megalodon.defense_guard import ROOT_PROGRAM


@pytest.fixture
def manager(tmp_path):
    row=dict(ip='1.1.1.1',scope='Public',local=False,packets=3,bytes=120,active_connections=1,
             ports=[dict(protocol='TCP',port=443,hint='HTTPS')],flags=['ACK'],names=[],findings=[])
    operations=SimpleNamespace(endpoint=lambda ip:dict(deepcopy(row),ip=ip))
    calls=[]
    worker=SimpleNamespace(config=SimpleNamespace(nmap_target='127.0.0.1/32',clamav_paths=(tmp_path/'Downloads',)),
                           request_collection=lambda selected: calls.append(selected) or {key:'queued' for key in selected})
    config=SimpleNamespace(home=tmp_path,settings=Settings(ai=AISettings(enabled=True)),companions=worker)
    def guard(argv,*args):
        calls.append(argv)
        return json.dumps(dict(ip=argv[-1],present=argv[-2]=='apply',remaining_seconds=299 if argv[-2]=='apply' else None,verified=True)).encode(),0
    defense=Defense(operations,config,run=guard,model=lambda *a,**k:'{"explanation":"Observed activity; safety is unknown.","proposal":"contain"}')
    return defense,calls,row


def perform(manager,body):
    manager.start(body);manager._thread.join(3)
    return manager.snapshot()['job']


def test_model_cannot_apply_even_when_it_proposes_containment(manager):
    defense,calls,_=manager
    result=perform(defense,dict(action='analyze',ip='1.1.1.1'))
    assert result['state']=='finished' and result['result']['proposal']=='contain'
    assert not calls and not defense.snapshot()['active']
    assert defense.path.exists()


def test_analysis_uses_real_provider_contract_without_model_authority(manager,monkeypatch):
    from megalodon import ai_provider
    defense,calls,_=manager
    monkeypatch.setattr(ai_provider,'qwen_provider_posture',lambda:{'listening':'yes','loopback_only':True})
    def transport(path,method,body,timeout):
        if path=='/api/tags':
            return json.dumps({'models':[{'name':AISettings.model,'digest':AISettings.model_digest}]}).encode()
        payload=json.loads(body)
        assert 1<=payload['options']['num_predict']<=256
        assert len(payload['prompt'].encode())<=4096
        assert payload['format']['properties']['proposal']['enum']==['observe','refresh_inventory','scan_files','contain']
        assert payload['format']['additionalProperties'] is False
        assert payload['options']['num_batch']==64
        return json.dumps({'model':AISettings.model,'response':'{"explanation":"Observed traffic; no hostile evidence.","proposal":"observe"}','done':True,'done_reason':'stop'}).encode()
    monkeypatch.setattr(ai_provider,'_request',transport)
    defense.model=ai_provider.generate
    result=perform(defense,dict(action='analyze',ip='1.1.1.1'))
    assert result['state']=='finished' and result['result']['proposal']=='observe'
    assert not calls


def test_provider_busy_reports_retry_without_action(manager):
    from megalodon.ai_provider import AIProviderError
    defense,calls,_=manager
    def busy(*a,**k):raise AIProviderError('CONCURRENCY_LIMIT_REACHED')
    defense.model=busy
    result=perform(defense,dict(action='analyze',ip='1.1.1.1'))
    assert result['state']=='failed' and 'Retry' in result['message']
    assert not calls


def test_preview_apply_release_are_distinct_receipted_actions(manager):
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    assert plan['duration_seconds']==300 and calls==[]
    applied=perform(defense,dict(action='apply_containment',plan_id=plan['id']))
    assert applied['state']=='finished' and applied['result']['verified']
    assert calls[-1][:4]==['/usr/bin/pkexec','/usr/bin/python3','-I','-c']
    assert calls[-1][4]==ROOT_PROGRAM
    assert defense.snapshot()['active'][0]['ip']=='1.1.1.1'
    restored=Defense(defense.operations,defense.configuration,run=defense.run)
    assert restored.snapshot()['active'][0]['ip']=='1.1.1.1'
    released=perform(restored,dict(action='release_containment',ip='1.1.1.1'))
    assert released['state']=='finished' and not restored.snapshot()['active']
    replay=perform(defense,dict(action='apply_containment',plan_id=plan['id']))
    assert replay['state']=='failed' and len(calls)==2


def test_expired_preview_cannot_mutate(manager):
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    defense._plans[plan['id']]['expires_at']='2000-01-01T00:00:00Z'
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='failed'
    assert calls==[]


def test_ambiguous_host_action_retains_release_path_after_restart(manager):
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    defense.run=lambda *a:(b'',1)
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='failed'
    assert defense.snapshot()['active'][0]['state']=='needs_review'
    restored=Defense(defense.operations,defense.configuration,run=lambda argv,*a:(json.dumps(dict(ip=argv[-1],present=False,remaining_seconds=None,verified=True)).encode(),0))
    assert restored.snapshot()['active'][0]['state']=='needs_review'
    assert perform(restored,dict(action='release_containment',ip='1.1.1.1'))['state']=='finished'
    assert restored.snapshot()['active']==[]


@pytest.mark.parametrize('ip',['127.0.0.1','192.168.1.1','224.0.0.1','::1','::ffff:101:101'])
def test_local_and_nonpublic_containment_refused(manager,ip):
    defense,calls,_=manager
    assert perform(defense,dict(action='plan_containment',ip=ip))['state']=='failed'
    assert calls==[]


@pytest.mark.parametrize('port',[22,53,853,3389])
def test_dns_and_remote_access_services_are_protected(manager,port):
    defense,calls,row=manager
    row['ports'][0]['port']=port
    assert perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['state']=='failed'
    assert calls==[]


@pytest.mark.parametrize('body',[{'action':'shell','command':'whoami'},{'action':'scan_files','path':'/'},{'action':'analyze','ip':'1.1.1.1;id'},{'action':'apply_containment','plan_id':'x'*32},{'action':'plan_containment','ip':'1.1.1.0/24'}])
def test_no_arbitrary_commands_targets_or_scopes(body):
    with pytest.raises(ValueError):validate_request(body)


def test_invalid_model_output_is_not_executed(manager):
    defense,calls,_=manager
    defense.model=lambda *a,**k:'{"explanation":"Do it","proposal":"shell","command":"id"}'
    assert perform(defense,dict(action='analyze',ip='1.1.1.1'))['state']=='failed'
    assert calls==[]


def test_fixed_collectors_keep_existing_scope(manager):
    defense,calls,_=manager
    assert perform(defense,{'action':'scan_files'})['state']=='finished'
    assert perform(defense,{'action':'refresh_inventory'})['state']=='finished'
    assert calls==[{'clamav'},{'nmap','osquery'}]


def test_guard_refuses_foreign_rules_and_does_not_flush_other_tables():
    helper={'__name__':'guard_fixture'};exec(ROOT_PROGRAM,helper)
    objects=[]
    for item in helper['initial']()['nftables']:
        objects.append(deepcopy(item['add']))
    data={'nftables':objects}
    assert helper['validate'](data)=={'blocked_v4':{},'blocked_v6':{}}
    data['nftables'][-1]['rule']['expr']=[{'accept':None}]
    with pytest.raises(ValueError):helper['validate'](data)
    assert 'flush' not in ROOT_PROGRAM
