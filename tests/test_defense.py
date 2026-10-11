from copy import deepcopy
from ipaddress import ip_address
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
    monkeypatch.setattr(ai_provider,'qwen_provider_posture',lambda **_:{'listening':'yes','loopback_only':True})
    def transport(path,method,body,timeout,*,deadline=None):
        if path == '/api/show':
            return json.dumps({'details':{'format':'gguf'},'capabilities':['completion']}).encode()
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


def test_managed_explanation_is_referenced_not_copied_to_action_ledger(manager):
    defense,calls,_=manager
    defense.configuration.intelligence=SimpleNamespace(explain_device=lambda ip:dict(
        review_id='a'*24,explanation='Source-expiring explanation',proposal='observe',analysis_state='ready'),endpoint_result_valid=lambda result:True)
    result=perform(defense,dict(action='analyze',ip='1.1.1.1'))
    assert result['state']=='finished'
    assert result['result']['explanation']=='Source-expiring explanation'
    from megalodon.ai_broker import ReceiptStore
    with ReceiptStore(defense.path) as store:
        audit=store.latest(defense.snapshot()['recent'][-1]['receipt_id'])
    assert audit['result']==dict(review_id='a'*24,action_status='not_attempted')
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
    # Python releases differ in their canonical rendering of mapped IPv6.
    assert perform(defense,dict(action='plan_containment',ip=str(ip_address(ip))))['state']=='failed'
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


def test_failed_reapply_keeps_the_recorded_block_releasable(manager):
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='finished'
    # The still-observed address is previewed again, but that preview expires before
    # Apply, so the attempt fails without touching the host.
    second=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    defense._plans[second['id']]['expires_at']='2000-01-01T00:00:00Z'
    assert perform(defense,dict(action='apply_containment',plan_id=second['id']))['state']=='failed'
    assert [(a['ip'],a['state']) for a in defense.snapshot()['active']]==[('1.1.1.1','applied')]
    restored=Defense(defense.operations,defense.configuration,run=defense.run)
    assert [(a['ip'],a['state']) for a in restored.snapshot()['active']]==[('1.1.1.1','applied')]
    assert perform(restored,dict(action='release_containment',ip='1.1.1.1'))['state']=='finished'
    assert calls[-1][-2:]==['release','1.1.1.1'] and restored.snapshot()['active']==[]


def test_outcome_row_may_use_the_ledger_reserve_after_a_host_change(manager,monkeypatch):
    from megalodon import defense as defense_module
    from megalodon.ai_broker import ReceiptStore
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    guard=defense.run

    def guard_then_reserve_reached(argv,*args):
        # The pre-execution row was admitted; the ledger now sits inside the reserve.
        monkeypatch.setattr(defense_module,'MAX_LEDGER_BYTES',0)
        return guard(argv,*args)

    defense.run=guard_then_reserve_reached
    applied=perform(defense,dict(action='apply_containment',plan_id=plan['id']))
    assert applied['state']=='finished' and defense.snapshot()['audit_ready'] is True
    with ReceiptStore(defense.path) as store:
        last=json.loads(store.connection.execute(
            'SELECT payload_json FROM ai_receipt_events ORDER BY sequence DESC LIMIT 1').fetchone()[0])
    assert (last['action'],last['state'],last['result']['ip'])==('apply_containment','applied','1.1.1.1')
    # A new action is still refused before it runs, and its refusal never writes
    # an outcome row without a recorded opening row.
    refused=perform(defense,dict(action='plan_containment',ip='1.0.0.1'))
    assert refused['state']=='failed'
    with ReceiptStore(defense.path) as store:
        store.verify_chain()
        after=json.loads(store.connection.execute(
            'SELECT payload_json FROM ai_receipt_events ORDER BY sequence DESC LIMIT 1').fetchone()[0])
    assert after==last


def test_protected_service_survives_port_list_truncation(tmp_path):
    from megalodon.operations import Operations

    def flow(index,remote_port,local_port):
        side=dict(packets=1,bytes=100,last_seen='2026-10-10T00:00:00Z')
        return dict(id=str(index),protocol='TCP',a=dict(ip='192.168.1.10',port=local_port,local=True,location=None),
                    b=dict(ip='8.8.4.4',port=remote_port,local=False,location=None),
                    a_to_b=dict(side),b_to_a=dict(side),first_seen='2026-10-10T00:00:00Z',
                    last_seen='2026-10-10T00:00:00Z',state='recent',flags=[],active=True)

    # Twelve more recent flows fill the bounded port list before the DNS flow.
    live=dict(connections=[flow(i,40000+i,8443) for i in range(12)]+[flow(99,53,51515)],
              capture=dict(state='running'),background={},totals=dict(unmapped=0,truncated=False))
    config=SimpleNamespace(live_snapshot=lambda:live,settings=Settings(),home=tmp_path,companions=None)
    operations=Operations(config,context_reader=lambda:{})
    ports=[p['port'] for p in operations.endpoint('8.8.4.4')['ports']]
    assert len(ports)==12 and 53 in ports
    defense=Defense(operations,config,run=lambda *a:pytest.fail('no host action expected'))
    with pytest.raises(ValueError,match='protected'):
        defense._target('8.8.4.4')


def test_unrecorded_request_writes_no_outcome_row_and_keeps_release(manager,monkeypatch):
    from megalodon import defense as defense_module
    from megalodon.ai_broker import BrokerError,ReceiptStore
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='finished'

    class Contended(ReceiptStore):
        # Another writer holds the ledger: only the opening row is refused, once.
        def append(self,receipt_id,payload):
            if payload['state']=='not_attempted':
                monkeypatch.setattr(defense_module,'ReceiptStore',ReceiptStore)
                raise BrokerError('AUDIT_UNAVAILABLE')
            return super().append(receipt_id,payload)

    monkeypatch.setattr(defense_module,'ReceiptStore',Contended)
    refused=perform(defense,{'action':'refresh_inventory'})
    with ReceiptStore(defense.path) as store:store.verify_chain()
    restored=Defense(defense.operations,defense.configuration,run=defense.run)
    assert restored.snapshot()['audit_ready'] is True
    assert refused['state']=='failed' and 'nothing was attempted' in refused['message']
    assert calls[-1]!={'nmap','osquery'} and defense.snapshot()['audit_ready'] is True
    assert perform(restored,dict(action='release_containment',ip='1.1.1.1'))['state']=='finished'


def test_storage_reserve_refusal_does_not_disable_release(manager,monkeypatch):
    from megalodon import defense as defense_module
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='finished'
    limit=defense_module.MAX_LEDGER_BYTES
    monkeypatch.setattr(defense_module,'MAX_LEDGER_BYTES',0)
    refused=perform(defense,{'action':'scan_files'})
    assert defense.snapshot()['audit_ready'] is True and calls[-1]!={'clamav'}
    assert refused['state']=='failed' and refused['message']=='Defense audit storage is full.'
    # Once the operator frees space, Release works without a restart.
    monkeypatch.setattr(defense_module,'MAX_LEDGER_BYTES',limit)
    assert perform(defense,dict(action='release_containment',ip='1.1.1.1'))['state']=='finished'
    assert calls[-1][-2:]==['release','1.1.1.1'] and defense.snapshot()['active']==[]


@pytest.mark.parametrize('ip',['64:ff9b::808:808','64:ff9b::101:101','64:ff9b::c0a8:101','64:ff9b:1::808:808'])
def test_nat64_forms_are_refused_like_mapped_addresses(manager,ip):
    from dataclasses import replace
    from ipaddress import ip_network
    defense,calls,_=manager
    settings=defense.configuration.settings
    defense.configuration.settings=replace(settings,blocking=replace(settings.blocking,allowlist=(ip_network('8.8.8.0/24'),)))
    refused=perform(defense,dict(action='plan_containment',ip=ip))
    assert refused['state']=='failed' and 'protected' in refused['message'] and calls==[]
    helper={'__name__':'guard_fixture'};exec(ROOT_PROGRAM,helper)
    helper['nft']=lambda *a,**k:pytest.fail('no firewall access expected')
    with pytest.raises(ValueError,match='Mapped target refused'):helper['act']('apply',ip)


def _guard_with_kernel(kernel):
    """The fixed helper against a fake nft modelling set semantics: add of an
    existing element is a no-op, and a -f batch applies all-or-nothing."""
    helper={'__name__':'guard_fixture'};exec(ROOT_PROGRAM,helper)
    def nft(args,body=None):
        if args==['list','tables']:
            return 0,{'nftables':[{'metainfo':{}},{'table':{'family':'inet','name':'megalodon_guard'}}]}
        if args==['list','table','inet','megalodon_guard']:
            objects=[deepcopy(item['add']) for item in helper['initial']()['nftables']]
            for item in objects:
                if 'set' in item:
                    item['set']['elem']=[{'elem':{'val':ip,'timeout':300,'expires':left}} for ip,left in kernel.items()
                                         if ip_address(ip).version==int(item['set']['name'][-1])]
            return 0,{'nftables':objects}
        assert args==['-f','-']
        staged=dict(kernel)
        for command in body['nftables']:
            (verb,item),=command.items()
            for entry in item['element']['elem']:
                ip=entry['elem']['val'] if type(entry) is dict else entry
                if verb=='add':staged.setdefault(ip,entry['elem']['timeout'])
                elif ip not in staged:return 1,None
                else:del staged[ip]
        kernel.clear();kernel.update(staged)
        return 0,None
    helper['nft']=nft
    return helper


def test_reapply_restarts_the_kernel_timeout():
    kernel={'1.1.1.1':2,'1.0.0.1':150}
    helper=_guard_with_kernel(kernel)
    assert helper['act']('apply','1.1.1.1')=={'ip':'1.1.1.1','present':True,'remaining_seconds':300,'verified':True}
    assert kernel=={'1.1.1.1':300,'1.0.0.1':150}
    assert helper['act']('apply','2606:4700::1111')['remaining_seconds']==300
    assert helper['act']('release','1.1.1.1')['present'] is False and '1.1.1.1' not in kernel


def test_restart_restores_blocks_within_their_lifetime_and_unfinished_applies(manager,monkeypatch):
    from datetime import datetime,timedelta
    from megalodon import defense as defense_module
    from megalodon.ai_broker import ReceiptStore
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='finished'
    with ReceiptStore(defense.path) as store:
        # The HUD stopped while an apply of another address was running.
        store.append('interrupted',dict(state='not_attempted',action='apply_containment',ip='1.0.0.1',message='Operator requested a fixed workflow.',
                     request=dict(action='apply_containment',plan_id='a'*32),approved_preview=dict(plan,ip='1.0.0.1'),result=None))
    for _ in range(40):perform(defense,{'action':'scan_files'})
    states=lambda value:sorted((a['ip'],a['state']) for a in value.snapshot()['active'])
    restored=Defense(defense.operations,defense.configuration,run=defense.run)
    assert states(restored)==[('1.0.0.1','needs_review'),('1.1.1.1','applied')]
    assert len(restored.snapshot()['recent'])==20

    class Later(datetime):
        @classmethod
        def now(cls,tz=None):return datetime.now(tz)+timedelta(hours=1)

    monkeypatch.setattr(defense_module,'datetime',Later)
    # The kernel timeout removed the older block; the unfinished apply still needs review.
    later=Defense(defense.operations,defense.configuration,run=defense.run)
    assert states(later)==[('1.0.0.1','needs_review')]
    assert perform(later,dict(action='release_containment',ip='1.0.0.1'))['state']=='finished'
    assert states(Defense(defense.operations,defense.configuration,run=defense.run))==[]


def test_ambiguous_reapply_of_a_recorded_block_needs_review(manager):
    from megalodon.managed_capture import now
    defense,calls,_=manager
    plan=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    assert perform(defense,dict(action='apply_containment',plan_id=plan['id']))['state']=='finished'
    defense._active['1.1.1.1']=dict(defense._active['1.1.1.1'],expires_at='2000-01-01T00:00:00Z')
    second=perform(defense,dict(action='plan_containment',ip='1.1.1.1'))['result']
    defense.run=lambda *a:(b'',126)   # the helper may have changed the host; its result was lost
    assert perform(defense,dict(action='apply_containment',plan_id=second['id']))['state']=='failed'
    for value in (defense,Defense(defense.operations,defense.configuration,run=defense.run)):
        (entry,)=value.snapshot()['active']
        assert (entry['ip'],entry['state'],entry['verified'])==('1.1.1.1','needs_review',False)
        assert entry['expires_at']>now()


def test_finished_at_is_never_stamped_onto_the_next_job(manager):
    import threading,time
    defense,calls,_=manager
    real=defense._lock;paused=threading.Event();go=threading.Event();gate=threading.Event()

    class Preempt:
        # Stall a worker that re-enters the lock after reporting completion.
        def __enter__(self):
            if (threading.current_thread().name=='megalodon-defense' and defense._job['state'] in {'finished','failed'}
                    and not go.is_set()):
                paused.set();go.wait(3)
            return real.__enter__()
        def __exit__(self,*a):return real.__exit__(*a)

    defense._lock=Preempt()
    defense.start({'action':'scan_files'});first=defense._thread
    deadline=time.monotonic()+3
    while first.is_alive() and not paused.is_set() and time.monotonic()<deadline:time.sleep(.01)
    collect=defense.configuration.companions.request_collection
    defense.configuration.companions.request_collection=lambda selected:(gate.wait(3),collect(selected))[1]
    defense.start({'action':'refresh_inventory'})
    go.set();first.join(3)
    job=defense.snapshot()['job']
    assert (job['action'],job['state'],job['finished_at'])==('refresh_inventory','running',None)
    gate.set();defense._thread.join(3)
    assert defense.snapshot()['job']['finished_at'] is not None
