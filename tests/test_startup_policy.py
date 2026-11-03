"""Reboot preferences and fixed service setup with no live service mutations."""
import json
from pathlib import Path

import pytest

from megalodon import hud_autostart, startup_policy, support_config
from megalodon.config import AISettings, Settings


@pytest.fixture
def manager(monkeypatch):
    calls = []
    units = {'ollama':('inactive','disabled'), 'snap.ollama.listener':('active','enabled'),
             'suricata':('inactive','disabled'), 'clamav-freshclam':('inactive','disabled')}
    state = dict(login='disabled', deny=False)
    def run(argv, limit, timeout):
        assert limit<=2048 and timeout<=90
        calls.append(argv)
        if argv[0]=='/usr/bin/pkexec':
            if state['deny']:return b'',126
            for unit in argv[4:]:units[unit.removesuffix('.service')]=('active','enabled')
            return b'',0
        if '--user' in argv:return state['login'].encode(),0 if state['login']=='enabled' else 1
        assert argv[1]=='show'
        unit=argv[-1].removesuffix('.service')
        if unit not in units:return b'LoadState=not-found\nActiveState=inactive\nUnitFileState=\n',0
        active,enabled=units[unit]
        return f'LoadState=loaded\nActiveState={active}\nUnitFileState={enabled}\n'.encode(),0
    monkeypatch.setattr(startup_policy, '_trusted_system_executable', lambda n:'/usr/bin/'+n)
    monkeypatch.setattr(hud_autostart, 'validate_unit', lambda:True)
    monkeypatch.setattr(hud_autostart, '_service_state', lambda:dict(FragmentPath=str(hud_autostart.unit_path()),DropInPaths='',LoadState='loaded',ActiveState='active'))
    monkeypatch.setattr(hud_autostart, 'enable', lambda:state.update(login='enabled'))
    monkeypatch.setattr(hud_autostart, 'disable_login', lambda:state.update(login='disabled'))
    monkeypatch.setattr(startup_policy.Path, 'is_file', lambda _:True)
    return startup_policy.StartupPolicy(run=run),calls,units,state


def test_snapshot_is_passive_and_explicit_check_is_read_only(manager):
    policy,calls,_,_=manager
    assert policy.snapshot()['login']=='unchecked' and calls==[]
    policy.check()
    assert policy.snapshot()['login']=='disabled'
    count=len(calls)
    assert policy.snapshot()['services'][0]['unit']=='snap.ollama.listener'
    policy.snapshot();assert len(calls)==count
    assert all('show' in argv or 'is-enabled' in argv for argv in calls)


@pytest.mark.parametrize('enabled',[True,False])
def test_login_change_is_read_back_and_survives_controller_restart(manager,enabled):
    policy,calls,_,_=manager
    policy.login(enabled)
    fresh=startup_policy.StartupPolicy(run=policy.run)
    assert fresh.check()['login']==('enabled' if enabled else 'disabled')
    assert not any('pkexec' in argv[0] for argv in calls)


def test_enable_uses_active_snap_and_only_configured_fixed_services(manager):
    policy,calls,units,_=manager
    policy.enable_services(clamav_configured=True)
    writes=[a for a in calls if a[0]=='/usr/bin/pkexec']
    assert writes==[['/usr/bin/pkexec','/usr/bin/systemctl','enable','--now','snap.ollama.listener.service','suricata.service','clamav-freshclam.service']]
    assert units['ollama']==('inactive','disabled')
    assert all(r['enabled']=='enabled' and r['active']=='running' for r in policy.snapshot()['services'])


def test_unconfigured_sensors_and_signature_downloads_are_skipped(manager,monkeypatch):
    policy,calls,_,_=manager
    monkeypatch.setattr(startup_policy.Path,'is_file',lambda _:False)
    policy.enable_services(clamav_configured=False)
    assert [a for a in calls if a[0]=='/usr/bin/pkexec']==[['/usr/bin/pkexec','/usr/bin/systemctl','enable','--now','snap.ollama.listener.service']]


@pytest.mark.parametrize('units',[{'ollama':('inactive','disabled'),'snap.ollama.listener':('inactive','disabled')},
                                 {'ollama':('active','enabled'),'snap.ollama.listener':('active','enabled')}])
def test_ambiguous_ollama_services_are_not_changed(manager,units,monkeypatch):
    policy,calls,current,_=manager
    current.clear();current.update(units)
    monkeypatch.setattr(startup_policy.Path,'is_file',lambda _:False)
    with pytest.raises(ValueError,match='No eligible'):policy.enable_services()
    assert not any(a[0]=='/usr/bin/pkexec' for a in calls)
    assert policy.snapshot()['services'][0]['unit'] is None


def test_denied_authorization_reports_observed_partial_state(manager):
    policy,_,_,state=manager
    state['deny']=True
    with pytest.raises(ValueError,match='not confirmed'):policy.enable_services(clamav_configured=True)
    result={r['id']:r for r in policy.snapshot()['services']}
    assert result['qwen']['enabled']=='enabled' and result['suricata']['enabled']=='disabled'


def test_unavailable_query_does_not_select_another_ollama_service(manager):
    policy,_,_,_=manager
    real=policy.run
    def run(argv,*args):
        if argv[-1]=='snap.ollama.listener.service':raise ValueError('timeout')
        return real(argv,*args)
    assert startup_policy.service_observation('qwen',run)['unit'] is None


@pytest.mark.parametrize('status',['enabled-runtime','static','alias','masked'])
def test_exit_zero_is_not_persistent_login_enablement(manager,status):
    policy,_,_,state=manager
    state['login']=status
    assert policy.check()['login']=='unavailable'


def test_turning_off_login_does_not_stop_or_remove_current_hud(monkeypatch):
    calls=[]
    monkeypatch.setattr(hud_autostart,'validate_unit',lambda:True)
    monkeypatch.setattr(hud_autostart,'_service_state',lambda:dict(FragmentPath=str(hud_autostart.unit_path()),LoadState='loaded',ActiveState='active',DropInPaths=''))
    monkeypatch.setattr(hud_autostart,'_systemctl',lambda *args:calls.append(args))
    hud_autostart.disable_login()
    assert calls==[('disable','megalodon-hud.service')]


@pytest.mark.parametrize('extra',[dict(unit='sshd'),dict(command='anything'),dict(enabled=True),dict(timeout_seconds=60)])
@pytest.mark.parametrize('action',['startup_check','startup_enable','startup_disable','startup_services'])
def test_startup_request_cannot_supply_execution_parameters(action,extra):
    with pytest.raises(ValueError):support_config.validate_action(dict(action=action,**extra))


def test_saved_model_is_restored_offline_before_any_provider_work(tmp_path,monkeypatch):
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    saved=dict(schema='megalodon-local-model-v2',model='nemotron:120b',model_digest='b'*64,compute_mode='auto',timeout_seconds=900)
    # Exercise the profile decoder independently of this sandbox's ancestry.
    monkeypatch.setattr(support_config.os.path,'lexists',lambda p:str(p).endswith('qwen-profile.json'))
    monkeypatch.setattr(support_config,'_regular_owned_file',lambda *a,**kw:json.dumps(saved).encode())
    from megalodon import ai_provider
    def forbidden(*a,**kw):pytest.fail('Restoring preferences contacted Ollama')
    monkeypatch.setattr(ai_provider,'_request',forbidden)
    for _ in range(2):
        value=support_config.SupportConfiguration(Settings(db_path=tmp_path/'events.db'),home=tmp_path)
        assert value._model_selection_state=='restored'
        assert value.settings.ai.model=='nemotron:120b' and value.settings.ai.timeout_seconds==900
        assert value.settings.ai.compute_mode=='auto' and value.settings.ai.model_digest=='b'*64
        assert value.model_telemetry.snapshot()['options']==[]


def test_invalid_saved_profile_does_not_activate_a_different_default_model(tmp_path,monkeypatch):
    monkeypatch.setattr(support_config,'interfaces',lambda:[])
    monkeypatch.setattr(support_config.os.path,'lexists',lambda p:str(p).endswith('qwen-profile.json'))
    monkeypatch.setattr(support_config,'_regular_owned_file',lambda *a,**kw:b'{"invalid":true}')
    value=support_config.SupportConfiguration(Settings(db_path=tmp_path/'events.db',ai=AISettings(enabled=True)),home=tmp_path)
    assert value._model_selection_state=='invalid' and value.settings.ai.enabled is False
