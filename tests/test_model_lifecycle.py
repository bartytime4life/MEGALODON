"""Startup, interrupted-provider recovery and exact-selection load boundaries."""
from dataclasses import replace
from threading import Event

import pytest

from megalodon import ai_provider
from megalodon.config import AISettings
from megalodon.model_lifecycle import ModelLifecycle


def fixture_worker():
    state = dict(settings=AISettings(enabled=True, keep_warm=True), now=0., loaded=False,
                 available=True, prepares=[], fail=None)
    def inspect(settings):
        return {'state':'model_available' if state['available'] else 'ollama_unavailable'}
    def prepare(settings):
        state['prepares'].append(settings)
        if state['fail']:
            raise ai_provider.AIProviderError(state['fail'])
        state['loaded']=True
    worker=ModelLifecycle(lambda:state['settings'],prepare=prepare,inspect=inspect,
        loaded=lambda _:dict(loaded=state['loaded']),clock=lambda:state['now'])
    return worker,state


def test_startup_load_lease_renewal_and_reconnect_without_changing_selection():
    worker,state=fixture_worker()
    worker._step()
    assert worker.snapshot()['state']=='ready' and len(state['prepares'])==1
    worker._step()
    assert len(state['prepares'])==1
    state['now']=121
    worker._step()
    assert len(state['prepares'])==2
    state.update(available=False,loaded=False)
    worker._step()
    assert worker.snapshot()['state']=='retrying'
    assert worker.snapshot()['retry_in_seconds']==5
    state['available']=True
    worker._step()
    assert len(state['prepares'])==2
    state['now']+=5
    worker._step()
    assert worker.snapshot()['state']=='ready' and len(state['prepares'])==3
    assert all(x.model_digest==state['settings'].model_digest for x in state['prepares'])


def test_backoff_is_bounded_and_manual_retry_resets_it():
    worker,state=fixture_worker()
    state['fail']='MODEL_MISMATCH'
    for i in range(8):
        worker._step()
        delay=worker.snapshot()['retry_in_seconds']
        assert 1<=delay<=120
        state['now']+=delay
    assert worker.snapshot()['state']=='retrying'
    state['fail']=None
    worker._step(force=True)
    assert worker.snapshot()['state']=='ready'


def test_disabled_or_on_demand_policy_has_no_provider_effects():
    worker,state=fixture_worker()
    state['settings']=replace(state['settings'],keep_warm=False)
    worker.inspect=lambda _:(_ for _ in ()).throw(AssertionError('provider contacted'))
    worker._step()
    assert worker.snapshot()['state']=='paused' and not state['prepares']
    state['settings']=replace(state['settings'],enabled=False)
    worker._step()
    assert worker.snapshot()['state']=='disabled'


def test_load_completion_for_old_selection_cannot_mark_new_selection_ready():
    worker,state=fixture_worker()
    def change_selection(settings):
        state['settings']=replace(settings,model='other:latest',model_digest='a'*64)
    worker.prepare=change_selection
    worker._step()
    assert worker.snapshot()['state']!='ready'


def test_load_response_without_runtime_allocation_is_not_ready():
    worker,state=fixture_worker()
    worker.prepare=lambda _:None
    worker._step()
    assert worker.snapshot()['state']=='retrying'


def test_worker_starts_once_and_closes_without_waiting_for_poll():
    worker,state=fixture_worker()
    loaded=Event()
    worker.prepare=lambda _: (state.update(loaded=True),loaded.set())
    worker.start(); first=worker._thread; worker.start()
    assert worker._thread is first and loaded.wait(2)
    worker.close()
    assert not first.is_alive()


def test_busy_metadata_does_not_report_provider_failure_or_attempt_a_load():
    worker,state=fixture_worker()
    worker.inspect=lambda _: {'state':'model_loading'}
    worker.loaded=lambda _: (_ for _ in ()).throw(AssertionError('busy metadata cannot prove allocation'))
    worker._step()
    value=worker.snapshot()
    assert value['state']=='checking' and value['error_code'] is None
    assert value['retry_in_seconds']==worker.poll_seconds and not state['prepares']
    assert worker._failures==0


@pytest.mark.parametrize('code', ['CONCURRENCY_LIMIT_REACHED','REQUEST_CANCELLED'])
def test_busy_or_manually_preempted_load_defers_without_false_readiness(code):
    worker,state=fixture_worker()
    state['fail']=code
    worker._step()
    assert worker.snapshot()['state']=='checking'
    assert worker.snapshot()['error_code'] is None and worker._failures==0
    assert not state['loaded'] and len(state['prepares'])==1
    worker._step()
    assert len(state['prepares'])==1, 'busy retry must remain bounded'
    state['now']+=worker.poll_seconds;state['fail']=None
    worker._step()
    assert worker.snapshot()['state']=='ready' and len(state['prepares'])==2
