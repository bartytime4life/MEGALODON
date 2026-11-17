"""Local hint tests use a fake helper; no live desktop notification is emitted."""
import json
import os
import subprocess
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from megalodon import desktop_notifications as module

SCOPE = 'detector:' + 'a' * 32
SENSOR = 'sensor:' + 'b' * 32


class Clock:
    def __init__(self):
        self.wall, self.mono = 1_800_000_000.0, 1000.0

    def advance(self, amount):
        self.wall += amount
        self.mono += amount


@pytest.fixture
def setup(private_tmp_path):
    clock, calls = Clock(), []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    def make(**kwargs):
        return module.DesktopNotifications(home=private_tmp_path, clock=lambda: clock.wall,
                                           monotonic=lambda: clock.mono, runner=runner,
                                           availability=lambda: None, **kwargs)

    return make, clock, calls


def active(setup):
    make, clock, calls = setup
    instance = make()
    assert instance.bootstrap({SCOPE: 5})
    assert instance.configure(enabled=True)
    return instance, clock, calls


def test_default_disabled_and_explicit_opt_in_never_replays_disabled_findings(setup):
    make, _, calls = setup
    instance = make()
    assert not instance.enabled
    assert instance.bootstrap()
    assert instance.observe(SCOPE, 1)
    assert not instance.tick()
    assert instance.configure(enabled=True)
    assert not instance.observe(SCOPE, 1)
    assert not instance.tick()
    assert instance.observe(SCOPE, 2)
    assert instance.tick()
    assert len(calls) == 1


def test_fixed_generic_argv_and_truthful_submission_state(setup):
    instance, _, calls = active(setup)
    assert not instance.observe(SCOPE, 5)
    assert instance.observe(SCOPE, 6, count=3)
    assert instance.tick()
    argv, kwargs = calls[0]
    assert argv == list(module.ARGV)
    assert kwargs == dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                          timeout=5, check=False)
    status = instance.snapshot()
    assert status['last_result'] == 'submitted'
    assert status['delivery_verified'] is False
    assert status['action_authority'] == 'none'
    assert status['pending_count'] == 0
    assert os.stat(instance.path).st_mode & 0o777 == 0o600
    assert os.stat(instance.path.parent).st_mode & 0o777 == 0o700


def test_restart_preserves_enabled_progress_and_cooldown_without_replaying_queue(setup):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    instance.tick()
    instance.observe(SCOPE, 7)
    instance.close()
    restarted = setup[0]()
    assert restarted.enabled
    assert restarted.bootstrap({SCOPE: 7})
    assert not restarted.observe(SCOPE, 6)
    assert not restarted.observe(SCOPE, 7)
    assert restarted.snapshot()['pending_count'] == 0
    restarted.observe(SCOPE, 8)
    assert not restarted.tick()
    clock.advance(60)
    assert restarted.tick()
    assert len(calls) == 2


def test_bootstrap_skips_retained_history_and_runs_once(setup):
    make, _, calls = setup
    instance = make(enabled=True)
    assert instance.bootstrap({SCOPE: 100, SENSOR: 45})
    assert not instance.bootstrap({SCOPE: 150})
    assert not instance.observe(SCOPE, 100)
    assert not instance.observe(SENSOR, 45)
    assert not instance.tick()
    assert calls == []


def test_no_admission_until_bootstrap(setup):
    instance = setup[0](enabled=True)
    assert not instance.start()
    assert not instance.observe(SCOPE, 1)
    assert not instance.tick()
    assert not instance.path.exists()


def test_coalesces_pending_counts_and_limits_every_attempt_to_one_minute(setup):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    instance.tick()
    instance.observe(SCOPE, 7, count=2000)
    assert instance.snapshot()['pending_count'] == module.MAX_PENDING
    assert instance.snapshot()['pending_saturated'] is True
    for _ in range(59):
        clock.advance(1)
        assert not instance.tick()
    clock.advance(1)
    assert instance.tick()
    assert len(calls) == 2
    assert not instance.snapshot()['pending_saturated']


def test_progress_storage_is_bounded_across_rotating_sources(setup):
    instance, _, _ = active(setup)
    for index in range(module.MAX_SCOPES + 5):
        instance.observe('sensor:' + f'{index:032x}', index + 1, count=0)
    value = json.loads(instance.path.read_bytes())
    assert len(value['cursors']) == module.MAX_SCOPES
    assert instance.path.stat().st_size < module.MAX_STATE_BYTES
    assert instance.snapshot()['pending_count'] == 0


@pytest.mark.parametrize('failure,reason', [('returncode', 'helper_failed'), ('oserror', 'helper_failed'),
                                         ('timeout', 'helper_timeout'), ('unavailable', 'no_desktop_session')])
def test_failure_consumes_slot_and_does_not_retry_old_hints(setup, failure, reason):
    instance, clock, calls = active(setup)
    attempts = []

    def fail(*args, **kwargs):
        attempts.append(1)
        if failure == 'oserror':
            raise OSError('Private error must not be displayed')
        if failure == 'timeout':
            raise subprocess.TimeoutExpired('private command', 5)
        return SimpleNamespace(returncode=1)

    instance._runner = fail
    if failure == 'unavailable':
        instance._availability = lambda: 'no_desktop_session'
    instance.observe(SCOPE, 6)
    assert instance.tick()
    assert instance.snapshot()['last_result'] == 'unavailable'
    assert instance.snapshot()['reason'] == reason
    clock.advance(60)
    assert not instance.tick()
    assert len(attempts) == (0 if failure == 'unavailable' else 1)
    assert calls == []


def test_new_findings_after_failure_still_wait_for_interval(setup):
    instance, clock, calls = active(setup)
    instance._availability = lambda: 'no_desktop_session'
    instance.observe(SCOPE, 6)
    instance.tick()
    instance._availability = lambda: None
    instance.observe(SCOPE, 7)
    assert not instance.tick()
    clock.advance(60)
    assert instance.tick()
    assert len(calls) == 1


@pytest.mark.parametrize('damage', ['invalid_json', 'unknown_field', 'duplicate_key', 'bad_cursor',
                                    'duplicate_scope', 'invalid_timestamp', 'permissions', 'symlink'])
def test_corrupt_or_unsafe_saved_state_fails_closed_without_replacement(setup, damage):
    instance, _, calls = active(setup)
    value = json.loads(instance.path.read_bytes())
    if damage == 'invalid_json':
        instance.path.write_text('{')
    elif damage == 'duplicate_key':
        instance.path.write_text('{"schema": "one", "schema": "two"}')
    elif damage == 'permissions':
        instance.path.chmod(0o644)
    elif damage == 'symlink':
        original = instance.path.with_name('original.json')
        instance.path.rename(original)
        instance.path.symlink_to(original)
    else:
        if damage == 'unknown_field':
            value['unexpected'] = 'private'
        elif damage == 'bad_cursor':
            value['cursors'] = [[SCOPE, True]]
        elif damage == 'duplicate_scope':
            value['cursors'] *= 2
        else:
            value['last_attempt_at'] = float('nan')
        instance.path.write_text(json.dumps(value))
    raw = instance.path.read_bytes()
    restarted = setup[0]()
    assert restarted.snapshot()['state'] == 'unavailable'
    assert restarted.snapshot()['reason'] == 'state_unavailable'
    assert not restarted.bootstrap()
    assert not restarted.observe(SCOPE, 6)
    assert not restarted.tick()
    assert instance.path.read_bytes() == raw
    assert calls == []


@pytest.mark.parametrize('stage', ['observe', 'tick', 'configure'])
def test_persistence_failure_prevents_subprocess_and_disables_admission(setup, monkeypatch, stage):
    instance, _, calls = active(setup)
    if stage == 'tick':
        instance.observe(SCOPE, 6)

    def fail(*args):
        raise OSError('disk full at private path')

    monkeypatch.setattr(module, '_atomic_write', fail)
    if stage == 'observe':
        assert not instance.observe(SCOPE, 6)
    elif stage == 'tick':
        assert not instance.tick()
    else:
        assert not instance.configure(enabled=False)
    assert instance.snapshot()['state'] == 'unavailable'
    assert instance.snapshot()['reason'] == 'state_unavailable'
    assert not instance.tick()
    assert calls == []


def test_unknown_outcome_retains_attempt_record_before_subprocess(setup, monkeypatch):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    original, writes = module._atomic_write, []

    def write(path, raw, mode):
        writes.append(json.loads(raw))
        if len(writes) == 2:
            raise OSError('failed after subprocess')
        original(path, raw, mode)

    monkeypatch.setattr(module, '_atomic_write', write)
    assert instance.tick()
    assert len(calls) == 1
    assert writes[0]['last_result'] == 'attempted'
    assert writes[0]['cursors'] == [[SCOPE, 6]]
    assert json.loads(instance.path.read_bytes())['last_result'] == 'attempted'
    monkeypatch.setattr(module, '_atomic_write', original)
    restarted = setup[0]()
    assert restarted.bootstrap()
    restarted.observe(SCOPE, 7)
    assert not restarted.tick()
    clock.advance(60)
    assert restarted.tick()


def test_wall_clock_rollback_does_not_bypass_running_monotonic_throttle(setup):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    instance.tick()
    instance.observe(SCOPE, 7)
    clock.wall -= 5000
    clock.mono += 59
    assert not instance.tick()
    clock.mono += 1
    assert instance.tick()
    assert len(calls) == 2


def test_restart_wall_clock_rollback_waits_one_full_monotonic_interval(setup):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    instance.tick()
    instance.close()
    clock.wall -= 5000
    clock.mono = 1
    restarted = setup[0]()
    restarted.bootstrap()
    restarted.observe(SCOPE, 7)
    assert not restarted.tick()
    clock.advance(59)
    assert not restarted.tick()
    clock.advance(1)
    assert restarted.tick()
    assert len(calls) == 2


def test_monotonic_rollback_starts_new_full_cooldown(setup):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    instance.tick()
    instance.observe(SCOPE, 7)
    clock.mono -= 100
    assert not instance.tick()
    clock.advance(60)
    assert instance.tick()
    assert len(calls) == 2


def test_nonfinite_clock_fails_closed(setup):
    instance, clock, calls = active(setup)
    instance.observe(SCOPE, 6)
    clock.mono = float('nan')
    assert not instance.tick()
    assert instance.snapshot()['reason'] == 'clock_unavailable'
    assert calls == []


@pytest.mark.parametrize('scope,cursor,count', [('bad', 1, 1), (SCOPE, True, 1), (SCOPE, -1, 1),
                                             (SCOPE, 2**63, 1), (SCOPE, 6, -1), (SCOPE, 6, True)])
def test_invalid_commit_inputs_are_refused_before_state_change(setup, scope, cursor, count):
    instance, _, calls = active(setup)
    original = instance.path.read_bytes()
    with pytest.raises(ValueError):
        instance.observe(scope, cursor, count=count)
    assert instance.path.read_bytes() == original
    assert calls == []


def test_stage0_denies_constructor_and_mutating_entries_before_work(setup, monkeypatch):
    instance, _, calls = active(setup)
    original = instance.path.read_bytes()

    def deny():
        raise module.execution_boundary.Stage0Denied()

    monkeypatch.setattr(module.execution_boundary, 'require_effects_allowed', deny)
    for operation in [setup[0], lambda: instance.observe(SCOPE, 6), instance.tick,
                      instance.start, instance.bootstrap, lambda: instance.configure(enabled=False)]:
        with pytest.raises(module.execution_boundary.Stage0Denied):
            operation()
    assert instance.path.read_bytes() == original
    assert calls == []
    assert instance.snapshot()['pending_count'] == 0
    instance.close()


def test_second_boundary_check_denies_at_subprocess_entry(setup, monkeypatch):
    instance, _, calls = active(setup)
    instance.observe(SCOPE, 6)

    def deny():
        raise module.execution_boundary.Stage0Denied()

    def availability():
        monkeypatch.setattr(module.execution_boundary, 'require_effects_allowed', deny)
        return None

    instance._availability = availability
    assert instance.tick()
    assert instance.snapshot()['reason'] == 'boundary_denied'
    assert calls == []


def test_status_is_inert_and_shutdown_discards_queue_without_flushing(setup, monkeypatch):
    instance, _, calls = active(setup)
    instance.observe(SCOPE, 6)
    assert instance.start()
    assert not instance.start()

    def forbidden(*args):
        pytest.fail('Read-only snapshot touched effects or private state')

    monkeypatch.setattr(instance, '_save', forbidden)
    monkeypatch.setattr(instance, '_availability', forbidden)
    assert instance.snapshot()['pending_count'] == 1
    instance.close()
    assert not instance._thread.is_alive()
    assert instance.snapshot()['state'] == 'closed'
    assert instance.snapshot()['pending_count'] == 0
    assert not instance.observe(SCOPE, 7)
    assert not instance.tick()
    assert not instance.configure(enabled=True)
    assert calls == []


def test_no_desktop_session_has_fixed_reason(monkeypatch):
    monkeypatch.setattr(module.sys, 'platform', 'linux')
    monkeypatch.delenv('DISPLAY', raising=False)
    monkeypatch.delenv('WAYLAND_DISPLAY', raising=False)
    assert module._desktop_reason() == 'no_desktop_session'


def test_waiting_helper_does_not_block_committed_evidence_callbacks(setup):
    instance, _, _ = active(setup)
    entered, release, observed = Event(), Event(), Event()

    def runner(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return SimpleNamespace(returncode=0)

    def observe():
        assert instance.observe(SCOPE, 7)
        observed.set()

    instance._runner = runner
    instance.observe(SCOPE, 6)
    sender = Thread(target=instance.tick)
    observer = Thread(target=observe)
    sender.start()
    try:
        assert entered.wait(1)
        observer.start()
        assert observed.wait(1), 'Desktop helper blocked a committed-evidence callback'
        assert not instance.tick()
        assert instance.snapshot()['last_result'] == 'attempted'
    finally:
        release.set()
        sender.join(6)
        if observer.ident is not None:
            observer.join(6)
    assert instance.snapshot()['pending_count'] == 1
    assert instance.snapshot()['last_result'] == 'submitted'
    assert json.loads(instance.path.read_bytes())['cursors'] == [[SCOPE, 7]]
