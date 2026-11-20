"""Recovery survives policy errors and lock waits; every process operation here is a stand-in."""
from __future__ import annotations

from argparse import Namespace
from datetime import datetime, timedelta, timezone
from functools import partial
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from megalodon import execution_boundary
from megalodon import response_engine as re_


T0 = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
TARGET = "543210@123:/tmp/synthetic-existing-worker"
NEW_TARGET = "543211@124:/tmp/synthetic-new-worker"


class RecordingExecutor:
    def __init__(self):
        self.resumed, self.applied, self.notices = [], [], []
        self.resume_error = None

    def undo_suspend_process(self, record):
        if self.resume_error is not None:
            raise self.resume_error
        self.resumed.append(record["target"])

    def suspend_process(self, target, decision):
        self.applied.append(target)
        return {"simulated": True}

    def notify_resumed(self, records):
        self.notices.extend(records)


@pytest.fixture(autouse=True)
def no_native_process_operations(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("a synthetic admission test must not signal a process or run a host command")

    monkeypatch.setattr(en.Executor, "_signal", forbidden)
    monkeypatch.setattr(en.subprocess, "run", forbidden)


@pytest.fixture
def case(tmp_path):
    case = SimpleNamespace(
        policy=tmp_path / "enforce.toml", response=tmp_path / "response.toml",
        ledger=tmp_path / "ledger.jsonl", journal=tmp_path / "state" / "enforced.jsonl",
        state=tmp_path / "state" / "enforce-state.json", executor=RecordingExecutor(),
    )
    re_.write_default_policy(case.response)
    en.init(case.policy, response_policy=case.response)
    return case


def policy_state(case, state):
    if state == "missing":
        case.policy.unlink()
    elif state == "malformed":
        case.policy.write_text("[enforce\nenabled = false\n")
    elif state == "writable":
        case.policy.chmod(0o666)
    elif state == "enabled":
        text = case.policy.read_text().replace("enabled = false", "enabled = true")
        text = text.replace("actions = []", 'actions = ["suspend_process"]')
        text = text.replace("playbooks = []", 'playbooks = ["code-loaded-into-memory"]')
        case.policy.write_text(text)
    else:
        assert state == "disabled"


def seed_pause(case, *, until=T0 + timedelta(minutes=5)):
    record = dict(schema=en.SCHEMA, id="existing-pause", at=en._iso(T0), action="suspend_process",
                  target=TARGET, status="applied", until=en._iso(until), undo={})
    en._journal(case.journal, [record])
    return record


def seed_decision(case, *, decided_at=T0):
    decision = dict(
        decided_at=en._iso(decided_at), policy_sha256=re_.load_policy(case.response).digest,
        playbook="code-loaded-into-memory", signal=dict(key="synthetic", rule_id="MEMORY_ELF_IN_ANONYMOUS"),
        actions=[dict(action="suspend_process", target=NEW_TARGET, status="would_apply", minutes=5)],
    )
    case.ledger.write_text(json.dumps(decision) + "\n")
    case.ledger.chmod(0o600)


def run(case, **kwargs):
    return en.run(policy_path=case.policy, response_policy=case.response, ledger=case.ledger,
                  journal=case.journal, state_path=case.state, executor=case.executor,
                  protected=set(), **kwargs)


@pytest.mark.parametrize("state", ["malformed", "writable", "missing", "disabled"])
def test_due_recovery_does_not_depend_on_a_valid_enabled_policy(case, state):
    seed_pause(case)
    seed_decision(case)
    policy_state(case, state)

    result = run(case, now=T0 + timedelta(minutes=6))

    assert result["enabled"] is False and result["applied"] == []
    assert [record["status"] for record in result["expired"]] == ["undone"]
    assert case.executor.resumed == [TARGET] and case.executor.applied == []
    assert en.active(case.journal) == []
    assert ("policy_error" in result) == (state in {"malformed", "writable"})
    assert not case.state.exists(), "recovery does not consume new-action decision state"


def test_failed_recovery_is_retained_alongside_the_policy_error(case):
    seed_pause(case)
    policy_state(case, "malformed")
    case.executor.resume_error = PermissionError("synthetic permission failure")

    result = run(case, now=T0 + timedelta(minutes=6))

    assert result["policy_error"] and result["expired"][0]["status"] == "failed"
    assert [record["id"] for record in en.active(case.journal)] == ["existing-pause"]
    assert case.executor.applied == []


def test_unreadable_policy_cannot_cancel_due_recovery(case, monkeypatch):
    seed_pause(case)

    def unreadable(*args):
        raise PermissionError("synthetic policy read denied")

    monkeypatch.setattr(en, "load_policy", unreadable)

    result = run(case, now=T0 + timedelta(minutes=6))

    assert "synthetic policy read denied" in result["policy_error"]
    assert result["enabled"] is False and result["applied"] == []
    assert result["expired"][0]["status"] == "undone"
    assert case.executor.resumed == [TARGET] and case.executor.applied == []


def test_unexpandable_quarantine_folder_is_a_policy_error_and_recovery_continues(case, monkeypatch):
    seed_pause(case)
    seed_decision(case)
    policy_state(case, "enabled")
    folder = "~synthetic-missing-home/quarantine"
    case.policy.write_text(case.policy.read_text().replace(en.DEFAULT_QUARANTINE, folder))
    real_expanduser = Path.expanduser

    def expanduser(path):
        if str(path) == folder:
            raise RuntimeError("synthetic home directory unavailable")
        return real_expanduser(path)

    monkeypatch.setattr(Path, "expanduser", expanduser)

    result = run(case, now=T0 + timedelta(minutes=6))

    assert "quarantine_folder" in result["policy_error"]
    assert result["enabled"] is False and result["applied"] == []
    assert result["expired"][0]["status"] == "undone"
    assert case.executor.resumed == [TARGET] and case.executor.applied == []
    assert not case.state.exists()


@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_policy_is_reported_as_invalid_without_blocking_recovery(case, dangling):
    seed_pause(case)
    case.policy.unlink()
    case.policy.symlink_to(case.policy.parent / "absent" if dangling else case.response)

    result = run(case, now=T0 + timedelta(minutes=6))

    assert result["policy_error"] and result["enabled"] is False
    assert result["expired"][0]["status"] == "undone"
    assert case.executor.resumed == [TARGET] and case.executor.applied == []


def test_response_policy_failure_preserves_completed_recovery(case):
    policy_state(case, "enabled")
    seed_pause(case)
    seed_decision(case)
    case.response.write_text("[response\n")

    result = run(case, now=T0 + timedelta(minutes=6))

    assert "response policy" in result["note"] and result["policy_error"]
    assert result["enabled"] is False and result["applied"] == []
    assert [record["status"] for record in result["expired"]] == ["undone"]
    assert case.executor.resumed == [TARGET] and case.executor.applied == []
    assert not case.state.exists()


@pytest.mark.parametrize("state", ["malformed", "missing", "disabled"])
def test_no_due_recovery_and_no_enabled_policy_create_no_state(case, state, monkeypatch):
    policy_state(case, state)
    before = sorted(case.policy.parent.rglob("*"))
    monkeypatch.setattr(en, "_Lock", lambda *args: pytest.fail("nothing to do: no lock"))

    result = run(case, now=T0)

    assert result["enabled"] is False and result["expired"] == []
    assert sorted(case.policy.parent.rglob("*")) == before
    assert not case.journal.parent.exists()
    assert case.executor.applied == case.executor.resumed == []


@pytest.mark.parametrize("state", ["malformed", "writable", "missing", "disabled"])
def test_dry_run_reports_due_recovery_without_effects(case, state, monkeypatch):
    seed_pause(case)
    policy_state(case, state)
    before = case.journal.read_bytes()
    monkeypatch.setattr(en, "_Lock", lambda *args: pytest.fail("dry run must not create a lock"))
    monkeypatch.setattr(en, "_expire", lambda *args: pytest.fail("dry run must not recover a process"))

    result = run(case, now=T0 + timedelta(minutes=6), dry_run=True)

    assert [record["status"] for record in result["expired"]] == ["would_resume"]
    assert result["action"] == "dry_run" and result["applied"] == []
    assert case.journal.read_bytes() == before and not case.state.exists()
    assert case.executor.applied == case.executor.resumed == case.executor.notices == []


def delayed_lock(monkeypatch, clock, change=lambda: None):
    class Waiting:
        def __init__(self, journal):
            pass

        def __enter__(self):
            clock[0] = T0 + timedelta(minutes=20)
            change()

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(en, "_now", lambda: clock[0])
    monkeypatch.setattr(en, "_Lock", Waiting)


@pytest.mark.parametrize("change", ["disabled", "malformed", "missing"])
def test_queued_run_recovers_but_admits_no_actions_after_policy_change(case, monkeypatch, change):
    policy_state(case, "enabled")
    seed_pause(case)
    seed_decision(case)

    def update():
        if change == "disabled":
            case.policy.write_text(case.policy.read_text().replace("enabled = true", "enabled = false"))
        else:
            policy_state(case, change)

    delayed_lock(monkeypatch, [T0], update)
    result = run(case)

    assert result["enabled"] is False and result["applied"] == []
    assert case.executor.resumed == [TARGET] and case.executor.applied == []
    assert result["expired"][0]["at"] == en._iso(T0 + timedelta(minutes=20))
    assert ("policy_error" in result) == (change == "malformed")


def test_queued_run_uses_the_current_time_for_recovery_and_decision_age(case, monkeypatch):
    policy_state(case, "enabled")
    seed_pause(case)
    seed_decision(case)
    delayed_lock(monkeypatch, [T0])

    result = run(case)

    assert case.executor.resumed == [TARGET] and case.executor.applied == []
    assert result["applied"] == [] and "too old" in result["refused"][0]["reason"]
    assert result["expired"][0]["at"] == en._iso(T0 + timedelta(minutes=20))


def test_a_new_pause_uses_the_time_after_the_lock_wait(case, monkeypatch):
    policy_state(case, "enabled")
    delayed_lock(monkeypatch, [T0], lambda: seed_decision(case, decided_at=T0 + timedelta(minutes=18)))

    result = run(case)

    assert case.executor.applied == [NEW_TARGET]
    assert result["applied"][0]["at"] == en._iso(T0 + timedelta(minutes=20))
    assert result["applied"][0]["until"] == en._iso(T0 + timedelta(minutes=25))


def test_an_explicit_now_remains_deterministic(case, monkeypatch):
    policy_state(case, "enabled")
    seed_pause(case)
    seed_decision(case)
    monkeypatch.setattr(en, "_now", lambda: pytest.fail("an explicit time must not read the real clock"))

    result = run(case, now=T0 + timedelta(minutes=6))

    assert result["expired"][0]["at"] == en._iso(T0 + timedelta(minutes=6))
    assert result["applied"][0]["until"] == en._iso(T0 + timedelta(minutes=11))


def test_expire_refreshes_time_for_sibling_pauses_after_the_lock_wait(case, monkeypatch):
    first = seed_pause(case)
    sibling = dict(first, id="later-pause", until=en._iso(T0 + timedelta(minutes=10)))
    en._journal(case.journal, [sibling])
    delayed_lock(monkeypatch, [T0 + timedelta(minutes=6)])

    expired = en.expire(journal=case.journal, executor=case.executor)

    assert {record["undo_of"] for record in expired} == {first["id"], sibling["id"]}
    assert {record["at"] for record in expired} == {en._iso(T0 + timedelta(minutes=20))}
    assert all(record["status"] == "undone" for record in expired)
    assert set(case.executor.resumed) == {TARGET} and en.active(case.journal) == []


def test_expire_keeps_an_explicit_time(case, monkeypatch):
    seed_pause(case)
    monkeypatch.setattr(en, "_now", lambda: pytest.fail("an explicit time must not read the real clock"))

    expired = en.expire(journal=case.journal, executor=case.executor, now=T0 + timedelta(minutes=6))

    assert expired[0]["at"] == en._iso(T0 + timedelta(minutes=6))
    assert case.executor.resumed == [TARGET] and en.active(case.journal) == []


@pytest.mark.parametrize("state", ["enabled", "disabled", "missing", "malformed"])
def test_stage0_refuses_recovery_before_the_lock(case, state, monkeypatch):
    policy_state(case, state)
    seed_pause(case)
    before = case.journal.read_bytes()
    monkeypatch.setattr(execution_boundary, "_stage0_selected", True)
    monkeypatch.setattr(en, "_Lock", lambda *args: pytest.fail("Stage 0 must refuse before the lock"))

    with pytest.raises(en.EnforcementError, match="Stage 0"):
        run(case, now=T0 + timedelta(minutes=6))

    assert case.journal.read_bytes() == before
    assert case.executor.applied == case.executor.resumed == case.executor.notices == []


@pytest.mark.parametrize("state,code", [("malformed", 2), ("missing", 0)])
def test_cli_keeps_recovery_results_and_reports_policy_failure(case, state, code, monkeypatch, capsys):
    from megalodon.cli import _enforce

    seed_pause(case)
    policy_state(case, state)
    monkeypatch.setattr(en, "run", partial(en.run, response_policy=case.response, ledger=case.ledger,
                                         journal=case.journal, state_path=case.state, executor=case.executor,
                                         protected=set(), now=T0 + timedelta(minutes=6)))

    assert _enforce(Namespace(policy=case.policy, enforce_command="run", dry_run=False)) == code

    output = json.loads(capsys.readouterr().out)
    assert [record["status"] for record in output["expired"]] == ["undone"]
    assert case.executor.resumed == [TARGET] and case.executor.applied == []
    assert ("policy_error" in output) == (state == "malformed")
