"""Confirmed pre-signal refusal is not a process hold; no native signals are used."""
from __future__ import annotations

from argparse import Namespace
from datetime import datetime, timedelta, timezone
import errno
import json
import os
import signal
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from megalodon import execution_boundary
from megalodon import response_engine as response
from test_enforcement import enable, enforce, paths


NOW = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
PID, START, HANDLE = 42424242, 12345, 987654
PROGRAM = "/synthetic/legitimate-worker"
TARGET = f"{PID}@{START}:{PROGRAM}"


@pytest.fixture(autouse=True)
def no_native_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("no-stop regression tests must not execute a native process operation")

    monkeypatch.setattr(en.os, "pidfd_open", forbidden, raising=False)
    monkeypatch.setattr(en.signal, "pidfd_send_signal", forbidden, raising=False)
    monkeypatch.setattr(en.os, "kill", forbidden)
    monkeypatch.setattr(en.subprocess, "run", forbidden)


@pytest.fixture
def process(monkeypatch):
    state = SimpleNamespace(opens=[], signals=[], closes=[], notices=[], start=START, program=PROGRAM,
                            open_error=None, start_error=None, exe_error=None, signal_error=None,
                            close_error=None)
    real_close = os.close

    def opened(pid):
        assert pid == PID
        state.opens.append(pid)
        if state.open_error:
            raise state.open_error
        return HANDLE

    def started(pid, root):
        assert pid == PID and root == "/synthetic"
        if state.start_error:
            raise state.start_error
        return state.start

    def executable(path):
        assert str(path) == f"/synthetic/proc/{PID}/exe"
        if state.exe_error:
            raise state.exe_error
        return state.program

    def sent(handle, number):
        assert handle == HANDLE
        state.signals.append(number)
        if state.signal_error:
            raise state.signal_error

    def closed(fd):
        if fd != HANDLE:
            return real_close(fd)       # temporary journal/lock files, never a native pidfd
        state.closes.append(fd)
        if state.close_error:
            raise state.close_error

    monkeypatch.setattr(en, "getpid", lambda: PID + 1)
    monkeypatch.setattr(en, "_start", started)
    monkeypatch.setattr(en.os, "pidfd_open", opened, raising=False)
    monkeypatch.setattr(en.os, "readlink", executable)
    monkeypatch.setattr(en.os, "close", closed)
    monkeypatch.setattr(en.signal, "pidfd_send_signal", sent, raising=False)
    state.executor = en.Executor(root="/synthetic", home="/synthetic", quarantine="/synthetic/quarantine")
    monkeypatch.setattr(state.executor, "notify_resumed", lambda records: state.notices.extend(records))
    return state


@pytest.fixture
def p(tmp_path):
    p = paths(tmp_path)
    response.write_default_policy(p["policy"])
    en.init(p["enforce"], response_policy=p["policy"])
    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    return p


def decide(p, *, at=NOW, key="first", minutes=0):
    if minutes:
        # A later policy can replace an indefinite default with a finite pause.
        p["policy"].write_text(p["policy"].read_text().replace(
            'name = "code-loaded-into-memory"\n',
            f'name = "code-loaded-into-memory"\nsuspend_minutes = {minutes}\n'))
        en.init(p["enforce"], response_policy=p["policy"], replace=True)
    record = dict(decided_at=en._iso(at), policy_sha256=response.load_policy(p["policy"]).digest,
                  playbook="code-loaded-into-memory", signal=dict(key=key, rule_id="MEMORY_ELF_IN_ANONYMOUS"),
                  actions=[dict(action="suspend_process", target=TARGET, status="would_apply", minutes=minutes)])
    with p["ledger"].open("a") as stream:
        stream.write(json.dumps(record) + "\n")
    p["ledger"].chmod(0o600)


@pytest.mark.parametrize("case", ["invalid", "open_denied", "exited", "pid_overflow", "start_unavailable",
                                  "reused", "exe_unavailable", "exe_changed"])
def test_pre_signal_rejections_prove_no_stop_was_attempted(process, case):
    target = TARGET
    if case == "invalid":
        target = "not-an-exact-process"
    elif case == "open_denied":
        process.open_error = PermissionError(errno.EACCES, "synthetic pidfd denied")
    elif case == "exited":
        process.open_error = ProcessLookupError(errno.ESRCH, "synthetic process exited")
    elif case == "pid_overflow":
        process.open_error = OverflowError("synthetic pid is outside the native range")
    elif case == "start_unavailable":
        process.start_error = en.ProcessIdentityUnavailable("synthetic stat read denied")
    elif case == "reused":
        process.start = START + 1
    elif case == "exe_unavailable":
        process.exe_error = PermissionError(errno.EACCES, "synthetic executable read denied")
    else:
        process.program = "/synthetic/another-program"

    with pytest.raises(en.SuspensionNotAttempted):
        process.executor.suspend_process(target, {})

    assert process.signals == []


def test_the_enforcing_process_is_rejected_before_opening_a_pidfd(process, monkeypatch):
    monkeypatch.setattr(en, "getpid", lambda: PID)

    with pytest.raises(en.SuspensionNotAttempted, match="cannot suspend itself"):
        process.executor.suspend_process(TARGET, {})

    assert process.opens == process.signals == process.closes == []


def test_a_failed_indefinite_intent_does_not_hold_a_later_finite_pause(p, process):
    decide(p)
    process.exe_error = PermissionError(errno.EACCES, "synthetic pre-signal read denied")

    first = enforce(p, executor=process.executor, now=NOW)

    assert first["refused"][0]["status"] == "failed"
    assert first["refused"][0]["stop_attempted"] is False
    assert [r["status"] for r in en.entries(p["journal"])] == ["pending", "failed"]
    assert en.active(p["journal"]) == [] and process.signals == []
    process.exe_error = None
    p["enforce_state"].unlink()
    assert enforce(p, executor=process.executor, now=NOW)["applied"] == []
    assert len(process.opens) == 1, "a confirmed refusal is not silently replayed after cursor loss"

    decide(p, at=NOW + timedelta(minutes=1), key="later", minutes=1)
    applied = enforce(p, executor=process.executor, now=NOW + timedelta(minutes=1))["applied"]
    assert len(applied) == 1
    expired = en.expire(journal=p["journal"], executor=process.executor, now=NOW + timedelta(minutes=3))

    assert len(expired) == 1 and expired[0]["status"] == "undone" and not expired[0].get("note")
    assert process.signals == [signal.SIGSTOP, signal.SIGCONT]
    assert en.active(p["journal"]) == [] and len(process.notices) == 1


@pytest.mark.parametrize("fault", ["signal_error", "close_error"])
def test_failure_after_the_signal_invocation_keeps_the_intent(p, process, fault):
    decide(p)
    setattr(process, fault, OSError(errno.EIO, "synthetic outcome unavailable"))

    result = enforce(p, executor=process.executor, now=NOW)

    assert process.signals == [signal.SIGSTOP]
    assert result["refused"][0]["status"] == "failed"
    assert "stop_attempted" not in result["refused"][0]
    assert [r["status"] for r in en.active(p["journal"])] == ["pending"]


@pytest.mark.parametrize("case", ["missing_flag", "true_flag", "zero_flag", "string_flag", "undo_attempt",
                                  "other_target", "other_decision", "applied", "applied_then_pending"])
def test_only_matching_unapplied_intents_can_be_cancelled(tmp_path, case):
    path = tmp_path / "journal.jsonl"
    pending = dict(schema=en.SCHEMA, id="hold-a", action="suspend_process", target=TARGET,
                   decided_at=en._iso(NOW), signal_key="finding-a", at=en._iso(NOW), status="pending")
    failed = dict(pending, status="failed", stop_attempted=False, reason="synthetic pre-signal refusal")
    history = [pending]
    if case == "missing_flag":
        failed.pop("stop_attempted")
    elif case == "true_flag":
        failed["stop_attempted"] = True
    elif case == "zero_flag":
        failed["stop_attempted"] = 0
    elif case == "string_flag":
        failed["stop_attempted"] = "false"
    elif case == "undo_attempt":
        failed["undo_of"] = "hold-a"
    elif case == "other_target":
        failed["target"] = f"{PID + 1}@{START}:{PROGRAM}"
    elif case == "other_decision":
        failed["signal_key"] = "another-finding"
    else:
        history.append(dict(pending, status="applied", undo={}))
        if case == "applied_then_pending":
            history.append(pending)
    en._journal(path, history + [failed])

    active = en.active(path)

    assert len(active) == 1 and active[0]["id"] == "hold-a"
    assert active[0]["status"] == ("applied" if case.startswith("applied") else "pending")


def test_failure_to_persist_the_refusal_keeps_the_uncertain_intent(p, process, monkeypatch):
    decide(p)
    process.exe_error = PermissionError(errno.EACCES, "synthetic read denied")
    real_journal = en._journal

    def journal(path, records):
        if records[0].get("stop_attempted") is False:
            raise OSError(errno.ENOSPC, "synthetic cancellation append failed")
        real_journal(path, records)

    monkeypatch.setattr(en, "_journal", journal)
    with pytest.raises(OSError, match="cancellation append failed"):
        enforce(p, executor=process.executor, now=NOW)

    assert process.signals == []
    assert [r["status"] for r in en.active(p["journal"])] == ["pending"]


@pytest.mark.parametrize("case,exception", [("gone", en.ProcessIdentityGone),
                                           ("unavailable", en.ProcessIdentityUnavailable)])
def test_resume_identity_outcomes_keep_their_original_types(process, case, exception):
    if case == "gone":
        process.start = START + 1
    else:
        process.exe_error = PermissionError(errno.EACCES, "synthetic read denied")

    with pytest.raises(exception) as caught:
        process.executor.undo_suspend_process(dict(target=TARGET))

    assert not isinstance(caught.value, en.SuspensionNotAttempted) and process.signals == []


def test_stage0_refuses_before_any_new_intent_or_signal(p, process, monkeypatch):
    decide(p)
    monkeypatch.setattr(execution_boundary, "_stage0_selected", True)

    with pytest.raises(en.EnforcementError, match="Stage 0"):
        enforce(p, executor=process.executor, now=NOW)

    assert not p["journal"].exists()
    assert not p["journal"].with_name(p["journal"].name + ".lock").exists()
    assert process.opens == process.signals == []


def test_cli_keeps_a_confirmed_no_stop_as_a_failed_action(p, process, monkeypatch, capsys):
    from megalodon.cli import _enforce

    decide(p)
    process.start_error = en.ProcessIdentityUnavailable("synthetic stat read denied")
    result = enforce(p, executor=process.executor, now=NOW)
    monkeypatch.setattr(en, "run", lambda **kwargs: result)

    code = _enforce(Namespace(policy=p["enforce"], enforce_command="run", dry_run=False))

    output = json.loads(capsys.readouterr().out)
    assert code == 1 and output["refused"][0]["stop_attempted"] is False
    assert output["refused"][0]["status"] == "failed" and output["applied"] == []
