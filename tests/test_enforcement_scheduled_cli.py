"""Generated enforcement argv through the real CLI, with no native process or service effects.

This exercises default-path discovery and command results, not a systemd manager,
installed-wheel acceptance, or a physical SIGSTOP/SIGCONT operation.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import errno
import io
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

from megalodon import cli, enforcement as en, execution_boundary, response_engine as response, schedule


NOW = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
PID, START = 42424242, 12345
PROGRAM = "/synthetic/scheduled-worker"
TARGET = f"{PID}@{START}:{PROGRAM}"


@pytest.fixture
def scheduled(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("scheduled CLI acceptance must not perform a native process, network, or service operation")

    # Patch native entry points before making the enforcement module's OS proxy.
    # Only the explicit fake pidfd functions below are allowed to represent signals.
    for name in ("kill", "killpg", "pidfd_open", "fork", "forkpty", "posix_spawn", "posix_spawnp", "system",
                 "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
                 "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        monkeypatch.setattr(os, name, forbidden, raising=False)
    monkeypatch.setattr(signal, "pidfd_send_signal", forbidden, raising=False)
    monkeypatch.setattr(signal, "raise_signal", forbidden)
    monkeypatch.setattr(signal, "pthread_kill", forbidden, raising=False)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(schedule, "_systemctl", forbidden)
    monkeypatch.setattr(execution_boundary, "_stage0_selected", False)
    monkeypatch.setattr(execution_boundary, "_effects_entered", False)

    case = SimpleNamespace(home=tmp_path / "account-a", proc_root=tmp_path / "machine",
                           xdg_config=tmp_path / "xdg-config", xdg_state=tmp_path / "xdg-state",
                           clock=NOW, starts=[], attempts=[], closed=[], notices=[], handles={},
                           signal_error=None, exited=False, process_state="T")
    case.home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(case.home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(case.xdg_config))
    monkeypatch.setenv("XDG_STATE_HOME", str(case.xdg_state))
    case.policy = case.home / ".config/megalodon/enforce.toml"
    case.journal = case.home / ".local/state/megalodon/enforced.jsonl"
    case.state = case.home / ".local/state/megalodon/enforce-state.json"
    case.lock = case.journal.with_name(case.journal.name + ".lock")
    proc = case.proc_root / "proc" / str(PID)
    proc.mkdir(parents=True)
    (proc / "exe").symlink_to(PROGRAM)

    def stat(start=START):
        (proc / "stat").write_text(
            f"{PID} (synthetic (scheduled worker)) "
            + " ".join([case.process_state] + ["0"] * 18 + [str(start)]), encoding="utf-8")

    stat()
    case.stat = stat
    case.stat_path = proc / "stat"
    real_close = os.close
    fake_os = SimpleNamespace(**vars(os))

    def pidfd_open(pid):
        assert pid == PID, "default-path recovery must only inspect the selected synthetic identity"
        case.starts.append(pid)
        if case.exited:
            raise ProcessLookupError(errno.ESRCH, "synthetic process exited")
        handle = object()
        case.handles[handle] = pid
        return handle

    def close(handle):
        if handle in case.handles:
            case.closed.append(case.handles.pop(handle))
        else:
            real_close(handle)

    def send_signal(handle, number):
        assert case.handles[handle] == PID
        assert number == signal.SIGCONT, "this recovery-only fixture must never attempt a new stop"
        case.attempts.append(number)
        if case.signal_error is not None:
            raise case.signal_error
        case.process_state = "R"
        stat()

    fake_os.pidfd_open, fake_os.close = pidfd_open, close
    monkeypatch.setattr(en, "os", fake_os)
    monkeypatch.setattr(en, "signal", SimpleNamespace(SIGSTOP=signal.SIGSTOP, SIGCONT=signal.SIGCONT,
                                                     pidfd_send_signal=send_signal))
    monkeypatch.setattr(en, "_now", lambda: case.clock)
    actual_executor = en.Executor

    class SyntheticExecutor(actual_executor):
        def __init__(self, **kwargs):
            super().__init__(**dict(kwargs, root=str(case.proc_root), home=case.home, run=forbidden))

        def notify_resumed(self, records):
            case.notices.extend(dict(record) for record in records)

    monkeypatch.setattr(en, "Executor", SyntheticExecutor)
    response.write_default_policy()
    en.init()
    launcher = [sys.executable, "-m", "megalodon"]
    job = next(job for job in schedule.JOBS if job.name == "enforce")
    case.units = schedule.units(job, launcher, True)
    command = next(line.removeprefix("ExecStart=") for line in case.units["megalodon-enforce.service"].splitlines()
                   if line.startswith("ExecStart="))
    argv = shlex.split(command)
    assert argv[:len(launcher)] == launcher
    case.argv = argv[len(launcher):]
    assert case.argv == ["enforce", "run"]

    def invoke(arguments=None):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), pytest.raises(SystemExit) as result:
            cli.main(case.argv if arguments is None else arguments)
        rendered = output.getvalue()
        return SimpleNamespace(code=result.value.code, output=json.loads(rendered) if rendered else None,
                               stderr=errors.getvalue())

    case.invoke = invoke
    return case


def seed(case, identifier="pause-a", *, until=None):
    record = dict(schema=en.SCHEMA, id=identifier, action="suspend_process", target=TARGET,
                  status="applied", at=en._iso(NOW - timedelta(minutes=10)),
                  until=en._iso(until or NOW - timedelta(minutes=1)))
    en._journal(case.journal, [record])
    return record


@pytest.mark.parametrize("policy,code", [("disabled", 0), ("missing", 0), ("invalid", 2)])
def test_generated_command_recovers_using_home_defaults(scheduled, policy, code):
    case = scheduled
    seed(case)
    if policy == "missing":
        case.policy.unlink()
    elif policy == "invalid":
        case.policy.write_text("[enforce\n", encoding="utf-8")

    result = case.invoke()

    assert result.code == code and result.output["enabled"] is False
    assert result.output["applied"] == [] and result.output["expired"][0]["status"] == "undone"
    assert ("policy_error" in result.output) == (policy == "invalid")
    assert case.attempts == [signal.SIGCONT] and case.closed == [PID] and not case.handles
    assert en.active(case.journal) == [] and len(case.notices) == 1
    assert case.journal.stat().st_mode & 0o777 == 0o600
    assert not case.state.exists(), "recovery does not consume a new-action cursor"


def test_sigcont_failure_is_visible_then_next_invocation_retries(scheduled):
    case = scheduled
    seed(case)
    case.signal_error = PermissionError(errno.EPERM, "synthetic permission failure")

    first = case.invoke()

    assert first.code == 1 and first.output["expired"][0]["status"] == "failed"
    assert [record["id"] for record in en.active(case.journal)] == ["pause-a"]
    assert case.process_state == "T" and case.notices == []
    case.signal_error = None
    case.clock += timedelta(minutes=2)
    second = case.invoke()
    assert second.code == 0 and second.output["expired"][0]["status"] == "undone"
    assert case.process_state == "R" and len(case.notices) == 1
    assert case.attempts == [signal.SIGCONT, signal.SIGCONT]
    assert case.invoke().output["expired"] == [] and len(case.attempts) == 2


def test_skipped_invocation_recovers_late_when_command_runs_again(scheduled):
    case = scheduled
    seed(case, until=NOW + timedelta(minutes=1))
    assert case.invoke().output["expired"] == [] and not case.lock.exists()
    before = case.journal.read_bytes()
    case.clock += timedelta(minutes=20)          # no scheduler or background worker is run by this fixture
    assert case.journal.read_bytes() == before and case.process_state == "T" and case.attempts == []

    result = case.invoke()

    assert result.code == 0 and result.output["expired"][0]["at"] == en._iso(case.clock)
    assert case.attempts == [signal.SIGCONT] and en.active(case.journal) == []


def test_two_due_holds_share_one_signal_through_the_cli(scheduled):
    case = scheduled
    seed(case)
    seed(case, "pause-b")

    result = case.invoke()

    assert result.code == 0
    assert {record["undo_of"] for record in result.output["expired"]} == {"pause-a", "pause-b"}
    assert case.attempts == [signal.SIGCONT] and len(case.notices) == 1
    assert en.active(case.journal) == []


@pytest.mark.parametrize("identity", ["unreadable", "reused", "exited"])
def test_cli_identity_outcomes_cannot_reach_a_native_pid(scheduled, identity):
    case = scheduled
    seed(case)
    if identity == "unreadable":
        case.stat_path.unlink()
    elif identity == "reused":
        case.stat(START + 1)
    else:
        case.exited = True

    result = case.invoke()

    assert result.code == (1 if identity == "unreadable" else 0)
    assert result.output["expired"][0]["status"] == ("failed" if identity == "unreadable" else "undone")
    assert bool(en.active(case.journal)) == (identity == "unreadable")
    assert case.attempts == case.notices == [] and not case.handles


def test_cli_preserves_successful_resume_and_failed_audit_outcome(scheduled, monkeypatch):
    case = scheduled
    seed(case)
    before = case.journal.read_bytes()

    def full(*args):
        raise OSError(errno.ENOSPC, "synthetic journal full")

    monkeypatch.setattr(en.os, "write", full)
    result = case.invoke()

    assert result.code == 1 and result.output["enabled"] is False and result.output["applied"] == []
    ended = result.output["expired"][0]
    assert ended["status"] == "failed" and ended["recovery_status"] == "undone"
    assert "synthetic journal full" in ended["journal_error"]
    assert case.process_state == "R" and case.attempts == [signal.SIGCONT] and len(case.notices) == 1
    assert case.journal.read_bytes() == before and not case.state.exists()


def test_stage0_cli_denies_before_default_path_lock_or_signal_work(scheduled):
    case = scheduled
    seed(case)
    before = case.journal.read_bytes()

    for arguments in (["--stage0-offline", *case.argv], case.argv):
        result = case.invoke(arguments)
        assert result.code == 2 and result.output is None
        assert execution_boundary.DENIAL in result.stderr
    assert case.journal.read_bytes() == before and not case.lock.exists()
    assert case.starts == case.attempts == case.notices == []


def test_another_home_cannot_discover_the_original_accounts_journal(scheduled, tmp_path, monkeypatch):
    case = scheduled
    seed(case)
    before = case.journal.read_bytes()
    other = tmp_path / "account-b"
    other.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(other))

    result = case.invoke()

    assert result.code == 0 and result.output["expired"] == []
    assert list(other.iterdir()) == [] and case.journal.read_bytes() == before and not case.lock.exists()
    assert case.process_state == "T" and case.attempts == []
    monkeypatch.setenv("HOME", str(case.home))
    assert case.invoke().output["expired"][0]["status"] == "undone"


def test_xdg_directories_do_not_redirect_the_existing_home_defaults(scheduled):
    case = scheduled
    seed(case)
    xdg_journal = case.xdg_state / "megalodon/enforced.jsonl"
    en._journal(xdg_journal, [dict(schema=en.SCHEMA, id="xdg-pause", action="suspend_process",
                                 target="11111111@7:/synthetic/other", status="applied",
                                 at=en._iso(NOW - timedelta(minutes=10)), until=en._iso(NOW))])
    xdg_policy = case.xdg_config / "megalodon/enforce.toml"
    xdg_policy.parent.mkdir(parents=True)
    xdg_policy.write_text("invalid TOML in an unrelated XDG location", encoding="utf-8")
    before = xdg_journal.read_bytes()

    result = case.invoke()

    assert result.code == 0 and "policy_error" not in result.output
    assert [record["undo_of"] for record in result.output["expired"]] == ["pause-a"]
    assert case.starts == [PID] and case.attempts == [signal.SIGCONT]
    assert xdg_journal.read_bytes() == before and not xdg_journal.with_name(xdg_journal.name + ".lock").exists()
