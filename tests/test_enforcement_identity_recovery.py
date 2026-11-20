"""Recovery never forgets a pause merely because process identity is unavailable.

All process, procfs, signal, lock and journal operations are in-memory stand-ins.
No native process is created or signalled by these tests.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import errno
import signal
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en


NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
PID, START, HANDLE = 42424242, 12345, 987654
PROGRAM = "/synthetic/worker"


@pytest.fixture
def recovery(monkeypatch):
    record = dict(schema=en.SCHEMA, id="pause-a", status="applied", action="suspend_process",
                  target=f"{PID}@{START}:{PROGRAM}", at="2026-11-20T11:50:00Z",
                  until="2026-11-20T11:55:00Z", incident="incident-a")
    state = SimpleNamespace(journal=[record], signals=[], closed=[], notices=[], opens=[], locks=[],
                            read_error=None, stat_text=None, start=START, executable=PROGRAM,
                            exe_error=None, open_error=None, signal_error=None)
    executor = en.Executor(root="/synthetic", quarantine="/synthetic/quarantine", home="/synthetic")

    class ProcPath:
        def __init__(self, *parts):
            self.parts = parts

        def read_text(self, *args):
            assert self.parts == ("/synthetic", "proc", str(PID), "stat")
            if state.read_error:
                raise state.read_error
            return state.stat_text if state.stat_text is not None else (
                f"{PID} (synthetic (worker)) " + " ".join(["S"] + ["0"] * 18 + [str(state.start)]))

    def open_pidfd(pid):
        assert pid == PID
        state.opens.append(pid)
        if state.open_error:
            raise state.open_error
        return HANDLE

    def readlink(path):
        assert path.parts == ("/synthetic", "proc", str(PID), "exe")
        if state.exe_error:
            raise state.exe_error
        return state.executable

    def send_signal(handle, number):
        assert handle == HANDLE
        state.signals.append(number)
        if state.signal_error:
            raise state.signal_error

    class MemoryLock:
        def __init__(self, journal):
            assert journal == "memory-journal"

        def __enter__(self):
            state.locks.append(True)
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(en, "Path", ProcPath)
    monkeypatch.setattr(en, "os", SimpleNamespace(pidfd_open=open_pidfd, readlink=readlink,
                                                 close=state.closed.append))
    monkeypatch.setattr(en, "signal", SimpleNamespace(SIGSTOP=signal.SIGSTOP, SIGCONT=signal.SIGCONT,
                                                     pidfd_send_signal=send_signal))
    monkeypatch.setattr(en, "entries", lambda path=None: deepcopy(state.journal))
    monkeypatch.setattr(en, "_journal", lambda path, records: state.journal.extend(deepcopy(records)))
    monkeypatch.setattr(en, "_Lock", MemoryLock)
    monkeypatch.setattr(executor, "notify_resumed", lambda ended: state.notices.extend(deepcopy(ended)))
    state.executor = executor
    state.expire = lambda: en.expire(journal="memory-journal", executor=executor, now=NOW)
    return state


def assert_retryable(state):
    result = state.expire()
    assert result[0]["status"] == "failed"
    assert [r["id"] for r in en.active("memory-journal")] == ["pause-a"]
    assert state.journal[-1]["status"] == "failed", "the failed recovery attempt is durable"
    assert state.journal[-1]["undo_of"] == "pause-a"
    assert not state.notices, "an unresolved pause must not be announced as resumed"
    return result


@pytest.mark.parametrize("error", [PermissionError(errno.EACCES, "denied"),
                                   OSError(errno.EIO, "unavailable"), FileNotFoundError(errno.ENOENT, "gone")])
def test_unreadable_stat_keeps_the_pause_for_retry(recovery, error):
    recovery.read_error = error
    assert_retryable(recovery)
    assert recovery.signals == [] and recovery.closed == [HANDLE]


@pytest.mark.parametrize("text", ["not a proc stat", f"{PID} (worker) S",
                                  f"{PID} (worker) " + " ".join(["S"] + ["0"] * 18 + ["unknown"]),
                                  f"{PID} (worker) " + " ".join(["S"] + ["0"] * 18 + ["-1"])])
def test_malformed_stat_keeps_the_pause_for_retry(recovery, text):
    recovery.stat_text = text
    assert_retryable(recovery)
    assert recovery.signals == [] and recovery.closed == [HANDLE]


def test_a_transient_identity_failure_is_retried_then_resumed_once(recovery):
    recovery.read_error = PermissionError(errno.EACCES, "temporarily denied")
    assert_retryable(recovery)
    recovery.read_error = None
    assert recovery.expire()[0]["status"] == "undone"
    assert recovery.expire() == []
    assert recovery.signals == [signal.SIGCONT]
    assert en.active("memory-journal") == []
    assert [r["status"] for r in recovery.journal] == ["applied", "failed", "undone"]
    assert len(recovery.notices) == 1


@pytest.mark.parametrize("error", [PermissionError(errno.EACCES, "denied"),
                                   FileNotFoundError(errno.ENOENT, "unavailable")])
def test_an_unreadable_executable_never_allows_a_signal(recovery, error):
    recovery.exe_error = error
    assert_retryable(recovery)
    assert recovery.signals == [] and recovery.closed == [HANDLE]


def test_a_changed_executable_does_not_prove_the_original_pause_ended(recovery):
    recovery.executable = "/synthetic/another-program"
    assert_retryable(recovery)
    assert recovery.signals == []


def test_a_confirmed_exit_ends_the_record_without_a_signal(recovery):
    recovery.open_error = ProcessLookupError(errno.ESRCH, "no process")
    result = recovery.expire()
    assert result[0]["status"] == "undone" and "exited" in result[0]["note"]
    assert en.active("memory-journal") == []
    assert recovery.signals == recovery.closed == recovery.notices == []


def test_a_verified_reused_pid_is_never_signalled(recovery):
    recovery.start = START + 1
    result = recovery.expire()
    assert result[0]["status"] == "undone" and "start time differs" in result[0]["note"]
    assert en.active("memory-journal") == []
    assert recovery.signals == recovery.notices == [] and recovery.closed == [HANDLE]


def test_a_signal_failure_is_recorded_and_remains_retryable(recovery):
    recovery.signal_error = PermissionError(errno.EPERM, "not permitted")
    assert_retryable(recovery)
    recovery.signal_error = None
    assert recovery.expire()[0]["status"] == "undone"
    assert recovery.signals == [signal.SIGCONT, signal.SIGCONT]
    assert len(recovery.notices) == 1


def test_a_pidfd_permission_failure_remains_retryable(recovery):
    recovery.open_error = PermissionError(errno.EPERM, "not permitted")
    assert_retryable(recovery)
    assert recovery.signals == recovery.closed == []


def test_an_invalid_target_is_not_silently_retired(recovery):
    recovery.journal[0]["target"] = "not-an-exact-process"
    assert_retryable(recovery)
    assert recovery.opens == recovery.signals == []


def test_a_new_pause_also_requires_a_readable_executable(recovery):
    recovery.exe_error = PermissionError(errno.EACCES, "denied")
    with pytest.raises(en.EnforcementError):
        recovery.executor.suspend_process(recovery.journal[0]["target"], {})
    assert recovery.signals == [] and recovery.closed == [HANDLE]


def test_stage0_refuses_before_lock_identity_or_journal_work(recovery, monkeypatch):
    from megalodon import execution_boundary

    monkeypatch.setattr(execution_boundary, "_stage0_selected", True)
    with pytest.raises(en.EnforcementError, match="Stage 0"):
        recovery.expire()
    assert recovery.opens == recovery.signals == recovery.locks == recovery.notices == []
    assert len(recovery.journal) == 1
