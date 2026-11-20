"""Overlapping suspension decisions release holds before resuming a process.

The shared recovery fixture replaces every process, procfs, signal, lock and
journal operation. These tests create and signal no native process.
"""
from copy import deepcopy
from datetime import timedelta
import errno
import signal
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from test_enforcement_identity_recovery import HANDLE, NOW, PID, PROGRAM, START, recovery  # noqa: F401


def add_hold(state, identifier, *, until="2026-11-20T11:59:00Z", target=None):
    record = deepcopy(state.journal[0])
    record.update(id=identifier, incident=f"incident-{identifier}")
    if target is not None:
        record["target"] = target
    if until is None:
        record.pop("until")
    else:
        record["until"] = until
    state.journal.append(record)
    return record


def undo(state, identifier):
    return en.undo(identifier, journal="memory-journal", executor=state.executor, now=NOW)


def test_due_holds_share_one_resume_and_one_notice(recovery):
    add_hold(recovery, "pause-b")

    ended = recovery.expire()

    assert [(r["undo_of"], r["status"]) for r in ended] == [
        ("pause-a", "undone"), ("pause-b", "undone")]
    assert recovery.signals == [signal.SIGCONT]
    assert recovery.opens == [PID] and recovery.closed == [HANDLE]
    assert len(recovery.notices) == 1
    assert recovery.notices[0]["undo_of"] == "pause-a"
    assert all(r["reason"] == "expired" for r in recovery.journal[2:])
    assert en.active("memory-journal") == []
    assert recovery.expire() == []
    assert recovery.signals == [signal.SIGCONT]


def test_distinct_exact_targets_are_resumed_independently(recovery, monkeypatch):
    first = recovery.journal[0]["target"]
    second = f"{PID + 1}@{START}:{PROGRAM}"
    add_hold(recovery, "pause-b", target=second)
    add_hold(recovery, "pause-c")
    add_hold(recovery, "pause-d", target=second)
    attempts = []
    monkeypatch.setattr(recovery.executor, "undo_suspend_process", lambda record: attempts.append(record["target"]))

    assert len(recovery.expire()) == 4

    assert attempts == [first, second]
    assert [r["target"] for r in recovery.notices] == [first, second]
    assert en.active("memory-journal") == []


def test_a_failed_journal_does_not_repeat_or_starve_grouped_recovery(recovery, monkeypatch):
    first = recovery.journal[0]["target"]
    second = f"{PID + 1}@{START}:{PROGRAM}"
    add_hold(recovery, "pause-b")
    add_hold(recovery, "pause-c", target=second)
    add_hold(recovery, "pause-d", target=second)
    recovery.journal.insert(0, dict(recovery.journal[0], status="pending"))
    attempts, writes = [], []
    monkeypatch.setattr(recovery.executor, "undo_suspend_process", lambda record: attempts.append(record["target"]))

    def full_journal(path, records):
        writes.extend(record["undo_of"] for record in records)
        raise en.EnforcementError("synthetic journal capacity exceeded")

    monkeypatch.setattr(en, "_journal", full_journal)
    ended = recovery.expire()

    assert attempts == [first, second], "a failed audit must not prevent the next process from being resumed"
    assert [record["undo_of"] for record in ended] == writes == ["pause-a", "pause-b", "pause-c", "pause-d"]
    assert all(record["status"] == "failed" and record["recovery_status"] == "undone"
               and record["journal_error"] for record in ended)
    assert [record["target"] for record in recovery.notices] == [first, second]
    assert [record["undo_of"] for record in ended if record.get("notified")] == ["pause-a", "pause-c"]
    assert [record["id"] for record in en.active("memory-journal")] == ["pause-a", "pause-b", "pause-c", "pause-d"], \
        "pending and applied rows for one ID are one hold, including when recovery audit fails"


def test_mixed_group_audit_failures_preserve_notices_and_block_new_actions(recovery, monkeypatch):
    first = recovery.journal[0]["target"]
    second = f"{PID + 1}@{START}:{PROGRAM}"
    add_hold(recovery, "pause-b")
    add_hold(recovery, "pause-c", target=second)
    add_hold(recovery, "pause-d", target=second)
    attempts, writes = [], []
    journal = en._journal
    monkeypatch.setattr(recovery.executor, "undo_suspend_process", lambda record: attempts.append(record["target"]))

    def partly_available_journal(path, records):
        assert len(records) == 1
        writes.append(records[0]["undo_of"])
        if records[0]["undo_of"] in {"pause-b", "pause-c"}:
            raise OSError(errno.ENOSPC, "synthetic audit failure")
        journal(path, records)

    policy_path = SimpleNamespace(lstat=lambda: None)
    policy_path.expanduser = lambda: policy_path
    monkeypatch.setattr(en, "Path", lambda path: policy_path)
    monkeypatch.setattr(en, "load_policy", lambda path: {"enabled": True})
    monkeypatch.setattr(en, "_journal", partly_available_journal)
    monkeypatch.setattr(en.engine, "load_policy", lambda path: pytest.fail("audit failure must block new actions"))

    result = en.run(policy_path="synthetic-policy", journal="memory-journal", executor=recovery.executor, now=NOW)

    assert attempts == [first, second]
    assert [record["undo_of"] for record in result["expired"]] == writes == ["pause-a", "pause-b", "pause-c", "pause-d"]
    assert [record["status"] for record in result["expired"]] == ["undone", "failed", "failed", "undone"]
    failed = [record for record in result["expired"] if record["status"] == "failed"]
    assert all(record["recovery_status"] == "undone" and record["journal_error"] for record in failed)
    assert [record["target"] for record in recovery.notices] == [first, second]
    assert [record["undo_of"] for record in result["expired"] if record.get("notified")] == ["pause-a", "pause-c"]
    assert result["enabled"] is False and result["applied"] == [] and "journal" in result["note"]
    assert [record["id"] for record in en.active("memory-journal")] == ["pause-b", "pause-c"]


def test_a_later_hold_defers_resume_until_its_own_expiry(recovery):
    add_hold(recovery, "pause-b", until=en._iso(NOW + timedelta(minutes=5)))

    ended = recovery.expire()

    assert [(r["undo_of"], r["note"]) for r in ended] == [("pause-a", "still paused by pause-b")]
    assert recovery.opens == recovery.signals == recovery.notices == []
    assert [r["id"] for r in en.active("memory-journal")] == ["pause-b"]
    ended = en.expire(journal="memory-journal", executor=recovery.executor, now=NOW + timedelta(minutes=6))
    assert [r["undo_of"] for r in ended] == ["pause-b"]
    assert recovery.signals == [signal.SIGCONT] and len(recovery.notices) == 1
    assert en.active("memory-journal") == []


def test_an_indefinite_hold_outlives_all_expiring_holds(recovery):
    add_hold(recovery, "pause-b")
    add_hold(recovery, "pause-c", until=None)

    ended = recovery.expire()

    assert len(ended) == 2 and all(r["note"] == "still paused by pause-c" for r in ended)
    assert [r["id"] for r in en.active("memory-journal")] == ["pause-c"]
    assert en.expire(journal="memory-journal", executor=recovery.executor, now=NOW + timedelta(days=8)) == []
    assert recovery.opens == recovery.signals == recovery.notices == []


@pytest.mark.parametrize("failure", ["read_error", "signal_error"])
def test_a_retryable_failure_retains_every_due_hold(recovery, failure):
    add_hold(recovery, "pause-b")
    setattr(recovery, failure, PermissionError(errno.EPERM, "temporarily denied"))

    ended = recovery.expire()

    assert [(r["undo_of"], r["status"]) for r in ended] == [("pause-a", "failed"), ("pause-b", "failed")]
    assert [r["id"] for r in en.active("memory-journal")] == ["pause-a", "pause-b"]
    assert recovery.opens == [PID] and recovery.closed == [HANDLE]
    assert recovery.notices == []
    assert [(r["undo_of"], r["status"]) for r in recovery.journal[2:]] == [
        ("pause-a", "failed"), ("pause-b", "failed")]

    setattr(recovery, failure, None)
    ended = recovery.expire()

    assert len(ended) == 2 and all(r["status"] == "undone" for r in ended)
    assert recovery.signals == [signal.SIGCONT] * (2 if failure == "signal_error" else 1)
    assert en.active("memory-journal") == [] and len(recovery.notices) == 1


@pytest.mark.parametrize("gone", ["exited", "reused"])
def test_a_gone_identity_ends_every_due_hold_without_a_notice(recovery, gone):
    add_hold(recovery, "pause-b")
    if gone == "exited":
        recovery.open_error = ProcessLookupError(errno.ESRCH, "no process")
    else:
        recovery.start = START + 1

    ended = recovery.expire()

    assert len(ended) == 2 and all(r["status"] == "undone" and r.get("note") for r in ended)
    assert recovery.opens == [PID]
    assert recovery.signals == recovery.notices == []
    assert en.active("memory-journal") == []


def test_manual_undo_releases_only_its_hold_and_names_the_remaining_holds(recovery):
    add_hold(recovery, "pause-b", until=None)
    add_hold(recovery, "pause-c", until=None)

    ended = undo(recovery, "pause-a")

    assert ended["status"] == "undone" and ended["note"] == "still paused by pause-b, pause-c"
    assert [r["id"] for r in en.active("memory-journal")] == ["pause-b", "pause-c"]
    assert undo(recovery, "pause-b")["note"] == "still paused by pause-c"
    assert recovery.opens == recovery.signals == recovery.notices == []
    ended = undo(recovery, "pause-c")
    assert ended["status"] == "undone" and not ended.get("note")
    assert recovery.signals == [signal.SIGCONT]
    assert en.active("memory-journal") == []


def test_an_indefinite_hold_for_another_identity_does_not_block_manual_undo(recovery):
    add_hold(recovery, "pause-b", until=None, target=f"{PID}@{START + 1}:{PROGRAM}")

    ended = undo(recovery, "pause-a")

    assert ended["status"] == "undone" and not ended.get("note")
    assert recovery.signals == [signal.SIGCONT]
    assert [r["id"] for r in en.active("memory-journal")] == ["pause-b"]


def test_failed_manual_resume_keeps_the_last_hold_available_for_retry(recovery):
    add_hold(recovery, "pause-b")
    undo(recovery, "pause-a")
    recovery.signal_error = PermissionError(errno.EPERM, "temporarily denied")

    with pytest.raises(PermissionError):
        undo(recovery, "pause-b")

    assert [r["id"] for r in en.active("memory-journal")] == ["pause-b"]
    recovery.signal_error = None
    assert undo(recovery, "pause-b")["status"] == "undone"
    assert recovery.signals == [signal.SIGCONT, signal.SIGCONT]
    assert en.active("memory-journal") == []


def test_notice_failure_does_not_retain_successfully_released_holds(recovery, monkeypatch):
    add_hold(recovery, "pause-b")
    attempts = []

    def fail_notice(ended):
        attempts.extend(ended)
        raise en.EnforcementError("no alert destinations are configured")

    monkeypatch.setattr(recovery.executor, "notify_resumed", fail_notice)
    ended = recovery.expire()

    assert len(attempts) == 1 and attempts[0]["undo_of"] == "pause-a"
    assert ended[0]["notified"] is False and "no notice sent" in ended[0]["notice"]
    assert all(r["status"] == "undone" for r in ended)
    assert recovery.signals == [signal.SIGCONT] and en.active("memory-journal") == []


@pytest.mark.parametrize("operation", ["expire", "undo"])
def test_stage0_rejects_overlap_release_before_lock_or_process_work(recovery, monkeypatch, operation):
    from megalodon import execution_boundary

    add_hold(recovery, "pause-b")
    before = deepcopy(recovery.journal)
    monkeypatch.setattr(execution_boundary, "_stage0_selected", True)

    with pytest.raises(en.EnforcementError, match="Stage 0"):
        recovery.expire() if operation == "expire" else undo(recovery, "pause-a")

    assert recovery.opens == recovery.signals == recovery.locks == recovery.notices == []
    assert recovery.journal == before
