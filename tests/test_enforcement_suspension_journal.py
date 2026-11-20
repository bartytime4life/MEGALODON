"""Durable suspension intent and fault recovery, with no real process or service operations."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import errno
import os
import stat

import pytest

from megalodon import enforcement as en
from megalodon import response_engine as response
from megalodon import timeline
from test_enforcement import decide, enable, enforce, paths


NOW = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
TARGET = "424242@100:/synthetic/workload"


@pytest.fixture(autouse=True)
def no_native_signals(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("these journal tests must never reach a real signal operation")
    monkeypatch.setattr(en.Executor, "_signal", forbidden)
    monkeypatch.setattr(os, "pidfd_open", forbidden, raising=False)
    monkeypatch.setattr(en.signal, "pidfd_send_signal", forbidden, raising=False)
    monkeypatch.setattr(os, "kill", forbidden)


@pytest.fixture
def p(tmp_path):
    result = paths(tmp_path)
    response.write_default_policy(result["policy"])
    result["policy"].write_text(result["policy"].read_text().replace(
        'name = "code-loaded-into-memory"\n', 'name = "code-loaded-into-memory"\nsuspend_minutes = 5\n'))
    en.init(result["enforce"], response_policy=result["policy"])
    enable(result, ["suspend_process"], ["code-loaded-into-memory"])
    signals = response.memory_signals(dict(checked_at=en._iso(NOW), findings=[dict(
        rule_id="MEMORY_ELF_IN_ANONYMOUS", severity="CRITICAL", subject="memory:424242:100",
        detail="synthetic memory finding",
        evidence=dict(processes=[dict(pid=424242, start=100, program="/synthetic/workload")]))]))
    decide(result, signals, now=NOW)
    return result


class Recorder:
    def __init__(self, p, stop=None):
        self.p, self.stop = p, stop
        self.calls, self.notices = [], []

    def suspend_process(self, target, decision):
        pending = en.active(self.p["journal"])
        assert len(pending) == 1 and pending[0]["status"] == "pending"
        assert pending[0]["target"] == target == TARGET
        assert pending[0]["until"] == en._iso(NOW + timedelta(minutes=5))
        self.calls.append("STOP")
        if self.stop:
            self.stop()
        return dict(pid=424242, start=100, program="/synthetic/workload")

    def undo_suspend_process(self, record):
        assert record["target"] == TARGET
        self.calls.append("CONT")

    def notify_resumed(self, records):
        self.notices.extend(records)


def test_intent_is_synced_before_stop_and_completed_once(p, monkeypatch):
    synced = []
    real_fsync = os.fsync

    def fsync(fd):
        real_fsync(fd)
        synced.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")

    monkeypatch.setattr(os, "fsync", fsync)

    def check_sync():
        assert synced[:2] == ["file", "directory"]

    executor = Recorder(p, check_sync)
    result = enforce(p, now=NOW, executor=executor)
    records = en.entries(p["journal"])
    assert [r["status"] for r in records] == ["pending", "applied"]
    assert records[0]["id"] == records[1]["id"] == result["applied"][0]["id"]
    assert en.active(p["journal"]) == [records[1]], "the intent and completion are one active hold"
    assert enforce(p, now=NOW, executor=executor)["applied"] == []
    assert executor.calls == ["STOP"]
    events = timeline.events(ledger=p["ledger"], journal=p["journal"])
    actions = [e for e in events if e["kind"] == "action"]
    assert [e["status"] for e in actions] == ["pending", "applied"]
    assert sum(e["status"] == "applied" for e in actions) == 1


def test_intent_write_failure_prevents_stop(p, monkeypatch):
    executor = Recorder(p)
    monkeypatch.setattr(en, "_journal", lambda *a: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full")))
    with pytest.raises(OSError, match="full"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == [] and en.active(p["journal"]) == []


def test_directory_sync_failure_prevents_stop(p, monkeypatch):
    real_fsync = os.fsync

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "directory sync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    executor = Recorder(p)
    with pytest.raises(OSError, match="directory sync failed"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == []
    assert en.active(p["journal"])[0]["status"] == "pending"


def test_interruption_after_stop_keeps_intent_and_restart_does_not_repeat_stop(p):
    class Interrupted(BaseException):
        pass

    executor = Recorder(p, lambda: (_ for _ in ()).throw(Interrupted()))
    with pytest.raises(Interrupted):
        enforce(p, now=NOW, executor=executor)
    assert [r["status"] for r in en.active(p["journal"])] == ["pending"]
    assert not p["enforce_state"].exists(), "the interrupted cursor was never saved"
    executor.stop = None
    assert enforce(p, now=NOW + timedelta(minutes=1), executor=executor)["applied"] == []
    assert executor.calls == ["STOP"], "durable intent prevents a duplicate stop after cursor loss"
    result = enforce(p, now=NOW + timedelta(minutes=6), executor=executor)
    assert [r["status"] for r in result["expired"]] == ["undone"]
    assert executor.calls == ["STOP", "CONT"] and en.active(p["journal"]) == []


def test_applied_append_failure_keeps_intent_and_can_be_recovered(p, monkeypatch):
    real_journal = en._journal

    def journal(path, records):
        if records[0]["status"] == "applied":
            raise OSError(errno.EIO, "completion write failed")
        real_journal(path, records)

    monkeypatch.setattr(en, "_journal", journal)
    executor = Recorder(p)
    with pytest.raises(OSError, match="completion write failed"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == ["STOP"]
    pending = en.active(p["journal"])
    assert len(pending) == 1 and pending[0]["status"] == "pending"
    monkeypatch.setattr(en, "_journal", real_journal)
    result = en.undo(pending[0]["id"], journal=p["journal"], executor=executor, now=NOW)
    assert result["status"] == "undone" and en.active(p["journal"]) == []
    assert executor.calls == ["STOP", "CONT"]


def test_failed_action_preserves_uncertain_intent(p):
    executor = Recorder(p, lambda: (_ for _ in ()).throw(OSError(errno.EIO, "outcome unavailable")))
    result = enforce(p, now=NOW, executor=executor)
    assert [r["status"] for r in result["refused"]] == ["failed"]
    assert [r["status"] for r in en.entries(p["journal"])] == ["pending", "failed"]
    assert [r["status"] for r in en.active(p["journal"])] == ["pending"]


def test_state_write_failure_does_not_repeat_completed_suspension(p, monkeypatch):
    real_write = response._atomic_write

    def write(path, data):
        if path == p["enforce_state"]:
            raise OSError(errno.EIO, "cursor write failed")
        real_write(path, data)

    monkeypatch.setattr(response, "_atomic_write", write)
    executor = Recorder(p)
    with pytest.raises(OSError, match="cursor write failed"):
        enforce(p, now=NOW, executor=executor)
    monkeypatch.setattr(response, "_atomic_write", real_write)
    assert [r["status"] for r in en.active(p["journal"])] == ["applied"]
    assert enforce(p, now=NOW + timedelta(minutes=1), executor=executor)["applied"] == []
    assert executor.calls == ["STOP"]


def test_short_writes_are_completed_before_success(tmp_path, monkeypatch):
    path = tmp_path / "journal.jsonl"
    real_write = os.write
    writes = []

    def write(fd, data):
        writes.append(len(data))
        return real_write(fd, data[:7])

    monkeypatch.setattr(os, "write", write)
    en._journal(path, [dict(id="one", action="suspend_process", status="pending", target=TARGET)])
    assert len(writes) > 1 and en.entries(path)[0]["id"] == "one"
    assert path.read_bytes().endswith(b"\n")


def test_zero_write_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "write", lambda *args: 0)
    with pytest.raises(OSError, match="no progress"):
        en._journal(tmp_path / "journal.jsonl", [dict(id="one")])


def test_incomplete_tail_is_preserved_and_refuses_new_intent(p):
    p["journal"].write_bytes(b'{"unfinished":')
    p["journal"].chmod(0o600)
    executor = Recorder(p)
    with pytest.raises(en.EnforcementError, match="incomplete record"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == [] and p["journal"].read_bytes() == b'{"unfinished":'


def test_partial_completion_preserves_the_complete_pending_record(p, monkeypatch):
    real_write = os.write
    partial = []

    def write(fd, data):
        if partial:
            raise OSError(errno.EIO, "torn completion")
        if b'"status":"applied"' in bytes(data):
            partial.append(True)
            return real_write(fd, data[:9])
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", write)
    executor = Recorder(p)
    with pytest.raises(OSError, match="torn completion"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == ["STOP"]
    assert [r["status"] for r in en.active(p["journal"])] == ["pending"]
    monkeypatch.setattr(os, "write", real_write)
    with pytest.raises(en.EnforcementError, match="incomplete record"):
        en._journal(p["journal"], [dict(id="another")])


class RecoveryRecorder:
    def __init__(self):
        self.resumed, self.notices = [], []

    def suspend_process(self, target, decision):
        pytest.fail("an unusable journal must prevent any new stop")

    def undo_suspend_process(self, record):
        self.resumed.append(record["target"])

    def notify_resumed(self, records):
        self.notices.extend(records)


def recovery_record(identifier, target):
    return dict(schema=en.SCHEMA, id=identifier, at=en._iso(NOW - timedelta(minutes=10)),
                action="suspend_process", status="applied", target=target,
                until=en._iso(NOW - timedelta(minutes=1)))


@pytest.mark.parametrize("fault", ["capacity", "torn_tail", "write_error"])
def test_journal_failure_does_not_starve_later_due_targets(p, monkeypatch, fault):
    targets = ["424243@100:/synthetic/first", "424244@100:/synthetic/second"]
    records = [recovery_record("first", targets[0]), recovery_record("second", targets[1])]
    records[0]["status"] = "pending"
    en._journal(p["journal"], records)
    original = p["journal"].read_bytes()
    executor = RecoveryRecorder()

    with monkeypatch.context() as patch:
        if fault == "capacity":
            patch.setattr(en, "MAX_JOURNAL_BYTES", len(original))
        elif fault == "torn_tail":
            p["journal"].write_bytes(original + b'{"incomplete":')
        else:
            def failed_write(*args):
                raise OSError(errno.ENOSPC, "synthetic storage exhausted")
            patch.setattr(os, "write", failed_write)

        result = en.expire(journal=p["journal"], executor=executor, now=NOW)

        assert executor.resumed == targets
        assert [r["status"] for r in result] == ["failed", "failed"]
        assert all(r["recovery_status"] == "undone" and r["journal_error"] for r in result)
        assert all(r["notified"] for r in result), "a resume notice must survive audit failure"
        assert executor.notices == result
        assert en.active(p["journal"]) == records
        run_result = enforce(p, now=NOW, executor=executor)
        assert run_result["enabled"] is False and run_result["applied"] == []
        assert [r["status"] for r in run_result["expired"]] == ["failed", "failed"]
        assert all(r["recovery_status"] == "undone" and r["journal_error"] for r in run_result["expired"])
        assert "journal" in run_result["note"] and not p["enforce_state"].exists()
        assert executor.resumed == targets * 2, "each run attempts every due target before refusing a new stop"

    # Repair only this synthetic fixture. The implementation never truncates or silently repairs a journal.
    p["journal"].write_bytes(original)
    retried = en.expire(journal=p["journal"], executor=executor, now=NOW)
    assert [r["status"] for r in retried] == ["undone", "undone"]
    assert all("journal_error" not in r for r in retried)
    assert executor.resumed == targets * 3 and en.active(p["journal"]) == []


def test_run_preserves_recovery_and_denies_other_actions_after_journal_fsync_failure(p, monkeypatch):
    record = recovery_record("existing", "424243@100:/synthetic/existing")
    en._journal(p["journal"], [record])
    p["enforce"].write_text(p["enforce"].read_text().replace(
        'actions = ["suspend_process"]', 'actions = ["collect_evidence"]'))

    class Executor(RecoveryRecorder):
        def collect_evidence(self, target, decision):
            pytest.fail("journal failure must also prevent non-suspension actions")

    def failed_fsync(fd):
        raise OSError(errno.EIO, "synthetic sync failed after a complete line was written")

    monkeypatch.setattr(os, "fsync", failed_fsync)
    executor = Executor()
    result = enforce(p, now=NOW, executor=executor)

    assert executor.resumed == [record["target"]] and executor.notices == result["expired"]
    assert result["enabled"] is False and result["applied"] == []
    assert len(result["expired"]) == 1
    recovery = result["expired"][0]
    assert recovery["status"] == "failed" and recovery["recovery_status"] == "undone"
    assert "synthetic sync failed" in recovery["journal_error"] and recovery["notified"] is True
    assert not p["enforce_state"].exists()
    # The complete line is readable despite the sync failure; this does not establish power-loss durability.
    assert [r["status"] for r in en.entries(p["journal"])] == ["applied", "undone"]
    assert en.active(p["journal"]) == []


def test_failed_audit_of_a_held_pause_does_not_starve_another_target(p, monkeypatch):
    held = recovery_record("held", "424243@100:/synthetic/held")
    later = dict(held, id="later", until=en._iso(NOW + timedelta(minutes=5)))
    independent = recovery_record("independent", "424244@100:/synthetic/independent")
    records = [held, later, independent]
    en._journal(p["journal"], records)
    monkeypatch.setattr(en, "MAX_JOURNAL_BYTES", p["journal"].stat().st_size)
    executor = RecoveryRecorder()

    result = en.expire(journal=p["journal"], executor=executor, now=NOW)

    assert [r["status"] for r in result] == ["failed", "failed"]
    assert result[0]["note"] == "still paused by later" and result[0]["recovery_status"] == "undone"
    assert executor.resumed == [independent["target"]]
    assert executor.notices == [result[1]], "a retained sibling is not reported as resumed"
    assert en.active(p["journal"]) == records


def test_writer_never_crosses_the_reader_capacity_before_stop(p, monkeypatch):
    monkeypatch.setattr(en, "MAX_JOURNAL_BYTES", 1)
    executor = Recorder(p)
    with pytest.raises(en.EnforcementError, match="journal capacity"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == [] and en.active(p["journal"]) == []


def test_legacy_applied_records_and_failed_recovery_attempts_stay_active(tmp_path):
    path = tmp_path / "journal.jsonl"
    legacy = dict(id="legacy", action="suspend_process", target=TARGET, status="applied", undo={})
    pending = dict(id="new", action="suspend_process", target=TARGET, status="pending")
    completed = dict(pending, status="applied", undo={})
    failed_resume = dict(id="attempt", action="suspend_process", target=TARGET, status="failed", undo_of="legacy")
    en._journal(path, [legacy, pending, completed, failed_resume])
    assert en.active(path) == [legacy, completed]
    en._journal(path, [dict(id="undo", action="suspend_process", status="undone", undo_of="new")])
    assert en.active(path) == [legacy]


@pytest.mark.parametrize("completed,limit,allowed", [(False, 1, False), (True, 2, True)])
def test_uncertain_intents_consume_one_rate_limit_slot(p, completed, limit, allowed):
    enable(p, ["suspend_process"], ["code-loaded-into-memory"], max_actions_per_hour=limit)
    earlier = dict(id="earlier", at=en._iso(NOW), action="suspend_process", status="pending",
                   target="424243@100:/synthetic/earlier-workload")
    en._journal(p["journal"], [earlier] + ([dict(earlier, status="applied")] if completed else []))

    class Executor:
        def __init__(self):
            self.calls = []

        def suspend_process(self, target, decision):
            self.calls.append(target)
            return {}

    executor = Executor()
    result = enforce(p, now=NOW, executor=executor)
    assert executor.calls == ([TARGET] if allowed else [])
    assert len(result["applied"]) == int(allowed)
    if not allowed:
        assert "rate limit" in result["refused"][0]["reason"]


def test_dry_run_does_not_create_a_pending_intent(p):
    executor = Recorder(p)
    result = enforce(p, now=NOW, executor=executor, dry_run=True)
    assert [r["status"] for r in result["applied"]] == ["would_enforce"]
    assert executor.calls == [] and not p["journal"].exists()


def test_stage0_refusal_precedes_the_intent(p, monkeypatch):
    def denied():
        raise en.EnforcementError("this process is in Stage 0: no effects are allowed")

    monkeypatch.setattr(en, "_admit", denied)
    executor = Recorder(p)
    with pytest.raises(en.EnforcementError, match="Stage 0"):
        enforce(p, now=NOW, executor=executor)
    assert executor.calls == [] and not p["journal"].exists()
