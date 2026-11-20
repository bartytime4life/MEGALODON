"""Ransomware recovery with fake procfs/pidfds, clocks and inotify only.

The shared fixture rejects native signals, subprocesses, sockets and systemctl.
These are command/loop regressions, not installed-systemd acceptance.
"""
from __future__ import annotations

from datetime import timedelta
import errno
import json
import signal
from threading import Event, Thread

import pytest

from megalodon import cli, enforcement as en, execution_boundary, ransomware_watch as rw
from megalodon import response_engine as response
from test_enforcement_scheduled_cli import NOW, START, seed, scheduled  # noqa: F401


def forbidden(*args, **kwargs):
    pytest.fail("recovery maintenance must not discover processes or admit new actions")


def responder(case, **kwargs):
    return rw.Responder(journal=case.journal, enforcement_policy=case.policy,
                        enforcement_state=case.state, **kwargs)


def finding():
    return rw.Finding("RANSOM_NOTE", "HIGH", NOW, "synthetic note", {})


def watcher(case, monkeypatch, *, polls, emit=forbidden):
    """Drive the real loop with a monotonic clock, never a real inotify descriptor."""
    stop, monotonic = Event(), [0.0]
    state = {"polls": 0, "closed": False}
    events = iter(polls)
    root = case.home / "watched"
    root.mkdir()

    class SyntheticInotify:
        def add(self, path):
            return True

        def events(self, timeout):
            assert timeout >= 0
            state["polls"] += 1
            try:
                seconds, batch = next(events)
            except StopIteration:
                stop.set()
                return []
            monotonic[0] = seconds
            case.clock = NOW + timedelta(seconds=seconds)
            return batch

        def close(self):
            state["closed"] = True

    monkeypatch.setattr(rw, "_Inotify", SyntheticInotify)
    actual = rw.Watcher([root], rw.RansomwareDetector(), emit, suspects_fn=forbidden,
                        clock=lambda: monotonic[0])
    state.update(stop=stop, monotonic=monotonic, root=root)
    return actual, state


@pytest.mark.parametrize("policy", ["disabled", "missing", "invalid"])
def test_quiet_watch_recovers_without_new_decisions_or_an_enabled_policy(scheduled, monkeypatch, policy):
    case = scheduled
    seed(case, until=NOW + timedelta(minutes=1))
    if policy == "missing":
        case.policy.unlink()
    elif policy == "invalid":
        case.policy.write_text("[enforce\n", encoding="utf-8")
    monkeypatch.setattr(en, "run", forbidden)
    monkeypatch.setattr(response, "ingest", forbidden)
    actual, loop = watcher(case, monkeypatch, polls=[(29, []), (30, []), (59, []), (60, []), (61, [])])
    attempts = []
    recovery = responder(case)

    def maintain():
        result = recovery.recover()
        attempts.append((case.clock, result))

    actual.run(loop["stop"], maintenance=maintain)

    assert [at for at, _ in attempts] == [NOW, NOW + timedelta(seconds=30), NOW + timedelta(seconds=60)]
    assert attempts[-1][1]["expired"][0]["status"] == "undone"
    assert case.attempts == [signal.SIGCONT] and case.process_state == "R"
    assert en.active(case.journal) == [] and not case.state.exists()


def test_startup_recovers_before_the_first_poll_and_retries_a_failed_signal(scheduled, monkeypatch):
    case = scheduled
    seed(case)
    case.signal_error = PermissionError(errno.EPERM, "synthetic SIGCONT denied")
    actual, loop = watcher(case, monkeypatch, polls=[(29, []), (30, []), (31, [])])
    recovery, outcomes = responder(case), []

    def maintain():
        result = recovery.recover()
        outcomes.append((loop["polls"], result))
        if len(outcomes) == 1:
            assert [r["id"] for r in en.active(case.journal)] == ["pause-a"]
            case.signal_error = None

    actual.run(loop["stop"], maintenance=maintain)

    assert outcomes[0][0] == 0, "an overdue hold must not wait for a new filesystem event"
    assert outcomes[0][1]["expired"][0]["status"] == "failed"
    assert "synthetic SIGCONT denied" in outcomes[0][1]["expired"][0]["reason"]
    assert outcomes[1][1]["expired"][0]["status"] == "undone"
    assert len(outcomes) == 2 and case.attempts == [signal.SIGCONT, signal.SIGCONT]
    assert en.active(case.journal) == []


def test_busy_event_batch_cannot_starve_due_recovery(scheduled, monkeypatch):
    case = scheduled
    seed(case, until=NOW + timedelta(minutes=1))
    loop = {}

    def events():
        for second in (10, 30, 59, 60, 90):
            loop["monotonic"][0] = second
            case.clock = NOW + timedelta(seconds=second)
            yield (rw.IN_Q_OVERFLOW, 0, None, "")

    actual, loop = watcher(case, monkeypatch, polls=[(0, events())])
    observed = []

    def maintain():
        result = responder(case).recover()
        if result["expired"]:
            observed.append((case.clock, loop["polls"], result))

    actual.run(loop["stop"], maintenance=maintain)

    assert len(observed) == 1
    assert observed[0][:2] == (NOW + timedelta(seconds=60), 1), "recover inside the first busy batch"
    assert case.attempts == [signal.SIGCONT] and actual.overflows == 5


def test_plain_watch_does_not_recover_an_existing_hold(scheduled, monkeypatch):
    case = scheduled
    seed(case)
    before = case.journal.read_bytes()
    monkeypatch.setattr(en, "expire", forbidden)
    actual, loop = watcher(case, monkeypatch, polls=[(60, []), (120, [])])

    actual.run(loop["stop"])

    assert case.journal.read_bytes() == before and not case.lock.exists()
    assert case.starts == case.attempts == []


def test_stopping_and_restarting_the_watch_delays_recovery_until_it_runs(scheduled, monkeypatch):
    case = scheduled
    seed(case, until=NOW + timedelta(minutes=1))
    actual, loop = watcher(case, monkeypatch, polls=[(10, [])])
    actual.run(loop["stop"], maintenance=responder(case).recover)
    before = case.journal.read_bytes()
    case.clock = NOW + timedelta(hours=1)
    assert case.journal.read_bytes() == before and case.process_state == "T"
    assert case.attempts == []

    loop["stop"].clear()
    actual.run(loop["stop"], maintenance=responder(case).recover)

    assert case.attempts == [signal.SIGCONT] and en.active(case.journal) == []


@pytest.mark.parametrize("state", ["missing_enforcement", "invalid_enforcement", "no_decision", "bad_response"])
def test_findings_cannot_bypass_recovery_when_new_actions_are_unavailable(scheduled, monkeypatch, state):
    case = scheduled
    seed(case)
    decision = dict(decisions=0 if state == "no_decision" else 1, would_apply=0)

    def ingest(*args, **kwargs):
        if state == "bad_response":
            raise response.ResponseError("synthetic response policy unreadable")
        return decision

    monkeypatch.setattr(response, "ingest", ingest)
    if state == "missing_enforcement":
        case.policy.unlink()
    elif state == "invalid_enforcement":
        case.policy.write_text("[enforce\n", encoding="utf-8")
    if state in ("no_decision", "bad_response"):
        monkeypatch.setattr(en, "run", forbidden)

    result = responder(case)(finding())

    detail = result["recovery" if state in ("no_decision", "bad_response") else "enforcement"]
    assert detail["expired"][0]["status"] == "undone"
    assert case.attempts == [signal.SIGCONT] and en.active(case.journal) == []
    assert not case.state.exists()
    if state == "bad_response":
        assert result["decided"] is False and "unreadable" in result["error"]
    if state == "invalid_enforcement":
        assert detail["enabled"] is False and detail["policy_error"]
    if state == "missing_enforcement":
        assert detail["enabled"] is False and "no enforcement policy" in detail["note"]


@pytest.mark.parametrize("identity", ["unreadable", "reused", "exited"])
def test_recovery_retains_existing_process_identity_safeguards(scheduled, identity):
    case = scheduled
    seed(case)
    if identity == "unreadable":
        case.stat_path.unlink()
    elif identity == "reused":
        case.stat(START + 1)
    else:
        case.exited = True

    result = responder(case).recover()

    assert result["expired"][0]["status"] == ("failed" if identity == "unreadable" else "undone")
    assert bool(en.active(case.journal)) == (identity == "unreadable")
    assert case.attempts == case.notices == [] and not case.handles


def test_retiring_one_hold_does_not_claim_the_process_was_resumed(scheduled):
    case = scheduled
    seed(case)
    seed(case, "later-pause", until=NOW + timedelta(minutes=5))

    result = responder(case).recover()

    assert result["expired"][0]["status"] == "undone"
    assert "still paused by later-pause" in result["expired"][0]["note"]
    assert case.attempts == [] and case.process_state == "T"
    assert [r["id"] for r in en.active(case.journal)] == ["later-pause"]


def test_responder_keeps_failed_audit_separate_from_successful_signal(scheduled, monkeypatch):
    case = scheduled
    seed(case)
    before = case.journal.read_bytes()

    def full(*args):
        raise OSError(errno.ENOSPC, "synthetic journal full")

    monkeypatch.setattr(en.os, "write", full)
    monkeypatch.setattr(response, "ingest", lambda *a, **k: dict(decisions=1, would_apply=0))
    result = responder(case)(finding())["enforcement"]

    entry = result["expired"][0]
    assert (entry["status"], entry["recovery_status"]) == ("failed", "undone")
    assert "synthetic journal full" in entry["journal_error"]
    assert result["applied"] == [] and "could not be persisted" in result["note"]
    assert case.attempts == [signal.SIGCONT] and case.process_state == "R"
    assert case.journal.read_bytes() == before


def test_refused_action_classification_and_policy_diagnostics_are_preserved(scheduled, monkeypatch):
    monkeypatch.setattr(response, "ingest", lambda *a, **k: dict(decisions=1, would_apply=0))
    monkeypatch.setattr(en, "run", lambda **k: dict(enabled=False, applied=[], expired=[],
                        refused=[dict(action="suspend_process", target="synthetic", status="failed",
                                      reason="synthetic action failure")],
                        policy_error="synthetic invalid policy", note="new actions refused"))

    result = responder(scheduled)(finding())["enforcement"]

    assert result["refused"][0]["status"] == "failed"
    assert result["expired"] == [] and result["policy_error"] == "synthetic invalid policy"
    assert result["note"] == "new actions refused"


def test_recovery_error_is_reported_and_can_be_retried(scheduled, monkeypatch):
    case = scheduled
    seed(case)
    original = en.expire

    def denied(**kwargs):
        raise PermissionError(errno.EACCES, "synthetic unreadable journal")

    monkeypatch.setattr(en, "expire", denied)
    first = responder(case).recover()
    assert first["expired"] == [] and "unreadable journal" in first["error"]
    assert case.attempts == []
    monkeypatch.setattr(en, "expire", original)
    assert responder(case).recover()["expired"][0]["status"] == "undone"


def test_stage0_denies_recovery_before_locking_or_signalling(scheduled):
    case = scheduled
    seed(case)
    before = case.journal.read_bytes()
    execution_boundary.select_stage0()

    result = responder(case).recover()

    assert result["expired"] == [] and "Stage 0: no effects are allowed" in result["error"]
    assert case.journal.read_bytes() == before and not case.lock.exists()
    assert case.starts == case.attempts == []


def test_watcher_and_enforcement_run_share_the_recovery_lock(scheduled, monkeypatch):
    case = scheduled
    seed(case)
    entered, release, second_started = Event(), Event(), Event()
    original = en.Executor.undo_suspend_process
    results, errors = [], []

    def slow(self, record):
        entered.set()
        assert release.wait(5)
        return original(self, record)

    monkeypatch.setattr(en.Executor, "undo_suspend_process", slow)

    def first():
        try:
            results.append(en.run(policy_path=case.policy, journal=case.journal, state_path=case.state))
        except BaseException as exc:
            errors.append(exc)

    def second():
        second_started.set()
        try:
            results.append(responder(case).recover())
        except BaseException as exc:
            errors.append(exc)

    timer, watch = Thread(target=first), Thread(target=second)
    timer.start()
    try:
        assert entered.wait(5)
        watch.start()
        assert second_started.wait(5)
        watch.join(0.05)
        assert watch.is_alive(), "the second recovery waits for the shared journal lock"
    finally:
        release.set()
        timer.join(5)
        if watch.ident is not None:
            watch.join(5)
    assert not timer.is_alive() and not watch.is_alive() and not errors
    assert len(results) == 2 and sum(len(result["expired"]) for result in results) == 1
    assert case.attempts == [signal.SIGCONT] and en.active(case.journal) == []


@pytest.mark.parametrize("respond", [False, True])
def test_cli_recovery_stays_on_stderr_and_plain_watch_has_no_callback(scheduled, monkeypatch, capsys, respond):
    case = scheduled
    seed(case)
    case.signal_error = PermissionError(errno.EPERM, "synthetic SIGCONT denied")
    root = case.home / "docs"
    root.mkdir()

    class SyntheticWatcher:
        watched, truncated = 1, False

        def __init__(self, roots, detector, emit):
            assert roots == [str(root)]
            self.emit = emit

        def run(self, stop, *, maintenance=None):
            if respond:
                assert maintenance is not None
                maintenance()
            else:
                assert maintenance is None

        def close(self):
            pass

    monkeypatch.setattr(rw, "Watcher", SyntheticWatcher)
    monkeypatch.setattr(en, "run", forbidden)
    monkeypatch.setattr(response, "ingest", forbidden)
    argv = ["ransomware", "watch", "--dir", str(root)] + (["--respond"] if respond else [])
    with pytest.raises(SystemExit) as exit_:
        cli.main(argv)
    captured = capsys.readouterr()

    assert exit_.value.code == 0 and captured.out == ""
    recovery = [line.removeprefix("megalodon: recovery ") for line in captured.err.splitlines()
                if line.startswith("megalodon: recovery ")]
    assert len(recovery) == int(respond)
    if respond:
        entry = json.loads(recovery[0])["expired"][0]
        assert entry["status"] == "failed" and "SIGCONT denied" in entry["reason"]
        assert case.attempts == [signal.SIGCONT]
    else:
        assert case.attempts == [] and not case.lock.exists()
