"""A decision's containment comes first: the process is paused, and the address blocked, before evidence is
collected, so a process encrypting files or holding a reverse shell is not left running while it is."""
from __future__ import annotations

from test_enforcement import child, decide, enable, enforce, memory_signal, p  # noqa: F401

from megalodon import enforcement as en
from megalodon import response_engine as re_


def test_the_process_is_paused_before_evidence_is_collected(p, child):  # noqa: F811
    order = []

    class Recording(en.Executor):
        def collect_evidence(self, target, decision):
            order.append("collect_evidence")
            return {}

        def suspend_process(self, target, decision):
            order.append("suspend_process")
            return {}

    text = re_.DEFAULT_POLICY_TEXT
    playbook = text[text.index('name = "code-loaded-into-memory"'):]
    assert playbook[:playbook.index("\n[[")].count('actions = ["collect_evidence", "suspend_process"') == 1, \
        "the playbook lists evidence first"
    enable(p, ["collect_evidence", "suspend_process"], ["code-loaded-into-memory"])
    decide(p, memory_signal(child))
    result = enforce(p, executor=Recording())
    assert order == ["suspend_process", "collect_evidence"], result
    assert [r["action"] for r in result["applied"]] == ["suspend_process", "collect_evidence"]


def test_decisions_written_just_before_the_ledger_rotates_are_still_carried_out(p, monkeypatch):  # noqa: F811
    import os
    from types import SimpleNamespace
    done = []

    class Recording(en.Executor):
        def suspend_process(self, target, decision):
            done.append(decision["signal"]["key"])
            return {}

    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    me = SimpleNamespace(pid=os.getpid())
    decide(p, memory_signal(me, start=1))
    enforce(p, executor=Recording())                          # reads the ledger up to here
    decide(p, memory_signal(me, start=2))                      # appended after that read...
    monkeypatch.setattr(re_, "MAX_LEDGER_BYTES", 1)
    decide(p, memory_signal(me, start=3))                      # ...then the ledger rotates before this one
    assert p["ledger"].with_name(p["ledger"].name + ".1").exists()
    enforce(p, executor=Recording())
    assert len(done) == 3 and len(set(done)) == 3, done


def test_containment_comes_first_and_the_rest_keeps_the_playbooks_order():
    plans = [dict(action=name) for name in ("collect_evidence", "suspend_process", "block_address", "notify")]
    assert [p["action"] for p in en._in_order(plans)] == [
        "suspend_process", "block_address", "collect_evidence", "notify"]
    plans = [dict(action=name) for name in ("collect_evidence", "lock_account", "block_address", "notify")]
    assert [p["action"] for p in en._in_order(plans)] == [
        "block_address", "collect_evidence", "lock_account", "notify"]


def test_a_rotated_copy_that_is_not_the_ledger_last_read_is_left_alone(p, tmp_path):  # noqa: F811
    import os
    import shutil
    from types import SimpleNamespace
    done = []

    class Recording(en.Executor):
        def suspend_process(self, target, decision):
            done.append(decision["signal"]["key"])
            return {}

    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    me = SimpleNamespace(pid=os.getpid())
    decide(p, memory_signal(me, start=1))
    enforce(p, executor=Recording())
    # Some other file now sits at `.1` (copied in, so not the ledger that was read), holding a decision.
    other = dict(p, ledger=tmp_path / "other.jsonl", state=tmp_path / "other-state.json")
    decide(other, memory_signal(me, start=2) + memory_signal(me, start=3))
    # The removed ledger is held open, so neither new file can be given its inode number.
    with open(p["ledger"], "rb"):
        shutil.copy(other["ledger"], p["ledger"].with_name(p["ledger"].name + ".1"))
        p["ledger"].unlink()                                   # the ledger was removed, not rotated...
        decide(p, memory_signal(me, start=4))                  # ...and a new one started
    enforce(p, executor=Recording())
    assert [key.rsplit(":", 1)[1] for key in done] == ["1", "4"], done
