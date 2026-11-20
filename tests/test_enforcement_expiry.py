"""Paused processes end on time: a playbook's suspend_minutes, then the next run resumes them, with the same checks."""
from __future__ import annotations

from datetime import timedelta
import time

import pytest

from megalodon import enforcement as en
from megalodon import response_engine as re_
from test_enforcement import child, decide, enable, enforce, memory_signal, p, state_of  # noqa: F401


def pause_for(p, minutes):
    """The memory playbook, with a pause that ends after `minutes`, pinned again."""
    text = p["policy"].read_text()
    marker = 'name = "code-loaded-into-memory"\n'
    assert marker in text
    p["policy"].write_text(text.replace(marker, marker + f"suspend_minutes = {minutes}\n"))
    en.init(p["enforce"], response_policy=p["policy"], replace=True)


def wait_for(pid, states):
    for _ in range(100):
        if state_of(pid) in states:
            return state_of(pid)
        time.sleep(0.02)
    return state_of(pid)


def paused(p, child):
    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    decide(p, memory_signal(child))
    result = enforce(p)
    assert wait_for(child.pid, "T") == "T"
    return result["applied"][0]


def test_a_pause_ends_when_its_time_is_up(p, child):
    pause_for(p, 30)
    record = paused(p, child)
    start = en._parse(record["at"])
    assert en._parse(record["until"]) == start + timedelta(minutes=30)
    assert enforce(p, now=start + timedelta(minutes=10))["expired"] == []
    assert state_of(child.pid) == "T", "not before its time"
    result = enforce(p, now=start + timedelta(minutes=31))
    assert [(r["status"], r["reason"], r["undo_of"]) for r in result["expired"]] == [("undone", "expired", record["id"])]
    assert wait_for(child.pid, "SR") in "SR" and en.active(p["journal"]) == []
    assert enforce(p, now=start + timedelta(minutes=40))["expired"] == [], "resumed once"
    from megalodon import timeline as tl
    ended = [e for e in tl.events(ledger=p["ledger"], journal=p["journal"]) if e["kind"] == "undo"]
    assert len(ended) == 1 and ended[0]["expired"] is True
    assert tl._line(ended[0]).startswith("ended on time: suspend_process"), "the timeline says it ended on time"


def test_a_pause_ends_even_when_enforcement_is_turned_off(p, child):
    pause_for(p, 5)
    record = paused(p, child)
    p["enforce"].write_text(p["enforce"].read_text().replace("enabled = true", "enabled = false"))
    result = enforce(p, now=en._parse(record["at"]) + timedelta(minutes=6))
    assert result["enabled"] is False and [r["status"] for r in result["expired"]] == ["undone"]
    assert wait_for(child.pid, "SR") in "SR"


def test_without_suspend_minutes_a_pause_lasts_until_undone(p, child):
    record = paused(p, child)
    assert "until" not in record
    assert enforce(p, now=en._now() + timedelta(days=30))["expired"] == []
    assert state_of(child.pid) == "T"
    en.undo(record["id"], journal=p["journal"])


def test_an_exited_process_is_never_signalled_and_its_pause_is_over(p, child):
    pause_for(p, 5)
    record = paused(p, child)
    child.kill()
    child.wait()
    result = enforce(p, now=en._parse(record["at"]) + timedelta(minutes=6))
    assert result["expired"][0]["status"] == "undone" and "exited" in result["expired"][0]["note"]
    assert en.active(p["journal"]) == []


def test_a_resume_that_fails_is_kept_and_tried_again(p, child):
    pause_for(p, 5)
    record = paused(p, child)

    class Refusing(en.Executor):
        def undo_suspend_process(self, record):
            raise PermissionError("operation not permitted")
    later = en._parse(record["at"]) + timedelta(minutes=6)
    result = enforce(p, now=later, executor=Refusing())
    assert result["expired"][0]["status"] == "failed" and "not permitted" in result["expired"][0]["reason"]
    assert [r["id"] for r in en.active(p["journal"])] == [record["id"]], "still listed as paused"
    assert [r["status"] for r in enforce(p, now=later)["expired"]] == ["undone"], "tried again, and resumed"
    assert wait_for(child.pid, "SR") in "SR"


def test_a_dry_run_only_says_what_it_would_resume(p, child):
    pause_for(p, 5)
    record = paused(p, child)
    result = enforce(p, now=en._parse(record["at"]) + timedelta(minutes=6), dry_run=True)
    assert [r["status"] for r in result["expired"]] == ["would_resume"]
    assert state_of(child.pid) == "T" and len(en.active(p["journal"])) == 1
    en.undo(record["id"], journal=p["journal"])


def test_expire_reads_only_when_nothing_is_due(tmp_path):
    journal = tmp_path / "state" / "enforced.jsonl"
    assert en.expire(journal=journal) == []
    assert not (tmp_path / "state").exists(), "no lock, no folder, nothing written"


@pytest.mark.parametrize("value", [-1, 10081, "true", True])
def test_suspend_minutes_is_checked(p, value):
    text = p["policy"].read_text().replace('name = "code-loaded-into-memory"\n',
                                           f'name = "code-loaded-into-memory"\nsuspend_minutes = {str(value).lower()}\n')
    p["policy"].write_text(text)
    with pytest.raises(re_.ResponseError, match="suspend_minutes"):
        re_.load_policy(p["policy"])
