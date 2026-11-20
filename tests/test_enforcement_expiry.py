"""Paused processes end on time: a playbook's suspend_minutes, then the next run resumes them, with the same checks."""
from __future__ import annotations

from datetime import timedelta
import json
import os
from pathlib import Path
import time

import pytest

from megalodon import enforcement as en
from megalodon import response_engine as re_
from test_enforcement import child, decide, enable, enforce, memory_signal, p, state_of  # noqa: F401


class Sent:
    """Stands in for the alert destinations: records what would be sent."""

    def __init__(self):
        self.notices, self.enabled = [], True

    def __call__(self, alerts):
        assert alerts == "test-alerts", "the configured alert settings are the ones used"
        return self if self.enabled else None

    def submit(self, notices, *, any_severity=False):
        self.notices += [(n, any_severity) for n in notices]


@pytest.fixture(autouse=True)
def sent(monkeypatch):
    """Every test here uses its own alert settings, never the home folder's."""
    from types import SimpleNamespace

    from megalodon import alerts, config
    recorder = Sent()
    monkeypatch.setattr(config, "load_settings", lambda path=None: SimpleNamespace(alerts="test-alerts"))
    monkeypatch.setattr(alerts, "dispatcher_for", recorder)
    return recorder


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


def test_a_process_paused_twice_stays_paused_until_both_end(p, child):
    """Two decisions pause the same process: the first to end does not resume it under the second."""
    pause_for(p, 30)
    text = p["policy"].read_text()
    marker = 'name = "dropped-tool-phoning-home"\n'
    p["policy"].write_text(text.replace(marker, marker + "suspend_minutes = 30\n"))
    en.init(p["enforce"], response_policy=p["policy"], replace=True)
    enable(p, ["suspend_process"], ["code-loaded-into-memory", "dropped-tool-phoning-home"])
    start = en._now().replace(microsecond=0)
    decide(p, memory_signal(child), now=start)
    first = enforce(p, now=start)["applied"][0]
    assert wait_for(child.pid, "T") == "T"
    text = Path(f"/proc/{child.pid}/stat").read_text()
    started, exe = int(text[text.rindex(")") + 2:].split()[19]), os.readlink(f"/proc/{child.pid}/exe")
    outbound = re_.egress_signals(dict(checked_at="2026-11-20T00:05:00Z", findings=[dict(
        rule_id="OUTBOUND_FROM_TEMPORARY", severity="HIGH", program=exe, protocol="tcp", port=443,
        address="198.51.100.4", evidence=dict(processes=[dict(pid=child.pid, start=started, program=exe)]))]))
    decide(p, outbound, now=start + timedelta(minutes=5))
    second = enforce(p, now=start + timedelta(minutes=5))["applied"][0]
    assert first["target"] == second["target"] and first["id"] != second["id"]
    ended = enforce(p, now=start + timedelta(minutes=31))["expired"]
    assert [(r["undo_of"], r["status"]) for r in ended] == [(first["id"], "undone")]
    assert ended[0]["note"] == f"still paused by {second['id']}"
    time.sleep(0.1)
    assert state_of(child.pid) == "T", "the second pause still holds it"
    assert [r["id"] for r in en.active(p["journal"])] == [second["id"]]
    assert [r["undo_of"] for r in enforce(p, now=start + timedelta(minutes=36))["expired"]] == [second["id"]]
    assert wait_for(child.pid, "SR") in "SR"


def test_a_dry_run_without_an_enforcement_policy_resumes_nothing(tmp_path, monkeypatch, capsys):
    from megalodon.cli import main
    pending = [dict(id="abc", action="suspend_process", target="1@2:/tmp/x", until="2026-11-20T00:00:00Z")]
    monkeypatch.setattr(en, "due", lambda *a, **k: pending)
    monkeypatch.setattr(en, "expire", lambda *a, **k: pytest.fail("a dry run must not resume anything"))
    with pytest.raises(SystemExit) as exit_:
        main(["enforce", "run", "--dry-run", "--policy", str(tmp_path / "missing.toml")])
    assert exit_.value.code == 0
    assert [r["status"] for r in json.loads(capsys.readouterr().out)["expired"]] == ["would_resume"]


def test_a_pause_that_ends_is_announced(p, child, sent):
    pause_for(p, 5)
    record = paused(p, child)
    ended = enforce(p, now=en._parse(record["at"]) + timedelta(minutes=6))["expired"]
    assert ended[0]["notified"] is True
    [(notice, any_severity)] = sent.notices
    assert (notice.rule_id, notice.severity, any_severity) == ("PAUSE_ENDED", "HIGH", True), \
        "sent whatever the destinations' minimum severity"
    assert record["target"] in notice.message and record["id"] in notice.message
    assert record["incident"] and record["incident"] in notice.message


def test_nothing_is_announced_when_nothing_was_resumed(p, child, sent):
    pause_for(p, 5)
    record = paused(p, child)
    child.kill()
    child.wait()
    enforce(p, now=en._parse(record["at"]) + timedelta(minutes=6))
    assert sent.notices == [], "an exited process does not run again"


def test_a_pause_ends_even_when_it_cannot_be_announced(p, child, sent, monkeypatch):
    pause_for(p, 5)
    record = paused(p, child)
    sent.enabled = False                                 # alerts are off in the settings
    ended = enforce(p, now=en._parse(record["at"]) + timedelta(minutes=6))["expired"]
    assert (ended[0]["status"], ended[0]["notified"]) == ("undone", False)
    assert "no alert destinations" in ended[0]["notice"]
    assert wait_for(child.pid, "SR") in "SR" and en.active(p["journal"]) == []

    from megalodon import config
    from megalodon.validation import ValidationError
    monkeypatch.setattr(config, "load_settings", lambda path=None: (_ for _ in ()).throw(ValidationError("bad")))
    second = paused_again(p, child)
    ended = enforce(p, now=en._parse(second["at"]) + timedelta(minutes=6))["expired"]
    assert ended[0]["status"] == "undone" and "bad" in ended[0]["notice"]


def paused_again(p, child):
    decide(p, memory_signal(child, start=None), now=en._now() + timedelta(days=2))
    result = enforce(p, now=en._now() + timedelta(days=2))
    assert wait_for(child.pid, "T") == "T"
    return result["applied"][0]
