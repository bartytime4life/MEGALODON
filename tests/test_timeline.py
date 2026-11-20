"""Incident timeline: findings, decisions, enforcement and undos from the engine's own records, in order."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from megalodon import response_engine as re_
from megalodon import timeline as tl
from test_enforcement import enable, memory_signal, paths

T0 = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def signal(key, source, rule, severity, summary, **entities):
    return re_.Signal(key, source, rule, severity, T0.strftime('%Y-%m-%dT%H:%M:%SZ'), summary,
                      re_._entities(**entities))


@pytest.fixture
def p(tmp_path):
    p = paths(tmp_path)
    re_.write_default_policy(p["policy"])
    return p


def run(p, signals, minutes):
    re_.run(policy_path=p["policy"], ledger=p["ledger"], state_path=p["state"], signals=signals, protected=set(),
            now=T0 + timedelta(minutes=minutes))


def recorded(p):
    return dict(ledger=p["ledger"], journal=p["journal"])


def test_an_incident_is_told_in_order(p):
    run(p, [signal("egress:1", "egress", "OUTBOUND_FROM_TEMPORARY", "HIGH", "/tmp/x connects to 203.0.113.9:443",
                   address=["203.0.113.9"], process=["/tmp/x"])], 0)
    # No playbook decides on this one; the timeline still has it, from the observation log.
    run(p, [signal("credentials:1", "credentials", "CREDENTIAL_READ", "MEDIUM", "/tmp/x read ~/.ssh/id_ed25519",
                   process=["/tmp/x"], file=["/home/u/.ssh/id_ed25519"])], 5)
    run(p, [signal("webroot:1", "webroot", "WEB_SHELL_PATTERN", "HIGH", "a shell in uploads",
                   file=["/var/www/up/x.php"])], 6)
    assert oct(re_.observations_path(p["ledger"]).stat().st_mode & 0o777) == "0o600"
    listed = tl.incidents(now=T0 + timedelta(hours=1), **recorded(p))["incidents"]
    assert len(listed) == 2
    story = next(r for r in listed if "egress" in r["sources"])
    assert (story["sources"], story["findings"], story["decisions"], story["severity"]) == (
        ["credentials", "egress"], 2, 1, "HIGH")
    assert story["entities"]["address"] == ["203.0.113.9"] and story["entities"]["process"] == ["/tmp/x"]
    shown = tl.show(story["incident"][:6], **recorded(p))          # the start of an ID is enough
    assert [(e["kind"], e.get("rule_id")) for e in shown["events"]] == [
        ("finding", "OUTBOUND_FROM_TEMPORARY"), ("decision", "OUTBOUND_FROM_TEMPORARY"),
        ("finding", "CREDENTIAL_READ")]
    text = tl.text(shown)
    assert "decided by playbook" in text and "credentials: CREDENTIAL_READ" in text
    assert "seen by: credentials, egress" in text
    assert tl.incidents(now=T0 + timedelta(days=30), **recorded(p))["incidents"] == [], "--hours bounds the list"


def test_merged_incidents_tell_one_story(p):
    run(p, [signal("a", "egress", "OUTBOUND_FROM_TEMPORARY", "HIGH", "a", address=["198.51.100.4"])], 0)
    run(p, [signal("b", "webroot", "WEB_SHELL_PATTERN", "HIGH", "b", file=["/var/www/up/b.php"])], 1)
    first = {e["incident"] for e in tl.events(**recorded(p)) if e["kind"] == "finding"}
    assert len(first) == 2
    # One finding names both: the engine merges the incidents, and the timeline follows.
    run(p, [signal("c", "egress", "OUTBOUND_FROM_TEMPORARY", "HIGH", "c", address=["198.51.100.4"],
                   file=["/var/www/up/b.php"])], 2)
    listed = tl.incidents(now=T0 + timedelta(hours=1), **recorded(p))["incidents"]
    assert len(listed) == 1 and listed[0]["findings"] == 3
    for old in first:
        assert len(tl.show(old, **recorded(p))["events"]) == len(tl.events(**recorded(p))), \
            "either old ID opens the merged incident"


def test_enforcement_and_undo_join_their_incident(p):
    class Recording(en.Executor):
        def collect_evidence(self, target, decision):
            return dict(bundle="/var/lib/megalodon/evidence/bundle-1", memory=[])

        def suspend_process(self, target, decision):
            return {}

        def undo_suspend_process(self, record):
            return None
    en.init(p["enforce"], response_policy=p["policy"])
    enable(p, ["collect_evidence", "suspend_process"], ["code-loaded-into-memory"])
    me = SimpleNamespace(pid=os.getpid())
    re_.run(policy_path=p["policy"], ledger=p["ledger"], state_path=p["state"], signals=memory_signal(me),
            protected=set())
    result = en.run(policy_path=p["enforce"], response_policy=p["policy"], ledger=p["ledger"], journal=p["journal"],
                    state_path=p["enforce_state"], protected=set(), executor=Recording())
    suspended = next(r for r in result["applied"] if r["action"] == "suspend_process")
    en.undo(suspended["id"], journal=p["journal"], executor=Recording())
    listed = tl.incidents(**recorded(p))["incidents"]
    assert len(listed) == 1 and listed[0]["actions_applied"] == 2 and listed[0]["undone"] == 1
    assert listed[0]["evidence"] == ["/var/lib/megalodon/evidence/bundle-1"]
    events = tl.show(listed[0]["incident"], **recorded(p))["events"]
    assert [e["kind"] for e in events] == ["finding", "decision", "action", "action", "action", "undo"]
    actions = [e for e in events if e["kind"] == "action"]
    assert sum(e["status"] == "pending" for e in actions) == 1
    assert sum(e["status"] == "applied" for e in actions) == 2


def test_older_records_without_observations_or_incident_ids(tmp_path):
    ledger, journal = tmp_path / "ledger.jsonl", tmp_path / "enforced.jsonl"
    decision = dict(decided_at="2026-11-19T12:00:00Z", playbook="reverse-shell", incident=dict(id="abc123def456"),
                    signal=dict(key="k", source="process_review", rule_id="SHELL_HOLDS_SOCKET", severity="HIGH",
                                summary="a shell holds a socket", entities=dict(process=["/bin/sh"])),
                    actions=[dict(action="notify", target=None, status="would_apply")])
    action = dict(id="e1", at="2026-11-19T12:01:00Z", action="notify", target=None, status="applied",
                  playbook="reverse-shell", rule_id="SHELL_HOLDS_SOCKET", decided_at="2026-11-19T12:00:00Z")
    undone = dict(id="u1", at="2026-11-19T12:02:00Z", action="notify", target=None, status="undone", undo_of="e1")
    for path, records in ((ledger, [decision]), (journal, [action, undone])):
        path.write_text("".join(json.dumps(r) + "\n" for r in records))
        os.chmod(path, 0o600)
    events = tl.events(ledger=ledger, journal=journal)
    assert [(e["kind"], e["incident"]) for e in events] == [
        ("finding", "abc123def456"), ("decision", "abc123def456"), ("action", "abc123def456"),
        ("undo", "abc123def456")]
    os.chmod(ledger, 0o644)
    with pytest.raises(re_.ResponseError, match="mode-600"):
        tl.events(ledger=ledger, journal=journal)


def test_an_entity_across_incidents_html_and_the_cli(p, tmp_path, capsys):
    run(p, [signal("a", "egress", "OUTBOUND_FROM_TEMPORARY", "HIGH", "<script>alert(1)</script> first",
                   address=["192.0.2.50"])], 0)
    run(p, [signal("b", "listeners", "NEW_LISTENER", "MEDIUM", "second", address=["192.0.2.50"])], 120)
    shown = tl.show(entity="address:192.0.2.50", **recorded(p))
    assert len(shown["incidents"]) == 2, "two hours apart: two incidents, one address"
    page = tl.page(shown)
    assert "<script" not in page and "&lt;script&gt;" in page and "default-src 'none'" in page
    with pytest.raises(tl.TimelineError, match="KIND:VALUE"):
        tl.show(entity="192.0.2.50", **recorded(p))
    with pytest.raises(tl.TimelineError, match="no incident"):
        tl.show("ffffffffffff", **recorded(p))
    from megalodon.cli import main
    out = tmp_path / "export/timeline.html"
    with pytest.raises(SystemExit) as exit_:
        main(["timeline", "show", "--entity", "address:192.0.2.50", "--format", "html", "--output", str(out),
              "--ledger", str(p["ledger"]), "--journal", str(p["journal"])])
    assert exit_.value.code == 0 and oct(out.stat().st_mode & 0o777) == "0o600"
    with pytest.raises(SystemExit) as exit_:
        main(["timeline", "list", "--format", "json", "--hours", "100000", "--ledger", str(p["ledger"]),
              "--journal", str(p["journal"])])
    assert len(json.loads(capsys.readouterr().out.split("wrote", 1)[-1].split("\n", 1)[-1])["incidents"]) == 2


def legacy_decision(incident, target, at="2026-11-19T12:00:00Z"):
    return dict(decided_at=at, playbook="reverse-shell", incident=dict(id=incident),
                signal=dict(key=f"k-{incident}", source="process_review", rule_id="SHELL_HOLDS_SOCKET",
                            severity="HIGH", summary="a shell holds a socket", entities=dict(process=[target])),
                actions=[dict(action="suspend_process", target=target, status="would_apply")])


def legacy_action(identifier, target, at="2026-11-19T12:01:00Z"):
    return dict(id=identifier, at=at, action="suspend_process", target=target, status="applied",
                playbook="reverse-shell", rule_id="SHELL_HOLDS_SOCKET", decided_at="2026-11-19T12:00:00Z")


def write_log(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    os.chmod(path, 0o600)


def test_older_actions_go_to_their_own_incident_or_to_none(tmp_path):
    ledger, journal = tmp_path / "ledger.jsonl", tmp_path / "enforced.jsonl"
    # One engine pass decided the same rule, under the same playbook, for two incidents.
    write_log(ledger, [legacy_decision("aaaaaaaaaaaa", "10@1:/bin/sh"), legacy_decision("bbbbbbbbbbbb", "20@1:/bin/sh"),
                       legacy_decision("cccccccccccc", "30@1:/bin/sh"), legacy_decision("dddddddddddd", "30@1:/bin/sh")])
    write_log(journal, [legacy_action("e1", "10@1:/bin/sh"), legacy_action("e2", "20@1:/bin/sh"),
                        legacy_action("e3", "30@1:/bin/sh")])
    actions = {e["id"]: e["incident"] for e in tl.events(ledger=ledger, journal=journal) if e["kind"] == "action"}
    assert actions == {"e1": "aaaaaaaaaaaa", "e2": "bbbbbbbbbbbb", "e3": None}, \
        "each action goes with the decision on its target; one two incidents share goes with neither"


def test_a_large_journal_is_read_to_its_end(tmp_path):
    ledger, journal = tmp_path / "ledger.jsonl", tmp_path / "enforced.jsonl"
    write_log(ledger, [legacy_decision("aaaaaaaaaaaa", "10@1:/bin/sh")])
    filler = json.dumps(dict(id="x", at="2026-11-19T11:00:00Z", action="notify", status="refused",
                             reason="r" * 400)) + "\n"
    with open(journal, "w") as stream:
        stream.write(filler * (20 * 1024 * 1024 // len(filler)))     # past the 17 MiB a single read took
        stream.write(json.dumps(legacy_action("last", "10@1:/bin/sh")) + "\n")
    os.chmod(journal, 0o600)
    assert any(e.get("id") == "last" and e["incident"] == "aaaaaaaaaaaa"
               for e in tl.events(ledger=ledger, journal=journal))
