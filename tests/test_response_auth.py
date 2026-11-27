"""Failed logins from the auth log as a response-engine source, and the owner's own scanners ignored by campaigns.

Findings are built from neutral placeholders; no log text is generated here (auth-review's own tests cover reading).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from megalodon import auth_review
from megalodon import campaign
from megalodon import response_engine as re_

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.70"


def at(seconds):
    return (NOW + timedelta(seconds=seconds)).isoformat()


def finding(rule, seconds, subject=ATTACKER, **evidence):
    return dict(rule_id=rule, severity=auth_review.SEVERITY[rule], observed_at=at(seconds), subject=subject,
                message=f"placeholder {rule}", evidence=evidence)


@pytest.fixture
def paths(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("placeholder\n")
    monkeypatch.setattr(re_, "AUTH_LOGS", (str(log),))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text()
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    for name in ("audit_db", "ancestry_allow_file", "credential_allow_file"):
        text = "\n".join(f'{name} = ""' if line.startswith(f"{name} = ") else line for line in text.splitlines())
    policy.write_text(text + "\n")
    return dict(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
                protected=set(), log=log)


def reviewed(monkeypatch, findings):
    """auth-review over a log, as the engine sees it: each finding handed over as it is made."""
    def review(lines, *, on_finding=None, **_):
        for f in findings:
            on_finding(f)
        return dict(findings=list(findings)[:auth_review.MAX_FINDINGS]), None
    monkeypatch.setattr(auth_review, "review", review)


def run(paths, now=NOW + timedelta(minutes=5)):
    return re_.run(now=now, **{k: v for k, v in paths.items() if k != "log"})


def ledger(paths):
    path = Path(paths["ledger"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_the_attacker_address_and_real_accounts_are_linked_never_the_usernames_tried():
    signals, cursor = re_.auth_signals(dict(findings=[
        finding("AUTH_FAILURE_BURST", 0, source=ATTACKER, usernames_tried=["root", "admin"]),
        finding("PASSWORD_SPRAY", 1, source=ATTACKER, usernames_tried=["root", "oracle"]),
        finding("AUTH_SUCCESS_AFTER_FAILURES", 2, subject=ATTACKER, source=ATTACKER, user="alice"),
        finding("SUDO_DENIED", 3, subject="bob", user="bob"),
        finding("ACCOUNT_CREATED", 4, subject="carol", user="carol", uid=1003)]))
    linked = {s.rule_id: {k: sorted(v) for k, v in s.entities.items() if v} for s in signals}
    assert linked == {"AUTH_FAILURE_BURST": {"address": [ATTACKER]}, "PASSWORD_SPRAY": {"address": [ATTACKER]},
                      "AUTH_SUCCESS_AFTER_FAILURES": {"address": [ATTACKER], "account": ["alice"]},
                      "SUDO_DENIED": {"account": ["bob"]}, "ACCOUNT_CREATED": {"account": ["carol"]}}
    assert all(s.source == "auth" and s.observed_at.endswith("Z") for s in signals)
    assert cursor["at"] == "2026-11-27T12:00:04Z"


def test_the_log_read_again_yields_only_what_is_new():
    first = [finding("AUTH_FAILURE_BURST", 0, source=ATTACKER), finding("PASSWORD_SPRAY", 5, source=ATTACKER)]
    signals, cursor = re_.auth_signals(dict(findings=first))
    assert len(signals) == 2
    assert re_.auth_signals(dict(findings=first), cursor)[0] == [], "read again: nothing new"
    same_second = finding("AUTH_FAILURE_BURST", 5, subject="198.51.100.9", source="198.51.100.9")
    later = finding("AUTH_FAILURE_BURST", 60, subject="198.51.100.10", source="198.51.100.10")
    signals, cursor = re_.auth_signals(dict(findings=first + [same_second, later]), cursor)
    assert [s.entities["address"] for s in signals] == [{"198.51.100.9"}, {"198.51.100.10"}]
    assert re_.auth_signals(dict(findings=first + [same_second, later]), cursor)[0] == []


def test_failed_logins_are_decided_once_and_a_guessed_login_too(paths, monkeypatch):
    reviewed(monkeypatch, [finding("AUTH_FAILURE_BURST", 0, source=ATTACKER),
                           finding("AUTH_SUCCESS_AFTER_FAILURES", 30, source=ATTACKER, user="alice")])
    run(paths)
    decided = {d["signal"]["rule_id"]: (d["playbook"], [(a["action"], a["target"]) for a in d["actions"]])
               for d in ledger(paths)}
    assert decided == {
        "AUTH_FAILURE_BURST": ("attacker-at-the-door", [("block_address", ATTACKER), ("notify", None)]),
        "AUTH_SUCCESS_AFTER_FAILURES": ("guessed-login", [("collect_evidence", None), ("block_address", ATTACKER),
                                                          ("notify", None)])}
    run(paths, now=NOW + timedelta(days=3))                       # long after the engine's daily dedupe forgets
    assert len(ledger(paths)) == 2, "the log's old findings are never decided again"
    assert json.loads(Path(paths["state_path"]).read_text())["auth_cursor"]["at"] == "2026-11-27T12:00:30Z"


def test_a_first_pass_looks_back_one_day_only(paths, monkeypatch):
    reviewed(monkeypatch, [finding("AUTH_FAILURE_BURST", -3 * 86400, source="198.51.100.20"),
                           finding("AUTH_FAILURE_BURST", -3600, source=ATTACKER)])
    run(paths)
    assert [d["signal"]["entities"]["address"] for d in ledger(paths)] == [[ATTACKER]]


def test_an_unreadable_auth_log_is_a_gap(paths):
    Path(paths["log"]).unlink()
    assert any(g.startswith("auth: auth log cannot be opened") for g in run(paths)["gaps"])


def test_init_writes_the_auth_log_this_system_keeps(tmp_path, monkeypatch):
    monkeypatch.setattr(re_, "AUTH_LOGS", (str(tmp_path / "none"), str(tmp_path / "secure")))
    (tmp_path / "secure").write_text("")
    re_.write_default_policy(tmp_path / "one.toml")
    assert re_.load_policy(tmp_path / "one.toml").sources["auth_log"] == str(tmp_path / "secure")
    (tmp_path / "secure").unlink()
    re_.write_default_policy(tmp_path / "two.toml")
    assert re_.load_policy(tmp_path / "two.toml").sources["auth_log"] == ""


def test_password_guessing_counts_toward_a_campaign_across_sensors(paths, monkeypatch):
    reviewed(monkeypatch, [finding("AUTH_FAILURE_BURST", 20, source=ATTACKER),
                           finding("PASSWORD_SPRAY", 25, source=ATTACKER)])
    hosts = [f"192.168.1.{n}" for n in range(10, 16)]
    network = [re_.Signal(f"network:{n}", "network", ("PORT_SCAN", "HOST_SWEEP", "BRUTE_FORCE")[n % 3], "MEDIUM",
                          (NOW + timedelta(seconds=n)).strftime("%Y-%m-%dT%H:%M:%SZ"), "placeholder",
                          re_._entities(address=[ATTACKER], peer=[ATTACKER, host])) for n, host in enumerate(hosts)]
    signals, gaps = re_.collect(re_.load_policy(paths["policy_path"]), {}, NOW + timedelta(minutes=5))
    re_.run(signals=network + signals, now=NOW + timedelta(minutes=5),
            **{k: v for k, v in paths.items() if k != "log"})
    [decision] = [d for d in ledger(paths) if d["signal"]["rule_id"] == campaign.RULE_ID]
    assert decision["signal"]["severity"] == "CRITICAL" and "seen by auth, network" in decision["signal"]["summary"]


def test_the_owners_own_scanners_are_never_a_campaign(paths):
    text = Path(paths["policy_path"]).read_text()
    Path(paths["policy_path"]).write_text(text.replace("ignore_addresses = []", 'ignore_addresses = ["203.0.113.64/28"]'))
    policy = re_.load_policy(paths["policy_path"])
    assert policy.campaign.ignore_addresses == ("203.0.113.64/28",)
    sweep = [re_.Signal(f"network:{n}", "network", ("PORT_SCAN", "HOST_SWEEP", "BRUTE_FORCE")[n % 3], "MEDIUM",
                        (NOW + timedelta(seconds=n)).strftime("%Y-%m-%dT%H:%M:%SZ"), "placeholder",
                        re_._entities(address=[ATTACKER], peer=[ATTACKER, f"192.168.1.{n}"])) for n in range(10)]
    assert campaign.observe({}, sweep, NOW, policy.campaign, re_._campaign_signal) == []
    assert len(campaign.observe({}, sweep, NOW, campaign.Settings(), re_._campaign_signal)) == 1
    Path(paths["policy_path"]).write_text(text.replace("ignore_addresses = []", 'ignore_addresses = ["scanner"]'))
    with pytest.raises(re_.ResponseError, match="ignore_addresses contains an invalid address"):
        re_.load_policy(paths["policy_path"])


def real_review(monkeypatch, events):
    """The real reviewer, given login attempts as values (never log text), through the engine's own call."""
    def review(lines, *, source, on_finding=None, **_):
        reviewer = auth_review.AuthReviewer(on_finding=on_finding)
        for kind, *args in events:
            getattr(reviewer, kind)(*args)
        return reviewer.report(source), reviewer
    monkeypatch.setattr(auth_review, "review", review)


def bursts(count, start, prefix="10.9"):
    return [("_failure", start + timedelta(seconds=n), f"{prefix}.{n // 250}.{n % 250 + 1}", "root")
            for n in range(count) for _ in range(6)]


def test_every_finding_is_handed_over_even_past_the_reports_display_cap():
    seen = []
    reviewer = auth_review.AuthReviewer(on_finding=seen.append)
    for kind, *args in bursts(600, NOW):
        getattr(reviewer, kind)(*args)
    assert len(seen) == 600 and len(reviewer.findings) == auth_review.MAX_FINDINGS


def test_findings_past_the_display_cap_still_reach_the_engine(paths, monkeypatch):
    real_review(monkeypatch, bursts(600, NOW - timedelta(hours=2)) + bursts(1, NOW + timedelta(seconds=30), "203.0"))
    policy = re_.load_policy(paths["policy_path"])
    state = {}
    signals, _ = re_.collect(policy, state, NOW + timedelta(minutes=5))
    addresses = {a for s in signals for a in s.entities["address"]}
    assert len(signals) == 601 and "203.0.0.1" in addresses
    assert re_.collect(policy, state, NOW + timedelta(minutes=10))[0] == [], "and none of them again"


def test_more_than_a_pass_takes_is_taken_over_the_next_passes(paths, monkeypatch):
    monkeypatch.setattr(re_, "MAX_AUTH_SIGNALS", 100)
    real_review(monkeypatch, bursts(250, NOW - timedelta(hours=1)))
    policy, state, taken = re_.load_policy(paths["policy_path"]), {}, []
    for minutes in (5, 10, 15, 20):
        signals, _ = re_.collect(policy, state, NOW + timedelta(minutes=minutes))
        taken.append(len(signals))
        seen = {s.key for s in signals}
        assert not seen & set(state.get("_keys", ())), "never twice"
        state["_keys"] = sorted(set(state.get("_keys", ())) | seen)
    assert taken == [100, 100, 50, 0] and len(state["_keys"]) == 250


def test_two_accounts_logged_in_in_one_second_are_two_findings(paths, monkeypatch):
    when = NOW + timedelta(minutes=1)
    failures = [("_failure", when - timedelta(seconds=n), ATTACKER, "root") for n in range(1, 7)]
    real_review(monkeypatch, failures + [("_accepted", when, ATTACKER, "alice", "password"),
                                         ("_accepted", when, ATTACKER, "bob", "password")])
    run(paths, now=when + timedelta(minutes=1))
    guessed = [d for d in ledger(paths) if d["signal"]["rule_id"] == "AUTH_SUCCESS_AFTER_FAILURES"]
    assert sorted(d["signal"]["entities"]["account"] for d in guessed) == [["alice"], ["bob"]]


def test_every_finding_in_the_cursors_second_is_remembered_however_many():
    findings = [finding("AUTH_FAILURE_BURST", 0, subject=f"10.8.{n // 250}.{n % 250 + 1}",
                        source=f"10.8.{n // 250}.{n % 250 + 1}") for n in range(300)]
    signals, cursor = re_.auth_signals(dict(findings=findings))
    assert len(signals) == 300 and len(cursor["keys"]) == 300
    assert re_.auth_signals(dict(findings=findings), cursor)[0] == []
