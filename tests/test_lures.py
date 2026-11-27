"""Agent lures: a note to automated agents naming an account no one has; a login tried as it is LURE_FOLLOWED.

Login attempts are given to the reviewer as values (address, account), never as log text.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import pytest

from megalodon import auth_review
from megalodon import canary
from megalodon import response_engine as re_
from megalodon.validation import ValidationError

ATTACKER = "203.0.113.80"


@pytest.fixture
def planted(tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()
    manifest = tmp_path / "canaries.json"
    result = canary.plant(str(bait), str(manifest), count=1, lure=True)
    return dict(result=result, manifest=manifest, bait=bait)


def test_a_lure_names_an_account_no_one_has_and_is_kept_in_the_manifest(planted):
    [account] = planted["result"]["lure_accounts"]
    lure = planted["bait"] / canary.LURE_NAME
    assert canary.LURE_ACCOUNT.fullmatch(account) and account in lure.read_text()
    assert "automated agents and AI assistants" in lure.read_text()
    assert canary.lures(str(planted["manifest"])) == {account: str(lure)}
    import pwd
    with pytest.raises(KeyError):
        pwd.getpwnam(account)
    assert oct(lure.stat().st_mode & 0o777) == "0o600"


def test_without_lure_none_is_planted(tmp_path):
    (tmp_path / "bait").mkdir()
    result = canary.plant(str(tmp_path / "bait"), str(tmp_path / "m.json"), count=2)
    assert result["lure_accounts"] == [] and canary.lures(str(tmp_path / "m.json")) == {}
    assert not (tmp_path / "bait" / canary.LURE_NAME).exists()


def test_a_manifest_with_a_malformed_lure_account_is_refused(planted):
    data = json.loads(planted["manifest"].read_text())
    data["canaries"][-1]["lure_account"] = "root"
    planted["manifest"].write_text(json.dumps(data))
    os.chmod(planted["manifest"], 0o600)
    with pytest.raises(ValidationError, match="invalid entry"):
        canary.lures(str(planted["manifest"]))


def test_a_read_lure_says_when_it_was_read(planted):
    lure = planted["bait"] / canary.LURE_NAME
    if not planted["result"]["read_detection"]:
        pytest.skip("this filesystem records no reads")
    lure.read_text()
    [finding] = [f for f in canary.check(str(planted["manifest"]))["findings"] if f["path"] == str(lure)]
    read = datetime.fromisoformat(finding["read_at"].replace("Z", "+00:00"))
    assert finding["rule_id"] == "CANARY_READ" and abs(datetime.now(timezone.utc) - read) < timedelta(minutes=5)


def test_any_login_tried_as_a_lure_account_is_reported_and_no_other():
    reviewer = auth_review.AuthReviewer(lure_users=["svc-k3x9qe"])
    when = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
    reviewer._failure(when, ATTACKER, "SVC-K3X9QE")                 # one try is enough, whatever its case
    reviewer._failure(when, "198.51.100.5", "admin")
    reviewer._accepted(when + timedelta(seconds=1), "198.51.100.6", "svc-k3x9qe", "password")
    lured = [f for f in reviewer.findings if f["rule_id"] == "LURE_FOLLOWED"]
    assert [(f["severity"], f["evidence"]["source"], f["evidence"]["outcome"].split(":")[0]) for f in lured] == [
        ("CRITICAL", ATTACKER, "refused"), ("CRITICAL", "198.51.100.6", "accepted")]
    assert auth_review.AuthReviewer()._lure(when, ATTACKER, "svc-k3x9qe", "refused") is None


@pytest.mark.parametrize("gap,expected", [
    (6, "6 s after it was read: an AI agent reading text and acting on it, at machine speed."),
    (600, "10 min after it was read: something read the note and acted on it."),
    (None, ": something read a note written for automated agents and acted on it."),
    (-30, ": something read a note written for automated agents and acted on it."),
])
def test_how_soon_the_lure_was_followed_is_said(gap, expected):
    at = "2026-11-27T12:00:00Z"
    read = None if gap is None else (datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
                                     - timedelta(seconds=gap)).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = re_._lure_summary(ATTACKER, "svc-k3x9qe", dict(path="/srv/decoy/OPERATIONS-NOTE.txt", read_at=read), at)
    assert summary.startswith(f"{ATTACKER} tried svc-k3x9qe, the account OPERATIONS-NOTE.txt names")
    assert summary.endswith(expected) and len(summary) <= 300


def test_a_followed_lure_is_decided_and_joins_the_lure_read_in_one_incident(planted, tmp_path, monkeypatch):
    lure = planted["bait"] / canary.LURE_NAME
    if not planted["result"]["read_detection"]:
        pytest.skip("this filesystem records no reads")
    lure.read_text()
    [account] = planted["result"]["lure_accounts"]
    log = tmp_path / "auth.log"
    log.write_text("placeholder\n")
    monkeypatch.setattr(re_, "AUTH_LOGS", (str(log),))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text().replace('canary_manifest = ""', f'canary_manifest = "{planted["manifest"]}"')
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    for name in ("audit_db", "ancestry_allow_file", "credential_allow_file"):
        text = "\n".join(f'{name} = ""' if line.startswith(f"{name} = ") else line for line in text.splitlines())
    policy.write_text(text + "\n")
    tried = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=5)

    def review(lines, *, source, lure_users=(), on_finding=None, **_):
        reviewer = auth_review.AuthReviewer(lure_users=lure_users, on_finding=on_finding)
        reviewer._failure(tried, ATTACKER, account)                 # the attempt, as a value, not as log text
        return reviewer.report(source), reviewer
    monkeypatch.setattr(auth_review, "review", review)
    ledger = tmp_path / "ledger.jsonl"
    re_.run(policy_path=policy, ledger=ledger, state_path=tmp_path / "state.json", protected=set(),
            now=tried + timedelta(minutes=1))
    decisions = [json.loads(line) for line in ledger.read_text().splitlines()]
    [lured] = [d for d in decisions if d["signal"]["rule_id"] == "LURE_FOLLOWED"]
    assert lured["playbook"] == "lure-followed" and ("block_address", ATTACKER) in [
        (a["action"], a["target"]) for a in lured["actions"]]
    assert "s after it was read: an AI agent reading text and acting on it" in lured["signal"]["summary"]
    observed = [json.loads(line) for line in re_.observations_path(ledger).read_text().splitlines()]
    incidents = {o["signal"]["rule_id"]: o["incident"] for o in observed if o["kind"] == "finding"}
    assert incidents["LURE_FOLLOWED"] == incidents["CANARY_READ"], "the read and the attempt are one story"


# ------------------------------------------------------------------ attribution: an AI agent, with the evidence

from megalodon import campaign as campaigns                            # noqa: E402

START = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


def _attempt(n, rule, seconds, source="network"):
    return re_.Signal(f"{source}:{n}", source, rule, "MEDIUM", (START + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"), rule, re_._entities(address=[ATTACKER], peer=[ATTACKER, f"192.168.1.{n}"]))


def _burst(count=8, start=0):
    return [_attempt(start + n, ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP")[n % 3], start + 5 * n) for n in range(count)]


def _followed(seconds):
    return re_.Signal("auth:LURE_FOLLOWED:x", "auth", "LURE_FOLLOWED", "CRITICAL",
                      (START + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"), "lure",
                      re_._entities(address=[ATTACKER], file=["/srv/decoy/OPERATIONS-NOTE.txt"]))


def test_a_campaign_that_followed_a_lure_is_ai_driven_and_critical():
    [raised] = campaigns.observe({}, _burst(7) + [_followed(40)], START + timedelta(minutes=2), campaigns.Settings(),
                                 re_._campaign_signal)
    assert raised.severity == "CRITICAL" and raised.summary.endswith("It followed an agent lure: an AI agent is driving it.")
    assert len(raised.summary) <= 300 and "LURE_FOLLOWED" in raised.summary
    [plain] = campaigns.observe({}, _burst(8), START + timedelta(minutes=2), campaigns.Settings(), re_._campaign_signal)
    assert plain.severity == "HIGH" and plain.summary.endswith("an attack tool or an AI agent, not a person.")


def test_a_lure_followed_after_a_campaign_was_raised_raises_it_again_as_ai_driven():
    state = {}
    [first] = campaigns.observe(state, _burst(8), START + timedelta(minutes=1), campaigns.Settings(), re_._campaign_signal)
    [again] = campaigns.observe(state, [_followed(50)], START + timedelta(minutes=2), campaigns.Settings(),
                                re_._campaign_signal)
    assert (first.severity, again.severity) == ("HIGH", "CRITICAL") and "AI agent is driving it" in again.summary


def test_the_report_names_an_ai_driven_attack_and_a_followed_lure_plainly(tmp_path, monkeypatch):
    from megalodon import guided_review
    from megalodon import security_report as sr
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home/.config/megalodon").mkdir(parents=True)
    re_.write_default_policy()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    near = [re_.Signal(s.key, s.source, s.rule_id, s.severity,
                       (datetime.fromisoformat(s.observed_at.replace("Z", "+00:00")) - START + now
                        - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"), s.summary, s.entities)
            for s in _burst(7) + [_followed(40)]]
    re_.run(signals=near, now=now, protected=set())
    built = sr.build(now=now, system=False)
    [incident] = built["incidents"]
    assert incident["rules"][:2] == ["AUTOMATED_CAMPAIGN", "LURE_FOLLOWED"] and incident["severity"] == "CRITICAL"
    assert incident["meaning"] == sr.AI_CAMPAIGN_MEANING and built["verdict"] == "act"
    assert sr.AI_CAMPAIGN_MEANING in sr.text(built) and "An AI-driven attack" in sr.page(built)
    [item] = [i for i in guided_review.items(built) if i["heading"].startswith("Incident")]
    assert item["meaning"].startswith(sr.AI_CAMPAIGN_MEANING)
    assert sr._incident_meaning(["LURE_FOLLOWED", "CANARY_READ"]) == sr.LURE_MEANING
    assert sr._incident_meaning(["LURE_FOLLOWED", "LOGIN_NEW_SOURCE"]).endswith(sr.LOGIN_IN_CAMPAIGN)


def test_a_lure_makes_a_campaign_critical_even_from_one_sensor():
    guessing = re_.Signal("auth:AUTH_FAILURE_BURST:x", "auth", "AUTH_FAILURE_BURST", "HIGH",
                          START.strftime("%Y-%m-%dT%H:%M:%SZ"), "burst", re_._entities(address=[ATTACKER]))
    few = campaigns.Settings(min_attempts=2, min_kinds=2)
    [raised] = campaigns.observe({}, [guessing, _followed(10)], START + timedelta(minutes=1), few,
                                 re_._campaign_signal)
    assert raised.severity == "CRITICAL" and "seen by auth;" in raised.summary
