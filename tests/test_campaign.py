"""Automated attack campaigns: one address trying many different attacks at machine speed, across sensors."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from megalodon import campaign
from megalodon import response_engine as re_

NOW = datetime(2026, 11, 18, 22, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.114.9"
HOSTS = [f"192.168.1.{n}" for n in range(10, 30)]


@pytest.fixture
def paths(tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    return dict(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
                protected=set())


def at(seconds):
    return (NOW + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def attempt(n, rule, host, seconds, address=ATTACKER, severity="MEDIUM"):
    """One network finding from `address` against `host`, as the audit store hands it over."""
    return re_.Signal(f"network:{n}", "network", rule, severity, at(seconds), rule,
                      re_._entities(address=[address], peer=[address, host]))


def login(n, seconds, user="admin", address=ATTACKER):
    """A login from the attacker's address, as the login watch reports one: it got in."""
    return re_.login_signals(dict(findings=[dict(rule_id="LOGIN_NEW_SOURCE", severity="HIGH", user=user,
                                                 src_ip=address, when=at(seconds), detail=f"{n}")]))[0]


def sweep(count=8, kinds=("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP"), every=6, start=0, address=ATTACKER):
    """`count` different attempts, cycling through `kinds` and hosts, one every `every` seconds."""
    return [attempt(start + n, kinds[n % len(kinds)], HOSTS[n % len(HOSTS)], start + n * every, address)
            for n in range(count)]


def run(paths, signals, now=NOW + timedelta(minutes=5)):
    return re_.run(signals=signals, now=now, **paths)


def lines(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def campaigns(paths):
    return [d for d in lines(paths["ledger"]) if d["signal"]["rule_id"] == campaign.RULE_ID]


def actions(decision):
    return [(a["action"], a["target"], a["status"]) for a in decision["actions"]]


def test_many_kinds_of_attack_within_minutes_are_a_campaign_against_its_address(paths):
    run(paths, sweep())
    [decision] = campaigns(paths)
    assert decision["playbook"] == "automated-campaign" and decision["signal"]["severity"] == "HIGH"
    assert actions(decision) == [("collect_evidence", None, "would_apply"), ("block_address", ATTACKER, "would_apply"),
                                 ("notify", None, "would_apply")]
    summary = decision["signal"]["summary"]
    assert summary.startswith(f"{ATTACKER}: 8 different attacks of 3 kinds in 42 s") and "seen by network" in summary
    assert "BRUTE_FORCE, HOST_SWEEP, PORT_SCAN." in summary and "AI agent" in summary
    # It joins the incident of the findings it was made from, through the attacker's address.
    observed = [o for o in lines(re_.observations_path(paths["ledger"])) if o["kind"] == "finding"]
    assert len({o["incident"] for o in observed}) == 1 and len(observed) == 9
    assert decision["incident"]["sources"] == ["campaign", "network"]


@pytest.mark.parametrize("signals", [
    sweep(count=7),                                                   # too few attempts
    sweep(kinds=("PORT_SCAN", "BRUTE_FORCE")),                        # too few kinds
    sweep(every=120),                                                 # 8 attempts over 14 minutes: a person's pace
    [attempt(n, ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP")[n % 3], HOSTS[n % 3], n) for n in range(12)],  # 3 repeated
    sweep(address="127.0.0.1"),                                       # this machine, not an attacker
], ids=["few", "narrow", "slow", "repeats", "loopback"])
def test_what_is_not_a_campaign(paths, signals):
    run(paths, signals)
    assert campaigns(paths) == []


def test_this_machine_is_never_the_attacker_when_both_ends_are_named(paths):
    me = "192.168.1.5"
    kinds = ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP", "DECOY_TOUCH", "SYN_FLOOD", "IOC_MATCH", "BEACONING",
             "DGA_DOMAIN")
    piped = [json.dumps(dict(rule_id=kind, severity="MEDIUM", src_ip=ATTACKER, dst_ip=me, detected_at=at(n),
                             message=f"attempt {n}")) for n, kind in enumerate(kinds)]
    re_.ingest(piped, now=NOW + timedelta(minutes=1), **dict(paths, protected={me}))
    assert [d["signal"]["entities"]["address"] for d in campaigns(paths)] == [[ATTACKER]]


def test_it_counts_across_passes_by_when_attempts_happened_not_when_they_were_read(paths):
    attempts = sweep()
    run(paths, attempts[:4], now=NOW + timedelta(minutes=1))
    assert campaigns(paths) == []
    run(paths, attempts[4:], now=NOW + timedelta(hours=2))          # read late, but they happened within a minute
    assert len(campaigns(paths)) == 1


def test_a_campaign_in_a_late_backlog_is_found_though_later_findings_came_with_it(paths):
    run(paths, sweep() + [attempt(99, "PORT_SCAN", HOSTS[19], 3600)], now=NOW + timedelta(hours=2))
    [decision] = campaigns(paths)
    assert "8 different attacks of 3 kinds in 42 s" in decision["signal"]["summary"]
    assert decision["signal"]["observed_at"] == at(42), "the campaign is placed where it happened"


def test_a_raise_after_a_short_cooldown_is_a_finding_of_its_own(paths):
    text = paths["policy_path"].read_text()
    paths["policy_path"].write_text(text.replace("cooldown_minutes = 30", "cooldown_minutes = 1"))
    run(paths, sweep(), now=NOW + timedelta(minutes=1))
    run(paths, [attempt(50, "PORT_SCAN", HOSTS[15], 160)], now=NOW + timedelta(minutes=3))
    assert len(campaigns(paths)) == 2, "the same window start and severity, but a new raise"


def test_repeats_never_push_out_the_different_attempts_kept(paths):
    # The same attempt again and again, once a second after the others: more of it than the attempts kept.
    repeats = [attempt(1000 + n, "PORT_SCAN", HOSTS[0], 40 + n) for n in range(campaign.MAX_ATTEMPTS + 100)]
    run(paths, sweep(count=7) + repeats, now=NOW + timedelta(minutes=7))
    assert campaigns(paths) == []
    run(paths, [attempt(60, "PORT_SCAN", HOSTS[18], 400)], now=NOW + timedelta(minutes=8))
    [decision] = campaigns(paths)
    assert "8 different attacks of 3 kinds" in decision["signal"]["summary"], "repeats are one attempt"


def test_of_several_campaigns_in_one_backlog_the_worst_then_the_latest_is_raised(paths):
    kinds = ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP", "DECOY_TOUCH", "SYN_FLOOD")
    early_critical = sweep(count=10, kinds=kinds)
    later_high = sweep(start=3000)
    run(paths, early_critical + later_high, now=NOW + timedelta(hours=2))
    [decision] = campaigns(paths)
    assert decision["signal"]["severity"] == "CRITICAL" and decision["signal"]["observed_at"] == at(54)
    paths = dict(paths, state_path=Path(paths["state_path"]).with_name("other-state.json"),
                 ledger=Path(paths["ledger"]).with_name("other-ledger.jsonl"))
    run(paths, sweep() + sweep(start=3000), now=NOW + timedelta(hours=2))
    [decision] = campaigns(paths)
    assert decision["signal"]["observed_at"] == at(3042), "of two equal campaigns, the latest"


def test_a_late_earlier_finding_does_not_raise_again_a_campaign_already_raised(paths):
    run(paths, sweep(start=3000), now=NOW + timedelta(hours=1))
    assert len(campaigns(paths)) == 1
    # Read after the cooldown, from long before that campaign's window: it is in no campaign of its own.
    run(paths, [attempt(90, "PORT_SCAN", HOSTS[12], 1000)], now=NOW + timedelta(hours=2))
    assert len(campaigns(paths)) == 1


def test_the_summary_counts_an_attempt_repeated_within_the_window_once(paths):
    again = [attempt(500 + n, "PORT_SCAN", HOSTS[0], 1 + n) for n in range(5)]
    run(paths, sweep() + again)
    [decision] = campaigns(paths)
    assert decision["signal"]["summary"].startswith(f"{ATTACKER}: 8 different attacks of 3 kinds")


def test_two_sensors_or_many_kinds_make_it_critical(paths):
    run(paths, sweep(count=6) + [login(1, 40), login(2, 41, user="root")])
    [decision] = campaigns(paths)
    assert decision["signal"]["severity"] == "CRITICAL" and "seen by logins, network" in decision["signal"]["summary"]
    assert decision["incident"]["corroborated"] is True, "the network and the login records are independent"


def test_broad_kinds_make_it_critical(paths):
    kinds = ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP", "DECOY_TOUCH", "SYN_FLOOD")
    run(paths, sweep(count=10, kinds=kinds, every=2))
    [decision] = campaigns(paths)
    assert decision["signal"]["severity"] == "CRITICAL" and "of 5 kinds" in decision["signal"]["summary"]
    assert "next kind after 2 s (median)" in decision["signal"]["summary"]


def test_raised_once_per_cooldown_unless_it_becomes_critical(paths):
    run(paths, sweep(), now=NOW + timedelta(minutes=2))
    run(paths, sweep(count=9, start=100)[8:], now=NOW + timedelta(minutes=3))     # more of the same: not again
    run(paths, sweep(start=700), now=NOW + timedelta(minutes=13))  # a new window of attempts, within the cooldown
    assert [d["signal"]["severity"] for d in campaigns(paths)] == ["HIGH"]
    run(paths, [login(1, 760)], now=NOW + timedelta(minutes=14))                # now two sensors: raised again
    assert [d["signal"]["severity"] for d in campaigns(paths)] == ["HIGH", "CRITICAL"]
    run(paths, sweep(count=8, start=3000), now=NOW + timedelta(minutes=50))     # after the cooldown, a new one
    assert [d["signal"]["severity"] for d in campaigns(paths)] == ["HIGH", "CRITICAL", "HIGH"]


def test_a_campaign_is_not_a_second_independent_source(paths):
    run(paths, sweep())
    run(paths, [attempt(99, "BEACONING", HOSTS[0], 60, severity="HIGH")])
    [beacon] = [d for d in lines(paths["ledger"]) if d["signal"]["rule_id"] == "BEACONING"]
    assert beacon["incident"]["corroborated"] is False
    assert ("block_address", ATTACKER, "refused") in actions(beacon), "made from network findings only"


def test_it_can_be_tuned_or_turned_off(paths):
    text = paths["policy_path"].read_text()
    paths["policy_path"].write_text(text.replace("min_attempts = 8", "min_attempts = 12"))
    run(paths, sweep(count=11))
    assert campaigns(paths) == []
    paths["policy_path"].write_text(text.replace("enabled = true\nwindow_seconds", "enabled = false\nwindow_seconds"))
    run(paths, sweep(count=20, start=50))
    assert campaigns(paths) == []


@pytest.mark.parametrize("old,new,message", [
    ("min_attempts = 8", "min_attempts = 1", "min_attempts must be an integer from 2"),
    ("min_attempts = 8", "min_attempts = true", "min_attempts must be an integer"),
    ("min_attempts = 8", "min_attempts = 257", "min_attempts must be an integer from 2 to 256"),  # more than kept
    ("broad_kinds = 5", "broad_kinds = 2", "broad_kinds must be at least min_kinds"),
    ("enabled = true\nwindow", 'enabled = "yes"\nwindow', "enabled must be true or false"),
    ("cooldown_minutes = 30", "cooldown_minutes = 30\nthreshold = 3", "unsupported settings: threshold"),
])
def test_bad_campaign_settings_are_refused(paths, old, new, message):
    text = paths["policy_path"].read_text()
    assert old in text
    paths["policy_path"].write_text(text.replace(old, new))
    with pytest.raises(re_.ResponseError, match=message):
        re_.load_policy(paths["policy_path"])


def test_a_policy_without_the_table_uses_the_defaults(paths):
    text = paths["policy_path"].read_text()
    start, end = text.index("[response.campaign]"), text.index("[[response.playbook]]")
    paths["policy_path"].write_text(text[:start] + text[end:])
    assert re_.load_policy(paths["policy_path"]).campaign == campaign.Settings()


def test_what_it_keeps_is_bounded(monkeypatch):
    monkeypatch.setattr(campaign, "MAX_ADDRESSES", 3)
    state = {}
    for n in range(5):
        address = f"203.0.114.{n + 20}"
        campaign.observe(state, [attempt(n, "PORT_SCAN", HOSTS[0], n, address=address)], NOW, campaign.Settings(),
                         re_._campaign_signal)
    assert sorted(state["campaigns"]) == ["203.0.114.22", "203.0.114.23", "203.0.114.24"]
    campaign.observe(state, [attempt(9, "PORT_SCAN", HOSTS[0], 25 * 3600, address="203.0.114.99")],
                     NOW + timedelta(hours=25), campaign.Settings(), re_._campaign_signal)
    assert sorted(state["campaigns"]) == ["203.0.114.99"], "a day later, the old addresses are forgotten"


def test_the_summary_fits_what_the_ledger_keeps():
    kinds = tuple(f"RULE_{n:02d}_WITH_A_LONG_NAME" for n in range(12))
    signals = [attempt(n, kinds[n], HOSTS[n], n) for n in range(12)]
    [raised] = campaign.observe({}, signals, NOW, campaign.Settings(), re_._campaign_signal)
    assert len(raised.summary) <= 300 and raised.summary.count("RULE_") >= 3 and ", ..." in raised.summary
    widest = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
    [raised] = campaign.observe({}, [attempt(n, kinds[n], HOSTS[n], n, address=widest) for n in range(12)], NOW,
                                campaign.Settings(), re_._campaign_signal)
    assert len(raised.summary) <= 300
