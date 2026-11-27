"""One campaign spread over several addresses of one network: an attacker rotating through a cloud range or a
provider's block stays below the thresholds at each address, and is judged as one campaign by its network."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from megalodon import campaign
from megalodon import response_engine as re_

NOW = datetime(2026, 11, 27, 20, 0, tzinfo=timezone.utc)
NET = "203.0.113"
HOSTS = [f"192.168.1.{n}" for n in range(10, 40)]
KINDS = ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP")


def at(seconds):
    return (NOW + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def attempt(n, rule, host, seconds, address):
    return re_.Signal(f"network:{n}", "network", rule, "MEDIUM", at(seconds), rule,
                      re_._entities(address=[address], peer=[address, host]))


def rotating(addresses, count=9, every=8, start=0):
    """`count` different attempts, of three kinds against different hosts, each from the next of `addresses`."""
    return [attempt(start + n, KINDS[n % 3], HOSTS[n % len(HOSTS)], start + n * every, addresses[n % len(addresses)])
            for n in range(count)]


def observe(signals, state=None, now=NOW + timedelta(minutes=5), exclude=frozenset(), **settings):
    return campaign.observe({} if state is None else state, signals, now, campaign.Settings(**settings),
                            re_._campaign_signal, exclude=exclude)


def test_an_attacker_rotating_through_a_network_is_one_campaign_naming_the_addresses_that_took_part():
    addresses = [f"{NET}.{n}" for n in (11, 12, 13, 14)]
    [raised] = observe(rotating(addresses))
    assert raised.summary.startswith(f"{NET}.0/24: 4 addresses, 9 different attacks of 3 kinds in 64 s")
    assert raised.entities["address"] == set(addresses), "the addresses that attacked, never the network"
    assert raised.severity == "HIGH" and len(raised.summary) <= 300
    assert raised.summary.endswith("Machine speed: an attack tool or an AI agent, not a person.")


def test_no_address_alone_is_raised_and_one_that_is_still_is():
    addresses = [f"{NET}.{n}" for n in (11, 12, 13, 14)]
    raised = observe(rotating(addresses) + rotating([f"{NET}.99"], count=8, start=100))
    assert sorted(s.summary.split(":")[0] for s in raised) == [f"{NET}.0/24", f"{NET}.99"]
    [network] = [s for s in raised if s.summary.startswith(f"{NET}.0/24")]
    assert network.entities["address"] == set(addresses) | {f"{NET}.99"}


def test_the_same_attempt_from_many_addresses_is_one_attempt():
    many = [attempt(n, "PORT_SCAN", HOSTS[0], n * 5, f"{NET}.{n + 10}") for n in range(20)]
    assert observe(many) == [], "one rule against one target, however many addresses made it"


@pytest.mark.parametrize("addresses,raised", [((11, 12), False), ((11, 12, 13), True)])
def test_a_network_needs_min_addresses_of_its_addresses(addresses, raised):
    assert bool(observe(rotating([f"{NET}.{n}" for n in addresses]))) is raised
    assert observe(rotating([f"{NET}.{n}" for n in (11, 12)]), min_addresses=2)


def test_addresses_of_different_networks_are_not_joined():
    assert observe(rotating(["203.0.113.11", "198.51.100.12", "192.0.2.13"])) == []


def test_ipv6_addresses_are_judged_by_their_64():
    addresses = ["2001:db8:0:1::a", "2001:db8:0:1::b", "2001:db8:0:1:ffff::c"]
    [raised] = observe(rotating(addresses))
    assert raised.summary.startswith("2001:db8:0:1::/64: 3 addresses,")
    assert observe(rotating(["2001:db8:0:1::a", "2001:db8:0:2::b", "2001:db8:0:3::c"])) == []


def test_the_network_size_is_a_setting():
    addresses = ["203.0.113.11", "203.0.113.140", "203.0.112.13"]
    assert observe(rotating(addresses)) == []
    [raised] = observe(rotating(addresses), network_prefix_v4=16)
    assert raised.summary.startswith("203.0.0.0/16: 3 addresses,")


def test_networks_false_judges_each_address_alone():
    assert observe(rotating([f"{NET}.{n}" for n in (11, 12, 13, 14)]), networks=False) == []


def test_excluded_and_ignored_addresses_are_never_counted_toward_a_network():
    addresses = [f"{NET}.{n}" for n in (11, 12, 13)]
    assert observe(rotating(addresses), exclude=frozenset({f"{NET}.13"})) == []
    assert observe(rotating(addresses), ignore_addresses=(f"{NET}.13/32",)) == []


def test_a_network_is_raised_again_only_when_it_says_more():
    state = {}
    addresses = [f"{NET}.{n}" for n in (11, 12, 13)]
    [first] = observe(rotating(addresses), state)
    assert observe(rotating(addresses, start=200), state, now=NOW + timedelta(minutes=10)) == []
    lure = re_.Signal("auth:LURE_FOLLOWED:x", "auth", "LURE_FOLLOWED", "CRITICAL", at(300), "lure",
                      re_._entities(address=[f"{NET}.14"], file=["/srv/decoy/OPERATIONS-NOTE.txt"]))
    [again] = observe([lure], state, now=NOW + timedelta(minutes=11))
    assert (first.severity, again.severity) == ("HIGH", "CRITICAL")
    assert again.summary.endswith("It followed an agent lure: an AI agent is driving it.")
    assert f"{NET}.14" in again.entities["address"]


def test_networks_followed_are_bounded(monkeypatch):
    monkeypatch.setattr(campaign, "MAX_NETWORKS", 3)
    state = {}
    signals = [attempt(n, "PORT_SCAN", HOSTS[0], n, f"198.51.{n}.1") for n in range(6)]
    observe(signals, state)
    assert sorted(state["campaign_networks"]) == ["198.51.3.0/24", "198.51.4.0/24", "198.51.5.0/24"]


@pytest.mark.parametrize("table,message", [
    (dict(networks="yes"), "networks must be true or false"),
    (dict(min_addresses=1), "min_addresses must be an integer from 2 to 64"),
    (dict(network_prefix_v4=33), "network_prefix_v4 must be an integer from 8 to 32"),
    (dict(network_prefix_v6=8), "network_prefix_v6 must be an integer from 16 to 128"),
])
def test_bad_network_settings_are_refused(table, message):
    with pytest.raises(re_.ResponseError, match=message):
        re_._campaign(table)


def test_the_policy_settings_are_read():
    settings = re_._campaign(dict(networks=False, min_addresses=4, network_prefix_v4=20, network_prefix_v6=48))
    assert (settings.networks, settings.min_addresses, settings.network_prefix_v4, settings.network_prefix_v6) == (
        False, 4, 20, 48)
    written = re_._campaign({})
    assert (written.networks, written.min_addresses, written.network_prefix_v4, written.network_prefix_v6) == (
        True, 3, 24, 64)


def test_the_engine_blocks_each_address_that_took_part_never_one_it_must_not(tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    addresses = [f"{NET}.{n}" for n in (11, 12, 13, 14, 15)]
    re_.run(signals=rotating(addresses, count=15), now=NOW + timedelta(minutes=5), policy_path=policy,
            ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json", protected={f"{NET}.15"})
    decided = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    [network] = [d for d in decided if d["signal"]["rule_id"] == campaign.RULE_ID]
    assert network["playbook"] == "automated-campaign"
    blocks = {a["target"]: a["status"] for a in network["actions"] if a["action"] == "block_address"}
    # Documentation addresses are not public, so the guard refuses each; what matters here is which are named.
    assert set(blocks) == set(addresses[:4]), (
        "each address that attacked; never the network, nor an address this machine must reach")


def test_every_address_that_made_an_attempt_is_remembered_across_passes():
    state = {}
    a, b, c = (f"{NET}.{n}" for n in (11, 12, 13))

    def four(address, start, key):
        return [attempt(key + n, KINDS[n % 3], HOSTS[n], start + n * 5, address) for n in range(4)]
    # b makes four attempts, a repeats them, b repeats them again and makes three more: seven different, two
    # addresses, no campaign yet. What is kept between passes must still know a made some of them.
    signals = (four(b, 0, 0) + four(a, 20, 10) + four(b, 40, 20)
               + [attempt(30 + n, KINDS[n % 3], HOSTS[4 + n], 60 + n * 5, b) for n in range(3)])
    assert observe(signals, state) == [], "two addresses: not yet a network's campaign"
    [raised] = observe([attempt(40, KINDS[2], HOSTS[20], 80, c)], state, now=NOW + timedelta(minutes=6))
    assert raised.entities["address"] == {a, b, c}, "a, whose attempts b made before and after it, counts"


def test_one_attack_repeated_from_many_addresses_never_crowds_out_different_ones():
    state = {}
    seven = [attempt(n, KINDS[n % 3], HOSTS[n], n * 2, f"{NET}.{n + 1}") for n in range(7)]
    same = [attempt(100 + n, "PORT_SCAN", HOSTS[0], 20 + n % 200, f"{NET}.{n + 1}") for n in range(254)]
    assert observe(seven + same, state) == []
    kept = state["campaign_networks"][f"{NET}.0/24"]["attempts"]
    assert len({(a[1], a[3]) for a in kept}) == 7 and len(kept) <= campaign.MAX_ATTEMPTS
    [raised] = observe([attempt(999, KINDS[2], HOSTS[25], 250, f"{NET}.9")], state,
                       now=NOW + timedelta(minutes=6))
    assert "8 different attacks" in raised.summary


def test_an_address_ignored_or_protected_since_is_no_longer_counted_nor_named():
    a, b, c, d = (f"{NET}.{n}" for n in (11, 12, 13, 14))
    # b and d make seven different attacks; a repeats one of them.
    first = [attempt(n, KINDS[n % 3], HOSTS[n], n * 5, (b, d)[n % 2]) for n in range(7)] + [
        attempt(20, KINDS[0], HOSTS[0], 40, a)]
    for later in (dict(ignore_addresses=(f"{a}/32",)), dict(exclude=frozenset({a}))):
        state = {}
        observe(first, state)
        [raised] = observe([attempt(50, KINDS[1], HOSTS[20], 60, c)], state, now=NOW + timedelta(minutes=6), **later)
        assert a not in raised.entities["address"] and raised.entities["address"] == {b, c, d}
        assert a not in {x[4] for x in state["campaign_networks"][f"{NET}.0/24"]["attempts"]}
