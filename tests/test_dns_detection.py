"""Opt-in DNS domain-name detection: admission, capture, rules and privacy."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets

import pytest

from megalodon.capture import iter_jsonl
from megalodon.config import Settings, load_settings
from megalodon.managed_capture import capture_commands
from megalodon.models import PacketEvent
from megalodon.offline import tshark
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import (
    ThreatDetectionSettings, ThreatDetector, registrable_domain,
)
from megalodon.validation import ValidationError, parse_dns_name
from megalodon.watchlist import Watchlist, parse_lines, render

T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)
HOST = "192.168.1.10"


def query(name, i=0, src=HOST):
    return PacketEvent(T0 + timedelta(milliseconds=100 * i), src, "192.168.1.1", "DNS",
                       src_port=5353, dst_port=53, dns_query_name=name)


def rules(results):
    return [item.rule_id for item in results]


def detector(**kwargs):
    watch = kwargs.pop("watch", None)
    return ThreatDetector(ThreatDetectionSettings(dns_names=True, **kwargs),
                          watchlist=Watchlist(parse_lines(watch)) if watch else None)


# ------------------------------------------------------------ admission
@pytest.mark.parametrize("raw,expected", [("WWW.Example.COM.", "www.example.com"),
                                          ("_ldap._tcp.dc.example", "_ldap._tcp.dc.example"),
                                          ("xn--bcher-kva.example", "xn--bcher-kva.example")])
def test_names_are_canonicalized(raw, expected):
    assert parse_dns_name(raw) == expected


@pytest.mark.parametrize("raw", ["", ".", "a..b", "-bad.example", "bad-.example", "a b.example",
                                 "x" * 64 + ".example", ("a." * 127) + "com", "bücher.example",
                                 "evil\x00.example", 7])
def test_invalid_names_are_refused(raw):
    with pytest.raises(ValidationError):
        parse_dns_name(raw)


def test_to_dict_is_unchanged_without_a_name_and_round_trips_with_one():
    plain = PacketEvent(T0, HOST, "192.168.1.1", "TCP")
    assert "dns_query_name" not in plain.to_dict()
    named = query("Api.Example.com")
    assert named.to_dict()["dns_query_name"] == "api.example.com"
    assert PacketEvent.from_mapping(named.to_dict()) == named


def test_jsonl_accepts_names_and_refuses_bad_ones(tmp_path):
    good = {"observed_at": T0.isoformat(), "src_ip": HOST, "dst_ip": "192.168.1.1",
            "protocol": "DNS", "dns_query_name": "a.example.com"}
    path = tmp_path / "in.jsonl"
    path.write_text(json.dumps(good) + "\n")
    with path.open("r", encoding="utf-8") as stream:
        assert [e.dns_query_name for e in iter_jsonl(stream)] == ["a.example.com"]
    path.write_text(json.dumps(dict(good, dns_query_name="bad..name")) + "\n")
    with path.open("r", encoding="utf-8") as stream, pytest.raises(Exception):
        list(iter_jsonl(stream))


# --------------------------------------------------------------- capture
def _row(extra=()):
    base = {k: "" for k in tshark.FIELDS}
    base.update({"frame.time_epoch": "1788710400", "ip.src": HOST, "ip.dst": "192.168.1.1",
                 "ip.proto": "17", "udp.srcport": "5353", "udp.dstport": "53", "frame.len": "80"})
    return "\t".join([base[k] for k in tshark.FIELDS] + list(extra))


def test_tshark_reads_names_only_when_opted_in():
    assert "dns.qry.name" not in tshark.FIELDS and tshark.fields(False) == tshark.FIELDS
    assert tshark.fields(True)[-2:] == ("dns.flags.response", "dns.qry.name")
    assert tshark.fixed_argv(7, tshark.Limits()).count("dns.qry.name") == 0
    _, decode = capture_commands("eth0")
    assert "dns.qry.name" not in decode
    _, decode = capture_commands("eth0", dns_names=True)
    assert decode[-2:] == ["-e", "dns.qry.name"]
    event = tshark.parse_fields(_row(("0", "Mail.Example.com")), dns_names=True)
    assert (event.dns_query_name, event.dns_query_length) == ("mail.example.com", 16)
    # Responses echo the client's question; multi-question rows are ambiguous.
    assert tshark.parse_fields(_row(("1", "mail.example.com")), dns_names=True).dns_query_name is None
    assert tshark.parse_fields(_row(("0", "a.example,b.example")), dns_names=True).dns_query_name is None
    assert tshark.parse_fields(_row(("0", "bad..name")), dns_names=True).dns_query_name is None
    with pytest.raises(tshark.OfflineError):
        tshark.parse_fields(_row(("0", "mail.example.com")))  # wrong column count when not opted in


# ----------------------------------------------------------------- rules
def test_everyday_names_cdns_and_reverse_lookups_stay_quiet():
    d = detector()
    names = ["www.google.com", "mail.example.com", "login.microsoftonline.com",
             "a1b2c3d4e5f6a7b8c9d0e1f2.cloudfront.net", "fonts.gstatic.com",
             "5.1.168.192.in-addr.arpa", "printer.local", "update.example.co.uk"]
    for i, name in enumerate(names):
        assert rules(d.analyze(query(name, i))) == [], name


def test_generated_names_raise_dga_once_per_registrable_domain():
    d = detector()
    found = d.analyze(query("x7kq9zr2vbn4lp8wmt3c.com"))
    assert rules(found) == ["DGA_DOMAIN"]
    evidence = found[0].evidence
    assert evidence["signals"] >= 2 and evidence["registrable_domain"] == "x7kq9zr2vbn4lp8wmt3c.com"
    assert evidence["response_target"] == HOST
    assert d.analyze(query("x7kq9zr2vbn4lp8wmt3c.com", 1)) == []


def test_subdomain_churn_detects_a_dns_tunnel():
    d = detector(dns_churn_distinct_subdomains=20, dns_churn_window_seconds=30)
    seen = []
    for i in range(20):
        seen += rules(d.analyze(query(f"chunk{i:04d}.t.exfil-tunnel.example", i)))
    assert "DNS_TUNNEL_CHURN" in seen
    churn = [r for r in d.analyze(query("chunk9999.t.exfil-tunnel.example", 30))]
    assert "DNS_TUNNEL_CHURN" not in rules(churn)  # cooldown
    assert max(len(v) for v in d.churn.values()) <= 20


def test_churn_window_expires_slow_lookups():
    d = detector(dns_churn_distinct_subdomains=5, dns_churn_window_seconds=10)
    for i in range(20):
        event = PacketEvent(T0 + timedelta(seconds=3 * i), HOST, "192.168.1.1", "DNS",
                            dns_query_name=f"h{i}.slow.example")
        assert "DNS_TUNNEL_CHURN" not in rules(d.analyze(event))


def test_domain_watchlist_matches_subdomains_with_cooldown():
    d = detector(watch=["evil.example # known c2", "198.51.100.0/24"])
    found = d.analyze(query("cdn.api.evil.example"))
    assert rules(found) == ["IOC_MATCH"]
    assert found[0].evidence["matched_domain"] == "cdn.api.evil.example"
    assert found[0].evidence["indicator"] == "evil.example"
    assert found[0].evidence["indicator_label"] == "known c2"
    assert d.analyze(query("x.evil.example", 1)) == []
    assert d.analyze(query("notevil.example", 2)) == []


def test_everything_is_off_unless_opted_in():
    d = ThreatDetector(ThreatDetectionSettings(), watchlist=Watchlist(parse_lines(["evil.example"])))
    for i, name in enumerate(["x7kq9zr2vbn4lp8wmt3c.com", "a.evil.example"]
                             + [f"c{j}.tunnel.example" for j in range(40)]):
        assert d.analyze(query(name, i)) == []


def test_rollback_restores_churn_and_cooldowns():
    import copy
    d = detector(dns_churn_distinct_subdomains=3)
    for i in range(2):
        d.analyze(query(f"s{i}.x.example", i))
    before = copy.deepcopy((d.churn, d.last_emitted, list(d.lru)))
    prepared = d.prepare(query("s9.x.example", 5))
    assert "DNS_TUNNEL_CHURN" in rules(prepared.results)
    prepared.rollback()
    assert copy.deepcopy((d.churn, d.last_emitted, list(d.lru))) == before


def test_registrable_domain_approximation():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("x.y.evil.com") == "evil.com"
    assert registrable_domain("evil.com") == "evil.com"


def test_watchlist_domains_render_and_refuse_bare_tlds():
    entries = parse_lines(["evil.example # c2", "203.0.113.5"])
    assert render(entries, "h").splitlines()[1:] == ["evil.example  # c2", "203.0.113.5"]
    with pytest.raises(ValidationError, match="two labels"):
        parse_lines(["com"])


def test_settings_parse_dns_options(tmp_path):
    path = tmp_path / "s.toml"
    path.write_text("[threat_detection]\ndns_names = true\ndns_churn_distinct_subdomains = 12\n")
    threat = load_settings(path).threat
    assert threat.dns_names is True and threat.dns_churn_distinct_subdomains == 12
    path.write_text('[threat_detection]\ndns_names = "yes"\n')
    with pytest.raises(ValidationError):
        load_settings(path)


# --------------------------------------------------------------- privacy
def test_only_flagged_domains_reach_the_database(tmp_path):
    db = tmp_path / "private" / "audit.db"
    settings = Settings(db_path=db, threat=ThreatDetectionSettings(dns_names=True))
    now = datetime.now(timezone.utc) - timedelta(seconds=60)
    routine = [f"routine-site-{secrets.token_hex(4)}.example" for _ in range(5)]
    flagged = "x7kq9zr2vbn4lp8wmt3c.com"
    with Store(db) as store:
        service = MegalodonService(settings, store)
        for i, name in enumerate(routine + [flagged]):
            service.process(PacketEvent(now + timedelta(seconds=i), HOST, "192.168.1.1", "DNS",
                                        dst_port=53, dns_query_name=name))
        events = store.connection.execute("SELECT * FROM events").fetchall()
        assert len(events) == 6
    raw = b"".join(Path(p).read_bytes() for p in db.parent.iterdir() if p.is_file())
    assert flagged.encode() in raw, "a flagged domain is kept in its finding's evidence"
    for name in routine:
        assert name.encode() not in raw, f"routine lookup {name} leaked into storage"
