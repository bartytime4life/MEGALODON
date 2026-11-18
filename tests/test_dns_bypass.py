"""Opt-in DNS bypass: lookups that skip this network's resolvers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import sqlite3

import pytest

from megalodon import public_resolvers
from megalodon.config import Settings, load_settings
from megalodon.models import PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import ThreatDetectionSettings, ThreatDetector
from megalodon.validation import ValidationError

T0 = datetime(2026, 11, 18, 19, 0, tzinfo=timezone.utc)
HOST, ROUTER, PIHOLE = "192.168.1.50", "192.168.1.1", "192.168.1.2"
JA3 = "0" * 32


def lookup(at, dst, port=53, protocol="UDP", src=HOST, sni=None):
    extra = dict(tls_ja3=JA3, tls_sni=sni) if sni else {}
    return PacketEvent(T0 + timedelta(seconds=at), src, dst, protocol, src_port=50000 + at, dst_port=port,
                       byte_count=80, **extra)


def detector(**settings):
    return ThreatDetector(ThreatDetectionSettings(dns_bypass=True, **settings))


def rules(found):
    return [item.rule_id for item in found]


# ------------------------------------------------------------- settings and data

def test_settings_parse_and_refuse(tmp_path):
    path = tmp_path / "settings.toml"
    path.write_text('[threat_detection]\ndns_bypass = true\ndns_resolvers = ["192.168.1.2", "2606:4700:4700::1111"]\n',
                    encoding="utf-8")
    threat = load_settings(path).threat
    assert threat.dns_bypass and threat.dns_resolvers == (PIHOLE, "2606:4700:4700::1111")
    assert ThreatDetectionSettings().dns_bypass is False
    for body in ('dns_resolvers = ["nope"]', 'dns_resolvers = ["10.0.0.1", "10.0.0.1"]',
                 'dns_bypass = "yes"', 'dns_resolvers = "10.0.0.1"'):
        path.write_text("[threat_detection]\n" + body + "\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_settings(path)


def test_public_resolver_list_is_well_formed():
    assert public_resolvers.provider_for_address("8.8.4.4") == "Google"
    assert public_resolvers.provider_for_address("45.90.28.17") == "NextDNS"
    assert public_resolvers.provider_for_address("2606:4700:4700::1111") == "Cloudflare"
    assert public_resolvers.provider_for_address("93.184.215.14") is None
    assert public_resolvers.provider_for_name("mozilla.cloudflare-dns.com") == "Cloudflare"
    assert public_resolvers.provider_for_name("DNS.Google.") == "Google"
    for name in ("notcloudflare-dns.com", "www.quad9.net", "google.com", "", None):
        assert public_resolvers.provider_for_name(name) is None, name
    for provider, (addresses, names) in public_resolvers.PROVIDERS.items():
        assert all(ipaddress.ip_network(a).is_global for a in addresses), provider
        assert names and all(n == n.lower() and "." in n for n in names), provider


# ------------------------------------------------------------- default mode

def test_off_by_default():
    quiet = ThreatDetector(ThreatDetectionSettings())
    assert rules(quiet.analyze(lookup(0, "8.8.8.8"))) == []


def test_plain_dns_to_a_public_resolver_is_a_bypass():
    d = detector()
    assert rules(d.analyze(lookup(0, ROUTER))) == [], "the local resolver is fine"
    found = d.analyze(lookup(1, "8.8.8.8"))
    assert rules(found) == ["DNS_BYPASS"] and found[0].severity == "MEDIUM"
    evidence = found[0].evidence
    assert (evidence["method"], evidence["provider"], evidence["resolver"], evidence["service_port"]) == (
        "dns", "Google", "8.8.8.8", 53)
    assert evidence["response_target"] == "8.8.8.8" and evidence["configured_resolvers"] == []
    assert "skipping this network's own resolvers" in found[0].message
    assert rules(d.analyze(lookup(2, "8.8.8.8"))) == [], "one finding per host, resolver and method per cooldown"
    unknown = d.analyze(lookup(3, "203.0.114.53", protocol="TCP"))
    assert rules(unknown) == ["DNS_BYPASS"] and "provider" not in unknown[0].evidence


def test_dns_over_tls_and_quic():
    d = detector()
    dot = d.analyze(lookup(0, "9.9.9.9", port=853, protocol="TCP"))
    doq = d.analyze(lookup(1, "94.140.14.14", port=853, protocol="UDP"))
    assert [f.evidence["method"] for f in dot + doq] == ["dot", "doq"]
    assert [f.evidence["provider"] for f in dot + doq] == ["Quad9", "AdGuard"]


def test_dns_over_https_by_address_and_by_server_name():
    d = detector()
    assert rules(d.analyze(lookup(0, "93.184.215.14", port=443, protocol="TCP"))) == [], "ordinary HTTPS"
    by_address = d.analyze(lookup(1, "1.1.1.1", port=443, protocol="TCP"))
    assert rules(by_address) == ["DNS_BYPASS"] and by_address[0].evidence["method"] == "doh"
    assert rules(d.analyze(lookup(2, "2001:4860:4860::8888", port=443, protocol="UDP"))) == ["DNS_BYPASS"]
    named = lookup(3, "104.16.248.249", port=443, protocol="TCP", sni="mozilla.cloudflare-dns.com")
    assert rules(d.analyze(named)) == [], "server names are not read without tls_fingerprints"
    d = detector(tls_fingerprints=True)
    by_name = d.analyze(named)
    assert rules(by_name) == ["DNS_BYPASS"]
    assert (by_name[0].evidence["server_name"], by_name[0].evidence["provider"]) == (
        "mozilla.cloudflare-dns.com", "Cloudflare")
    assert rules(d.analyze(lookup(4, "104.16.1.1", port=443, protocol="TCP", sni="notcloudflare-dns.com"))) == []


def test_replies_outside_sources_and_non_lookups_stay_quiet():
    d = detector()
    reply = PacketEvent(T0, "8.8.8.8", HOST, "UDP", src_port=53, dst_port=50000, byte_count=120)
    assert rules(d.analyze(reply)) == []
    assert rules(d.analyze(lookup(1, "8.8.8.8", src="203.0.114.9"))) == [], "not an internal host"
    assert rules(d.analyze(lookup(2, "224.0.0.251"))) == []
    assert rules(d.analyze(lookup(3, "8.8.8.8", port=5353))) == []
    assert rules(d.analyze(PacketEvent(T0, HOST, "8.8.8.8", "ICMP", byte_count=64))) == []


# ------------------------------------------------------------- configured resolvers

def test_configured_resolvers_and_forwarders():
    d = detector(dns_resolvers=(PIHOLE, "1.1.1.1"))
    assert rules(d.analyze(lookup(0, PIHOLE))) == []
    assert rules(d.analyze(lookup(1, "1.1.1.1", port=443, protocol="TCP"))) == [], "a listed resolver over DoH"
    rogue = d.analyze(lookup(2, ROUTER))
    assert rules(rogue) == ["DNS_BYPASS"], "an internal resolver that is not listed"
    assert rogue[0].evidence["configured_resolvers"] == ["1.1.1.1", PIHOLE]
    assert "skipping the configured resolvers" in rogue[0].message
    assert rules(d.analyze(lookup(3, "9.9.9.9", src=PIHOLE))) == [], "a listed resolver forwarding upstream"


def test_allowlist_rollback_and_service_storage(tmp_path):
    allowed = ThreatDetector(ThreatDetectionSettings(dns_bypass=True),
                             allowlist=(ipaddress.ip_network("8.8.8.8/32"),))
    assert allowed.analyze(lookup(0, "8.8.8.8"))[0].suppressed_reason == "target_allowlisted"
    d = detector()
    prepared = d.prepare(lookup(0, "8.8.8.8"))
    assert rules(prepared.results) == ["DNS_BYPASS"]
    prepared.rollback()
    assert rules(d.analyze(lookup(1, "8.8.8.8"))) == ["DNS_BYPASS"], "rollback restores the cooldown"
    settings = Settings(db_path=tmp_path / "audit.db", threat=ThreatDetectionSettings(dns_bypass=True))
    now = datetime.now(timezone.utc) - timedelta(seconds=30)
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        event = PacketEvent(now, HOST, "9.9.9.9", "TCP", src_port=50001, dst_port=853, byte_count=80)
        assert rules(service.process(event)) == ["DNS_BYPASS"]
    with sqlite3.connect(settings.db_path) as connection:
        stored = connection.execute("SELECT rule_id, severity FROM detections").fetchall()
    assert stored == [("DNS_BYPASS", "MEDIUM")]
