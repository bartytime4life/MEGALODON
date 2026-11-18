"""Opt-in LAN integrity for IPv6: neighbour-discovery spoofing, rogue routers and rogue DHCPv6."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import sqlite3
import struct
import subprocess

import pytest

from megalodon.config import Settings, load_settings
from megalodon.models import PacketEvent
from megalodon.offline import tshark
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import ThreatDetectionSettings, ThreatDetector
from megalodon.validation import ValidationError

T0 = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
ROUTER, CLIENT, OTHER = "fe80::1", "fe80::50", "fe80::66"
ROUTER_MAC, CLIENT_MAC, OTHER_MAC = "a4:91:b1:00:00:01", "a4:91:b1:00:00:50", "02:00:5e:10:00:66"
ALL_NODES = "ff02::1"


def ra(at, src=ROUTER, mac=ROUTER_MAC, lifetime=1800):
    return PacketEvent(T0 + timedelta(seconds=at), src, ALL_NODES, "ICMPV6", byte_count=78,
                       nd_type=134, nd_mac=mac, ra_router_lifetime=lifetime)


def na(at, target, mac, src=None):
    return PacketEvent(T0 + timedelta(seconds=at), src or target, ALL_NODES, "ICMPV6", byte_count=86,
                       nd_type=136, nd_mac=mac, nd_target=target)


def ns(at, src, mac):
    return PacketEvent(T0 + timedelta(seconds=at), src, "ff02::1:ff00:1", "ICMPV6", byte_count=86,
                       nd_type=135, nd_mac=mac)


def dhcpv6(at, server, kind=7):
    return PacketEvent(T0 + timedelta(seconds=at), server, CLIENT, "UDP", src_port=547, dst_port=546,
                       byte_count=120, dhcp_message_type=kind)


def detector(**settings):
    return ThreatDetector(ThreatDetectionSettings(lan_integrity=True, **settings))


def rules(found):
    return [item.rule_id for item in found]


# ------------------------------------------------------------- inputs

def test_neighbour_discovery_fields_validate_together():
    event = na(0, ROUTER, ROUTER_MAC)
    assert PacketEvent.from_mapping(event.to_dict()) == event
    assert "nd_type" not in PacketEvent(T0, CLIENT, ROUTER, "ICMPV6").to_dict()
    for bad in (dict(nd_type=137), dict(nd_mac=ROUTER_MAC), dict(nd_type=136),
                dict(nd_type=134), dict(nd_type=135, ra_router_lifetime=0),
                dict(nd_type=136, nd_target="192.168.1.1"), dict(nd_type=135, nd_mac="ff:ff:ff:ff:ff:ff")):
        with pytest.raises(ValidationError):
            PacketEvent(T0, CLIENT, ALL_NODES, "ICMPV6", **bad)
    with pytest.raises(ValidationError):
        PacketEvent(T0, CLIENT, ALL_NODES, "UDP", nd_type=135)
    with pytest.raises(ValidationError):
        PacketEvent(T0, "192.168.1.5", "192.168.1.6", "ICMPV6", nd_type=135)


def test_router_settings_parse_and_refuse(tmp_path):
    path = tmp_path / "settings.toml"
    path.write_text('[threat_detection]\nlan_integrity = true\nipv6_routers = ["FE80::0001"]\n'
                    "router_window_seconds = 600\n", encoding="utf-8")
    threat = load_settings(path).threat
    assert threat.ipv6_routers == (ROUTER,) and threat.router_window_seconds == 600
    for body in ('ipv6_routers = ["192.168.1.1"]', 'ipv6_routers = ["fe80::1", "FE80::1"]',
                 'ipv6_routers = ["nope"]', "router_window_seconds = 5", 'ipv6_routers = "fe80::1"'):
        path.write_text("[threat_detection]\n" + body + "\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_settings(path)


# ------------------------------------------------------------- NDP_SPOOFING

def test_a_rebound_neighbour_advertisement_is_ndp_spoofing():
    d = detector()
    assert rules(d.analyze(na(0, ROUTER, ROUTER_MAC))) == []
    found = d.analyze(na(8, ROUTER, OTHER_MAC, src=OTHER))
    assert rules(found) == ["NDP_SPOOFING"] and found[0].severity == "HIGH"
    evidence = found[0].evidence
    assert (evidence["claimed_address"], evidence["previous_mac"], evidence["new_mac"]) == (
        ROUTER, ROUTER_MAC, OTHER_MAC)
    assert evidence["seconds_since_previous"] == 8
    # The sender, not the multicast destination, is the party a response targets.
    assert evidence["response_target"] == OTHER and found[0].suppressed_reason is None
    assert rules(d.analyze(na(9, ROUTER, ROUTER_MAC))) == [], "one finding per address per cooldown"


def test_allowlisting_the_sender_suppresses_and_the_claimed_address_does_not():
    import ipaddress as ip

    def found_with(allowed):
        d = ThreatDetector(ThreatDetectionSettings(lan_integrity=True), allowlist=(ip.ip_network(allowed),))
        d.analyze(na(0, ROUTER, ROUTER_MAC))
        return d.analyze(na(1, ROUTER, OTHER_MAC, src=OTHER))[0]
    assert found_with(OTHER + "/128").suppressed_reason == "source_allowlisted"
    assert found_with(ROUTER + "/128").suppressed_reason is None


def test_solicitations_and_router_advertisements_also_bind_their_sender():
    d = detector()
    d.analyze(ns(0, CLIENT, CLIENT_MAC))
    assert rules(d.analyze(na(3, CLIENT, OTHER_MAC, src=OTHER))) == ["NDP_SPOOFING"]
    d = detector()
    d.analyze(ra(0))
    assert rules(d.analyze(ns(3, ROUTER, OTHER_MAC))) == ["NDP_SPOOFING"]


def test_duplicate_address_detection_stale_bindings_and_opt_out_stay_quiet():
    d = detector(arp_rebind_seconds=60)
    d.analyze(na(0, CLIENT, CLIENT_MAC))
    assert rules(d.analyze(na(61, CLIENT, OTHER_MAC))) == [], "an old binding moved to a new device"
    assert rules(d.analyze(ns(62, "::", OTHER_MAC))) == []
    no_option = PacketEvent(T0 + timedelta(seconds=63), OTHER, ALL_NODES, "ICMPV6", nd_type=136,
                            nd_target=CLIENT)
    assert rules(d.analyze(no_option)) == [], "an advertisement without a link-layer address claims nothing"
    off = ThreatDetector(ThreatDetectionSettings())
    off.analyze(na(0, ROUTER, ROUTER_MAC))
    assert rules(off.analyze(na(1, ROUTER, OTHER_MAC))) == []


def test_rollback_restores_the_neighbour_binding():
    d = detector()
    d.analyze(na(0, ROUTER, ROUTER_MAC))
    prepared = d.prepare(na(1, ROUTER, OTHER_MAC))
    assert rules(prepared.results) == ["NDP_SPOOFING"]
    prepared.rollback()
    assert d.nd[ROUTER][0] == ROUTER_MAC
    assert rules(d.analyze(na(2, ROUTER, OTHER_MAC))) == ["NDP_SPOOFING"]


# ------------------------------------------------------------- ROGUE_IPV6_ROUTER

def test_learned_mode_flags_a_second_router():
    d = detector()
    assert rules(d.analyze(ra(0))) == [] and rules(d.analyze(ra(200))) == []
    found = d.analyze(ra(300, src=OTHER, mac=OTHER_MAC))
    assert rules(found) == ["ROGUE_IPV6_ROUTER"]
    evidence = found[0].evidence
    assert evidence["known_routers"] == [ROUTER] and evidence["configured"] is False
    assert evidence["router_mac"] == OTHER_MAC and evidence["response_target"] == OTHER
    assert "default gateway" in found[0].message


def test_configured_routers_window_and_withdrawals():
    d = detector(ipv6_routers=(ROUTER,))
    assert rules(d.analyze(ra(0))) == []
    found = d.analyze(ra(1, src=OTHER, mac=OTHER_MAC, lifetime=0))
    assert rules(found) == ["ROGUE_IPV6_ROUTER"] and found[0].evidence["configured"] is True
    assert found[0].evidence["router_lifetime_seconds"] == 0 and "withdraws" in found[0].message
    d = detector(router_window_seconds=60)
    d.analyze(ra(0))
    assert rules(d.analyze(ra(61, src=OTHER, mac=OTHER_MAC))) == [], "the first router is no longer active"


# ------------------------------------------------------------- ROGUE_DHCP over DHCPv6

def test_a_second_dhcpv6_server_is_rogue_dhcp():
    d = detector()
    assert rules(d.analyze(dhcpv6(0, ROUTER, kind=2))) == [] and rules(d.analyze(dhcpv6(1, ROUTER))) == []
    found = d.analyze(dhcpv6(30, OTHER))
    assert rules(found) == ["ROGUE_DHCP"]
    evidence = found[0].evidence
    assert (evidence["protocol"], evidence["message_type"], evidence["known_servers"]) == ("dhcpv6", "reply", [ROUTER])
    assert found[0].message.startswith("DHCPv6 server fe80::66")
    for kind in (1, 3, 11, 12):  # client messages and relay forwards
        assert rules(d.analyze(dhcpv6(40, "fe80::77", kind=kind))) == []


def test_address_families_are_checked_separately():
    d = detector(dhcp_servers=("192.168.1.1",))
    assert rules(d.analyze(dhcpv6(0, ROUTER))) == [], "IPv4 servers configured; DHCPv6 is learned"
    assert rules(d.analyze(dhcpv6(1, OTHER))) == ["ROGUE_DHCP"]
    d = detector()
    d.analyze(PacketEvent(T0, "192.168.1.1", "192.168.1.77", "UDP", src_port=67, dst_port=68,
                          dhcp_message_type=5, dhcp_server_id="192.168.1.1"))
    assert rules(d.analyze(dhcpv6(1, ROUTER))) == [], "an IPv4 server does not make a DHCPv6 server a second one"
    d = detector(dhcp_servers=("192.168.1.1", ROUTER))
    assert rules(d.analyze(dhcpv6(0, ROUTER))) == [] and rules(d.analyze(dhcpv6(1, OTHER))) == ["ROGUE_DHCP"]


# ------------------------------------------------------------- capture

def _checksum(src, dst, payload, next_header):
    data = ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    data += struct.pack("!I3xB", len(payload), next_header) + payload
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv6_frame(mac, src, dst, next_header, payload):
    header = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 255)
    header += ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    return b"\x33\x33\x00\x00\x00\x01" + bytes.fromhex(mac.replace(":", "")) + b"\x86\xdd" + header + payload


def _icmpv6(mac, src, dst, kind, body):
    message = bytes([kind, 0, 0, 0]) + body
    message = message[:2] + struct.pack("!H", _checksum(src, dst, message, 58)) + message[4:]
    return _ipv6_frame(mac, src, dst, 58, message)


def _link_option(kind, mac):
    return bytes([kind, 1]) + bytes.fromhex(mac.replace(":", ""))


def _ra_frame(src, mac, lifetime=1800):
    return _icmpv6(mac, src, ALL_NODES, 134, struct.pack("!BBHII", 64, 0, lifetime, 0, 0) + _link_option(1, mac))


def _na_frame(target, mac, src):
    body = struct.pack("!I", 0x20000000) + ipaddress.IPv6Address(target).packed + _link_option(2, mac)
    return _icmpv6(mac, src, ALL_NODES, 136, body)


def _dhcpv6_frame(src, mac, kind=7):
    message = bytes([kind, 0x12, 0x34, 0x56])
    udp = struct.pack("!HHHH", 547, 546, 8 + len(message), 0) + message
    udp = udp[:6] + struct.pack("!H", _checksum(src, CLIENT, udp, 17)) + udp[8:]
    return _ipv6_frame(mac, src, CLIENT, 17, udp)


def _decode(tmp_path, frames):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "LANG": "C", "LC_ALL": "C"}
    lan = tshark.lan_subset(tshark.probe_fields(tshark.LAN_FIELDS, subprocess.Popen, env))
    assert lan == tshark.LAN_FIELDS
    records = [struct.pack("<IIII", 1795510800 + i, 0, len(f), len(f)) + f for i, f in enumerate(frames)]
    capture = tmp_path / "ipv6.pcap"
    capture.write_bytes(tshark.EMPTY_PCAP + b"".join(records))
    argv = ["/usr/bin/tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=n", "-E", "separator=/t",
            "-E", "quote=n", "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in tshark.fields(False, (), lan):
        argv += ["-e", field]
    rows = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30).stdout.splitlines()
    return [e for e in (tshark.parse_fields(row, lan=lan) for row in rows) if e is not None]


@pytest.mark.skipif(not Path("/usr/bin/tshark").exists(), reason="TShark not installed")
def test_real_tshark_decodes_neighbour_discovery_and_dhcpv6_into_findings(tmp_path):
    frames = [_ra_frame(ROUTER, ROUTER_MAC), _na_frame(ROUTER, OTHER_MAC, OTHER),
              _ra_frame(OTHER, OTHER_MAC, lifetime=0), _dhcpv6_frame(ROUTER, ROUTER_MAC),
              _dhcpv6_frame(OTHER, OTHER_MAC, kind=2)]
    events = _decode(tmp_path, frames)
    assert [(e.protocol, e.nd_type, e.nd_mac, e.nd_target, e.ra_router_lifetime, e.dhcp_message_type)
            for e in events] == [
        ("ICMPV6", 134, ROUTER_MAC, None, 1800, None), ("ICMPV6", 136, OTHER_MAC, ROUTER, None, None),
        ("ICMPV6", 134, OTHER_MAC, None, 0, None), ("UDP", None, None, None, None, 7),
        ("UDP", None, None, None, None, 2)]
    d = detector()
    assert [r for e in events for r in rules(d.analyze(e))] == ["NDP_SPOOFING", "ROGUE_IPV6_ROUTER", "ROGUE_DHCP"]


def test_other_icmpv6_and_ambiguous_rows_carry_no_claims():
    lan = tshark.LAN_FIELDS
    base = ["1795510800.0", "", "", OTHER, ALL_NODES, "", "58", "", "", "", "", "", "64"]

    def row(values):
        optional = [values.get(name, "") for name in lan]
        return "\t".join(base + optional)
    echo = tshark.parse_fields(row({"icmpv6.type": "128"}), lan=lan)
    assert echo.protocol == "ICMPV6" and echo.nd_type is None
    doubled = tshark.parse_fields(row({"icmpv6.type": "136", "icmpv6.nd.na.target_address": ROUTER,
                                       "icmpv6.opt.target_linkaddr": f"{ROUTER_MAC},{OTHER_MAC}"}), lan=lan)
    assert doubled.nd_type is None and doubled.nd_mac is None


# ------------------------------------------------------------- storage

def test_routine_neighbour_bindings_are_not_stored(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.db", threat=ThreatDetectionSettings(lan_integrity=True))
    now = datetime.now(timezone.utc) - timedelta(seconds=60)

    def at(seconds, event):
        return PacketEvent.from_mapping({**event.to_dict(), "observed_at": (now + timedelta(seconds=seconds)).isoformat()})
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        assert service.process(at(0, na(0, CLIENT, CLIENT_MAC))) == []
        service.process(at(1, na(0, ROUTER, ROUTER_MAC)))
        assert rules(service.process(at(2, na(0, ROUTER, OTHER_MAC, src=OTHER)))) == ["NDP_SPOOFING"]
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("audit.db*"))
    assert OTHER_MAC.encode() in raw, "the flagged binding is kept in its finding's evidence"
    assert CLIENT_MAC.encode() not in raw, "a routine binding never reaches the database"
    with sqlite3.connect(settings.db_path) as connection:
        assert {row[0] for row in connection.execute("SELECT protocol FROM events")} == {"ICMPV6"}
