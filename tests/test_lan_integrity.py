"""Opt-in LAN integrity: ARP spoofing and rogue DHCP server detection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import sqlite3
import struct
import subprocess

import pytest

from megalodon.config import Settings, load_settings
from megalodon.managed_capture import capture_commands
from megalodon.models import PacketEvent
from megalodon.offline import tshark
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import ThreatDetectionSettings, ThreatDetector
from megalodon.validation import ValidationError, parse_mac

T0 = datetime(2026, 11, 18, 3, 0, tzinfo=timezone.utc)
GATEWAY, CLIENT, ATTACKER = "192.168.1.1", "192.168.1.50", "192.168.1.66"
ROUTER_MAC, ATTACKER_MAC = "a4:91:b1:00:00:01", "02:13:37:00:00:66"


def arp(at, sender, mac, target=CLIENT, opcode=2):
    return PacketEvent(T0 + timedelta(seconds=at), sender, target, "OTHER", byte_count=42,
                       arp_opcode=opcode, arp_sender_mac=mac)


def dhcp(at, server, kind=2, src=None, src_port=67, client="192.168.1.77"):
    return PacketEvent(T0 + timedelta(seconds=at), src or server, client, "UDP", src_port=src_port, dst_port=68,
                       byte_count=342, dhcp_message_type=kind, dhcp_server_id=server)


def detector(**settings):
    return ThreatDetector(ThreatDetectionSettings(lan_integrity=True, **settings))


def rules(found):
    return [item.rule_id for item in found]


# ------------------------------------------------------------- inputs

def test_mac_and_event_validation():
    assert parse_mac("A4-91-B1-00-00-01") == ROUTER_MAC
    for bad in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "a4:91:b1:00:00", 7):
        with pytest.raises(ValidationError):
            parse_mac(bad)
    with pytest.raises(ValidationError):
        PacketEvent(T0, GATEWAY, CLIENT, "OTHER", arp_opcode=2)
    event = arp(0, GATEWAY, ROUTER_MAC)
    assert event.to_dict()["arp_sender_mac"] == ROUTER_MAC
    assert PacketEvent.from_mapping(event.to_dict()) == event
    assert "arp_opcode" not in PacketEvent(T0, GATEWAY, CLIENT, "TCP").to_dict()


def test_settings_parse_and_refuse(tmp_path):
    path = tmp_path / "settings.toml"
    path.write_text('[threat_detection]\nlan_integrity = true\ndhcp_servers = ["192.168.1.1"]\n'
                    "arp_rebind_seconds = 60\n", encoding="utf-8")
    threat = load_settings(path).threat
    assert threat.lan_integrity and threat.dhcp_servers == ("192.168.1.1",) and threat.arp_rebind_seconds == 60
    assert ThreatDetectionSettings().lan_integrity is False
    for body in ('dhcp_servers = ["nope"]', 'dhcp_servers = ["10.0.0.1", "10.0.0.1"]',
                 "arp_rebind_seconds = 1", 'lan_integrity = "yes"', 'dhcp_servers = "10.0.0.1"'):
        path.write_text("[threat_detection]\n" + body + "\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_settings(path)


# ------------------------------------------------------------- ARP_SPOOFING

def test_rebinding_a_recent_address_is_arp_spoofing():
    d = detector()
    assert rules(d.analyze(arp(0, GATEWAY, ROUTER_MAC))) == []
    assert rules(d.analyze(arp(5, GATEWAY, ROUTER_MAC))) == []
    found = d.analyze(arp(10, GATEWAY, ATTACKER_MAC))
    assert rules(found) == ["ARP_SPOOFING"] and found[0].severity == "HIGH"
    evidence = found[0].evidence
    assert (evidence["previous_mac"], evidence["new_mac"], evidence["seconds_since_previous"]) == (
        ROUTER_MAC, ATTACKER_MAC, 5)
    # The genuine gateway answering again is the flip-flop of a poisoning tool,
    # but one finding per address per cooldown.
    assert rules(d.analyze(arp(11, GATEWAY, ROUTER_MAC))) == []


def test_stale_bindings_probes_and_opt_out_stay_quiet():
    d = detector(arp_rebind_seconds=60)
    d.analyze(arp(0, CLIENT, ROUTER_MAC))
    assert rules(d.analyze(arp(61, CLIENT, ATTACKER_MAC))) == [], "an old lease moved to a new device"
    assert rules(d.analyze(arp(62, "0.0.0.0", ATTACKER_MAC, opcode=1))) == []
    off = ThreatDetector(ThreatDetectionSettings())
    off.analyze(arp(0, GATEWAY, ROUTER_MAC))
    assert rules(off.analyze(arp(1, GATEWAY, ATTACKER_MAC))) == []


def test_arp_requests_feed_decoys_but_not_traffic_rules():
    d = detector(decoy_addresses=("192.168.1.250",), host_sweep_distinct_hosts=3)
    assert rules(d.analyze(arp(0, ATTACKER, ATTACKER_MAC, target="192.168.1.250", opcode=1))) == ["DECOY_TOUCH"]
    for i in range(5):
        assert rules(d.analyze(arp(1 + i, ATTACKER, ATTACKER_MAC, target=f"192.168.1.{100 + i}", opcode=1))) == []


def test_rollback_restores_the_binding():
    d = detector()
    d.analyze(arp(0, GATEWAY, ROUTER_MAC))
    prepared = d.prepare(arp(1, GATEWAY, ATTACKER_MAC))
    assert rules(prepared.results) == ["ARP_SPOOFING"]
    prepared.rollback()
    assert d.arp[GATEWAY][0] == ROUTER_MAC
    assert rules(d.analyze(arp(2, GATEWAY, ATTACKER_MAC))) == ["ARP_SPOOFING"]


# ------------------------------------------------------------- ROGUE_DHCP

def test_learned_mode_flags_a_second_server():
    d = detector()
    assert rules(d.analyze(dhcp(0, GATEWAY))) == []
    assert rules(d.analyze(dhcp(1, GATEWAY, kind=5))) == []
    found = d.analyze(dhcp(30, ATTACKER))
    assert rules(found) == ["ROGUE_DHCP"]
    assert found[0].evidence["known_servers"] == [GATEWAY] and found[0].evidence["configured"] is False
    assert found[0].evidence["response_target"] == ATTACKER


def test_configured_servers_and_non_replies():
    d = detector(dhcp_servers=(GATEWAY,))
    assert rules(d.analyze(dhcp(0, GATEWAY))) == []
    assert rules(d.analyze(dhcp(1, ATTACKER, kind=5)))[0] == "ROGUE_DHCP"
    for kind in (1, 3, 7):  # DISCOVER, REQUEST, RELEASE come from clients
        assert rules(d.analyze(dhcp(2, "192.168.1.99", kind=kind))) == []
    assert rules(d.analyze(dhcp(3, "192.168.1.98", src_port=68))) == []


def test_window_and_relays():
    d = detector(dhcp_window_seconds=60)
    d.analyze(dhcp(0, "10.0.0.1", src="192.168.1.1"))
    assert rules(d.analyze(dhcp(61, "10.0.0.2", src="192.168.1.1"))) == [], "the first server is no longer active"
    found = d.analyze(dhcp(62, "10.0.0.3", src="192.168.1.1"))
    assert rules(found) == ["ROGUE_DHCP"] and found[0].evidence["relay_address"] == "192.168.1.1"
    assert found[0].evidence["server"] == "10.0.0.3"


# ------------------------------------------------------------- capture

def test_capture_profile_reads_lan_fields_with_whole_packets():
    capture, decode = capture_commands("eth0", lan=tshark.LAN_FIELDS)
    assert capture[capture.index("-s") + 1] == "65535"
    assert decode[-2 * len(tshark.LAN_FIELDS):] == [x for f in tshark.LAN_FIELDS for x in ("-e", f)]
    assert "arp.opcode" not in capture_commands("eth0")[1]
    assert tshark.lan_subset(tshark.ARP_FIELDS + ("dhcp.option.dhcp",)) == tshark.ARP_FIELDS


def _frame(src_mac, ethertype, payload):
    return b"\xff" * 6 + bytes.fromhex(src_mac.replace(":", "")) + struct.pack("!H", ethertype) + payload


def _arp_frame(mac, sender, target, opcode=2):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode) + bytes.fromhex(mac.replace(":", ""))
    body += ipaddress.IPv4Address(sender).packed + b"\0" * 6 + ipaddress.IPv4Address(target).packed
    return _frame(mac, 0x0806, body)


def _dhcp_frame(mac, server, kind=2):
    bootp = struct.pack("!BBBBIHH", 2, 1, 6, 0, 0x1234, 0, 0) + b"\0" * 4
    bootp += ipaddress.IPv4Address("192.168.1.77").packed + ipaddress.IPv4Address(server).packed + b"\0" * 4
    bootp += bytes.fromhex("aabbccddeeff") + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    bootp += bytes([53, 1, kind, 54, 4]) + ipaddress.IPv4Address(server).packed + b"\xff"
    udp = struct.pack("!HHHH", 67, 68, 8 + len(bootp), 0) + bootp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     ipaddress.IPv4Address(server).packed, b"\xff" * 4)
    return _frame(mac, 0x0800, ip + udp)


def _pcap(frames, snaplen=None):
    out = []
    for index, frame in enumerate(frames):
        kept = frame if snaplen is None else frame[:snaplen]
        out.append(struct.pack("<IIII", 1795489200 + index, 0, len(kept), len(frame)) + kept)
    return tshark.EMPTY_PCAP + b"".join(out)


def _decode(tmp_path, pcap):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "LANG": "C", "LC_ALL": "C"}
    lan = tshark.lan_subset(tshark.probe_fields(tshark.LAN_FIELDS, subprocess.Popen, env))
    assert lan == tshark.LAN_FIELDS
    capture = tmp_path / "lan.pcap"
    capture.write_bytes(pcap)
    argv = ["/usr/bin/tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=n", "-E", "separator=/t",
            "-E", "quote=n", "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in tshark.fields(False, (), lan):
        argv += ["-e", field]
    rows = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30).stdout.splitlines()
    return [e for e in (tshark.parse_fields(row, lan=lan) for row in rows) if e is not None]


@pytest.mark.skipif(not Path("/usr/bin/tshark").exists(), reason="TShark not installed")
def test_real_tshark_decodes_arp_and_dhcp_into_findings(tmp_path):
    frames = [_arp_frame(ROUTER_MAC, GATEWAY, CLIENT), _arp_frame(ATTACKER_MAC, GATEWAY, CLIENT),
              _dhcp_frame(ROUTER_MAC, GATEWAY), _dhcp_frame(ATTACKER_MAC, ATTACKER, kind=5)]
    events = _decode(tmp_path, _pcap(frames))
    assert [(e.protocol, e.arp_sender_mac, e.dhcp_server_id) for e in events] == [
        ("OTHER", ROUTER_MAC, None), ("OTHER", ATTACKER_MAC, None),
        ("UDP", None, GATEWAY), ("UDP", None, ATTACKER)]
    d = detector()
    assert [r for e in events for r in rules(d.analyze(e))] == ["ARP_SPOOFING", "ROGUE_DHCP"]
    # The metadata-only snapshot cuts the DHCP options, so no server identity is read.
    cut = _decode(tmp_path, _pcap([_dhcp_frame(ROUTER_MAC, GATEWAY)], snaplen=256))
    assert all(e.dhcp_server_id is None for e in cut)


# ------------------------------------------------------------- storage

def test_routine_bindings_are_not_stored(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.db", threat=ThreatDetectionSettings(lan_integrity=True))
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        now = datetime.now(timezone.utc) - timedelta(seconds=60)
        quiet = PacketEvent(now, "192.168.1.20", CLIENT, "OTHER", arp_opcode=2, arp_sender_mac="a4:91:b1:00:00:20")
        assert service.process(quiet) == []
        service.process(PacketEvent(now + timedelta(seconds=1), GATEWAY, CLIENT, "OTHER", arp_opcode=2,
                                    arp_sender_mac=ROUTER_MAC))
        found = service.process(PacketEvent(now + timedelta(seconds=2), GATEWAY, CLIENT, "OTHER", arp_opcode=2,
                                            arp_sender_mac=ATTACKER_MAC))
        assert rules(found) == ["ARP_SPOOFING"]
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("audit.db*"))
    assert ATTACKER_MAC.encode() in raw, "the flagged binding is kept in its finding's evidence"
    assert b"a4:91:b1:00:00:20" not in raw, "a routine binding never reaches the database"
    with sqlite3.connect(settings.db_path) as connection:
        assert {row[0] for row in connection.execute("SELECT protocol FROM events")} == {"OTHER"}
