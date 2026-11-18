"""Opt-in TLS ClientHello fingerprinting: admission, TShark probing, rules, privacy."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import ssl
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
from megalodon.validation import ValidationError, parse_ja3, parse_ja4
from megalodon.watchlist import Watchlist, parse_lines, render

T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)
HOST = "192.168.1.10"
JA3 = "e8df55bdfa49d878dc07891c00a025ce"
JA4 = "t13d171100_ab0a1bf427ad_8e6e362c5eac"
JA4_NO_SNI = "t13i171000_ab0a1bf427ad_8e6e362c5eac"


def hello(dst="8.8.4.4", sni=None, i=0, ja3=JA3, ja4=JA4, src=HOST):
    return PacketEvent(T0 + timedelta(seconds=i), src, dst, "TCP", src_port=50000, dst_port=443,
                       tcp_flags=frozenset({"ACK", "PSH"}), tls_ja3=ja3, tls_ja4=ja4, tls_sni=sni)


def rules(results):
    return [item.rule_id for item in results]


def detector(watch=None):
    return ThreatDetector(ThreatDetectionSettings(tls_fingerprints=True),
                          watchlist=Watchlist(parse_lines(watch)) if watch else None)


# ------------------------------------------------------------ admission
def test_fingerprint_validation():
    assert parse_ja3(JA3.upper()) == JA3
    assert parse_ja4(JA4) == JA4 and parse_ja4("q13d0310h3_55b375c5d22e_cd85d2d88918")
    for bad in ["", "e8df55", JA3 + "0", "z" * 32]:
        with pytest.raises(ValidationError):
            parse_ja3(bad)
    for bad in ["", "t13d171100", "x13d171100_ab0a1bf427ad_8e6e362c5eac", JA4 + "_00"]:
        with pytest.raises(ValidationError):
            parse_ja4(bad)


def test_model_round_trip_and_default_output_unchanged():
    event = hello(sni="API.Example.com")
    assert event.tls_sni == "api.example.com" and event.is_client_hello
    assert PacketEvent.from_mapping(event.to_dict()) == event
    plain = PacketEvent(T0, HOST, "8.8.4.4", "TCP")
    assert not plain.is_client_hello
    assert not {"tls_ja3", "tls_ja4", "tls_sni"} & set(plain.to_dict())


# ------------------------------------------------------------- TShark
def _row(extra):
    base = {k: "" for k in tshark.FIELDS}
    base.update({"frame.time_epoch": "1788710400", "ip.src": HOST, "ip.dst": "8.8.4.4",
                 "ip.proto": "6", "tcp.srcport": "50000", "tcp.dstport": "443",
                 "tcp.flags": "0x018", "frame.len": "583"})
    return "\t".join([base[k] for k in tshark.FIELDS] + list(extra))


def test_parse_fields_reads_only_single_client_hellos():
    tls = tshark.TLS_FIELDS
    event = tshark.parse_fields(_row(["1", JA3, JA4, "www.example.com"]), tls=tls)
    assert (event.tls_ja3, event.tls_ja4, event.tls_sni) == (JA3, JA4, "www.example.com")
    for values in (["2", JA3, JA4, ""], ["", "", "", ""], ["1,2", JA3, JA4, ""]):
        assert not tshark.parse_fields(_row(values), tls=tls).is_client_hello
    garbled = tshark.parse_fields(_row(["1", "nothex", JA4, "bad..name"]), tls=tls)
    assert (garbled.tls_ja3, garbled.tls_ja4, garbled.tls_sni) == (None, JA4, None)
    # Older TShark without JA4: the probed subset drives the column layout.
    older = ("tls.handshake.type", "tls.handshake.ja3", "tls.handshake.extensions_server_name")
    event = tshark.parse_fields(_row(["1", JA3, "a.example"]), tls=older)
    assert (event.tls_ja3, event.tls_ja4, event.tls_sni) == (JA3, None, "a.example")
    assert "tls.handshake.ja3" not in tshark.FIELDS


def test_capture_commands_include_tls_fields_only_when_given():
    _, decode = capture_commands("eth0")
    assert not any(f.startswith("tls.") for f in decode)
    _, decode = capture_commands("eth0", tls=tshark.TLS_FIELDS)
    assert decode[-8:] == [x for f in tshark.TLS_FIELDS for x in ("-e", f)]


class _FakeProcess:
    def __init__(self, ok):
        self.returncode = 0 if ok else 1

    def communicate(self, data=None, timeout=None):
        return b"", b""


def test_probe_falls_back_to_the_accepted_subset():
    calls = []

    def popen(argv, **kwargs):
        names = argv[argv.index("fields") + 1:][1::2]
        calls.append(names)
        assert kwargs["env"] == {"PATH": "/usr/bin"}
        return _FakeProcess("tls.handshake.ja4" not in names)

    assert tshark.probe_fields(tshark.TLS_FIELDS, popen, {"PATH": "/usr/bin"}) == (
        "tls.handshake.type", "tls.handshake.ja3", "tls.handshake.extensions_server_name")
    assert calls[0] == list(tshark.TLS_FIELDS) and len(calls) == 5

    def broken(argv, **kwargs):
        raise FileNotFoundError("no tshark")

    assert tshark.probe_fields(tshark.TLS_FIELDS, broken, {}) == ()


def _client_hello(server_name):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=server_name)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def _pcap(payloads):
    def checksum(data):
        if len(data) % 2:
            data += b"\0"
        total = sum(struct.unpack(f"!{len(data) // 2}H", data))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF

    frames = []
    for index, payload in enumerate(payloads):
        tcp = struct.pack("!HHIIBBHHH", 50000 + index, 443, 1, 1, 5 << 4, 0x18, 64240, 0, 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), index, 0, 64, 6, 0,
                         bytes([192, 168, 1, 10]), bytes([8, 8, 4, 4]))
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        frame = b"\x00" * 12 + b"\x08\x00" + ip + tcp
        frames.append(struct.pack("<IIII", 1788710400 + index, 0, len(frame), len(frame)) + frame)
    return tshark.EMPTY_PCAP + b"".join(frames)


@pytest.mark.skipif(not Path("/usr/bin/tshark").exists(), reason="TShark not installed")
def test_real_tshark_fingerprints_a_genuine_client_hello(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "LANG": "C", "LC_ALL": "C"}
    tls = tshark.probe_fields(tshark.TLS_FIELDS, subprocess.Popen, env)
    assert {"tls.handshake.type", "tls.handshake.ja3"} <= set(tls)
    capture = tmp_path / "hello.pcap"
    capture.write_bytes(_pcap([_client_hello("api.example-sni.test"), _client_hello(None)]))
    argv = ["/usr/bin/tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=n",
            "-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=a", "-E", "aggregator=,",
            "-o", "tls.desegment_ssl_records:TRUE", "-d", "tcp.port==443,tls"]
    for field in tshark.fields(False, tls):
        argv += ["-e", field]
    rows = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30).stdout.splitlines()
    events = [tshark.parse_fields(row, tls=tls) for row in rows]
    hellos = [e for e in events if e is not None and e.is_client_hello]
    assert [e.tls_sni for e in hellos] == ["api.example-sni.test", None]
    assert all(e.tls_ja3 and len(e.tls_ja3) == 32 for e in hellos)
    if "tls.handshake.ja4" in tls:
        assert hellos[0].tls_ja4[3] == "d" and hellos[1].tls_ja4[3] == "i"  # SNI flag
    found = []
    d = detector()
    for event in hellos:
        found += rules(d.analyze(event))
    assert found == ["TLS_WITHOUT_SNI"]


# ----------------------------------------------------------------- rules
def test_fingerprint_watchlist_matches_ja3_and_ja4():
    d = detector([f"ja3:{JA3} # lab client", "ja4:" + JA4_NO_SNI])
    first = d.analyze(hello(sni="www.example.com"))
    assert rules(first) == ["IOC_MATCH"]
    assert first[0].evidence["indicator"] == f"ja3:{JA3}"
    assert first[0].evidence["indicator_label"] == "lab client"
    assert first[0].evidence["server_name"] == "www.example.com"
    assert first[0].evidence["response_target"] == HOST
    assert d.analyze(hello(sni="www.example.com", i=1)) == []  # cooldown
    second = d.analyze(hello(ja3="dbb158bbf02cb040164d288c9b1d8492", ja4=JA4_NO_SNI,
                             dst="192.168.1.20", i=2))
    assert rules(second) == ["IOC_MATCH"] and second[0].evidence["fingerprint_kind"] == "ja4"


def test_sni_feeds_domain_watchlist_and_generated_name_checks():
    d = detector(["evil.example # c2"])
    assert rules(d.analyze(hello(sni="cdn.evil.example"))) == ["IOC_MATCH"]
    found = d.analyze(hello(sni="x7kq9zr2vbn4lp8wmt3c.com", i=1))
    assert rules(found) == ["DGA_DOMAIN"] and found[0].evidence["name_source"] == "tls_sni"
    for i, name in enumerate(["www.google.com", "login.microsoftonline.com", "fonts.gstatic.com"]):
        assert d.analyze(hello(sni=name, i=10 + i)) == []


def test_tls_without_sni_targets_the_bare_public_server():
    d = detector()
    found = d.analyze(hello(dst="9.9.9.9", ja4=JA4_NO_SNI))
    assert rules(found) == ["TLS_WITHOUT_SNI"]
    assert found[0].severity == "LOW" and found[0].evidence["response_target"] == "9.9.9.9"
    assert found[0].evidence["ja4"] == JA4_NO_SNI
    assert d.analyze(hello(dst="9.9.9.9", ja4=JA4_NO_SNI, i=1)) == []
    assert d.analyze(hello(dst="192.168.1.20", ja4=JA4_NO_SNI, i=2)) == []  # internal server
    assert d.analyze(hello(dst="9.9.9.9", src="8.8.8.8", ja4=JA4_NO_SNI, i=3)) == []  # external client


def test_everything_is_off_unless_opted_in():
    d = ThreatDetector(ThreatDetectionSettings(),
                       watchlist=Watchlist(parse_lines([f"ja3:{JA3}", "evil.example"])))
    for i, event in enumerate([hello(), hello(sni="a.evil.example"), hello(dst="9.9.9.9")]):
        assert d.analyze(event) == [], i


def test_rollback_restores_tls_cooldowns():
    d = detector([f"ja3:{JA3}"])
    before = copy.deepcopy((d.last_emitted, list(d.lru)))
    prepared = d.prepare(hello(dst="9.9.9.9"))
    assert set(rules(prepared.results)) == {"IOC_MATCH", "TLS_WITHOUT_SNI"}
    prepared.rollback()
    assert copy.deepcopy((d.last_emitted, list(d.lru))) == before


def test_watchlist_fingerprint_lines_render_and_refuse_garbage():
    entries = parse_lines([f"JA3:{JA3.upper()} # x", "ja4:" + JA4])
    assert render(entries, "h").splitlines()[1:] == [f"ja3:{JA3}  # x", f"ja4:{JA4}"]
    for bad in ["ja3:abc", "ja4:t13d", "ja5:" + JA3]:
        with pytest.raises(ValidationError):
            parse_lines([bad])


def test_settings_parse_tls_option(tmp_path):
    path = tmp_path / "s.toml"
    path.write_text("[threat_detection]\ntls_fingerprints = true\n")
    assert load_settings(path).threat.tls_fingerprints is True
    path.write_text('[threat_detection]\ntls_fingerprints = 1\n')
    with pytest.raises(ValidationError):
        load_settings(path)


def test_routine_server_names_never_reach_the_database(tmp_path):
    db = tmp_path / "private" / "audit.db"
    settings = Settings(db_path=db, threat=ThreatDetectionSettings(tls_fingerprints=True))
    now = datetime.now(timezone.utc) - timedelta(seconds=60)
    routine = ["routine-bank-portal.example", "routine-mail.example"]
    with Store(db) as store:
        service = MegalodonService(settings, store)
        for i, name in enumerate(routine):
            service.process(PacketEvent(now + timedelta(seconds=i), HOST, "8.8.4.4", "TCP",
                                        dst_port=443, tls_ja3=JA3, tls_ja4=JA4, tls_sni=name))
    raw = b"".join(p.read_bytes() for p in db.parent.iterdir() if p.is_file())
    for name in routine + [JA3, JA4]:
        assert name.encode() not in raw, f"{name} leaked into storage"
