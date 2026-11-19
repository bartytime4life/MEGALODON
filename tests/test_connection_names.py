"""Names for outgoing connections: DNS answers and TLS server names, cached by lifetime and joined to the egress watch."""
from __future__ import annotations

import os
import socket
import struct
import sys
import time

import pytest

from megalodon import connection_names as cn
from megalodon import egress_watch as ew
from megalodon import response_engine as re_
from megalodon.watchlist import Watchlist, parse_lines
from test_egress_watch import add_connection, host  # noqa: F401
from test_process_network import proc, row, tables  # noqa: F401


def label(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_answer(name, records, *, flags=0x8180):
    """A response for `name` whose answers are (type, ttl, value) records, compressed the usual way."""
    answers = b""
    for kind, ttl, value in records:
        answers += struct.pack("!HHHIH", 0xC00C, kind, 1, ttl, len(value)) + value
    return (struct.pack("!HHHHHH", 7, flags, 1, len(records), 0, 0) + label(name) + struct.pack("!HH", 1, 1)
            + answers)


def client_hello(name):
    host_ = name.encode()
    sni = struct.pack("!HHHBH", 0, len(host_) + 5, len(host_) + 3, 0, len(host_)) + host_
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(sni)) + sni)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def ipv4_udp(source_port, payload):
    udp = struct.pack("!HHHH", source_port, 40000, 8 + len(payload), 0) + payload
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, b"\x08\x08\x08\x08",
                       b"\xc0\xa8\x01\x05") + udp


def ipv6_tcp(destination, port, payload):
    tcp = struct.pack("!HHIIBBHHH", 50000, port, 1, 0, 5 << 4, 0x18, 1024, 0, 0) + payload
    return (struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + socket.inet_pton(socket.AF_INET6, "2001:db8::5")
            + socket.inet_pton(socket.AF_INET6, destination) + tcp)


def test_dns_answers_map_addresses_to_the_name_asked_for():
    cname = label("edge.cdn.example")
    answer = dns_answer("updates.example.org", [(5, 300, cname), (1, 30, socket.inet_aton("93.184.216.34")),
                                                (28, 999999, socket.inet_pton(socket.AF_INET6, "2001:db8::34"))])
    assert cn.parse_dns(answer) == [("93.184.216.34", "updates.example.org", 60),        # short lifetimes held a minute
                                    ("2001:db8::34", "updates.example.org", 86400)]      # long ones a day at most
    assert cn.parse_dns(dns_answer("x.example", [(1, 60, b"\x01\x02\x03\x04")], flags=0x0100)) == [], "a query"
    assert cn.parse_dns(dns_answer("x.example", [(1, 60, b"\x01\x02\x03\x04")], flags=0x8183)) == [], "NXDOMAIN"
    assert cn.parse_dns(answer[:30]) == [] and cn.parse_dns(b"") == []
    looping = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    assert cn.parse_dns(looping) == [], "a name that points at itself"


def test_client_hello_server_names():
    assert cn.parse_client_hello(client_hello("api.example.net")) == "api.example.net"
    assert cn.parse_client_hello(client_hello("api.example.net")[:50]) is None
    assert cn.parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" + b"\0" * 40) is None
    assert cn.parse_packet(ipv4_udp(53, dns_answer("a.example", [(1, 120, b"\x5d\xb8\xd8\x22")]))) == \
        ("dns", [("93.184.216.34", "a.example", 120)])
    assert cn.parse_packet(ipv4_udp(5353, dns_answer("a.example", [(1, 120, b"\x5d\xb8\xd8\x22")]))) is None
    assert cn.parse_packet(ipv6_tcp("2001:db8::99", 443, client_hello("b.example"))) == \
        ("sni", "2001:db8::99", 443, "b.example")


def test_the_cache_prefers_the_name_asked_for_and_forgets_on_time():
    now = [100.0]
    names = cn.Names(clock=lambda: now[0])
    names.learn(("dns", [("93.184.216.34", "updates.example.org", 60)]))
    names.learn(("sni", "93.184.216.34", 443, "api.example.net"))
    assert names.lookup("93.184.216.34", 443) == ["api.example.net", "updates.example.org"]
    assert names.lookup("93.184.216.34", 8443) == ["updates.example.org"]
    now[0] += 61
    assert names.lookup("93.184.216.34", 8443) == [], "the answer's lifetime is over"
    for number in range(cn.MAX_NAMES + 3):
        names.learn(("dns", [("93.184.216.35", f"n{number}.example", 300)]))
    assert len(names.lookup("93.184.216.35")) == cn.MAX_NAMES


def test_the_egress_watch_names_destinations_and_reports_watchlisted_and_generated_names(host, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(host))
    names = cn.Names()
    names.learn(("dns", [("151.101.1.69", "deb.example.org", 300)]))                  # the known package manager
    add_connection(host, 822, ("93.184.215.71", 443), 221, "/usr/bin/python3", b"python3\0job.py\0")
    names.learn(("sni", "93.184.215.71", 443, "c2.bad-actor.example"))
    add_connection(host, 823, ("93.184.215.72", 443), 222, "/usr/bin/curl", b"curl\0")
    names.learn(("dns", [("93.184.215.72", "q8x7k2v9n4m3b6z1w5p0.example", 300)]))
    watchlist = Watchlist(parse_lines(["bad-actor.example  # reported by the CERT"]))
    found = []
    watcher = ew.Watcher(manifest, found.append, root=str(host), names=names, watchlist=watchlist)
    watcher.poll()
    watcher.poll()
    by_rule = {f["rule_id"]: f for f in found}
    assert sorted(f["rule_id"] for f in found) == ["NEW_OUTBOUND_PROGRAM", "NEW_OUTBOUND_PROGRAM",
                                                   "OUTBOUND_TO_GENERATED_NAME", "OUTBOUND_TO_WATCHLISTED_NAME"]
    hit = by_rule["OUTBOUND_TO_WATCHLISTED_NAME"]
    assert hit["severity"] == "CRITICAL" and hit["name"] == "c2.bad-actor.example"
    assert "on the watchlist as bad-actor.example: reported by the CERT" in hit["detail"]
    new = next(f for f in found if f["rule_id"] == "NEW_OUTBOUND_PROGRAM" and f["port"] == 443
               and f["address"] == "93.184.215.71")
    assert "c2.bad-actor.example (93.184.215.71):443/tcp" in new["detail"]
    assert new["names"] == ["c2.bad-actor.example"]
    assert by_rule["OUTBOUND_TO_GENERATED_NAME"]["severity"] == "MEDIUM"
    # Watchlisted names are acted on like dropped tools phoning home; in shadow mode, nothing is carried out.
    signals = re_.egress_signals(dict(findings=[hit], checked_at="2026-11-19T00:00:00Z"))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    import json
    decision = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    assert decision["playbook"] == "watchlisted-name"
    assert {a["action"] for a in decision["actions"]} >= {"suspend_process", "block_address"}


def _capture():
    try:
        names, listener, error = cn.start()
    except OSError:
        return None
    return None if error else (names, listener)


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0, reason="raw capture needs root")
def test_live_capture_reads_only_dns_answers_and_client_hellos():
    started = _capture()
    if started is None:
        pytest.skip("raw packet capture is not available here")
    names, listener = started
    try:
        time.sleep(0.2)
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            server.bind(("127.0.0.1", 53))
        except OSError:
            pytest.skip("port 53 is in use")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        server.sendto(dns_answer("updates.example.org", [(1, 300, socket.inet_aton("93.184.216.34"))]),
                      client.getsockname())
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x" * 64, client.getsockname())   # not from 53
        listening = socket.socket()
        listening.bind(("127.0.0.1", 0))
        listening.listen(2)
        plain = socket.create_connection(listening.getsockname())
        plain.sendall(b"GET / HTTP/1.1\r\n\r\n")                                                     # not a handshake
        tls = socket.create_connection(listening.getsockname())
        tls.sendall(client_hello("api.example.net"))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not (names.lookup("93.184.216.34")
                                                   and names.lookup("127.0.0.1", listening.getsockname()[1])):
            time.sleep(0.05)
        assert names.lookup("93.184.216.34") == ["updates.example.org"]
        assert names.lookup("127.0.0.1", listening.getsockname()[1]) == ["api.example.net"]
        # The kernel filter passed only the answer and the handshake (each seen twice on loopback).
        assert listener.stats["packets"] == listener.stats["dns"] + listener.stats["sni"]
    finally:
        listener.stop.set()
