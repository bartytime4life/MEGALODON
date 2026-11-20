"""Connections too short for a scan: heard as the kernel announces them closing, and judged by their destination."""
from __future__ import annotations

import errno
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from megalodon import closed_connections as cc
from megalodon import egress_watch as ew
from megalodon import response_engine as re_
from test_net_namespaces import CONTAINER_NS, HOST_NS, machine, stat_line  # noqa: F401
from test_process_network import proc, row

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux sockets")


def message(family, local, local_port, remote, port, protocol=6, info=None, kind=cc.SOCK_DIAG_BY_FAMILY):
    """One sock_diag destroy announcement as the kernel sends it: owner and inode left zero."""
    width = 4 if family == socket.AF_INET else 16
    pack = lambda text: socket.inet_pton(family, text).ljust(16, b"\0")[:16]  # noqa: E731
    body = struct.pack("=BBBB", family, 7, 0, 0) + struct.pack(">HH", local_port, port) + pack(local) + pack(remote)
    body += struct.pack("=I", 0) + b"\x11" * 8 + struct.pack("=IIIII", 0, 0, 0, 0, 0)
    assert len(body) == cc.MESSAGE and width
    attribute = struct.pack("=HH", 5, cc.INET_DIAG_PROTOCOL) + bytes([protocol]) + b"\0" * 3
    if info is not None:
        attribute += struct.pack("=HH", 4 + len(info), cc.INET_DIAG_INFO) + info + b"\0" * (-len(info) % 4)
    body += attribute
    return struct.pack("=IHHII", 16 + len(body), kind, 0, 0, 0) + body


def tcp_info(sent, received):
    info = bytearray(232)
    struct.pack_into("=QQ", info, 120, sent, received)
    struct.pack_into("=Q", info, 104, 7777)                  # pacing rate, just before: never read as a count
    return bytes(info)


def closed(address, port, local_port=51234, protocol="tcp", sent=0, received=0):
    address = ipaddress.ip_address(address)
    return dict(protocol=protocol, family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
                local=ipaddress.ip_address("192.168.1.5"), local_port=local_port, address=address, port=port,
                sent=sent, received=received)


class FakeClosings:
    def __init__(self, gaps=()):
        self.queue, self.gaps, self.missed, self.subscribed, self.closed = [], set(gaps), 0, [], False

    def subscribe(self, spaces):
        self.subscribed.append(sorted(s["id"] for s in spaces if not s["own"]))

    def drain(self):
        out, self.queue = self.queue, []
        return out

    def filenos(self):
        return []

    def close(self):
        self.closed = True


# ------------------------------------------------------------------ reading the announcements

def test_announcements_are_read_with_their_addresses_ports_and_byte_counts():
    data = (message(socket.AF_INET, "192.168.1.5", 41962, "93.184.215.14", 443, info=tcp_info(5120, 830))
            + message(socket.AF_INET6, "2001:db8::5", 40000, "2606:4700::6810:84e5", 53, protocol=17)
            + message(socket.AF_INET, "192.168.1.5", 1, "93.184.215.14", 2, protocol=132)          # SCTP: not ours
            + message(socket.AF_INET, "192.168.1.5", 3, "93.184.215.14", 4, kind=3))              # NLMSG_DONE
    found = cc.parse(data + b"\x40\0\0\0truncated")
    assert [(f["protocol"], str(f["local"]), f["local_port"], str(f["address"]), f["port"], f["sent"], f["received"])
            for f in found] == [("tcp", "192.168.1.5", 41962, "93.184.215.14", 443, 5120, 830),
                                ("udp", "2001:db8::5", 40000, "2606:4700::6810:84e5", 53, None, None)]
    short = message(socket.AF_INET, "192.168.1.5", 41962, "93.184.215.14", 443, info=b"\0" * 100)
    assert cc.parse(short)[0]["sent"] is None, "a tcp_info too short to hold the counts is not guessed from"


def test_only_outgoing_connections_to_other_machines_are_kept():
    assert ew.heard(closed("93.184.215.14", 443))["program"] == ew.UNNAMED
    assert ew.heard(closed("93.184.215.14", 0)) is None, "a listener, or an unconnected socket"
    assert ew.heard(closed("127.0.0.1", 8080)) is None and ew.heard(closed("::1", 8080)) is None
    assert ew.heard(closed("192.168.1.1", 53, protocol="udp")) is None, "the LAN is off by default"
    assert ew.heard(closed("192.168.1.1", 53, protocol="udp"), include_private=True)["scope"] == "private"
    # sshd's side of a connection that came in: its local port is one listened on.
    assert ew.heard(closed("140.82.112.3", 51000, local_port=22), listening={22}) is None
    assert ew.heard(closed("140.82.112.3", 22, local_port=22), listening={80}) is not None
    inside = ew.heard(closed("93.184.215.14", 443), CONTAINER_NS, "docker:ab12cd34ef56")
    assert inside["program"] == "[container] " + ew.UNNAMED and inside["namespace"] == CONTAINER_NS


# ------------------------------------------------------------------ judging them

def baseline(**extra):
    value = dict(schema=ew.SCHEMA, programs={
        "/usr/lib/apt/methods/https": dict(ports=["tcp/443"], networks=["151.101.1.0/24"]),
        "/opt/vendor/agent": dict(ports=[], networks=["93.184.216.0/24"], any_port=True),
        "[container] /usr/bin/python3 /app/server.py": dict(ports=["tcp/443"], networks=["93.184.215.0/24"])})
    value.update(extra)
    return value


def test_a_destination_no_learned_program_uses_is_reported_with_what_was_sent():
    connection = ew.heard(closed("93.184.215.99", 8443, sent=48213, received=310))
    (finding,) = ew.judge_closed(baseline(), connection)
    assert finding["rule_id"] == "BRIEF_OUTBOUND_CONNECTION" and finding["severity"] == "MEDIUM"
    assert finding["closed"] is True and (finding["sent"], finding["received"]) == (48213, 310)
    assert "93.184.215.99:8443/tcp, sending about 48213 bytes and receiving about 310" in finding["detail"]
    assert finding["evidence"]["processes"] == [] and finding["dst_ip"] == "93.184.215.99"
    assert "account" not in finding and "uid" not in finding, "the announcement names no owner: none is claimed"


def test_a_port_and_network_a_learned_program_uses_is_quiet():
    assert ew.judge_closed(baseline(), ew.heard(closed("151.101.1.70", 443))) == []
    assert ew.judge_closed(baseline(), ew.heard(closed("93.184.216.10", 9999))) == [], "any_port"
    assert [f["rule_id"] for f in ew.judge_closed(baseline(), ew.heard(closed("151.101.1.70", 80)))] == [
        "BRIEF_OUTBOUND_CONNECTION"], "the network is known, the port is not"
    assert [f["severity"] for f in ew.judge_closed(baseline(), ew.heard(
        closed("192.168.1.1", 9999), include_private=True))] == ["LOW"]


def test_containers_and_the_host_are_judged_apart():
    everywhere = baseline(all_namespaces=True)
    # The host's package manager does not make the same destination normal inside a container, nor the reverse.
    assert len(ew.judge_closed(everywhere, ew.heard(closed("151.101.1.70", 443), CONTAINER_NS, "docker:x"))) == 1
    assert len(ew.judge_closed(everywhere, ew.heard(closed("93.184.215.20", 443)))) == 1
    assert ew.judge_closed(everywhere, ew.heard(closed("93.184.215.20", 443), CONTAINER_NS, "docker:x")) == []
    # A baseline learned before other namespaces were read knows nothing of them: not reported as new.
    assert ew.judge_closed(baseline(), ew.heard(closed("151.101.1.70", 443), CONTAINER_NS, "docker:x")) == []


def test_watchlisted_names_are_reported_even_without_a_program():
    class Watchlist:
        def match_domain(self, name):
            return ("c2.bad-actor.example", "listed") if name == "c2.bad-actor.example" else None
    connection = ew.heard(closed("93.184.215.40", 443))
    connection["names"] = ["c2.bad-actor.example"]
    found = ew.judge_closed(baseline(), connection, Watchlist())
    assert [f["rule_id"] for f in found] == ["OUTBOUND_TO_WATCHLISTED_NAME", "BRIEF_OUTBOUND_CONNECTION"]
    assert found[0]["severity"] == "CRITICAL" and found[0]["name"] == "c2.bad-actor.example"


def test_allowed_destinations_are_quiet_and_badly_written_ones_refused(tmp_path):
    manifest = tmp_path / "egress.json"
    assert ew.allow(manifest, destination="tcp/8443@93.184.215.99")["destination"] == "tcp/8443@93.184.215.99/32"
    ew.allow(manifest, destination="[container] udp/53@0.0.0.0/0")
    value = ew.read(manifest)
    assert value["destinations"] == ["[container] udp/53@0.0.0.0/0", "tcp/8443@93.184.215.99/32"]
    assert ew.judge_closed(value, ew.heard(closed("93.184.215.99", 8443))) == []
    assert len(ew.judge_closed(value, ew.heard(closed("93.184.215.98", 8443)))) == 1
    value["all_namespaces"] = True
    assert ew.judge_closed(value, ew.heard(closed("8.8.8.8", 53, protocol="udp"), CONTAINER_NS, "docker:x")) == []
    assert len(ew.judge_closed(value, ew.heard(closed("8.8.8.8", 53, protocol="udp")))) == 1, "for containers only"
    for bad in ("443@1.2.3.0/24", "tcp/0@1.2.3.0/24", "tcp/443@nowhere", "[pod] tcp/443@1.2.3.0/24", "icmp/1@1.2.3.4"):
        with pytest.raises(ew.EgressError):
            ew.allow(manifest, destination=bad)
    with pytest.raises(ew.EgressError, match="name a program"):
        ew.allow(manifest)


def test_the_command_takes_a_program_or_a_destination(tmp_path, capsys):
    from megalodon import cli

    def main(argv):
        try:
            return cli.main(argv)
        except SystemExit as exit:
            return exit.code
    manifest = tmp_path / "egress.json"
    assert main(["egress", "allow", "--manifest", str(manifest)]) == 2
    assert main(["egress", "allow", "/opt/x", "--destination", "tcp/1@1.2.3.4", "--manifest", str(manifest)]) == 2
    assert main(["egress", "allow", "--destination", "tcp/9@93.184.215.0/24", "--manifest", str(manifest)]) == 0
    assert ew.read(manifest)["destinations"] == ["tcp/9@93.184.215.0/24"]


# ------------------------------------------------------------------ the watch

def test_the_watch_reports_what_no_scan_saw_once_and_nothing_a_scan_saw(machine, tmp_path):  # noqa: F811
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine), all_namespaces=True)
    closings, found, warned = FakeClosings(), [], []
    watcher = ew.Watcher(manifest, found.append, root=str(machine), closings=closings, warn=warned.append)
    watcher.poll()
    assert closings.subscribed == [[CONTAINER_NS]], "every namespace a scan found is listened in"
    # The host's ssh connection, seen by the scan, closes: it was judged with its program already.
    closings.queue = [(None, closed("140.82.112.3", 22, local_port=50001)),
                      (None, closed("140.82.112.3", 51999, local_port=22)),            # sshd's accepted side
                      (CONTAINER_NS, closed("93.184.216.34", 443, local_port=40000)),  # seen in the container
                      (None, closed("93.184.215.77", 8443, sent=900, received=20)),    # never seen
                      (None, closed("93.184.215.77", 8443, local_port=51300)),          # the same, again
                      (CONTAINER_NS, closed("93.184.215.78", 25))]
    assert [(f["rule_id"], f["program"], f["port"]) for f in watcher.hear()] == [
        ("BRIEF_OUTBOUND_CONNECTION", ew.UNNAMED, 8443),
        ("BRIEF_OUTBOUND_CONNECTION", "[container] " + ew.UNNAMED, 25)]
    assert found[1]["container"] == "docker:ab12cd34ef56" and "in container docker:ab12cd34ef56" in found[1]["detail"]
    assert watcher.stats["closed"] == 6 and watcher.stats["brief"] == 3 and warned == []


def test_a_connection_that_closes_before_the_next_scan_is_still_known_as_seen(machine, tmp_path):  # noqa: F811
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine), all_namespaces=True)
    # A new program connects to a destination nothing learned; the scan sees it, and reports it with its program.
    with open(machine / "proc/net/tcp", "a") as table:
        table.write(row(("192.168.1.5", 50777), ("93.184.215.60", 8443), "01", 777))
    proc(machine, 120, "/opt/vendor/agent", [777], cmdline=b"agent\0")
    stat_line(machine, 120, 9100)
    closings, found = FakeClosings(), []
    watcher = ew.Watcher(manifest, found.append, root=str(machine), closings=closings, warn=lambda text: None)
    assert [f["rule_id"] for f in watcher.poll()] == ["NEW_OUTBOUND_PROGRAM"]
    # It closes and is gone from the tables. The announcement is read at the start of the next scan, while the last
    # scan's connections are still known: it is not reported a second time, without its program.
    lines = (machine / "proc/net/tcp").read_text().splitlines(keepends=True)
    (machine / "proc/net/tcp").write_text("".join(line for line in lines if " 777 " not in line))
    closings.queue = [(None, closed("93.184.215.60", 8443, local_port=50777))]
    assert watcher.poll() == [] and watcher.hear() == [] and len(found) == 1


def test_gaps_and_lost_announcements_are_told_once(machine, tmp_path):  # noqa: F811
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine))
    closings, warned = FakeClosings(gaps={"closed connections cannot be heard here: run as root"}), []
    watcher = ew.Watcher(manifest, lambda f: None, root=str(machine), closings=closings, warn=warned.append)
    watcher.poll()
    closings.missed = 3
    watcher.hear()
    watcher.hear()
    assert warned == ["closed connections cannot be heard here: run as root",
                      "3 bursts of closed connections came faster than they could be read: some short connections "
                      "were missed"]


def test_learning_records_short_connections_by_destination(machine, tmp_path):  # noqa: F811
    manifest = tmp_path / "egress.json"
    closings, clock = FakeClosings(), [0.0]

    def sleep(seconds):
        clock[0] += seconds
        closings.queue = [(None, closed("93.184.215.77", 8443)), (None, closed("140.82.112.3", 22, local_port=50001))]
    result = ew.learn(manifest, root=str(machine), seconds=2, clock=lambda: clock[0], sleep=sleep, closings=closings,
                      all_namespaces=True)
    assert result["brief_destinations_recorded"] == 1 and closings.closed
    value = ew.read(manifest)
    assert value["destinations"] == ["tcp/8443@93.184.215.0/24"], "the ssh connection was learned with its program"
    assert ew.judge_closed(value, ew.heard(closed("93.184.215.70", 8443))) == []
    assert ew.learn(manifest, root=str(machine), closings=closings)["brief_destinations_recorded"] == 0


def test_a_brief_finding_reaches_the_response_engine_as_an_address():
    connection = ew.heard(closed("93.184.215.77", 8443))
    report = dict(checked_at="2026-11-20T00:00:00Z", findings=ew.judge_closed(baseline(), connection))
    (signal,) = re_.egress_signals(report)
    assert signal.rule_id == "BRIEF_OUTBOUND_CONNECTION" and set(signal.entities["address"]) == {"93.184.215.77"}
    assert not signal.entities.get("process_id")


# ------------------------------------------------------------------ listening in other namespaces

def test_a_namespace_is_entered_only_while_its_process_is_still_in_it(tmp_path, monkeypatch):
    own = os.readlink("/proc/self/ns/net")
    with pytest.raises(OSError) as raised:
        cc._opened_inside("/", dict(id="net:[1]", pid=os.getpid()))
    assert raised.value.errno == errno.ESRCH and own == os.readlink("/proc/self/ns/net")

    made, tried = [], []

    def opened(root, space):
        tried.append(space["id"])
        if space["id"] == "net:[3]":
            raise OSError(errno.EPERM, "Operation not permitted")
        made.append(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
        return made[-1]
    monkeypatch.setattr(cc, "_opened_inside", opened)
    monkeypatch.setattr(cc, "_listen", lambda sock: sock)
    closings = cc.Closings.__new__(cc.Closings)
    closings.root, closings.gaps, closings.missed, closings.failed = "/", set(), 0, set()
    closings.sockets = {None: socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)}
    spaces = [dict(id="net:[2]", own=False, pid=2), dict(id="net:[3]", own=False, pid=3), dict(id="h", own=True)]
    closings.subscribe(spaces)
    closings.subscribe(spaces)
    assert sorted(n for n in closings.sockets if n) == ["net:[2]"] and tried == ["net:[2]", "net:[3]"], \
        "each opened once, and a refusal remembered rather than retried every scan"
    assert closings.gaps == {"closed connections in net:[3] cannot be heard: Operation not permitted"}
    closings.subscribe([dict(id="h", own=True)])
    assert list(closings.sockets) == [None] and made[0].fileno() == -1, "a namespace that is gone is let go"
    closings.close()


def test_without_root_the_gap_is_named(monkeypatch):
    real = socket.socket

    def refused(family=-1, *args, **kwargs):
        if family == socket.AF_NETLINK:
            raise PermissionError(errno.EPERM, "Operation not permitted")
        return real(family, *args, **kwargs)
    monkeypatch.setattr(cc.socket, "socket", refused)
    closings = cc.Closings()
    assert closings.sockets == {} and closings.drain() == []
    assert closings.gaps == {"closed connections cannot be heard here: run as root to see connections too short "
                             "for a scan"}
    closings.subscribe([dict(id="net:[2]", own=False, pid=2)])
    assert closings.sockets == {} and len(closings.gaps) == 1, "without this namespace's socket, no other is tried"


def test_announcements_lost_to_a_full_buffer_are_counted():
    class Burst:
        def __init__(self):
            self.reads = [OSError(errno.ENOBUFS, "No buffer space available"),
                          message(socket.AF_INET, "192.168.1.5", 41000, "93.184.215.14", 443), BlockingIOError()]

        def recv(self, size):
            item = self.reads.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
    closings = cc.Closings.__new__(cc.Closings)
    closings.sockets, closings.missed = {"net:[2]": Burst()}, 0
    (found,) = closings.drain()
    assert found[0] == "net:[2]" and found[1]["port"] == 443 and closings.missed == 1


@linux
@pytest.mark.skipif(os.geteuid() != 0, reason="the destroy announcements are root's")
def test_a_real_connection_is_heard_as_it_closes():
    closings = cc.Closings()
    assert None in closings.sockets, closings.gaps
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    client = socket.create_connection(server.getsockname())
    accepted, _ = server.accept()
    port, served = client.getsockname()[1], server.getsockname()[1]
    client.sendall(b"x" * 3000)
    accepted.recv(4096)
    client.close(), accepted.close(), server.close()
    deadline, heard = time.monotonic() + 3, []
    while time.monotonic() < deadline and not any(c["local_port"] == port for _, c in heard):
        time.sleep(0.02)
        heard += closings.drain()
    closings.close()
    (mine,) = [c for space, c in heard if c["local_port"] == port and space is None]
    assert mine["protocol"] == "tcp" and mine["port"] == served and 3000 <= mine["sent"] <= 3002, "SYN and FIN are counted too"


@linux
@pytest.mark.skipif(os.geteuid() != 0 or not os.path.exists("/usr/bin/unshare"), reason="needs root and unshare")
def test_a_real_namespace_is_listened_in_through_a_helper():
    holder = subprocess.Popen(["unshare", "--net", sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and os.readlink(f"/proc/{holder.pid}/ns/net") == \
                os.readlink("/proc/self/ns/net"):
            time.sleep(0.02)
        space = dict(id=os.readlink(f"/proc/{holder.pid}/ns/net"), own=False, pid=holder.pid)
        closings = cc.Closings()
        closings.subscribe([space])
        assert space["id"] in closings.sockets, closings.gaps
        assert os.readlink("/proc/self/ns/net") != space["id"], "this process never changed namespace"
        closings.close()
    finally:
        holder.kill()
        holder.wait()
