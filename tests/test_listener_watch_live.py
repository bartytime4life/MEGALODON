"""`listeners watch`: each change reported once while it lasts, and, as root, listeners that open and close between
two checks, heard as the kernel announces them closing."""
from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import sys
import time

import pytest

from megalodon import cli
from megalodon import listener_watch as lw
from test_listener_watch import BASE_PROCESSES, BASE_SOCKETS, fake_proc

root_only = pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0,
                               reason="hearing closed sockets needs root on Linux")


class Closings:
    """Closed sockets as `closed_connections.Closings.drain` gives them."""
    def __init__(self):
        self.items, self.gaps, self.missed = [], set(), 0

    def closed(self, port, local="0.0.0.0", address="0.0.0.0", remote=0, protocol="tcp", space=None):
        self.items.append((space, dict(protocol=protocol, family=4, local=ipaddress.ip_address(local),
                                       local_port=port, address=ipaddress.ip_address(address), port=remote,
                                       sent=0, received=0)))

    def drain(self):
        out, self.items = self.items, []
        return out

    def filenos(self):
        return []

    def subscribe(self, spaces):
        pass

    def close(self):
        pass


def watcher(tmp_path, closings=None, clock=None, warned=None):
    root = fake_proc(tmp_path / "root", BASE_SOCKETS, BASE_PROCESSES)
    manifest = tmp_path / "listeners.json"
    lw.baseline(manifest, root=root, all_namespaces=False)
    found = []
    watch = lw.Watcher(manifest, found.append, root=root, closings=closings, all_namespaces=False,
                       clock=clock or time.monotonic, warn=(warned.append if warned is not None else lambda t: None))
    return watch, found


def test_a_change_is_reported_once_while_it_lasts_and_again_when_it_returns(tmp_path):
    watch, found = watcher(tmp_path)
    assert watch.poll() == []
    shell = fake_proc(tmp_path / "shell", BASE_SOCKETS + [("tcp", "0.0.0.0", 4444, "0A", 900)],
                      {**BASE_PROCESSES, 900: ("/usr/bin/dash", "sh", [900])})
    plain = watch.root
    watch.root = shell
    first = watch.poll()
    assert [(f["rule_id"], f["listener"], f["severity"]) for f in first] == [("NEW_LISTENER", "tcp:4444", "HIGH")]
    assert watch.poll() == [], "not again while it lasts"
    watch.root = plain
    watch.poll()
    watch.root = shell
    assert [f["listener"] for f in watch.poll()] == ["tcp:4444"], "again once it closed and came back"
    assert all("detected_at" in f for f in found) and len(found) == 2


def test_a_listener_that_opened_and_closed_between_checks_is_heard(tmp_path):
    closings = Closings()
    watch, found = watcher(tmp_path, closings)       # before any check: only the baseline is known
    closings.closed(4444)
    closings.closed(4445, local="127.0.0.1")                          # loopback only
    closings.closed(50001, address="198.51.100.7", remote=443)         # a connection, not a listener
    closings.closed(22)                                               # sshd restarting: in the baseline
    closings.closed(0)                                                # never bound to a port
    closings.closed(5353, protocol="udp")
    heard = watch.hear()
    assert [(f["rule_id"], f["listener"], f["severity"], f["addresses"], f["programs"]) for f in heard] == [
        ("LISTENER_OPENED_AND_CLOSED", "tcp:4444", "MEDIUM", ["0.0.0.0:4444"], [])]
    assert heard[0]["techniques"] == ["T1571"] and found == heard


def test_a_listener_a_check_already_saw_is_not_reported_again_when_it_closes(tmp_path):
    closings = Closings()
    watch, found = watcher(tmp_path, closings)
    watch.root = fake_proc(tmp_path / "web", BASE_SOCKETS + [("tcp", "0.0.0.0", 8080, "0A", 900)],
                           {**BASE_PROCESSES, 900: ("/usr/bin/python3", "python3", [900])})
    assert [f["listener"] for f in watch.poll()] == ["tcp:8080"]
    closings.closed(8080)
    assert watch.hear() == []


def test_each_brief_listener_once_in_a_while_and_a_limit_an_hour(tmp_path):
    now, warned = [0.0], []
    closings = Closings()
    watch, _found = watcher(tmp_path, closings, clock=lambda: now[0], warned=warned)
    closings.closed(4444)
    closings.closed(4444)
    assert len(watch.hear()) == 1, "the same port twice at once"
    now[0] = lw.CLOSED_COOLDOWN_SECONDS + 1
    closings.closed(4444)
    assert len(watch.hear()) == 1, "and again after the cooldown"
    for port in range(20000, 20000 + lw.MAX_CLOSED_PER_HOUR + 5):
        closings.closed(port)
    assert len(watch.hear()) == lw.MAX_CLOSED_PER_HOUR - 2
    assert watch.stats["capped"] == 7 and len([w for w in warned if "brief listeners in an hour" in w]) == 1
    now[0] += 3600
    closings.closed(30000)
    assert len(watch.hear()) == 1, "the limit is per hour"


def test_a_brief_listener_in_a_container(tmp_path):
    closings = Closings()
    watch, _found = watcher(tmp_path, closings)
    watch.spaces = {"net:[4026532300]": "docker:3f2a"}
    closings.closed(4444, space="net:[4026532300]")
    assert watch.hear() == [], "a baseline that never read other namespaces has nothing to compare with"
    watch.baseline["all_namespaces"] = True
    closings.closed(4444, space="net:[4026532300]")
    heard = watch.hear()
    assert [(f["listener"], f["where"]) for f in heard] == [("container/tcp:4444", ["docker:3f2a"])]


def test_the_watch_command_needs_a_baseline(tmp_path, capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["listeners", "watch", "--manifest", str(tmp_path / "none.json")])
    assert stopped.value.code == 2 and "listeners baseline" in capsys.readouterr().err


@root_only
def test_a_real_listener_opened_and_closed_between_checks_is_heard(tmp_path):
    manifest = tmp_path / "listeners.json"
    lw.baseline(manifest)
    watch = lw.Watcher(manifest, lambda f: None, warn=lambda t: None)
    try:
        watch.poll()
        server = socket.socket()
        server.bind(("0.0.0.0", 0))
        server.listen(1)
        port = server.getsockname()[1]
        server.close()
        deadline = time.monotonic() + 3
        heard = []
        while time.monotonic() < deadline and not heard:
            select.select(watch.closings.filenos(), [], [], 0.2)
            heard = [f for f in watch.hear() if f["port"] == port]
        assert [(f["rule_id"], f["listener"]) for f in heard] == [("LISTENER_OPENED_AND_CLOSED", f"tcp:{port}")]
        print(json.dumps(heard[0]))
    finally:
        watch.closings.close()
