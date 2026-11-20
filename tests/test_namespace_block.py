"""An address a container calls is blocked inside the container's own network namespace, not on this machine."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from megalodon import egress_watch as ew
from megalodon import enforcement as en
from megalodon import response_engine as re_
from test_enforcement import decide, enable, enforce, p  # noqa: F401
from test_net_namespaces import CONTAINER_NS, machine, plant  # noqa: F401

REMOTE = "93.184.215.66"


class Recorder:
    """Stands in for nft: records each command; the table is missing at first in every namespace."""

    def __init__(self):
        self.ran, self.tables = [], set()

    def __call__(self, argv, data=None):
        self.ran.append(list(argv))
        where = argv[1] if argv[0] == "nsenter" else "host"
        rest = argv[2:] if argv[0] == "nsenter" else argv
        if rest[:3] == ["nft", "list", "table"] and where not in self.tables:
            return SimpleNamespace(returncode=1, stdout="", stderr="No such file or directory")
        if rest[:2] == ["nft", "-f"]:
            self.tables.add(where)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def container_finding(machine, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine), all_namespaces=True)
    plant(machine, 301, 950, "/tmp/.cache/x", (REMOTE, 4444))
    return ew.check(manifest, root=str(machine))


def test_a_container_s_destination_is_planned_inside_its_namespace(machine, tmp_path):
    report = container_finding(machine, tmp_path)
    signals = re_.egress_signals(report)
    assert all(s.entities["namespace_address"] == {f"{REMOTE}@{CONTAINER_NS}"} for s in signals)
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    dropped = next(d for d in decisions if d["playbook"] == "dropped-tool-phoning-home")
    [block] = [a for a in dropped["actions"] if a["action"] == "block_address"]
    assert (block["target"], block["status"]) == (f"{REMOTE}@{CONTAINER_NS}", "would_apply")


@pytest.mark.parametrize("target,why", [
    (f"{REMOTE}@{CONTAINER_NS}", None),
    (f"172.17.0.9@{CONTAINER_NS}", "not a public address"),
    (f"{REMOTE}@net:[x]", "not an address"),
    (f"203.0.113.300@{CONTAINER_NS}", "not an address"),
])
def test_the_address_guards_apply_inside_a_namespace_too(tmp_path, target, why):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    guards = re_.Guards(re_.load_policy(policy), {}, re_._now(), protected=set())
    found = guards.check("block_address", target)
    assert (found is None) if why is None else (why in found)


def test_never_touch_and_this_machine_s_own_addresses_hold_inside_a_namespace(tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    policy.write_text(policy.read_text().replace("never_touch_addresses = []", f'never_touch_addresses = ["{REMOTE}/32"]'))
    guards = re_.Guards(re_.load_policy(policy), {}, re_._now(), protected=set())
    assert "never_touch_addresses" in guards.check("block_address", f"{REMOTE}@{CONTAINER_NS}")
    # This machine's DNS server, blocked inside a container, would cut the container's name lookups.
    dns = "9.9.9.9"
    guards = re_.Guards(re_.load_policy(tmp_path / "policy.toml"), {}, re_._now(), protected={dns})
    assert "gateway, DNS server or own address" in guards.check("block_address", f"{dns}@{CONTAINER_NS}")


def test_the_block_is_made_and_undone_in_that_namespace_only(machine, p):
    commands = Recorder()
    executor = en.Executor(root=str(machine), run=commands, quarantine=p["quarantine"])
    decision = dict(playbook="dropped-tool-phoning-home", actions=[dict(target=f"{REMOTE}@{CONTAINER_NS}", minutes=15)])
    undo = executor.block_address(f"{REMOTE}@{CONTAINER_NS}", decision)
    entry = f"--net={machine}/proc/300/ns/net"
    assert all(command[:2] == ["nsenter", entry] for command in commands.ran), "nothing runs on this machine's own table"
    assert commands.ran[-1][2:] == ["nft", "add", "element", "inet", "megalodon", "blocked_v4", "{", REMOTE,
                                    "timeout", "900s", "}"]
    assert (undo["set"], undo["address"], undo["namespace"]) == ("blocked_v4", REMOTE, CONTAINER_NS)
    commands.ran.clear()
    executor.undo_block_address(dict(target=f"{REMOTE}@{CONTAINER_NS}", undo=undo))
    assert commands.ran == [["nsenter", entry, "nft", "delete", "element", "inet", "megalodon", "blocked_v4",
                             "{", REMOTE, "}"]]


def test_a_namespace_that_is_gone_is_refused_and_its_undo_is_done(machine, p):
    commands = Recorder()
    executor = en.Executor(root=str(machine), run=commands, quarantine=p["quarantine"])
    os.remove(machine / "proc/300/ns/net")
    with pytest.raises(en.EnforcementError, match="is gone"):
        executor.block_address(f"{REMOTE}@{CONTAINER_NS}", dict(playbook="x", actions=[]))
    executor.undo_block_address(dict(target=f"{REMOTE}@{CONTAINER_NS}",
                                     undo=dict(set="blocked_v4", address=REMOTE, namespace=CONTAINER_NS)))
    assert commands.ran == [], "nothing to undo: the block went with the namespace"


def test_a_host_address_is_still_blocked_on_this_machine(machine, p):
    commands = Recorder()
    executor = en.Executor(root=str(machine), run=commands, quarantine=p["quarantine"])
    executor.block_address(REMOTE, dict(playbook="x", actions=[]))
    assert commands.ran[-1][:4] == ["nft", "add", "element", "inet"] and "nsenter" not in commands.ran[-1]


live = pytest.mark.skipif(not (sys.platform.startswith("linux") and os.geteuid() == 0 and shutil.which("nft")
                               and shutil.which("unshare") and shutil.which("nsenter")),
                          reason="needs root, nft, unshare and nsenter")


@live
def test_a_real_namespace_gets_the_block_and_this_machine_does_not(p):
    if subprocess.run(["nft", "list", "table", "inet", "megalodon"], capture_output=True).returncode == 0:
        pytest.skip("this machine already has MEGALODON's table; the test must not touch it")
    inside = subprocess.Popen(["unshare", "--net", "sleep", "30"])
    try:
        for _ in range(50):
            space = os.readlink(f"/proc/{inside.pid}/ns/net")
            if space != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.02)
        executor = en.Executor(quarantine=p["quarantine"])
        undo = executor.block_address(f"{REMOTE}@{space}", dict(playbook="x", actions=[]))
        listed = subprocess.run(["nsenter", f"--net=/proc/{inside.pid}/ns/net", "nft", "list", "set", "inet",
                                 "megalodon", "blocked_v4"], capture_output=True, text=True).stdout
        assert REMOTE in listed
        assert subprocess.run(["nft", "list", "table", "inet", "megalodon"], capture_output=True).returncode != 0, \
            "this machine's own table was never created"
        executor.undo_block_address(dict(target=f"{REMOTE}@{space}", undo=undo))
        listed = subprocess.run(["nsenter", f"--net=/proc/{inside.pid}/ns/net", "nft", "list", "set", "inet",
                                 "megalodon", "blocked_v4"], capture_output=True, text=True).stdout
        assert REMOTE not in listed
    finally:
        inside.kill()
        inside.wait()


def test_a_way_in_that_left_the_namespace_is_not_used(machine, p, monkeypatch):
    """The process the namespace was found through is checked again just before nsenter uses it."""
    from megalodon import net_namespaces as nn
    commands = Recorder()
    executor = en.Executor(root=str(machine), run=commands, quarantine=p["quarantine"])
    found = nn.namespaces(str(machine))
    # Found in the container's namespace; by the time it is used, PID 300 is a process somewhere else.
    monkeypatch.setattr(nn, "namespaces", lambda root: found)
    os.remove(machine / "proc/300/ns/net")
    os.symlink("net:[4026539999]", machine / "proc/300/ns/net")
    with pytest.raises(en.EnforcementError, match="is gone"):
        executor.block_address(f"{REMOTE}@{CONTAINER_NS}", dict(playbook="x", actions=[]))
    assert commands.ran == []


def test_a_piped_finding_from_a_namespace_is_blocked_there():
    [signal], _ = re_.ingest_signals([json.dumps(dict(rule_id="X", severity="HIGH", dst_ip=REMOTE,
                                                      namespace=CONTAINER_NS))], re_._now())
    assert signal.entities["namespace_address"] == {f"{REMOTE}@{CONTAINER_NS}"} and not signal.entities["address"]
