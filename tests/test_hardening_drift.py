"""Hardening drift: weakened review checks, file capabilities and root's search path, from a stand-in root."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct

import pytest

from megalodon import hardening_drift as hd
from megalodon import response_engine as re_


def cap_value(*bits, effective=True):
    permitted = sum(1 << b for b in bits)
    return struct.pack("<IIIII", 0x02000000 | int(effective), permitted & 0xFFFFFFFF, 0, permitted >> 32, 0)


SETUID, NET_RAW, BPF = 7, 13, 39


def reviewer(states):
    def review(root):
        return dict(checks=[dict(id=k, title=k.replace("_", " "), state=s, observed=o) for k, (s, o) in states.items()])
    return review


GOOD = dict(ptrace_scope=("pass", "1"), ssh_root_login=("pass", "prohibit-password"), auto_updates=("pass", "on"))


@pytest.fixture
def root(tmp_path, monkeypatch):
    # The account running the tests stands in for root: on CI it is an ordinary user.
    monkeypatch.setattr(hd, "TRUSTED_UID", os.getuid())
    monkeypatch.setattr(hd, "TRUSTED_GID", os.getgid())
    base = tmp_path / "root"
    for folder in ("usr/local/bin", "usr/bin", "opt/tools", "etc/sudoers.d"):
        (base / folder).mkdir(parents=True)
    os.chmod(base, 0o755)
    (base / "usr/bin/tool").write_text("")
    os.chmod(base / "usr/bin/tool", 0o755)
    (base / "etc/environment").write_text('PATH="/usr/local/bin:/usr/bin:/opt/tools"\n')
    (base / "etc/sudoers").write_text('Defaults\tsecure_path="/usr/local/bin:/usr/bin"\n')
    return base


def rules(report):
    return sorted((f["severity"], f["rule_id"], f["subject"]) for f in report["findings"])


def test_capability_values_are_decoded():
    assert hd.capabilities(cap_value(SETUID, BPF)) == (["BPF", "SETUID"], True)
    assert hd.capabilities(cap_value(NET_RAW, effective=False)) == (["NET_RAW"], False)
    assert hd.capabilities(struct.pack("<III", 0x01000001, 1 << SETUID, 0)) == (["SETUID"], True)   # version 1
    assert hd.capabilities(b"\x00" * 4) is None


def test_weakened_checks_and_a_writable_search_path(root, tmp_path):
    manifest = tmp_path / "hardening.json"
    first = hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    assert first["findings"] == [] and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert hd.check(manifest, review=reviewer(GOOD), budget=30)["findings"] == []
    weaker = dict(GOOD, ptrace_scope=("fail", "0"), ssh_root_login=("fail", "yes"), auto_updates=("review", "off"))
    os.chmod(root / "opt/tools", 0o777)                         # anyone can plant a program root will run
    os.chmod(root / "usr/bin/tool", 0o777)                      # anyone can change a program root runs
    (root / "etc/sudoers.d/dev").write_text('Defaults secure_path="/usr/bin:."\n')
    report = hd.check(manifest, review=reviewer(weaker), budget=30)
    assert rules(report) == [
        ("CRITICAL", "PATH_FOLDER_WRITABLE", "file:/opt/tools"), ("CRITICAL", "PROGRAM_WRITABLE", "file:/usr/bin/tool"),
        ("HIGH", "HARDENING_WEAKENED", "hardening:ptrace_scope"),
        ("HIGH", "HARDENING_WEAKENED", "hardening:ssh_root_login"),
        ("HIGH", "PATH_HAS_RELATIVE_ENTRY", "path:."),
        ("MEDIUM", "HARDENING_WEAKENED", "hardening:auto_updates")]
    weakened = next(f for f in report["findings"] if f["subject"] == "hardening:ptrace_scope")
    assert weakened["detail"] == "ptrace scope: 1 → 0 (pass → fail)"
    hd.accept(manifest, review=reviewer(weaker), budget=30)
    assert hd.check(manifest, review=reviewer(weaker), budget=30)["findings"] == []


def test_a_folder_above_a_search_path_folder_counts(root, tmp_path):
    manifest = tmp_path / "hardening.json"
    hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    os.chmod(root / "opt", 0o777)                               # whoever can rename /opt/tools can swap it
    assert rules(hd.check(manifest, review=reviewer(GOOD), budget=30)) == [
        ("CRITICAL", "PATH_FOLDER_WRITABLE", "file:/opt")]


def _can_set_capabilities(path):
    try:
        os.setxattr(path, "security.capability", cap_value(NET_RAW))
        return True
    except OSError:
        return False


def test_file_capabilities_that_lead_to_root(root, tmp_path):
    probe = root / "usr/bin/tool"
    if not _can_set_capabilities(probe):
        pytest.skip("setting file capabilities needs root and a file system that keeps them")
    manifest = tmp_path / "hardening.json"
    first = hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    assert first["findings"] == [] and first["file_capabilities"] == 1      # an ordinary ping-like capability
    (root / "tmp").mkdir()
    for path, bits in (("usr/bin/python3.12", (SETUID,)), ("tmp/x", (BPF,)), ("usr/local/bin/backup", (2,)),
                       ("usr/bin/mtr-packet", (NET_RAW,))):
        (root / path).write_text("")
        os.setxattr(root / path, "security.capability", cap_value(*bits))
    report = hd.check(manifest, review=reviewer(GOOD), budget=30)
    assert rules(report) == [
        ("CRITICAL", "FILE_CAPABILITY_BACKDOOR", "file:/tmp/x"),
        ("CRITICAL", "FILE_CAPABILITY_BACKDOOR", "file:/usr/bin/python3.12"),
        ("HIGH", "FILE_CAPABILITY_ADDED", "file:/usr/local/bin/backup"),
        ("MEDIUM", "FILE_CAPABILITY_CHANGED", "file:/usr/bin/mtr-packet")]
    assert next(f for f in report["findings"] if f["subject"] == "file:/usr/bin/python3.12")["detail"] == \
        "/usr/bin/python3.12 holds cap_setuid+ep"
    # A back door already there when the baseline is taken is reported then, not recorded as normal.
    again = hd.baseline(tmp_path / "second.json", root=str(root), review=reviewer(GOOD), budget=30)
    assert [f["subject"] for f in again["findings"]] == ["file:/tmp/x", "file:/usr/bin/python3.12"]


def test_findings_become_shadow_decisions_and_the_cli(root, tmp_path, capsys, monkeypatch):
    manifest = tmp_path / "hardening.json"
    hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    os.chmod(root / "opt/tools", 0o777)
    report = hd.check(manifest, review=reviewer(dict(GOOD, ssh_root_login=("fail", "yes"))), budget=30)
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=re_.hardening_signals(report), protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert len(decisions) == 2 and {d["playbook"] for d in decisions} == {"hardening-drift"}
    from megalodon.cli import main
    from megalodon import hardening_review
    monkeypatch.setattr(hardening_review, "review", reviewer(dict(GOOD, ssh_root_login=("fail", "yes"))))
    with pytest.raises(SystemExit) as exit_:
        main(["hardening", "check", "--manifest", str(manifest)])
    assert exit_.value.code == 1
    assert {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]} == {
        "PATH_FOLDER_WRITABLE", "HARDENING_WEAKENED"}
