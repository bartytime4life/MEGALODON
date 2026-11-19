"""Credential access: unexpected readers of keys, browser stores, tokens and shadow, live and at a glance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from megalodon import credential_watch as cw
from megalodon import response_engine as re_

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")


@pytest.fixture
def home(tmp_path):
    base = tmp_path / "home"
    for path, text in ((".ssh/id_ed25519", "placeholder key\n"), (".ssh/id_ed25519.pub", "public\n"),
                       (".ssh/known_hosts", "host\n"), (".aws/credentials", "[default]\n"),
                       (".mozilla/firefox/abc.default/logins.json", "{}"), (".bitcoin/wallet.dat", "w")):
        (base / path).parent.mkdir(parents=True, exist_ok=True)
        (base / path).write_text(text)
    return base


def info(path, argv=None, start=1000, deleted=False):
    return dict(path=path, deleted=deleted, argv=argv or [path], start=start, cwd="/")


def test_what_counts_as_a_credential(home):
    watched = cw.patterns([str(home)])
    assert cw.classify(str(home / ".ssh/id_ed25519"), watched) == "ssh"
    assert cw.classify(str(home / ".ssh/id_ed25519.pub"), watched) is None, "public keys are not secrets"
    assert cw.classify(str(home / ".ssh/known_hosts"), watched) is None
    assert cw.classify(str(home / ".mozilla/firefox/abc.default/logins.json"), watched) == "browser"
    assert cw.classify("/etc/shadow", watched) == "system"
    files, folders = cw.targets(watched)
    assert str(home / ".ssh/id_ed25519") in files and str(home / ".ssh/id_ed25519.pub") not in files
    assert str(home / ".ssh") in folders, "folders are watched for keys created later"


def test_expected_readers_impostors_dropped_tools_and_sweeps(home):
    judge = cw.Judge(own_pid=1)
    key, aws, wallet = str(home / ".ssh/id_ed25519"), str(home / ".aws/credentials"), str(home / ".bitcoin/wallet.dat")
    assert judge.judge(10, info("/usr/bin/ssh"), key, "ssh", 0) == []
    assert judge.judge(11, info("/usr/bin/python3.12", ["aws", "/usr/bin/aws", "s3", "ls"]), aws, "cloud", 0) == []
    # A program called ssh, but not where packages install programs.
    impostor = judge.judge(12, info("/home/u/.local/bin/ssh"), key, "ssh", 0)
    assert [(f["rule_id"], f["severity"]) for f in impostor] == [("CREDENTIAL_READ", "HIGH")]
    # A dropped tool, and the same tool going on to a second kind of credential.
    first = judge.judge(13, info("/tmp/.x/update"), key, "ssh", 1)
    assert [f["rule_id"] for f in first] == ["CREDENTIAL_READ_BY_DROPPED_TOOL"] and first[0]["severity"] == "CRITICAL"
    second = judge.judge(13, info("/tmp/.x/update"), wallet, "wallet", 2)
    assert [f["rule_id"] for f in second] == ["CREDENTIAL_SWEEP", "CREDENTIAL_READ_BY_DROPPED_TOOL"]
    assert set(second[0]["files"]) == {key, wallet}
    assert [f["rule_id"] for f in judge.judge(13, info("/tmp/.x/update"), aws, "cloud", 3)] == [
        "CREDENTIAL_READ_BY_DROPPED_TOOL"], "one sweep per process"
    # A script in /tmp run by an installed interpreter is a dropped tool too.
    staged = judge.judge(14, info("/usr/bin/python3.12", ["python3", "/tmp/s.py"]), key, "ssh", 4)
    assert staged[0]["rule_id"] == "CREDENTIAL_READ_BY_DROPPED_TOOL"
    assert judge.judge(12, info("/home/u/.local/bin/ssh"), key, "ssh", 5) == [], "once an hour per program and file"
    assert judge.judge(1, info("/tmp/x"), key, "ssh", 6) == [], "MEGALODON's own process"


def test_allow_list_is_owner_only_and_respected(home, tmp_path):
    allow = tmp_path / "allow.json"
    assert cw.allow(allow, "/usr/bin/rsync", "any") == 1 and oct(allow.stat().st_mode & 0o777) == "0o600"
    judge = cw.Judge(cw._load_allow(allow), own_pid=1)
    assert judge.judge(20, info("/usr/bin/rsync"), str(home / ".ssh/id_ed25519"), "ssh", 0) == []
    with pytest.raises(cw.CredentialError, match="category"):
        cw.allow(allow, "/usr/bin/rsync", "everything")
    os.chmod(allow, 0o666)
    with pytest.raises(cw.CredentialError, match="writable only by you"):
        cw._load_allow(allow)


def test_check_finds_credentials_held_open(home, tmp_path):
    root = tmp_path / "root"
    for pid, exe, opened in ((300, "/usr/bin/ssh", home / ".ssh/id_ed25519"),
                             (301, "/dev/shm/collector", home / ".mozilla/firefox/abc.default/logins.json")):
        base = root / f"proc/{pid}"
        (base / "fd").mkdir(parents=True)
        os.symlink(exe, base / "exe")
        os.symlink(opened, base / "fd/3")
        (base / "cmdline").write_bytes(exe.encode() + b"\0")
        (base / "stat").write_text(f"{pid} (x) S 1 " + " ".join(["0"] * 17) + " 4242 0 0\n")
    report = cw.check(root=str(root), home_dirs=[str(home)], allow_path=None)
    assert [(f["rule_id"], f["program"]) for f in report["findings"]] == [
        ("CREDENTIAL_READ_BY_DROPPED_TOOL", "/dev/shm/collector")]
    assert report["findings"][0]["evidence"]["processes"] == [{"program": "/dev/shm/collector", "pid": 301,
                                                               "start": 4242}]


@linux
def test_a_live_reader_is_caught_as_it_opens(home, tmp_path):
    collector = tmp_path / "collect.py"      # a script in a temporary folder: a dropped tool
    collector.write_text("import sys, time\n"
                         "held = [open(p) for p in sys.argv[1:]]\n"
                         "time.sleep(1.0)\n")
    found = []
    watcher = cw.Watcher(found.append, home_dirs=[str(home)], allow_path=None)
    stop = threading.Event()
    worker = threading.Thread(target=watcher.run, args=(stop,), kwargs=dict(timeout=0.05), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        subprocess.run([sys.executable, str(collector), str(home / ".ssh/id_ed25519"),
                        str(home / ".aws/credentials")], check=True)
        time.sleep(0.5)
    finally:
        stop.set()
        worker.join(5)
        watcher.close()
    rules = {f["rule_id"] for f in found if str(collector) in f["program"]}
    assert {"CREDENTIAL_READ_BY_DROPPED_TOOL", "CREDENTIAL_SWEEP"} <= rules, (watcher.mode, watcher.stats)


def test_findings_become_targeted_shadow_decisions(home, tmp_path):
    judge = cw.Judge(own_pid=1)
    judge.judge(400, info("/tmp/.x/update", start=777), str(home / ".ssh/id_ed25519"), "ssh", 0)
    sweep = judge.judge(400, info("/tmp/.x/update", start=777), str(home / ".aws/credentials"), "cloud", 1)[0]
    signals, refused = re_.ingest_signals([json.dumps(sweep)], re_._now())
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decision = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    assert refused == 0 and decision["playbook"] == "credential-theft"
    assert ("suspend_process", "400@777:/tmp/.x/update", "would_apply") in {
        (a["action"], a["target"], a["status"]) for a in decision["actions"]}


def test_cli_allow(tmp_path, capsys):
    from megalodon.cli import main
    with pytest.raises(SystemExit) as exit_:
        main(["credentials", "allow", "--allow-file", str(tmp_path / "a.json"), "/usr/bin/restic",
              "--category", "any"])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["allowed"] == 1


@linux
def test_without_fanotify_a_reader_still_holding_the_file_is_named(home, tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError(1, "fanotify needs root")
    monkeypatch.setattr(cw, "Fanotify", unavailable)
    collector = tmp_path / "hold.py"
    collector.write_text("import sys, time\nheld = open(sys.argv[1])\ntime.sleep(1.0)\n")
    found = []
    watcher = cw.Watcher(found.append, home_dirs=[str(home)], allow_path=None)
    assert watcher.mode.startswith("inotify")
    stop = threading.Event()
    worker = threading.Thread(target=watcher.run, args=(stop,), kwargs=dict(timeout=0.05), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        subprocess.run([sys.executable, str(collector), str(home / ".bitcoin/wallet.dat")], check=True)
        time.sleep(0.3)
    finally:
        stop.set()
        worker.join(5)
        watcher.close()
    assert any(f["rule_id"] == "CREDENTIAL_READ_BY_DROPPED_TOOL" and f["category"] == "wallet" for f in found), \
        watcher.stats
