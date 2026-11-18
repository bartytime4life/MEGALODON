"""Persistence watch over a throwaway folder tree: baseline, change detection, manifest safety, CLI."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from megalodon import persistence_watch as pw


def key_line(seed, comment):
    blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + bytes([seed]) * 36).decode()
    return f"ssh-ed25519 {blob} {comment}\n"


def put(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def tree(tmp_path):
    root, home = tmp_path / "root", tmp_path / "home"
    put(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n")
    put(root / "etc/crontab", "# system crontab\n")
    put(root / "etc/systemd/system/example.service", "[Service]\nExecStart=/usr/bin/true\n")
    put(root / "usr/bin/tool", "binary placeholder\n", 0o755)
    put(home / ".bashrc", "export EDITOR=vi\n")
    put(home / ".ssh/authorized_keys", key_line(1, "me@laptop"), 0o600)
    options = dict(root=str(root), home=str(home), setuid_dirs=("/usr/bin",))
    return root, home, options, tmp_path / "manifest.json"


def check(manifest, options):
    return {(f["change"], f["category"], f["location"]): f for f in pw.check(manifest, **options)["findings"]}


def test_an_unchanged_system_reports_nothing(tree):
    _, _, options, manifest = tree
    summary = pw.baseline(manifest, **options)
    assert summary["entries"] >= 4 and summary["accounts"] == 2
    assert oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert pw.check(manifest, **options)["findings"] == []


def test_each_kind_of_change_is_found_with_its_technique(tree):
    root, home, options, manifest = tree
    pw.baseline(manifest, **options)
    put(root / "etc/cron.d/added-job", "*/5 * * * * root /usr/bin/true\n")
    put(home / ".config/autostart/added.desktop", "[Desktop Entry]\nType=Application\nExec=/usr/bin/true\n")
    put(home / ".config/systemd/user/added.service", "[Service]\nExecStart=/usr/bin/true\n")
    put(home / ".bashrc", "export EDITOR=vi\nexport ADDED=1\n")
    put(home / ".ssh/authorized_keys", key_line(1, "me@laptop") + key_line(2, "new-key"), 0o600)
    put(root / "etc/ld.so.preload", "/usr/lib/placeholder.so\n")
    (root / "usr/bin/tool").chmod(0o4755)
    put(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/var/lib/svc:/bin/bash\n"
                              "second:x:0:0::/home/second:/bin/bash\n")
    (root / "etc/systemd/system/example.service").unlink()
    found = check(manifest, options)
    expect = {
        ("added", "cron", "/etc/cron.d/added-job"): ("MEDIUM", "T1053.003"),
        ("added", "autostart", "~/.config/autostart/added.desktop"): ("MEDIUM", "T1547.013"),
        ("added", "systemd", "~/.config/systemd/user/added.service"): ("MEDIUM", "T1543.002"),
        ("changed", "shell_startup", "~/.bashrc"): ("MEDIUM", "T1546.004"),
        ("changed", "ssh", "~/.ssh/authorized_keys"): ("CRITICAL", "T1098.004"),
        ("added", "preload", "/etc/ld.so.preload"): ("CRITICAL", "T1574.006"),
        ("added", "setuid", "/usr/bin/tool"): ("HIGH", "T1548.001"),
        ("added", "account", "second"): ("CRITICAL", "T1136.001"),
        ("changed", "account", "svc"): ("HIGH", "T1136.001"),
        ("removed", "systemd", "/etc/systemd/system/example.service"): ("LOW", "T1543.002"),
    }
    for key, (severity, technique) in expect.items():
        assert key in found, key
        assert (found[key]["severity"], found[key]["technique"]) == (severity, technique), key
    keys = found[("changed", "ssh", "~/.ssh/authorized_keys")]["detail"]["keys_added"]
    assert [k["comment"] for k in keys] == ["new-key"] and keys[0]["fingerprint"].startswith("SHA256:")
    assert found[("changed", "shell_startup", "~/.bashrc")]["detail"]["lines"] == [1, 2]
    report = pw.check(manifest, **options)
    assert report["findings"][0]["severity"] == "CRITICAL", "most severe first"
    assert "ADDED=1" not in json.dumps(report), "file contents are never copied"


def test_accept_records_the_reviewed_state(tree):
    root, _, options, manifest = tree
    pw.baseline(manifest, **options)
    put(root / "etc/cron.d/reviewed", "# reviewed\n")
    assert check(manifest, options)
    assert pw.accept(manifest, **options)["action"] == "accept"
    assert pw.check(manifest, **options)["findings"] == []


def test_links_are_recorded_not_followed(tree):
    root, _, options, manifest = tree
    pw.baseline(manifest, **options)
    link = root / "etc/systemd/system/multi-user.target.wants/example.service"
    link.parent.mkdir(parents=True)
    os.symlink("/etc/systemd/system/example.service", link)
    found = check(manifest, options)
    item = found[("added", "systemd", "/etc/systemd/system/multi-user.target.wants/example.service")]
    assert item["detail"] == {"kind": "link", "target": "/etc/systemd/system/example.service"}


def test_unreadable_locations_are_reported_as_gaps(tree):
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    root, _, options, manifest = tree
    locked = root / "etc/sudoers.d"
    locked.mkdir(parents=True)
    locked.chmod(0)
    try:
        gaps = pw.baseline(manifest, **options)["gaps"]
    finally:
        locked.chmod(0o755)
    assert {"category": "sudoers", "location": "/etc/sudoers.d/*"} in gaps


def test_the_baseline_file_must_be_private(tree):
    _, _, options, manifest = tree
    pw.baseline(manifest, **options)
    with pytest.raises(pw.PersistenceError, match="exists"):
        pw.baseline(manifest, **options)
    manifest.chmod(0o644)
    with pytest.raises(pw.PersistenceError, match="mode-600"):
        pw.check(manifest, **options)
    with pytest.raises(pw.PersistenceError, match="no persistence baseline"):
        pw.check(Path(str(manifest) + ".missing"), **options)
    os.mkfifo(str(manifest) + ".fifo", 0o600)
    with pytest.raises(pw.PersistenceError):
        pw.check(Path(str(manifest) + ".fifo"), **options)


def test_cli_exit_codes(tree, monkeypatch, capsys):
    root, _, options, manifest = tree
    real = pw.snapshot
    monkeypatch.setattr(pw, "snapshot", lambda **kw: real(**options))
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("persistence", "check", "--manifest", str(manifest)) == 2
    assert code("persistence", "baseline", "--manifest", str(manifest)) == 0
    assert code("persistence", "check", "--manifest", str(manifest)) == 0
    put(root / "etc/cron.d/new", "# new\n")
    capsys.readouterr()
    assert code("persistence", "check", "--manifest", str(manifest)) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["category"] == "cron"
