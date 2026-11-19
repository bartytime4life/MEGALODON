"""Known-vulnerable software: pending security fixes joined to exposed services, kernels and code not yet restarted."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time

import pytest

from megalodon import vuln_check as vc
from test_process_network import proc, row, tables  # noqa: F401

APT = """NOTE: This is only a simulation!
Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst libgcc-s1:i386 [12.3.0-1] (12.3.0-2 Debian-Security:12/stable-security [i386])
Inst docker-ce [5:27.0.1-1] (5:27.1.0-1 Docker CE:jammy [amd64])
Conf libssl3 (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64])
"""
DNF = """FEDORA-2026-1a2b3c Important/Sec. openssl-libs-1:3.1.4-2.fc41.x86_64
FEDORA-2026-4d5e6f Moderate/Sec.  kernel-6.11.4-301.fc41.x86_64
"""


def runner(text):
    calls = []

    def run(argv):
        calls.append(argv)
        return text, ''
    run.calls = calls
    return run


def test_update_lists_are_read():
    found = vc.apt_updates(APT)
    assert sorted(found) == ["docker-ce", "libgcc-s1:i386", "libssl3"]
    assert found["libssl3"]["security"] and found["libgcc-s1:i386"]["security"] and not found["docker-ce"]["security"]
    assert (found["libssl3"]["arch"], found["libgcc-s1:i386"]["arch"]) == ("amd64", "i386")
    assert found["libssl3"]["available"] == "3.0.2-0ubuntu1.12"
    found = vc.dnf_updates(DNF)
    assert sorted(found) == ["kernel", "openssl-libs"] and found["openssl-libs"]["severity"] == "Important"


def maps(root, pid, *paths):
    (root / f"proc/{pid}/maps").write_text("".join(
        f"7f00{i:04x}000-7f00{i:04x}fff r-xp 00000000 08:01 {100 + i} {p}\n" for i, p in enumerate(paths)))


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "root"
    (root / "var/lib/dpkg/info").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text("")
    # dpkg lists /lib/...; a merged-/usr system runs it from /usr/lib/...
    (root / "var/lib/dpkg/info/libssl3:amd64.list").write_text("/lib/x86_64-linux-gnu/libssl.so.3\n")
    (root / "var/lib/dpkg/info/nginx-core.list").write_text("/usr/sbin/nginx\n")
    (root / "var/lib/dpkg/info/cron.list").write_text("/usr/sbin/cron\n")
    (root / "var/lib/apt/lists").mkdir(parents=True)
    (root / "var/lib/apt/lists/archive_dists_jammy_InRelease").write_text("")
    tables(root, tcp=[row(("0.0.0.0", 443), ("0.0.0.0", 0), "0A", 801),
                      row(("127.0.0.1", 8080), ("0.0.0.0", 0), "0A", 802)])
    proc(root, 300, "/usr/sbin/nginx", [801])                           # reachable from anywhere
    maps(root, 300, "/usr/sbin/nginx", "/usr/lib/x86_64-linux-gnu/libssl.so.3")
    proc(root, 301, "/usr/local/bin/admin", [802])                      # loopback only
    maps(root, 301, "/usr/lib/x86_64-linux-gnu/libssl.so.3")
    proc(root, 302, "/usr/sbin/cron", [])                               # updated, not restarted
    maps(root, 302, "/usr/sbin/cron", "/usr/lib/x86_64-linux-gnu/libpam.so.0 (deleted)")
    (root / "boot").mkdir()
    for version in ("6.1.0-9-amd64", "6.1.0-10-amd64"):
        (root / f"boot/vmlinuz-{version}").write_text("")
    return root


def rules(report):
    return [(f["severity"], f["rule_id"], f["subject"]) for f in report["findings"]]


def test_an_exposed_service_with_a_waiting_fix_comes_first(host):
    run = runner(APT)
    report = vc.check(str(host), run=run, release="6.1.0-9-amd64")
    assert run.calls == [["apt-get", "-s", "-o", "Debug::NoLocking=true", "-o", "APT::Get::Show-Versions=true",
                          "dist-upgrade"]], "a simulation: nothing installed, no lock taken"
    assert rules(report) == [
        ("CRITICAL", "VULNERABLE_EXPOSED_SERVICE", "process:300"),
        ("HIGH", "KERNEL_FIX_NOT_RUNNING", "kernel"),
        ("HIGH", "SECURITY_UPDATES_PENDING", "packages:apt"),
        ("MEDIUM", "FIX_NOT_RUNNING", "process:302")]
    exposed = report["findings"][0]
    assert exposed["listening"] == ["0.0.0.0:443"] and exposed["packages"] == ["libssl3"]
    assert "running 6.1.0-9-amd64, installed 6.1.0-10-amd64" in report["findings"][1]["detail"]
    assert report["security_updates"] == 2 and report["updates"] == 3
    assert "libpam.so.0" in report["findings"][3]["detail"]


def test_a_restart_due_on_an_exposed_service_stale_lists_and_a_requested_reboot(host):
    maps(host, 300, "/usr/sbin/nginx", "/usr/lib/x86_64-linux-gnu/libz.so.1 (deleted)")
    old = time.time() - 10 * 86400
    os.utime(host / "var/lib/apt/lists/archive_dists_jammy_InRelease", (old, old))
    (host / "run").mkdir()
    (host / "run/reboot-required").write_text("*** System restart required ***\n")
    (host / "run/reboot-required.pkgs").write_text("linux-image-6.1.0-10-amd64\nlibc6\n")
    report = vc.check(str(host), run=runner(""), release="6.1.0-10-amd64")
    assert rules(report) == [
        ("HIGH", "KERNEL_FIX_NOT_RUNNING", "kernel"), ("HIGH", "FIX_NOT_RUNNING_EXPOSED", "process:300"),
        ("MEDIUM", "PACKAGE_LISTS_STALE", "packages:apt"), ("MEDIUM", "FIX_NOT_RUNNING", "process:302")]
    assert "a reboot was asked for by libc6, linux-image-6.1.0-10-amd64" in report["findings"][0]["detail"]
    assert "listens on 0.0.0.0:443" in report["findings"][1]["detail"]


def test_dnf_hosts_and_a_clean_machine(tmp_path, host):
    root = tmp_path / "fedora"
    (root / "proc").mkdir(parents=True)
    report = vc.check(str(root), run=runner(DNF), release="6.11.4-301.fc41.x86_64")
    assert report["manager"] == "dnf" and rules(report) == [("HIGH", "SECURITY_UPDATES_PENDING", "packages:dnf")]
    clean = vc.check(str(host), run=runner(""), release="6.1.0-10-amd64")
    assert rules(clean) == [("MEDIUM", "FIX_NOT_RUNNING", "process:302")], "only the program not yet restarted"


def test_the_cli(host, capsys, monkeypatch):
    from megalodon.cli import main
    real = vc.check
    monkeypatch.setattr(vc, "check", lambda: real(str(host), run=runner(APT), release="6.1.0-10-amd64"))
    with pytest.raises(SystemExit) as exit_:
        main(["vulns", "check"])
    assert exit_.value.code == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "VULNERABLE_EXPOSED_SERVICE"


def test_another_architectures_fix_and_replaced_data_files_are_not_reported(host):
    # Only the i386 copy of libssl3 has a fix waiting; nginx loads the amd64 one.
    (host / "var/lib/dpkg/info/libssl3:i386.list").write_text("/lib/i386-linux-gnu/libssl.so.3\n")
    foreign = ("Inst libssl3:i386 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [i386])\n")
    # A replaced locale archive is data, mapped read-only; it needs no restart.
    (host / "proc/300/maps").write_text(
        "7f0000000000-7f0000000fff r-xp 00000000 08:01 100 /usr/sbin/nginx\n"
        "7f0000001000-7f0000001fff r-xp 00000000 08:01 101 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
        "7f0000002000-7f0000002fff r--p 00000000 08:01 102 /usr/lib/locale/locale-archive (deleted)\n")
    report = vc.check(str(host), run=runner(foreign), release="6.1.0-10-amd64")
    assert rules(report) == [("HIGH", "SECURITY_UPDATES_PENDING", "packages:apt"),
                             ("MEDIUM", "FIX_NOT_RUNNING", "process:302")]
    assert report["findings"][0]["packages"] == ["libssl3:i386"]
    # The same service loading the i386 library is reported.
    (host / "proc/300/maps").write_text("7f0000000000-7f0000000fff r-xp 00000000 08:01 100 "
                                        "/usr/lib/i386-linux-gnu/libssl.so.3\n")
    exposed = vc.check(str(host), run=runner(foreign), release="6.1.0-10-amd64")["findings"][0]
    assert (exposed["rule_id"], exposed["packages"]) == ("VULNERABLE_EXPOSED_SERVICE", ["libssl3:i386"])
