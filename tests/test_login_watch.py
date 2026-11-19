"""Login anomalies: successful logins, sudo and su that do not fit the learned baseline."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import struct

import pytest

from megalodon import login_watch as lw
from megalodon import response_engine as re_

# Ordinary, everyday log lines: an account logging in with its usual key from its usual network, and using sudo.
KEY = "SHA256:" + "A" * 43
HISTORY = "".join(
    f"2026-11-{day:02d}T{hour:02d}:15:00+00:00 host sshd[{100 + day}]: Accepted publickey for alice from "
    f"93.184.216.{10 + day % 3} port 50{day:03d} ssh2: ED25519 {KEY}\n"
    f"2026-11-{day:02d}T{hour:02d}:20:00+00:00 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
    f"COMMAND=/usr/bin/apt update\n"
    for day in range(1, 26) for hour in (9, 14))


def write(path, text):
    path.write_text(text)
    return str(path)


@pytest.fixture
def paths(tmp_path):
    return dict(manifest=tmp_path / "logins.json", cursor=tmp_path / "cursor.json",
                history=write(tmp_path / "history.log", HISTORY))


def rules(report):
    return sorted((f["rule_id"], f["user"]) for f in report["findings"])


def test_logins_that_fit_are_quiet_and_those_that_do_not_are_reported(paths, tmp_path):
    learned = lw.learn(paths["manifest"], logs=[paths["history"]], cursor=paths["cursor"])
    assert learned["events"] == 100 and learned["accounts"] == 1
    assert oct(paths["manifest"].stat().st_mode & 0o777) == "0o600"
    usual = write(tmp_path / "usual.log", HISTORY + "2026-11-27T09:15:00+00:00 host sshd[9]: Accepted publickey "
                  f"for alice from 93.184.216.12 port 50999 ssh2: ED25519 {KEY}\n")
    assert lw.check(paths["manifest"], logs=[usual], cursor=paths["cursor"])["findings"] == []
    new = write(tmp_path / "new.log", "".join([
        # alice, from a network she never used, with a key she never used, at 03:00
        "2026-11-28T03:05:00+00:00 host sshd[20]: Accepted publickey for alice from 45.33.32.7 port 40000 ssh2: "
        "ED25519 SHA256:" + "B" * 43 + "\n",
        # alice by password, when she always used a key
        "2026-11-28T09:30:00+00:00 host sshd[21]: Accepted password for alice from 93.184.216.11 port 40001 ssh2\n",
        # an account that never logged in, and root over the network
        "2026-11-28T10:00:00+00:00 host sshd[22]: Accepted publickey for bob from 93.184.216.11 port 40002 ssh2\n",
        "2026-11-28T10:01:00+00:00 host sshd[23]: Accepted password for root from 45.33.32.8 port 40003 ssh2\n",
        # a system account logging in
        "2026-11-28T10:02:00+00:00 host sshd[24]: Accepted password for daemon from 45.33.32.9 port 40004 ssh2\n",
        # sudo by someone who never used it, alice as a new target, and a new su
        "2026-11-28T10:03:00+00:00 host sudo:      bob : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh\n",
        "2026-11-28T10:04:00+00:00 host sudo:    alice : TTY=pts/0 ; PWD=/ ; USER=postgres ; COMMAND=/bin/psql\n",
        "2026-11-28T10:05:00+00:00 host su[25]: pam_unix(su-l:session): session opened for user root(uid=0) by "
        "alice(uid=1000)\n",
        # a failed sudo is not a use of sudo
        "2026-11-28T10:06:00+00:00 host sudo:      eve : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/ ; "
        "USER=root ; COMMAND=/bin/sh\n",
    ]))
    report = lw.check(paths["manifest"], logs=[new], cursor=paths["cursor"])
    assert rules(report) == [
        ("LOGIN_NEW_ACCOUNT", "bob"), ("LOGIN_NEW_KEY", "alice"), ("LOGIN_NEW_METHOD", "alice"),
        ("LOGIN_NEW_SOURCE", "alice"), ("LOGIN_ROOT_REMOTE", "root"), ("LOGIN_SERVICE_ACCOUNT", "daemon"),
        ("LOGIN_UNUSUAL_HOUR", "alice"), ("SUDO_FIRST_USE", "bob"), ("SUDO_NEW_TARGET", "alice"),
        ("SU_NEW", "alice")]
    assert report["findings"][0]["rule_id"] == "LOGIN_SERVICE_ACCOUNT" and report["findings"][0]["severity"] == \
        "CRITICAL"
    service = report["findings"][0]
    assert service["src_ip"] == "45.33.32.9" and service["techniques"] == ["T1078.003"]
    # The same lines again are not judged twice: the cursor moved past them.
    assert lw.check(paths["manifest"], logs=[new], cursor=paths["cursor"])["findings"] == []
    # Learning over reviewed logs accepts them.
    lw.learn(paths["manifest"], logs=[new], cursor=None)
    assert ("LOGIN_NEW_SOURCE", "alice") not in rules(lw.check(paths["manifest"], logs=[new], every=True,
                                                             cursor=None))


def test_a_new_network_inside_the_lan_is_lower_severity(paths, tmp_path):
    lw.learn(paths["manifest"], logs=[paths["history"]], cursor=None)
    lan = write(tmp_path / "lan.log", "2026-11-28T09:15:00+00:00 host sshd[30]: Accepted publickey for alice from "
                f"192.168.7.20 port 40100 ssh2: ED25519 {KEY}\n")
    found = lw.check(paths["manifest"], logs=[lan], cursor=None)["findings"]
    assert [(f["rule_id"], f["severity"]) for f in found] == [("LOGIN_NEW_SOURCE", "MEDIUM")]


def test_wtmp_is_read_when_there_is_no_text_log(tmp_path):
    def record(kind, user, line, host, seconds):
        return struct.pack(lw.UTMP_FORMAT, kind, 100, line.encode(), b"", user.encode(), host.encode(), 0, 0, 0,
                           seconds, 0, b"\0" * 16)
    stamp = int(datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc).timestamp())
    wtmp = tmp_path / "wtmp"
    wtmp.write_bytes(record(7, "alice", "pts/0", "93.184.216.10", stamp) + record(8, "", "pts/0", "", stamp + 60)
                     + record(7, "alice", "tty1", "", stamp + 120))
    events = lw.read_events([str(wtmp)])
    assert [(e["user"], e["source"], e["via"]) for e in events] == [("alice", "93.184.216.10", "ssh"),
                                                                     ("alice", None, "tty1")]


def test_findings_become_shadow_decisions(paths, tmp_path):
    lw.learn(paths["manifest"], logs=[paths["history"]], cursor=None)
    bad = write(tmp_path / "bad.log", "2026-11-28T10:02:00+00:00 host sshd[24]: Accepted password for daemon from "
                "45.33.32.9 port 40004 ssh2\n")
    signals = re_.login_signals(lw.check(paths["manifest"], logs=[bad], cursor=None))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decision = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    planned = {(a["action"], a["target"], a["status"]) for a in decision["actions"]}
    assert decision["playbook"] == "service-account-login"
    assert ("lock_account", "daemon", "would_apply") in planned
    assert ("block_address", "45.33.32.9", "would_apply") in planned


def test_cli_and_baseline_permissions(paths, tmp_path, capsys, monkeypatch):
    from megalodon.cli import main
    monkeypatch.setenv("HOME", str(tmp_path / "home"))       # the default read position lives under HOME

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    manifest = tmp_path / "cli.json"
    assert code("logins", "learn", "--manifest", str(manifest), "--log", paths["history"]) == 0
    assert code("logins", "check", "--manifest", str(manifest), "--log", paths["history"], "--all") == 0
    other = write(tmp_path / "other.log", "2026-11-28T10:00:00+00:00 host sshd[22]: Accepted publickey for bob "
                  "from 93.184.216.11 port 40002 ssh2\n")
    capsys.readouterr()
    assert code("logins", "check", "--manifest", str(manifest), "--log", other, "--all") == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "LOGIN_NEW_ACCOUNT"
    os.chmod(manifest, 0o644)
    assert code("logins", "check", "--manifest", str(manifest), "--log", other) == 2


def test_classic_syslog_lines_are_read_in_local_time(paths, tmp_path):
    # Classic lines carry no year or zone. They used to crash on a naive-versus-aware comparison.
    classic = write(tmp_path / "classic.log",
                    f"Nov 19 09:15:00 host sshd[40]: Accepted publickey for alice from 93.184.216.10 port 50001 "
                    f"ssh2: ED25519 {KEY}\n"
                    "Nov 19 09:20:00 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
                    "COMMAND=/usr/bin/apt update\n")
    reference = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
    events = lw.events_from_lines(Path(classic).read_text().splitlines(), reference=reference)
    assert [e["kind"] for e in events] == ["login", "sudo"]
    assert all(e["when"].tzinfo is not None and e["when"].year == 2026 for e in events)
    assert events[0]["when"].astimezone().replace(tzinfo=None) == datetime(2026, 11, 19, 9, 15)
    lw.learn(paths["manifest"], logs=[paths["history"]], cursor=None)
    assert lw.check(paths["manifest"], logs=[classic], cursor=paths["cursor"])["events"] == 2


def test_the_cursor_keeps_fractional_seconds(paths, tmp_path):
    lw.learn(paths["manifest"], logs=[paths["history"]], cursor=None)
    precise = write(tmp_path / "precise.log", "2026-11-28T10:00:00.123456+00:00 host sshd[50]: Accepted publickey "
                                              "for bob from 93.184.216.11 port 40002 ssh2\n")
    first = lw.check(paths["manifest"], logs=[precise], cursor=paths["cursor"])
    assert [f["rule_id"] for f in first["findings"]] == ["LOGIN_NEW_ACCOUNT"]
    for _ in range(2):          # the same unchanged log is not judged again
        again = lw.check(paths["manifest"], logs=[precise], cursor=paths["cursor"])
        assert again["events"] == 0 and again["findings"] == []
    # A cursor written before fractions were kept is still read.
    paths["cursor"].write_text(json.dumps(dict(schema=lw.SCHEMA + "-cursor", last="2026-11-28T09:59:59Z")))
    os.chmod(paths["cursor"], 0o600)
    assert lw.check(paths["manifest"], logs=[precise], cursor=paths["cursor"])["events"] == 1
