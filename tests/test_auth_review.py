from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path

import pytest

from megalodon.auth_review import (
    AuthReviewSettings, MAX_LINE_BYTES, read_lines, review,
)
from megalodon.validation import ValidationError

REF = datetime(2026, 11, 17, 23, 0, tzinfo=timezone.utc)
UTC = timezone.utc
ATTACKER = "203.0.113.5"


def run(lines, **kwargs):
    raw = [(line + "\n").encode() for line in lines]
    report, reviewer = review(raw, source="test", reference=REF, zone=UTC, **kwargs)
    return report, reviewer


def rules(report):
    return [item["rule_id"] for item in report["findings"]]


def ssh_fail(minute, second, user="root", ip=ATTACKER, pid=1000, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return (f"Nov 17 22:{minute:02d}:{second:02d} web sshd[{pid}]: Failed password for {who} "
            f"from {ip} port {40000 + second} ssh2")


def test_burst_then_success_is_the_critical_signal():
    lines = [ssh_fail(1, s * 5, pid=1000 + s) for s in range(6)]
    lines.append(f"Nov 17 22:03:00 web sshd[2000]: Accepted password for root from {ATTACKER} "
                 "port 50000 ssh2")
    report, _ = run(lines)
    assert rules(report) == ["AUTH_FAILURE_BURST", "AUTH_SUCCESS_AFTER_FAILURES"]
    critical = report["findings"][1]
    assert critical["severity"] == "CRITICAL"
    assert critical["evidence"]["prior_failures"] == 6
    assert critical["evidence"]["user"] == "root"
    assert report["observed"]["failed_logins"] == 6
    assert report["observed"]["successful_logins"] == 1
    assert report["top_failing_sources"] == [{"source": ATTACKER, "failures": 6}]


def test_a_few_typos_then_success_is_quiet():
    lines = [ssh_fail(1, 0, user="alice"), ssh_fail(1, 10, user="alice"),
             f"Nov 17 22:01:20 web sshd[3]: Accepted password for alice from {ATTACKER} port 1 ssh2"]
    report, _ = run(lines)
    assert report["findings"] == []


def test_invalid_user_pair_from_one_connection_counts_once():
    lines = []
    for i in range(5):
        lines.append(f"Nov 17 22:10:{i:02d} web sshd[{500 + i}]: Invalid user u{i} from {ATTACKER} port {i}")
        lines.append(ssh_fail(10, i, user=f"u{i}", pid=500 + i, invalid=True))
    report, _ = run(lines)
    assert report["observed"]["failed_logins"] == 5
    assert rules(report) == ["PASSWORD_SPRAY"]
    assert report["findings"][0]["evidence"]["distinct_users"] == 4
    assert report["findings"][0]["evidence"]["usernames_tried"] == ["u0", "u1", "u2", "u3"]


def test_repeat_guesses_on_one_connection_each_count():
    lines = [ssh_fail(20, s, pid=777) for s in range(6)]
    report, _ = run(lines)
    assert rules(report) == ["AUTH_FAILURE_BURST"]


def test_slow_failures_outside_window_do_not_burst():
    lines = [f"Nov 17 {h:02d}:00:00 web sshd[{h}]: Failed password for root from {ATTACKER} port 1 ssh2"
             for h in range(10, 20)]
    report, _ = run(lines)
    assert "AUTH_FAILURE_BURST" not in rules(report)


def test_cooldown_reports_a_long_attack_once_per_hour():
    lines = [ssh_fail(m, s, pid=m * 100 + s) for m in range(0, 30) for s in (0, 20, 40)]
    report, _ = run(lines)
    assert rules(report).count("AUTH_FAILURE_BURST") == 1


def test_sudo_failures_denials_and_account_changes():
    lines = [
        "Nov 17 22:30:00 web sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; "
        "PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        "Nov 17 22:31:00 web sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; "
        "USER=root ; COMMAND=/bin/bash",
        "Nov 17 22:32:00 web useradd[999]: new user: name=backdoor, UID=1002, GID=1002, "
        "home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0",
        "Nov 17 22:32:05 web usermod[1000]: add 'backdoor' to group 'sudo'",
        "Nov 17 22:32:05 web usermod[1000]: add 'backdoor' to shadow group 'sudo'",
        "Nov 17 22:33:00 web gpasswd[1100]: user eve added by root to group docker",
        "Nov 17 22:34:00 web usermod[1200]: add 'carol' to group 'audio'",
    ]
    report, _ = run(lines)
    assert rules(report) == ["SUDO_FAILURES", "SUDO_DENIED", "ACCOUNT_CREATED",
                             "PRIVILEGE_GRANT", "PRIVILEGE_GRANT"]
    grants = [f["evidence"] for f in report["findings"] if f["rule_id"] == "PRIVILEGE_GRANT"]
    assert grants == [{"user": "backdoor", "group": "sudo"}, {"user": "eve", "group": "docker"}]
    assert report["findings"][2]["evidence"] == {"user": "backdoor", "uid": 1002}


def test_iso_and_journalctl_timestamps_and_ipv6_mapped():
    lines = [f"2026-11-17T22:4{i}:00.123456+00:00 web sshd[{i}]: Failed password for root from "
             f"::ffff:{ATTACKER} port 1 ssh2" for i in range(3)]
    lines += [f"2026-11-17T22:4{i}:30+0000 web sshd[{i}]: Failed password for root from "
              f"{ATTACKER} port 1 ssh2" for i in range(3)]
    report, _ = run(lines)
    assert rules(report) == ["AUTH_FAILURE_BURST"]
    assert report["findings"][0]["subject"] == ATTACKER
    assert report["window"]["start"].startswith("2026-11-17T22:40:00.123456")


def test_classic_year_rolls_back_across_new_year():
    _, reviewer = review([b"Dec 31 23:59:59 web sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2\n"],
                         source="t", reference=datetime(2027, 1, 1, 0, 5, tzinfo=UTC), zone=UTC)
    assert reviewer.first.year == 2026


def test_hostile_usernames_are_bounded_data():
    evil = "\x1b[31mroot" + "A" * 500
    lines = [f"Nov 17 22:50:{i:02d} web sshd[{i}]: Invalid user {evil}{i} from {ATTACKER} port 1"
             for i in range(6)]
    report, _ = run(lines)
    for finding in report["findings"]:
        for user in finding["evidence"]["usernames_tried"]:
            assert len(user) <= 64 and "\x1b" not in user


def test_garbage_oversized_and_unrelated_lines_are_counted_not_fatal():
    lines = ["not a log line", "Nov 99 99:99:99 web sshd[1]: Failed password for root from 1.2.3.4 port 1",
             "Nov 17 22:00:00 web cron[5]: (root) CMD (run-parts /etc/cron.hourly)",
             "Nov 17 22:00:00 web sshd[1]: Failed password for root from not-an-ip port 1 ssh2",
             "x" * (MAX_LINE_BYTES + 10)]
    report, _ = run(lines)
    assert report["findings"] == []
    assert report["input"]["unrecognized_lines"] == 1
    assert report["input"]["invalid_timestamps"] == 1
    assert report["input"]["oversized_lines"] == 1
    assert report["network_access_performed"] is False


def test_attacker_sources_feed_a_watchlist():
    lines = [ssh_fail(1, s, pid=s) for s in range(6)]
    lines += [ssh_fail(2, s, ip="127.0.0.1", pid=100 + s) for s in range(6)]
    _, reviewer = run(lines)
    assert reviewer.attacker_sources() == [(ATTACKER, "auth-review AUTH_FAILURE_BURST")]


def test_large_single_source_attack_stays_bounded_and_fast():
    import time
    lines = (f"Nov 17 2{(i // 3600) % 3}:{(i // 60) % 60:02d}:{i % 60:02d} web sshd[{i}]: Failed password "
             f"for u{i % 50} from {ATTACKER} port 1 ssh2\n".encode() for i in range(60_000))
    started = time.monotonic()
    report, reviewer = review(lines, source="t", reference=REF, zone=UTC)
    assert time.monotonic() - started < 20
    state = reviewer.failures[ATTACKER]
    assert len(state.burst) <= 4096 and len(state.users) <= 4096
    assert report["observed"]["failed_logins"] == 60_000


def test_read_lines_refuses_fifo_symlink_and_directory(tmp_path):
    good = tmp_path / "auth.log"
    good.write_text(ssh_fail(1, 1) + "\n")
    assert list(read_lines(str(good)))
    link = tmp_path / "link.log"
    link.symlink_to(good)
    with pytest.raises(ValidationError, match="cannot be opened"):
        list(read_lines(str(link)))
    with pytest.raises(ValidationError, match="regular file"):
        list(read_lines(str(tmp_path)))
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValidationError, match="regular file"):
        list(read_lines(str(fifo)))


@pytest.mark.parametrize("field,value", [("failure_threshold", 1), ("spray_window_seconds", 0),
                                         ("cooldown_seconds", 90000), ("sudo_failure_threshold", True)])
def test_settings_are_bounded(field, value):
    with pytest.raises(ValueError):
        AuthReviewSettings(**{field: value})


def test_finding_cap_never_hides_a_later_attack():
    from megalodon.auth_review import MAX_FINDINGS
    lines = [f"Nov 17 20:{(i // 60) % 60:02d}:{i % 60:02d} web useradd[{i}]: new user: name=u{i}, UID={2000 + i}, GID=1"
             for i in range(MAX_FINDINGS + 20)]
    lines += [ssh_fail(10, s, pid=9000 + s) for s in range(6)]
    lines.append(f"Nov 17 22:11:00 web sshd[9999]: Accepted password for root from {ATTACKER} port 1 ssh2")
    report, reviewer = run(lines)
    assert report["truncated"] is True
    assert len(report["findings"]) == MAX_FINDINGS
    assert report["severity_counts"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": MAX_FINDINGS + 20, "LOW": 0}
    kept = [f["rule_id"] for f in report["findings"]]
    assert "AUTH_SUCCESS_AFTER_FAILURES" in kept and "AUTH_FAILURE_BURST" in kept
    stamps = [f["observed_at"] for f in report["findings"]]
    assert stamps == sorted(stamps), "retained findings stay chronological"
    assert reviewer.attacker_sources() == [(ATTACKER, "auth-review AUTH_FAILURE_BURST")]
