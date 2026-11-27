"""The SSH agent lure against a real sshd: opt-in, with MEGALODON_TEST_LIVE_SSHD=1, as root on a machine where
journald runs and sshd, ssh and sshpass are installed.

Plants an agent lure, runs sshd in the foreground from a temporary folder on a free loopback port (a throwaway host
key, passwords only, no PAM), and tries one password login as the lure's account, which this machine does not have.
sshd's own messages about it go through syslog to the journal, where they stay like any logged line; the test reads
them back with journalctl and checks auth-review and the response engine on them. sshd is stopped and the folder
removed after. Nothing is sent off this machine.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

from megalodon import auth_review
from megalodon import canary
from megalodon import response_engine as re_

SSHD, LOG_SOCKET = "/usr/sbin/sshd", "/dev/log"


def _usable():
    return (os.path.isfile(SSHD) and all(shutil.which(tool) for tool in ("ssh", "sshpass", "ssh-keygen", "logger"))
            and os.path.exists(LOG_SOCKET) and os.path.exists("/run/systemd/journal/socket")
            and hasattr(os, "geteuid") and os.geteuid() == 0)


pytestmark = pytest.mark.skipif(
    os.environ.get("MEGALODON_TEST_LIVE_SSHD") != "1" or not _usable(),
    reason="explicit live sshd check: needs MEGALODON_TEST_LIVE_SSHD=1, root, a running journald with /dev/log, "
           "and sshd, ssh and sshpass")

CONFIG = """Port {port}
ListenAddress 127.0.0.1
HostKey {base}/host_key
PidFile {base}/sshd.pid
UsePAM no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
PermitRootLogin no
AuthorizedKeysFile none
StrictModes no
SyslogFacility AUTH
LogLevel INFO
"""


def _port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def tried():
    base = Path(tempfile.mkdtemp(prefix="megalodon-live-sshd-", dir="/tmp"))
    made_privsep = not os.path.isdir("/run/sshd")
    try:
        bait = base / "bait"
        bait.mkdir()
        manifest = base / "canary.json"
        [account] = canary.plant(str(bait), str(manifest), count=1, lure=True)["lure_accounts"]
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(base / "host_key")], check=True,
                       timeout=60)
        port = _port()
        (base / "sshd_config").write_text(CONFIG.format(port=port, base=base))
        if made_privsep:
            os.makedirs("/run/sshd", mode=0o755)
        before = datetime.now(timezone.utc) - timedelta(seconds=2)
        server = subprocess.Popen([SSHD, "-D", "-f", str(base / "sshd_config")], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                pytest.fail("sshd did not start")
            # One password attempt as the lure's account, with a password made up here: the attempt the lure watches for.
            attempt = subprocess.run(
                ["sshpass", "-p", secrets.token_hex(8), "ssh", "-p", str(port), "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
                 "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10",
                 "-o", "LogLevel=ERROR", f"{account}@127.0.0.1", "true"],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
            lines = []
            for _ in range(50):                 # sshd and journald write a moment later
                lines = [line for line in auth_review.read_journal(before, []) if account.encode() in line]
                if any(b"Failed password" in line for line in lines):
                    break
                time.sleep(0.2)
        finally:
            server.terminate()
            server.wait(timeout=30)
        yield dict(account=account, manifest=manifest, lines=lines, refused=attempt.returncode != 0, base=base,
                   bait=bait)
    finally:
        shutil.rmtree(base, ignore_errors=True)
        if made_privsep:
            shutil.rmtree("/run/sshd", ignore_errors=True)


def test_sshd_refused_the_lure_account_and_logged_it_to_the_journal(tried):
    assert tried["refused"], "the lure's account does not exist, so the login must fail"
    assert tried["lines"], "sshd's messages about the attempt reach the journal's auth messages"


def test_auth_review_reads_sshds_own_lines_and_reports_the_lure_followed(tried):
    report, reviewer = auth_review.review(tried["lines"], source="journal", lure_users=[tried["account"]])
    assert reviewer.stats["unrecognized_lines"] == 0 and reviewer.stats["failed_logins"] >= 1
    lured = [f for f in report["findings"] if f["rule_id"] == "LURE_FOLLOWED"]
    assert lured and lured[0]["evidence"] == dict(source="127.0.0.1", user=tried["account"], outcome="refused",
                                                  accepted=False)


@pytest.mark.parametrize("form", [b"Invalid user ", b"Failed password for invalid user "])
def test_each_of_sshds_messages_alone_reports_the_lure_followed(tried, form):
    """sshd writes both for one attempt, and they count once; each is read on its own too."""
    lines = [line for line in tried["lines"] if form in line]
    assert lines, f"sshd wrote a {form.decode().strip()!r} line"
    report, reviewer = auth_review.review(lines, source="journal", lure_users=[tried["account"]])
    assert reviewer.stats["failed_logins"] == 1
    assert [f["evidence"]["source"] for f in report["findings"] if f["rule_id"] == "LURE_FOLLOWED"] == ["127.0.0.1"]


def test_the_response_engine_decides_it_from_the_real_journal(tried, tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text()
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    keep = {"canary_manifest": str(tried["manifest"]), "auth_log": "journal", "web_log": ""}
    lines = []
    for line in text.splitlines():
        name = line.split("=")[0].strip()
        if name in keep:
            line = f"{name} = {json.dumps(keep[name])}"
        elif name.endswith(("_manifest", "_file", "_db")):
            line = f'{name} = ""'
        lines.append(line)
    policy.write_text("\n".join(lines) + "\n")
    ledger = tmp_path / "ledger.jsonl"
    result = re_.run(policy_path=policy, ledger=ledger, state_path=tmp_path / "state.json", protected=set(),
                     now=datetime.now(timezone.utc))
    assert not [gap for gap in result["gaps"] if gap.startswith(("auth", "canary"))], result["gaps"]
    decided = [json.loads(line) for line in ledger.read_text().splitlines()]
    [decision] = [d for d in decided if d["signal"]["rule_id"] == "LURE_FOLLOWED"
                  and tried["account"] in d["signal"]["summary"]]
    assert decision["playbook"] == "lure-followed" and decision["signal"]["source"] == "auth"
    assert decision["signal"]["summary"].startswith(
        f"127.0.0.1 tried {tried['account']}, the account {canary.LURE_NAME} names")
    assert [a["status"] for a in decision["actions"] if a["action"] == "block_address"] == ["refused"], (
        "a loopback address is never blocked")
