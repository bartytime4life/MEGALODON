"""Login review against a real sshd: opt-in, with MEGALODON_TEST_LIVE_SSHD=1, as root on a machine where journald
runs and sshd, ssh and sshpass are installed.

sshd runs in the foreground from a temporary folder on a free loopback port, with a throwaway host key and no PAM.
sshd's own messages go through syslog to the journal, where they stay like any logged line; the tests read them back
with journalctl and check auth-review and the response engine on them. Two things are tried:

* the SSH agent lure: one password login as the lure's account, which this machine does not have;
* a login let in after refused ones: five wrong passwords for `nobody`, then a login as `nobody` with a throwaway key
  that only this sshd accepts. `nobody`'s shell refuses to run anything, so the login does nothing.

The clients read none of this machine's SSH settings. sshd is stopped and the folders removed after. No account,
password or key of this machine is used or changed, and nothing is sent off this machine.
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import pwd
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
GUESSED = "nobody"                  # an account every system has, whose shell runs nothing
FAILURES = auth_review.AuthReviewSettings().success_min_failures


def _usable():
    try:
        pwd.getpwnam(GUESSED)
    except KeyError:
        return False
    return (os.path.isfile(SSHD) and all(shutil.which(tool) for tool in ("ssh", "sshpass", "ssh-keygen", "logger"))
            and os.path.exists(LOG_SOCKET) and os.path.exists("/run/systemd/journal/socket")
            and hasattr(os, "geteuid") and os.geteuid() == 0)


pytestmark = pytest.mark.skipif(
    os.environ.get("MEGALODON_TEST_LIVE_SSHD") != "1" or not _usable(),
    reason="explicit live sshd check: needs MEGALODON_TEST_LIVE_SSHD=1, root, a running journald with /dev/log, "
           "sshd, ssh and sshpass, and the nobody account")

CONFIG = """Port {port}
ListenAddress 127.0.0.1
HostKey {base}/host_key
PidFile {base}/sshd.pid
UsePAM no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication {pubkey}
AuthorizedKeysFile {keys}
PermitRootLogin no
StrictModes no
SyslogFacility AUTH
LogLevel INFO
"""
# Newer sshd refuses an address for a while after failed logins; the guessed login must still reach it.
NO_PENALTIES = "PerSourcePenalties no\n"
CLIENT = ["ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
          "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]


def _port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def privsep():
    """sshd's privilege separation folder, made for the run if this machine has none, and removed after."""
    made = not os.path.isdir("/run/sshd")
    if made:
        os.makedirs("/run/sshd", mode=0o755)
    try:
        yield
    finally:
        if made:
            shutil.rmtree("/run/sshd", ignore_errors=True)


@contextlib.contextmanager
def _sshd(base, *, keys=None):
    """sshd on a free loopback port, run from `base`; with `keys`, it accepts those keys too."""
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(base / "host_key")], check=True,
                   timeout=60)
    port = _port()
    config = base / "sshd_config"
    config.write_text(CONFIG.format(port=port, base=base, pubkey="yes" if keys else "no", keys=keys or "none"))
    with open(config, "a") as more:
        more.write(NO_PENALTIES)
    if subprocess.run([SSHD, "-t", "-f", str(config)], capture_output=True, timeout=60).returncode:
        config.write_text(config.read_text().replace(NO_PENALTIES, ""))   # an sshd that has no such setting
    server = subprocess.Popen([SSHD, "-D", "-f", str(config)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("sshd did not start")
        yield port
    finally:
        server.terminate()
        server.wait(timeout=30)


def _password(port, user):
    """One password login as `user`, with a password made up here."""
    return subprocess.run(
        ["sshpass", "-p", secrets.token_hex(8), *CLIENT, "-p", str(port), "-o", "PreferredAuthentications=password",
         "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", f"{user}@127.0.0.1", "true"],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=60)


def _journal(start, wanted, done):
    """The journal's auth lines written since `start` that `wanted` keeps, once `done` holds of them."""
    def since_start(line):
        # journalctl is asked from the second before; each line's own time, to the microsecond, keeps out a run
        # just before this one.
        try:
            return datetime.fromisoformat(line.split(b" ", 1)[0].decode()) >= start
        except ValueError:
            return False
    lines = []
    for _ in range(50):                     # sshd and journald write a moment later
        lines = [line for line in auth_review.read_journal(start - timedelta(seconds=2), [])
                 if since_start(line) and wanted(line)]
        if done(lines):
            break
        time.sleep(0.2)
    return lines


def _policy(tmp_path, manifest=""):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text()
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    keep = {"canary_manifest": manifest, "auth_log": "journal", "web_log": ""}
    lines = []
    for line in text.splitlines():
        name = line.split("=")[0].strip()
        if name in keep:
            line = f"{name} = {json.dumps(keep[name])}"
        elif name.endswith(("_manifest", "_file", "_db")):
            line = f'{name} = ""'
        lines.append(line)
    policy.write_text("\n".join(lines) + "\n")
    return policy


def _decide(tmp_path, manifest=""):
    ledger = tmp_path / "ledger.jsonl"
    result = re_.run(policy_path=_policy(tmp_path, manifest), ledger=ledger, state_path=tmp_path / "state.json",
                     protected=set(), now=datetime.now(timezone.utc))
    return result, [json.loads(line) for line in ledger.read_text().splitlines()]


@pytest.fixture(scope="module")
def tried(privsep):
    base = Path(tempfile.mkdtemp(prefix="megalodon-live-sshd-", dir="/tmp"))
    try:
        bait = base / "bait"
        bait.mkdir()
        manifest = base / "canary.json"
        [account] = canary.plant(str(bait), str(manifest), count=1, lure=True)["lure_accounts"]
        start = datetime.now(timezone.utc)
        with _sshd(base) as port:
            # One password attempt as the lure's account: the attempt the lure watches for.
            attempt = _password(port, account)
            lines = _journal(start, lambda line: account.encode() in line,
                             lambda lines: any(b"Failed password" in line for line in lines))
        yield dict(account=account, manifest=manifest, lines=lines, refused=attempt.returncode != 0)
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture(scope="module")
def guessed(privsep):
    """Five wrong passwords for `nobody`, then a login as `nobody` with a key only this sshd accepts."""
    base = Path(tempfile.mkdtemp(prefix="megalodon-live-sshd-", dir="/tmp"))
    try:
        # sshd reads the accepted keys as `nobody`: the folder and the file are set readable outright, whatever the
        # umask. The key is made here, for this sshd alone.
        base.chmod(0o755)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(base / "client_key")], check=True,
                       timeout=60)
        keys = base / "authorized_keys"
        shutil.copyfile(base / "client_key.pub", keys)
        keys.chmod(0o644)
        start = datetime.now(timezone.utc)
        with _sshd(base, keys=keys) as port:
            refused = [_password(port, GUESSED) for _ in range(FAILURES)]
            let_in = subprocess.run(
                [*CLIENT, "-p", str(port), "-i", str(base / "client_key"), "-o", "IdentitiesOnly=yes",
                 "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                 f"{GUESSED}@127.0.0.1", "true"],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
            ours = f" for {GUESSED} from 127.0.0.1 port ".encode()
            lines = _journal(start, lambda line: ours in line,
                             lambda lines: any(b"Accepted publickey" in line for line in lines))
        yield dict(lines=lines, refused=[r.returncode != 0 for r in refused], let_in=let_in)
    finally:
        shutil.rmtree(base, ignore_errors=True)


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
    result, decided = _decide(tmp_path, str(tried["manifest"]))
    assert not [gap for gap in result["gaps"] if gap.startswith(("auth", "canary"))], result["gaps"]
    [decision] = [d for d in decided if d["signal"]["rule_id"] == "LURE_FOLLOWED"
                  and tried["account"] in d["signal"]["summary"]]
    assert decision["playbook"] == "lure-followed" and decision["signal"]["source"] == "auth"
    assert decision["signal"]["summary"].startswith(
        f"127.0.0.1 tried {tried['account']}, the account {canary.LURE_NAME} names")
    assert [a["status"] for a in decision["actions"] if a["action"] == "block_address"] == ["refused"], (
        "a loopback address is never blocked")


def test_sshd_refused_the_wrong_passwords_and_let_the_key_in(guessed):
    assert guessed["refused"] == [True] * FAILURES
    assert sum(b"Failed password for " in line for line in guessed["lines"]) == FAILURES
    [accepted] = [line for line in guessed["lines"] if b"Accepted publickey for " in line]
    assert b"sshd" in accepted
    # Let in, and then refused by the account's shell: nothing ran.
    assert guessed["let_in"].returncode != 0


def test_auth_review_reports_the_login_let_in_after_refused_ones(guessed):
    report, reviewer = auth_review.review(guessed["lines"], source="journal")
    assert reviewer.stats["unrecognized_lines"] == 0
    assert (reviewer.stats["failed_logins"], reviewer.stats["successful_logins"]) == (FAILURES, 1)
    [finding] = [f for f in report["findings"] if f["rule_id"] == "AUTH_SUCCESS_AFTER_FAILURES"]
    assert finding["severity"] == "CRITICAL"
    evidence = finding["evidence"]
    assert (evidence["source"], evidence["user"], evidence["method"], evidence["prior_failures"]) == (
        "127.0.0.1", GUESSED, "publickey", FAILURES)


def test_one_refused_login_fewer_is_not_reported(guessed):
    """The same real lines with the first refused login left out: below the threshold, so nothing to report."""
    first = next(i for i, line in enumerate(guessed["lines"]) if b"Failed password for " in line)
    report, reviewer = auth_review.review(guessed["lines"][:first] + guessed["lines"][first + 1:], source="journal")
    assert (reviewer.stats["failed_logins"], reviewer.stats["successful_logins"]) == (FAILURES - 1, 1)
    assert not [f for f in report["findings"] if f["rule_id"] == "AUTH_SUCCESS_AFTER_FAILURES"]


def test_the_response_engine_decides_the_guessed_login_from_the_real_journal(guessed, tmp_path):
    result, decided = _decide(tmp_path)
    assert not [gap for gap in result["gaps"] if gap.startswith("auth")], result["gaps"]
    [decision] = [d for d in decided if d["signal"]["rule_id"] == "AUTH_SUCCESS_AFTER_FAILURES"
                  and f"Login as {GUESSED} via publickey" in d["signal"]["summary"]]
    assert decision["playbook"] == "guessed-login" and decision["signal"]["source"] == "auth"
    assert decision["signal"]["severity"] == "CRITICAL"
    assert GUESSED in decision["signal"]["entities"]["account"], "the account let in is linked"
    assert [a["status"] for a in decision["actions"] if a["action"] == "block_address"] == ["refused"], (
        "a loopback address is never blocked")
