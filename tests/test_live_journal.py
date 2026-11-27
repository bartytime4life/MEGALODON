"""The auth log read from a real systemd journal: opt-in, with MEGALODON_TEST_LIVE_JOURNAL=1, on a machine where
journald runs and this user can read its auth messages (root, adm or systemd-journal).

Writes three neutral messages tagged with a random marker to the journal, through journald's syslog socket: one
each under the auth and authpriv facilities, which the auth log holds, and one under daemon, which it does not.
They then stay in that journal, as any logged line does. Nothing else is changed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import pytest

from megalodon import auth_review
from megalodon import response_engine as re_

SOCKET = "/run/systemd/journal/dev-log"
pytestmark = pytest.mark.skipif(
    os.environ.get("MEGALODON_TEST_LIVE_JOURNAL") != "1" or not os.path.exists(SOCKET)
    or shutil.which("logger") is None or not any(os.path.isfile(j) for j in auth_review.JOURNALCTL),
    reason="explicit live journal check: needs MEGALODON_TEST_LIVE_JOURNAL=1, a running journald and logger")


@pytest.fixture(scope="module")
def logged():
    """The marker, and the time just before its messages were written."""
    marker, before = uuid.uuid4().hex[:16], datetime.now(timezone.utc) - timedelta(seconds=2)
    for facility in ("auth.info", "authpriv.notice", "daemon.info"):
        subprocess.run(["logger", "--socket", SOCKET, "-p", facility, "-t", "megalodon-live-test",
                        f"placeholder {marker} {facility.split('.')[0]}"], check=True, timeout=30)
    for _ in range(50):                         # journald writes them a moment later
        notes = []
        if sum(marker.encode() in line for line in auth_review.read_journal(before, notes)) >= 2:
            break
        time.sleep(0.2)
    return marker, before


def ours(marker, lines):
    return [line for line in lines if marker.encode() in line]


def test_the_journals_auth_and_authpriv_messages_are_read_and_no_other(logged):
    marker, before = logged
    notes = []
    lines = ours(marker, auth_review.read_journal(before, notes))
    assert notes == [], "this user must see the journal's auth messages: run as root, or in adm or systemd-journal"
    assert sorted(line.rsplit(b" ", 1)[-1].strip() for line in lines) == [b"auth", b"authpriv"]


def test_a_real_journal_line_is_one_auth_review_reads_with_its_time_to_the_microsecond(logged):
    marker, before = logged
    lines = ours(marker, auth_review.read_journal(before, []))
    _, reviewer = auth_review.review(lines, source="journal")
    assert reviewer.stats["lines"] == 2
    assert reviewer.stats["unrecognized_lines"] == 0 and reviewer.stats["invalid_timestamps"] == 0
    assert before <= reviewer.first <= datetime.now(timezone.utc), "read in UTC, as written"
    assert reviewer.first.microsecond or reviewer.last.microsecond, "short-iso-precise keeps the fraction"


def test_the_response_engine_reads_the_real_journal_without_a_gap(logged, tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text()
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    lines = [f'{line.split("=")[0].strip()} = ""' if line.split("=")[0].strip().endswith(("_manifest", "_file", "_db"))
             else line for line in text.splitlines()]
    text = "\n".join('auth_log = "journal"' if line.startswith("auth_log = ") else line for line in lines)
    policy.write_text(text + "\n")
    result = re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
                     protected=set(), now=datetime.now(timezone.utc))
    assert not [gap for gap in result["gaps"] if gap.startswith("auth")], result["gaps"]
    assert '"auth_cursor"' in Path(tmp_path / "state.json").read_text()
