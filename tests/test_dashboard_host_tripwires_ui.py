"""Shipped tripwire panel exercised with real reviews, real canaries and an inert DOM."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import canary, host_tripwires
from megalodon.dashboard_host_tripwires import HOST_TRIPWIRES_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_CSS, SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_JS

NOW = lambda: "2026-11-17T23:00:00Z"
ATTACKER = "198.51.100.23"


def _home(tmp_path, name, *, plant=0):
    home = tmp_path / name
    (home / ".config/megalodon").mkdir(parents=True)
    if plant:
        bait = home / "bait"
        bait.mkdir()
        canary.plant(str(bait), str(home / host_tripwires.MANIFEST), count=plant)
    return home


def _log(path, attack):
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    lines = []
    if attack:
        lines += [f"{(start + timedelta(seconds=i)).isoformat()} web sshd[{i}]: Failed password for root "
                  f"from {ATTACKER} port {i} ssh2" for i in range(8)]
        lines.append(f"{(start + timedelta(seconds=20)).isoformat()} web sshd[99]: Accepted password for "
                     f"root from {ATTACKER} port 9 ssh2")
    else:
        lines.append(f"{start.isoformat()} web sshd[1]: Accepted publickey for alice from 192.168.1.5 port 1 ssh2")
    path.write_text("\n".join(lines) + "\n")
    return str(path)


@pytest.fixture
def reviews(tmp_path):
    home = _home(tmp_path, "tripped", plant=3)
    bait = home / "bait"
    with open(bait / "ssh-key-backup.txt", "a") as stream:
        stream.write("encrypted")
    (bait / "wallet-recovery.txt").unlink()
    (bait / "passwords.txt").unlink()
    tripped = host_tripwires.review(home, auth_paths=(_log(tmp_path / "attack.log", True),), now=NOW)
    clear = host_tripwires.review(_home(tmp_path, "clear", plant=2),
                                  auth_paths=(_log(tmp_path / "quiet.log", False),), now=NOW)
    unconfigured = host_tripwires.review(_home(tmp_path, "none"), auth_paths=(_log(tmp_path / "q2.log", False),),
                                         now=NOW)
    locked = tmp_path / "locked.log"
    locked.mkdir()  # not a regular file: the reader refuses it like an unreadable log
    unreadable = host_tripwires.review(_home(tmp_path, "u"), auth_paths=(str(locked),), now=NOW)
    unreadable["auth"]["reason"] += " (reading auth logs usually needs membership in the adm group)"
    not_found = host_tripwires.review(_home(tmp_path, "nf"), auth_paths=(str(tmp_path / "auth.log"),
                                                                         str(tmp_path / "secure")), now=NOW)
    return dict(tripped=tripped, clear=clear, unconfigured=unconfigured, unreadable=unreadable, notFound=not_found)


def test_review_states_are_bounded_and_path_free(reviews):
    tripped = reviews["tripped"]
    assert tripped["action_authority"] == "none"
    assert tripped["canary"]["state"] == "tripped" and tripped["canary"]["findings_total"] == 3
    # Most severe first, then by file name.
    assert [(f["rule_id"], f["name"]) for f in tripped["canary"]["findings"]] == [
        ("CANARY_REMOVED", "passwords.txt"), ("CANARY_MODIFIED", "ssh-key-backup.txt"),
        ("CANARY_REMOVED", "wallet-recovery.txt")]
    assert all("/" not in f["name"] for f in tripped["canary"]["findings"])
    assert tripped["auth"]["state"] == "ready" and tripped["auth"]["source"] == "attack.log"
    assert tripped["auth"]["findings"][0]["rule_id"] == "AUTH_SUCCESS_AFTER_FAILURES"
    assert reviews["clear"]["canary"]["state"] == "clear"
    assert reviews["unconfigured"]["canary"]["state"] == "not_configured"
    assert reviews["unreadable"]["auth"]["state"] == "unreadable"
    assert reviews["notFound"]["auth"] == {"state": "not_found", "checked": ["auth.log", "secure"]}
    assert "/tmp" not in json.dumps(tripped) and str(Path.home()) not in json.dumps(tripped)


def test_panel_renders_real_reviews_and_rejects_forged_payloads(reviews):
    if not shutil.which("node"):
        pytest.skip("Node unavailable")
    pending = dict(schema=host_tripwires.SCHEMA, state="pending", action_authority="none")
    completed = subprocess.run([shutil.which("node"), str(Path(__file__).with_name("host_tripwires_browser.cjs"))],
                               input=json.dumps(dict(code=HOST_TRIPWIRES_JS, pending=pending, **reviews)),
                               text=True, capture_output=True, timeout=10)
    assert completed.returncode == 0, completed.stderr + completed.stdout


def test_panel_is_wired_into_setup_without_an_action():
    assert 'id="host-tripwires-review"' in SUPPORT_CONFIG_HTML
    assert "#host-tripwires-review" in SUPPORT_CONFIG_CSS
    assert "renderHostTripwires(el('host-tripwires-review'),v.host_tripwires)" in SUPPORT_CONFIG_JS
    assert "renderHostTripwires(el('host-tripwires-review'),null)" in SUPPORT_CONFIG_JS
    assert "hostTripwiresPending(state.payload?.host_tripwires)" in SUPPORT_CONFIG_JS
    actions = SUPPORT_CONFIG_JS.split('const actions=')[1].split('};')[0]
    assert 'tripwire' not in actions and 'canary' not in actions
    assert 'innerHTML' not in HOST_TRIPWIRES_JS and 'fetch(' not in HOST_TRIPWIRES_JS


def test_support_snapshot_carries_tripwires_from_the_background(tmp_path, monkeypatch):
    from megalodon import support_config
    calls = []

    def fake_review(home):
        calls.append(home)
        return dict(schema=host_tripwires.SCHEMA, reviewed_at=NOW(), action_authority="none",
                    canary={"state": "not_configured", "setup": "x"},
                    auth={"state": "not_found", "checked": ["auth.log"]})

    monkeypatch.setattr(support_config.host_tripwires, "review", fake_review)
    service = support_config.SupportConfiguration.__new__(support_config.SupportConfiguration)
    from threading import Lock
    service.home = tmp_path
    service._review_locks = dict(tripwires=Lock())
    service._reviews, service._refreshing, service._generations = {}, {}, {}
    first = service._tripwires_snapshot()
    assert first == dict(schema=host_tripwires.SCHEMA, state="pending", action_authority="none")
    for _ in range(200):
        if "tripwires" in service._reviews:
            break
        import time
        time.sleep(0.01)
    assert service._tripwires_snapshot()["canary"]["state"] == "not_configured"
    assert calls == [tmp_path]
