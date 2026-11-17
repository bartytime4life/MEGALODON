from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from megalodon import canary, cli
from megalodon.validation import ValidationError
from megalodon.watchlist import load_watchlist


def run(argv, capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(argv)
    out, err = capsys.readouterr()
    return raised.value.code, out, err


@pytest.fixture
def planted(tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()
    manifest = tmp_path / "canary.json"
    result = canary.plant(str(bait), str(manifest), count=5)
    return bait, manifest, result


def kinds(report):
    return sorted((Path(f["path"]).name, f["rule_id"]) for f in report["findings"])


def test_plant_creates_private_bait_and_manifest(planted):
    bait, manifest, result = planted
    assert len(result["planted"]) == 5
    assert os.stat(manifest).st_mode & 0o777 == 0o600
    for path in result["planted"]:
        assert os.stat(path).st_mode & 0o777 == 0o600
        info = os.stat(path)
        assert info.st_atime_ns < info.st_mtime_ns  # armed for read detection
    tokens = {Path(p).read_bytes() for p in result["planted"]}
    assert len(tokens) == 5  # every file carries its own random marker


def test_repeated_checks_never_trip_themselves(planted):
    _, manifest, _ = planted
    for _ in range(3):
        report = canary.check(str(manifest))
        assert report["tripped"] is False and report["findings"] == []


def test_each_kind_of_touch_is_reported(planted):
    bait, manifest, result = planted
    if result["read_detection"]:
        (bait / "passwords.txt").read_bytes()
    with open(bait / "ssh-key-backup.txt", "a") as stream:
        stream.write("encrypted")
    (bait / "wallet-recovery.txt").unlink()
    (bait / "vpn-client.ovpn").rename(bait / "renamed.ovpn")
    replaced = bait / "cloud-credentials.bak"
    replaced.unlink()
    replaced.write_text("attacker copy")
    expected = [("cloud-credentials.bak", "CANARY_REMOVED"), ("ssh-key-backup.txt", "CANARY_MODIFIED"),
                ("vpn-client.ovpn", "CANARY_REMOVED"), ("wallet-recovery.txt", "CANARY_REMOVED")]
    if result["read_detection"]:
        expected.insert(0, ("passwords.txt", "CANARY_READ"))
    report = canary.check(str(manifest))
    assert kinds(report) == sorted(expected)
    assert report["tripped"] is True


def test_permission_change_counts_as_modification(planted):
    bait, manifest, _ = planted
    os.chmod(bait / "passwords.txt", 0o644)
    assert kinds(canary.check(str(manifest))) == [("passwords.txt", "CANARY_MODIFIED")]


def test_rearm_clears_a_reviewed_read_and_refuses_missing_files(planted):
    bait, manifest, result = planted
    if not result["read_detection"]:
        pytest.skip("filesystem does not update access times")
    (bait / "passwords.txt").read_bytes()
    assert canary.check(str(manifest))["tripped"]
    canary.rearm(str(manifest))
    assert canary.check(str(manifest))["tripped"] is False
    (bait / "passwords.txt").read_bytes()
    assert kinds(canary.check(str(manifest))) == [("passwords.txt", "CANARY_READ")]
    (bait / "passwords.txt").unlink()
    with pytest.raises(ValidationError, match="re-plant"):
        canary.rearm(str(manifest))


def test_plant_refuses_unsafe_or_ambiguous_requests(tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()
    with pytest.raises(ValidationError, match="outside"):
        canary.plant(str(bait), str(bait / "m.json"))
    (bait / "passwords.txt").write_text("real file")
    with pytest.raises(ValidationError, match="overwrite existing"):
        canary.plant(str(bait), str(tmp_path / "m.json"))
    assert (bait / "passwords.txt").read_text() == "real file"
    with pytest.raises(ValidationError, match="cannot be used"):
        canary.plant(str(tmp_path / "missing"), str(tmp_path / "m.json"))
    with pytest.raises(ValidationError, match="existing directory"):
        canary.plant(str(bait / "passwords.txt"), str(tmp_path / "m.json"))
    with pytest.raises(ValidationError, match="count"):
        canary.plant(str(bait), str(tmp_path / "m.json"), count=9)


def test_manifest_must_be_private_and_well_formed(planted, tmp_path):
    _, manifest, _ = planted
    os.chmod(manifest, 0o666)
    with pytest.raises(ValidationError, match="writable"):
        canary.check(str(manifest))
    bogus = tmp_path / "bogus.json"
    bogus.write_text(json.dumps({"schema": "other"}))
    os.chmod(bogus, 0o600)
    with pytest.raises(ValidationError, match="unsupported"):
        canary.check(str(bogus))


def test_canary_cli_round_trip_and_exit_codes(tmp_path, capsys):
    bait = tmp_path / "bait"
    bait.mkdir()
    manifest = tmp_path / "m.json"
    code, out, _ = run(["canary", "plant", "--dir", str(bait), "--manifest", str(manifest),
                        "--count", "2"], capsys)
    assert code == 0 and len(json.loads(out)["planted"]) == 2
    code, out, _ = run(["canary", "check", "--manifest", str(manifest)], capsys)
    assert code == 0 and json.loads(out)["tripped"] is False
    (bait / "passwords.txt").unlink()
    code, out, _ = run(["canary", "check", "--manifest", str(manifest)], capsys)
    assert code == 1 and json.loads(out)["findings"][0]["rule_id"] == "CANARY_REMOVED"
    code, _, err = run(["canary", "check", "--manifest", str(tmp_path / "absent.json")], capsys)
    assert code == 2 and "cannot be opened" in err


def _auth_log(path, lines):
    path.write_text("\n".join(lines) + "\n")
    return path


def test_auth_review_cli_reports_and_emits_watchlist(tmp_path, capsys):
    attacker = "198.51.100.23"
    lines = [f"Nov 17 10:00:{i:02d} web sshd[{i}]: Failed password for root from {attacker} port {i} ssh2"
             for i in range(8)]
    lines.append(f"Nov 17 10:01:00 web sshd[99]: Accepted password for root from {attacker} port 9 ssh2")
    log = _auth_log(tmp_path / "auth.log", lines)
    watch = tmp_path / "attackers.txt"
    code, out, _ = run(["auth-review", "--input", str(log), "--utc", "--emit-watchlist", str(watch)],
                       capsys)
    report = json.loads(out)
    assert code == 1
    assert [f["rule_id"] for f in report["findings"]] == ["AUTH_FAILURE_BURST",
                                                         "AUTH_SUCCESS_AFTER_FAILURES"]
    assert report["watchlist_written"]["indicators"] == 1
    assert load_watchlist(watch).match(attacker) is not None
    code, _, err = run(["auth-review", "--input", str(log), "--emit-watchlist", str(watch)], capsys)
    assert code == 2 and "--replace" in err


def test_auth_review_cli_clean_log_and_unreadable_input(tmp_path, capsys):
    log = _auth_log(tmp_path / "auth.log", [
        "Nov 17 10:00:00 web sshd[1]: Accepted publickey for alice from 192.168.1.5 port 1 ssh2"])
    code, out, _ = run(["auth-review", "--input", str(log)], capsys)
    assert code == 0 and json.loads(out)["findings"] == []
    code, _, err = run(["auth-review", "--input", str(tmp_path / "missing.log")], capsys)
    assert code == 2 and "cannot be opened" in err
