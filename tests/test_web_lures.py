"""Agent lures over the web: the note names a page no page links to; a request for it in the access log is
LURE_FOLLOWED.

Requests for a lure's page are given to the reviewer as values (address, time, target). Log lines appear only as
neutral placeholders, to show the formats are read.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import pytest

from megalodon import campaign as campaigns
from megalodon import canary
from megalodon import response_engine as re_
from megalodon import web_review
from megalodon.validation import ValidationError

ATTACKER = "203.0.113.120"
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
PAGE = "/ops-k3x9qe7m2a"


@pytest.fixture
def planted(tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()
    manifest = tmp_path / "canaries.json"
    result = canary.plant(str(bait), str(manifest), count=1, lure=True)
    return dict(result=result, manifest=manifest, bait=bait)


def test_a_lure_names_a_page_no_page_links_to_and_keeps_it_in_the_manifest(planted):
    [page] = planted["result"]["lure_pages"]
    note = (planted["bait"] / canary.LURE_NAME).read_text()
    assert canary.LURE_PATH.fullmatch(page) and f"path:  {page}" in note
    assert "href" not in note and "http" not in note, "a path and a code in a sentence, never a link to follow"
    assert canary.web_lures(str(planted["manifest"])) == {page: str(planted["bait"] / canary.LURE_NAME)}
    [account] = planted["result"]["lure_accounts"]
    assert account in note, "the SSH account is still named"


def test_a_malformed_lure_page_is_refused_and_a_lure_from_before_pages_still_loads(planted):
    data = json.loads(planted["manifest"].read_text())
    data["canaries"][-1]["lure_path"] = "/"
    planted["manifest"].write_text(json.dumps(data))
    os.chmod(planted["manifest"], 0o600)
    with pytest.raises(ValidationError, match="invalid entry"):
        canary.web_lures(str(planted["manifest"]))
    del data["canaries"][-1]["lure_path"]
    planted["manifest"].write_text(json.dumps(data))
    assert canary.web_lures(str(planted["manifest"])) == {} and canary.lures(str(planted["manifest"]))


def test_the_access_log_formats_are_read():
    lines = [b'198.51.100.7 - - [27/Nov/2026:13:00:00 +0100] "GET /placeholder HTTP/1.1" 200 5 "-" "-"\n',
             b'2001:db8::7 - - [27/Nov/2026:12:00:01 +0000] "HEAD /placeholder HTTP/1.1" 200 0\n',
             b'not a request line\n',
             b'198.51.100.7 - - [27/Xyz/2026:12:00:00 +0000] "GET /placeholder HTTP/1.1" 200 5\n',
             b'x' * (web_review.MAX_LINE_BYTES + 1) + b'\n']
    report, reviewer = web_review.review(lines, source="placeholder", lure_pages=[PAGE])
    assert report["input"] == dict(lines=5, requests=2, unrecognized_lines=1, oversized_lines=1, invalid_timestamps=1)
    assert report["window"] == dict(start="2026-11-27T12:00:00+00:00", end="2026-11-27T12:00:01+00:00")
    assert report["findings"] == []


@pytest.mark.parametrize("target", [PAGE, PAGE + "?check=placeholder", PAGE + "/", PAGE.upper(),
                                    "https://placeholder.example" + PAGE + "?check=placeholder",
                                    PAGE.replace("ops", "%6Fps"), PAGE + "/more"])
def test_a_request_for_a_lures_page_is_reported_however_it_is_written(target):
    reviewer = web_review.WebReviewer([PAGE])
    reviewer._request(NOW, ATTACKER, "GET", target)
    [finding] = reviewer.findings
    assert (finding["rule_id"], finding["severity"], finding["evidence"]["source"], finding["evidence"]["page"]) == (
        "LURE_FOLLOWED", "CRITICAL", ATTACKER, PAGE)


@pytest.mark.parametrize("target", ["/", "/placeholder", PAGE + "x", "/ops-k3x9qe7m2", "/placeholder" + PAGE,
                                    "/placeholder?next=" + PAGE])
def test_no_other_request_is_reported(target):
    reviewer = web_review.WebReviewer([PAGE])
    reviewer._request(NOW, ATTACKER, "GET", target)
    assert reviewer.findings == []


def test_one_address_asking_again_within_the_hour_is_one_finding():
    reviewer = web_review.WebReviewer([PAGE])
    for seconds, address in ((0, ATTACKER), (30, ATTACKER), (3599, ATTACKER), (40, "198.51.100.8"),
                             (3600, ATTACKER)):
        reviewer._request(NOW + timedelta(seconds=seconds), address, "GET", PAGE)
    assert [(f["evidence"]["source"], f["observed_at"][11:19]) for f in reviewer.findings] == [
        (ATTACKER, "12:00:00"), ("198.51.100.8", "12:00:40"), (ATTACKER, "13:00:00")]


# ------------------------------------------------------------------ the response engine

@pytest.fixture
def engine(tmp_path, planted, monkeypatch):
    log = tmp_path / "access.log"
    log.write_text("placeholder\n")
    monkeypatch.setattr(web_review, "WEB_LOGS", (str(tmp_path / "none"), str(log)))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text().replace('canary_manifest = ""', f'canary_manifest = "{planted["manifest"]}"')
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    for name in ("audit_db", "ancestry_allow_file", "credential_allow_file", "auth_log"):
        text = "\n".join(f'{name} = ""' if line.startswith(f"{name} = ") else line for line in text.splitlines())
    policy.write_text(text + "\n")
    return dict(policy=policy, log=log, ledger=tmp_path / "ledger.jsonl", state=tmp_path / "state.json")


def requested(monkeypatch, *requests):
    """The access log, as the engine reads it: each request handed to the real reviewer as values."""
    seen = {}

    def review(lines, *, source, lure_pages=(), on_finding=None):
        seen.update(source=source, pages=sorted(lure_pages))
        reviewer = web_review.WebReviewer(lure_pages, on_finding=on_finding)
        for when, address, target in requests:
            reviewer._request(when, address, "GET", target)
        return reviewer.report(source), reviewer
    monkeypatch.setattr(web_review, "review", review)
    return seen


def run(engine, now):
    return re_.run(policy_path=engine["policy"], ledger=engine["ledger"], state_path=engine["state"],
                   protected=set(), now=now)


def decided(engine):
    path = Path(engine["ledger"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_init_writes_the_access_log_this_system_keeps(engine):
    assert re_.load_policy(engine["policy"]).sources["web_log"] == str(engine["log"])


def test_a_request_for_the_lures_page_is_decided_and_joins_the_lure_read_in_one_incident(engine, planted,
                                                                                        monkeypatch):
    lure = planted["bait"] / canary.LURE_NAME
    if not planted["result"]["read_detection"]:
        pytest.skip("this filesystem records no reads")
    lure.read_text()
    [page] = planted["result"]["lure_pages"]
    asked = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=5)
    seen = requested(monkeypatch, (asked, ATTACKER, page + "?check=placeholder"))
    run(engine, asked + timedelta(minutes=1))
    assert seen == dict(source=str(engine["log"]), pages=[page])
    [lured] = [d for d in decided(engine) if d["signal"]["rule_id"] == "LURE_FOLLOWED"]
    assert lured["playbook"] == "lure-followed" and lured["signal"]["source"] == "web"
    assert ("block_address", ATTACKER) in [(a["action"], a["target"]) for a in lured["actions"]]
    summary = lured["signal"]["summary"]
    assert summary.startswith(f"{ATTACKER} asked this site for {page}, the page {canary.LURE_NAME} names, ")
    assert "s after it was read: an AI agent reading text and acting on it, at machine speed." in summary
    observed = [json.loads(line) for line in re_.observations_path(engine["ledger"]).read_text().splitlines()]
    incidents = {o["signal"]["rule_id"]: o["incident"] for o in observed if o["kind"] == "finding"}
    assert incidents["LURE_FOLLOWED"] == incidents["CANARY_READ"], "the read and the request are one story"
    run(engine, asked + timedelta(days=3))
    assert len([d for d in decided(engine) if d["signal"]["rule_id"] == "LURE_FOLLOWED"]) == 1, "decided once"
    assert json.loads(Path(engine["state"]).read_text())["web_cursor"]["at"] == re_._iso(asked)


def test_lures_that_name_no_page_are_a_gap_and_no_lure_at_all_reads_nothing(engine, planted, monkeypatch):
    data = json.loads(planted["manifest"].read_text())
    del data["canaries"][-1]["lure_path"]
    planted["manifest"].write_text(json.dumps(data))
    os.chmod(planted["manifest"], 0o600)

    def unread(*_, **__):
        raise AssertionError("the web log is read only for a lure's page")
    monkeypatch.setattr(web_review, "read_lines", unread)
    gaps = run(engine, NOW)["gaps"]
    assert any(g.startswith("web: the canary manifest's lures name no page") for g in gaps)
    text = Path(engine["policy"]).read_text()
    Path(engine["policy"]).write_text(
        "\n".join('canary_manifest = ""' if line.startswith("canary_manifest = ") else line
                  for line in text.splitlines()) + "\n")
    assert not [g for g in run(engine, NOW)["gaps"] if g.startswith("web:")]


def test_an_unreadable_access_log_is_a_gap(engine):
    Path(engine["log"]).unlink()
    assert any(g.startswith("web: web log cannot be opened") for g in run(engine, NOW)["gaps"])


def test_a_campaign_that_asked_for_a_lures_page_is_ai_driven_and_seen_by_the_web(planted):
    start = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)

    def attempt(n, rule, seconds):
        return re_.Signal(f"network:{n}", "network", rule, "MEDIUM", re_._iso(start + timedelta(seconds=seconds)), rule,
                          re_._entities(address=[ATTACKER], peer=[ATTACKER, f"192.168.1.{n}"]))
    reviewer = web_review.WebReviewer([PAGE])
    reviewer._request(start + timedelta(seconds=40), ATTACKER, "GET", PAGE)
    [web], _ = re_.web_signals(dict(findings=reviewer.findings), None,
                               {PAGE: dict(path="/srv/www/decoy/OPERATIONS-NOTE.txt", read_at=None)})
    signals = [attempt(n, ("PORT_SCAN", "BRUTE_FORCE", "HOST_SWEEP")[n % 3], 5 * n) for n in range(7)] + [web]
    [raised] = campaigns.observe({}, signals, start + timedelta(minutes=2), campaigns.Settings(), re_._campaign_signal)
    assert raised.severity == "CRITICAL" and "seen by network, web;" in raised.summary
    assert raised.summary.endswith("It followed an agent lure: an AI agent is driving it.")
    assert web.entities["file"] == {"/srv/www/decoy/OPERATIONS-NOTE.txt"} and web.entities["address"] == {ATTACKER}


# ------------------------------------------------------------------ the command line

def test_web_review_from_the_command_line(planted, tmp_path, capsys):
    from megalodon.cli import main
    log = tmp_path / "access.log"
    log.write_bytes(b'198.51.100.7 - - [27/Nov/2026:12:00:00 +0000] "GET /placeholder HTTP/1.1" 200 5\n')

    def code(*argv):
        with pytest.raises(SystemExit) as done:
            main(list(argv))
        return done.value.code
    assert code("web-review", "--input", str(log), "--lures", str(planted["manifest"])) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == web_review.SCHEMA and report["lure_pages_watched"] == 1 and report["findings"] == []
    assert code("web-review", "--input", str(tmp_path / "missing.log"), "--lures", str(planted["manifest"])) == 2
    assert "web log cannot be opened" in capsys.readouterr().err
    data = json.loads(planted["manifest"].read_text())
    del data["canaries"][-1]["lure_path"]
    planted["manifest"].write_text(json.dumps(data))
    os.chmod(planted["manifest"], 0o600)
    assert code("web-review", "--input", str(log), "--lures", str(planted["manifest"])) == 2
    assert "name no page" in capsys.readouterr().err


def test_web_review_exits_one_when_a_lures_page_was_asked_for(planted, tmp_path, monkeypatch, capsys):
    from megalodon.cli import main
    log = tmp_path / "access.log"
    log.write_text("placeholder\n")
    [page] = planted["result"]["lure_pages"]
    requested(monkeypatch, (NOW, ATTACKER, page))
    with pytest.raises(SystemExit) as done:
        main(["web-review", "--input", str(log), "--lures", str(planted["manifest"])])
    [finding] = json.loads(capsys.readouterr().out)["findings"]
    assert done.value.code == 1 and finding["evidence"] == dict(source=ATTACKER, page=page, method="GET",
                                                                requested=page)
