"""Fleet timeline: each machine's incidents pushed to the collector, signed, and joined across machines."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import urllib.error
import urllib.request

import pytest

from megalodon import fleet, tamper
from megalodon import response_engine as re_
from megalodon import timeline as tl
from test_fleet import collector, machine  # noqa: F401

T0 = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


class Machine:
    """One enrolled machine: its heartbeat configuration and its own response engine records."""

    def __init__(self, tmp_path, url, data, name):
        self.name, self.dir = name, tmp_path / name
        self.dir.mkdir()
        self.config, key = machine(tmp_path, url, name)
        fleet.enroll(name, key, data=data)
        self.policy, self.ledger, self.state = self.dir / "policy.toml", self.dir / "ledger.jsonl", self.dir / "s.json"
        re_.write_default_policy(self.policy)

    def finds(self, key, source, rule, summary, minutes, **entities):
        signal = re_.Signal(key, source, rule, "HIGH", (T0 + timedelta(minutes=minutes)).strftime(
            '%Y-%m-%dT%H:%M:%SZ'), summary, re_._entities(**entities))
        re_.run(policy_path=self.policy, ledger=self.ledger, state_path=self.state, signals=[signal],
                protected=set(), now=T0 + timedelta(minutes=minutes))

    def push(self, **kw):
        return tl.push(config=self.config, cursor_path=self.dir / "cursor.json", ledger=self.ledger,
                       journal=self.dir / "enforced.jsonl", now=kw.pop("now", None), **kw)


def get(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode()


def test_two_machines_one_attacker(collector, tmp_path):
    data, url, view = collector
    web, db, other = (Machine(tmp_path, url, data, n) for n in ("web-1", "db-1", "mail-1"))
    web.finds("w1", "egress", "OUTBOUND_FROM_TEMPORARY", "/tmp/x connects to 203.0.113.9", 0,
              address=["203.0.113.9"], process=["/tmp/x"])
    db.finds("d1", "logins", "LOGIN_NEW_SOURCE", "root logged in from 203.0.113.9", 120,
             address=["203.0.113.9"], account=["root"])
    other.finds("m1", "webroot", "WEB_SHELL_PATTERN", "a shell in uploads", 5, file=["/var/www/up/x.php"])
    for one in (web, db, other):
        assert one.push()["sent"] >= 1
    assert web.push()["sent"] == 0, "what was sent is not sent again"
    listed = fleet.fleet_timeline(data=data, now=T0 + timedelta(hours=3))["incidents"]
    assert len(listed) == 2
    joined = next(r for r in listed if len(r["machines"]) == 2)
    assert (joined["machines"], joined["linked_by"], joined["sources"]) == (
        ["db-1", "web-1"], ["203.0.113.9"], ["egress", "logins"])
    shown = fleet.fleet_show(joined["incident"][:6], data=data)
    assert [(e["machine"], e["kind"]) for e in shown["events"]] == [
        ("web-1", "finding"), ("web-1", "decision"), ("db-1", "finding"), ("db-1", "decision")], \
        "each machine's findings and the decisions on them, in order"
    text = tl.text(shown)
    assert "machines: db-1, web-1 (joined by 203.0.113.9)" in text and "web-1" in text.split("\n\n", 1)[1]
    assert len(fleet.fleet_show(entity="address:203.0.113.9", data=data)["events"]) == 4
    # The view, on its loopback listener only.
    page = get(view + "/timeline")
    assert f'href="/timeline/{joined["incident"]}"' in page and "<script" not in page
    assert "db-1/" in get(view + f"/timeline/{joined['incident']}")
    assert len(json.loads(get(view + "/timeline.json"))["incidents"]) == 2
    with pytest.raises(urllib.error.HTTPError) as hidden:
        get(url + "/timeline")
    assert hidden.value.code == 404


def test_far_apart_sightings_are_not_joined(collector, tmp_path):
    data, url, _view = collector
    web, db = (Machine(tmp_path, url, data, n) for n in ("web-1", "db-1"))
    web.finds("w1", "egress", "OUTBOUND_FROM_TEMPORARY", "first", 0, address=["198.51.100.7"])
    db.finds("d1", "egress", "OUTBOUND_FROM_TEMPORARY", "a day and more later", 30 * 60, address=["198.51.100.7"])
    web.push(), db.push()
    assert len(fleet.fleet_timeline(data=data, now=T0 + timedelta(days=2))["incidents"]) == 2


def test_forged_replayed_and_unknown_batches(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data, "web-1")
    web.finds("w1", "egress", "UNDECIDED_RULE", "x", 0, address=["192.0.2.10"])
    bodies = []
    result = web.push(send=lambda settings, body: (bodies.append(body), tamper.send(settings, body)))
    assert result["sent"] == 1 and len(bodies) == 1

    def post(body):
        request = urllib.request.Request(url + "/events", data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
    assert post(bodies[0]) == 409, "a batch sent again adds nothing"
    forged = dict(bodies[0], sequence=bodies[0]["sequence"] + 10,
                  events=[dict(bodies[0]["events"][0], summary="nothing happened here")])
    assert post(forged) == 401
    assert post(dict(forged, sensor="stranger")) == 403
    assert post(dict(schema="other")) == 400
    events = fleet.fleet_events(data=data)
    assert len(events) == 1 and events[0]["summary"] == "x", "neither the replay nor the forgery was kept"
    # A machine that lost its cursor sends everything again, in a new batch: still one event each.
    (web.dir / "cursor.json").unlink()
    assert web.push(now=T0 + timedelta(days=1))["sent"] == 1
    assert len(fleet.fleet_events(data=data)) == 1


def test_the_cli_and_a_plain_monitor(collector, tmp_path, capsys):
    data, url, _view = collector
    web = Machine(tmp_path, url, data, "web-1")
    web.finds("w1", "egress", "UNDECIDED_RULE", "x", 0, address=["192.0.2.10"])
    from megalodon.cli import main
    common = ["--config", str(web.config), "--ledger", str(web.ledger), "--journal", str(web.dir / "j.jsonl")]
    with pytest.raises(SystemExit) as exit_:
        main(["timeline", "push", "--url", url + "/nowhere", *common])
    assert exit_.value.code == 0 and "takes no timelines" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_:
        main(["timeline", "push", "--dry-run", *common])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["sent"] == 1
    web.push()
    with pytest.raises(SystemExit) as exit_:
        main(["fleet", "timeline", "--data", str(data), "--hours", "1000000"])
    assert exit_.value.code == 0 and "on web-1" in capsys.readouterr().out
