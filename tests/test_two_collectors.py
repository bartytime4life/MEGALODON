"""A machine that reports to two collectors: the same heartbeats, timelines and evidence reach each one, and one that is
down catches up on its own without holding the other back."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.server
import json
import threading

import pytest

from megalodon import cli, fleet, tamper
from megalodon import command_log as cl
from megalodon import evidence_shipping as shipping
from megalodon import response_engine as re_
from megalodon import timeline as tl

T0 = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


class Collector:
    def __init__(self, root, name):
        self.data = root / name
        self.start()

    def start(self, port=0):
        self.httpd = fleet.server("127.0.0.1", port, data=self.data)
        fleet.serve_in_background(self.httpd)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def row(self, name):
        return next(r for r in fleet.status(data=self.data)["machines"] if r["machine"] == name)


@pytest.fixture
def pair(tmp_path):
    first, second = Collector(tmp_path, "first"), Collector(tmp_path, "second")
    yield first, second
    for one in (first, second):
        try:
            one.stop()
        except OSError:
            pass


def machine(tmp_path, collectors, name="web-1"):
    """A machine set up with `heartbeat init --url A --url B`, enrolled at each collector with the one key."""
    config = tmp_path / f"{name}-heartbeat.json"
    result = tamper.init_heartbeat([c.url + "/heartbeat" for c in collectors], config=config)
    settings = json.loads(config.read_text())
    config.write_text(json.dumps(dict(settings, sensor=name)))
    for one in collectors:
        fleet.enroll(name, result["key"], data=one.data)
    return config


REAL_HEARTBEAT = tamper.heartbeat


def send(tmp_path, config, monkeypatch, capsys):
    """`megalodon heartbeat send`, with this machine's files: (exit code, printed result, standard error)."""
    monkeypatch.setattr(tamper, "heartbeat", lambda: REAL_HEARTBEAT(
        config, manifest=tmp_path / "no-tamper.json", sequence_path=tmp_path / "beats.json", runner=lambda *a: "",
        uptime=lambda: 1.0))
    try:
        code = cli.main(["heartbeat", "send"])
    except SystemExit as exit:
        code = exit.code
    out = capsys.readouterr()
    return code, json.loads(out.out or "{}"), out.err


def finds(tmp_path, key, minutes):
    """A finding recorded by this machine's response engine: an event its timeline pushes."""
    policy, ledger, state = tmp_path / "policy.toml", tmp_path / "ledger.jsonl", tmp_path / "state.json"
    if not policy.exists():
        re_.write_default_policy(policy)
    signal = re_.Signal(key, "egress", "OUTBOUND_FROM_TEMPORARY", "HIGH",
                        (T0 + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ'), f"/tmp/{key}",
                        re_._entities(address=["203.0.113.9"]))
    re_.run(policy_path=policy, ledger=ledger, state_path=state, signals=[signal], protected=set(),
            now=T0 + timedelta(minutes=minutes))


def push(tmp_path, config):
    return tl.push(config=config, cursor_path=tmp_path / "timeline-cursor.json", ledger=tmp_path / "ledger.jsonl",
                   journal=tmp_path / "enforced.jsonl")


def test_every_heartbeat_reaches_both_collectors_and_one_down_does_not_stop_the_other(pair, tmp_path, monkeypatch,
                                                                                      capsys):
    first, second = pair
    config = machine(tmp_path, pair)
    code, result, _err = send(tmp_path, config, monkeypatch, capsys)
    assert code == 0 and [d["status"] for d in result["destinations"]] == [200, 200]
    assert first.row("web-1")["last_sequence"] == second.row("web-1")["last_sequence"] == 1
    second.stop()
    code, result, err = send(tmp_path, config, monkeypatch, capsys)
    assert code == 1, "a destination that could not be reached is a failure the schedule shows"
    assert result["destinations"][0]["status"] == 200 and "error" in result["destinations"][1]
    assert first.row("web-1")["last_sequence"] == 2, "the first collector still got it"
    assert f"heartbeat 2 was not delivered to {second.url}/heartbeat" in err


def test_timelines_reach_each_collector_from_its_own_record(pair, tmp_path):
    first, second = pair
    config = machine(tmp_path, pair)
    finds(tmp_path, "a", 0)
    result = push(tmp_path, config)
    assert [(c["destination"], c["sent"] > 0) for c in result["collectors"]] == [
        (first.url + "/heartbeat", True), (second.url + "/heartbeat", True)]
    second.stop()
    finds(tmp_path, "b", 10)
    result = push(tmp_path, config)
    assert result["collectors"][0]["sent"] > 0 and "error" in result["collectors"][1]
    second.start()
    tamper.change_destinations(config, remove=json.loads(config.read_text())["urls"][1])
    tamper.change_destinations(config, add=second.url + "/heartbeat")    # the same collector, at its new port
    result = push(tmp_path, config)
    assert result["collectors"][0]["sent"] == 0, "the first collector is not sent anything twice"
    assert result["collectors"][1]["sent"] > 0, "the second catches up from its own record"
    held = [fleet.fleet_events(data=one.data) for one in pair]
    assert sorted(e["event_id"] for e in held[0]) == sorted(e["event_id"] for e in held[1]), "both hold the same"


def test_evidence_reaches_both_and_each_copy_verifies(pair, tmp_path):
    first, second = pair
    config = machine(tmp_path, pair)
    state, log = tmp_path / "commands-state.json", tmp_path / "commands.jsonl"
    key = cl.init(state=state, log=log)["key"]
    with cl.Recorder(state=state, log=log) as recorder:
        for number, program in enumerate(("/usr/bin/id", "/tmp/.x")):
            recorder.add("exec", pid=2000 + number, uid=1000, program=program, argv=[program])
    result = shipping.push(config=config, cursor_path=tmp_path / "evidence-cursor.json", log=log,
                           evidence_root=tmp_path / "evidence")
    assert [c["command_lines"] for c in result["collectors"]] == [2, 2]
    for one in pair:
        assert shipping.verify(one.data, "web-1", key_hex=key)["commands"]["verified"] == 2
    again = shipping.push(config=config, cursor_path=tmp_path / "evidence-cursor.json", log=log,
                          evidence_root=tmp_path / "evidence")
    assert [c["command_lines"] for c in again["collectors"]] == [0, 0], "each record keeps its own place"


def test_adding_and_removing_destinations_keeps_the_key(pair, tmp_path):
    first, second = pair
    config = tmp_path / "heartbeat.json"
    key = tamper.init_heartbeat(first.url + "/heartbeat", config=config)["key"]
    assert tamper.destinations(json.loads(config.read_text())) == [first.url + "/heartbeat"]
    tamper.change_destinations(config, add=second.url + "/heartbeat")
    settings = json.loads(config.read_text())
    assert settings["key"] == key and tamper.destinations(settings) == [first.url + "/heartbeat",
                                                                        second.url + "/heartbeat"]
    with pytest.raises(tamper.TamperError, match="already"):
        tamper.change_destinations(config, add=second.url + "/heartbeat")
    with pytest.raises(tamper.TamperError, match="first destination cannot be removed"):
        tamper.change_destinations(config, remove=first.url + "/heartbeat")
    with pytest.raises(tamper.TamperError):
        tamper.change_destinations(config, add="ftp://elsewhere.example/heartbeat")
    tamper.change_destinations(config, remove=second.url + "/heartbeat")
    assert tamper.destinations(json.loads(config.read_text())) == [first.url + "/heartbeat"]
    with pytest.raises(tamper.TamperError, match="between 1 and"):
        tamper.init_heartbeat([f"https://c{n}.example/heartbeat" for n in range(tamper.MAX_COLLECTORS + 1)],
                              config=tmp_path / "too-many.json")


def test_a_configuration_from_before_has_one_destination_and_the_same_results(pair, tmp_path):
    first, _second = pair
    config = tmp_path / "heartbeat.json"
    key = tamper.init_heartbeat(first.url + "/heartbeat", config=config)["key"]
    settings = json.loads(config.read_text())
    del settings["urls"]
    config.write_text(json.dumps(dict(settings, sensor="web-1")))
    fleet.enroll("web-1", key, data=first.data)
    assert tamper.destinations(settings) == [first.url + "/heartbeat"]
    # A list that does not start with the configured destination is not trusted over it.
    assert tamper.destinations(dict(settings, urls=["https://other.example/heartbeat"])) == [first.url + "/heartbeat"]
    result = tl.push(config=config, cursor_path=tmp_path / "cursor.json", ledger=tmp_path / "ledger.jsonl",
                     journal=tmp_path / "enforced.jsonl")
    assert "collectors" not in result and result["url"] == first.url + "/events"


def test_each_destination_has_its_own_push_record_and_a_plain_monitor_is_not_an_error(tmp_path):
    base = tmp_path / "cursor.json"
    named = [tamper.cursor_for(base, n, f"https://c{n}.example/heartbeat") for n in range(3)]
    assert named[0] == base and len(set(named)) == 3 and all(p.parent == base.parent for p in named)

    class NotFound(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass
    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NotFound)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    try:
        config = tmp_path / "heartbeat.json"
        tamper.init_heartbeat(["http://127.0.0.1:9/heartbeat", f"http://127.0.0.1:{plain.server_address[1]}/heartbeat"],
                              config=config)
        finds(tmp_path, "a", 0)
        result = tl.push(config=config, cursor_path=base, ledger=tmp_path / "ledger.jsonl",
                         journal=tmp_path / "enforced.jsonl")
    finally:
        plain.shutdown()
        plain.server_close()
    down, monitor = result["collectors"]
    assert "error" in down and down["sent"] == 0, "nothing listens there"
    assert "error" not in monitor and "not a fleet collector" in monitor["note"], \
        "a heartbeat monitor that takes no timelines is not a failure"


def test_the_first_collector_down_does_not_stop_the_second(pair, tmp_path, monkeypatch, capsys):
    first, second = pair
    config = machine(tmp_path, pair)
    first.stop()
    code, result, _err = send(tmp_path, config, monkeypatch, capsys)
    assert code == 1 and "error" in result["destinations"][0] and result["destinations"][1]["status"] == 200
    assert second.row("web-1")["last_sequence"] == 1


def test_the_push_commands_fail_when_any_collector_failed(pair, tmp_path, monkeypatch, capsys):
    first, second = pair
    config = machine(tmp_path, pair)
    finds(tmp_path, "a", 0)
    state, log = tmp_path / "commands-state.json", tmp_path / "commands.jsonl"
    cl.init(state=state, log=log)
    with cl.Recorder(state=state, log=log) as recorder:
        recorder.add("exec", pid=2000, uid=1000, program="/usr/bin/id", argv=["/usr/bin/id"])
    second.stop()
    monkeypatch.setattr(tl, "push", lambda real=tl.push, **kw: real(**dict(
        kw, config=config, cursor_path=tmp_path / "timeline-cursor.json")))
    monkeypatch.setattr(shipping, "push", lambda real=shipping.push, **kw: real(**dict(
        kw, config=config, cursor_path=tmp_path / "evidence-cursor.json")))
    for argv in (["timeline", "push", "--ledger", str(tmp_path / "ledger.jsonl")],
                 ["evidence", "push", "--log", str(log),
                  "--evidence-root", str(tmp_path / "no-evidence")]):
        try:
            code = cli.main(argv)
        except SystemExit as exit:
            code = exit.code
        printed = json.loads(capsys.readouterr().out)
        assert code == 2, argv
        assert "error" not in printed["collectors"][0] and "error" in printed["collectors"][1]
