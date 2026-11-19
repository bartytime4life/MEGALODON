"""Fleet view: a collector that receives real heartbeats and alerts from enrolled machines and shows them together."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

import pytest

from megalodon import alerts, fleet, tamper


@pytest.fixture
def collector(tmp_path):
    data = tmp_path / "fleet"
    httpd = fleet.server("127.0.0.1", 0, data=data)
    view = fleet.view_server("127.0.0.1", 0, data=data)
    fleet.serve_in_background(httpd)
    fleet.serve_in_background(view)
    yield data, f"http://127.0.0.1:{httpd.server_address[1]}", f"http://127.0.0.1:{view.server_address[1]}"
    for server in (httpd, view):
        server.shutdown()
        server.server_close()


def machine(tmp_path, url, name):
    """A sender set up the way `megalodon heartbeat init` sets one up."""
    config = tmp_path / f"{name}-heartbeat.json"
    key = tamper.init_heartbeat(url + "/heartbeat", config=config)["key"]
    settings = json.loads(config.read_text())
    settings["sensor"] = name
    config.write_text(json.dumps(settings))
    return config, key


def beat(tmp_path, config, name, **body_changes):
    settings, body = tamper.heartbeat(config, manifest=tmp_path / f"{name}-no-tamper.json",
                                      sequence_path=tmp_path / f"{name}-sequence.json", runner=lambda *a: "",
                                      uptime=lambda: 1.0)
    body.update(body_changes)
    try:
        return tamper.send(settings, body)
    except urllib.error.HTTPError as exc:
        return exc.code


def post(url, value, headers=None):
    request = urllib.request.Request(url, data=json.dumps(value).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_heartbeats_and_alerts_from_two_machines(collector, tmp_path):
    data, url, view = collector
    config_a, key_a = machine(tmp_path, url, "web-1")
    config_b, key_b = machine(tmp_path, url, "db-1")
    token_a = fleet.enroll("web-1", key_a, data=data)["alert_token"]
    fleet.enroll("db-1", key_b, data=data)
    assert oct((data / "machines.json").stat().st_mode & 0o777) == "0o600"
    assert token_a not in (data / "machines.json").read_text(), "only the token's SHA-256 is kept"
    assert beat(tmp_path, config_a, "web-1") == 200
    assert beat(tmp_path, config_a, "web-1") == 200
    # A real alert, formatted and sent the way a webhook destination with format = "json" sends it.
    destination = alerts.AlertDestination(name="fleet", kind="webhook", url_file="unused", format="json")
    notice = alerts.HostNotice("EGRESS_NEW_PROGRAM", "HIGH", datetime.now(timezone.utc), "curl connects out",
                               summary="new outbound program")
    body, headers = alerts.webhook_request(destination, url + "/alert", token_a,
                                           alerts.record(notice, detail="full", sensor="claims-to-be-db-1"))
    alerts.post(url + "/alert", body, headers)                  # raises unless the collector accepted it
    report = fleet.status(data=data)
    rows = {row["machine"]: row for row in report["machines"]}
    assert rows["web-1"]["state"] == "attention" and rows["web-1"]["last_sequence"] == 2
    assert rows["web-1"]["heartbeat_findings"] == [], "real heartbeats verify; the alert is what needs attention"
    assert rows["web-1"]["alerts"]["HIGH"] == 1 and rows["web-1"]["recent"][0]["rule_id"] == "EGRESS_NEW_PROGRAM"
    assert rows["db-1"]["state"] == "silent", "enrolled, never heard from"
    stored = json.loads((data / "machines/web-1/alerts.jsonl").read_text().splitlines()[0])
    assert stored["machine"] == "web-1" and stored["claimed_sensor"] == "claims-to-be-db-1", \
        "the token decides the machine, not what the alert claims"
    # The view, on its own loopback listener; the receiving listener never shows it.
    with urllib.request.urlopen(view + "/status", timeout=5) as response:
        assert json.loads(response.read())["summary"] == dict(ok=0, attention=1, silent=1)
    for path in ("/status", "/"):
        with pytest.raises(urllib.error.HTTPError) as hidden:
            urllib.request.urlopen(url + path, timeout=5)
        assert hidden.value.code == 404, "a proxy in front of the receiver forwards from loopback"
    assert post(view + "/alert", dict(rule_id="X", severity="HIGH"), {"Authorization": f"Bearer {token_a}"}) == 404
    with urllib.request.urlopen(view + "/", timeout=5) as response:
        page = response.read().decode()
        assert "web-1" in page and "<script" not in page
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_forged_unknown_and_oversized_posts(collector, tmp_path):
    data, url, view = collector
    config, key = machine(tmp_path, url, "web-1")
    token = fleet.enroll("web-1", key, data=data)["alert_token"]
    stranger_config, _ = machine(tmp_path, url, "stranger")
    assert beat(tmp_path, stranger_config, "stranger") == 403, "not enrolled"
    assert beat(tmp_path, config, "web-1") == 200
    forged = dict(schema=tamper.HEARTBEAT_SCHEMA, sensor="web-1", sequence=2, sent_at="2026-11-19T00:00:00Z",
                  state_digest="0" * 64, tamper_baseline=False, findings=[], mac="0" * 64)
    assert post(url + "/heartbeat", forged) == 401
    assert "HEARTBEAT_FORGED" in fleet.status(data=data)["machines"][0]["heartbeat_findings"], \
        "a forged heartbeat is kept and shown"
    alert = dict(rule_id="X", severity="HIGH")
    assert post(url + "/alert", alert) == 401
    assert post(url + "/alert", alert, {"Authorization": "Bearer wrong"}) == 401
    assert post(url + "/alert", dict(rule_id="X", severity="loud"), {"Authorization": f"Bearer {token}"}) == 400
    assert post(url + "/alert", dict(rule_id="X", severity="HIGH", pad="x" * fleet.MAX_BODY),
                {"Authorization": f"Bearer {token}"}) == 413
    assert post(url + "/nowhere", alert) == 404


def test_the_view_is_refused_off_this_machine(collector, tmp_path, monkeypatch):
    _data, _url, view = collector
    monkeypatch.setattr(fleet.Handler, "_local", lambda self: False)
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(view + "/status", timeout=5)
    assert refused.value.code == 403
    with pytest.raises(fleet.FleetError, match="loopback only"):
        fleet.view_server("0.0.0.0", 0, data=tmp_path / "fleet")


def test_a_replaced_key_and_sensor_names(collector, tmp_path):
    data, url, _view = collector
    config, key = machine(tmp_path, url, "web-1")
    fleet.enroll("web-1", key, data=data)
    assert beat(tmp_path, config, "web-1") == 200
    # The machine is set up again with a new key; its old heartbeats are kept aside, not judged by the new key.
    config.unlink()
    (tmp_path / "web-1-sequence.json").unlink()
    config, key = machine(tmp_path, url, "web-1")
    fleet.enroll("web-1", key, data=data, replace=True)
    assert beat(tmp_path, config, "web-1") == 200
    row = fleet.status(data=data)["machines"][0]
    assert row["state"] == "ok" and row["heartbeat_findings"] == [] and row["last_sequence"] == 1
    assert any(p.name.startswith("heartbeats-before-") for p in (data / "machines/web-1").iterdir())
    # One sensor name, one machine.
    with pytest.raises(fleet.FleetError, match="already belongs to web-1"):
        fleet.enroll("web-2", "b" * 64, sensor="web-1", data=data)
    fleet.enroll("db-1", "c" * 64, data=data)
    with pytest.raises(fleet.FleetError, match="already belongs to db-1"):
        fleet.enroll("web-3", "d" * 64, sensor="db-1", data=data)


def test_silence_rules_and_refusals(tmp_path, monkeypatch, capsys):
    data = tmp_path / "fleet"
    with pytest.raises(fleet.FleetError, match="64 hexadecimal"):
        fleet.enroll("web-1", "short", data=data)
    with pytest.raises(fleet.FleetError, match="letters"):
        fleet.enroll("../etc", "a" * 64, data=data)
    fleet.enroll("web-1", "a" * 64, data=data)
    with pytest.raises(fleet.FleetError, match="already enrolled"):
        fleet.enroll("web-1", "b" * 64, data=data)
    with pytest.raises(fleet.FleetError, match="needs --certificate"):
        fleet.server("0.0.0.0", 0, data=data)
    os.chmod(data / "machines.json", 0o644)
    with pytest.raises(fleet.FleetError, match="mode-600"):
        fleet.status(data=data)
    os.chmod(data / "machines.json", 0o600)
    # A machine heard from long ago is silent.
    old = dict(schema=tamper.HEARTBEAT_SCHEMA, sensor="web-1", sequence=1, sent_at="2026-11-19T00:00:00Z",
               state_digest="0" * 64, tamper_baseline=False, findings=[])
    old["mac"] = tamper._sign("a" * 64, old)
    assert fleet.receive_heartbeat(old, data=data) == (200, "ok")
    later = datetime(2026, 11, 19, 1, 0, tzinfo=timezone.utc)
    report = fleet.status(data=data, now=later)
    assert report["machines"][0]["state"] == "silent"
    assert report["findings"][0]["detail"].startswith("web-1: the last heartbeat (1) was 60 minutes ago")
    from megalodon.cli import main
    with pytest.raises(SystemExit) as exit_:
        main(["fleet", "status", "--data", str(data)])
    assert exit_.value.code == 1
    assert json.loads(capsys.readouterr().out)["summary"]["silent"] == 1
    assert fleet.remove("web-1", data=data)["removed"] and fleet.status(data=data)["machines"] == []
