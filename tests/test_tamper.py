"""Tamper detection: the sensor's code, schedule and configuration, and a signed heartbeat whose silence is seen."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading

import pytest

from megalodon import schedule as sc
from megalodon import tamper as tp

NOW = datetime(2026, 11, 19, 2, 0, tzinfo=timezone.utc)


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    package = tmp_path / "pkg"
    (package / "sub").mkdir(parents=True)
    (package / "cli.py").write_text("print('sensor')\n")
    (package / "sub/rules.py").write_text("RULES = 1\n")
    config = tmp_path / "home/.config/megalodon"
    config.mkdir(parents=True)
    for name, text in (("settings.toml", "[alerts]\nenabled = true\n"), ("listeners.json", "{}"),
                       ("ancestry-allow.json", '{"allow": []}'), ("network-config.json", "{}")):
        (config / name).write_text(text)
    units = tmp_path / "units"
    sc.install(system=False, only=["rootkit"], directory=units, launcher=["/usr/bin/megalodon"],
               runner=lambda system, *a: subprocess.CompletedProcess(a, 0, "", ""))
    return dict(package=str(package), config_dir=str(config), unit_dir=str(units), system=False)


def fake_systemctl(states):
    def run(system, *args):
        unit = args[1]
        enabled, active, last = states.get(unit, ("enabled", "active", 0))
        return subprocess.CompletedProcess(args, 0, f"UnitFileState={enabled}\nActiveState={active}\n"
                                                    f"LastTriggerUSecMonotonic={last}\n", "")
    return run


def rules(report):
    return sorted((f["rule_id"], f["subject"]) for f in report["findings"])


def test_changes_to_code_schedule_and_configuration_are_reported(world, tmp_path):
    manifest = tmp_path / "tamper.json"
    result = tp.baseline(manifest, **world)
    assert result["code_files"] == 2 and result["units"] == ["megalodon-rootkit.service", "megalodon-rootkit.timer"]
    assert "network-config.json" not in result["configs"], "the HUD's own files are not watched"
    healthy = fake_systemctl({})
    assert tp.check(manifest, runner=healthy, uptime=100.0, **world)["findings"] == []
    package, config, units = Path(world["package"]), Path(world["config_dir"]), Path(world["unit_dir"])
    (package / "cli.py").write_text("print('sensor')\nimport os  # blinded\n")
    (package / "sub/rules.py").unlink()
    (config / "ancestry-allow.json").write_text('{"allow": [{"service": "/usr/sbin/nginx", "program": "/bin/sh"}]}')
    (config / "settings.toml").write_text("[alerts]\nenabled = false\n")
    (config / "listeners.json").write_text('{"changed": true}')
    (config / "network-config.json").write_text('{"hud": 2}')                     # normal HUD use: not a finding
    service = units / "megalodon-rootkit.service"
    service.write_text(service.read_text().replace("rootkit check --skip-ports --alert", "--version"))
    (units / "megalodon-rootkit.timer").unlink()
    report = tp.check(manifest, runner=healthy, uptime=100.0, **world)
    assert rules(report) == [
        ("ALERTS_CONFIG_CHANGED", "config:settings.toml"), ("ALLOW_LIST_CHANGED", "config:ancestry-allow.json"),
        ("BASELINE_CHANGED", "config:listeners.json"), ("SCHEDULE_CHANGED", "unit:megalodon-rootkit.service"),
        ("SCHEDULE_REMOVED", "unit:megalodon-rootkit.timer"), ("SENSOR_CODE_CHANGED", "code:cli.py"),
        ("SENSOR_CODE_REMOVED", "code:sub/rules.py")]
    assert report["findings"][0]["severity"] == "CRITICAL" and report["findings"][0]["techniques"] == ["T1562.001"]
    tp.accept(manifest, **world)
    assert tp.check(manifest, runner=healthy, uptime=100.0, **world)["findings"] == []
    os.chmod(manifest, 0o644)
    with pytest.raises(tp.TamperError, match="mode-600"):
        tp.check(manifest, runner=healthy, **world)


def test_stopped_disabled_and_overdue_watches_are_reported(world, tmp_path):
    manifest = tmp_path / "tamper.json"
    tp.baseline(manifest, **world)
    hour = 3600 * 10**6
    report = tp.check(manifest, runner=fake_systemctl({"megalodon-rootkit.timer": ("disabled", "inactive", hour)}),
                      uptime=5 * 3600.0, **world)
    assert rules(report) == [("WATCH_DISABLED", "unit:megalodon-rootkit.timer"),
                             ("WATCH_OVERDUE", "unit:megalodon-rootkit.timer"),
                             ("WATCH_STOPPED", "unit:megalodon-rootkit.timer")]
    assert "240 minutes ago" in next(f for f in report["findings"] if f["rule_id"] == "WATCH_OVERDUE")["detail"]
    recent = fake_systemctl({"megalodon-rootkit.timer": ("enabled", "active", 4 * hour)})
    assert tp.check(manifest, runner=recent, uptime=4.5 * 3600, **world)["findings"] == []


class Receiver(BaseHTTPRequestHandler):
    bodies: list = []

    def do_POST(self):
        Receiver.bodies.append(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def receiver():
    Receiver.bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/ping"
    server.shutdown()
    server.server_close()


def test_signed_heartbeats_are_delivered_and_their_problems_seen(world, tmp_path, receiver):
    config, sequence = tmp_path / "heartbeat.json", tmp_path / "state/sequence.json"
    key = tp.init_heartbeat(receiver, config)["key"]
    with pytest.raises(tp.TamperError, match="exists"):
        tp.init_heartbeat(receiver, config)
    with pytest.raises(tp.TamperError, match="https"):
        tp.init_heartbeat("http://monitor.example/ping", tmp_path / "other.json")
    manifest = tmp_path / "tamper.json"
    tp.baseline(manifest, **world)
    lines = []
    for minute in range(3):
        settings, body = tp.heartbeat(config, manifest=manifest, sequence_path=sequence,
                                      now=NOW + timedelta(minutes=5 * minute), runner=fake_systemctl({}),
                                      uptime=100.0, **world)
        assert tp.send(settings, body) == 200
    lines = list(Receiver.bodies)
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2, 3]
    assert tp.monitor(lines, key, now=NOW + timedelta(minutes=12))["findings"] == []
    # Silence: nothing after the last one.
    assert rules(tp.monitor(lines, key, now=NOW + timedelta(hours=1))) == [("HEARTBEAT_SILENT", "heartbeat:3")]
    # Forgery: an intruder edits a heartbeat to hide findings, without the key.
    forged = json.loads(lines[2])
    forged["state_digest"] = "0" * 64
    assert "HEARTBEAT_FORGED" in {f["rule_id"] for f in tp.monitor(lines[:2] + [json.dumps(forged)], key,
                                                                    now=NOW + timedelta(minutes=12))["findings"]}
    # Replay and loss.
    replayed = tp.monitor([lines[0], lines[2], lines[1]], key, now=NOW + timedelta(minutes=12))
    assert rules(replayed) == [("HEARTBEAT_GAP", "heartbeat:2-2"), ("HEARTBEAT_REPLAYED", "heartbeat:2")]
    # The sensor's own tamper findings and a changed state reach the monitor, once.
    (Path(world["config_dir"]) / "settings.toml").write_text("[alerts]\nenabled = false\n")
    for minute in (15, 20):
        settings, body = tp.heartbeat(config, manifest=manifest, sequence_path=sequence,
                                      now=NOW + timedelta(minutes=minute), runner=fake_systemctl({}),
                                      uptime=100.0, **world)
        tp.send(settings, body)
    report = tp.monitor(Receiver.bodies, key, now=NOW + timedelta(minutes=22))
    assert rules(report) == [("HEARTBEAT_REPORTS_TAMPER", "heartbeat:4"), ("SENSOR_STATE_CHANGED", "heartbeat:4")]
    assert tp.monitor(Receiver.bodies, "ab" * 32, now=NOW)["findings"][0]["rule_id"] == "HEARTBEAT_FORGED"


def test_the_schedule_includes_the_tamper_check_and_asks_for_heartbeat_setup(world, tmp_path):
    jobs = {row["job"]: row for row in sc.plan(system=False, directory=tmp_path / "u", launcher=["m"])["jobs"]}
    assert jobs["tamper"]["command"] == "m tamper check --alert"
    assert jobs["heartbeat"]["baseline"].startswith("megalodon heartbeat init --url")
    with pytest.raises(sc.ScheduleError, match="set up first: heartbeat"):
        sc.install(system=False, only=["heartbeat"], directory=tmp_path / "u", launcher=["m"],
                   runner=lambda system, *a: subprocess.CompletedProcess(a, 0, "", ""))


def test_cli(world, tmp_path, capsys, receiver):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    manifest = tmp_path / "tamper-cli.json"
    assert code("tamper", "baseline", "--manifest", str(manifest)) == 0
    assert code("tamper", "check", "--manifest", str(manifest)) == 0
    capsys.readouterr()
    assert code("heartbeat", "init", "--url", receiver) == 0
    printed = json.loads(capsys.readouterr().out)
    settings = json.loads((Path(world["config_dir"]) / "heartbeat.json").read_text())
    assert printed["key"] == settings["key"] and oct((Path(world["config_dir"]) / "heartbeat.json").stat().st_mode
                                                     & 0o777) == "0o600"
    key_file = tmp_path / "key"
    key_file.write_text(settings["key"] + "\n")
    os.chmod(key_file, 0o600)
    assert code("heartbeat", "send") == 0
    received = tmp_path / "received.jsonl"
    received.write_text("\n".join(Receiver.bodies) + "\n")
    capsys.readouterr()
    assert code("heartbeat", "monitor", "--input", str(received), "--key-file", str(key_file)) == 0
    capsys.readouterr()
    assert code("heartbeat", "monitor", "--input", str(received), "--key-file", str(key_file),
                "--max-gap", "0") == 1
    assert [f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]] == ["HEARTBEAT_SILENT"]


def test_a_changed_alert_destination_file_is_reported_without_its_contents(world, tmp_path):
    config = Path(world["config_dir"])
    (config / "alerts").mkdir()
    hook = config / "alerts/ntfy.url"
    hook.write_text("https://ntfy.example/alerts-7f2c\n")
    (config / "settings.toml").write_text('[alerts]\nenabled = true\n[[alerts.destination]]\nname = "phone"\n'
                                          f'kind = "webhook"\nurl_file = "{hook}"\n')
    manifest = tmp_path / "tamper.json"
    tp.baseline(manifest, **world)
    assert tp.check(manifest, runner=fake_systemctl({}), uptime=100.0, **world)["findings"] == []
    hook.write_text("https://attacker.example/sink\n")            # alerts redirected; settings.toml untouched
    report = tp.check(manifest, runner=fake_systemctl({}), uptime=100.0, **world)
    assert rules(report) == [("ALERTS_CONFIG_CHANGED", f"config:secret:{hook}")]
    assert "attacker" not in json.dumps(report) and "7f2c" not in manifest.read_text(), "hashes only"
    hook.unlink()
    assert "removed" in tp.check(manifest, runner=fake_systemctl({}), uptime=100.0, **world)["findings"][0]["detail"]


def test_removing_the_tamper_baseline_is_reported_on_and_off_the_machine(world, tmp_path, receiver):
    config, sequence = tmp_path / "heartbeat.json", tmp_path / "state/sequence.json"
    key = tp.init_heartbeat(receiver, config)["key"]
    manifest = tmp_path / "tamper.json"
    tp.baseline(manifest, **world)

    def beat(minute):
        settings, body = tp.heartbeat(config, manifest=manifest, sequence_path=sequence,
                                      now=NOW + timedelta(minutes=minute), runner=fake_systemctl({}),
                                      uptime=100.0, **world)
        tp.send(settings, body)
        return body
    assert beat(0)["tamper_baseline"] is True and Receiver.bodies
    manifest.unlink()
    body = beat(5)
    assert body["tamper_baseline"] is False
    assert [(f["rule_id"], f["subject"]) for f in body["findings"]] == [("CONFIG_REMOVED", "config:tamper.json")]
    report = tp.monitor(Receiver.bodies, key, now=NOW + timedelta(minutes=6))
    assert {"TAMPER_BASELINE_LOST", "HEARTBEAT_REPORTS_TAMPER"} <= {f["rule_id"] for f in report["findings"]}
    # Wiping the sender's own record as well still shows from outside.
    sequence.unlink()
    Receiver.bodies.clear()
    tp.baseline(manifest, **world)
    beat(10)
    manifest.unlink()
    sequence.unlink()
    beat(15)
    lost = tp.monitor(Receiver.bodies, key, now=NOW + timedelta(minutes=16))
    assert "TAMPER_BASELINE_LOST" in {f["rule_id"] for f in lost["findings"]}
