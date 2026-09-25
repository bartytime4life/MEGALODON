from __future__ import annotations

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import threading

import pytest

from megalodon import tool_heartbeat, tool_installer
from megalodon.tool_heartbeat import Heartbeat, heartbeat_report
from megalodon.tool_installer import Installer, RECIPES, install_command


def _fake_proc(root: Path, processes: dict[int, tuple[str, int]], btime: int = 1_700_000_000) -> Path:
    root.mkdir()
    (root / "stat").write_text(f"cpu 0 0 0\nbtime {btime}\n")
    for pid, (name, start_ticks) in processes.items():
        entry = root / str(pid)
        entry.mkdir()
        (entry / "comm").write_text(name + "\n")
        fields = ["S"] + ["0"] * 18 + [str(start_ticks)] + ["0"] * 10
        (entry / "stat").write_text(f"{pid} ({name}) " + " ".join(fields))
    (root / "self").mkdir()
    (root / "self" / "stat").write_text("1 (python) " + " ".join(["S"] + ["0"] * 18 + ["100"]))
    return root


def test_report_covers_fixed_tools_with_lights(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_heartbeat, "runtime_platform", lambda: "linux")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("nmap", "suricata", "zabbix_agent2"):
        exe = bin_dir / name
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # An Ollama store with no qwen2.5:7b manifest is positive evidence of "missing".
    (tmp_path / "home" / ".ollama" / "models" / "manifests").mkdir(parents=True)
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    monkeypatch.setattr(tool_heartbeat, "OLLAMA_MODEL_ROOTS", ())
    monkeypatch.setattr(tool_heartbeat, "PROBES", {
        key: tool_heartbeat.ToolProbe(probe.executables, (), (), probe.python_module, probe.processes, probe.service)
        for key, probe in tool_heartbeat.PROBES.items()
    })
    proc = _fake_proc(tmp_path / "proc", {42: ("zabbix_agent2", 500), 77: ("ollama", 1000)})
    report = heartbeat_report(proc)
    tools = {tool["id"]: tool for tool in report["tools"]}
    assert report["schema"] == "megalodon-tool-heartbeat-v1"
    assert list(tools) == list(RECIPES)
    assert tools["core"]["light"] == "green"
    assert tools["nmap"] == {**tools["nmap"], "installed": "yes", "service": "standalone", "light": "green"}
    # Installed service that is not running is amber, not green.
    assert tools["suricata"]["light"] == "amber"
    # A running agent is green with an uptime anchor derived from /proc.
    assert tools["zabbix"]["light"] == "green"
    assert tools["zabbix"]["running_since"] == "2023-11-14T22:13:25Z"
    # A running process counts as installed even when off PATH, but without
    # the model downloaded the light stays amber.
    assert tools["qwen"]["installed"] == "yes" and tools["qwen"]["model"] == "missing"
    assert tools["qwen"]["light"] == "amber"
    assert tools["nmap"]["model"] is None
    assert tools["tshark"]["light"] == "red" and tools["tshark"]["service"] == "none"
    for tool in report["tools"]:
        assert set(tool) == {"id", "installed", "installed_since", "service", "running_since", "light", "expects_service", "model"}
    assert "/" not in json.dumps([t["id"] for t in report["tools"]])


def test_heartbeat_cache_and_invalidate(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(tool_heartbeat, "heartbeat_report", lambda root: calls.append(1) or {"n": len(calls), "tools": []})
    beat = Heartbeat(tmp_path)
    assert beat.snapshot() == beat.snapshot()
    assert len(calls) == 1
    beat.invalidate()
    beat.snapshot()
    assert len(calls) == 2


def test_recipes_are_closed_and_never_interpolate_requests(monkeypatch):
    monkeypatch.setattr(tool_installer, "runtime_platform", lambda: "linux")
    which = {"apt-get": "/usr/bin/apt-get", "pkexec": "/usr/bin/pkexec"}.get
    command = install_command("tshark", which=which, is_root=False)
    assert command[:3] == ["/usr/bin/pkexec", "/bin/sh", "-c"]
    assert "install-setuid boolean false" in command[3]
    assert command[3].endswith("apt-get install -y --no-install-recommends tshark")
    assert install_command("tshark", which=which, is_root=True)[0] == "/bin/sh"
    assert install_command("tshark", which={}.get, is_root=False) is None
    for guided in ("core", "zeek", "osquery", "ossec", "greenbone"):
        assert install_command(guided, which=which) is None
    assert install_command("qwen", which={}.get) is None
    with pytest.raises(KeyError):
        Installer().start("rm -rf /")


def test_installer_runs_one_job_and_reports_output():
    finished = threading.Event()

    class FakeProcess:
        stdout = iter(["line one\n", "line two\n"])

        def wait(self):
            return 0

    seen = []
    installer = Installer(on_finish=finished.set, runner=lambda argv, **kw: seen.append(argv) or FakeProcess())
    installer.start("scapy")
    assert finished.wait(5)
    status = installer.status()
    assert status["state"] == "succeeded" and status["tool"] == "scapy"
    assert status["output"] == ["line one", "line two"]
    assert seen[0][-1] == "scapy>=2.5,<3"


def _request(server, method, path, headers=None, body=None):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    connection.request(method, path, body=body, headers={"Host": f"127.0.0.1:{server.server_port}", **(headers or {})})
    response = connection.getresponse()
    return response.status, response.read()


def test_routes_require_explicit_same_origin_requests(monkeypatch):
    from http.server import ThreadingHTTPServer
    from megalodon.dashboard import DashboardHandler

    started = []
    installer = Installer()
    monkeypatch.setattr(installer, "start", lambda tool, action="install": started.append(tool) or installer.status())
    monkeypatch.setattr("megalodon.dashboard._tool_management_user", lambda: True)
    handler = type("H", (DashboardHandler,), {"heartbeat": Heartbeat(), "installer": installer,
                   "tool_management_enabled": True, "install_operator_token": "t" * 32})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _request(server, "GET", "/api/heartbeat")[0] == 403
        status, body = _request(server, "GET", "/api/heartbeat", {"X-Megalodon-Check": "1"})
        assert status == 200 and json.loads(body)["schema"] == "megalodon-tool-heartbeat-v1"
        origin = f"http://127.0.0.1:{server.server_port}"
        good = {"Origin": origin, "Content-Type": "application/json", "X-Megalodon-Install": "1",
                "X-Megalodon-Install-Token": "t" * 32}
        payload = json.dumps({"tool": "nmap"})
        assert _request(server, "POST", "/api/install", {**good, "Origin": "http://evil.example"}, payload)[0] == 403
        assert _request(server, "POST", "/api/install", {k: v for k, v in good.items() if k != "X-Megalodon-Install"}, payload)[0] == 403
        assert _request(server, "POST", "/api/install", good, json.dumps({"tool": "bash"}))[0] == 400
        assert _request(server, "POST", "/api/install", good, payload)[0] == 202
        assert started == ["nmap"]
    finally:
        server.shutdown()
        server.server_close()


def test_installer_kills_a_hung_install():
    import time
    finished = threading.Event()

    class HungProcess:
        def __init__(self):
            self.killed = threading.Event()

        @property
        def stdout(self):
            def lines():
                yield "starting\n"
                self.killed.wait(5)
            return lines()

        def kill(self):
            self.killed.set()

        def wait(self):
            return -9

    process = HungProcess()
    installer = Installer(on_finish=finished.set, runner=lambda argv, **kw: process, timeout=0.2)
    started = time.monotonic()
    installer.start("scapy")
    assert finished.wait(5)
    assert time.monotonic() - started < 3
    status = installer.status()
    assert status["state"] == "failed" and status["exit_code"] is None
    assert status["output"][-1] == "The job timed out and was stopped."


def test_qwen_model_manifest_turns_the_light_green(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_heartbeat, "runtime_platform", lambda: "linux")
    monkeypatch.setattr(tool_heartbeat, "OLLAMA_MODEL_ROOTS", ())
    models = tmp_path / "models"
    manifest = models.joinpath(*tool_heartbeat.QWEN_MODEL_MANIFEST)
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}")
    monkeypatch.setenv("OLLAMA_MODELS", str(models))
    monkeypatch.setenv("PATH", "/nonexistent")
    proc = _fake_proc(tmp_path / "proc", {77: ("ollama", 1000)})
    qwen = next(tool for tool in heartbeat_report(proc)["tools"] if tool["id"] == "qwen")
    assert qwen["model"] == "present" and qwen["light"] == "green"


def test_start_command_uses_only_fixed_existing_units(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_installer, "runtime_platform", lambda: "linux")
    units = tmp_path / "units"
    units.mkdir()
    (units / "zabbix-agent.service").write_text("[Unit]\n")
    which = {"systemctl": "/usr/bin/systemctl", "pkexec": "/usr/bin/pkexec"}.get
    dirs = (str(units),)
    assert tool_installer.start_command("zabbix", which=which, is_root=False, directories=dirs) == [
        "/usr/bin/pkexec", "/usr/bin/systemctl", "start", "zabbix-agent.service"]
    assert tool_installer.start_command("zabbix", which=which, is_root=True, directories=dirs)[0] == "/usr/bin/systemctl"
    # No unit file, no systemctl, or a standalone tool: no command at all.
    assert tool_installer.start_command("suricata", which=which, directories=dirs) is None
    assert tool_installer.start_command("zabbix", which={}.get, directories=dirs) is None
    assert tool_installer.start_command("nmap", which=which, directories=dirs) is None


def test_install_route_accepts_only_known_actions(monkeypatch):
    from http.server import ThreadingHTTPServer
    from megalodon.dashboard import DashboardHandler

    calls = []
    installer = Installer()
    monkeypatch.setattr(installer, "start", lambda tool, action="install": calls.append((tool, action)) or installer.status())
    monkeypatch.setattr("megalodon.dashboard._tool_management_user", lambda: True)
    handler = type("H", (DashboardHandler,), {"heartbeat": Heartbeat(), "installer": installer,
                   "tool_management_enabled": True, "install_operator_token": "t" * 32})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        good = {"Origin": f"http://127.0.0.1:{server.server_port}", "Content-Type": "application/json",
                "X-Megalodon-Install": "1", "X-Megalodon-Install-Token": "t" * 32}
        assert _request(server, "POST", "/api/install", good, json.dumps({"tool": "zabbix", "action": "start"}))[0] == 202
        assert _request(server, "POST", "/api/install", good, json.dumps({"tool": "zabbix", "action": "stop"}))[0] == 400
        assert _request(server, "POST", "/api/install", good, json.dumps({"tool": "zabbix", "extra": 1}))[0] == 400
        assert calls == [("zabbix", "start")]
    finally:
        server.shutdown()
        server.server_close()


def test_history_tracks_changes_and_time_weighted_health():
    history = tool_heartbeat.HeartbeatHistory(started=1_000)
    report = lambda light: {"tools": [{"id": "suricata", "light": light}]}
    history.observe(report("green"), now=1_000)
    history.observe(report("green"), now=1_060)   # 60 s green
    history.observe(report("amber"), now=1_080)   # +20 s green, then amber
    result = history.observe(report("green"), now=1_100)  # +20 s amber
    entry = result["tools"]["suricata"]
    assert result["since"] == "1970-01-01T00:16:40Z"
    assert [change["light"] for change in entry["changes"]] == ["green", "amber", "green"]
    assert entry["healthy_percent"] == 80.0 and entry["observed_seconds"] == 100
    for step in range(20):
        history.observe(report("red" if step % 2 else "green"), now=1_600 + step)
    assert len(history.observe(report("green"), now=2_000)["tools"]["suricata"]["changes"]) == tool_heartbeat.MAX_HISTORY_CHANGES


def test_snapshot_includes_history(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_heartbeat, "heartbeat_report",
                        lambda root: {"tools": [{"id": "nmap", "light": "red"}]})
    payload = json.loads(Heartbeat(tmp_path).snapshot())
    assert payload["history"]["tools"]["nmap"]["changes"][0]["light"] == "red"


def test_qwen_model_is_unknown_without_a_visible_store(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_heartbeat, "OLLAMA_MODEL_ROOTS", ())
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    # No store anywhere: the server may keep models where the HUD cannot see.
    assert tool_heartbeat._model_status(tmp_path / "home") == "unknown"
    store = tmp_path / "home" / ".ollama" / "models" / "manifests"
    store.mkdir(parents=True)
    assert tool_heartbeat._model_status(tmp_path / "home") == "missing"
    unreadable = tmp_path / "service"
    (unreadable / "manifests").mkdir(parents=True)
    monkeypatch.setattr(tool_heartbeat, "OLLAMA_MODEL_ROOTS", (str(unreadable),))
    real_stat = os.stat

    def guarded(path, *args, **kwargs):
        if str(path).startswith(str(unreadable)):
            raise PermissionError(13, "denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(tool_heartbeat.os, "stat", guarded)
    # A readable empty store plus an unreadable one cannot prove absence.
    assert tool_heartbeat._model_status(tmp_path / "home") == "unknown"
