"""Opt-in companion jobs are scoped, bounded and counts-only."""

import json
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from megalodon.companion_automation import (
    CompanionAutomation, CompanionConfig, _run_fixed, load_config,
)
from megalodon.config import AISettings


def _config(tmp_path: Path, source: str) -> CompanionConfig:
    config = tmp_path / "companions.toml"
    config.write_text(source)
    return load_config(config)


def test_scopes_are_explicit_and_conservative(tmp_path):
    empty = _config(tmp_path, "")
    assert empty.nmap_target is None and empty.clamav_paths == () and not empty.osquery_enabled
    folder = tmp_path / "scan"
    folder.mkdir()
    accepted = _config(tmp_path, f'[collection]\ninterval_seconds=300\nnmap_target="192.168.1.0/24"\nclamav_paths=["{folder}"]\nosquery_enabled=true\n')
    assert accepted.nmap_target == "192.168.1.0/24" and accepted.clamav_paths == (folder,)
    for target in ("8.8.8.8", "192.0.2.1", "0.0.0.0", "10.0.0.0/16", "example.com"):
        with pytest.raises(ValueError):
            _config(tmp_path, f'[collection]\nnmap_target="{target}"\n')
    with pytest.raises(ValueError):
        _config(tmp_path, '[collection]\nclamav_paths=["/"]\n')
    with pytest.raises(ValueError):
        _config(tmp_path, '[watch]\nclamscan_text="/tmp/report.txt"\n')


def test_watched_report_is_aggregated_without_identifiers_and_qwen_gets_counts(tmp_path, monkeypatch):
    watched = tmp_path / "osquery.json"
    watched.write_text('[{"package_count":"137"}]')
    config = _config(tmp_path, f'[watch]\nosquery_json="{watched}"\n[qwen]\nadvisory=true\n')
    prompts = []

    def generate(_settings, prompt, *, max_tokens):
        prompts.append(prompt)
        assert max_tokens == 120
        return "Advisory: package count is not proof of safety."

    monkeypatch.setattr("megalodon.ai_provider.generate", generate)
    worker = CompanionAutomation(config, AISettings(enabled=True))
    worker.tick()
    result = worker.snapshot()
    assert result["results"]["osquery"]["package_rows"] == 137
    assert "Advisory" in result["advisory"]["osquery"]
    assert "package_count" not in json.dumps(result)
    assert "137" in prompts[0] and str(watched) not in prompts[0]
    assert len(prompts) == 1
    worker.tick()
    assert len(prompts) == 1
    watched.write_text('[{"package_count":"oops","path":"secret"}]')
    worker.tick()
    assert worker.snapshot()["results"]["osquery"]["package_rows"] == 137
    assert "preserved" in worker.snapshot()["status"]["osquery"]


def test_fixed_collector_runs_only_configured_action(tmp_path, monkeypatch):
    config = _config(tmp_path, '[collection]\ninterval_seconds=300\nnmap_target="127.0.0.1"\n')
    calls = []

    def run(argv, limit, timeout, cancel):
        calls.append((argv, limit, timeout))
        return b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05" start="1700000000"><runstats><finished exit="success" time="1700000010"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>', 0

    monkeypatch.setattr("megalodon.companion_automation._run_fixed", run)
    worker = CompanionAutomation(config, AISettings())
    worker.tick()
    assert [call[0][0] for call in calls] == ["nmap"]
    assert calls[0][0][-1] == "127.0.0.1/32"
    assert worker.snapshot()["results"]["nmap"]["hosts"] == [0, 0]
    worker.tick()
    assert len(calls) == 1


def test_child_output_is_bounded_without_shell():
    with pytest.raises(ValueError, match="exceeded limit"):
        _run_fixed(["python3", "-c", "print('x'*1000)"], 100, 5)


def test_local_hud_companion_route_is_read_only_and_query_closed(tmp_path):
    from megalodon.dashboard import DashboardHandler

    worker = CompanionAutomation(_config(tmp_path, ""), AISettings())
    handler = type("CompanionHandler", (DashboardHandler,), {"companion_automation": worker})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/api/companions"
    try:
        with urlopen(base, timeout=2) as response:
            payload = json.load(response)
        assert payload["schema"] == "megalodon-companion-automation-v1"
        assert payload["results"] == {}
        with pytest.raises(HTTPError) as error:
            urlopen(base + "?path=/etc/passwd", timeout=2)
        assert error.value.code == 400
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
