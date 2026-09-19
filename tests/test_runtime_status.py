"""Startup runtime observations remain bounded and disclose only closed states."""

from pathlib import Path

from megalodon import runtime_status
from megalodon.readiness import TOOL_IDS


def _process(root: Path, pid: int, name: str) -> None:
    directory = root / str(pid)
    directory.mkdir(parents=True)
    (directory / "comm").write_text(name + "\n")


def test_runtime_report_matches_only_known_process_names(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_status, "runtime_platform", lambda: "linux")
    _process(tmp_path, 12, "suricata")
    _process(tmp_path, 13, "ollama")
    _process(tmp_path, 14, "unrelated-private-name")

    report = runtime_status.runtime_report(tmp_path)

    assert report["schema"] == "megalodon-tool-runtime-v1"
    assert [item["id"] for item in report["tools"]] == list(TOOL_IDS)
    statuses = {item["id"]: item["status"] for item in report["tools"]}
    assert statuses["python-sqlite"] == "running"
    assert statuses["suricata"] == "running"
    assert statuses["qwen-ollama"] == "running"
    assert statuses["zeek"] == "not_running"
    assert statuses["nmap"] == "not_applicable"
    serialized = repr(report)
    assert "unrelated-private-name" not in serialized
    assert "pid" not in serialized.lower()


def test_runtime_report_fails_closed_when_process_snapshot_is_excessive(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_status, "runtime_platform", lambda: "linux")
    monkeypatch.setattr(runtime_status, "MAX_PROCESS_ENTRIES", 1)
    _process(tmp_path, 1, "suricata")
    _process(tmp_path, 2, "ollama")

    statuses = {item["id"]: item["status"] for item in runtime_status.runtime_report(tmp_path)["tools"]}

    assert statuses["python-sqlite"] == "running"
    assert statuses["suricata"] == "not_checked"
    assert statuses["qwen-ollama"] == "not_checked"
    assert statuses["nmap"] == "not_applicable"
