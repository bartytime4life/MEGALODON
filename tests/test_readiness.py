"""Readiness receipts report bounded presence without exercising companion tools."""

from __future__ import annotations

import builtins
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess

import pytest

from megalodon.capabilities import catalog
from megalodon.cli import main
from megalodon import readiness


@pytest.fixture(autouse=True)
def linux_profile(monkeypatch):
    monkeypatch.setattr(readiness, "runtime_platform", lambda: "linux")


def _statuses(report):
    return {item["id"]: item["status"] for item in report["tools"]}


def test_receipt_is_closed_bounded_catalog_aligned_and_has_no_host_details(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    before = datetime.now(timezone.utc).replace(microsecond=0)
    rendered = readiness.readiness_json()
    after = datetime.now(timezone.utc).replace(microsecond=0)
    report = json.loads(rendered)
    assert set(report) == {"schema", "checked_at", "platform", "probe_mode", "tools", "boundaries"}
    assert report["schema"] == "megalodon-tool-readiness-v1"
    assert report["platform"] == "linux"
    assert report["probe_mode"] == "path_presence_only"
    assert before <= datetime.fromisoformat(report["checked_at"].replace("Z", "+00:00")) <= after
    assert len(report["checked_at"]) == 20
    assert report["boundaries"] == list(readiness.BOUNDARIES)
    expected_ids = [item["id"] for item in catalog("linux")["components"]]
    assert [item["id"] for item in report["tools"]] == expected_ids
    assert all(set(item) == {"id", "status"} for item in report["tools"])
    assert {item["status"] for item in report["tools"]} <= readiness.STATUSES
    assert _statuses(report)["python-sqlite"] == "not_checked"
    assert _statuses(report)["scapy"] == "not_checked"
    assert len(rendered.encode("utf-8")) + 1 <= readiness.MAX_REPORT_BYTES
    assert str(tmp_path) not in rendered


def test_regular_executable_presence_does_not_execute_or_import(monkeypatch, tmp_path):
    marker = tmp_path / "unexpected-execution"
    executable = tmp_path / "tshark"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    executable.chmod(0o700)
    (tmp_path / "zeek").write_text("not executable", encoding="utf-8")
    (tmp_path / "suricata").mkdir()
    (tmp_path / "ollama").symlink_to(executable)
    (tmp_path / "nagios4").symlink_to(executable)
    monkeypatch.setenv("PATH", str(tmp_path))

    def denied(*args, **kwargs):
        raise AssertionError("readiness must not execute, connect, open content or import companion tools")

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in {"scapy", "ollama"}:
            denied()
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", denied)
        guard.setattr(builtins, "__import__", guarded_import)
        guard.setattr(subprocess, "Popen", denied)
        guard.setattr(subprocess, "run", denied)
        guard.setattr(os, "system", denied)
        guard.setattr(socket, "socket", denied)
        guard.setattr(socket, "create_connection", denied)
        guard.setattr(sqlite3, "connect", denied)
        report = readiness.readiness_report()
    values = _statuses(report)
    assert values["wireshark-tshark"] == "executable_found"
    assert values["zeek"] == "not_found"
    assert values["suricata"] == "not_found"
    assert values["qwen-ollama"] == "executable_found"
    assert values["nagios-core"] == "executable_found"
    assert not marker.exists()


@pytest.mark.parametrize(
    "path",
    [
        None, "", ".", "bin", "/bin:", ":/bin", "/bin::/usr/bin", "/bin:relative",
        "/bin/../sbin", "/bin/./tools", "//server/tools", "/bin\x00", "/bin\n",
        "/bin\x7f", "/bin\udcff", "a" * (readiness.MAX_PATH_BYTES + 1),
        "/" + "a" * readiness.MAX_DIRECTORY_BYTES,
        ":".join(["/bin"] * (readiness.MAX_PATH_ENTRIES + 1)),
        ":".join(["/" + "é" * 2047] * 5),
    ],
)
def test_invalid_path_is_rejected_before_any_probe(monkeypatch, path):
    def denied(*args, **kwargs):
        raise AssertionError("invalid PATH must not trigger filesystem probes")

    monkeypatch.setattr(readiness.os.environ, "get", lambda key: path)
    with monkeypatch.context() as guard:
        guard.setattr(os, "stat", denied)
        guard.setattr(os, "access", denied)
        report = readiness.readiness_report()
    assert {_statuses(report)[tool] for tool in readiness.TOOL_IDS} == {"not_checked"}


def test_path_exact_bounds_and_deduplication():
    maximum_directory = "/" + "a" * (readiness.MAX_DIRECTORY_BYTES - 1)
    assert readiness._path_directories(maximum_directory) == (maximum_directory,)
    entries = [maximum_directory] * 3
    remaining = readiness.MAX_PATH_BYTES - sum(map(len, entries)) - 3
    exact_path = ":".join([*entries, "/" + "b" * (remaining - 1)])
    assert len(exact_path.encode("utf-8")) == readiness.MAX_PATH_BYTES
    assert readiness._path_directories(exact_path) is not None
    assert readiness._path_directories(exact_path + "b") is None
    assert readiness._path_directories(":".join(["/bin"] * readiness.MAX_PATH_ENTRIES)) == ("/bin",)
    assert readiness._path_directories("/bin/:/bin:/") == ("/bin", "/")


def test_probe_count_is_fixed_and_never_enumerates_directories(monkeypatch):
    directories = tuple(f"/tools/{number}" for number in range(readiness.MAX_PATH_ENTRIES))
    monkeypatch.setenv("PATH", ":".join(directories))
    visited = []
    accessed = []

    def fake_stat(candidate):
        visited.append(candidate)
        return os.stat_result((stat.S_IFREG | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def fake_access(candidate, mode, *, effective_ids):
        accessed.append(candidate)
        assert mode == os.X_OK
        assert effective_ids is True
        return False

    def denied(*args, **kwargs):
        raise AssertionError("directory enumeration is not allowed")

    with monkeypatch.context() as guard:
        guard.setattr(os, "stat", fake_stat)
        guard.setattr(os, "access", fake_access)
        guard.setattr(os, "listdir", denied)
        guard.setattr(os, "scandir", denied)
        report = readiness.readiness_report()
    binaries = {name for _, name in readiness.TOOL_EXECUTABLES if name is not None}
    assert len(visited) == len(binaries) * readiness.MAX_PATH_ENTRIES == 768
    assert accessed == visited
    assert {Path(candidate).name for candidate in visited} == binaries
    assert all(Path(candidate).parent.as_posix() in directories for candidate in visited)
    assert set(_statuses(report).values()) == {"not_found", "not_checked"}


@pytest.mark.parametrize("failure", [PermissionError, OSError])
def test_unreadable_metadata_is_unknown_not_absent(monkeypatch, failure):
    monkeypatch.setenv("PATH", "/private")

    def unreadable(candidate):
        raise failure("host-specific detail must not escape")

    with monkeypatch.context() as guard:
        guard.setattr(os, "stat", unreadable)
        rendered = readiness.readiness_json()
    assert set(_statuses(json.loads(rendered)).values()) == {"not_checked"}
    assert "host-specific" not in rendered
    assert "/private" not in rendered


def test_later_executable_can_be_found_after_an_unreadable_entry(monkeypatch, tmp_path):
    executable = tmp_path / "tshark"
    executable.write_text("inert", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", f"/private:{tmp_path}")
    original_stat = os.stat

    def restricted_stat(candidate):
        if candidate.startswith("/private/"):
            raise PermissionError("private")
        return original_stat(candidate)

    with monkeypatch.context() as guard:
        guard.setattr(os, "stat", restricted_stat)
        statuses = _statuses(readiness.readiness_report())
    assert statuses["wireshark-tshark"] == "executable_found"
    assert statuses["zeek"] == "not_checked"


@pytest.mark.parametrize("platform", ["windows", "other"])
def test_non_linux_never_reads_path_or_probes(monkeypatch, platform):
    monkeypatch.setattr(readiness, "runtime_platform", lambda: platform)

    def denied(*args, **kwargs):
        raise AssertionError("unsupported platform must not read PATH or probe")

    with monkeypatch.context() as guard:
        guard.setattr(os.environ, "get", denied)
        guard.setattr(os, "stat", denied)
        guard.setattr(os, "access", denied)
        report = readiness.readiness_report()
    assert report["platform"] == platform
    assert set(_statuses(report).values()) == {"not_checked"}


def test_cli_emits_only_receipt_and_does_not_load_configuration(monkeypatch, capsys, tmp_path):
    from megalodon import cli

    monkeypatch.setenv("PATH", str(tmp_path))

    def denied(*args, **kwargs):
        raise AssertionError("readiness CLI must not load configuration, mutate stores or run tools")

    monkeypatch.setattr(cli, "_load", denied)
    monkeypatch.setattr(cli, "Store", denied)
    monkeypatch.setattr(cli, "MegalodonService", denied)
    monkeypatch.setattr(cli, "NftablesFirewall", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(sqlite3, "connect", denied)
    with pytest.raises(SystemExit) as caught:
        main(["readiness"])
    assert caught.value.code == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out)["schema"] == readiness.SCHEMA
    assert len(output.out.encode("utf-8")) <= readiness.MAX_REPORT_BYTES
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("arguments", [["--platform", "linux"], ["--tool", "sh"], ["--path", "/bin"]])
def test_cli_has_no_arbitrary_probe_or_platform_override(arguments, capsys):
    with pytest.raises(SystemExit) as caught:
        main(["readiness", *arguments])
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""
