"""Capability discovery stays static, bounded, and honest about support."""

from __future__ import annotations

import json
import socket
import subprocess

import pytest

from megalodon.capabilities import PLATFORMS, SCHEMA, STATUSES, catalog, runtime_platform
from megalodon.cli import main


def test_catalog_is_closed_consistent_and_fresh():
    value = catalog("linux")
    assert set(value) == {
        "schema",
        "selected_platform",
        "catalog_mode",
        "default_posture",
        "installation_performed",
        "network_access_performed",
        "components",
        "excluded",
    }
    assert value["schema"] == SCHEMA
    assert value["catalog_mode"] == "static_no_host_probe"
    assert value["default_posture"] == "observe_only"
    assert value["installation_performed"] is False
    assert value["network_access_performed"] is False
    assert len({item["id"] for item in value["components"]}) == len(value["components"])
    for item in value["components"]:
        assert set(item) == {
            "id",
            "software",
            "software_class",
            "integration",
            "selected_status",
            "platforms",
            "boundary",
        }
        assert item["software_class"] == "free_or_open_source"
        assert set(item["platforms"]) == set(PLATFORMS)
        assert set(item["platforms"].values()) <= STATUSES
        assert item["selected_status"] == item["platforms"]["linux"]

    value["components"][0]["platforms"]["linux"] = "unsupported"
    assert catalog("linux")["components"][0]["platforms"]["linux"] == "implemented"


def test_critical_boundaries_are_explicit():
    value = catalog("windows")
    items = {item["id"]: item for item in value["components"]}
    assert items["python-sqlite"]["selected_status"] == "evaluation_only"
    assert items["wireshark-tshark"]["selected_status"] == "manual_only"
    assert items["zeek"]["selected_status"] == "guest_only"
    assert items["suricata"]["selected_status"] == "contract_only"
    assert items["scapy"]["selected_status"] == "unsupported"
    assert items["nftables"]["selected_status"] == "unsupported"
    assert items["nftables"]["integration"] == "plan_only_time_limited_response"
    assert items["nftables"]["boundary"] == (
        "Plans are inert review evidence; live application is unsupported and refused."
    )
    assert items["qwen-ollama"]["selected_status"] == "contract_only"
    assert "no CLI" in items["qwen-ollama"]["boundary"]
    assert items["nmap"]["selected_status"] == "proposed"
    assert items["ossec"]["selected_status"] == "proposed"
    assert items["greenbone"]["selected_status"] == "guest_only"
    assert items["zabbix"]["selected_status"] == "proposed"
    assert items["nagios-core"]["selected_status"] == "guest_only"
    assert value["excluded"] == [
        {
            "id": "npcap",
            "software": "Npcap",
            "reason": "not_an_open_source_baseline_dependency",
            "boundary": "Windows live capture is unsupported; saved-capture analysis does not require Npcap.",
        }
    ]


def test_suricata_runtime_status_matches_reader_and_explicit_consumer():
    linux = {item["id"]: item for item in catalog("linux")["components"]}
    windows = {item["id"]: item for item in catalog("windows")["components"]}
    assert linux["suricata"]["selected_status"] == "implemented"
    assert linux["suricata"]["integration"] == (
        "completed_file_alert_reader_and_durable_consumer"
    )
    assert "main-thread API" in linux["suricata"]["boundary"]
    assert "one completed private contract envelope file" in linux["suricata"]["boundary"]
    assert "pre-created private store" in linux["suricata"]["boundary"]
    assert windows["suricata"]["selected_status"] == "contract_only"


def test_planned_interface_slots_never_claim_runtime_authority():
    items = {item["id"]: item for item in catalog("linux")["components"]}
    planned = {"nmap", "ossec", "greenbone", "zabbix", "nagios-core"}
    assert set(items) >= planned
    assert {items[item]["selected_status"] for item in planned} <= {"contract_only", "proposed"}
    assert items["qwen-ollama"]["selected_status"] == "manual_only"
    assert "no CLI" in items["qwen-ollama"]["boundary"]
    assert "No scan launcher" in items["nmap"]["boundary"]
    assert "No daemon" in items["ossec"]["boundary"]
    assert "No scanner or feed control" in items["greenbone"]["boundary"]
    assert "No endpoint, credential" in items["zabbix"]["boundary"]
    assert "No CGI endpoint, credential" in items["nagios-core"]["boundary"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("linux", "linux"), ("linux2", "linux"), ("win32", "windows"), ("cygwin", "windows"), ("darwin", "other")],
)
def test_runtime_platform_families(value, expected):
    assert runtime_platform(value) == expected


def test_cli_performs_no_network_process_or_install_probe(monkeypatch, capsys):
    def denied(*args, **kwargs):
        raise AssertionError("capability reporting must not open sockets or launch processes")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    with pytest.raises(SystemExit) as caught:
        main(["capabilities", "--platform", "windows"])
    assert caught.value.code == 0
    value = json.loads(capsys.readouterr().out)
    assert value == catalog("windows")


def test_invalid_platform_profile_is_rejected():
    with pytest.raises(ValueError, match="unsupported platform profile"):
        catalog("secret-platform")
