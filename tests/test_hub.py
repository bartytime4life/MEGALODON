"""The integration hub stays closed, deterministic, and non-executing."""

from __future__ import annotations

import json
import socket
import subprocess

import pytest

from megalodon.capabilities import catalog
from megalodon.cli import main
from megalodon.hub import HUB_MODE, SCHEMA, WORKFLOW_IDS, integration_plan


def test_plan_covers_each_selected_component_once():
    value = integration_plan("linux")
    assert set(value) == {
        "schema",
        "capability_schema",
        "selected_platform",
        "hub_mode",
        "default_posture",
        "execution_performed",
        "network_access_performed",
        "host_change_performed",
        "action_status",
        "workflows",
    }
    assert value["schema"] == SCHEMA
    assert value["hub_mode"] == HUB_MODE == "static_plan_only"
    assert value["default_posture"] == "observe_only"
    assert value["execution_performed"] is False
    assert value["network_access_performed"] is False
    assert value["host_change_performed"] is False
    assert value["action_status"] == "not_attempted"
    assert tuple(item["id"] for item in value["workflows"]) == WORKFLOW_IDS

    expected = {item["id"] for item in catalog("linux")["components"]}
    actual = [item["component"] for item in value["workflows"]]
    assert set(actual) == expected
    assert len(actual) == len(set(actual))


@pytest.mark.parametrize("platform", ("linux", "windows", "other"))
def test_statuses_are_derived_from_capability_catalog(platform):
    expected = {item["id"]: item["selected_status"] for item in catalog(platform)["components"]}
    value = integration_plan(platform)
    assert value["selected_platform"] == platform
    for item in value["workflows"]:
        assert item["selected_status"] == expected[item["component"]]
        assert set(item) == {
            "id",
            "component",
            "software",
            "selected_status",
            "source_kind",
            "integration_owner",
            "input_contract",
            "output_contract",
            "entry_point",
            "launch_policy",
            "data_boundary",
            "action_boundary",
            "next_gate",
        }


def test_workflow_filter_returns_one_fresh_plan():
    first = integration_plan("linux", "alert-metadata")
    assert [item["id"] for item in first["workflows"]] == ["alert-metadata"]
    assert first["workflows"][0]["selected_status"] == "implemented"
    assert first["workflows"][0]["entry_point"] == (
        "Python APIs: read_completed_raw_eve, read_completed_file, "
        "consume_publication, reconcile_publication"
    )

    first["workflows"][0]["selected_status"] = "unsupported"
    assert integration_plan("linux", "alert-metadata")["workflows"][0]["selected_status"] == "implemented"


def test_workflow_contracts_match_their_owned_entry_points():
    alert = integration_plan("linux", "alert-metadata")["workflows"][0]
    assert alert["input_contract"] == (
        "pinned Suricata 8.0.7 alert-only EVE file or "
        "suricata-eve-alert-input-v1 envelope"
    )
    assert alert["output_contract"] == (
        "immutable external-alert-v1 publication plus terminal consumer or reconciliation receipt"
    )
    assert alert["launch_policy"] == (
        "explicit_checksum_bound_completed_file_conversion_or_envelope_read_then_"
        "explicit_local_transaction_or_read_only_reconciliation"
    )
    assert "no sensor launch" in alert["action_boundary"]
    assert "explicit existing store" in alert["action_boundary"]
    assert "reconciliation is read-only" in alert["action_boundary"]

    response = integration_plan("linux", "time-limited-response")["workflows"][0]
    assert response["entry_point"] == "megalodon firewall-plan or block"
    assert "firewall-install" not in response["entry_point"]
    assert response["output_contract"] == "planned ActionRecord only"
    assert response["launch_policy"] == "plan_only_apply_refused"
    assert response["data_boundary"] == "validated target and inert nftables plan only"
    assert response["action_boundary"] == (
        "live application is unsupported; no firewall subprocess is reachable"
    )
    assert response["next_gate"] == (
        "durable intent, terminal outcome, reconciliation, recovery, and "
        "disposable-namespace safety tests"
    )

    advisory = integration_plan("linux", "local-ai-advisory")["workflows"][0]
    assert advisory["selected_status"] == "manual_only"
    assert advisory["entry_point"] == "Python API: invoke_qwen_advisory"
    assert advisory["launch_policy"] == "explicit_library_call_only_no_scheduler"
    assert "no raw traffic" in advisory["data_boundary"]
    assert "cannot execute commands" in advisory["action_boundary"]

    for workflow in (
        "network-inventory-import",
        "host-integrity-import",
        "vulnerability-report-import",
        "zabbix-availability-read",
        "nagios-availability-read",
    ):
        item = integration_plan("linux", workflow)["workflows"][0]
        assert item["entry_point"] is None
        assert item["selected_status"] == "proposed"
        assert item["integration_owner"] == "not_implemented"


def test_unknown_workflow_is_rejected():
    with pytest.raises(ValueError, match="unknown integration workflow"):
        integration_plan("linux", "arbitrary-command")


def test_cli_performs_no_network_process_or_host_probe(monkeypatch, capsys):
    def denied(*args, **kwargs):
        raise AssertionError("hub planning must not open sockets or launch processes")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    with pytest.raises(SystemExit) as caught:
        main(["hub-plan", "--platform", "linux", "--workflow", "offline-packet-metadata"])
    assert caught.value.code == 0
    value = json.loads(capsys.readouterr().out)
    assert value == integration_plan("linux", "offline-packet-metadata")
