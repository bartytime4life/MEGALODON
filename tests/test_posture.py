import socket
import subprocess

import pytest

from megalodon import posture
from megalodon.reference import ReferenceDataError


class Bundle:
    bundle_id = "iana-network-reference-20260910"
    manifest_sha256 = "a" * 64
    services = ("one", "two")
    protocols = ("one",)


def test_posture_is_closed_and_marks_every_side_effect_not_attempted(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("posture must not inspect the host or launch a process")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(posture, "load_iana", lambda: Bundle())

    value = posture.local_posture("windows")

    assert set(value) == {
        "action_status",
        "capability_status_counts",
        "declared_posture",
        "host_change_performed",
        "host_inspection_performed",
        "limitations",
        "network_access_performed",
        "package_version",
        "persistence_status",
        "reference_data",
        "schema",
        "selected_platform",
        "selection_mode",
    }
    assert value["schema"] == posture.SCHEMA
    assert value["selected_platform"] == "windows"
    assert value["selection_mode"] == "explicit_static_profile"
    assert value["declared_posture"] == "observe_only"
    assert value["network_access_performed"] is False
    assert value["host_change_performed"] is False
    assert value["host_inspection_performed"] is False
    assert value["action_status"] == "not_attempted"
    assert value["persistence_status"] == "not_attempted"
    assert value["reference_data"] == {
        "action_status": "not_attempted",
        "bundle_id": "iana-network-reference-20260910",
        "manifest_sha256": "a" * 64,
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "protocol_records": 1,
        "service_records": 2,
        "status": "verified",
    }
    assert set(value["capability_status_counts"]) == posture.STATUSES
    assert sum(value["capability_status_counts"].values()) == len(
        posture.catalog("windows")["components"]
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            ReferenceDataError("REFERENCE_DATA:RESOURCE_IO"),
            {"status": "unavailable", "error": "reference bundle unavailable"},
        ),
        (
            ReferenceDataError("REFERENCE_DATA:MANIFEST_HASH"),
            {"status": "integrity_failure", "error": "reference bundle integrity failure"},
        ),
    ],
)
def test_reference_failure_is_fixed_and_nonpartial(monkeypatch, error, expected):
    def fail():
        raise error

    monkeypatch.setattr(posture, "load_iana", fail)
    reference = posture.local_posture()["reference_data"]
    assert reference == {
        "action_status": "not_attempted",
        "error": expected["error"],
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "status": expected["status"],
    }


def test_invalid_platform_is_rejected_by_the_static_catalog(monkeypatch):
    monkeypatch.setattr(posture, "load_iana", lambda: Bundle())
    with pytest.raises(ValueError, match="unsupported platform profile"):
        posture.local_posture("unreviewed")


def test_default_profile_is_explicitly_labeled_as_runtime_selection(monkeypatch):
    monkeypatch.setattr(posture, "load_iana", lambda: Bundle())
    monkeypatch.setattr(posture, "runtime_platform", lambda: "windows")
    value = posture.local_posture()
    assert value["selected_platform"] == "windows"
    assert value["selection_mode"] == "runtime_platform"
