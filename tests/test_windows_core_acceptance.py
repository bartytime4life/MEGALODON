"""Synthetic Windows contract checks; these are not native execution evidence."""

import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from megalodon import capture, firewall, offline_projection
from megalodon.offline import common
from megalodon.offline.common import OfflineError


ROOT = Path(__file__).parents[1]
MATRIX = json.loads(
    (ROOT / "contracts" / "platform" / "windows-core-v1" / "acceptance.json").read_text(
        encoding="utf-8"
    )
)

EXPECTED_FEATURE_STATUSES = {
    "metadata-validation": "synthetic_reusable",
    "sample-jsonl-processing": "synthetic_reusable",
    "fixed-detections": "synthetic_reusable",
    "sqlite-audit": "native_receipt_required",
    "loopback-dashboard": "native_receipt_required",
    "private-ntfs-storage": "native_receipt_required",
}
EXPECTED_FEATURE_TESTS = {
    "metadata-validation": ("tests/test_validation.py",),
    "sample-jsonl-processing": (
        "tests/test_capture.py",
        "tests/test_cli.py::CliTests::test_default_run_works_outside_the_source_checkout",
        "tests/test_cli.py::CliTests::test_explicit_missing_config_fails_without_echoing_the_path",
    ),
    "fixed-detections": (
        "tests/test_detector.py",
        "tests/test_detector_acceptance.py",
    ),
    "sqlite-audit": (
        "tests/test_storage.py",
        "tests/test_storage_failures.py",
    ),
    "loopback-dashboard": (
        "tests/test_dashboard.py::test_dashboard_parser_and_remote_projection_boundary",
        "tests/test_dashboard.py::test_dashboard_rejects_invalid_programmatic_polling_controls",
        "tests/test_dashboard.py::test_dashboard_ui_has_accessible_read_only_states",
        "tests/test_dashboard.py::test_dashboard_config_assets_and_query_validation",
        "tests/test_dashboard.py::test_events_api_projects_only_fields_required_by_the_ui",
        "tests/test_dashboard_binding.py",
    ),
    "private-ntfs-storage": (),
}
EXPECTED_UNSUPPORTED_DIAGNOSTICS = {
    "offline-analysis": "LINUX_REQUIRED",
    "offline-dashboard-projection": "LINUX_REQUIRED",
    "live-scapy-capture": "live Scapy capture is supported only on Linux",
    "nftables": "nftables operations are supported only on Linux",
    "nftables-live-apply": "live firewall application is unsupported in this evaluation release",
}
EXPECTED_NATIVE_RECEIPTS = {
    "windows-edition-build-architecture-and-cpython",
    "selected-core-tests-with-pass-fail-skip-counts",
    "database-wal-shm-ntfs-acl-review",
    "loopback-listener-and-real-browser-ui-api-checks",
    "unsupported-operation-negative-controls",
    "same-head-linux-test-job",
}


def _forbidden(*_args, **_kwargs):
    raise AssertionError("unsupported Windows operation crossed a forbidden boundary")


def _matrix_diagnostic_pattern(operation_id: str) -> str:
    matches = [
        item["diagnostic"]
        for item in MATRIX["unsupported_operations"]
        if item["id"] == operation_id
    ]
    assert len(matches) == 1
    return rf"^{re.escape(matches[0])}$"


def _workflow_job(workflow: str, name: str) -> str:
    marker = f"  {name}:\n"
    assert workflow.count(marker) == 1
    remainder = workflow.split(marker, 1)[1]
    lines = []
    for line in remainder.splitlines():
        if line.startswith("  ") and not line.startswith("    "):
            break
        lines.append(line)
    return "\n".join(lines)


def test_acceptance_matrix_is_closed_truthful_and_points_to_tests():
    assert set(MATRIX) == {
        "schema",
        "repository_baseline",
        "candidate_revision_source",
        "profile",
        "native_execution_status",
        "required_linux_job",
        "features",
        "unsupported_operations",
        "native_receipts_required",
    }
    assert MATRIX["schema"] == "windows-core-acceptance-v1"
    assert MATRIX["repository_baseline"] == "7435eee1503f76b6b07ccbc45278f4ad71aec4cf"
    assert MATRIX["candidate_revision_source"] == (
        "external exact-head PR or handoff receipt"
    )
    assert MATRIX["profile"] == "W1-native-windows-11-x64-evaluation"
    assert MATRIX["native_execution_status"] == "not_performed"
    assert MATRIX["required_linux_job"] == {
        "name": "test",
        "runner": "ubuntu-24.04",
        "python": "3.11",
        "disposition": "preserve",
    }
    feature_statuses = {
        item["id"]: item["status"] for item in MATRIX["features"]
    }
    feature_tests = {
        item["id"]: tuple(item["tests"]) for item in MATRIX["features"]
    }
    assert len(feature_statuses) == len(MATRIX["features"])
    assert feature_statuses == EXPECTED_FEATURE_STATUSES
    assert feature_tests == EXPECTED_FEATURE_TESTS
    for feature in MATRIX["features"]:
        assert set(feature) == {"id", "status", "tests"}
        for relative in feature["tests"]:
            assert relative.startswith("tests/")
            assert (ROOT / relative.split("::", 1)[0]).is_file()
    selected = {
        test
        for feature in MATRIX["features"]
        for test in feature["tests"]
    }
    assert "tests/test_cli.py" not in selected
    assert "tests/test_dashboard.py" not in selected

    unsupported = MATRIX["unsupported_operations"]
    assert all(set(item) == {"id", "status", "diagnostic"} for item in unsupported)
    unsupported_diagnostics = {
        item["id"]: item["diagnostic"] for item in unsupported
    }
    assert len(unsupported_diagnostics) == len(unsupported)
    assert unsupported_diagnostics == EXPECTED_UNSUPPORTED_DIAGNOSTICS
    assert {item["status"] for item in unsupported} == {"rejected"}

    native_receipts = MATRIX["native_receipts_required"]
    assert len(native_receipts) == len(set(native_receipts))
    assert set(native_receipts) == EXPECTED_NATIVE_RECEIPTS


def test_required_linux_ci_job_is_still_present():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    test_job = _workflow_job(workflow, "test")
    assert "    runs-on: ubuntu-24.04" in test_job
    assert '          python-version: "3.11"' in test_job


def test_windows_scapy_refuses_before_optional_import_or_interface_use(monkeypatch):
    monkeypatch.setattr(capture, "runtime_platform", lambda: "windows")
    iterator = capture.iter_scapy("Ethernet")
    with pytest.raises(
        capture.CaptureError,
        match=_matrix_diagnostic_pattern("live-scapy-capture"),
    ):
        next(iterator)


def test_windows_nftables_refuses_before_probe_privilege_or_process(monkeypatch):
    monkeypatch.setattr(firewall, "runtime_platform", lambda: "windows")
    monkeypatch.setattr(firewall.shutil, "which", _forbidden)
    monkeypatch.setattr(os, "geteuid", _forbidden, raising=False)
    monkeypatch.setattr(os, "system", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    backend = firewall.NftablesFirewall(public_only=False)

    assert backend.available() is False
    diagnostic = _matrix_diagnostic_pattern("nftables")
    with pytest.raises(firewall.FirewallError, match=diagnostic):
        backend.plan_block("8.8.8.8", "synthetic")
    with pytest.raises(firewall.FirewallError, match=diagnostic):
        backend.install()
    apply_diagnostic = _matrix_diagnostic_pattern("nftables-live-apply")
    with pytest.raises(firewall.FirewallError, match=apply_diagnostic):
        backend.install(apply=True, confirm="WRONG")
    with pytest.raises(firewall.FirewallError, match=apply_diagnostic):
        backend.block("not-an-ip", "", apply=True)
    assert not hasattr(firewall.NftablesFirewall, "_require_apply")
    assert not hasattr(firewall.NftablesFirewall, "_run")


def test_windows_offline_paths_refuse_before_posix_file_access(monkeypatch):
    monkeypatch.setattr(common.sys, "platform", "win32")
    monkeypatch.setattr(common.os, "getuid", _forbidden, raising=False)
    with pytest.raises(
        OfflineError,
        match=_matrix_diagnostic_pattern("offline-analysis"),
    ):
        common.require_unprivileged_linux()

    monkeypatch.setattr(offline_projection, "runtime_platform", lambda: "windows")
    monkeypatch.setattr(offline_projection, "_read_report_set", _forbidden)
    with pytest.raises(
        OfflineError,
        match=_matrix_diagnostic_pattern("offline-dashboard-projection"),
    ):
        offline_projection.load_offline_projection("not-read")
