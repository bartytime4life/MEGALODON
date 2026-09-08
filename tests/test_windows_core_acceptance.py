"""Synthetic Windows contract checks; these are not native execution evidence."""

import json
from pathlib import Path

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


def _forbidden(*_args, **_kwargs):
    raise AssertionError("unsupported Windows operation crossed a forbidden boundary")


def test_acceptance_matrix_is_closed_truthful_and_points_to_tests():
    assert set(MATRIX) == {
        "schema",
        "repository_baseline",
        "profile",
        "native_execution_status",
        "required_linux_job",
        "features",
        "unsupported_operations",
        "native_receipts_required",
    }
    assert MATRIX["schema"] == "windows-core-acceptance-v1"
    assert MATRIX["native_execution_status"] == "not_performed"
    assert MATRIX["required_linux_job"] == {
        "name": "test",
        "runner": "ubuntu-24.04",
        "python": "3.11",
        "disposition": "preserve",
    }
    feature_ids = {item["id"] for item in MATRIX["features"]}
    assert len(feature_ids) == len(MATRIX["features"])
    assert {item["status"] for item in MATRIX["features"]} <= {
        "synthetic_reusable",
        "native_receipt_required",
    }
    for feature in MATRIX["features"]:
        assert set(feature) == {"id", "status", "tests"}
        for relative in feature["tests"]:
            assert relative.startswith("tests/")
            assert (ROOT / relative).is_file()

    unsupported = MATRIX["unsupported_operations"]
    assert len({item["id"] for item in unsupported}) == len(unsupported)
    assert all(set(item) == {"id", "status", "diagnostic"} for item in unsupported)
    assert {item["status"] for item in unsupported} == {"rejected"}


def test_required_linux_ci_job_is_still_present():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "\n  test:\n" in workflow
    assert "runs-on: ubuntu-24.04" in workflow
    assert 'python-version: "3.11"' in workflow


def test_windows_scapy_refuses_before_optional_import_or_interface_use(monkeypatch):
    monkeypatch.setattr(capture, "runtime_platform", lambda: "windows")
    iterator = capture.iter_scapy("Ethernet")
    with pytest.raises(capture.CaptureError, match="supported only on Linux"):
        next(iterator)


def test_windows_nftables_refuses_before_probe_privilege_or_process(monkeypatch):
    monkeypatch.setattr(firewall, "runtime_platform", lambda: "windows")
    monkeypatch.setattr(firewall.shutil, "which", _forbidden)
    monkeypatch.setattr(firewall.subprocess, "run", _forbidden)
    monkeypatch.setattr(firewall.os, "geteuid", _forbidden, raising=False)
    backend = firewall.NftablesFirewall(public_only=False)

    assert backend.available() is False
    with pytest.raises(firewall.FirewallError, match="supported only on Linux"):
        backend.plan_block("8.8.8.8", "synthetic")
    with pytest.raises(firewall.FirewallError, match="supported only on Linux"):
        backend.install()


def test_windows_offline_paths_refuse_before_posix_file_access(monkeypatch):
    monkeypatch.setattr(common.sys, "platform", "win32")
    monkeypatch.setattr(common.os, "getuid", _forbidden, raising=False)
    with pytest.raises(OfflineError, match="LINUX_REQUIRED"):
        common.require_unprivileged_linux()

    monkeypatch.setattr(offline_projection, "runtime_platform", lambda: "windows")
    monkeypatch.setattr(offline_projection, "_read_report_set", _forbidden)
    with pytest.raises(OfflineError, match="LINUX_REQUIRED"):
        offline_projection.load_offline_projection("not-read")
