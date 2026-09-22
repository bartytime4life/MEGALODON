"""Contract tests for the bounded storage-admission diagnostic."""
from __future__ import annotations

import json
import runpy
import subprocess
import sys


def _assert_redacted(serialized: str) -> None:
    assert "/tmp/" not in serialized
    assert "/private/" not in serialized
    assert "/Users/" not in serialized
    assert "audit.db" not in serialized


def test_storage_admission_probe_emits_bounded_redacted_json():
    completed = subprocess.run(
        [sys.executable, "tools/probe_storage_admission.py"],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(completed.stdout)
    assert report["diagnostic_status"] == "complete"
    assert report["production_directory_open"] == "accepted"
    assert report["production_database_open"] == "accepted"
    assert report["descriptor_strategy"] in {
        "proc_self_fd", "dev_fd", "other"
    }
    assert report["database_identity_before"] is True
    assert report["database_identity_after"] is True
    assert report["directory_identity_before"] is True
    assert report["directory_identity_after"] is True
    assert report["sqlite_filename_relation"] in {
        "admitted_path", "descriptor_path", "other", "empty", "unavailable"
    }
    assert report["production_validator"] == "accepted" or str(
        report["production_validator"]
    ).startswith("STORAGE_PATH:")
    assert len(completed.stdout.encode("utf-8")) <= 4097
    _assert_redacted(completed.stdout)


def test_storage_admission_probe_serializes_expected_directory_refusal(monkeypatch):
    namespace = runpy.run_path("tools/probe_storage_admission.py")
    storage = namespace["storage"]

    def refuse_directory(*args, **kwargs):
        raise storage.StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY")

    monkeypatch.setattr(storage, "_open_private_directory", refuse_directory)
    report = namespace["collect_report"]()

    assert report["diagnostic_status"] == "directory_open_refused"
    assert report["production_directory_open"] == "STORAGE_PATH:UNSAFE_DIRECTORY"
    assert "production_database_open" not in report
    assert "descriptor_strategy" not in report
    assert report["temporary_path_class"] in {
        "var_alias", "private_var", "users", "other"
    }
    serialized = json.dumps(report, sort_keys=True)
    _assert_redacted(serialized)


def test_darwin_alias_observation_is_fixed_shape_without_paths():
    namespace = runpy.run_path("tools/probe_storage_admission.py")
    observation = namespace["_darwin_alias_observation"]()
    if sys.platform == "darwin":
        assert observation["status"] == "observed"
        assert observation["var_kind"] in {
            "directory", "symlink", "regular", "other"
        } or str(observation["var_kind"]).startswith("error:")
        assert observation["private_kind"] in {
            "directory", "symlink", "regular", "other"
        } or str(observation["private_kind"]).startswith("error:")
        assert observation["private_var_kind"] in {
            "directory", "symlink", "regular", "other"
        } or str(observation["private_var_kind"]).startswith("error:")
        for key in ("private_var_direct_open", "private_var_relative_open"):
            assert observation[key] == "accepted" or str(
                observation[key]
            ).startswith(("error:", "parent_error:"))
    else:
        assert observation == {"status": "not_applicable"}
    _assert_redacted(json.dumps(observation, sort_keys=True))
