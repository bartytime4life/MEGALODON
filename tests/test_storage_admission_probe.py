"""Contract tests for the bounded storage-admission diagnostic."""
from __future__ import annotations

import json
import subprocess
import sys


def test_storage_admission_probe_emits_bounded_redacted_json():
    completed = subprocess.run(
        [sys.executable, "tools/probe_storage_admission.py"],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(completed.stdout)
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
    serialized = completed.stdout
    assert "/tmp/" not in serialized
    assert "/private/" not in serialized
    assert "/Users/" not in serialized
    assert "audit.db" not in serialized
