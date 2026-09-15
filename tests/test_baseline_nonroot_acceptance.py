"""Real-process acceptance coverage for the capability-free comparator."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


BASELINE = {
    "schema": "offline-baseline-v1",
    "adapter": "tshark-fields-v1",
    "record_kind": "packet",
    "record_count": 5,
    "total_bytes": 320,
    "protocols": [{"protocol": "TCP", "count": 5}],
    "destination_ports": [{"protocol": "TCP", "port": 443, "count": 5}],
    "byte_bands": {"small": 5, "medium": 0, "large": 0},
    "relative_minutes": [{"minute": 0, "count": 5}],
}


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.getuid() == 0 or os.geteuid() == 0,
    reason="requires a real non-root Linux process",
)
def test_installed_comparator_succeeds_as_capability_free_nonroot(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir(mode=0o700)
    encoded = (json.dumps(BASELINE, sort_keys=True) + "\n").encode("ascii")
    paths = [input_root / name for name in ("before.json", "after.json")]
    for path in paths:
        path.write_bytes(encoded)
        path.chmod(0o600)
    snapshot = {path.name: path.read_bytes() for path in paths}
    entries = sorted(path.name for path in input_root.iterdir())

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "megalodon.offline.compare",
         "--input-root", str(input_root), "--reference", "before.json",
         "--current", "after.json"],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stderr == b""
    assert len(completed.stdout) <= 64 * 1024
    receipt = json.loads(completed.stdout)
    assert receipt["schema"] == "offline-baseline-comparison-v1"
    assert receipt["status"] == "compared"
    assert receipt["reference_records"] == receipt["current_records"] == 5
    assert receipt["changed_destination_ports"] == []
    assert receipt["network_access_performed"] is False
    assert receipt["persistence_status"] == receipt["action_status"] == "not_attempted"
    assert snapshot == {path.name: path.read_bytes() for path in paths}
    assert entries == sorted(path.name for path in input_root.iterdir())
    assert str(tmp_path) not in completed.stdout.decode("ascii")
