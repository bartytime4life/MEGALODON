from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from megalodon.sqlite_recovery_workflow import backup_database
from megalodon.storage import Store

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on non-POSIX hosts
    resource = None


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "contracts" / "sqlite-recovery" / "v1" / "schema.json").read_text(
        encoding="utf-8"
    )
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="SQLite recovery v1 has a POSIX-only runtime profile"
)
FILE_LIMIT_ONLY = pytest.mark.skipif(
    os.name != "posix" or resource is None or not hasattr(resource, "RLIMIT_FSIZE"),
    reason="POSIX RLIMIT_FSIZE is required",
)


@pytest.fixture
def private_directory(tmp_path: Path) -> Path:
    tmp_path.chmod(0o700)
    return tmp_path


def _create_store(directory: Path, *, padding_bytes: int = 0) -> Path:
    path = directory / "source.db"
    with Store(path):
        pass
    if padding_bytes:
        metadata = json.dumps(
            {"synthetic_padding": "x" * padding_bytes}, separators=(",", ":")
        )
        with sqlite3.connect(path) as connection:
            connection.execute(
                """
                INSERT INTO events (
                    observed_at, src_ip, dst_ip, protocol, src_port, dst_port,
                    tcp_flags, dns_query_length, byte_count, interface, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-09-19T00:00:00+00:00",
                    "192.0.2.1",
                    "198.51.100.2",
                    "TCP",
                    12345,
                    443,
                    "[]",
                    None,
                    padding_bytes,
                    "native-test",
                    metadata,
                ),
            )
    return path


def _write_config(directory: Path, source: Path) -> Path:
    config = directory / "settings.toml"
    config.write_text(
        f"[app]\ndb_path = {json.dumps(os.fspath(source))}\n", encoding="utf-8"
    )
    config.chmod(0o600)
    return config


def _assert_failure_receipt(
    receipt: dict[str, object], *, reason: str, state: str
) -> None:
    VALIDATOR.validate(receipt)
    encoded = json.dumps(receipt, sort_keys=True)
    assert len(encoded.encode("utf-8")) < 8192
    assert "/" not in encoded
    assert "\\" not in encoded
    assert receipt["status"] == "failed"
    assert receipt["reason"] == reason
    assert receipt["destination_state"] == state
    assert receipt["destination_complete"] is False
    assert not any(receipt["effects"].values())


def _backup_command(
    config: Path, destination: Path, manifest: Path, operation_id: str
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "megalodon",
        "database-backup",
        os.fspath(destination),
        "--manifest",
        os.fspath(manifest),
        "--operation-id",
        operation_id,
        "--config",
        os.fspath(config),
    ]


def _wait_for_created_destination(process: subprocess.Popen[str], path: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "recovery process exited before destination creation: "
                f"returncode={process.returncode} stdout={stdout!r} stderr={stderr!r}"
            )
        time.sleep(0.001)
    process.kill()
    process.communicate()
    pytest.fail("recovery process did not create its destination within 10 seconds")


@POSIX_ONLY
def test_real_sqlite_exclusive_lock_exhausts_the_closed_retry_budget(
    private_directory: Path,
) -> None:
    source = _create_store(private_directory)
    destination = private_directory / "locked-backup.db"
    manifest = private_directory / "locked-backup.manifest.json"
    blocker = sqlite3.connect(source, timeout=0, isolation_level=None)
    blocker.execute("PRAGMA journal_mode=DELETE")
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        receipt = backup_database(
            source,
            destination,
            manifest,
            operation_id="native-lock-timeout",
        )
    finally:
        blocker.rollback()
        blocker.close()

    _assert_failure_receipt(receipt, reason="LOCK_TIMEOUT", state="not_created")
    assert receipt["destination_created"] is False
    assert not destination.exists()
    assert not manifest.exists()


@POSIX_ONLY
def test_cli_sigint_after_creation_preserves_the_incomplete_destination(
    private_directory: Path,
) -> None:
    source = _create_store(private_directory, padding_bytes=32 * 1024**2)
    config = _write_config(private_directory, source)
    destination = private_directory / "interrupted-backup.db"
    manifest = private_directory / "interrupted-backup.manifest.json"
    process = subprocess.Popen(
        _backup_command(config, destination, manifest, "native-interrupt"),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_created_destination(process, destination)
    process.send_signal(signal.SIGINT)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 2
    assert stderr == ""
    receipt = json.loads(stdout)
    _assert_failure_receipt(
        receipt, reason="INTERRUPTED_AFTER_CREATE", state="incomplete_preserved"
    )
    assert receipt["destination_created"] is True
    assert destination.exists()
    assert not manifest.exists()


@POSIX_ONLY
@pytest.mark.parametrize("operation", ("backup", "restore"))
def test_destination_path_replacement_is_completion_uncertain_and_preserved(
    private_directory: Path, operation: str
) -> None:
    source = _create_store(private_directory, padding_bytes=32 * 1024**2)
    artifact = private_directory / "reviewed-race-backup.db"
    manifest = private_directory / "raced-backup.manifest.json"
    destination = private_directory / f"raced-{operation}.db"
    displaced = private_directory / f"held-created-{operation}.db"
    if operation == "backup":
        config = _write_config(private_directory, source)
        command = _backup_command(
            config, destination, manifest, "native-destination-race-backup"
        )
    else:
        backup = backup_database(
            source,
            artifact,
            manifest,
            operation_id="native-destination-race-setup",
        )
        assert backup["status"] == "completed"
        command = [
            sys.executable,
            "-m",
            "megalodon",
            "database-restore",
            os.fspath(artifact),
            os.fspath(destination),
            "--manifest",
            os.fspath(manifest),
            "--artifact-sha256",
            str(backup["artifact_sha256"]),
            "--operation-id",
            "native-destination-race-restore",
        ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_created_destination(process, destination)
    destination.rename(displaced)
    replacement = b"operator-owned-race-winner"
    destination.write_bytes(replacement)
    destination.chmod(0o600)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 2
    assert stderr == ""
    receipt = json.loads(stdout)
    _assert_failure_receipt(
        receipt, reason="COMPLETION_UNCERTAIN", state="unknown"
    )
    assert receipt["completion_uncertain"] is True
    assert receipt["destination_created"] is True
    assert destination.read_bytes() == replacement
    assert displaced.exists()
    assert manifest.exists() is (operation == "restore")


def _limit_regular_file_size() -> None:
    assert resource is not None
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024, 256 * 1024))


@FILE_LIMIT_ONLY
@pytest.mark.parametrize("operation", ("backup", "restore"))
def test_cli_kernel_file_limit_fails_closed_and_preserves_output(
    private_directory: Path, operation: str
) -> None:
    source = _create_store(private_directory, padding_bytes=2 * 1024**2)
    artifact = private_directory / "reviewed-backup.db"
    manifest = private_directory / "reviewed-backup.manifest.json"
    if operation == "backup":
        config = _write_config(private_directory, source)
        destination = artifact
        command = _backup_command(
            config, destination, manifest, "native-file-limit-backup"
        )
    else:
        backup = backup_database(
            source,
            artifact,
            manifest,
            operation_id="native-file-limit-setup",
        )
        assert backup["status"] == "completed"
        destination = private_directory / "file-limited-restore.db"
        command = [
            sys.executable,
            "-m",
            "megalodon",
            "database-restore",
            os.fspath(artifact),
            os.fspath(destination),
            "--manifest",
            os.fspath(manifest),
            "--artifact-sha256",
            str(backup["artifact_sha256"]),
            "--operation-id",
            "native-file-limit-restore",
        ]

    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
        preexec_fn=_limit_regular_file_size,
    )

    assert completed.returncode == 2
    assert completed.stderr == ""
    receipt = json.loads(completed.stdout)
    _assert_failure_receipt(receipt, reason="IO_ERROR", state="incomplete_preserved")
    assert receipt["destination_created"] is True
    assert destination.exists()
    assert destination.stat().st_size <= 256 * 1024
    if operation == "backup":
        assert not manifest.exists()
