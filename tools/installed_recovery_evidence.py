"""Bounded installed-wheel synthetic recovery evidence; never candidate acceptance."""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import zipfile


MAX_OUTPUT = 16_384
MAX_FILE = 8 * 1024 * 1024
COMMAND_SECONDS = 30
TABLES = ("events", "detections", "actions", "ingestion_runs",
          "ingestion_run_events", "detection_actions", "sqlite_sequence")
BUILD_TOOLS = ("build", "setuptools", "packaging", "pyproject-hooks", "pip")
CHECKS = {
    "installed_wheel": "verified", "backup": "completed", "restore": "completed",
    "artifact_and_manifest": "digest_verified", "source_events": 13,
    "restored_events": 13, "integrity": "ok", "foreign_key_violations": 0,
    "all_table_contents": "equal", "source": "preserved",
    "existing_destination": "refused_and_preserved",
    "temporary_data": "removed",
}
EXCLUSIONS = (
    "release", "tag", "publication", "trusted_publishing", "deployment",
    "host_installation", "activation", "network_access", "remote_ui",
    "firewall_apply", "scheduler_notifier", "live_sensors", "model_operation",
    "operator_acceptance", "independent_acceptance", "candidate_packet_completion",
    "sdist_recovery", "upgrade_rollback_uninstall", "physical_disk_full",
    "power_loss", "high_write_wal", "clock_rollback",
)
# This guards Python CLI calls against accidental socket/process use. It is not
# an OS sandbox or evidence of containment against hostile native code.
CLI_BOOTSTRAP = """
import sys
def guard(event, args):
    if (event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn'))
            or event in ('os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn')):
        raise RuntimeError('EXCLUDED_EFFECT')
sys.addaudithook(guard)
from megalodon.cli import main
main()
"""


class EvidenceError(ValueError):
    """No host paths, environment values or subprocess output in failures."""


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def read_bounded(path, limit=MAX_FILE):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "FILE_TYPE")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "FILE_LIMIT")
    return raw


def command(arguments, directory, expected_code=0, timeout=COMMAND_SECONDS):
    """Drain both pipes with a combined byte ceiling and a monotonic deadline."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTHONPATH", "PYTHONHOME"}}
    environment["PYTHONNOUSERSITE"] = "1"
    with subprocess.Popen(arguments, cwd=directory, env=environment,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        output = bytearray()
        size = 0
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "COMMAND_TIMEOUT")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        require(size <= MAX_OUTPUT, "OUTPUT_LIMIT")
                        if key.fileobj is process.stdout:
                            output.extend(chunk)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            require(process.returncode == expected_code, "COMMAND_FAILED")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    return bytes(output)


def cli(arguments, root, expected_code=0):
    return json.loads(command([sys.executable, "-I", "-c", CLI_BOOTSTRAP, *arguments],
                              root, expected_code))


def source_identity(checkout, commit, tree):
    require(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (commit, tree)), "SOURCE_PIN")
    def git(*args):
        return command(["git", *args], checkout).decode().strip()
    require(git("rev-parse", "--verify", "HEAD") == commit, "SOURCE_MISMATCH")
    require(git("rev-parse", "--verify", "HEAD^{tree}") == tree, "SOURCE_MISMATCH")
    require(not git("status", "--porcelain", "--untracked-files=normal"), "SOURCE_DIRTY")
    return {"commit": commit, "tree": tree, "working_tree_dirty": False}


def installed_wheel(wheel, checkout):
    import megalodon

    prefix = Path(sys.prefix).resolve()
    require(sys.prefix != sys.base_prefix and sys.flags.isolated == 1, "ISOLATED_VENV_REQUIRED")
    require(not Path.cwd().resolve().is_relative_to(checkout.resolve()), "CHECKOUT_CWD")
    require(Path(megalodon.__file__).resolve().is_relative_to(prefix), "INSTALLED_ORIGIN")
    require(not Path(megalodon.__file__).resolve().is_relative_to(checkout.resolve()), "INSTALLED_ORIGIN")
    distributions = {dist.metadata["Name"].lower().replace("_", "-")
                     for dist in importlib.metadata.distributions()}
    require(distributions == {"pip", "megalodon-defense"}, "VENV_NOT_CLEAN")
    raw = read_bounded(wheel)
    wheel_digest = digest(raw)
    dist = importlib.metadata.distribution("megalodon-defense")
    direct = json.loads(dist.read_text("direct_url.json") or "{}")
    require(direct.get("archive_info", {}).get("hashes", {}).get("sha256")
            == wheel_digest.removeprefix("sha256:"), "WHEEL_BINDING")
    require("dir_info" not in direct, "EDITABLE_INSTALL")
    # Check the installed package bytes as well as pip's local-wheel receipt.
    with zipfile.ZipFile(wheel) as archive:
        members = [item for item in archive.infolist()
                   if item.filename.startswith("megalodon/") and not item.is_dir()]
        require(members and sum(item.file_size for item in members) <= MAX_FILE, "WHEEL_LIMIT")
        for item in members:
            path = Path(dist.locate_file(item.filename)).resolve()
            require(path.is_relative_to(prefix), "INSTALLED_ORIGIN")
            require(read_bounded(path) == archive.read(item), "INSTALLED_BYTES")
    return {"distribution": "megalodon-defense", "version": dist.version,
            "sha256": wheel_digest, "size_bytes": len(raw)}


def snapshot(path, *, immutable=False):
    require(path.stat().st_size <= MAX_FILE, "DATABASE_LIMIT")
    # Backup/restore destinations are closed and have no sidecars. Immutable
    # inspection avoids creating WAL/SHM files that restore correctly refuses.
    # The original source can have sidecars from its ordinary read-only opens.
    if immutable:
        require(not any(path.with_name(path.name + suffix).exists()
                        for suffix in ("-wal", "-shm", "-journal")), "DATABASE_NOT_QUIESCENT")
    uri = path.as_uri() + ("?mode=ro&immutable=1" if immutable else "?mode=ro")
    with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db:
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        db.execute("PRAGMA query_only=ON")
        require(db.execute("PRAGMA user_version").fetchone() == (3,), "SCHEMA")
        require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "INTEGRITY")
        require(db.execute("PRAGMA foreign_key_check").fetchall() == [], "FOREIGN_KEYS")
        require({row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                == set(TABLES), "TABLE_SET")
        result = {}
        for table in TABLES:
            rows = db.execute(f'SELECT * FROM "{table}" ORDER BY rowid LIMIT 1025').fetchall()
            require(len(rows) <= 1024, "ROW_LIMIT")
            result[table] = rows
        require(len(result["events"]) == 13, "EVENT_COUNT")
        return result


def completed(receipt, operation):
    require(receipt["operation"] == operation and receipt["status"] == "completed"
            and receipt["reason"] == "COMPLETED", "RECOVERY_FAILED")
    require(receipt["destination_created"] is True and receipt["destination_complete"] is True
            and receipt["destination_same_as_source"] is False
            and receipt["completion_uncertain"] is False
            and receipt["clock_rollback_observed"] is False, "RECOVERY_INCOMPLETE")
    require(receipt["effects"] and all(value is False for value in receipt["effects"].values()), "EFFECTS")
    for side in ("source", "destination"):
        require(receipt[side]["integrity_check"] == "ok"
                and receipt[side]["foreign_key_check"] == "ok", "RECOVERY_VERIFICATION")


def rehearsal():
    with tempfile.TemporaryDirectory(prefix="megalodon-installed-recovery-") as directory:
        root = Path(directory)
        for name in ("source", "backup", "restored"):
            (root / name).mkdir(mode=0o700)
        source = root / "source/audit.db"
        config = root / "settings.toml"
        config.write_text('[app]\ndb_path = ' + json.dumps(str(source)) +
                          '\n[storage]\nmax_database_bytes = 8388608\n'
                          '[blocking]\nenabled = false\ndry_run = true\nauto_block = false\n'
                          '[dashboard]\nenabled = false\n', encoding="utf-8")
        config.chmod(0o600)
        cli(["run", "--source", "sample", "--max-events", "13", "--config", str(config)], root)
        original = snapshot(source)
        source_bytes = read_bounded(source)
        artifact, manifest = root / "backup/audit.db", root / "backup/manifest.json"
        backup = cli(["database-backup", str(artifact), "--manifest", str(manifest),
                      "--operation-id", "installed-synthetic-backup", "--config", str(config)], root)
        completed(backup, "backup")
        require(digest(read_bounded(artifact)) == backup["artifact_sha256"], "ARTIFACT_DIGEST")
        require(digest(read_bounded(manifest, MAX_OUTPUT)) == backup["manifest_sha256"], "MANIFEST_DIGEST")
        require(snapshot(artifact, immutable=True) == original, "BACKUP_CONTENT")
        destination = root / "restored/audit.db"
        args = ["database-restore", str(artifact), str(destination), "--manifest", str(manifest),
                "--artifact-sha256", backup["artifact_sha256"], "--operation-id", "installed-synthetic-restore"]
        restored = cli(args, root)
        completed(restored, "restore")
        require(all(restored[key] == backup[key] for key in ("artifact_sha256", "manifest_sha256")), "DIGEST_BINDING")
        require(snapshot(destination, immutable=True) == original, "RESTORE_CONTENT")
        before = destination.stat()
        before_bytes = read_bounded(destination)
        collision = cli(args, root, expected_code=2)
        require(collision["status"] == "failed" and collision["reason"] == "DESTINATION_EXISTS"
                and collision["destination_created"] is False
                and collision["destination_complete"] is False
                and collision["destination_state"] == "not_created", "COLLISION_REFUSAL")
        require(collision["effects"] and all(value is False for value in collision["effects"].values()), "EFFECTS")
        after = destination.stat()
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                and read_bounded(destination) == before_bytes
                and snapshot(destination, immutable=True) == original, "DESTINATION_CHANGED")
        require(read_bounded(source) == source_bytes and snapshot(source) == original, "SOURCE_CHANGED")
    require(not root.exists(), "CLEANUP")
    return dict(CHECKS)


def host_facts(build_python, checkout):
    require(sys.platform == "linux" and os.getuid() != 0 and os.geteuid() != 0, "NONROOT_LINUX_REQUIRED")
    release = platform.freedesktop_os_release()
    require((release.get("ID"), release.get("VERSION_ID")) == ("ubuntu", "24.04"), "PLATFORM")
    require(platform.python_implementation() == "CPython" and sys.version_info[:2] == (3, 12)
            and platform.machine() == "x86_64", "PLATFORM")
    systemd = command(["systemd", "--version"], checkout).decode().splitlines()
    require(systemd and systemd[0].startswith("systemd "), "SYSTEMD")
    build = json.loads(command([str(build_python), "-I", "-c",
                               "import importlib.metadata as m, json; print(json.dumps("
                               "{name: m.version(name) for name in " + repr(BUILD_TOOLS) + "}))"], checkout))
    ci = os.environ.get("GITHUB_ACTIONS") == "true"
    return {
        "basis": "github_actions" if ci else "local_validation",
        "os": "ubuntu-24.04", "architecture": platform.machine(), "non_root": True,
        "image_os": os.environ.get("ImageOS", "") if ci else "not_applicable",
        "image_version": os.environ.get("ImageVersion", "") if ci else "not_applicable",
        "kernel": platform.release(), "systemd": systemd[0].removeprefix("systemd "),
        "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "installer_pip": importlib.metadata.version("pip"), "build_tools": build,
        "build_requirements_sha256": digest(read_bounded(checkout / "constraints/build-linux-cp312.txt")),
    }


def validate(receipt, commit, tree):
    """Closed allowlist: never retain arbitrary CLI fields or host identifiers."""
    def keys(value, expected):
        require(type(value) is dict and set(value) == set(expected), "RECEIPT_FIELDS")
    def match(value, pattern):
        require(type(value) is str and re.fullmatch(pattern, value) is not None, "RECEIPT_VALUE")
    keys(receipt, ("schema_version", "status", "source", "wheel", "platform", "checks", "exclusions", "authentication"))
    require(receipt["schema_version"] == "installed-wheel-recovery-v1"
            and receipt["status"] == "synthetic_slice_passed"
            and receipt["authentication"] == "not_performed", "RECEIPT_STATUS")
    match(commit, r"[0-9a-f]{40}")
    match(tree, r"[0-9a-f]{40}")
    keys(receipt["source"], ("commit", "tree", "working_tree_dirty"))
    require(receipt["source"] == {"commit": commit, "tree": tree, "working_tree_dirty": False}
            and receipt["source"]["working_tree_dirty"] is False, "SOURCE_MISMATCH")
    keys(receipt["wheel"], ("distribution", "version", "sha256", "size_bytes"))
    wheel = receipt["wheel"]
    require(wheel["distribution"] == "megalodon-defense" and type(wheel["size_bytes"]) is int
            and 0 < wheel["size_bytes"] <= MAX_FILE, "WHEEL_VALUE")
    match(wheel["version"], r"[0-9]+(?:\.[0-9]+){1,3}")
    match(wheel["sha256"], r"sha256:[0-9a-f]{64}")
    host = receipt["platform"]
    keys(host, ("basis", "os", "architecture", "non_root", "image_os", "image_version", "kernel",
                "systemd", "python", "sqlite", "installer_pip", "build_tools", "build_requirements_sha256"))
    require(host["os"] == "ubuntu-24.04" and host["architecture"] == "x86_64"
            and host["non_root"] is True, "PLATFORM")
    require(host["basis"] in ("github_actions", "local_validation"), "PLATFORM")
    if host["basis"] == "github_actions":
        require(host["image_os"] == "ubuntu24", "PLATFORM")
        match(host["image_version"], r"[0-9]{8}\.[0-9]+(?:\.[0-9]+)?")
    else:
        require(host["image_os"] == host["image_version"] == "not_applicable", "PLATFORM")
    match(host["kernel"], r"[A-Za-z0-9._+~-]{1,128}")
    match(host["systemd"], r"[0-9]{1,4}(?: \([A-Za-z0-9.+:~ -]{1,128}\))?")
    match(host["python"], r"3\.12\.[0-9]+")
    for key in ("sqlite", "installer_pip"):
        match(host[key], r"[0-9]+(?:\.[0-9]+){1,3}")
    keys(host["build_tools"], BUILD_TOOLS)
    for version in host["build_tools"].values():
        match(version, r"[0-9]+(?:\.[0-9]+){1,3}")
    match(host["build_requirements_sha256"], r"sha256:[0-9a-f]{64}")
    require(canonical(receipt["checks"]) == canonical(CHECKS), "CHECKS")
    require(receipt["exclusions"] == list(EXCLUSIONS), "EXCLUSIONS")
    require(len(canonical(receipt)) <= MAX_OUTPUT, "RECEIPT_LIMIT")


def packet(receipt):
    return {"receipt": receipt, "receipt_sha256": digest(canonical(receipt))}


def verify(raw, commit, tree):
    require(len(raw) <= MAX_OUTPUT, "RECEIPT_LIMIT")
    wrapper = json.loads(raw)
    require(type(wrapper) is dict and set(wrapper) == {"receipt", "receipt_sha256"}, "PACKET_FIELDS")
    require(canonical(wrapper) == raw, "PACKET_CANONICAL")
    validate(wrapper["receipt"], commit, tree)
    require(digest(canonical(wrapper["receipt"])) == wrapper["receipt_sha256"], "RECEIPT_DIGEST")
    return wrapper["receipt"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    modes = parser.add_subparsers(dest="mode", required=True)
    collect = modes.add_parser("collect")
    collect.add_argument("--checkout", type=Path, required=True)
    collect.add_argument("--wheel", type=Path, required=True)
    collect.add_argument("--build-python", type=Path, required=True)
    check = modes.add_parser("verify")
    check.add_argument("receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "verify":
            verify(read_bounded(args.receipt, MAX_OUTPUT), args.expected_commit, args.expected_tree)
            print('{"authentication":"not_performed","status":"binding_verified"}')
        else:
            source = source_identity(args.checkout, args.expected_commit, args.expected_tree)
            host = host_facts(args.build_python, args.checkout)
            wheel = installed_wheel(args.wheel, args.checkout)
            receipt = {"schema_version": "installed-wheel-recovery-v1", "status": "synthetic_slice_passed",
                       "source": source, "wheel": wheel, "platform": host, "checks": dict(CHECKS),
                       "exclusions": list(EXCLUSIONS), "authentication": "not_performed"}
            validate(receipt, args.expected_commit, args.expected_tree)
            receipt["checks"] = rehearsal()
            source_identity(args.checkout, args.expected_commit, args.expected_tree)
            require(installed_wheel(args.wheel, args.checkout) == wheel, "WHEEL_CHANGED")
            validate(receipt, args.expected_commit, args.expected_tree)
            sys.stdout.buffer.write(canonical(packet(receipt)))
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, IndexError, RecursionError,
            ImportError, sqlite3.Error, subprocess.SubprocessError, zipfile.BadZipFile):
        print('{"reason":"INSTALLED_RECOVERY_EVIDENCE_FAILED","status":"failed"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
