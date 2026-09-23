"""Boundary and failure tests for the separate installed-wheel evidence slice."""
from contextlib import redirect_stdout
from contextlib import closing
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installed_recovery_evidence", ROOT / "tools/installed_recovery_evidence.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
COMMIT, TREE = "a" * 40, "b" * 40


@pytest.fixture
def receipt():
    phases = [
        tool.phase_receipt(phase, status, COMMIT, TREE, "sha256:" + "c" * 64,
                           "sha256:" + "e" * 64, "sha256:" + "f" * 64,
                           "sha256:" + "1" * 64,
                           "sha256:" + "2" * 64 if index >= 2 else None,
                           {"operation": phase} if index != 1 else None)
        for index, (phase, status) in enumerate(zip(tool.PHASES, tool.PHASE_STATUS))
    ]
    return {
        "schema_version": "installed-wheel-recovery-v2", "status": "synthetic_slice_passed",
        "source": {"commit": COMMIT, "tree": TREE, "working_tree_dirty": False},
        "wheel": {"distribution": "megalodon-defense", "version": "0.1.0",
                  "sha256": "sha256:" + "c" * 64, "size_bytes": 200_000},
        "platform": {
            "basis": "github_actions", "os": "ubuntu-24.04", "architecture": "x86_64",
            "non_root": True, "image_os": "ubuntu24", "image_version": "20260920.1.0",
            "kernel": "6.14.0-1014-azure", "systemd": "255 (255.4-1ubuntu8.10)",
            "python": "3.12.14", "sqlite": "3.45.1", "installer_pip": "25.2",
            "build_tools": {name: "1.2.3" for name in tool.BUILD_TOOLS},
            "build_requirements_sha256": "sha256:" + "d" * 64,
        },
        "checks": dict(tool.CHECKS), "phase_receipts": phases,
        "exclusions": list(tool.EXCLUSIONS),
        "authentication": "not_performed",
    }


def test_receipt_offline_roundtrip_requires_external_source_pins(receipt):
    raw = tool.canonical(tool.packet(receipt))
    assert tool.verify(raw, COMMIT, TREE) == receipt
    assert len(raw) < tool.MAX_OUTPUT
    for commit, tree in (("e" * 40, TREE), (COMMIT, "e" * 40), ("main", TREE)):
        with pytest.raises(tool.EvidenceError):
            tool.verify(raw, commit, tree)


@pytest.mark.parametrize("section,key,value", [
    (None, "operator_acceptance", "accepted"),
    (None, "status", "candidate_evidence"),
    (None, "authentication", "verified"),
    (None, "exclusions", []),
    ("source", "working_tree_dirty", 0),
    ("platform", "uid", 1001),
    ("platform", "hostname", "private-host"),
    ("platform", "non_root", False),
    ("platform", "os", "ubuntu-22.04"),
    ("platform", "image_version", ""),
    ("platform", "image_version", "/private/runner"),
    ("platform", "python", "3.11.9"),
    ("wheel", "path", "/private/wheel.whl"),
    ("wheel", "sha256", "bad"),
    ("wheel", "size_bytes", True),
    ("checks", "foreign_key_violations", False),
    ("checks", "source_events", 12),
    ("checks", "existing_destination", "overwritten"),
    ("checks", "raw_receipt", {"inode": 12345}),
    ("phase_receipts", 0, {"raw_path": "/private/audit.db"}),
])
def test_closed_receipt_refuses_privacy_leaks_and_claim_escalation(receipt, section, key, value):
    target = receipt if section is None else receipt[section]
    target[key] = value
    with pytest.raises(tool.EvidenceError):
        tool.verify(tool.canonical(tool.packet(receipt)), COMMIT, TREE)


def test_receipt_refuses_byte_tampering_duplicate_keys_and_oversize(receipt):
    raw = tool.canonical(tool.packet(receipt))
    for changed in (
        raw.replace(b"3.12.14", b"3.12.15"),
        raw.replace(b'"receipt":', b'"extra":{},"receipt":'),
        raw.replace(b'"status":"synthetic_slice_passed"',
                    b'"status":"failed","status":"synthetic_slice_passed"'),
        raw + b" " * tool.MAX_OUTPUT,
        raw + b"\n",
    ):
        with pytest.raises(tool.EvidenceError):
            tool.verify(changed, COMMIT, TREE)


def test_local_validation_cannot_claim_a_hosted_runner_image(receipt):
    receipt["platform"]["basis"] = "local_validation"
    with pytest.raises(tool.EvidenceError):
        tool.validate(receipt, COMMIT, TREE)
    receipt["platform"].update(image_os="not_applicable", image_version="not_applicable")
    tool.validate(receipt, COMMIT, TREE)


@pytest.mark.parametrize("index,key,value", [
    (0, "commit", "e" * 40),
    (1, "wheel_sha256", "sha256:" + "9" * 64),
    (2, "artifact_sha256", "sha256:" + "9" * 64),
    (3, "manifest_sha256", "sha256:" + "9" * 64),
    (3, "destination_sha256", "sha256:" + "9" * 64),
    (3, "status", "completed"),
    (1, "cli_receipt_sha256", "sha256:" + "9" * 64),
    (0, "destination_sha256", "sha256:" + "9" * 64),
])
def test_phase_receipts_refuse_cross_candidate_and_artifact_mismatch(receipt, index, key, value):
    receipt["phase_receipts"][index][key] = value
    with pytest.raises(tool.EvidenceError):
        tool.verify(tool.canonical(tool.packet(receipt)), COMMIT, TREE)


def test_prior_aggregate_receipt_cannot_claim_per_phase_binding(receipt):
    receipt["schema_version"] = "installed-wheel-recovery-v1"
    with pytest.raises(tool.EvidenceError, match="RECEIPT_STATUS"):
        tool.verify(tool.canonical(tool.packet(receipt)), COMMIT, TREE)


@pytest.fixture
def local_cli(monkeypatch, tmp_path):
    """Exercise real SQLite/CLI semantics; installed isolation is tested in CI."""
    from megalodon.cli import main

    def invoke(arguments, root, expected_code=0):
        output = io.StringIO()
        with redirect_stdout(output), pytest.raises(SystemExit) as result:
            main(arguments)
        assert result.value.code == expected_code
        return json.loads(output.getvalue())

    monkeypatch.setattr(tool, "cli", invoke)
    original_temp = tool.tempfile.TemporaryDirectory
    monkeypatch.setattr(tool.tempfile, "TemporaryDirectory",
                        lambda **kwargs: original_temp(dir=tmp_path, **kwargs))
    return invoke


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX recovery workflow")
def test_real_rehearsal_checks_all_rows_refusal_and_cleans_temporary_data(local_cli, tmp_path):
    phases = tool.rehearsal(COMMIT, TREE, "sha256:" + "c" * 64)
    assert [row["phase"] for row in phases] == list(tool.PHASES)
    assert all(row["commit"] == COMMIT and row["tree"] == TREE for row in phases)
    assert all(row["artifact_sha256"] == phases[0]["artifact_sha256"] for row in phases)
    assert phases[2]["destination_sha256"] == phases[3]["destination_sha256"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX recovery workflow")
@pytest.mark.parametrize("fault,reason", [
    ("manifest", "MANIFEST_DIGEST"),
    ("content", "RESTORE_CONTENT"),
    ("foreign_key", "FOREIGN_KEYS"),
    ("collision_content", "DESTINATION_CHANGED"),
    ("collision_success", "COLLISION_REFUSAL"),
    ("source", "SOURCE_CHANGED"),
])
def test_rehearsal_fails_closed_on_bad_recovery(local_cli, monkeypatch, tmp_path, fault, reason):
    def corrupted(arguments, root, expected_code=0):
        result = local_cli(arguments, root, expected_code)
        if arguments[0] == "database-backup" and fault == "manifest":
            (root / "backup/manifest.json").write_bytes(b"tampered")
        if arguments[0] == "database-restore":
            destination = root / "restored/audit.db"
            if (expected_code == 0 and fault == "content"
                    or expected_code == 2 and fault == "collision_content"):
                with closing(sqlite3.connect(destination)) as db, db:
                    db.execute("UPDATE events SET byte_count = byte_count + 1 WHERE id = 1")
            if expected_code == 0 and fault == "foreign_key":
                with closing(sqlite3.connect(destination)) as db, db:
                    db.execute("UPDATE ingestion_run_events SET event_id = 999999 WHERE event_id = 1")
            if expected_code == 2 and fault == "collision_success":
                result["status"] = "completed"
            if expected_code == 2 and fault == "source":
                with closing(sqlite3.connect(root / "source/audit.db")) as db, db:
                    db.execute("UPDATE events SET byte_count = byte_count + 1 WHERE id = 1")
        return result

    monkeypatch.setattr(tool, "cli", corrupted)
    with pytest.raises(tool.EvidenceError, match=reason):
        tool.rehearsal(COMMIT, TREE, "sha256:" + "c" * 64)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("code,reason", [
    ("import os; os.write(1, b'x'*20000)", "OUTPUT_LIMIT"),
    ("import os; os.write(2, b'x'*20000)", "OUTPUT_LIMIT"),
    ("import time; time.sleep(10)", "COMMAND_TIMEOUT"),
    ("raise SystemExit(1)", "COMMAND_FAILED"),
])
def test_subprocess_output_and_duration_are_bounded(tmp_path, code, reason):
    with pytest.raises(tool.EvidenceError, match=reason):
        tool.command([sys.executable, "-I", "-c", code], tmp_path, timeout=0.2)


@pytest.mark.parametrize("code", [
    "import socket; socket.socket()",
    "import subprocess; subprocess.run(['true'])",
    "import os; os.system('true')",
])
def test_cli_guard_refuses_sockets_and_process_launches(tmp_path, code):
    guard = tool.CLI_BOOTSTRAP.split("from megalodon.cli")[0]
    with pytest.raises(tool.EvidenceError, match="COMMAND_FAILED"):
        tool.command([sys.executable, "-I", "-c", guard + code], tmp_path)


def test_source_check_uses_observed_commit_tree_and_clean_status(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()
    git("init", "-q")
    (tmp_path / "source.txt").write_text("original")
    git("add", "source.txt")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
    commit, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    assert tool.source_identity(tmp_path, commit, tree)["working_tree_dirty"] is False
    with pytest.raises(tool.EvidenceError, match="SOURCE_MISMATCH"):
        tool.source_identity(tmp_path, COMMIT, tree)
    with pytest.raises(tool.EvidenceError, match="SOURCE_MISMATCH"):
        tool.source_identity(tmp_path, commit, TREE)
    (tmp_path / "source.txt").write_text("changed")
    with pytest.raises(tool.EvidenceError, match="SOURCE_DIRTY"):
        tool.source_identity(tmp_path, commit, tree)


@pytest.mark.parametrize("fault,reason", [
    (None, None),
    ("source_import", "INSTALLED_ORIGIN"),
    ("installed_bytes", "INSTALLED_BYTES"),
    ("wheel_hash", "WHEEL_BINDING"),
    ("editable", "EDITABLE_INSTALL"),
    ("optional_package", "VENV_NOT_CLEAN"),
    ("not_isolated", "ISOLATED_VENV_REQUIRED"),
    ("checkout_cwd", "CHECKOUT_CWD"),
])
def test_installed_subject_binding_rejects_contamination(tmp_path, monkeypatch, fault, reason):
    import megalodon

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    prefix = tmp_path / "venv"
    site = prefix / "site-packages"
    package = site / "megalodon/__init__.py"
    package.parent.mkdir(parents=True)
    package.write_bytes(b"# synthetic package fixture\n")
    wheel = tmp_path / "fixture.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("megalodon/__init__.py", package.read_bytes())
    direct = {"archive_info": {"hashes": {"sha256": tool.digest(wheel.read_bytes())[7:]}}}
    distributions = [SimpleNamespace(metadata={"Name": name})
                     for name in ("pip", "megalodon-defense")]
    monkeypatch.setattr(tool, "sys", SimpleNamespace(
        prefix=str(prefix), base_prefix=sys.base_prefix, flags=SimpleNamespace(isolated=1)))
    monkeypatch.setattr(megalodon, "__file__", str(package))
    monkeypatch.setattr(tool.importlib.metadata, "distributions", lambda: distributions)
    monkeypatch.setattr(tool.importlib.metadata, "distribution", lambda name: SimpleNamespace(
        version="0.1.0", read_text=lambda filename: json.dumps(direct),
        locate_file=lambda filename: site / filename))
    monkeypatch.chdir(tmp_path)
    if fault == "source_import":
        monkeypatch.setattr(megalodon, "__file__", str(checkout / "megalodon/__init__.py"))
    elif fault == "installed_bytes":
        package.write_bytes(b"# unexpected installed bytes\n")
    elif fault == "wheel_hash":
        direct["archive_info"]["hashes"]["sha256"] = "0" * 64
    elif fault == "editable":
        direct["dir_info"] = {"editable": True}
    elif fault == "optional_package":
        distributions.append(SimpleNamespace(metadata={"Name": "scapy"}))
    elif fault == "not_isolated":
        monkeypatch.setattr(tool.sys, "flags", SimpleNamespace(isolated=0))
    elif fault == "checkout_cwd":
        monkeypatch.chdir(checkout)
    if reason:
        with pytest.raises(tool.EvidenceError, match=reason):
            tool.installed_wheel(wheel, checkout)
    else:
        assert tool.installed_wheel(wheel, checkout)["sha256"] == tool.digest(wheel.read_bytes())


def test_failure_cli_never_echoes_paths_or_raw_errors(tmp_path, capsys):
    private = tmp_path / "private-host-sensitive-receipt.json"
    private.write_text('{"secret":"do-not-retain"}')
    assert tool.main(["--expected-commit", COMMIT, "--expected-tree", TREE,
                      "verify", str(private)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == '{"reason":"INSTALLED_RECOVERY_EVIDENCE_FAILED","status":"failed"}\n'


@pytest.fixture(params=["legacy", "declared_origin"])
def retained_subjects(tmp_path, receipt, request):
    """Synthetic byte subjects; no build or installed recovery claim."""
    subject_spec = importlib.util.spec_from_file_location(
        "release_subjects_fixture", ROOT / "tools/release_subjects.py")
    subjects = importlib.util.module_from_spec(subject_spec)
    subject_spec.loader.exec_module(subjects)
    directory = tmp_path / "subjects"
    directory.mkdir()
    wheel = directory / "megalodon_defense-0.1.0-py3-none-any.whl"
    sdist = directory / "megalodon_defense-0.1.0.tar.gz"
    wheel.write_bytes(b"synthetic wheel bytes")
    sdist.write_bytes(b"synthetic sdist bytes")
    receipt["wheel"].update(sha256=tool.digest(wheel.read_bytes()), size_bytes=wheel.stat().st_size)
    for phase in receipt["phase_receipts"]:
        phase["wheel_sha256"] = receipt["wheel"]["sha256"]
    manifest = {
        "schema": subjects.SCHEMA, "status": "built_unreviewed",
        "source": {"commit": COMMIT, "tree": TREE}, "package_version": "0.1.0",
        "artifacts": [subjects._artifact(wheel, "wheel", wheel.name),
                      subjects._artifact(sdist, "sdist", sdist.name)],
        "published": False, "limitations": list(subjects.LIMITATIONS),
    }
    if request.param == "declared_origin":
        manifest.update(schema=subjects.CI_SCHEMA, producer={
            "basis": "github_actions", "authentication": "not_performed",
            "repository": subjects.REPOSITORY, "workflow": subjects.WORKFLOW,
            "workflow_ref": subjects.REPOSITORY + "/" + subjects.WORKFLOW + "@refs/pull/396/merge",
            "workflow_commit": "f" * 40, "job": "build-subjects", "run_id": "12345", "run_attempt": "2",
        })
    (directory / "subjects.json").write_bytes(subjects._canonical(manifest))
    return directory, wheel, sdist, manifest, subjects


def test_paired_verification_requires_retained_bytes_and_keeps_legacy_scope(
        tmp_path, receipt, retained_subjects):
    directory, *_ = retained_subjects
    packet = tmp_path / "recovery.json"
    packet.write_bytes(tool.canonical(tool.packet(receipt)))
    command = [sys.executable, "-I", str(ROOT / "tools/installed_recovery_evidence.py"),
               "--expected-commit", COMMIT, "--expected-tree", TREE, "verify", str(packet)]
    # An artifact-side module must not be imported, including outside checkout.
    (tmp_path / "release_subjects.py").write_text("raise AssertionError('untrusted module')")
    legacy = subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True)
    paired = subprocess.run(command + ["--subjects-directory", str(directory)],
                            cwd=tmp_path, check=True, capture_output=True, text=True)
    assert json.loads(legacy.stdout) == {"authentication": "not_performed", "status": "binding_verified"}
    assert json.loads(paired.stdout) == {"authentication": "not_performed",
                                       "status": "release_subject_binding_verified"}
    assert not legacy.stderr and not paired.stderr


@pytest.mark.parametrize("fault", [
    "wheel_hash", "wheel_size", "wheel_version", "commit", "tree",
    "retained_wheel", "retained_sdist", "extra_file", "symlink", "rebound_subject",
])
def test_paired_verification_refuses_inconsistent_or_different_subjects(
        tmp_path, receipt, retained_subjects, capsys, fault):
    directory, wheel, sdist, manifest, subjects = retained_subjects
    if fault == "wheel_hash":
        receipt["wheel"]["sha256"] = "sha256:" + "0" * 64
        for phase in receipt["phase_receipts"]:
            phase["wheel_sha256"] = receipt["wheel"]["sha256"]
    elif fault == "wheel_size":
        receipt["wheel"]["size_bytes"] += 1
    elif fault == "wheel_version":
        receipt["wheel"]["version"] = "0.2.0"
    elif fault in ("commit", "tree"):
        manifest["source"][fault] = "e" * 40
        (directory / "subjects.json").write_bytes(subjects._canonical(manifest))
    elif fault in ("retained_wheel", "rebound_subject"):
        # Equal size and version with different bytes must still fail.
        wheel.write_bytes(b"Synthetic wheel bytes")
        if fault == "rebound_subject":
            manifest["artifacts"][0] = subjects._artifact(wheel, "wheel", wheel.name)
            (directory / "subjects.json").write_bytes(subjects._canonical(manifest))
    elif fault == "retained_sdist":
        sdist.write_bytes(b"changed")
    elif fault == "extra_file":
        (directory / "unexpected.json").write_text("{}")
    elif fault == "symlink":
        actual = tmp_path / "wheel"
        wheel.rename(actual)
        wheel.symlink_to(actual)
    packet = tmp_path / "private-recovery.json"
    packet.write_bytes(tool.canonical(tool.packet(receipt)))
    assert tool.main(["--expected-commit", COMMIT, "--expected-tree", TREE,
                      "verify", str(packet), "--subjects-directory", str(directory)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == '{"reason":"INSTALLED_RECOVERY_EVIDENCE_FAILED","status":"failed"}\n'


@pytest.mark.parametrize("when", ["before", "during"])
def test_collection_checks_subjects_before_and_after_recovery(
        tmp_path, receipt, retained_subjects, monkeypatch, capsys, when):
    directory, wheel, sdist, *_ = retained_subjects
    calls = []
    monkeypatch.setattr(tool, "source_identity", lambda *_: receipt["source"])
    monkeypatch.setattr(tool, "host_facts", lambda *_: receipt["platform"])
    monkeypatch.setattr(tool, "installed_wheel", lambda *_: receipt["wheel"])

    def rehearsal(*_):
        calls.append("rehearsal")
        sdist.write_bytes(b"changed during recovery")
        return receipt["phase_receipts"]

    monkeypatch.setattr(tool, "rehearsal", rehearsal)
    if when == "before":
        sdist.write_bytes(b"changed before recovery")
    assert tool.main(["--expected-commit", COMMIT, "--expected-tree", TREE,
                      "collect", "--checkout", str(tmp_path), "--wheel", str(wheel),
                      "--build-python", sys.executable,
                      "--subjects-directory", str(directory)]) == 2
    assert calls == ([] if when == "before" else ["rehearsal"])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == '{"reason":"INSTALLED_RECOVERY_EVIDENCE_FAILED","status":"failed"}\n'


def test_workflow_preserves_install_isolation_and_exact_artifact_roundtrip():
    workflow = (ROOT / ".github/workflows/installed-recovery-evidence.yml").read_text()
    assert "runs-on: ubuntu-24.04" in workflow
    assert "timeout-minutes: 10" in workflow
    assert "pull_request_target" not in workflow
    assert "permissions:\n  contents: read\n" in workflow and ": write" not in workflow
    assert "ref: ${{ github.event.pull_request.head.sha }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "--require-hashes --only-binary=:all:" in workflow
    assert "--no-isolation --wheel" in workflow
    assert "--no-index --no-deps --no-cache-dir" in workflow
    assert 'cd "$RUNNER_TEMP/recovery-run"' in workflow
    assert 'recovery-installed/bin/python" -I' in workflow
    assert "if: always()" not in workflow
    assert workflow.count("uses: actions/upload-artifact@") == 1
    assert "path: ${{ runner.temp }}/recovery-receipts/installed-wheel-recovery.json" in workflow
    assert "retention-days: 14" in workflow
    assert "needs: installed-recovery-evidence" in workflow
    assert "artifact-ids: ${{ needs.installed-recovery-evidence.outputs.artifact-id }}" in workflow
    assert "digest-mismatch: error" in workflow
    assert "EXPECTED_PACKET_SHA256: ${{ needs.installed-recovery-evidence.outputs.packet-sha256 }}" in workflow
    assert "--expected-commit \"$EXPECTED_COMMIT\" --expected-tree \"$EXPECTED_TREE\"" in workflow
