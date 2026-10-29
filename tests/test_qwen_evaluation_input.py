"""Bounded local evidence intake; never launch or contact a model."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from megalodon import evaluation_input
from megalodon.model_evaluation import MAX_INPUT_BYTES, MAX_MANIFEST_BYTES


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "contracts/local-model-evaluation/v1/fixtures"


def command(entry, path):
    if entry == "manifest":
        return ["tools/qwen_evaluation_manifest.py", str(path)]
    if entry == "receipt":
        return ["tools/qwen_evaluation_receipt.py", str(path)]
    return ["tools/qwen_evaluation_receipt.py",
            str(FIXTURES / "accepted-synthetic.json"), "--manifest", str(path)]


def refusal(entry, path, code):
    completed = subprocess.run(
        [sys.executable, *command(entry, path)], cwd=ROOT, capture_output=True,
        text=True, timeout=3, check=False,
    )
    assert completed.returncode == 2, completed.stderr
    result = json.loads(completed.stdout)
    assert result["state"] == "REFUSED"
    assert result["error_code"] == code
    assert result["provider_request_performed"] is False
    assert result["signature_verified_by_tool"] is False
    assert str(path) not in completed.stdout
    assert completed.stderr == ""


@pytest.mark.parametrize("entry", ["manifest", "receipt", "receipt_manifest"])
@pytest.mark.parametrize("kind", ["empty", "oversized", "directory", "missing"])
def test_cli_refuses_invalid_evidence_files(entry, kind, tmp_path):
    path = tmp_path / "private-evidence"
    prefix = "RECEIPT" if entry == "receipt" else "MANIFEST"
    limit = MAX_INPUT_BYTES if entry == "receipt" else MAX_MANIFEST_BYTES
    if kind == "directory":
        path.mkdir()
    elif kind in {"empty", "oversized"}:
        with path.open("wb") as stream:
            stream.truncate(0 if kind == "empty" else limit + 1)
    refusal(entry, path, prefix + ("_SIZE" if kind in {"empty", "oversized"} else "_READ"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX nonblocking file admission")
@pytest.mark.parametrize("entry", ["manifest", "receipt", "receipt_manifest"])
def test_fifo_without_writer_refuses_without_waiting(entry, tmp_path):
    path = tmp_path / "private-pipe"
    os.mkfifo(path, 0o600)
    prefix = "RECEIPT" if entry == "receipt" else "MANIFEST"
    refusal(entry, path, prefix + "_READ")


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow admission")
@pytest.mark.parametrize("entry", ["manifest", "receipt", "receipt_manifest"])
def test_final_symlink_refuses_instead_of_reading_its_target(entry, tmp_path):
    source = FIXTURES / ("accepted-synthetic.json" if entry == "receipt" else "manifest-synthetic.json")
    before = source.read_bytes()
    path = tmp_path / "private-link"
    path.symlink_to(source)
    prefix = "RECEIPT" if entry == "receipt" else "MANIFEST"
    refusal(entry, path, prefix + "_READ")
    assert source.read_bytes() == before


@pytest.mark.parametrize("kind", ["receipt", "manifest"])
def test_reader_accepts_exact_limit_and_preserves_file(kind, tmp_path):
    limit = MAX_INPUT_BYTES if kind == "receipt" else MAX_MANIFEST_BYTES
    path = tmp_path / "evidence.json"
    data = b"x" * limit
    path.write_bytes(data)
    before = path.stat()
    assert getattr(evaluation_input, "read_" + kind + "_file")(path) == data
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns,
    )
    assert path.read_bytes() == data


@pytest.mark.parametrize("kind", ["receipt", "manifest"])
def test_oversized_file_refuses_before_any_content_read(kind, tmp_path, monkeypatch):
    limit = MAX_INPUT_BYTES if kind == "receipt" else MAX_MANIFEST_BYTES
    path = tmp_path / "evidence.json"
    with path.open("wb") as stream:
        stream.truncate(limit + 1)
    reads = []

    def forbidden(*args):
        reads.append(args)
        pytest.fail("oversized evidence reached a data read")

    with monkeypatch.context() as guard:
        guard.setattr(os, "read", forbidden)
        with pytest.raises(evaluation_input.ModelEvaluationError, match="^" + kind.upper() + "_SIZE$"):
            getattr(evaluation_input, "read_" + kind + "_file")(path)
    assert reads == []


@pytest.mark.parametrize("kind", ["receipt", "manifest"])
def test_growth_after_stat_cannot_exceed_byte_budget(kind, tmp_path, monkeypatch):
    from types import SimpleNamespace

    path = tmp_path / "evidence.json"
    path.write_bytes(b"123456789")
    real_read, real_stat, real_open = os.read, os.fstat, os.open
    descriptors, consumed = [], []

    def opened(*args, **kwargs):
        assert not args[1] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def before_growth(descriptor):
        info = real_stat(descriptor)
        return SimpleNamespace(st_mode=info.st_mode, st_size=8)

    def short_read(descriptor, count):
        assert 0 < count <= 9 - sum(consumed)
        result = real_read(descriptor, min(count, 2))
        consumed.append(len(result))
        return result

    with monkeypatch.context() as guard:
        guard.setattr(evaluation_input, "MAX_INPUT_BYTES" if kind == "receipt" else "MAX_MANIFEST_BYTES", 8)
        guard.setattr(os, "open", opened)
        guard.setattr(os, "fstat", before_growth)
        guard.setattr(os, "read", short_read)
        with pytest.raises(evaluation_input.ModelEvaluationError, match="^" + kind.upper() + "_SIZE$"):
            getattr(evaluation_input, "read_" + kind + "_file")(path)
    assert sum(consumed) == 9
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.parametrize("change", ["size", "mtime", "ctime", "read_error"])
def test_unstable_or_failed_read_refuses_and_closes_descriptor(change, tmp_path, monkeypatch):
    from types import SimpleNamespace

    path = tmp_path / "evidence.json"
    path.write_bytes(b"12345678")
    real_stat, real_open = os.fstat, os.open
    descriptors, checks = [], []

    def opened(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def changed(descriptor):
        info = real_stat(descriptor)
        checks.append(descriptor)
        fields = {key: getattr(info, key) for key in (
            "st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
        )}
        if len(checks) == 2:
            fields[{"size": "st_size", "mtime": "st_mtime_ns", "ctime": "st_ctime_ns"}[change]] += 1
        return SimpleNamespace(**fields)

    def failed_read(*_args):
        raise OSError("private detail must not escape")

    with monkeypatch.context() as guard:
        guard.setattr(os, "open", opened)
        guard.setattr(os, "fstat", changed)
        if change == "read_error":
            guard.setattr(os, "read", failed_read)
        with pytest.raises(evaluation_input.ModelEvaluationError, match="^RECEIPT_READ$"):
            evaluation_input.read_receipt_file(path)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_embedded_nul_path_is_a_fixed_refusal():
    with pytest.raises(evaluation_input.ModelEvaluationError, match="^RECEIPT_READ$"):
        evaluation_input.read_receipt_file(Path("private\x00path"))
