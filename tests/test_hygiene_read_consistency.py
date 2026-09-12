"""Synthetic worktree races; no network, real secrets, or operator data."""
import errno
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools import check_repository_hygiene as guard


CAP = 64
CASES = ("growth", "truncation", "rewrite", "replacement", "deletion")


def change_file(path, case):
    if case == "growth":
        path.write_bytes(b"x" * (CAP + 32))
    elif case == "truncation":
        path.write_bytes(b"x")
    elif case == "rewrite":
        previous = path.stat()
        path.write_bytes(b"y" * previous.st_size)
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns + 2_000_000_000))
    elif case == "replacement":
        replacement = path.with_name("replacement.txt")
        replacement.write_bytes(b"r" * path.stat().st_size)
        os.replace(replacement, path)
    else:
        path.unlink()


def before_read_change(monkeypatch, path, change):
    original = Path.lstat
    changed = False

    def lstat(self, *args, **kwargs):
        nonlocal changed
        metadata = original(self, *args, **kwargs)
        if self == path and not changed:
            changed = True
            change()
        return metadata

    monkeypatch.setattr(Path, "lstat", lstat)


def assert_refusal(findings):
    assert findings in (["tracked file changed during scan: fixture.txt"],
                        ["tracked file is unreadable: fixture.txt"])


@pytest.mark.parametrize("case", CASES)
def test_before_read_change_cannot_pass(tmp_path, monkeypatch, case):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"original")
    before_read_change(monkeypatch, path, lambda: change_file(path, case))
    assert_refusal(guard.scan_paths(tmp_path, (path.name,), max_file_bytes=CAP))


@pytest.mark.parametrize("case", CASES)
def test_after_read_change_cannot_pass(tmp_path, monkeypatch, case):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"original")
    original = guard.os.fdopen
    descriptors = []

    class ChangedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def read(self, limit):
            assert limit == CAP + 1
            data = self.stream.read(limit)
            change_file(path, case)
            return data

        def __exit__(self, *args):
            self.stream.close()

    def fdopen(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        return ChangedReader(original(descriptor, *args, **kwargs))

    monkeypatch.setattr(guard.os, "fdopen", fdopen)
    assert_refusal(guard.scan_paths(tmp_path, (path.name,), max_file_bytes=CAP))
    assert len(descriptors) == 1
    with pytest.raises(OSError) as error:
        os.fstat(descriptors[0])
    assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("size", (0, CAP - 1, CAP, CAP + 1))
def test_unchanged_boundary_sizes(tmp_path, size):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"a" * size)
    findings = guard.scan_paths(tmp_path, (path.name,), max_file_bytes=CAP)
    assert findings == ([] if size <= CAP else [
        f"large tracked file: fixture.txt ({size} bytes > {CAP})"])


def test_overflow_byte_is_not_ignored_by_size_accounting(tmp_path, monkeypatch):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"a")
    # Independently protect size accounting even if stat sampling misses a change.
    monkeypatch.setattr(guard, "_read_checked", lambda path, metadata, limit: b"a" * limit)
    assert guard.scan_paths(tmp_path, (path.name,), max_file_bytes=CAP) == [
        f"large tracked file: fixture.txt ({CAP + 1} bytes > {CAP})"]


def test_cli_refuses_growth_without_printing_content(tmp_path, monkeypatch, capsys):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"original")
    marker = b"-----BEGIN " + b"PRIVATE KEY-----"
    before_read_change(monkeypatch, path, lambda: path.write_bytes(marker))
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard, "tracked_paths", lambda: (path.name,))
    assert guard.main() == 1
    output = capsys.readouterr()
    assert output.out == ("repository hygiene guard: failed\n"
                          "- tracked file changed during scan: fixture.txt\n")
    assert marker.decode() not in output.out
    assert output.err == ""


def test_read_error_is_bounded_and_descriptor_closed(tmp_path, monkeypatch):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"original")
    descriptors = []

    class BrokenReader:
        def __enter__(self):
            return self

        def read(self, limit):
            raise OSError("synthetic-private-diagnostic")

        def __exit__(self, *args):
            return False

    def fdopen(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        return BrokenReader()

    monkeypatch.setattr(guard.os, "fdopen", fdopen)
    assert guard.scan_paths(tmp_path, (path.name,)) == [
        "tracked file is unreadable: fixture.txt"]
    with pytest.raises(OSError) as error:
        os.fstat(descriptors[0])
    assert error.value.errno == errno.EBADF


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="Linux no-follow open profile required")
def test_symlink_substitution_is_refused_before_content_read(tmp_path, monkeypatch):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"original")
    target = tmp_path / "target.txt"
    target.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----")

    def replace():
        path.unlink()
        path.symlink_to(target)

    def no_content_read(*args, **kwargs):
        pytest.fail("substituted symlink must not reach a content reader")

    before_read_change(monkeypatch, path, replace)
    monkeypatch.setattr(guard.os, "fdopen", no_content_read)
    assert guard.scan_paths(tmp_path, (path.name,)) == [
        "tracked file is unreadable: fixture.txt"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO probe required")
def test_fifo_substitution_does_not_block(tmp_path):
    # An outer timeout also fails a weakened implementation without hanging pytest.
    script = r'''
import importlib.util
import os
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("guard", sys.argv[1])
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
root = Path(sys.argv[2])
path = root / "fixture.txt"
path.write_bytes(b"original")
original = Path.lstat
changed = False
def lstat(self, *args, **kwargs):
    global changed
    result = original(self, *args, **kwargs)
    if self == path and not changed:
        changed = True
        path.unlink()
        os.mkfifo(path, 0o600)
    return result
Path.lstat = lstat
def forbidden(*args, **kwargs):
    raise AssertionError("FIFO must be rejected before content read")
guard.os.fdopen = forbidden
assert guard.scan_paths(root, (path.name,)) == ["tracked file changed during scan: fixture.txt"]
print("FIFO_REFUSED_BEFORE_READ")
'''
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("PYTHONPATH", "PYTHONHOME")}
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(Path(guard.__file__).resolve()), str(tmp_path)],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "FIFO_REFUSED_BEFORE_READ\n"
    assert result.stderr == ""
