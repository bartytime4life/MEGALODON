"""Bounded, read-only file intake for the offline Qwen evaluation tools.

File admission is separate from the pure evaluation validators. Reading a
stable regular file does not authenticate its origin, signature or contents.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from .model_evaluation import MAX_INPUT_BYTES, MAX_MANIFEST_BYTES, ModelEvaluationError


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(path: Path, limit: int, prefix: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name == "posix":
        # A FIFO must not wait for a writer before fstat can reject it.
        flags |= os.O_NONBLOCK | os.O_NOFOLLOW | os.O_NOCTTY
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ModelEvaluationError(prefix + "_READ")
            if not 1 <= before.st_size <= limit:
                raise ModelEvaluationError(prefix + "_SIZE")
            data = bytearray()
            while True:
                chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ModelEvaluationError(prefix + "_SIZE")
            after = os.fstat(descriptor)
            if len(data) != before.st_size or _snapshot(before) != _snapshot(after):
                raise ModelEvaluationError(prefix + "_READ")
            return bytes(data)
        finally:
            os.close(descriptor)
    except ModelEvaluationError:
        raise
    except (OSError, ValueError):
        # Never echo a private path, file content or operating-system detail.
        raise ModelEvaluationError(prefix + "_READ") from None


def read_receipt_file(path: Path) -> bytes:
    """Read at most 128 KiB plus one overflow byte, from one regular file."""
    return _read_file(path, MAX_INPUT_BYTES, "RECEIPT")


def read_manifest_file(path: Path) -> bytes:
    """Read at most 4 MiB plus one overflow byte, from one regular file."""
    return _read_file(path, MAX_MANIFEST_BYTES, "MANIFEST")
