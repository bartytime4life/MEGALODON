"""Fail-closed checks for tracked repository artifacts and high-confidence secrets."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024
MAX_BINARY_FILE_BYTES = 1 * 1024 * 1024
MAX_DISPLAY_PATH_CHARS = 256

_SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\..*)?|\.netrc|\.pypirc|"
    r"credentials[^/]*|secrets[^/]*|[^/]+\.(?:pem|key|p12|pfx|jks|token))$",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    ("private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)


def tracked_paths(root: Path = ROOT) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("git ls-files failed")
    return tuple(
        item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item
    )


def _sensitive_path(relative: str) -> bool:
    normalized = relative.replace("\\", "/")
    name = Path(normalized).name.lower()
    if name == ".env.example" or (name.startswith(".env.") and name.endswith(".example")):
        return False
    return bool(_SENSITIVE_PATH.search(normalized))


class _ChangedFileError(OSError):
    """A tracked pathname or opened file changed during the bounded scan."""


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    # Reading may update atime; it must not create a false change finding.
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _read_checked(path: Path, metadata: os.stat_result, limit: int) -> bytes:
    # On Linux, refuse a final-component symlink swap and do not block opening
    # a substituted FIFO. The checkout's parent directories remain trusted.
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or _file_signature(opened) != _file_signature(metadata)):
            raise _ChangedFileError
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit)
        if (_file_signature(os.fstat(descriptor)) != _file_signature(metadata)
                or _file_signature(path.lstat()) != _file_signature(metadata)):
            raise _ChangedFileError
        return data
    finally:
        os.close(descriptor)


def _display_path(relative: str) -> str:
    """Bound and escape filename data without changing the filesystem path."""
    suffix = "...[truncated]"
    remaining = MAX_DISPLAY_PATH_CHARS - len(suffix)
    parts: list[str] = []
    for char in relative:
        # Encode one character at a time so even escaping work is bounded.
        escaped = json.dumps(char, ensure_ascii=True)[1:-1]
        # Escape delimiter text even mid-line; newline escaping alone leaves
        # it intact. Neutralize both modern and legacy command delimiters.
        if char == ":":
            escaped = r"\u003a"
        elif char == "#":
            escaped = r"\u0023"
        if len(escaped) > remaining:
            return "".join(parts) + suffix
        parts.append(escaped)
        remaining -= len(escaped)
    return "".join(parts)


def scan_paths(
    root: Path,
    paths: Iterable[str],
    *,
    max_file_bytes: int = MAX_TRACKED_FILE_BYTES,
    max_binary_bytes: int = MAX_BINARY_FILE_BYTES,
) -> list[str]:
    findings: list[str] = []
    read_limit = max_file_bytes + 1
    for relative in paths:
        normalized = relative.replace("\\", "/")
        display = _display_path(relative)
        path = root / Path(relative)
        if _sensitive_path(normalized):
            findings.append(f"sensitive tracked filename: {display}")
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                findings.append(f"tracked path is not a regular file: {display}")
                continue
            data = _read_checked(path, metadata, read_limit)
            # The overflow byte is evidence too, even if a stale stat was small.
            size = max(metadata.st_size, len(data))
        except _ChangedFileError:
            findings.append(f"tracked file changed during scan: {display}")
            continue
        except OSError:
            findings.append(f"tracked file is unreadable: {display}")
            continue
        if size > max_file_bytes:
            findings.append(
                f"large tracked file: {display} ({size} bytes > {max_file_bytes})"
            )
        if b"\0" in data and size > max_binary_bytes:
            findings.append(
                f"large tracked binary: {display} ({size} bytes > {max_binary_bytes})"
            )
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(data):
                findings.append(f"suspected {label} marker: {display}")
    return findings


def main() -> int:
    try:
        paths = tracked_paths()
        findings = scan_paths(ROOT, paths)
    except Exception as error:
        print(f"repository hygiene guard error: {type(error).__name__}", file=sys.stderr)
        return 2
    if findings:
        print("repository hygiene guard: failed")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print(f"repository hygiene guard: passed ({len(paths)} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
