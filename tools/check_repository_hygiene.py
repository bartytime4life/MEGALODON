"""Fail-closed checks for tracked repository artifacts and high-confidence secrets."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024
MAX_BINARY_FILE_BYTES = 1 * 1024 * 1024

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


def scan_paths(
    root: Path,
    paths: Iterable[str],
    *,
    max_file_bytes: int = MAX_TRACKED_FILE_BYTES,
    max_binary_bytes: int = MAX_BINARY_FILE_BYTES,
) -> list[str]:
    findings: list[str] = []
    for relative in paths:
        normalized = relative.replace("\\", "/")
        path = root / Path(relative)
        if _sensitive_path(normalized):
            findings.append(f"sensitive tracked filename: {normalized}")
        try:
            if not path.is_file():
                findings.append(f"tracked path is not a regular file: {normalized}")
                continue
            data = path.read_bytes()
        except OSError:
            findings.append(f"tracked file is unreadable: {normalized}")
            continue
        size = len(data)
        if size > max_file_bytes:
            findings.append(
                f"large tracked file: {normalized} ({size} bytes > {max_file_bytes})"
            )
        if b"\0" in data and size > max_binary_bytes:
            findings.append(
                f"large tracked binary: {normalized} ({size} bytes > {max_binary_bytes})"
            )
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(data):
                findings.append(f"suspected {label} marker: {normalized}")
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
