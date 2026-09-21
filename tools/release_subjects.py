#!/usr/bin/env python3
"""Bind two ephemeral distribution subjects to one clean source checkout."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MAX_ARTIFACT_BYTES = 67_108_864
MAX_MANIFEST_BYTES = 16_384
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}\Z")
REPOSITORY_URLS = {
    "https://github.com/bartytime4life/MEGALODON",
    "https://github.com/bartytime4life/MEGALODON.git",
}
SCHEMA = "megalodon-ephemeral-subjects-v1"
LIMITATIONS = (
    "Temporary CI build subjects; no package publication or release authority.",
    "Source and artifact digests bind bytes but do not authenticate the runner or builder.",
    "Nine release checks, license review, operator recovery and independent acceptance remain separate.",
)


class SubjectError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"RELEASE_SUBJECTS:{code}")


def _fail(code: str) -> None:
    raise SubjectError(code) from None


def _read_regular(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
                _fail("FILE_INVALID")
            chunks = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        _fail("FILE_INVALID")
    if not raw or len(raw) > maximum or len(raw) != before.st_size:
        _fail("FILE_INVALID")
    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
        if getattr(before, field) != getattr(after, field):
            _fail("FILE_CHANGED")
    return raw


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("MANIFEST_INVALID")
        result[key] = value
    return result


def _names(version: str) -> tuple[str, str]:
    if type(version) is not str or VERSION.fullmatch(version) is None:
        _fail("VERSION_INVALID")
    return (f"megalodon_defense-{version}-py3-none-any.whl",
            f"megalodon_defense-{version}.tar.gz")


def _artifact(path: Path, artifact_id: str, name: str) -> dict:
    if path.name != name:
        _fail("ARTIFACT_MISMATCH")
    raw = _read_regular(path, MAX_ARTIFACT_BYTES)
    return {"id": artifact_id, "name": name, "size_bytes": len(raw),
            "sha256": "sha256:" + sha256(raw).hexdigest()}


def _git(checkout: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args], cwd=checkout, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("SOURCE_UNAVAILABLE")
    if len(result.stdout) > 4096:
        _fail("SOURCE_UNAVAILABLE")
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        _fail("SOURCE_UNAVAILABLE")


def collect(checkout: Path, commit: str, tree: str, version: str,
            wheel: Path, sdist: Path) -> dict:
    if any(type(value) is not str or HEX40.fullmatch(value) is None for value in (commit, tree)):
        _fail("SOURCE_MISMATCH")
    wheel_name, sdist_name = _names(version)
    if (
        _git(checkout, "rev-parse", "--verify", "HEAD") != commit
        or _git(checkout, "rev-parse", "--verify", "HEAD^{tree}") != tree
        or _git(checkout, "status", "--porcelain", "--untracked-files=normal")
        or _git(checkout, "remote", "get-url", "origin") not in REPOSITORY_URLS
    ):
        _fail("SOURCE_MISMATCH")
    artifacts = [_artifact(wheel, "wheel", wheel_name),
                 _artifact(sdist, "sdist", sdist_name)]
    if (
        _git(checkout, "rev-parse", "--verify", "HEAD") != commit
        or _git(checkout, "rev-parse", "--verify", "HEAD^{tree}") != tree
        or _git(checkout, "status", "--porcelain", "--untracked-files=normal")
    ):
        _fail("SOURCE_MISMATCH")
    manifest = {"schema": SCHEMA, "status": "built_unreviewed",
                "source": {"commit": commit, "tree": tree}, "package_version": version,
                "artifacts": artifacts, "published": False,
                "limitations": list(LIMITATIONS)}
    if len(_canonical(manifest)) > MAX_MANIFEST_BYTES:
        _fail("MANIFEST_INVALID")
    return manifest


def verify(directory: Path, commit: str, tree: str) -> dict:
    if any(type(value) is not str or HEX40.fullmatch(value) is None for value in (commit, tree)):
        _fail("SOURCE_MISMATCH")
    try:
        if not stat.S_ISDIR(directory.lstat().st_mode):
            _fail("FILE_INVALID")
        names = {item.name for item in directory.iterdir()}
    except OSError:
        _fail("FILE_INVALID")
    raw = _read_regular(directory / "subjects.json", MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: _fail("MANIFEST_INVALID"))
    except (UnicodeError, ValueError, RecursionError):
        _fail("MANIFEST_INVALID")
    if type(manifest) is not dict or set(manifest) != {
        "schema", "status", "source", "package_version", "artifacts", "published", "limitations"
    } or raw != _canonical(manifest):
        _fail("MANIFEST_INVALID")
    version = manifest["package_version"]
    wheel_name, sdist_name = _names(version)
    if names != {"subjects.json", wheel_name, sdist_name}:
        _fail("FILE_SET")
    if manifest["source"] != {"commit": commit, "tree": tree}:
        _fail("SOURCE_MISMATCH")
    if (manifest["schema"] != SCHEMA or manifest["status"] != "built_unreviewed"
            or manifest["published"] is not False
            or manifest["limitations"] != list(LIMITATIONS)):
        _fail("MANIFEST_INVALID")
    observed = [_artifact(directory / wheel_name, "wheel", wheel_name),
                _artifact(directory / sdist_name, "sdist", sdist_name)]
    if manifest["artifacts"] != observed:
        _fail("ARTIFACT_MISMATCH")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    group = parser.add_subparsers(dest="command", required=True)
    build = group.add_parser("collect", allow_abbrev=False)
    build.add_argument("--checkout", required=True, type=Path)
    build.add_argument("--expected-commit", required=True)
    build.add_argument("--expected-tree", required=True)
    build.add_argument("--package-version", required=True)
    build.add_argument("--wheel", required=True, type=Path)
    build.add_argument("--sdist", required=True, type=Path)
    check = group.add_parser("verify", allow_abbrev=False)
    check.add_argument("--directory", required=True, type=Path)
    check.add_argument("--expected-commit", required=True)
    check.add_argument("--expected-tree", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            manifest = collect(args.checkout, args.expected_commit, args.expected_tree,
                               args.package_version, args.wheel, args.sdist)
            sys.stdout.buffer.write(_canonical(manifest))
        else:
            manifest = verify(args.directory, args.expected_commit, args.expected_tree)
            print(json.dumps({"schema": SCHEMA, "status": "binding_verified",
                              "authentication": "not_performed",
                              "source": manifest["source"]}, sort_keys=True))
        return 0
    except SubjectError as exc:
        print(json.dumps({"schema": SCHEMA, "status": "blocked", "reason": exc.code},
                         sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
