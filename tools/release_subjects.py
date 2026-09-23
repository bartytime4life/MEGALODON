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
CI_SCHEMA = "megalodon-ephemeral-subjects-v2"
REPOSITORY = "bartytime4life/MEGALODON"
WORKFLOW = ".github/workflows/release-subject-evidence.yml"
PRODUCER_JOB = "build-subjects"
WORKFLOW_REF = re.compile(re.escape(REPOSITORY + "/" + WORKFLOW) + r"@refs/pull/[1-9][0-9]{0,9}/merge\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
RUN_ATTEMPT = re.compile(r"[1-9][0-9]{0,5}\Z")
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


def validate_producer(value: object) -> dict:
    """Validate a closed declaration, never authenticate a GitHub runner."""
    if type(value) is not dict or set(value) != {
        "basis", "repository", "workflow", "workflow_ref", "workflow_commit",
        "job", "run_id", "run_attempt", "authentication",
    } or any(type(item) is not str for item in value.values()):
        _fail("PRODUCER_INVALID")
    if (value["basis"] != "github_actions"
            or value["authentication"] != "not_performed"
            or value["repository"] != REPOSITORY or value["workflow"] != WORKFLOW
            or value["job"] != PRODUCER_JOB
            or WORKFLOW_REF.fullmatch(value["workflow_ref"]) is None
            or HEX40.fullmatch(value["workflow_commit"]) is None
            or RUN_ID.fullmatch(value["run_id"]) is None
            or RUN_ATTEMPT.fullmatch(value["run_attempt"]) is None):
        _fail("PRODUCER_INVALID")
    return value


def github_actions_producer(*, roundtrip: bool = False) -> dict:
    """Capture only allowlisted CI context; environment values are self-asserted."""
    env = os.environ
    if (env.get("GITHUB_ACTIONS") != "true"
            or env.get("GITHUB_SERVER_URL") != "https://github.com"
            or env.get("GITHUB_EVENT_NAME") != "pull_request"
            or env.get("GITHUB_JOB") != ("subject-roundtrip" if roundtrip else PRODUCER_JOB)):
        _fail("PRODUCER_CONTEXT")
    if env.get("GITHUB_WORKFLOW_REF") != REPOSITORY + "/" + WORKFLOW + "@" + env.get("GITHUB_REF", ""):
        _fail("PRODUCER_CONTEXT")
    return validate_producer({
        "basis": "github_actions", "authentication": "not_performed",
        "repository": env.get("GITHUB_REPOSITORY", ""), "workflow": WORKFLOW,
        "workflow_ref": env.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_commit": env.get("GITHUB_WORKFLOW_SHA", ""),
        "job": PRODUCER_JOB, "run_id": env.get("GITHUB_RUN_ID", ""),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
    })


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
            wheel: Path, sdist: Path, *, github_actions_origin: bool = False) -> dict:
    if any(type(value) is not str or HEX40.fullmatch(value) is None for value in (commit, tree)):
        _fail("SOURCE_MISMATCH")
    producer = github_actions_producer() if github_actions_origin else None
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
    if producer is not None:
        manifest.update(schema=CI_SCHEMA, producer=producer)
    if len(_canonical(manifest)) > MAX_MANIFEST_BYTES:
        _fail("MANIFEST_INVALID")
    return manifest


def parse_manifest(raw: bytes, commit: str, tree: str) -> dict:
    """Validate retained manifest bytes without inspecting a host or artifact."""
    if any(type(value) is not str or HEX40.fullmatch(value) is None for value in (commit, tree)):
        _fail("SOURCE_MISMATCH")
    if not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        _fail("MANIFEST_INVALID")
    try:
        manifest = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: _fail("MANIFEST_INVALID"))
    except (UnicodeError, ValueError, RecursionError):
        _fail("MANIFEST_INVALID")
    if type(manifest) is not dict or type(manifest.get("schema")) is not str:
        _fail("MANIFEST_INVALID")
    expected_keys = {
        "schema", "status", "source", "package_version", "artifacts", "published", "limitations"
    }
    if manifest.get("schema") == CI_SCHEMA:
        expected_keys.add("producer")
    if set(manifest) != expected_keys or raw != _canonical(manifest):
        _fail("MANIFEST_INVALID")
    _names(manifest["package_version"])
    if manifest["source"] != {"commit": commit, "tree": tree}:
        _fail("SOURCE_MISMATCH")
    if (manifest["schema"] not in {SCHEMA, CI_SCHEMA} or manifest["status"] != "built_unreviewed"
            or manifest["published"] is not False
            or manifest["limitations"] != list(LIMITATIONS)):
        _fail("MANIFEST_INVALID")
    if manifest["schema"] == CI_SCHEMA:
        validate_producer(manifest["producer"])
    return manifest


def verify(directory: Path, commit: str, tree: str) -> dict:
    try:
        if not stat.S_ISDIR(directory.lstat().st_mode):
            _fail("FILE_INVALID")
        names = {item.name for item in directory.iterdir()}
    except OSError:
        _fail("FILE_INVALID")
    manifest = parse_manifest(_read_regular(directory / "subjects.json", MAX_MANIFEST_BYTES), commit, tree)
    wheel_name, sdist_name = _names(manifest["package_version"])
    if names != {"subjects.json", wheel_name, sdist_name}:
        _fail("FILE_SET")
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
    build.add_argument("--github-actions-origin", action="store_true")
    check = group.add_parser("verify", allow_abbrev=False)
    check.add_argument("--directory", required=True, type=Path)
    check.add_argument("--expected-commit", required=True)
    check.add_argument("--expected-tree", required=True)
    check.add_argument("--github-actions-origin", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            manifest = collect(args.checkout, args.expected_commit, args.expected_tree,
                               args.package_version, args.wheel, args.sdist,
                               github_actions_origin=args.github_actions_origin)
            sys.stdout.buffer.write(_canonical(manifest))
        else:
            manifest = verify(args.directory, args.expected_commit, args.expected_tree)
            if args.github_actions_origin:
                expected = github_actions_producer(roundtrip=os.environ.get("GITHUB_JOB") == "subject-roundtrip")
                if manifest.get("producer") != expected:
                    _fail("PRODUCER_MISMATCH")
            print(json.dumps({"schema": manifest["schema"], "status": "binding_verified",
                              "authentication": "not_performed",
                              "source": manifest["source"]}, sort_keys=True))
        return 0
    except SubjectError as exc:
        print(json.dumps({"schema": SCHEMA, "status": "blocked", "reason": exc.code},
                         sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
