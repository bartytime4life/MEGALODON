"""Validate selected, operator-captured GitHub readbacks without contacting GitHub.

Development tooling only: no runtime-package import, network, subprocess, Git
mutation, or output-file writer. The trusted checkout and capture provenance are
operator responsibilities; a digest is integrity bookkeeping, not authentication.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/repository-currentness/v1/schema.json"
MAX_INPUT_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 12
BASE = "https://api.github.com/repos/bartytime4life/MEGALODON/"
CLAIMS = {
    "firewall-refusal": (("megalodon/firewall.py",), ("tests/test_firewall.py",)),
    "storage-documentation": (("docs/storage-layout.md",), ("tests/test_documentation_currentness.py",)),
    "site-parity-unverified": (("docs/site-source-alignment.md",), ("tests/test_documentation_currentness.py",)),
    "control-disposition": (("SECURITY_REVIEW.md",), ()),
}


class Refusal(ValueError):
    """A closed diagnostic; never contains caller-supplied content."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("INPUT_INVALID")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise Refusal("INPUT_INVALID")


def _depth(value: object, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise Refusal("INPUT_LIMIT")
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in children:
        _depth(child, depth + 1)


def _read_regular(path: Path, limit: int) -> bytes:
    """Bound regular-file reads; the checkout's parent directories are trusted."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise Refusal("IO_UNAVAILABLE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        if signature(os.fstat(fd)) != signature(before):
            raise Refusal("IO_UNAVAILABLE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if (len(raw) > limit or signature(os.fstat(fd)) != signature(before)
                or signature(path.lstat()) != signature(before)):
            raise Refusal("IO_UNAVAILABLE")
        return raw
    finally:
        os.close(fd)


def _time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def generate(raw: bytes, root: Path = ROOT) -> dict:
    """Return a complete manifest, or one deterministic, data-free refusal."""
    try:
        if len(raw) > MAX_INPUT_BYTES:
            raise Refusal("INPUT_LIMIT")
        capture = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        _depth(capture)
        schema = json.loads(_read_regular(CONTRACT, MAX_INPUT_BYTES))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        if next(validator.iter_errors(capture), None) is not None:
            raise Refusal("INPUT_INVALID")
        readbacks = capture["readbacks"]
        if any(row["status"] != "observed" for row in readbacks.values()):
            raise Refusal("READBACK_UNAVAILABLE")
        data = {key: row["excerpt"] for key, row in readbacks.items()}
        commit, tree = capture["commit_sha"], capture["tree_sha"]
        if (data["branch_start"] != data["branch_end"]
                or data["branch_start"]["sha"] != commit
                or data["commit"] != {"sha": commit, "tree_sha": tree}
                or data["tree"]["sha"] != tree):
            raise Refusal("PIN_MISMATCH")
        for key, expected in {
            "commit": f"git/commits/{commit}",
            "tree": f"git/trees/{tree}?recursive=1",
            "checks": f"commits/{commit}/check-runs?per_page=100",
            "workflows": f"actions/runs?head_sha={commit}&per_page=100",
        }.items():
            if readbacks[key]["query"] != BASE + expected:
                raise Refusal("PIN_MISMATCH")
        start, finish = _time(capture["started_at"]), _time(capture["finished_at"])
        times = {key: _time(row["observed_at"]) for key, row in readbacks.items()}
        if (not 0 <= (finish - start).total_seconds() <= 900
                or any(not start <= t <= finish for t in times.values())
                or times["branch_start"] != min(times.values())
                or times["branch_end"] != max(times.values())):
            raise Refusal("TIME_WINDOW")
        if (data["tree"]["truncated"] or data["rulesets"]["ids"] != [22394782]
                or not data["ruleset"]["default_branch_only"]):
            raise Refusal("INCOMPLETE_READBACK")
        issues, pulls = data["issues"]["items"], data["pulls"]["numbers"]
        if (len({row["number"] for row in issues}) != len(issues)
                or sorted(row["number"] for row in issues if row["kind"] == "pull_request") != sorted(pulls)):
            raise Refusal("INCOMPLETE_READBACK")
        for key in ("checks", "workflows"):
            rows = data[key]["items"]
            if (len(rows) != data[key]["total_count"]
                    or len({row["id"] for row in rows}) != len(rows)):
                raise Refusal("INCOMPLETE_READBACK")
            for row in rows:
                if row["head_sha"] != commit:
                    raise Refusal("PIN_MISMATCH")
                if (row["status"] == "completed") != (row["conclusion"] is not None):
                    raise Refusal("INCOMPLETE_READBACK")
        files = data["tree"]["files"]
        indexed = {row["path"]: row for row in files}
        expected_paths = {path for groups in CLAIMS.values() for group in groups for path in group}
        if len(indexed) != len(files) or set(indexed) != expected_paths:
            raise Refusal("CLAIM_REFERENCE")
        for relative, row in indexed.items():
            path = root / relative
            if any(parent.is_symlink() for parent in path.parents):
                raise Refusal("LOCAL_IDENTITY")
            blob = _read_regular(path, MAX_SOURCE_BYTES)
            identity = hashlib.sha1(b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob).hexdigest()
            if identity != row["sha"]:
                raise Refusal("LOCAL_IDENTITY")
        claims = capture["claims"]
        claim_ids = {claim["id"] for claim in claims}
        if len(claim_ids) != len(claims) or claim_ids != set(CLAIMS):
            raise Refusal("CLAIM_REFERENCE")
        successful_checks = {row["id"] for row in data["checks"]["items"] if row["conclusion"] == "success"}
        for claim in claims:
            sources, tests = CLAIMS[claim["id"]]
            if (claim["source_paths"] != list(sources) or claim["test_paths"] != list(tests)
                    or not set(claim["check_run_ids"]) <= successful_checks
                    or (claim["state"] == "verified" and tests and not claim["check_run_ids"])):
                raise Refusal("CLAIM_REFERENCE")
        return {
            "schema_version": "megalodon-currentness-manifest-v1",
            "status": "validated", "scope": "point-in-time-selected-fields-only",
            "capture": capture, "capture_sha256": digest(capture),
            "excerpt_sha256": {key: digest(row["excerpt"]) for key, row in readbacks.items()},
        }
    except Refusal as error:
        reason = str(error)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        reason = "INPUT_INVALID"
    except OSError:
        reason = "IO_UNAVAILABLE"
    return {"schema_version": "megalodon-currentness-manifest-v1", "status": "blocked", "reason": reason}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="reviewed, bounded local JSON capture")
    args = parser.parse_args(argv)
    try:
        raw = _read_regular(args.capture, MAX_INPUT_BYTES)
        result = generate(raw)
    except (OSError, Refusal):
        result = {"schema_version": "megalodon-currentness-manifest-v1", "status": "blocked", "reason": "IO_UNAVAILABLE"}
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0 if result["status"] == "validated" else 3


if __name__ == "__main__":
    raise SystemExit(main())
