"""HUD projection of the host tripwires: canary files and login review. Read-only.

The HUD runs this in the background. It checks the canary manifest at the
conventional path ``~/.config/megalodon/canary.json`` (planted with
``megalodon canary plant``) and reviews the first readable system auth log.
Nothing is planted, rearmed, written, fetched or blocked here; those stay
explicit CLI actions. The projection is bounded, and file paths are reduced
to file names so the HUD never displays this account's directory layout.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Callable

from . import auth_review, canary
from .validation import ValidationError

SCHEMA = "megalodon-host-tripwires-v1"
MANIFEST = Path(".config/megalodon/canary.json")
AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")
MAX_FINDINGS = 16
MAX_SOURCES = 5
MAX_TEXT = 512
_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(value: object, limit: int = MAX_TEXT) -> str:
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text[:limit] or "-"


def _canary(home: Path) -> dict[str, Any]:
    manifest = home / MANIFEST
    command = "megalodon canary plant --dir <folder> --manifest ~/.config/megalodon/canary.json"
    if not os.path.lexists(manifest):
        return {"state": "not_configured", "setup": command}
    try:
        report = canary.check(str(manifest))
    except ValidationError as exc:
        return {"state": "unavailable", "reason": _text(exc, 256)}
    findings = sorted(report["findings"], key=lambda f: (_RANK[f["severity"]], f["path"]))
    return {
        "state": "tripped" if findings else "clear",
        "canaries": report["canaries"],
        "read_detection": report["read_detection"],
        "findings": [
            {"rule_id": f["rule_id"], "severity": f["severity"],
             "name": _text(os.path.basename(f["path"]), 255), "detail": _text(f["detail"])}
            for f in findings[:MAX_FINDINGS]
        ],
        "findings_total": len(findings),
    }


def _auth(paths: tuple[str, ...], now: datetime | None) -> dict[str, Any]:
    present = [path for path in paths if os.path.exists(path)]
    if not present:
        return {"state": "not_found", "checked": [os.path.basename(p) for p in paths]}
    errors = []
    for path in present:
        try:
            report, _ = auth_review.review(auth_review.read_lines(path), source=path,
                                           reference=now)
        except ValidationError as exc:
            errors.append(_text(exc, 256))
            continue
        findings = sorted(report["findings"],
                          key=lambda f: (_RANK[f["severity"]], -datetime.fromisoformat(
                              f["observed_at"]).timestamp()))
        return {
            "state": "ready",
            "source": os.path.basename(path),
            "window": report["window"],
            "observed": report["observed"],
            "severity_counts": report["severity_counts"],
            "top_failing_sources": report["top_failing_sources"][:MAX_SOURCES],
            "findings": [
                {"rule_id": f["rule_id"], "severity": f["severity"], "observed_at": f["observed_at"],
                 "subject": _text(f["subject"], 128), "message": _text(f["message"]),
                 "attack": list(f["attack"])}
                for f in findings[:MAX_FINDINGS]
            ],
            # Every emitted finding, including any beyond the retained cap.
            "findings_total": sum(report["severity_counts"].values()),
            "truncated": report["truncated"],
        }
    return {"state": "unreadable", "reason": errors[0]}


def review(home: Path | None = None, *, auth_paths: tuple[str, ...] = AUTH_LOGS,
           now: Callable[[], str] = _now, reference: datetime | None = None) -> dict[str, Any]:
    home = Path.home() if home is None else Path(home)
    return {
        "schema": SCHEMA,
        "reviewed_at": now(),
        "canary": _canary(home),
        "auth": _auth(tuple(auth_paths), reference),
        "action_authority": "none",
    }
