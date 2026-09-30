"""Read one saved, operator-run osqueryi package-count result without host access."""
import argparse
from datetime import datetime, timezone
import json
import re
import sys

SCHEMA = "megalodon-osquery-package-count-v2"
MAX_BYTES = 4096


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Timestamp must have timezone")
    return value.astimezone(timezone.utc)


def summarize(raw: bytes, *, exported_at: datetime | None = None,
              collection_completed_at: datetime | None = None) -> dict:
    """Keep processing time separate from a trusted local collector's completion.

    The raw count has no observation timestamp. Saved reports and CLI exports
    leave collection completion unknown; file metadata cannot establish it.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("Unsupported result")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Constant")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Unsupported result") from exc
    if not isinstance(value, list) or len(value) != 1 or type(value[0]) is not dict or set(value[0]) != {"package_count"}:
        raise ValueError("Unsupported result")
    count = value[0]["package_count"]
    if not isinstance(count, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,8})", count):
        raise ValueError("Unsupported count")
    at = _utc(datetime.now(timezone.utc) if exported_at is None else exported_at)
    completed = None
    if collection_completed_at is not None:
        completed = _utc(collection_completed_at)
        if completed > at:
            raise ValueError("Collection completion cannot follow processing")
    return {"schema": SCHEMA, "exported_at": at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "collection_completed_at": (completed.isoformat(timespec="seconds").replace("+00:00", "Z")
                                        if completed is not None else None),
            "package_rows": int(count)}


def main(argv=None):
    argparse.ArgumentParser(description="Export a count from a saved osqueryi --json result; "
                            "processing time is recorded, observation time remains unknown").parse_args(argv)
    try:
        result = summarize(sys.stdin.buffer.read(MAX_BYTES + 1))
    except ValueError:
        print("Unsupported osquery package-count result; no summary exported.", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
