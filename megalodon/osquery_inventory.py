"""Read one saved, operator-run osqueryi package-count result without host access."""
import argparse
from datetime import datetime, timezone
import json
import re
import sys

SCHEMA = "megalodon-osquery-package-count-v1"
MAX_BYTES = 4096


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def summarize(raw: bytes, *, exported_at: datetime | None = None) -> dict:
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
    at = exported_at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ValueError("Export timestamp must have timezone")
    return {"schema": SCHEMA, "exported_at": at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "package_rows": int(count)}


def main(argv=None):
    argparse.ArgumentParser(description="Export a count from a saved osqueryi --json result").parse_args(argv)
    try:
        result = summarize(sys.stdin.buffer.read(MAX_BYTES + 1))
    except ValueError:
        print("Unsupported osquery package-count result; no summary exported.", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
