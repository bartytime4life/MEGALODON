"""Bounded, read-only counts projection from a completed clamscan report."""

import argparse
from datetime import datetime, timezone
import json
import re
import sys

MAX_BYTES = 1024 * 1024
MARKER = "----------- SCAN SUMMARY -----------"
SCHEMA = "megalodon-clamscan-summary-v1"
COUNT_FIELDS = {"Scanned directories": "scanned_directories", "Scanned files": "scanned_files",
                "Infected files": "infected_files", "Total errors": "errors"}
OTHER_FIELDS = {"Known viruses", "Engine version", "Data scanned", "Data read", "Time"}
OPTIONAL_ACTIONS = {"Not removed", "Not moved", "Not copied"}


def summarize_report(raw: bytes, exit_code: int, *, exported_at: datetime | None = None) -> dict:
    """Return only aggregate fields; caller supplies the recorded clamscan exit status."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES or exit_code not in (0, 1):
        raise ValueError("Unsupported completed clamscan report")
    try:
        report = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Unsupported completed clamscan report") from exc
    if report.count(MARKER) != 1 or "\x00" in report:
        raise ValueError("Unsupported completed clamscan report")
    tail = report.split(MARKER, 1)[1].strip().splitlines()
    fields = {}
    allowed = set(COUNT_FIELDS) | OTHER_FIELDS | OPTIONAL_ACTIONS | {"Start Date", "End Date"}
    for line in tail:
        match = re.fullmatch(r"([A-Za-z ]+):\s*([^\r\n]+)", line.strip())
        if not match or match[1] not in allowed or match[1] in fields:
            raise ValueError("Unsupported completed clamscan report")
        fields[match[1]] = match[2]
    required = set(COUNT_FIELDS) - {"Total errors"} | OTHER_FIELDS | {"Start Date", "End Date"}
    if not required <= fields.keys() or set(fields) & OPTIONAL_ACTIONS or not tail[-1].lstrip().startswith("End Date:"):
        raise ValueError("Unsupported completed clamscan report")
    counts = {}
    for source, target in COUNT_FIELDS.items():
        value = fields.get(source, "0")
        if not re.fullmatch(r"(?:0|[1-9][0-9]{0,8})", value):
            raise ValueError("Unsupported completed clamscan report")
        counts[target] = int(value)
    if (counts["errors"] or counts["infected_files"] > counts["scanned_files"]
            or (exit_code == 0) != (counts["infected_files"] == 0)):
        raise ValueError("Incomplete or inconsistent clamscan result")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", fields["Engine version"]):
        raise ValueError("Unsupported clamscan engine version")
    stamps = []
    for key in ("Start Date", "End Date"):
        if not re.fullmatch(r"\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}", fields[key]):
            raise ValueError("Unsupported scan date")
        try:
            stamp = datetime.strptime(fields[key], "%Y:%m:%d %H:%M:%S")
        except ValueError as exc:
            raise ValueError("Unsupported scan date") from exc
        stamps.append(stamp)
    if stamps[0] > stamps[1]:
        raise ValueError("Reversed scan interval")
    at = exported_at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ValueError("Export timestamp must have a timezone")
    return {"schema": SCHEMA, "exported_at": at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_start_local": fields["Start Date"], "scan_end_local": fields["End Date"],
            "engine_version": fields["Engine version"], **counts}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export counts from a completed clamscan report on stdin")
    parser.add_argument("--exit-code", required=True, type=int, choices=(0, 1), help="Recorded clamscan exit status; status 2 is refused")
    args = parser.parse_args(argv)
    try:
        value = summarize_report(sys.stdin.buffer.read(MAX_BYTES + 1), args.exit_code)
    except ValueError:
        print("Unsupported or incomplete clamscan report; no summary exported.", file=sys.stderr)
        return 1
    print(json.dumps(value, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
