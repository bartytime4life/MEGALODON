"""Bounded, read-only RRULE parser and occurrence preview for automation v1.

`docs/automation-contract.md` describes a future scheduling subsystem for
issue #84. Alongside the Stage 0 JSON Schema shape in
`contracts/automation/v1`, this module implements the bounded "Recurrence
semantics and parser" preview without adding a scheduler:

- `parse_rrule` validates and canonicalizes one RFC 5545 `RRULE` value beyond
  the contract's structural regex: known/duplicate rule parts, per-part value
  ranges, and the documented COUNT/UNTIL exclusion and high-frequency bound.
- `next_occurrences` turns one validated `dtstart` + `schedule_timezone` +
  `rrule` + `dst_policy` into a bounded, deterministic, chronologically
  ordered preview of future occurrence instants, using only the standard
  library (`zoneinfo`).

This is a pure, offline, read-only computation. It creates no automation
record, ledger row, scheduler loop, worker, retry, model call, folder
resolution, or firewall/network/shell access, and it does not decide whether
an automation may activate. To keep every supported case verifiably correct
rather than approximated, generation intentionally covers a narrower surface
than the full RFC 5545 grammar (documented per rule part below) and fails
closed with `UNSUPPORTED_COMBINATION` outside it, the same fail-closed
posture `megalodon.alert_lifecycle` uses for its own closed edge set.
"""

from __future__ import annotations

from collections.abc import Mapping
import calendar
from datetime import datetime, timedelta, timezone
from itertools import islice
from types import MappingProxyType
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import re

FREQUENCIES = frozenset({"MINUTELY", "HOURLY", "DAILY", "WEEKLY", "MONTHLY", "YEARLY"})
_HIGH_FREQUENCIES = frozenset({"MINUTELY", "HOURLY"})
WEEKDAY_CODES = ("MO", "TU", "WE", "TH", "FR", "SA", "SU")
DST_POLICIES = frozenset({"reject", "skip", "shift_forward", "fold_earlier", "fold_later"})

# Policy defaults for this implementation only; not an RFC 5545 requirement.
MAX_INTERVAL = 1_000
MAX_COUNT = 3_660
MAX_GENERATED_OCCURRENCES = 366
_MAX_CANDIDATE_SCANS = 10_000

_KNOWN_PARTS = frozenset({
    "INTERVAL", "COUNT", "UNTIL", "BYDAY", "BYMONTHDAY", "BYMONTH",
    "BYHOUR", "BYMINUTE", "WKST",
})
_PART_ORDER = ("INTERVAL", "COUNT", "UNTIL", "BYMONTH", "BYMONTHDAY", "BYDAY", "BYHOUR", "BYMINUTE", "WKST")

_CANONICAL = re.compile(
    r"FREQ=(MINUTELY|HOURLY|DAILY|WEEKLY|MONTHLY|YEARLY)(;[A-Z]+=[A-Z0-9,+-]+)*\Z"
)
_POSITIVE_INT = re.compile(r"[0-9]{1,9}\Z")
_UNTIL = re.compile(r"[0-9]{8}T[0-9]{6}Z\Z")
_DTSTART = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\Z")
_ZONE_NAME = re.compile(r"(UTC|[A-Za-z_+-]+/[A-Za-z0-9_+./-]+)\Z")

ERROR_CODES = frozenset({
    "PATTERN", "DUPLICATE_PART", "UNKNOWN_PART", "COUNT_AND_UNTIL",
    "INTERVAL_VALUE", "INTERVAL_BOUND", "COUNT_VALUE", "COUNT_BOUND",
    "UNTIL_VALUE", "BYDAY_VALUE", "BYMONTHDAY_VALUE", "BYMONTH_VALUE",
    "BYHOUR_VALUE", "BYMINUTE_VALUE", "WKST_VALUE", "UNBOUNDED_HIGH_FREQUENCY",
    "UNSUPPORTED_COMBINATION", "DTSTART_VALUE", "TIMEZONE_VALUE",
    "DST_POLICY_VALUE", "DST_UNRESOLVED", "DST_POLICY_INAPPLICABLE", "LIMIT_VALUE",
    "SCAN_LIMIT",
})


class AutomationScheduleError(ValueError):
    """A fixed, closed diagnostic for the bounded RRULE preview boundary."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "PATTERN"
        super().__init__(f"AUTOMATION_SCHEDULE_V1:{code}")
        self.code = code


def _fail(code: str) -> None:
    raise AutomationScheduleError(code) from None


def _bounded_int(text: str, minimum: int, maximum: int, code: str) -> int:
    if not _POSITIVE_INT.fullmatch(text):
        _fail(code)
    value = int(text)
    if not minimum <= value <= maximum:
        _fail(code)
    return value


def _int_list(text: str, minimum: int, maximum: int, code: str) -> tuple[int, ...]:
    items = text.split(",")
    values = [_bounded_int(item, minimum, maximum, code) for item in items]
    if len(values) != len(set(values)):
        _fail(code)
    return tuple(sorted(values))


def _day_list(text: str) -> tuple[str, ...]:
    items = text.split(",")
    for item in items:
        if item not in WEEKDAY_CODES:
            _fail("BYDAY_VALUE")
    if len(items) != len(set(items)):
        _fail("BYDAY_VALUE")
    return tuple(sorted(items, key=WEEKDAY_CODES.index))


def parse_rrule(rrule: str) -> Mapping[str, Any]:
    """Validate one RRULE value and return its bounded, canonical fields.

    Beyond the contract's structural regex this rejects unknown or duplicate
    rule parts, out-of-range values, COUNT together with UNTIL, and an
    indefinite MINUTELY/HOURLY schedule, matching the policy
    `docs/automation-contract.md` section 6.1 describes for a future v1
    validator.
    """
    if type(rrule) is not str or not 10 <= len(rrule) <= 512:
        _fail("PATTERN")
    text = rrule[len("RRULE:"):] if rrule.startswith("RRULE:") else rrule
    if not _CANONICAL.fullmatch(text):
        _fail("PATTERN")

    parts = text.split(";")
    frequency = parts[0].split("=", 1)[1]
    seen: set[str] = set()
    interval = 1
    count: int | None = None
    until: str | None = None
    by_day: tuple[str, ...] = ()
    by_month_day: tuple[int, ...] = ()
    by_month: tuple[int, ...] = ()
    by_hour: int | None = None
    by_minute: int | None = None
    week_start = "MO"

    for part in parts[1:]:
        key, _, value = part.partition("=")
        if key in seen:
            _fail("DUPLICATE_PART")
        seen.add(key)
        if key not in _KNOWN_PARTS:
            _fail("UNKNOWN_PART")
        if key == "INTERVAL":
            interval = _bounded_int(value, 1, MAX_INTERVAL, "INTERVAL_BOUND")
        elif key == "COUNT":
            count = _bounded_int(value, 1, MAX_COUNT, "COUNT_BOUND")
        elif key == "UNTIL":
            if not _UNTIL.fullmatch(value):
                _fail("UNTIL_VALUE")
            try:
                datetime.strptime(value, "%Y%m%dT%H%M%SZ")
            except ValueError:
                _fail("UNTIL_VALUE")
            until = value
        elif key == "BYDAY":
            by_day = _day_list(value)
        elif key == "BYMONTHDAY":
            by_month_day = _int_list(value, 1, 31, "BYMONTHDAY_VALUE")
        elif key == "BYMONTH":
            by_month = _int_list(value, 1, 12, "BYMONTH_VALUE")
        elif key == "BYHOUR":
            values = _int_list(value, 0, 23, "BYHOUR_VALUE")
            if len(values) != 1:
                _fail("BYHOUR_VALUE")
            by_hour = values[0]
        elif key == "BYMINUTE":
            values = _int_list(value, 0, 59, "BYMINUTE_VALUE")
            if len(values) != 1:
                _fail("BYMINUTE_VALUE")
            by_minute = values[0]
        elif key == "WKST":
            if value not in WEEKDAY_CODES:
                _fail("WKST_VALUE")
            week_start = value

    if count is not None and until is not None:
        _fail("COUNT_AND_UNTIL")
    if frequency in _HIGH_FREQUENCIES and count is None and until is None:
        _fail("UNBOUNDED_HIGH_FREQUENCY")

    canonical_parts = [f"FREQ={frequency}"]
    values_by_key = {
        "INTERVAL": str(interval) if interval != 1 or "INTERVAL" in seen else None,
        "COUNT": str(count) if count is not None else None,
        "UNTIL": until,
        "BYMONTH": ",".join(str(v) for v in by_month) if by_month else None,
        "BYMONTHDAY": ",".join(str(v) for v in by_month_day) if by_month_day else None,
        "BYDAY": ",".join(by_day) if by_day else None,
        "BYHOUR": str(by_hour) if by_hour is not None else None,
        "BYMINUTE": str(by_minute) if by_minute is not None else None,
        "WKST": week_start if "WKST" in seen else None,
    }
    for key in _PART_ORDER:
        value = values_by_key[key]
        if value is not None:
            canonical_parts.append(f"{key}={value}")

    return MappingProxyType({
        "rrule": ";".join(canonical_parts),
        "frequency": frequency,
        "interval": interval,
        "count": count,
        "until": until,
        "by_day": by_day,
        "by_month_day": by_month_day,
        "by_month": by_month,
        "by_hour": by_hour,
        "by_minute": by_minute,
        "week_start": week_start,
    })


def _zone(name: object) -> ZoneInfo:
    if (type(name) is not str or len(name) > 128 or not _ZONE_NAME.fullmatch(name)
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        _fail("TIMEZONE_VALUE")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        _fail("TIMEZONE_VALUE")


def _local_datetime(value: object) -> datetime:
    if type(value) is not str or not _DTSTART.fullmatch(value):
        _fail("DTSTART_VALUE")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        _fail("DTSTART_VALUE")


def _day_exists(year: int, month: int, day: int) -> bool:
    return 1 <= day <= calendar.monthrange(year, month)[1]


def _month_add(year: int, month: int, delta: int) -> tuple[int, int]:
    total = year * 12 + (month - 1) + delta
    return total // 12, total % 12 + 1


def _check_generation_support(parsed: Mapping[str, Any], dtstart: datetime) -> None:
    frequency = parsed["frequency"]
    by_day, by_month_day, by_month = parsed["by_day"], parsed["by_month_day"], parsed["by_month"]
    by_hour, by_minute = parsed["by_hour"], parsed["by_minute"]

    if frequency in _HIGH_FREQUENCIES and (by_day or by_month_day or by_month or by_hour is not None or by_minute is not None):
        _fail("UNSUPPORTED_COMBINATION")
    if by_day and frequency not in {"DAILY", "WEEKLY"}:
        _fail("UNSUPPORTED_COMBINATION")
    if frequency == "DAILY" and by_day and parsed["interval"] != 1:
        _fail("UNSUPPORTED_COMBINATION")
    if by_month_day and not (frequency == "MONTHLY" or (frequency == "YEARLY" and by_month)):
        _fail("UNSUPPORTED_COMBINATION")
    if by_month and frequency != "YEARLY":
        _fail("UNSUPPORTED_COMBINATION")

    weekday_code = WEEKDAY_CODES[dtstart.weekday()]
    if by_day and weekday_code not in by_day:
        _fail("DTSTART_VALUE")
    if by_month_day and dtstart.day not in by_month_day:
        _fail("DTSTART_VALUE")
    if by_month and dtstart.month not in by_month:
        _fail("DTSTART_VALUE")
    if by_hour is not None and dtstart.hour != by_hour:
        _fail("DTSTART_VALUE")
    if by_minute is not None and dtstart.minute != by_minute:
        _fail("DTSTART_VALUE")


def _apply_time_override(candidate: datetime, by_hour: int | None, by_minute: int | None) -> datetime:
    if by_hour is None and by_minute is None:
        return candidate
    return candidate.replace(
        hour=by_hour if by_hour is not None else candidate.hour,
        minute=by_minute if by_minute is not None else candidate.minute,
    )


def _candidates(dtstart: datetime, parsed: Mapping[str, Any]):
    frequency = parsed["frequency"]
    interval = parsed["interval"]
    by_day, by_month_day, by_month = parsed["by_day"], parsed["by_month_day"], parsed["by_month"]
    by_hour, by_minute = parsed["by_hour"], parsed["by_minute"]

    if frequency == "MINUTELY":
        step = timedelta(minutes=interval)
        n = 0
        while True:
            yield dtstart + step * n
            n += 1
    elif frequency == "HOURLY":
        step = timedelta(hours=interval)
        n = 0
        while True:
            yield dtstart + step * n
            n += 1
    elif frequency == "DAILY" and not by_day:
        step = timedelta(days=interval)
        n = 0
        while True:
            yield _apply_time_override(dtstart + step * n, by_hour, by_minute)
            n += 1
    elif frequency == "DAILY":
        day = dtstart.date()
        while True:
            if WEEKDAY_CODES[day.weekday()] in by_day:
                yield _apply_time_override(datetime.combine(day, dtstart.time()), by_hour, by_minute)
            day += timedelta(days=1)
    elif frequency == "WEEKLY" and not by_day:
        step = timedelta(weeks=interval)
        n = 0
        while True:
            yield _apply_time_override(dtstart + step * n, by_hour, by_minute)
            n += 1
    elif frequency == "WEEKLY":
        week_start_index = WEEKDAY_CODES.index(parsed["week_start"])
        # Canonical BYDAY is Monday-first; generation must follow this rule's
        # week boundary before COUNT, UNTIL, or the preview limit is applied.
        day_offsets = sorted((WEEKDAY_CODES.index(code) - week_start_index) % 7 for code in by_day)
        dtstart_date = dtstart.date()
        offset = (dtstart_date.weekday() - week_start_index) % 7
        week0_start = dtstart_date - timedelta(days=offset)
        group = 0
        while True:
            if group % interval == 0:
                week_start_date = week0_start + timedelta(weeks=group)
                for day_offset in day_offsets:
                    date = week_start_date + timedelta(days=day_offset)
                    if group == 0 and date < dtstart_date:
                        continue
                    yield _apply_time_override(datetime.combine(date, dtstart.time()), by_hour, by_minute)
            group += 1
    elif frequency == "MONTHLY" and not by_month_day:
        n = 0
        while True:
            year, month = _month_add(dtstart.year, dtstart.month, n * interval)
            if _day_exists(year, month, dtstart.day):
                yield _apply_time_override(datetime(year, month, dtstart.day, dtstart.hour, dtstart.minute, dtstart.second), by_hour, by_minute)
            n += 1
    elif frequency == "MONTHLY":
        n = 0
        while True:
            year, month = _month_add(dtstart.year, dtstart.month, n * interval)
            for day in by_month_day:
                if n == 0 and day < dtstart.day:
                    continue
                if _day_exists(year, month, day):
                    yield _apply_time_override(datetime(year, month, day, dtstart.hour, dtstart.minute, dtstart.second), by_hour, by_minute)
            n += 1
    elif frequency == "YEARLY" and not by_month:
        n = 0
        while True:
            year = dtstart.year + n * interval
            if _day_exists(year, dtstart.month, dtstart.day):
                yield _apply_time_override(datetime(year, dtstart.month, dtstart.day, dtstart.hour, dtstart.minute, dtstart.second), by_hour, by_minute)
            n += 1
    else:  # YEARLY with BYMONTH
        day_list = by_month_day if by_month_day else (dtstart.day,)
        n = 0
        while True:
            year = dtstart.year + n * interval
            for month in by_month:
                for day in day_list:
                    if n == 0 and (month, day) < (dtstart.month, dtstart.day):
                        continue
                    if _day_exists(year, month, day):
                        yield _apply_time_override(datetime(year, month, day, dtstart.hour, dtstart.minute, dtstart.second), by_hour, by_minute)
            n += 1


def _dst_status(local_naive: datetime, zone: ZoneInfo) -> tuple[str, datetime, datetime]:
    dt0 = local_naive.replace(tzinfo=zone, fold=0)
    dt1 = local_naive.replace(tzinfo=zone, fold=1)
    utc0 = dt0.astimezone(timezone.utc)
    utc1 = dt1.astimezone(timezone.utc)
    if utc0 == utc1:
        return "normal", utc0, utc1
    back0 = utc0.astimezone(zone).replace(tzinfo=None)
    back1 = utc1.astimezone(zone).replace(tzinfo=None)
    if back0 == local_naive and back1 == local_naive:
        return "ambiguous", utc0, utc1
    return "gap", utc0, utc1


def _resolve(status: str, utc0: datetime, utc1: datetime, policy: str) -> datetime | None:
    if status == "normal":
        return utc0
    if policy == "reject":
        _fail("DST_UNRESOLVED")
    if policy == "skip":
        return None
    if status == "gap":
        if policy == "shift_forward":
            # In a gap, fold=0 uses the pre-transition offset. Its UTC instant
            # round-trips forward by the gap; fold=1 round-trips backward.
            return utc0
        _fail("DST_POLICY_INAPPLICABLE")
    if policy in {"fold_earlier", "fold_later"}:
        return utc0 if policy == "fold_earlier" else utc1
    _fail("DST_POLICY_INAPPLICABLE")


def _forward_preview(
    dtstart: datetime, parsed: Mapping[str, Any], zone: ZoneInfo,
    cap: int, until_utc: datetime | None,
) -> tuple[Mapping[str, Any], ...]:
    """Normalize shifted gaps by UTC identity before truncating the preview.

    Python UTC offsets are strictly between -24 and +24 hours. Thus every
    later local candidate must resolve after candidate-as-UTC minus 24 hours.
    This conservative watermark proves the bounded buffer's chronological
    prefix without relying on the size or spacing of IANA clock transitions.
    """
    status, utc0, utc1 = _dst_status(dtstart, zone)
    anchor = _resolve(status, utc0, utc1, "shift_forward")
    shifted_gap = status == "gap"
    if until_utc is not None and until_utc < anchor:
        return ()

    # Keep only the earliest cap instants, retaining the first intended local
    # candidate when two candidates share a UTC identity. An ambiguous future
    # candidate stays unresolved until we know whether it can affect the result.
    pending: dict[datetime, tuple[datetime, str]] = {}
    ambiguity: tuple[datetime, datetime] | None = None
    for candidate in islice(_candidates(dtstart, parsed), _MAX_CANDIDATE_SCANS):
        try:
            watermark = candidate.replace(tzinfo=timezone.utc) - timedelta(days=1)
        except OverflowError:
            watermark = datetime.min.replace(tzinfo=timezone.utc)
        if len(pending) == cap and max(pending) <= watermark:
            break
        if until_utc is not None and until_utc <= watermark:
            break

        status, utc0, utc1 = _dst_status(candidate, zone)
        shifted_gap = shifted_gap or status == "gap"
        if status == "ambiguous":
            if utc1 < anchor or (until_utc is not None and utc0 > until_utc):
                continue
            possible = (max(utc0, anchor), candidate)
            ambiguity = possible if ambiguity is None else min(ambiguity, possible)
            continue
        # Normal and gap cases resolve to utc0 under shift_forward.
        resolved = utc0
        if resolved < anchor:
            continue
        if until_utc is not None and resolved > until_utc:
            if not shifted_gap:
                break
            continue
        pending.setdefault(resolved, (candidate, status))
        if len(pending) > cap:
            del pending[max(pending)]
        # Before any forward-shifted gap, later local candidates cannot precede
        # the retained normal instants. Do not demand unnecessary lookahead
        # beyond a complete ordinary preview (including near the date ceiling).
        if len(pending) == cap and not shifted_gap:
            break
    else:
        _fail("SCAN_LIMIT")

    if ambiguity is not None:
        if len(pending) < cap or ambiguity < (max(pending), pending[max(pending)][0]):
            _fail("DST_POLICY_INAPPLICABLE")

    results: list[Mapping[str, Any]] = []
    for resolved, (candidate, status) in sorted(pending.items()):
        results.append(MappingProxyType({
            "occurrence_at": resolved.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "local_time": candidate.isoformat(),
            "dst_status": status,
        }))
    return tuple(results)


def next_occurrences(
    *, dtstart: str, schedule_timezone: str, rrule: str,
    dst_policy: str = "reject", limit: int = 10,
) -> tuple[Mapping[str, Any], ...]:
    """Preview up to `limit` future occurrences of one validated schedule.

    `dtstart` is a naive local wall-clock timestamp (`YYYY-MM-DDTHH:MM:SS`,
    no offset) interpreted in `schedule_timezone`, matching the contract's
    "local date-time plus zone" dtstart form. Each returned occurrence
    carries its resolved UTC instant, its local wall-clock time, and its DST
    status (`normal`, `ambiguous`, or `gap`). This function computes; it does
    not activate, schedule, claim, or run anything.
    """
    if type(limit) is not int or not 1 <= limit <= MAX_GENERATED_OCCURRENCES:
        _fail("LIMIT_VALUE")
    if dst_policy not in DST_POLICIES:
        _fail("DST_POLICY_VALUE")
    zone = _zone(schedule_timezone)
    dtstart_naive = _local_datetime(dtstart)
    parsed = parse_rrule(rrule)
    _check_generation_support(parsed, dtstart_naive)

    cap = limit if parsed["count"] is None else min(limit, parsed["count"])
    until_utc = (
        datetime.strptime(parsed["until"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        if parsed["until"] is not None else None
    )
    if dst_policy == "shift_forward":
        return _forward_preview(dtstart_naive, parsed, zone, cap, until_utc)

    results: list[Mapping[str, Any]] = []
    for scanned, candidate in enumerate(_candidates(dtstart_naive, parsed)):
        if scanned >= _MAX_CANDIDATE_SCANS or len(results) >= cap:
            break
        status, utc0, utc1 = _dst_status(candidate, zone)
        resolved = _resolve(status, utc0, utc1, dst_policy)
        if resolved is None:
            continue
        if until_utc is not None and resolved > until_utc:
            break
        results.append(MappingProxyType({
            "occurrence_at": resolved.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "local_time": candidate.isoformat(),
            "dst_status": status,
        }))
    return tuple(results)
