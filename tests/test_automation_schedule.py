"""Tests for the bounded RRULE preview engine (issue #84 recurrence gap)."""

from __future__ import annotations

import socket
import subprocess

import pytest

from megalodon.automation_schedule import (
    AutomationScheduleError,
    next_occurrences,
    parse_rrule,
)


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("automation schedule preview must remain inert")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


# --- parse_rrule -----------------------------------------------------------

@pytest.mark.parametrize("rrule", [
    "FREQ=DAILY;INTERVAL=1",
    "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR",
    "FREQ=MONTHLY;BYMONTHDAY=1",
    "FREQ=HOURLY;INTERVAL=6;COUNT=8",
    "FREQ=YEARLY;BYMONTH=1,7;BYMONTHDAY=1",
    "RRULE:FREQ=DAILY;COUNT=3",
])
def test_documented_examples_parse(rrule) -> None:
    parsed = parse_rrule(rrule)
    assert parsed["frequency"] in {"DAILY", "WEEKLY", "MONTHLY", "HOURLY", "YEARLY"}


def test_rrule_prefix_is_accepted_and_dropped() -> None:
    assert parse_rrule("RRULE:FREQ=DAILY;COUNT=3")["rrule"] == "FREQ=DAILY;COUNT=3"


def test_canonical_output_is_idempotent() -> None:
    parsed = parse_rrule("FREQ=WEEKLY;BYDAY=FR,MO;INTERVAL=2")
    reparsed = parse_rrule(parsed["rrule"])
    assert reparsed["rrule"] == parsed["rrule"]
    assert reparsed["by_day"] == ("MO", "FR")


@pytest.mark.parametrize(("rrule", "code"), [
    ("FREQ=SECONDLY;INTERVAL=1", "PATTERN"),
    ("not-a-rule-at-all", "PATTERN"),
    ("FREQ=DAILY;COUNT=5;UNTIL=20260908T000000Z", "COUNT_AND_UNTIL"),
    ("FREQ=DAILY;BYSETPOS=1", "UNKNOWN_PART"),
    ("FREQ=DAILY;INTERVAL=1;INTERVAL=2", "DUPLICATE_PART"),
    ("FREQ=DAILY;INTERVAL=99999", "INTERVAL_BOUND"),
    ("FREQ=DAILY;COUNT=999999", "COUNT_BOUND"),
    ("FREQ=DAILY;UNTIL=2026-09-08", "UNTIL_VALUE"),
    ("FREQ=DAILY;UNTIL=20261332T000000Z", "UNTIL_VALUE"),
    ("FREQ=WEEKLY;BYDAY=XX", "BYDAY_VALUE"),
    ("FREQ=MONTHLY;BYMONTHDAY=32", "BYMONTHDAY_VALUE"),
    ("FREQ=YEARLY;BYMONTH=13", "BYMONTH_VALUE"),
    ("FREQ=DAILY;BYHOUR=24", "BYHOUR_VALUE"),
    ("FREQ=DAILY;BYHOUR=1,2", "BYHOUR_VALUE"),
    ("FREQ=DAILY;BYMINUTE=60", "BYMINUTE_VALUE"),
    ("FREQ=WEEKLY;WKST=ZZ", "WKST_VALUE"),
    ("FREQ=MINUTELY;INTERVAL=1", "UNBOUNDED_HIGH_FREQUENCY"),
    ("FREQ=HOURLY;INTERVAL=1", "UNBOUNDED_HIGH_FREQUENCY"),
])
def test_rejected_rrules_fail_with_the_named_code(rrule, code) -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        parse_rrule(rrule)
    assert caught.value.code == code


# --- next_occurrences: documented examples ---------------------------------

def test_daily_interval_one() -> None:
    occ = next_occurrences(
        dtstart="2026-09-21T09:00:00", schedule_timezone="UTC",
        rrule="FREQ=DAILY;INTERVAL=1", limit=3,
    )
    assert [o["occurrence_at"] for o in occ] == [
        "2026-09-21T09:00:00Z", "2026-09-22T09:00:00Z", "2026-09-23T09:00:00Z",
    ]


def test_weekly_byday_skips_weekends_and_orders_first_week_correctly() -> None:
    # 2026-09-21 is a Monday.
    occ = next_occurrences(
        dtstart="2026-09-21T09:00:00", schedule_timezone="UTC",
        rrule="FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR", limit=6,
    )
    dates = [o["occurrence_at"][:10] for o in occ]
    assert dates == [
        "2026-09-21", "2026-09-22", "2026-09-23",
        "2026-09-24", "2026-09-25", "2026-09-28",
    ]


def test_weekly_byday_excludes_days_before_dtstart_in_first_week() -> None:
    # 2026-09-23 is a Wednesday; Monday/Tuesday of that week must not appear.
    occ = next_occurrences(
        dtstart="2026-09-23T09:00:00", schedule_timezone="UTC",
        rrule="FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR", limit=3,
    )
    dates = [o["occurrence_at"][:10] for o in occ]
    assert dates == ["2026-09-23", "2026-09-24", "2026-09-25"]


def test_monthly_bymonthday_one() -> None:
    occ = next_occurrences(
        dtstart="2026-01-01T08:00:00", schedule_timezone="UTC",
        rrule="FREQ=MONTHLY;BYMONTHDAY=1", limit=3,
    )
    assert [o["occurrence_at"] for o in occ] == [
        "2026-01-01T08:00:00Z", "2026-02-01T08:00:00Z", "2026-03-01T08:00:00Z",
    ]


def test_monthly_without_bymonthday_skips_short_months() -> None:
    occ = next_occurrences(
        dtstart="2026-01-31T09:00:00", schedule_timezone="UTC",
        rrule="FREQ=MONTHLY", limit=6,
    )
    months = [o["occurrence_at"][:7] for o in occ]
    assert months == ["2026-01", "2026-03", "2026-05", "2026-07", "2026-08", "2026-10"]


def test_hourly_interval_and_count() -> None:
    occ = next_occurrences(
        dtstart="2026-09-21T00:00:00", schedule_timezone="UTC",
        rrule="FREQ=HOURLY;INTERVAL=6;COUNT=8", limit=100,
    )
    assert len(occ) == 8
    assert occ[1]["occurrence_at"] == "2026-09-21T06:00:00Z"


def test_yearly_bymonth_and_bymonthday() -> None:
    occ = next_occurrences(
        dtstart="2026-01-01T00:00:00", schedule_timezone="UTC",
        rrule="FREQ=YEARLY;BYMONTH=1,7;BYMONTHDAY=1", limit=4,
    )
    assert [o["occurrence_at"][:10] for o in occ] == [
        "2026-01-01", "2026-07-01", "2027-01-01", "2027-07-01",
    ]


def test_count_and_until_both_bound_the_result() -> None:
    occ = next_occurrences(
        dtstart="2026-09-21T00:00:00", schedule_timezone="UTC",
        rrule="FREQ=DAILY;UNTIL=20260923T000000Z", limit=100,
    )
    assert [o["occurrence_at"][:10] for o in occ] == ["2026-09-21", "2026-09-22", "2026-09-23"]


def test_generated_occurrences_are_deterministic() -> None:
    kwargs = dict(
        dtstart="2026-09-21T09:00:00", schedule_timezone="UTC",
        rrule="FREQ=WEEKLY;BYDAY=MO,WE,FR", limit=10,
    )
    assert next_occurrences(**kwargs) == next_occurrences(**kwargs)


# --- DST handling (America/Chicago 2027 transitions) -----------------------

def test_dst_gap_rejects_by_default() -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2027-03-14T02:30:00", schedule_timezone="America/Chicago",
            rrule="FREQ=DAILY;COUNT=1",
        )
    assert caught.value.code == "DST_UNRESOLVED"


def test_dst_gap_skip_omits_the_nonexistent_occurrence() -> None:
    occ = next_occurrences(
        dtstart="2027-03-13T02:30:00", schedule_timezone="America/Chicago",
        rrule="FREQ=DAILY;COUNT=3", dst_policy="skip", limit=3,
    )
    assert [o["local_time"][:10] for o in occ] == ["2027-03-13", "2027-03-15", "2027-03-16"]
    assert all(o["dst_status"] == "normal" for o in occ)


def test_dst_gap_shift_forward_keeps_the_occurrence() -> None:
    occ = next_occurrences(
        dtstart="2027-03-13T02:30:00", schedule_timezone="America/Chicago",
        rrule="FREQ=DAILY;COUNT=3", dst_policy="shift_forward", limit=3,
    )
    assert [o["local_time"][:10] for o in occ] == ["2027-03-13", "2027-03-14", "2027-03-15"]
    gapped = occ[1]
    assert gapped["dst_status"] == "gap"
    assert gapped["occurrence_at"] == "2027-03-14T07:30:00Z"


def test_dst_gap_fold_policies_are_inapplicable() -> None:
    for policy in ("fold_earlier", "fold_later"):
        with pytest.raises(AutomationScheduleError) as caught:
            next_occurrences(
                dtstart="2027-03-14T02:30:00", schedule_timezone="America/Chicago",
                rrule="FREQ=DAILY;COUNT=1", dst_policy=policy,
            )
        assert caught.value.code == "DST_POLICY_INAPPLICABLE"


def test_dst_ambiguous_fold_earlier_vs_fold_later() -> None:
    earlier = next_occurrences(
        dtstart="2027-11-07T01:30:00", schedule_timezone="America/Chicago",
        rrule="FREQ=DAILY;COUNT=1", dst_policy="fold_earlier",
    )
    later = next_occurrences(
        dtstart="2027-11-07T01:30:00", schedule_timezone="America/Chicago",
        rrule="FREQ=DAILY;COUNT=1", dst_policy="fold_later",
    )
    assert earlier[0]["dst_status"] == later[0]["dst_status"] == "ambiguous"
    assert earlier[0]["occurrence_at"] == "2027-11-07T06:30:00Z"
    assert later[0]["occurrence_at"] == "2027-11-07T07:30:00Z"
    assert earlier[0]["occurrence_at"] != later[0]["occurrence_at"]


def test_dst_ambiguous_shift_forward_is_inapplicable() -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2027-11-07T01:30:00", schedule_timezone="America/Chicago",
            rrule="FREQ=DAILY;COUNT=1", dst_policy="shift_forward",
        )
    assert caught.value.code == "DST_POLICY_INAPPLICABLE"


def test_utc_zone_never_reports_dst_status_other_than_normal() -> None:
    occ = next_occurrences(
        dtstart="2027-03-14T02:30:00", schedule_timezone="UTC",
        rrule="FREQ=DAILY;COUNT=3",
    )
    assert all(o["dst_status"] == "normal" for o in occ)


# --- input boundaries and unsupported combinations --------------------------

def test_unsupported_combinations_fail_closed_instead_of_guessing() -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2026-01-01T00:00:00", schedule_timezone="UTC",
            rrule="FREQ=HOURLY;INTERVAL=1;COUNT=2;BYHOUR=5",
        )
    assert caught.value.code == "UNSUPPORTED_COMBINATION"


def test_dtstart_must_satisfy_its_own_byday_filter() -> None:
    # 2026-01-01 is a Thursday; BYDAY=TU excludes it.
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2026-01-01T00:00:00", schedule_timezone="UTC",
            rrule="FREQ=WEEKLY;BYDAY=TU",
        )
    assert caught.value.code == "DTSTART_VALUE"


def test_invalid_timezone_name_fails_closed() -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2026-01-01T00:00:00", schedule_timezone="Not/AZone",
            rrule="FREQ=DAILY;COUNT=1",
        )
    assert caught.value.code == "TIMEZONE_VALUE"


def test_dtstart_with_offset_is_rejected() -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2026-01-01T00:00:00Z", schedule_timezone="UTC",
            rrule="FREQ=DAILY;COUNT=1",
        )
    assert caught.value.code == "DTSTART_VALUE"


@pytest.mark.parametrize("limit", [0, -1, 367, "10"])
def test_limit_must_be_a_bounded_int(limit) -> None:
    with pytest.raises(AutomationScheduleError) as caught:
        next_occurrences(
            dtstart="2026-01-01T00:00:00", schedule_timezone="UTC",
            rrule="FREQ=DAILY;COUNT=1", limit=limit,
        )
    assert caught.value.code == "LIMIT_VALUE"


def test_engine_grants_no_activation_or_execution_authority() -> None:
    import megalodon.automation_schedule as module

    forbidden = ("activate", "schedule_job", "execute", "run", "claim", "notify", "model", "worker")
    public_names = [name for name in dir(module) if not name.startswith("_")]
    for name in public_names:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden), name
