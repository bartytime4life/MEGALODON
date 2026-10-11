"""Production Suricata durable-consumer acceptance tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import inspect
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import sqlite3
import subprocess
import sys
import time
from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator

from megalodon.offline import suricata, suricata_consumer
from megalodon.suricata_store import (
    initialize_suricata_store,
    validate_suricata_store,
)


ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
CONSUMER_SCHEMA = json.loads(
    (ROOT / "consumer" / "schema.json").read_text(encoding="utf-8")
)
CONSUMER_VALIDATOR = Draft202012Validator(CONSUMER_SCHEMA)
# Test-owned helper processes only; the autouse fixture denies the consumer.
_TEST_POPEN = subprocess.Popen


def _plain(value):
    if isinstance(value, MappingProxyType):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _publication(tmp_path: Path, *, run_id: str = "fixture-run-a"):
    records = []
    for case in CASES[:2]:
        record = deepcopy(case["input"])
        record["source"]["run_id"] = run_id
        records.append(record)
    source = tmp_path / f"{run_id}.jsonl"
    source.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )
    source.chmod(0o600)
    return suricata.read_completed_file(str(source))


def _store(tmp_path: Path) -> Path:
    path = tmp_path / "store" / "suricata.db"
    initialize_suricata_store(path)
    return path


def _counts(path: Path) -> tuple[int, int, int]:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("consumer_runs", "consumer_alerts", "consumer_receipts")
        )
    finally:
        connection.close()


def _assert_contract(receipt) -> None:
    CONSUMER_VALIDATOR.validate(_plain(receipt))


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("consumer must not use network or subprocesses")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)


def test_one_publication_commits_atomically_and_reads_back_exactly(tmp_path):
    publication = _publication(tmp_path)
    path = _store(tmp_path)

    receipt = suricata_consumer.consume_publication(
        path,
        publication,
        consumer_attempt_id="runtime-attempt-a",
    )

    assert receipt["status"] == "committed"
    assert receipt["transaction_status"] == "committed"
    assert receipt["durable_write_status"] == "committed"
    assert receipt["action_status"] == "not_attempted"
    _assert_contract(receipt)
    assert _counts(path) == (1, 2, 1)
    assert validate_suricata_store(path)["status"] == "compatible"
    with pytest.raises(TypeError):
        receipt["status"] = "failed"

    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        stored = connection.execute(
            "SELECT record_json FROM consumer_alerts ORDER BY source_record_index"
        ).fetchall()
        assert [row[0] for row in stored] == [
            json.dumps(_plain(item), sort_keys=True, separators=(",", ":"))
            for item in publication[0]
        ]
        decoded = [json.loads(row[0]) for row in stored]
        combined = "".join(row[0] for row in stored)
        for record in decoded:
            assert set(record["rule"]) == {"gid", "signature_id", "rev", "severity"}
            assert "signature" not in record["rule"]
            assert "category" not in record["rule"]
        for forbidden in (
            "payload", "packet", "http", "tls", "source_path",
            "content_hash", "exception",
        ):
            assert forbidden not in combined
    finally:
        connection.close()


def _with_addresses(publication, source, destination):
    batch, receipt = _plain(publication)
    total = 0
    for alert in batch:
        alert["src_ip"], alert["dst_ip"] = source, destination
        total += len(json.dumps(alert, sort_keys=True, separators=(",", ":")).encode())
    receipt["normalized_batch_bytes"] = total
    return tuple(_freeze(item) for item in batch), _freeze(receipt)


@pytest.mark.parametrize("source,destination,committed", [
    ("fe80::1%<img>", "fe80::2", False),
    ("fe80::1", "fe80::2%eth0", False),
    ("::ffff:192.0.2.1", "2001:db8::2", True),
    # Written by CPython releases that print IPv4-mapped addresses in hex.
    ("::ffff:c000:201", "2001:db8::2", True),
    ("::ffff:c000:0201", "2001:db8::2", False),
])
def test_addresses_must_be_canonical_without_zone_ids(tmp_path, source, destination, committed):
    path = _store(tmp_path)
    publication = _with_addresses(_publication(tmp_path), source, destination)
    if committed:
        receipt = suricata_consumer.consume_publication(path, publication, consumer_attempt_id="address-attempt")
        assert receipt["status"] == "committed"
    else:
        with pytest.raises(suricata_consumer.ConsumerPreflightError, match="INPUT_CONTRACT$"):
            suricata_consumer.consume_publication(path, publication, consumer_attempt_id="address-attempt")
        assert _counts(path) == (0, 0, 0)


def _reference_validate_timestamp(value):
    """The strptime validator replaced for projection cost, kept verbatim."""
    if type(value) is not str or suricata_consumer._UTC_TIME.fullmatch(value) is None:
        suricata_consumer._fail("INPUT_CONTRACT")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        suricata_consumer._fail("INPUT_CONTRACT")
    if parsed.year < 1970:
        suricata_consumer._fail("INPUT_CONTRACT")


def _outcome(function, value):
    try:
        result = function(value)
    except suricata_consumer.ConsumerPreflightError as error:
        assert error.code == "INPUT_CONTRACT"
        return "refused"
    return ("accepted", result)


def _timestamp_corpus(rng):
    years = (0, 1, 1600, 1900, 1969, 1970, 1971, 1999, 2000, 2023, 2024, 2025,
             2100, 2400, 9996, 9999)
    for year in years:
        for month in range(14):
            for day in range(33):
                yield f"{year:04d}-{month:02d}-{day:02d}T12:34:56.123456Z"
    for hour in range(26):
        for minute in (0, 59, 60, 99):
            for second in (0, 59, 60, 61, 62, 99):
                yield f"2024-02-29T{hour:02d}:{minute:02d}:{second:02d}.000000Z"
    yield from (
        None, 1_700_000_000, b"2024-02-29T00:00:00.000000Z", "",
        "2024-02-29T00:00:00.000000z", "2024-02-29T00:00:00.00000Z",
        "2024-02-29T00:00:00.0000000Z", "2024-02-29 00:00:00.000000Z",
        "2024-02-29T00:00:00.000000+00:00", "2024-02-29T00:00:00Z",
        "\u0662024-02-29T00:00:00.000000Z", "2024-02-29T00:00:00.000000Z\n",
    )
    digits = "0123456789"
    for _ in range(12_000):
        text = "".join(rng.choice(digits) for _ in range(20))
        yield (f"{text[0:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:"
               f"{text[10:12]}:{text[12:14]}.{text[14:20]}Z")
    alphabet = "0123456789-T:.Z +\u0663a"
    for _ in range(6_000):
        value = list(f"{rng.randint(1960, 2500):04d}-{rng.randint(0, 13):02d}-"
                     f"{rng.randint(0, 32):02d}T{rng.randint(0, 25):02d}:"
                     f"{rng.randint(0, 61):02d}:{rng.randint(0, 62):02d}."
                     f"{rng.randint(0, 999_999):06d}Z")
        value[rng.randrange(len(value))] = rng.choice(alphabet)
        yield "".join(value)


def _hextets(rng):
    return [0 if rng.random() < 0.5 else rng.getrandbits(rng.choice((4, 8, 16)))
            for _ in range(8)]


def _ip_corpus(rng):
    yield from (
        None, 7, b"192.0.2.1", "", "1", "::", ":::", "::0", "0::", "::1", "1::",
        "0.0.0.0", "255.255.255.255", "256.0.0.1", "01.2.3.4", "1.2.3", "1.2.3.4.5",
        "1..2.3", "1.2.3.4.", " 1.2.3.4", "\u0661.2.3.4", "::ffff:1.2.3.4",
        "::ffff:01.2.3.4", "::ffff:0.0.0.0", "::ffff:0:0", "::ffff:102:304",
        "::FFFF:102:304", "::ffff:0102:0304", "0:0:0:0:0:ffff:102:304",
        "::1.2.3.4", "64:ff9b::1.2.3.4", "fe80::1%eth0", "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3",
        "1:0:0:2:0:0:0:3", "1::2:0:0:0:3", "1:0:0:2::3", "1:0::2:3:4:5:6",
        "1::2:3:4:5:6:7", "0:0:1::", "::1:0:0", "1:0:0:1:0:0:1:0", "1::1:0:0:1:0",
        "1:0:0:1::1:0", "12345::", "abcd:" * 7 + "abcd", "ABCD::", "g::",
    )
    for _ in range(8_000):
        address = ipaddress.IPv4Address(rng.getrandbits(32))
        octets = str(address).split(".")
        yield str(address)
        yield "::ffff:" + str(address)
        index = rng.randrange(4)
        yield ".".join(octets[:index] + ["0" + octets[index]] + octets[index + 1:])
        yield ".".join(octets[:index] + [str(rng.randint(256, 999))] + octets[index + 1:])
    for _ in range(12_000):
        words = _hextets(rng)
        address = ipaddress.IPv6Address(int("".join(f"{w:04x}" for w in words), 16))
        yield str(address)
        yield address.exploded
        yield str(address).upper()
        yield ":".join(f"{w:x}" for w in words)
        yield ":".join(f"{w:x}" for w in words[:6]) + ":" + str(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
        mapped = (0xFFFF << 32) | (int(address) & 0xFFFFFFFF)
        yield "::ffff:%x:%x" % divmod(mapped & 0xFFFFFFFF, 0x10000)
        yield str(ipaddress.IPv6Address(mapped))
        # Compress a zero run other than the canonical one, or a single zero.
        start = rng.randrange(8)
        length = rng.randint(1, 8 - start)
        head = ":".join(f"{w:x}" for w in words[:start])
        tail = ":".join(f"{w:x}" for w in words[start + length:])
        yield f"{head}::{tail}"
        text = list(str(address))
        text[rng.randrange(len(text))] = rng.choice("0123456789abcdefABCDEF:.%")
        yield "".join(text)


def test_fast_record_validators_match_reference_over_generated_corpus():
    """Projection-speed validators accept and refuse exactly as before."""

    rng = random.Random(20261011)
    timestamps = list(_timestamp_corpus(rng))
    accepted = 0
    for value in timestamps:
        expected = _outcome(_reference_validate_timestamp, value)
        assert _outcome(suricata_consumer._validate_timestamp, value) == expected, value
        accepted += expected != "refused"
    assert len(timestamps) > 25_000 and 5_000 < accepted < len(timestamps) - 5_000
    for leap, common in (
        ("2024-02-29", "2023-02-29"), ("2000-02-29", "1900-02-29"),
        ("2400-02-29", "2100-02-29"),
    ):
        suricata_consumer._validate_timestamp(f"{leap}T00:00:00.000000Z")
        with pytest.raises(suricata_consumer.ConsumerPreflightError):
            suricata_consumer._validate_timestamp(f"{common}T00:00:00.000000Z")
    for invalid in ("2024-04-31", "2024-06-31", "2024-13-01", "2024-00-10", "1969-12-31"):
        with pytest.raises(suricata_consumer.ConsumerPreflightError):
            suricata_consumer._validate_timestamp(f"{invalid}T00:00:00.000000Z")
    for invalid in ("24:00:00", "23:60:00", "23:59:60"):
        with pytest.raises(suricata_consumer.ConsumerPreflightError):
            suricata_consumer._validate_timestamp(f"2024-01-01T{invalid}.000000Z")

    addresses = list(_ip_corpus(rng))
    accepted = {4: 0, 6: 0}
    for value in addresses:
        expected = _outcome(suricata_consumer._canonical_ip, value)
        if expected != "refused":
            expected = ("accepted", expected[1].version)
            accepted[expected[1]] += 1
        assert _outcome(suricata_consumer._canonical_ip_version, value) == expected, value
    assert len(addresses) > 100_000
    assert accepted[4] > 5_000 and accepted[6] > 20_000
    assert len(addresses) - sum(accepted.values()) > 20_000


def test_replay_and_attempt_collision_write_no_new_rows(tmp_path):
    path = _store(tmp_path)
    first = _publication(tmp_path, run_id="fixture-run-a")
    second = _publication(tmp_path, run_id="fixture-run-b")
    committed = suricata_consumer.consume_publication(
        path, first, consumer_attempt_id="shared-attempt"
    )
    assert committed["status"] == "committed"

    replay = suricata_consumer.consume_publication(
        path, first, consumer_attempt_id="different-attempt"
    )
    assert replay["status"] == "rejected"
    assert replay["failure_code"] == "REPLAY"
    assert replay["transaction_status"] == "not_started"

    collision = suricata_consumer.consume_publication(
        path, second, consumer_attempt_id="shared-attempt"
    )
    assert collision["status"] == "failed"
    assert collision["failure_code"] == "DATABASE_IDENTITY"
    assert collision["transaction_status"] == "not_started"
    assert _counts(path) == (1, 2, 1)


def test_precommit_deadline_failure_rolls_back_every_row(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    calls = 0

    def bounded(_started):
        nonlocal calls
        calls += 1
        if calls >= 4:
            raise suricata_consumer._TransactionTimeout
        return 30_000

    monkeypatch.setattr(suricata_consumer, "_remaining_milliseconds", bounded)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="deadline-attempt"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "TRANSACTION_TIMEOUT"
    assert receipt["transaction_status"] == "rolled_back"
    assert receipt["durable_write_status"] == "rolled_back"
    assert _counts(path) == (0, 0, 0)


def test_sqlite_progress_interrupt_is_timeout_and_leaves_store_usable(
    tmp_path, monkeypatch
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        for index in range(500):
            cursor = connection.execute(
                """INSERT INTO consumer_runs (
                       engine, adapter_profile, declared_version, version_basis,
                       sensor_id, run_id, ruleset_id, ruleset_basis,
                       consumer_attempt_id
                   ) VALUES ('suricata', 'suricata-eve-alert-v1', '8.0.1',
                             'operator_declared', 'fixture-sensor', ?,
                             'synthetic-rules-v1', 'operator_declared', ?)""",
                (f"prior-run-{index}", f"prior-attempt-{index}"),
            )
            connection.execute(
                "INSERT INTO consumer_alerts VALUES (?, 1, '{}')",
                (cursor.lastrowid,),
            )
            connection.execute(
                "INSERT INTO consumer_receipts VALUES (?, ?, '{}')",
                (cursor.lastrowid, f"prior-attempt-{index}"),
            )
        connection.commit()
    finally:
        connection.close()
    before = _counts(path)

    clock_calls = 0

    def expired_clock():
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 31.0

    progress_calls = 0
    real_progress = suricata_consumer._deadline_progress

    def observed_progress(started):
        nonlocal progress_calls
        progress_calls += 1
        return real_progress(started)

    monkeypatch.setattr(suricata_consumer.time, "monotonic", expired_clock)
    monkeypatch.setattr(suricata_consumer, "_deadline_progress", observed_progress)

    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="progress-timeout"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "TRANSACTION_TIMEOUT"
    assert receipt["transaction_status"] == "not_started"
    assert progress_calls >= 1
    assert _counts(path) == before
    assert validate_suricata_store(path)["status"] == "compatible"


def test_lost_commit_acknowledgement_requires_reconciliation(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)

    def lose_acknowledgement(connection):
        connection.commit()
        raise sqlite3.OperationalError("synthetic acknowledgement loss")

    monkeypatch.setattr(suricata_consumer, "_commit", lose_acknowledgement)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unknown-attempt"
    )

    assert receipt["status"] == "reconciliation_required"
    assert receipt["failure_code"] == "COMMIT_UNKNOWN"
    assert receipt["transaction_status"] == "unknown"
    assert receipt["reconciliation_status"] == "required"
    assert _counts(path) == (1, 2, 1)


def test_commit_failure_with_active_transaction_is_proven_rolled_back(
    tmp_path, monkeypatch
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)

    def fail_before_commit(connection):
        assert connection.in_transaction is True
        raise sqlite3.OperationalError("synthetic lock failure")

    monkeypatch.setattr(suricata_consumer, "_commit", fail_before_commit)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="rolled-back-commit"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "STORAGE_ERROR"
    assert receipt["transaction_status"] == "rolled_back"
    assert receipt["durable_write_status"] == "rolled_back"
    assert receipt["reconciliation_status"] == "not_required"
    _assert_contract(receipt)
    assert _counts(path) == (0, 0, 0)


def test_each_possible_lock_wait_rebinds_the_remaining_budget(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    observed = []
    real_set_timeout = suricata_consumer._set_remaining_busy_timeout

    def record_stage(connection, started):
        result = real_set_timeout(connection, started)
        observed.append((connection.in_transaction, result))
        return result

    monkeypatch.setattr(
        suricata_consumer, "_set_remaining_busy_timeout", record_stage
    )
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="deadline-rebind"
    )

    assert receipt["status"] == "committed"
    assert [active for active, _ in observed] == [False, True, False]
    assert all(1 <= milliseconds <= 30_000 for _, milliseconds in observed)


def _hold_write_lock(path: Path, seconds: float):
    """Another process mid-commit: RESERVED lock plus its live rollback journal."""

    holder = _TEST_POPEN(
        [sys.executable, "-c", (
            "import sqlite3, sys, time\n"
            "c = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
            "c.execute('BEGIN IMMEDIATE')\n"
            "c.execute(\"INSERT INTO consumer_runs (engine, adapter_profile, "
            "declared_version, version_basis, sensor_id, run_id, ruleset_id, "
            "ruleset_basis, consumer_attempt_id) VALUES ('suricata', "
            "'suricata-eve-alert-v1', '8.0.1', 'operator_declared', 's', 'r', "
            "'x', 'operator_declared', 'other-writer')\")\n"
            "print('held', flush=True)\n"
            "time.sleep(float(sys.argv[2]))\n"
            "c.execute('ROLLBACK')\n"
        ), str(path), str(seconds)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout.readline() == "held\n"
    assert path.with_name(path.name + "-journal").exists()
    return holder


def test_concurrent_writer_is_waited_out_within_the_budget(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    holder = _hold_write_lock(path, 1.0)
    try:
        started = time.monotonic()
        receipt = suricata_consumer.consume_publication(
            path, publication, consumer_attempt_id="waits-for-writer"
        )
        waited = time.monotonic() - started
    finally:
        assert holder.wait(timeout=30) == 0

    assert receipt["status"] == "committed"
    _assert_contract(receipt)
    assert waited >= 0.5
    assert _counts(path) == (1, 2, 1)


def test_concurrent_writer_outlasting_the_budget_is_a_transient_timeout(
    tmp_path, monkeypatch
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    monkeypatch.setattr(suricata_consumer, "MAX_TRANSACTION_SECONDS", 0.4)
    holder = _hold_write_lock(path, 5.0)
    try:
        started = time.monotonic()
        receipt = suricata_consumer.consume_publication(
            path, publication, consumer_attempt_id="writer-outlasts-budget"
        )
        waited = time.monotonic() - started
    finally:
        holder.kill()
        holder.wait(timeout=30)

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "TRANSACTION_TIMEOUT"
    assert receipt["transaction_status"] == "not_started"
    _assert_contract(receipt)
    assert 0.3 <= waited < 3
    # The killed holder left a hot journal; SQLite rolls it back on next open.
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM consumer_runs").fetchone() == (0,)
    finally:
        connection.close()
    assert _counts(path) == (0, 0, 0)


def test_persistent_wal_store_is_refused_like_projection_and_reconcile(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    finally:
        connection.close()

    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="persistent-wal"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "DATABASE_IDENTITY"
    assert receipt["transaction_status"] == "not_started"
    assert list(path.parent.iterdir()) == [path]
    assert path.read_bytes()[18:20] == b"\x02\x02"


def test_hot_journal_without_a_lock_holder_still_requires_recovery(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    journal = path.with_name(path.name + "-journal")
    journal.write_bytes(b"hot")
    journal.chmod(0o600)

    started = time.monotonic()
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="hot-journal"
    )

    assert time.monotonic() - started < 1
    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "DATABASE_IDENTITY"
    assert journal.read_bytes() == b"hot"


def test_deadline_expiring_before_commit_rolls_back(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    calls = 0
    real_set_timeout = suricata_consumer._set_remaining_busy_timeout

    def expire_at_commit(connection, started):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise suricata_consumer._TransactionTimeout
        return real_set_timeout(connection, started)

    monkeypatch.setattr(
        suricata_consumer, "_set_remaining_busy_timeout", expire_at_commit
    )
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="commit-deadline"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "TRANSACTION_TIMEOUT"
    assert receipt["transaction_status"] == "rolled_back"
    assert receipt["reconciliation_status"] == "not_required"
    _assert_contract(receipt)
    assert _counts(path) == (0, 0, 0)


def test_authoritative_replay_check_after_begin_rolls_back(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    calls = 0

    def concurrent_run(_connection, _identity):
        nonlocal calls
        calls += 1
        return None if calls == 1 else (999, "concurrent-attempt")

    monkeypatch.setattr(suricata_consumer, "_find_run", concurrent_run)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="race-attempt"
    )

    assert receipt["status"] == "rejected"
    assert receipt["failure_code"] == "REPLAY"
    assert receipt["transaction_status"] == "rolled_back"
    assert receipt["durable_write_status"] == "rolled_back"
    _assert_contract(receipt)
    assert _counts(path) == (0, 0, 0)


def test_failed_postcommit_readback_requires_reconciliation(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    monkeypatch.setattr(suricata_consumer, "_readback_matches", lambda *args: False)

    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="readback-attempt"
    )

    assert receipt["status"] == "reconciliation_required"
    assert receipt["failure_code"] == "COMMIT_UNKNOWN"
    assert receipt["transaction_status"] == "unknown"
    _assert_contract(receipt)
    assert _counts(path) == (1, 2, 1)

    retry = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="blind-retry"
    )
    assert retry["status"] == "rejected"
    assert retry["failure_code"] == "REPLAY"
    assert _counts(path) == (1, 2, 1)


def test_missing_store_is_not_created_and_schema_is_not_migrated(tmp_path):
    publication = _publication(tmp_path)
    ambiguous = suricata_consumer.consume_publication(
        Path("relative.db"), publication, consumer_attempt_id="ambiguous-store"
    )
    assert ambiguous["status"] == "failed"
    assert ambiguous["transaction_status"] == "not_started"

    missing = tmp_path / "missing" / "suricata.db"
    refusal = suricata_consumer.consume_publication(
        missing, publication, consumer_attempt_id="missing-store"
    )
    assert refusal["status"] == "failed"
    assert refusal["transaction_status"] == "not_started"
    assert not missing.exists()

    path = _store(tmp_path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version=2")
    connection.commit()
    connection.close()
    before = path.read_bytes()
    incompatible = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="future-schema"
    )
    assert incompatible["status"] == "failed"
    assert incompatible["failure_code"] == "SCHEMA_INCOMPATIBLE"
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode boundary")
def test_public_store_is_refused_without_permission_repair(tmp_path):
    publication = _publication(tmp_path)
    path = _store(tmp_path)
    before = path.read_bytes()
    path.chmod(0o644)

    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="public-store"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "DATABASE_IDENTITY"
    assert receipt["transaction_status"] == "not_started"
    assert receipt["durable_write_status"] == "not_attempted"
    _assert_contract(receipt)
    assert path.stat().st_mode & 0o777 == 0o644
    assert path.read_bytes() == before
    assert _counts(path) == (0, 0, 0)


def test_unsupported_runtime_refuses_before_store_access(tmp_path, monkeypatch):
    publication = _publication(tmp_path)
    path = _store(tmp_path)

    def unsupported():
        raise suricata.OfflineError("LINUX_REQUIRED")

    def opened_store(*args, **kwargs):
        raise AssertionError("unsupported runtime must not open the store")

    monkeypatch.setattr(suricata, "require_unprivileged_linux", unsupported)
    monkeypatch.setattr(
        suricata_consumer, "_open_suricata_store_writer", opened_store
    )
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unsupported-runtime"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "STORAGE_ERROR"
    assert receipt["transaction_status"] == "not_started"
    assert receipt["durable_write_status"] == "not_attempted"
    _assert_contract(receipt)
    assert _counts(path) == (0, 0, 0)


def test_constructed_frozen_garbage_and_mutable_input_fail_before_store(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    garbage = (
        (MappingProxyType({"garbage": "accepted-before-review"}),),
        publication[1],
    )
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path, garbage, consumer_attempt_id="garbage-attempt"
        )
    mutable = ([dict(_plain(publication[0][0]))], dict(_plain(publication[1])))
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path, mutable, consumer_attempt_id="mutable-attempt"
        )
    assert _counts(path) == (0, 0, 0)


def test_boolean_record_index_and_cyclic_proxy_fail_with_fixed_diagnostic(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    malformed = _plain(publication)
    malformed[0][0]["source_record_index"] = True
    malformed[1]["normalized_batch_bytes"] = sum(
        len(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for row in malformed[0]
    )
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path, _freeze(malformed), consumer_attempt_id="boolean-index"
        )

    backing = {}
    cyclic = MappingProxyType(backing)
    backing["cycle"] = cyclic
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path,
            ((cyclic,), MappingProxyType({})),
            consumer_attempt_id="cyclic-input",
        )
    assert _counts(path) == (0, 0, 0)


def test_consumer_owns_validated_snapshot_before_any_store_work(tmp_path, monkeypatch):
    path = _store(tmp_path)
    plain_batch, plain_receipt = _plain(_publication(tmp_path))
    source_backings = []
    frozen_batch = []
    for record in plain_batch:
        source = record["source"]
        rule = record["rule"]
        source_backings.append(source)
        record["source"] = MappingProxyType(source)
        record["rule"] = MappingProxyType(rule)
        frozen_batch.append(MappingProxyType(record))
    receipt_source = plain_receipt["run_identity"]
    source_backings.append(receipt_source)
    plain_receipt["run_identity"] = MappingProxyType(receipt_source)
    publication = (tuple(frozen_batch), MappingProxyType(plain_receipt))

    real_preflight = suricata_consumer.preflight_publication

    def mutate_then_preflight(connection, snapshot, *, database_path):
        for source in source_backings:
            source["run_id"] = "mutated-after-validation"
        return real_preflight(connection, snapshot, database_path=database_path)

    monkeypatch.setattr(
        suricata_consumer, "preflight_publication", mutate_then_preflight,
    )
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="owned-snapshot"
    )

    assert receipt["status"] == "committed"
    assert receipt["run_identity"]["run_id"] == "fixture-run-a"
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        assert connection.execute(
            "SELECT run_id FROM consumer_runs"
        ).fetchone() == ("fixture-run-a",)
        stored_alerts = connection.execute(
            "SELECT record_json FROM consumer_alerts ORDER BY source_record_index"
        ).fetchall()
        assert {
            json.loads(row[0])["source"]["run_id"] for row in stored_alerts
        } == {"fixture-run-a"}
    finally:
        connection.close()


def test_runtime_limits_and_authority_are_not_caller_tunable():
    signature = inspect.signature(suricata_consumer.consume_publication)
    assert tuple(signature.parameters) == (
        "database_path", "publication", "consumer_attempt_id",
    )
    assert suricata_consumer.MAX_TRANSACTION_SECONDS == 30
    source = inspect.getsource(suricata_consumer)
    for forbidden in (
        "shell=True", "subprocess.", "socket.", "requests.", "urllib.",
        "firewall", "qwen", "ollama",
    ):
        assert forbidden not in source.lower()
