"""Synthetic durable-consumer oracle; not a production database layer."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import socket
import sqlite3
import subprocess

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry
from referencing.exceptions import NoSuchResource


ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
CONSUMER_ROOT = ROOT / "consumer"
READER_ROOT = ROOT / "reader"
RECORD_SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
READER_SCHEMA = json.loads((READER_ROOT / "schema.json").read_text(encoding="utf-8"))
CONSUMER_SCHEMA = json.loads((CONSUMER_ROOT / "schema.json").read_text(encoding="utf-8"))
RECORD_CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
READER_ACCEPTED = json.loads(
    (READER_ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8")
)
ACCEPTED = json.loads(
    (CONSUMER_ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8")
)
REJECTED = json.loads(
    (CONSUMER_ROOT / "fixtures" / "rejected.json").read_text(encoding="utf-8")
)

LIMITS = ACCEPTED["policy"]["limits"]
MAX_RECORDS = LIMITS["max_records"]
MAX_OUTPUT_BYTES = LIMITS["max_normalized_batch_bytes"]
MAX_ELAPSED_MS = LIMITS["max_transaction_and_readback_ms"]
MAX_DIAGNOSTIC_BYTES = LIMITS["max_diagnostic_bytes"]
ERROR_CODES = frozenset(CONSUMER_SCHEMA["$defs"]["errorCode"]["enum"])
EXPECTED_ERROR_CODES = frozenset({
    "INPUT_CONTRACT", "COUNT_MISMATCH", "BATCH_BYTES", "REPLAY",
    "DATABASE_IDENTITY", "SCHEMA_INCOMPATIBLE", "STORAGE_CAPACITY",
    "TRANSACTION_TIMEOUT", "STORAGE_ERROR", "COMMIT_UNKNOWN",
    "RECONCILIATION_REQUIRED",
})
RUN_KEYS = (
    "engine", "adapter_profile", "declared_version", "version_basis",
    "sensor_id", "run_id", "ruleset_id", "ruleset_basis",
)


class ConsumerError(ValueError):
    """Fixed diagnostic only: never include data, paths, SQL or exceptions."""

    def __init__(self, code: str):
        assert code in ERROR_CODES
        super().__init__(f"SURICATA_CONSUMER_V1:{code}")


def _fail(code: str):
    raise ConsumerError(code)


def _no_retrieval(uri: str):
    raise NoSuchResource(ref=uri)


CHECKER = FormatChecker(formats=["ipv4", "ipv6"])


@CHECKER.checks("date-time", raises=(ValueError, OverflowError))
def _calendar_time(value):
    if not isinstance(value, str):
        return True
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


LOCAL_REGISTRY = Registry(retrieve=_no_retrieval)
ALERT_VALIDATOR = Draft202012Validator(
    {"$ref": "#/$defs/externalAlert", "$defs": RECORD_SCHEMA["$defs"]},
    format_checker=CHECKER,
    registry=LOCAL_REGISTRY,
)
READER_RECEIPT_VALIDATOR = Draft202012Validator(
    {"$ref": "#/$defs/completedRunReceipt", "$defs": READER_SCHEMA["$defs"]},
    registry=LOCAL_REGISTRY,
)
CONSUMER_VALIDATOR = Draft202012Validator(
    CONSUMER_SCHEMA, registry=LOCAL_REGISTRY
)


def _run_key(identity):
    return tuple(identity[key] for key in RUN_KEYS)


def _normalized_bytes(batch):
    return sum(len(json.dumps(
        item, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")) for item in batch)


def _validate_contract_value(value):
    if not CONSUMER_VALIDATOR.is_valid(value):
        _fail("INPUT_CONTRACT")


def _validate_publication(batch, reader_receipt):
    if (
        not isinstance(batch, (tuple, list))
        or not batch
        or len(batch) > MAX_RECORDS
        or not READER_RECEIPT_VALIDATOR.is_valid(reader_receipt)
    ):
        _fail("INPUT_CONTRACT")

    identity = reader_receipt["run_identity"]
    for expected_index, alert in enumerate(batch, start=1):
        if not ALERT_VALIDATOR.is_valid(alert):
            _fail("INPUT_CONTRACT")
        if alert["source_record_index"] != expected_index:
            _fail("INPUT_CONTRACT")
        if alert["source"] != identity:
            _fail("INPUT_CONTRACT")
        if alert["action_status"] != "not_attempted":
            _fail("INPUT_CONTRACT")

    record_count = len(batch)
    blocked_count = sum(
        item["producer_reported_action"] == "blocked" for item in batch
    )
    if (
        reader_receipt["record_count"] != record_count
        or reader_receipt["normalized_alert_count"] != record_count
        or reader_receipt["producer_blocked_count"] != blocked_count
    ):
        _fail("COUNT_MISMATCH")

    output_bytes = _normalized_bytes(batch)
    if output_bytes > MAX_OUTPUT_BYTES:
        _fail("BATCH_BYTES")
    if reader_receipt["normalized_batch_bytes"] != output_bytes:
        _fail("BATCH_BYTES")
    if (
        reader_receipt["action_status"] != "not_attempted"
        or reader_receipt["durable_write_status"] != "not_attempted"
    ):
        _fail("INPUT_CONTRACT")
    return identity, record_count, blocked_count, output_bytes


def _validate_consumer_receipt(receipt, batch):
    _validate_contract_value(receipt)
    if (
        receipt["record_count"] != len(batch)
        or receipt["normalized_alert_count"] != len(batch)
        or receipt["producer_blocked_count"]
        != sum(item["producer_reported_action"] == "blocked" for item in batch)
    ):
        _fail("COUNT_MISMATCH")
    if receipt["normalized_batch_bytes"] != _normalized_bytes(batch):
        _fail("BATCH_BYTES")


def _new_database():
    database = sqlite3.connect(":memory:", isolation_level=None)
    database.execute("PRAGMA foreign_keys = ON")
    database.executescript("""
        CREATE TABLE consumer_runs (
            id INTEGER PRIMARY KEY,
            engine TEXT NOT NULL,
            adapter_profile TEXT NOT NULL,
            declared_version TEXT NOT NULL,
            version_basis TEXT NOT NULL,
            sensor_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            ruleset_id TEXT NOT NULL,
            ruleset_basis TEXT NOT NULL,
            consumer_attempt_id TEXT NOT NULL UNIQUE,
            UNIQUE (
                engine, adapter_profile, declared_version, version_basis,
                sensor_id, run_id, ruleset_id, ruleset_basis
            )
        );
        CREATE TABLE consumer_alerts (
            run_row_id INTEGER NOT NULL REFERENCES consumer_runs(id),
            source_record_index INTEGER NOT NULL,
            normalized_alert_json TEXT NOT NULL,
            PRIMARY KEY (run_row_id, source_record_index)
        );
        CREATE TABLE consumer_receipts (
            run_row_id INTEGER PRIMARY KEY REFERENCES consumer_runs(id),
            consumer_attempt_id TEXT NOT NULL UNIQUE,
            receipt_json TEXT NOT NULL
        );
    """)
    return database


def _receipt(attempt_id, identity, count, blocked, output_bytes, status):
    states = {
        "committed": (
            "committed", "recorded", "committed", "not_required", None,
        ),
        "rejected": (
            "not_attempted", "duplicate", "not_started", "not_required", "REPLAY",
        ),
        "failed": (
            "rolled_back", "not_recorded", "rolled_back", "not_required",
            "STORAGE_ERROR",
        ),
        "reconciliation_required": (
            "unknown", "unknown", "unknown", "required", "COMMIT_UNKNOWN",
        ),
    }
    durable, replay, transaction, reconciliation, failure = states[status]
    value = {
        "schema_version": "suricata-eve-consumer-receipt-v1",
        "consumer_policy_version": "suricata-eve-consumer-policy-v1",
        "reader_receipt_version": "suricata-eve-reader-receipt-v1",
        "consumer_attempt_id": attempt_id,
        "status": status,
        "run_identity": deepcopy(identity),
        "record_count": count,
        "normalized_alert_count": count,
        "producer_blocked_count": blocked,
        "normalized_batch_bytes": output_bytes,
        "count_unit": "alert",
        "action_status": "not_attempted",
        "durable_write_status": durable,
        "replay_status": replay,
        "transaction_status": transaction,
        "reconciliation_status": reconciliation,
        "failure_code": failure,
    }
    _validate_contract_value(value)
    return value


def _find_run(database, identity):
    return database.execute(
        """SELECT id, consumer_attempt_id FROM consumer_runs
           WHERE engine=? AND adapter_profile=? AND declared_version=?
             AND version_basis=? AND sensor_id=? AND run_id=?
             AND ruleset_id=? AND ruleset_basis=?""",
        _run_key(identity),
    ).fetchone()


def _consume(database, batch, reader_receipt, *, attempt_id,
             fail_before_commit=False, lose_commit_acknowledgement=False,
             elapsed_ms=0):
    identity, count, blocked, output_bytes = _validate_publication(
        batch, reader_receipt
    )
    if elapsed_ms > MAX_ELAPSED_MS:
        _fail("TRANSACTION_TIMEOUT")

    if _find_run(database, identity) is not None:
        return _receipt(
            attempt_id, identity, count, blocked, output_bytes, "rejected"
        )

    committed = _receipt(
        attempt_id, identity, count, blocked, output_bytes, "committed"
    )
    try:
        database.execute("BEGIN IMMEDIATE")
        cursor = database.execute(
            """INSERT INTO consumer_runs (
                   engine, adapter_profile, declared_version, version_basis,
                   sensor_id, run_id, ruleset_id, ruleset_basis,
                   consumer_attempt_id
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (*_run_key(identity), attempt_id),
        )
        row_id = cursor.lastrowid
        for alert in batch:
            database.execute(
                """INSERT INTO consumer_alerts (
                       run_row_id, source_record_index, normalized_alert_json
                   ) VALUES (?, ?, ?)""",
                (
                    row_id,
                    alert["source_record_index"],
                    json.dumps(alert, sort_keys=True, separators=(",", ":")),
                ),
            )
        if fail_before_commit:
            raise sqlite3.OperationalError("synthetic pre-commit failure")
        database.execute(
            """INSERT INTO consumer_receipts (
                   run_row_id, consumer_attempt_id, receipt_json
               ) VALUES (?, ?, ?)""",
            (
                row_id,
                attempt_id,
                json.dumps(committed, sort_keys=True, separators=(",", ":")),
            ),
        )
        database.commit()
    except sqlite3.IntegrityError:
        database.rollback()
        return _receipt(
            attempt_id, identity, count, blocked, output_bytes, "rejected"
        )
    except sqlite3.DatabaseError:
        database.rollback()
        return _receipt(
            attempt_id, identity, count, blocked, output_bytes, "failed"
        )

    if lose_commit_acknowledgement:
        return _receipt(
            attempt_id, identity, count, blocked, output_bytes,
            "reconciliation_required",
        )
    return _reconcile(database, identity, attempt_id)


def _reconcile(database, identity, attempt_id):
    row = _find_run(database, identity)
    if row is None or row[1] != attempt_id:
        _fail("RECONCILIATION_REQUIRED")
    stored = database.execute(
        """SELECT receipt_json FROM consumer_receipts
           WHERE run_row_id=? AND consumer_attempt_id=?""",
        (row[0], attempt_id),
    ).fetchone()
    if stored is None:
        _fail("RECONCILIATION_REQUIRED")
    receipt = json.loads(stored[0])
    alert_count = database.execute(
        "SELECT COUNT(*) FROM consumer_alerts WHERE run_row_id=?", (row[0],)
    ).fetchone()[0]
    if alert_count != receipt["record_count"]:
        _fail("RECONCILIATION_REQUIRED")
    _validate_contract_value(receipt)
    return receipt


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Consumer contract tests must not use network or processes")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


@pytest.fixture
def publication():
    batch = tuple(deepcopy(case["normalized"]) for case in RECORD_CASES[:2])
    receipt = deepcopy(READER_ACCEPTED["receipts"][0]["receipt"])
    return batch, receipt


def test_schema_fixture_inventory_and_local_resolution():
    Draft202012Validator.check_schema(CONSUMER_SCHEMA)
    assert ACCEPTED["receipts"] and REJECTED
    assert len({case["id"] for case in ACCEPTED["receipts"]}) == len(
        ACCEPTED["receipts"]
    )
    assert len({case["id"] for case in REJECTED}) == len(REJECTED)

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node:
                assert node["$ref"].startswith("#/$defs/")
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(CONSUMER_SCHEMA)
    assert ERROR_CODES == EXPECTED_ERROR_CODES
    assert len(ERROR_CODES) == len(CONSUMER_SCHEMA["$defs"]["errorCode"]["enum"])


def test_policy_is_exact_transactional_and_not_runtime():
    policy = ACCEPTED["policy"]
    _validate_contract_value(policy)
    assert policy["status"] == "proposed_contract_only"
    assert policy["runtime_implemented"] is False
    assert policy["limits"] == {
        "max_records": 10000,
        "max_normalized_batch_bytes": 16777216,
        "max_transaction_and_readback_ms": 30000,
        "max_diagnostic_bytes": 64,
    }
    assert policy["transaction"] == {
        "database": "sqlite",
        "begin_mode": "immediate",
        "single_writer": True,
        "atomic_batch_registry_receipt": True,
        "complete_run_identity_unique": True,
        "commit_readback_required": True,
        "unknown_commit_requires_reconciliation": True,
        "blind_retry_after_unknown": False,
        "capacity_check_before_begin": True,
        "ordinary_startup_migration": False,
        "runtime_schema_migration_included": False,
    }
    assert policy["data"] == {
        "retain_normalized_alerts": True,
        "retain_original_eve_json": False,
        "retain_source_path": False,
        "retain_payload": False,
        "retain_payload_derived_hash": False,
        "retain_rule_labels": False,
        "retain_low_level_exception_text": False,
    }
    assert policy["side_effects"] == {
        "durable_local_write": True,
        "network_access": False,
        "process_launch": False,
        "sensor_control": False,
        "dashboard_projection": False,
        "action_execution": False,
        "firewall_mutation": False,
    }


@pytest.mark.parametrize("case", ACCEPTED["receipts"], ids=lambda c: c["id"])
def test_accepted_consumer_receipts(case, publication):
    batch, _ = publication
    _validate_consumer_receipt(case["receipt"], batch)


@pytest.mark.parametrize("case", REJECTED, ids=lambda c: c["id"])
def test_rejected_contract_mutations(case, publication):
    batch, _ = publication
    seeds = {"policy": ACCEPTED["policy"]}
    seeds.update({item["id"]: item["receipt"] for item in ACCEPTED["receipts"]})
    value = deepcopy(seeds[case["seed"]])
    parent = value
    for part in case["path"][:-1]:
        parent = parent[part]
    assert case["operation"] in {"set", "add"}
    parent[case["path"][-1]] = case["value"]
    if case["stage"] == "semantic":
        _validate_contract_value(value)
    with pytest.raises(ConsumerError) as caught:
        if case["seed"] == "policy":
            _validate_contract_value(value)
        else:
            _validate_consumer_receipt(value, batch)
    assert str(caught.value) == f"SURICATA_CONSUMER_V1:{case['code']}"


def test_two_record_publication_commits_once_and_matches_fixture(publication):
    batch, reader_receipt = publication
    database = _new_database()
    actual = _consume(
        database, batch, reader_receipt,
        attempt_id="fixture-attempt-committed",
    )
    assert actual == ACCEPTED["receipts"][0]["receipt"]
    assert database.execute("SELECT COUNT(*) FROM consumer_runs").fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM consumer_alerts").fetchone()[0] == 2
    assert database.execute("SELECT COUNT(*) FROM consumer_receipts").fetchone()[0] == 1

    replay = _consume(
        database, batch, reader_receipt,
        attempt_id="fixture-attempt-replay",
    )
    assert replay == ACCEPTED["receipts"][1]["receipt"]
    assert database.execute("SELECT COUNT(*) FROM consumer_alerts").fetchone()[0] == 2


def test_precommit_failure_rolls_back_registry_alerts_and_receipt(publication):
    batch, reader_receipt = publication
    database = _new_database()
    actual = _consume(
        database, batch, reader_receipt,
        attempt_id="fixture-attempt-rolled-back",
        fail_before_commit=True,
    )
    assert actual == ACCEPTED["receipts"][2]["receipt"]
    for table in ("consumer_runs", "consumer_alerts", "consumer_receipts"):
        assert database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_unknown_commit_requires_exact_reconciliation_before_success(publication):
    batch, reader_receipt = publication
    database = _new_database()
    unknown = _consume(
        database, batch, reader_receipt,
        attempt_id="fixture-attempt-unknown",
        lose_commit_acknowledgement=True,
    )
    assert unknown == ACCEPTED["receipts"][3]["receipt"]

    blind_retry = _consume(
        database, batch, reader_receipt,
        attempt_id="blind-retry-forbidden",
    )
    assert blind_retry["status"] == "rejected"
    assert blind_retry["failure_code"] == "REPLAY"
    with pytest.raises(ConsumerError, match="RECONCILIATION_REQUIRED$"):
        _reconcile(database, reader_receipt["run_identity"], "wrong-attempt")

    reconciled = _reconcile(
        database, reader_receipt["run_identity"], "fixture-attempt-unknown"
    )
    expected = deepcopy(ACCEPTED["receipts"][0]["receipt"])
    expected["consumer_attempt_id"] = "fixture-attempt-unknown"
    assert reconciled == expected


def test_publication_counts_identity_sequence_and_bytes_are_recomputed(publication):
    batch, reader_receipt = publication

    changed = deepcopy(reader_receipt)
    changed["record_count"] = 1
    with pytest.raises(ConsumerError, match="COUNT_MISMATCH$"):
        _validate_publication(batch, changed)

    changed = deepcopy(reader_receipt)
    changed["normalized_batch_bytes"] -= 1
    with pytest.raises(ConsumerError, match="BATCH_BYTES$"):
        _validate_publication(batch, changed)

    changed_batch = list(deepcopy(batch))
    changed_batch[1]["source_record_index"] = 3
    with pytest.raises(ConsumerError, match="INPUT_CONTRACT$"):
        _validate_publication(changed_batch, reader_receipt)

    changed_batch = list(deepcopy(batch))
    changed_batch[1]["source"]["run_id"] = "fixture-run-b"
    with pytest.raises(ConsumerError, match="INPUT_CONTRACT$"):
        _validate_publication(changed_batch, reader_receipt)


def test_transaction_budget_fails_before_a_write(publication):
    batch, reader_receipt = publication
    database = _new_database()
    with pytest.raises(ConsumerError, match="TRANSACTION_TIMEOUT$"):
        _consume(
            database, batch, reader_receipt,
            attempt_id="over-time-budget",
            elapsed_ms=MAX_ELAPSED_MS + 1,
        )
    assert database.execute("SELECT COUNT(*) FROM consumer_runs").fetchone()[0] == 0


def test_test_oracle_schema_stores_only_normalized_contract_data():
    database = _new_database()
    columns = {
        row[1]
        for table in ("consumer_runs", "consumer_alerts", "consumer_receipts")
        for row in database.execute(f"PRAGMA table_info({table})")
    }
    forbidden = {
        "path", "source_path", "raw_eve", "payload", "content_hash",
        "payload_hash", "rule_label", "exception",
    }
    assert columns.isdisjoint(forbidden)


def test_diagnostics_are_fixed_bounded_and_never_echo_storage_details(publication):
    batch, reader_receipt = publication
    changed = deepcopy(reader_receipt)
    changed["source_path"] = "/synthetic/private/eve.json"
    with pytest.raises(ConsumerError) as caught:
        _validate_publication(batch, changed)
    diagnostic = str(caught.value)
    assert diagnostic.encode("ascii")
    assert len(diagnostic.encode("ascii")) <= MAX_DIAGNOSTIC_BYTES
    for forbidden in ("path", "private", "eve.json", "sqlite", "SELECT"):
        assert forbidden not in diagnostic
