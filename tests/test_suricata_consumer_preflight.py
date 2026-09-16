"""Runtime tests for the bounded no-write Suricata consumer preflight."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import MappingProxyType

import pytest

from megalodon.offline import suricata, suricata_consumer


ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))


def _publication(tmp_path: Path):
    source = tmp_path / "alerts.jsonl"
    source.write_text(json.dumps(CASES[0]["input"]) + "\n", encoding="utf-8")
    source.chmod(0o600)
    return suricata.read_completed_file(str(source))


@pytest.fixture(autouse=True)
def unprivileged_runtime(monkeypatch):
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)


def _store(tmp_path: Path):
    path = tmp_path / "consumer.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA page_size=4096")
    connection.execute("VACUUM")
    return path, connection


def test_preflight_admits_one_immutable_publication_without_writes(tmp_path):
    publication = _publication(tmp_path)
    path, connection = _store(tmp_path)
    before = path.read_bytes()
    try:
        result = suricata_consumer.preflight_publication(
            connection, publication, database_path=path,
        )
        assert result.publication is not publication
        assert result.publication == publication
        assert result.publication[0] is not publication[0]
        assert result.publication[0][0] is not publication[0][0]
        assert result.publication[1] is not publication[1]
        assert result.transaction_status == "not_started"
        assert result.action_status == "not_attempted"
        assert result.capacity["max_pages"] == 131_072
        assert result.capacity["reservation_bytes"] == (
            4 * publication[1]["normalized_batch_bytes"] + 8_388_608
        )
        assert connection.in_transaction is False
        assert path.read_bytes() == before
        assert not path.with_name(path.name + "-wal").exists()
        assert not path.with_name(path.name + "-journal").exists()
        with pytest.raises(TypeError):
            result.capacity["max_pages"] = 1
    finally:
        connection.close()


@pytest.mark.parametrize("available", [0, 8_388_607])
def test_filesystem_refusal_is_fixed_and_writes_nothing(tmp_path, monkeypatch, available):
    publication = _publication(tmp_path)
    path, connection = _store(tmp_path)
    before = path.read_bytes()
    values = type("Stat", (), {"f_bavail": available, "f_frsize": 1})()
    monkeypatch.setattr(suricata_consumer.os, "statvfs", lambda _path: values)
    try:
        with pytest.raises(
            suricata_consumer.ConsumerPreflightError,
            match="SURICATA_CONSUMER_V1:STORAGE_CAPACITY$",
        ) as caught:
            suricata_consumer.preflight_publication(
                connection, publication, database_path=path,
            )
        assert caught.value.transaction_status == "not_started"
        assert caught.value.action_status == "not_attempted"
        assert connection.in_transaction is False
        assert path.read_bytes() == before
    finally:
        connection.close()


def test_rejects_transaction_schema_and_publication_mismatch(tmp_path):
    publication = _publication(tmp_path)
    path, connection = _store(tmp_path)
    connection.execute("BEGIN")
    with pytest.raises(suricata_consumer.ConsumerPreflightError, match="STORAGE_CAPACITY$"):
        suricata_consumer.preflight_publication(connection, publication, database_path=path)
    connection.rollback()
    connection.close()

    bad_path = tmp_path / "bad.db"
    bad = sqlite3.connect(bad_path)
    bad.execute("PRAGMA page_size=8192")
    bad.execute("VACUUM")
    try:
        with pytest.raises(suricata_consumer.ConsumerPreflightError, match="SCHEMA_INCOMPATIBLE$"):
            suricata_consumer.preflight_publication(bad, publication, database_path=bad_path)
    finally:
        bad.close()

    changed = (publication[0], dict(publication[1], normalized_batch_bytes=0))
    path, connection = _store(tmp_path)
    try:
        with pytest.raises(suricata_consumer.ConsumerPreflightError, match="INPUT_CONTRACT$"):
            suricata_consumer.preflight_publication(connection, changed, database_path=path)
    finally:
        connection.close()


def test_rejects_mutable_or_wrong_store_publication_evidence(tmp_path):
    publication = _publication(tmp_path)
    path, connection = _store(tmp_path)
    mutable = ([dict(publication[0][0])], dict(publication[1]))
    try:
        with pytest.raises(suricata_consumer.ConsumerPreflightError, match="INPUT_CONTRACT$"):
            suricata_consumer.preflight_publication(connection, mutable, database_path=path)
        wrong = tmp_path / "wrong.db"
        wrong.touch()
        with pytest.raises(suricata_consumer.ConsumerPreflightError, match="STORAGE_CAPACITY$"):
            suricata_consumer.preflight_publication(connection, publication, database_path=wrong)
    finally:
        connection.close()


def test_rejects_frozen_but_contract_invalid_records(tmp_path):
    publication = _publication(tmp_path)
    path, connection = _store(tmp_path)
    malformed = ((MappingProxyType({"garbage": "accepted-before-review"}),), publication[1])
    try:
        with pytest.raises(
            suricata_consumer.ConsumerPreflightError,
            match="INPUT_CONTRACT$",
        ):
            suricata_consumer.preflight_publication(
                connection, malformed, database_path=path,
            )
    finally:
        connection.close()


def test_rejects_memory_and_unnamed_databases(tmp_path):
    publication = _publication(tmp_path)
    connection = sqlite3.connect(":memory:")
    try:
        with pytest.raises(
            suricata_consumer.ConsumerPreflightError,
            match="STORAGE_CAPACITY$",
        ):
            suricata_consumer.preflight_publication(
                connection, publication, database_path=tmp_path,
            )
    finally:
        connection.close()


def test_freelist_pages_are_observed_but_never_credited(tmp_path, monkeypatch):
    publication = _publication(tmp_path)
    path, connection = _store(tmp_path)
    real_query = suricata_consumer._query_integer

    def fixed_query(selected, statement):
        if statement == "PRAGMA page_count":
            return 130_000
        if statement == "PRAGMA freelist_count":
            return 10_000
        return real_query(selected, statement)

    monkeypatch.setattr(suricata_consumer, "_query_integer", fixed_query)
    try:
        with pytest.raises(
            suricata_consumer.ConsumerPreflightError,
            match="STORAGE_CAPACITY$",
        ):
            suricata_consumer.preflight_publication(
                connection, publication, database_path=path,
            )
    finally:
        connection.close()
