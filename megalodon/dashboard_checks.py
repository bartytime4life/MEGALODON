"""Fixed, read-only local checks requested explicitly from the HUD.

No request selects a path, tool, command, process, or remote destination. The
metadata probes have finite operation counts, not an OS/filesystem deadline.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import platform
import sqlite3
from threading import Lock
from time import monotonic

from .capabilities import runtime_platform
from .readiness import readiness_report
from .runtime_status import runtime_report
from .storage import StorageSchemaError


MAX_CHECK_BYTES = 20 * 1024
CHECK_CACHE_SECONDS = 5


class LocalCheckBusy(Exception):
    """A check is already in progress; callers should retry later."""


class LocalChecks:
    """One collector per server, with a short cache and no overlapping probes."""

    def __init__(self, store: object, *, source_available: bool) -> None:
        self._store = store
        self._source_available = source_available
        self._lock = Lock()
        self._cached: bytes | None = None
        self._expires = 0.0

    def snapshot(self) -> bytes:
        if not self._lock.acquire(blocking=False):
            raise LocalCheckBusy
        try:
            if self._cached is not None and monotonic() < self._expires:
                return self._cached
            source = "not_configured"
            if self._source_available:
                try:
                    # Use the already admitted reader and its bounded query.
                    # Discard counters: readability is not qualified telemetry.
                    self._store.summary()
                    source = "available"
                except (StorageSchemaError, sqlite3.Error, OSError):
                    source = "unavailable"
            receipt = {
                "schema": "dashboard-local-checks-v1",
                "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "environment": {
                    "python_version": platform.python_version(),
                    "sqlite_version": sqlite3.sqlite_version,
                    "platform": runtime_platform(),
                },
                "source": {"status": source},
                "readiness": readiness_report(),
                "runtime": runtime_report(),
            }
            payload = json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            if len(payload) > MAX_CHECK_BYTES:
                raise ValueError("local check response exceeds limit")
            self._cached = payload
            self._expires = monotonic() + CHECK_CACHE_SECONDS
            return payload
        finally:
            self._lock.release()
