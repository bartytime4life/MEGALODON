"""Local dashboard. Telemetry routes are read-only.

HUD mode also serves a cached tool heartbeat and an inert recipe catalog.
Explicitly enabled, non-root Linux tool management requires a per-launch
operator token before fixed installation or service-start recipes can run.

The presentation constants live in ``dashboard_assets``; this module retains the
public Python API and the security boundary for every HTTP route.
"""

from __future__ import annotations

from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as _ThreadingHTTPServer
from ipaddress import AddressValueError, IPv4Address
import hmac
import json
import os
from pathlib import Path
import sys
from threading import BoundedSemaphore, Lock, Thread
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse
import webbrowser
import secrets

from .dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from .dashboard_action_plane import ACTION_PRESETS
from .dashboard_commands import local_hud_launch, local_python_lifecycle
from .dashboard_checks import LocalChecks, LocalCheckBusy, CHECK_CACHE_SECONDS
from .tool_heartbeat import Heartbeat, HeartbeatBusy, HEARTBEAT_CACHE_SECONDS
from .tool_installer import ACTIONS as INSTALL_ACTIONS, Installer, InstallBusy, InstallUnavailable, RECIPES, catalog as install_catalog
from .hub import integration_plan
from .qwen_advisory import QwenAdvisoryResult, validated_qwen_result
from .config import AISettings, BlockingSettings
from .reference import IanaBundle, ReferenceDataError, load_iana
from .storage import StorageSchemaError
from .suricata_projection import MAX_RESPONSE_BYTES as MAX_SURICATA_RESPONSE_BYTES, read_suricata_projection


MIN_REFRESH_SECONDS = 2
MAX_REFRESH_SECONDS = 300
MAX_EVENT_LIMIT = 200
DEFAULT_INGESTION_RUN_LIMIT = 8
MAX_INGESTION_RUN_LIMIT = 25
MAX_INGESTION_RUN_RESPONSE_BYTES = 32 * 1024
DASHBOARD_EVENT_FIELDS = ("detected_at", "rule_id", "severity", "src_ip", "message")
MAX_DASHBOARD_QUERY_LENGTH = 256
MAX_INTEGRATION_WORKFLOWS = 14
MAX_INTEGRATION_RESPONSE_BYTES = 32 * 1024
MAX_INTEGRATION_FIELD_LENGTH = 512
MAX_REFERENCE_QUERY_LENGTH = 256
MAX_REFERENCE_RESPONSE_BYTES = 64 * 1024
MAX_REFERENCE_CACHE_ENTRIES = 16
MAX_REFERENCE_MATCHES = 8
MAX_ADVISORY_RESPONSE_BYTES = 8 * 1024
REFERENCE_BUNDLE_VERSION = "v1"
REFERENCE_WARNING = (
    "Registration is analyst context, not proof of what was observed or whether an endpoint "
    "is safe or malicious."
)


class ThreadingHTTPServer(_ThreadingHTTPServer):
    """Bound the loopback server before HTTP headers reach the handler."""

    max_connections = 32
    request_queue_size = 32
    request_timeout_seconds = 2

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        self._connection_slots = BoundedSemaphore(self.max_connections)
        super().__init__(server_address, handler)

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.settimeout(self.request_timeout_seconds)
        except OSError:
            connection.close()
            raise
        return connection, address

    def process_request(self, request, client_address) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class DashboardReader(Protocol):
    def summary(self) -> dict[str, Any]: ...

    def recent(self, limit: int = 50) -> list[dict[str, Any]]: ...

    def ingestion_runs(
        self, limit: int = DEFAULT_INGESTION_RUN_LIMIT, *, source: str | None = None
    ) -> list[dict[str, Any]]: ...

    def traffic(self) -> dict[str, Any]: ...


class UnconfiguredDashboardReader:
    """A missing source is unavailable, never an empty/healthy database."""

    def summary(self) -> dict[str, Any]:
        raise StorageSchemaError("DASHBOARD_STORE:NO_DATABASE")

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        raise StorageSchemaError("DASHBOARD_STORE:NO_DATABASE")

    def ingestion_runs(self, limit: int = DEFAULT_INGESTION_RUN_LIMIT, *, source: str | None = None) -> list[dict[str, Any]]:
        raise StorageSchemaError("DASHBOARD_STORE:NO_DATABASE")

    def traffic(self) -> dict[str, Any]:
        raise StorageSchemaError("DASHBOARD_STORE:NO_DATABASE")


def setup_snapshot(*, inspect_tools: bool = False, source_available: bool = True) -> bytes:
    """One startup check, never a request-triggered probe or tool execution."""
    from .readiness import readiness_report, MAX_REPORT_BYTES
    from .runtime_status import runtime_report

    report = readiness_report() if inspect_tools else None
    runtime = runtime_report() if inspect_tools else None
    payload = json.dumps({
        "schema": "dashboard-setup-v2",
        "source_status": "connected" if source_available else "not_configured",
        "readiness": report,
        "runtime": runtime,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(payload) > (MAX_REPORT_BYTES * 2) + 1024:
        raise ValueError("dashboard setup response exceeds limit")
    return payload


class ReferenceLookupError(ValueError):
    """A fixed, path-free diagnostic for the dashboard reference surface."""


def suricata_snapshot(database_path: str | Path | None) -> bytes:
    """Own one optional startup projection; HTTP requests never reopen the store."""
    projection = read_suricata_projection(database_path)
    try:
        encoded = json.dumps(
            projection, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(encoded) > MAX_SURICATA_RESPONSE_BYTES:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        # An optional projection must never prevent core telemetry startup.
        projection = read_suricata_projection(None)
        projection.update(status="unavailable", failure_code="RESPONSE_LIMIT")
        encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    return encoded


def advisory_receipt_snapshot(
    value: QwenAdvisoryResult | None,
) -> dict[str, object] | None:
    """Validate and own one display-only Qwen result before server startup."""
    if value is None:
        return None
    try:
        receipt = validated_qwen_result(value).to_dict()
        owned = json.loads(
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )
        envelope = {
            "schema": "dashboard-advisory-receipt-v1",
            "available": True,
            "receipt": owned,
        }
        encoded = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(encoded) > MAX_ADVISORY_RESPONSE_BYTES:
            raise ValueError
    except (KeyError, MemoryError, OverflowError, TypeError, ValueError):
        raise ValueError("dashboard advisory receipt is invalid") from None
    return owned


class ReferenceLibrary:
    """A verified, immutable-in-process view of the bundled IANA snapshot.

    The bundle is loaded once, never refreshed from the network, and only a
    small LRU-like cache of exact manual lookups is retained. The cache is a
    performance detail, not a persistence or detection store.
    """

    def __init__(self, bundle: IanaBundle | Any | None = None, *, failure: str | None = None) -> None:
        if bundle is not None and failure is not None:
            raise ValueError("reference bundle and failure are mutually exclusive")
        self._bundle = bundle
        self._failure = failure
        self._cache: OrderedDict[tuple[str, str, int], dict[str, object]] = OrderedDict()
        self._lock = Lock()

    @classmethod
    def load(cls) -> "ReferenceLibrary":
        try:
            return cls(load_iana())
        except ReferenceDataError as exc:
            # Only the fixed resource-access code is ordinary unavailability.
            # All validation failures, including future codes, fail closed as
            # integrity failures without exposing loader detail or partial rows.
            category = (
                "unavailable"
                if str(exc) == "REFERENCE_DATA:RESOURCE_IO"
                else "integrity_failure"
            )
            return cls(failure=category)

    @property
    def available(self) -> bool:
        return self._bundle is not None and self._failure is None

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def status(self) -> dict[str, object]:
        if not self.available:
            category = self._failure or "unavailable"
            return {
                "schema": "reference-library-status-v1",
                "available": False,
                "status": category,
                "error": (
                    "reference bundle integrity failure"
                    if category == "integrity_failure"
                    else "reference bundle unavailable"
                ),
                "network_access_performed": False,
                "persistence_status": "not_attempted",
                "action_status": "not_attempted",
            }
        bundle = self._bundle
        assert bundle is not None
        return {
            "schema": "reference-library-status-v1",
            "available": True,
            "status": "ready",
            "bundle_id": bundle.bundle_id,
            "bundle_version": REFERENCE_BUNDLE_VERSION,
            "manifest_sha256": bundle.manifest_sha256,
            "service_records": len(bundle.services),
            "protocol_records": len(bundle.protocols),
            "cache_entries": self.cache_size,
            "cache_limit": MAX_REFERENCE_CACHE_ENTRIES,
            "sources": self._sources(bundle),
            "warning": bundle.warning,
            "network_access_performed": False,
            "persistence_status": "not_attempted",
            "action_status": "not_attempted",
        }

    def lookup_port(self, transport: str, port: int) -> dict[str, object]:
        # Type checks precede set membership: lists/dicts must fail with the
        # same bounded diagnostic instead of escaping as an unhashable TypeError.
        if (
            type(transport) is not str
            or transport not in {"tcp", "udp", "sctp", "dccp"}
            or type(port) is not int
            or not 0 <= port <= 65_535
        ):
            raise ReferenceLookupError("invalid reference lookup")
        key = ("port", transport, port)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                return json.loads(json.dumps(cached))
        if not self.available:
            return self.status()
        bundle = self._bundle
        assert bundle is not None
        all_matches = [
            item for item in bundle.services
            if item.transport == transport and item.port_start <= port <= item.port_end
        ]
        result = self._result(
            "port", all_matches, bundle,
            query={"transport": transport, "port": port},
            source_ids=("iana-service-names-port-numbers",),
        )
        self._remember(key, result)
        return json.loads(json.dumps(result))

    def lookup_protocol(self, number: int) -> dict[str, object]:
        if type(number) is not int or not 0 <= number <= 255:
            raise ReferenceLookupError("invalid reference lookup")
        key = ("protocol", "", number)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                return json.loads(json.dumps(cached))
        if not self.available:
            return self.status()
        bundle = self._bundle
        assert bundle is not None
        all_matches = [
            item for item in bundle.protocols
            if item.decimal_start <= number <= item.decimal_end
        ]
        result = self._result(
            "protocol", all_matches, bundle,
            query={"number": number}, source_ids=("iana-protocol-numbers",),
        )
        self._remember(key, result)
        return json.loads(json.dumps(result))

    def _remember(self, key: tuple[str, str, int], value: dict[str, object]) -> None:
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            while len(self._cache) > MAX_REFERENCE_CACHE_ENTRIES:
                self._cache.popitem(last=False)

    @staticmethod
    def _sources(bundle: Any) -> list[dict[str, str]]:
        return [dict(item) for item in getattr(bundle, "source_provenance", ())]

    def _result(
        self, kind: str, all_matches: list[Any], bundle: Any, *,
        query: dict[str, object], source_ids: tuple[str, ...],
    ) -> dict[str, object]:
        matches = all_matches[:MAX_REFERENCE_MATCHES]
        status = (
            "no_match" if not all_matches
            else "one_match" if len(all_matches) == 1
            else "multiple_matches"
        )
        sources = [
            source for source in self._sources(bundle)
            if source.get("id") in source_ids
        ]
        result = {
            "schema": "reference-library-lookup-v1", "status": status,
            "available": True, "kind": kind, "bundle_id": bundle.bundle_id,
            "bundle_version": REFERENCE_BUNDLE_VERSION,
            "manifest_sha256": bundle.manifest_sha256, "query": query,
            "match_count": len(all_matches),
            "matches": [item.public() for item in matches],
            "truncated": len(all_matches) > len(matches), "sources": sources,
            "warning": bundle.warning or REFERENCE_WARNING,
            "network_access_performed": False, "persistence_status": "not_attempted",
            "action_status": "not_attempted",
        }
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_REFERENCE_RESPONSE_BYTES:
            raise ReferenceLookupError("reference response exceeded bound")
        return result


_default_reference_library: ReferenceLibrary | None = None
_default_reference_lock = Lock()


def default_reference_library() -> ReferenceLibrary:
    global _default_reference_library
    with _default_reference_lock:
        if _default_reference_library is None:
            _default_reference_library = ReferenceLibrary.load()
        return _default_reference_library


def _canonical_decimal(value: object, maximum: int) -> bool:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        return False
    if len(value) > len(str(maximum)) or value != str(int(value)):
        return False
    return 0 <= int(value) <= maximum


def _bounded_query(query: str, *, max_fields: int) -> dict[str, list[str]]:
    """Bound parsing before allocation/conversion; errors never reflect input."""
    if len(query) > MAX_DASHBOARD_QUERY_LENGTH:
        raise ValueError("query is too long")
    try:
        return parse_qs(
            query, keep_blank_values=True, strict_parsing=True,
            encoding="utf-8", errors="strict", max_num_fields=max_fields,
        )
    except (ValueError, UnicodeError):
        raise ValueError("invalid query parameters") from None


class DashboardHandler(BaseHTTPRequestHandler):
    store: DashboardReader
    offline_summary: dict[str, Any] | None = None
    advisory_receipt: dict[str, object] | None = None
    reference_library: ReferenceLibrary | None = None
    suricata_evidence: bytes | None = None
    refresh_seconds: int = 5
    event_limit: int = 50
    setup_evidence: bytes | None = None
    local_checks: LocalChecks | None = None
    heartbeat: Heartbeat | None = None
    installer: Installer | None = None
    tool_management_enabled: bool = False
    install_operator_token: str | None = None
    javascript: bytes = DASHBOARD_JS.encode()
    ai_settings: AISettings = AISettings()
    ai_receipt_path: Path | None = None
    ai_operator_token: str | None = None
    ai_blocking: BlockingSettings = BlockingSettings()
    automation_preview_lock = Lock()

    def do_GET(self) -> None:  # noqa: N802
        if not self._has_expected_host():
            self._send_json({"error": "invalid request host"}, status=400)
            return
        try:
            route = urlparse(self.path)
        except ValueError:
            self._send_json({"error": "invalid request target"}, status=400)
            return
        if route.scheme or route.netloc or route.params or route.fragment:
            self._send_json({"error": "invalid request target"}, status=400)
            return
        if route.path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            return
        if route.path == "/assets/dashboard.css":
            self._send(200, "text/css; charset=utf-8", DASHBOARD_CSS.encode())
            return
        if route.path == "/assets/dashboard.js":
            self._send(200, "text/javascript; charset=utf-8", self.javascript)
            return
        if route.path in {"/api/config", "/api/setup", "/api/local-checks", "/api/summary", "/api/traffic", "/api/offline-summary", "/api/advisory-receipt", "/api/suricata", "/api/reference/status", "/api/heartbeat", "/api/install"} and route.query:
            self._send_json({"error": "unsupported query parameter"}, status=400)
            return
        if route.path == "/api/ai/status":
            from .ai_provider import status
            if not self.ai_settings.enabled and not route.query:
                self._send_json(status(self.ai_settings, probe=False))
                return
            token_values = self.headers.get_all("X-Megalodon-AI-Token", [])
            if (route.query or self.headers.get_all("X-Megalodon-AI-Check", []) != ["1"]
                    or self.ai_operator_token is None or len(token_values) != 1
                    or not hmac.compare_digest(token_values[0], self.ai_operator_token)):
                self._send_json({"error": "explicit local AI check required"}, status=403)
                return
            self._send_json(status(self.ai_settings, probe=True))
            return
        if route.path == "/api/setup":
            self._send(200, "application/json; charset=utf-8", self.setup_evidence or setup_snapshot())
            return
        if route.path == "/api/local-checks":
            # An explicit same-origin fetch can set this header; cross-origin
            # browser requests need a CORS preflight, which we do not permit.
            if self.headers.get_all("X-Megalodon-Check", []) != ["1"]:
                self._send_json({"error": "explicit local check required"}, status=403)
                return
            if self.local_checks is None:
                self._send_json({"error": "local checks require HUD mode"}, status=403)
                return
            try:
                payload = self.local_checks.snapshot()
            except LocalCheckBusy:
                self._send_json({"error": "local check in progress"}, status=429,
                                extra_headers={"Retry-After": str(CHECK_CACHE_SECONDS)})
                return
            except (OSError, ValueError, TypeError, OverflowError):
                self._send_json({"error": "local checks unavailable"}, status=503)
                return
            self._send(200, "application/json; charset=utf-8", payload)
            return
        if route.path in {"/api/heartbeat", "/api/install"}:
            if self.headers.get_all("X-Megalodon-Check", []) != ["1"]:
                self._send_json({"error": "explicit local check required"}, status=403)
                return
            if self.heartbeat is None or self.installer is None:
                self._send_json({"error": "heartbeat requires HUD mode"}, status=403)
                return
            if route.path == "/api/install":
                enabled = (self.tool_management_enabled is True
                           and self.install_operator_token is not None and _tool_management_user())
                self._send_json({**install_catalog(), "job": self.installer.status(),
                                 "management": {"enabled": enabled,
                                                "authorization": "per_launch_token" if enabled else "disabled"}})
                return
            try:
                payload = self.heartbeat.snapshot()
            except HeartbeatBusy:
                self._send_json({"error": "heartbeat in progress"}, status=429,
                                extra_headers={"Retry-After": str(HEARTBEAT_CACHE_SECONDS)})
                return
            except (OSError, ValueError, TypeError, OverflowError):
                self._send_json({"error": "heartbeat unavailable"}, status=503)
                return
            self._send(200, "application/json; charset=utf-8", payload)
            return
        if route.path == "/api/traffic":
            from .dashboard_traffic import MAX_BYTES, unavailable
            try:
                reader = getattr(self.store, "traffic", None)
                if reader is None:
                    raise StorageSchemaError("DASHBOARD_STORE:NO_DATABASE")
                payload = json.dumps(reader(), separators=(",", ":"), allow_nan=False).encode()
                if len(payload) > MAX_BYTES:
                    raise ValueError("response bound")
            except (StorageSchemaError, ValueError, TypeError, OverflowError):
                self._send_json(unavailable(), status=503)
                return
            self._send(200, "application/json; charset=utf-8", payload)
            return
        if route.path == "/api/traffic-history":
            from .dashboard_traffic import MAX_BYTES, history_parameters
            try:
                params = _bounded_query(route.query, max_fields=3)
                if not {"start", "end"} <= set(params) or set(params) - {"start", "end", "before"} or any(len(v) != 1 for v in params.values()):
                    raise ValueError("invalid history query")
                values = {key: items[0] for key, items in params.items()}
                history_parameters(**values)
            except ValueError:
                self._send_json({"error": "history requires a UTC start/end range of at most 31 days and an optional positive before cursor"}, status=400)
                return
            try:
                reader = getattr(self.store, "traffic_history", None)
                if reader is None:
                    raise StorageSchemaError("DASHBOARD_STORE:NO_DATABASE")
                payload = json.dumps(reader(**values), separators=(",", ":"), allow_nan=False).encode()
                if len(payload) > MAX_BYTES:
                    raise ValueError("response bound")
            except (StorageSchemaError, ValueError, TypeError, OverflowError):
                self._send_json({"error": "history unavailable"}, status=503)
                return
            self._send(200, "application/json; charset=utf-8", payload)
            return
        if route.path == "/api/config":
            self._send_json({
                "schema": "dashboard-config-v1", "read_only": True,
                "refresh_seconds": self.refresh_seconds, "event_limit": self.event_limit,
                "offline_summary_available": self.offline_summary is not None,
            })
            return
        if route.path == "/api/summary":
            try:
                summary = self.store.summary()
            except StorageSchemaError:
                self._send_json({"error": "telemetry unavailable"}, status=503)
                return
            self._send_json(summary)
            return
        if route.path == "/api/events":
            try:
                params = _bounded_query(route.query, max_fields=1)
            except ValueError:
                self._send_json({"error": "invalid event query"}, status=400)
                return
            if set(params) - {"limit"}:
                self._send_json({"error": "unsupported query parameter"}, status=400)
                return
            values = params.get("limit")
            if values is None:
                limit = self.event_limit
            elif len(values) != 1 or not _canonical_decimal(values[0], MAX_EVENT_LIMIT):
                self._send_json({"error": "limit must be one canonical decimal integer between 1 and 200"}, status=400)
                return
            else:
                limit = int(values[0])
            if not 1 <= limit <= MAX_EVENT_LIMIT:
                self._send_json({"error": f"limit must be between 1 and {MAX_EVENT_LIMIT}"}, status=400)
                return
            try:
                events = _dashboard_events(self.store, limit)
            except StorageSchemaError:
                self._send_json({"error": "telemetry unavailable"}, status=503)
                return
            self._send_json(events)
            return
        # /api/ingestion-runs (v1) is kept only for existing external callers;
        # the HUD itself reads the source-qualified v2 route exclusively.
        if route.path in {"/api/ingestion-runs", "/api/ingestion-runs-v2"}:
            qualified = route.path == "/api/ingestion-runs-v2"
            try:
                params = _bounded_query(route.query, max_fields=2 if qualified else 1)
            except ValueError:
                self._send_json({"error": "invalid ingestion run query"}, status=400)
                return
            if set(params) - ({"limit", "source"} if qualified else {"limit"}):
                self._send_json({"error": "unsupported query parameter"}, status=400)
                return
            values = params.get("limit")
            if values is None:
                limit = DEFAULT_INGESTION_RUN_LIMIT
            elif len(values) != 1 or not _canonical_decimal(
                values[0], MAX_INGESTION_RUN_LIMIT
            ):
                self._send_json(
                    {
                        "error": (
                            "limit must be one canonical decimal integer "
                            "between 1 and 25"
                        )
                    },
                    status=400,
                )
                return
            else:
                limit = int(values[0])
            if not 1 <= limit <= MAX_INGESTION_RUN_LIMIT:
                self._send_json(
                    {"error": "limit must be between 1 and 25"}, status=400
                )
                return
            source = "all"
            if qualified and "source" in params:
                selected = params["source"]
                if len(selected) != 1 or selected[0] not in {"all", "sample", "jsonl", "scapy"}:
                    self._send_json({"error": "unsupported ingestion source"}, status=400)
                    return
                source = selected[0]
            try:
                runs = self.store.ingestion_runs(
                    limit, source=None if source == "all" else source
                ) if qualified else self.store.ingestion_runs(limit)
            except StorageSchemaError:
                self._send_json({"error": "telemetry unavailable"}, status=503)
                return
            if not qualified:
                self._send_json({
                    "schema": "dashboard-ingestion-runs-v1",
                    "limit": limit,
                    "runs": runs,
                })
                return
            payload = json.dumps({
                "schema": "dashboard-ingestion-runs-v2",
                "limit": limit,
                "source_filter": source,
                "max_runs": MAX_INGESTION_RUN_LIMIT,
                "max_response_bytes": MAX_INGESTION_RUN_RESPONSE_BYTES,
                "not_recorded": ["adapter_identity", "accepted_count", "rejected_count"],
                "runs": runs,
            }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            if len(payload) > MAX_INGESTION_RUN_RESPONSE_BYTES:
                self._send_json({"error": "ingestion receipts unavailable"}, status=503)
                return
            self._send(200, "application/json; charset=utf-8", payload)
            return
        if route.path == "/api/offline-summary":
            self._send_json(
                {"available": False} if self.offline_summary is None
                else {"available": True, "snapshot": self.offline_summary}
            )
            return
        if route.path == "/api/suricata":
            # The bytes are owned before binding. Browser input can neither
            # select a path nor cause another store read or snapshot refresh.
            self._send(
                200, "application/json; charset=utf-8",
                self.suricata_evidence if self.suricata_evidence is not None
                else suricata_snapshot(None),
            )
            return
        if route.path == "/api/advisory-receipt":
            self._send_json(
                {
                    "schema": "dashboard-advisory-receipt-v1",
                    "available": False,
                }
                if self.advisory_receipt is None
                else {
                    "schema": "dashboard-advisory-receipt-v1",
                    "available": True,
                    "receipt": self.advisory_receipt,
                }
            )
            return
        if route.path == "/api/integrations":
            try:
                params = _bounded_query(route.query, max_fields=1)
            except ValueError:
                self._send_json({"error": "invalid integration query"}, status=400)
                return
            if set(params) - {"platform"} or any(len(values) != 1 for values in params.values()):
                self._send_json({"error": "unsupported or repeated integration query parameter"}, status=400)
                return
            platform = params.get("platform", [None])[0]
            if platform is not None and platform not in {"linux", "windows", "other"}:
                self._send_json({"error": "unsupported integration platform"}, status=400)
                return
            # Closed built-in catalog only. This route never reads telemetry,
            # probes a binary, launches a process, or contacts another service.
            try:
                payload = integration_plan(platform)
                workflows = payload["workflows"]
                if not isinstance(workflows, list) or len(workflows) != MAX_INTEGRATION_WORKFLOWS:
                    raise ValueError("integration count exceeded bound")
                for item in workflows:
                    for field, value in item.items():
                        if field == "entry_point" and value is None:
                            continue
                        if not isinstance(value, str) or not 1 <= len(value) <= MAX_INTEGRATION_FIELD_LENGTH:
                            raise ValueError("integration field exceeded bound")
                encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                if len(encoded) > MAX_INTEGRATION_RESPONSE_BYTES:
                    raise ValueError("integration response exceeded bound")
            except (KeyError, TypeError, ValueError, AttributeError):
                self._send_json({"error": "integration map unavailable"}, status=503)
                return
            self._send(200, "application/json; charset=utf-8", encoded)
            return
        if route.path == "/api/reference/status":
            payload = self._reference_library().status()
            self._send_json(payload, status=200 if payload.get("available") else 503)
            return
        if route.path == "/api/reference/port":
            values = self._reference_query(route.query, {"transport", "port"})
            if values is None:
                return
            transport, port_text = values["transport"], values["port"]
            if transport not in {"tcp", "udp", "sctp", "dccp"} or not _canonical_decimal(port_text, 65_535):
                self._send_json({"error": "reference lookup requires one normalized transport and decimal port"}, status=400)
                return
            try:
                payload = self._reference_library().lookup_port(transport, int(port_text))
            except ReferenceLookupError:
                self._send_json({"error": "reference response unavailable"}, status=503)
                return
            self._send_reference_result(payload)
            return
        if route.path == "/api/reference/protocol":
            values = self._reference_query(route.query, {"number"})
            if values is None:
                return
            number_text = values["number"]
            if not _canonical_decimal(number_text, 255):
                self._send_json({"error": "reference lookup requires one decimal protocol number"}, status=400)
                return
            try:
                payload = self._reference_library().lookup_protocol(int(number_text))
            except ReferenceLookupError:
                self._send_json({"error": "reference response unavailable"}, status=503)
                return
            self._send_reference_result(payload)
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._has_expected_host():
            self._send_json({"error": "invalid request host"}, status=400)
            return
        if self.path == "/api/ai/ask":
            self._ai_ask()
            return
        if self.path == "/api/install":
            self._install()
            return
        if self.path == "/api/automation-preview":
            self._automation_preview()
            return
        self._send_json({"error": "method not allowed"}, status=405, extra_headers={"Allow": "GET"})

    def _automation_preview(self) -> None:
        """Calculate a fixed recurrence; never create or run a job."""
        expected_origin = f"http://{self.headers.get('Host')}"
        if (self.local_checks is None
                or self.headers.get_all("X-Megalodon-Preview", []) != ["1"]
                or self.headers.get_all("Origin", []) != [expected_origin]
                or self.headers.get_all("Content-Type", []) != ["application/json"]
                or self.headers.get_all("Transfer-Encoding", [])
                or self.headers.get_all("Content-Encoding", [])):
            self._send_json({"error": "explicit local preview required"}, status=403)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or len(lengths[0]) > 3 or not lengths[0].isascii()
                or not lengths[0].isdigit() or not 1 <= int(lengths[0]) <= 512):
            self._send_json({"error": "invalid preview request length"}, status=400)
            return
        if not self.automation_preview_lock.acquire(blocking=False):
            self._send_json({"error": "preview already in progress"}, status=429)
            return
        try:
            from .ai_provider import _strict_pairs
            from .automation_schedule import AutomationScheduleError, next_occurrences
            self.connection.settimeout(2)
            body = json.loads(self.rfile.read(int(lengths[0])).decode("utf-8"),
                              object_pairs_hook=_strict_pairs)
            if (type(body) is not dict
                    or set(body) != {"dtstart", "schedule_timezone", "preset"}
                    or type(body["dtstart"]) is not str or len(body["dtstart"]) > 32
                    or type(body["schedule_timezone"]) is not str or len(body["schedule_timezone"]) > 128
                    or type(body["preset"]) is not str or body["preset"] not in ACTION_PRESETS):
                raise ValueError("invalid preview fields")
            occurrences = next_occurrences(
                dtstart=body["dtstart"], schedule_timezone=body["schedule_timezone"],
                rrule=ACTION_PRESETS[body["preset"]], limit=8,
            )
            self._send_json({"schema_version": "megalodon-automation-preview-v1",
                             "status": "preview_only", "occurrences": [dict(item) for item in occurrences]})
        except (AutomationScheduleError, ValueError, OSError, OverflowError) as exc:
            self._send_json({"error_code": getattr(exc, "code", "PREVIEW_UNAVAILABLE")}, status=400)
        finally:
            self.automation_preview_lock.release()

    def _ai_ask(self) -> None:
        token_values = self.headers.get_all("X-Megalodon-AI-Token", [])
        expected_origin = f"http://{self.headers.get('Host')}"
        if (not self.ai_settings.enabled or self.ai_operator_token is None
                or len(token_values) != 1
                or not hmac.compare_digest(token_values[0], self.ai_operator_token)
                or self.headers.get_all("Origin", []) != [expected_origin]
                or self.headers.get_all("Content-Type", []) != ["application/json"]
                or self.headers.get_all("Transfer-Encoding", [])
                or self.headers.get_all("Content-Encoding", [])):
            self._send_json({"error": "AI operator authorization required"}, status=403)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or len(lengths[0]) > 3 or not lengths[0].isascii()
                or not lengths[0].isdigit() or not 1 <= int(lengths[0]) <= 256):
            self._send_json({"error": "invalid AI request length"}, status=400)
            return
        try:
            from .ai_provider import _strict_pairs
            from .ai_broker import Broker, ReceiptStore
            from .ai_interface import QUESTIONS, ask
            self.connection.settimeout(2)
            body = json.loads(self.rfile.read(int(lengths[0])).decode("utf-8"),
                              object_pairs_hook=_strict_pairs)
            if (type(body) is not dict or set(body) != {"question"}
                    or type(body["question"]) is not str or body["question"] not in QUESTIONS):
                raise ValueError("invalid AI question")
            if self.ai_receipt_path is None:
                raise ValueError("AI audit path unavailable")
            with ReceiptStore(self.ai_receipt_path) as receipts:
                answer = ask(body["question"], Broker(
                    self.store, receipts, self.ai_settings, self.ai_blocking))
            self._send_json(answer)
        except (ValueError, OSError, RuntimeError) as exc:
            self._send_json({"schema": "megalodon-ai-answer-v1", "state": "failed",
                             "error_code": getattr(exc, "code", "AI_UNAVAILABLE")}, status=503)

    def _install(self) -> None:
        # Origin/custom headers prevent cross-site browser requests, but only
        # the terminal-delivered launch token authenticates a local operator.
        expected_origin = f"http://{self.headers.get('Host')}"
        tokens = self.headers.get_all("X-Megalodon-Install-Token", [])
        if (self.installer is None
                or self.tool_management_enabled is not True
                or self.install_operator_token is None
                or not _tool_management_user()
                or len(tokens) != 1 or len(tokens[0]) != 32 or not tokens[0].isascii()
                or not hmac.compare_digest(tokens[0], self.install_operator_token)
                or self.headers.get_all("X-Megalodon-Install", []) != ["1"]
                or self.headers.get_all("Origin", []) != [expected_origin]
                or self.headers.get_all("Content-Type", []) != ["application/json"]
                or self.headers.get_all("Transfer-Encoding", [])
                or self.headers.get_all("Content-Encoding", [])):
            self._send_json({"error": "tool management operator authorization required"}, status=403)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or len(lengths[0]) > 2
                or not lengths[0].isascii() or not lengths[0].isdigit()
                or not 1 <= int(lengths[0]) <= 96):
            self._send_json({"error": "invalid install request length"}, status=400)
            return
        try:
            from .ai_provider import _strict_pairs
            self.connection.settimeout(2)
            body = json.loads(self.rfile.read(int(lengths[0])).decode("utf-8"),
                              object_pairs_hook=_strict_pairs)
        except (ValueError, OSError):
            self._send_json({"error": "invalid install request"}, status=400)
            return
        if (type(body) is not dict or not {"tool"} <= set(body) <= {"tool", "action"}
                or type(body["tool"]) is not str or body["tool"] not in RECIPES
                or type(body.get("action", "install")) is not str
                or body.get("action", "install") not in INSTALL_ACTIONS):
            self._send_json({"error": "unknown tool or action"}, status=400)
            return
        try:
            status = self.installer.start(body["tool"], body.get("action", "install"))
        except InstallBusy:
            self._send_json({"error": "another installation is running"}, status=409)
            return
        except InstallUnavailable:
            self._send_json({"error": "this action is not available for this tool on this computer"}, status=422)
            return
        self._send_json(status, status=202)

    def _reference_library(self) -> ReferenceLibrary:
        library = self.reference_library
        if library is None:
            library = default_reference_library()
        return library

    def _reference_query(self, query: str, expected: set[str]) -> dict[str, str] | None:
        if len(query) > MAX_REFERENCE_QUERY_LENGTH:
            self._send_json({"error": "reference query is too long"}, status=400)
            return None
        try:
            params = _bounded_query(query, max_fields=len(expected))
        except ValueError:
            self._send_json({"error": "invalid reference query"}, status=400)
            return None
        if set(params) != expected or any(len(values) != 1 for values in params.values()):
            self._send_json({"error": "unsupported or repeated reference query parameter"}, status=400)
            return None
        return {key: values[0] for key, values in params.items()}

    def _send_reference_result(self, payload: dict[str, object]) -> None:
        available = payload.get("available") is True
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_REFERENCE_RESPONSE_BYTES:
            self._send_json({"error": "reference response unavailable"}, status=503)
            return
        self._send_json(payload, status=200 if available else 503)

    def _has_expected_host(self) -> bool:
        """Reject DNS-rebound and ambiguous requests before routing or store access."""
        values = self.headers.get_all("Host", [])
        if len(values) != 1:
            return False
        supplied = values[0]
        if not isinstance(supplied, str) or not 1 <= len(supplied) <= 64:
            return False
        if supplied != supplied.strip():
            return False
        bound_host, bound_port = self.server.server_address[:2]
        expected = {str(bound_host), f"{bound_host}:{bound_port}"}
        if bound_host == "127.0.0.1":
            expected.update({"localhost", f"localhost:{bound_port}"})
        return supplied in expected

    def _send_json(self, value: object, *, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        self._send(status, "application/json; charset=utf-8", payload, extra_headers=extra_headers)

    def _send(
        self, status: int, content_type: str, payload: bytes, *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
            "img-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; base-uri 'none'; "
            "frame-src http: https:; frame-ancestors 'none'; form-action 'none'; worker-src 'none'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        return


def _dashboard_events(store: DashboardReader, limit: int) -> list[dict[str, Any]]:
    """Project stored detections onto the dashboard's minimal read-only contract."""
    return [
        {field: detection[field] for field in DASHBOARD_EVENT_FIELDS}
        for detection in store.recent(limit)
    ]


def _bounded_dashboard_integer(value: int, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def loopback_host(host: str, *, allow_remote: bool = False) -> str:
    """Return a numeric IPv4 loopback bind; never resolve a hostname.

    The legacy override is a refusal, not a way to weaken this boundary.
    IPv6 is intentionally refused by this IPv4 HTTP server.
    """
    if allow_remote is not False:
        raise ValueError("dashboard requires loopback; --allow-remote is no longer supported")
    if not isinstance(host, str) or not 1 <= len(host) <= 15:
        raise ValueError("dashboard requires a numeric IPv4 loopback address or localhost")
    if host == "localhost":
        return "127.0.0.1"
    try:
        address = IPv4Address(host)
    except AddressValueError:
        raise ValueError("dashboard requires a numeric IPv4 loopback address or localhost") from None
    if not address.is_loopback:
        raise ValueError("dashboard requires a numeric IPv4 loopback address or localhost")
    return str(address)


def _tool_management_user() -> bool:
    """Fail closed unless this is an ordinary Linux process, including real UID."""
    try:
        return sys.platform.startswith("linux") and os.getuid() != 0 and os.geteuid() != 0
    except (AttributeError, OSError):
        return False


def validate_tool_management_mode(enabled: bool, *, inspect_tools: bool) -> None:
    if type(enabled) is not bool:
        raise ValueError("tool management enablement must be a boolean")
    if enabled:
        if inspect_tools is not True:
            raise ValueError("--enable-tool-management requires the hud command")
        if not _tool_management_user():
            raise ValueError("tool management requires a non-root Linux HUD; do not use sudo")


def serve(
    store: DashboardReader, host: str, port: int, *, enabled: bool = True,
    allow_remote: bool = False, offline_summary: dict[str, Any] | None = None,
    advisory_receipt: QwenAdvisoryResult | None = None,
    reference_library: ReferenceLibrary | None = None,
    suricata_db: str | Path | None = None,
    inspect_tools: bool = False, source_available: bool = True,
    refresh_seconds: int = 5, event_limit: int = 50,
    open_browser: bool = False,
    enable_tool_management: bool = False,
    ai_settings: AISettings | None = None,
    ai_receipt_path: Path | None = None,
    ai_blocking: BlockingSettings | None = None,
) -> None:
    if not enabled:
        raise ValueError("dashboard is disabled by configuration")
    validate_tool_management_mode(enable_tool_management, inspect_tools=inspect_tools)
    refresh_seconds = _bounded_dashboard_integer(
        refresh_seconds, "dashboard refresh_seconds", MIN_REFRESH_SECONDS, MAX_REFRESH_SECONDS
    )
    event_limit = _bounded_dashboard_integer(event_limit, "dashboard event_limit", 1, MAX_EVENT_LIMIT)
    advisory_snapshot = advisory_receipt_snapshot(advisory_receipt)
    ai_operator_token = secrets.token_urlsafe(24) if ai_settings is not None and ai_settings.enabled else None
    install_operator_token = secrets.token_urlsafe(24) if enable_tool_management else None
    host = loopback_host(host, allow_remote=allow_remote)
    setup_evidence = setup_snapshot(inspect_tools=inspect_tools, source_available=source_available)
    suricata_evidence = suricata_snapshot(suricata_db)
    # Capture inert command text once. HTTP input cannot choose an interpreter
    # or checkout, execute commands, or trigger filesystem discovery.
    lifecycle = json.dumps(local_python_lifecycle(), ensure_ascii=True, allow_nan=False)
    launch = json.dumps(local_hud_launch(), ensure_ascii=True, allow_nan=False)
    javascript = (f"const localHudLaunch = {launch};\n" + DASHBOARD_JS.replace(
        "const localPythonLifecycle = null;",
        f"const localPythonLifecycle = {lifecycle};",
        1,
    )).encode()
    heartbeat = Heartbeat() if inspect_tools else None
    installer = Installer(on_finish=heartbeat.invalidate) if heartbeat is not None else None
    handler = type(
        "BoundDashboardHandler", (DashboardHandler,), {
            "store": store, "offline_summary": offline_summary,
            "advisory_receipt": advisory_snapshot,
            "suricata_evidence": suricata_evidence,
            "reference_library": reference_library, "refresh_seconds": refresh_seconds,
            "event_limit": event_limit,
            "setup_evidence": setup_evidence,
            "local_checks": LocalChecks(store, source_available=source_available) if inspect_tools else None,
            "heartbeat": heartbeat,
            "installer": installer,
            "tool_management_enabled": enable_tool_management,
            "install_operator_token": install_operator_token,
            "javascript": javascript,
            "ai_settings": ai_settings or AISettings(),
            "ai_receipt_path": ai_receipt_path,
            "ai_operator_token": ai_operator_token,
            "ai_blocking": ai_blocking or BlockingSettings(),
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    try:
        url = f"http://{host}:{port}/"
        print(f"MEGALODON dashboard listening on {url}", flush=True)
        if install_operator_token is not None:
            print(f"MEGALODON tool management operator token (this launch only): {install_operator_token}", flush=True)
        if ai_operator_token is not None:
            print(f"MEGALODON AI operator token (this launch only): {ai_operator_token}", flush=True)
        if open_browser:
            def open_bound_dashboard() -> None:
                try:
                    opened = webbrowser.open_new_tab(url)
                except (OSError, webbrowser.Error):
                    opened = False
                if not opened:
                    print(f"Open {url} in your browser.", flush=True)

            Thread(
                target=open_bound_dashboard,
                name="megalodon-browser-open",
                daemon=True,
            ).start()
        server.serve_forever()
    finally:
        server.server_close()
