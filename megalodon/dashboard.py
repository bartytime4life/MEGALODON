"""Local read-only dashboard. It exposes telemetry, never control actions.

The presentation constants live in ``dashboard_assets``; this module retains the
public Python API and the security boundary for every HTTP route.
"""

from __future__ import annotations

from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import AddressValueError, IPv4Address
import json
from threading import Lock
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse

from .dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from .hub import integration_plan
from .reference import IanaBundle, ReferenceDataError, load_iana
from .storage import StorageSchemaError


MIN_REFRESH_SECONDS = 2
MAX_REFRESH_SECONDS = 300
MAX_EVENT_LIMIT = 200
DASHBOARD_EVENT_FIELDS = ("detected_at", "rule_id", "severity", "src_ip", "message")
MAX_DASHBOARD_QUERY_LENGTH = 256
MAX_INTEGRATION_WORKFLOWS = 8
MAX_INTEGRATION_RESPONSE_BYTES = 32 * 1024
MAX_INTEGRATION_FIELD_LENGTH = 512
MAX_REFERENCE_QUERY_LENGTH = 256
MAX_REFERENCE_RESPONSE_BYTES = 64 * 1024
MAX_REFERENCE_CACHE_ENTRIES = 16
MAX_REFERENCE_MATCHES = 8
REFERENCE_BUNDLE_VERSION = "v1"
REFERENCE_WARNING = (
    "Registration is analyst context, not proof of what was observed or whether an endpoint "
    "is safe or malicious."
)


class DashboardReader(Protocol):
    def summary(self) -> dict[str, Any]: ...

    def recent(self, limit: int = 50) -> list[dict[str, Any]]: ...


class ReferenceLookupError(ValueError):
    """A fixed, path-free diagnostic for the dashboard reference surface."""


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
    reference_library: ReferenceLibrary | None = None
    refresh_seconds: int = 5
    event_limit: int = 50

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
            self._send(200, "text/javascript; charset=utf-8", DASHBOARD_JS.encode())
            return
        if route.path in {"/api/config", "/api/summary", "/api/offline-summary", "/api/reference/status"} and route.query:
            self._send_json({"error": "unsupported query parameter"}, status=400)
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
        if route.path == "/api/offline-summary":
            self._send_json(
                {"available": False} if self.offline_summary is None
                else {"available": True, "snapshot": self.offline_summary}
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
        self._send_json({"error": "method not allowed"}, status=405, extra_headers={"Allow": "GET"})

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
            "frame-ancestors 'none'; form-action 'none'; worker-src 'none'",
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


def serve(
    store: DashboardReader, host: str, port: int, *, enabled: bool = True,
    allow_remote: bool = False, offline_summary: dict[str, Any] | None = None,
    reference_library: ReferenceLibrary | None = None,
    refresh_seconds: int = 5, event_limit: int = 50,
) -> None:
    if not enabled:
        raise ValueError("dashboard is disabled by configuration")
    refresh_seconds = _bounded_dashboard_integer(
        refresh_seconds, "dashboard refresh_seconds", MIN_REFRESH_SECONDS, MAX_REFRESH_SECONDS
    )
    event_limit = _bounded_dashboard_integer(event_limit, "dashboard event_limit", 1, MAX_EVENT_LIMIT)
    host = loopback_host(host, allow_remote=allow_remote)
    handler = type(
        "BoundDashboardHandler", (DashboardHandler,), {
            "store": store, "offline_summary": offline_summary,
            "reference_library": reference_library, "refresh_seconds": refresh_seconds,
            "event_limit": event_limit,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    try:
        print(f"MEGALODON dashboard listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
