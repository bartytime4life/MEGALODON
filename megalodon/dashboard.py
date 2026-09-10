"""Local read-only dashboard. It exposes telemetry, never control actions."""

from __future__ import annotations

from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import AddressValueError, IPv4Address
import json
from threading import Lock
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse

from .reference import IanaBundle, ReferenceDataError, load_iana
from .storage import StorageSchemaError


MIN_REFRESH_SECONDS = 2
MAX_REFRESH_SECONDS = 300
MAX_EVENT_LIMIT = 200
DASHBOARD_EVENT_FIELDS = ("detected_at", "rule_id", "severity", "src_ip", "message")
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
    small LRU-like cache of exact manual lookups is retained.  The cache is a
    performance detail, not a persistence or detection store.
    """

    def __init__(
        self,
        bundle: IanaBundle | Any | None = None,
        *,
        failure: str | None = None,
    ) -> None:
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
            # Do not expose loader detail or a filesystem/resource path to the
            # browser.  The fixed category remains useful to an operator.
            detail = str(exc)
            category = "integrity_failure" if any(
                token in detail
                for token in (
                    "INTEGRITY",
                    "MANIFEST",
                    "ARTIFACT",
                    "RESOURCE_SET",
                    "ROW_COUNT",
                    "ORDER_OR_DUPLICATE",
                )
            ) else "unavailable"
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
        if (
            transport not in {"tcp", "udp", "sctp", "dccp"}
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
            item
            for item in bundle.services
            if item.transport == transport and item.port_start <= port <= item.port_end
        ]
        result = self._result(
            "port",
            all_matches,
            bundle,
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
            item
            for item in bundle.protocols
            if item.decimal_start <= number <= item.decimal_end
        ]
        result = self._result(
            "protocol",
            all_matches,
            bundle,
            query={"number": number},
            source_ids=("iana-protocol-numbers",),
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
        self,
        kind: str,
        all_matches: list[Any],
        bundle: Any,
        *,
        query: dict[str, object],
        source_ids: tuple[str, ...],
    ) -> dict[str, object]:
        matches = all_matches[:MAX_REFERENCE_MATCHES]
        status = (
            "no_match"
            if not all_matches
            else "one_match"
            if len(all_matches) == 1
            else "multiple_matches"
        )
        sources = [
            source
            for source in self._sources(bundle)
            if source.get("id") in source_ids
        ]
        result = {
            "schema": "reference-library-lookup-v1",
            "status": status,
            "available": True,
            "kind": kind,
            "bundle_id": bundle.bundle_id,
            "bundle_version": REFERENCE_BUNDLE_VERSION,
            "manifest_sha256": bundle.manifest_sha256,
            "query": query,
            "match_count": len(all_matches),
            "matches": [item.public() for item in matches],
            "truncated": len(all_matches) > len(matches),
            "sources": sources,
            "warning": bundle.warning or REFERENCE_WARNING,
            "network_access_performed": False,
            "persistence_status": "not_attempted",
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


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>MEGALODON · Local telemetry</title>
  <link rel="stylesheet" href="/assets/dashboard.css">
  <script src="/assets/dashboard.js" defer></script>
</head>
<body>
<a class="skip-link" href="#detections-title">Skip to detections</a>
<main class="shell">
  <header class="topbar">
    <div class="brand" aria-label="MEGALODON">
      <div class="mark" aria-hidden="true">M</div>
      <div><p class="brand-name">MEGALODON</p><p class="brand-subtitle">Local defense telemetry</p></div>
    </div>
    <div class="connection" id="connection">Dashboard API · connecting</div>
  </header>

  <section class="hero" aria-labelledby="page-title">
    <div>
      <p class="eyebrow">Operational overview</p>
      <h1 id="page-title">Signal without surrendering control.</h1>
      <p class="lede">Review local metadata detections and one explicitly selected offline analysis snapshot. This surface cannot start analysis or apply a response.</p>
    </div>
    <div class="read-only">HTTP read only · loopback only</div>
  </section>

  <section class="trust-strip waiting" id="trust-strip" aria-labelledby="trust-title">
    <div class="trust-summary">
      <p class="eyebrow" id="trust-title">Operator trust status</p>
      <p class="trust-message" id="snapshot-status" role="status" aria-live="polite" aria-atomic="true">No successful dashboard data fetch yet. Dashboard API reachability does not measure capture or ingestion health.</p>
    </div>
    <dl class="trust-facts">
      <div><dt>Detection scope</dt><dd id="scope-status">Newest 50 detections maximum</dd></div>
      <div><dt>Response boundary</dt><dd>Review only · no live application</dd></div>
    </dl>
  </section>

  <section class="panel reference-panel" aria-labelledby="reference-title">
    <div class="panel-head">
      <div><h2 id="reference-title">Reference Library</h2><p>Manual context lookup against the installed, manifest-verified IANA snapshot. It never classifies traffic or changes stored records.</p></div>
      <span class="timestamp" id="reference-bundle-label">Loading pinned snapshot…</span>
    </div>
    <div class="reference-warning" role="note">
      Registration is analyst context, not proof of what was observed or whether an endpoint is safe or malicious.
    </div>
    <div class="reference-grid">
      <form class="reference-form" id="reference-port-form">
        <h3>Service and port</h3>
        <p>Look up one normalized transport and decimal port.</p>
        <label class="field" for="reference-transport"><span>Transport</span>
          <select id="reference-transport">
            <option value="tcp">TCP</option><option value="udp">UDP</option><option value="sctp">SCTP</option><option value="dccp">DCCP</option>
          </select>
        </label>
        <label class="field" for="reference-port"><span>Port</span>
          <input id="reference-port" name="port" type="text" inputmode="numeric" autocomplete="off" maxlength="5" pattern="[0-9]{1,5}" placeholder="443" required>
        </label>
        <button type="submit">Look up service</button>
      </form>
      <form class="reference-form" id="reference-protocol-form">
        <h3>IP protocol number</h3>
        <p>Look up one decimal protocol number from 0 through 255.</p>
        <label class="field" for="reference-protocol"><span>Number</span>
          <input id="reference-protocol" name="number" type="text" inputmode="numeric" autocomplete="off" maxlength="3" pattern="[0-9]{1,3}" placeholder="6" required>
        </label>
        <button type="submit">Look up protocol</button>
      </form>
    </div>
    <p class="reference-status" id="reference-status" role="status" aria-live="polite" aria-atomic="true">Loading the verified reference snapshot…</p>
    <div class="reference-result" id="reference-result" aria-live="polite" aria-atomic="true">
      <p class="reference-empty" id="reference-empty">Enter a value to inspect registration context.</p>
      <div id="reference-meta" hidden></div>
      <div id="reference-results" hidden></div>
    </div>
  </section>

  <section class="metrics" id="live-metrics" aria-label="Stored telemetry summary">
    <article class="metric"><div class="metric-label">Events</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">Detections</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">High / critical stored</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">Action records</div><div class="metric-value">—</div></article>
  </section>

  <section class="panel" id="triage-panel" aria-labelledby="detections-title" aria-busy="true">
    <div class="panel-head">
      <div><h2 id="detections-title">Recent detection triage</h2><p>Bounded local review of returned fixed-rule findings. Filters and timeline do not change stored data.</p></div>
      <time class="timestamp" id="updated">Awaiting first refresh</time>
    </div>
    <div class="priority-pulse" aria-labelledby="priority-title">
      <div>
        <p class="eyebrow" id="priority-title">Stored priority counter</p>
        <p class="priority-change" id="priority-change">Waiting for the first successful summary fetch.</p>
      </div>
      <p class="priority-boundary">Sequential count-change signal only · not unique alerts, incident state, or capture health</p>
      <p class="sr-only" id="priority-announcement" aria-live="polite" aria-atomic="true"></p>
    </div>
    <fieldset class="toolbar" id="triage-controls" disabled>
      <legend class="sr-only">Detection triage filters and refresh controls</legend>
      <label class="field field-search" for="filter-query">
        <span>Search detections</span>
        <input id="filter-query" type="search" maxlength="160" autocomplete="off" placeholder="Rule, source, or message">
      </label>
      <label class="field" for="filter-severity">
        <span>Review priority</span>
        <select id="filter-severity">
          <option value="ALL">All priorities</option>
          <option value="PRIORITY">High + critical</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </label>
      <label class="field" for="filter-rule">
        <span>Rule</span>
        <select id="filter-rule"><option value="">All rules</option></select>
      </label>
      <div class="toolbar-actions">
        <button id="clear-filters" type="button" class="button-secondary">Clear filters</button>
        <button id="refresh-button" type="button">Refresh now</button>
        <button id="pause-button" type="button" class="button-secondary" aria-pressed="false">Pause refresh</button>
      </div>
      <p class="filter-status" id="filter-status" role="status" aria-live="polite">Waiting for recent detections.</p>
    </fieldset>
    <div class="triage-summary" role="group" aria-label="Returned detection view summary">
      <span class="summary-chip" id="returned-status">No returned rows yet</span>
      <span class="summary-chip" id="priority-status">Priority rows unavailable</span>
      <span class="summary-chip" id="rule-status">Rule count unavailable</span>
    </div>
    <section class="timeline-section" aria-labelledby="timeline-title">
      <div class="timeline-head">
        <div><h3 id="timeline-title">Detection timing</h3><p>Up to 12 chronological bins from valid timestamps in the returned, non-time-filtered view.</p></div>
        <button id="clear-time-filter" type="button" class="button-secondary" hidden>Clear time filter</button>
      </div>
      <div class="timeline" id="timeline" role="group" aria-label="Filter detections by returned timestamp range"></div>
      <p class="timeline-status" id="timeline-status" role="status" aria-live="polite">Waiting for returned timestamps.</p>
    </section>
    <p class="sr-only" id="table-scroll-help">The recent detections table may scroll horizontally on narrow screens.</p>
    <div class="table-scroll" role="region" aria-label="Scrollable recent detections table" aria-describedby="table-scroll-help" tabindex="0">
      <table aria-describedby="filter-status">
        <caption>Recent MEGALODON detections</caption>
        <thead><tr><th scope="col">Time</th><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Source</th><th scope="col">Message</th></tr></thead>
        <tbody id="events"><tr><td class="empty" colspan="5">Loading local detections…</td></tr></tbody>
      </table>
    </div>
  </section>

  <section class="panel" aria-labelledby="offline-title">
    <div class="panel-head">
      <div><h2 id="offline-title">Offline analysis snapshot</h2><p>Validated, source-qualified, privacy-bounded summary loaded once at dashboard startup.</p></div>
      <span class="timestamp" id="offline-status">Checking</span>
    </div>
    <div class="offline-empty" id="offline-empty" hidden>
      No offline run is selected. Restart with <code>megalodon dashboard --offline-run /absolute/private/run</code> to view one completed report snapshot.
    </div>
    <div class="offline-grid" id="offline-content" hidden>
      <div class="offline-main">
        <p class="eyebrow" id="offline-case">Offline run</p>
        <div class="run-id" id="offline-run-id"></div>
        <div class="facts" id="offline-facts"></div>
        <h3 class="subhead">Protocol distribution</h3><div class="bars" id="protocols"></div>
        <h3 class="subhead">Top destination ports</h3><div class="chips" id="ports"></div>
      </div>
      <aside class="offline-side" aria-label="Offline review context">
        <h3 class="subhead">Review candidates</h3><ul class="candidate-list" id="candidates"></ul>
        <h3 class="subhead">Interpretation limits</h3><ul class="limitations" id="limitations"></ul>
      </aside>
    </div>
  </section>
  <p class="sr-only" id="refresh-announcement" aria-live="polite"></p>
  <noscript><p class="offline-empty">JavaScript is required to render this local dashboard.</p></noscript>
</main>
</body>
</html>"""


DASHBOARD_CSS = """
:root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --bg: #061017; --surface: rgba(13, 31, 42, .88); --line: rgba(148, 188, 202, .18);
  --text: #e8f4f5; --muted: #99b2ba; --aqua: #51e6cf; --cyan: #6ed8ff;
  --amber: #ffd166; --orange: #ff9f68; --rose: #ff758f; --radius: 18px;
  --shadow: 0 24px 70px rgba(0, 0, 0, .28);
}
* { box-sizing: border-box; }
body {
  margin: 0; min-width: 300px; min-height: 100vh; color: var(--text);
  background: radial-gradient(circle at 12% -8%, rgba(32, 151, 166, .22), transparent 34rem),
              radial-gradient(circle at 92% 8%, rgba(48, 103, 161, .18), transparent 30rem), var(--bg);
}
body::before {
  position: fixed; inset: 0; pointer-events: none; content: ""; opacity: .16;
  background-image: linear-gradient(rgba(132, 196, 207, .12) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(132, 196, 207, .12) 1px, transparent 1px);
  background-size: 42px 42px; mask-image: linear-gradient(to bottom, black, transparent 72%);
}
:focus-visible { outline: 3px solid var(--cyan); outline-offset: 3px; }
.skip-link { position: fixed; z-index: 10; top: 10px; left: 10px; padding: 9px 12px; transform: translateY(-160%); border-radius: 9px; background: var(--text); color: var(--bg); font-weight: 800; }
.skip-link:focus { transform: translateY(0); }
.shell { position: relative; width: min(1240px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 48px; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 34px; }
.brand { display: flex; align-items: center; gap: 13px; }
.mark {
  display: grid; width: 46px; height: 46px; place-items: center; color: var(--aqua);
  border: 1px solid rgba(81, 230, 207, .42); border-radius: 15px;
  background: linear-gradient(145deg, rgba(81, 230, 207, .2), rgba(110, 216, 255, .05));
  box-shadow: inset 0 1px rgba(255, 255, 255, .1), 0 10px 28px rgba(25, 164, 157, .12);
  font-weight: 900; letter-spacing: -.08em;
}
.brand-name { margin: 0; font-size: 1.05rem; letter-spacing: .13em; }
.brand-subtitle { margin: 3px 0 0; color: var(--muted); font-size: .78rem; }
.connection {
  display: inline-flex; align-items: center; gap: 8px; min-height: 36px; padding: 7px 12px;
  border: 1px solid var(--line); border-radius: 999px; background: rgba(4, 14, 20, .56);
  color: var(--muted); font-size: .78rem; font-weight: 700;
}
.connection::before { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); content: ""; }
.connection.ok::before { background: var(--aqua); box-shadow: 0 0 0 5px rgba(81, 230, 207, .1); }
.connection.error::before { background: var(--rose); box-shadow: 0 0 0 5px rgba(255, 117, 143, .1); }
.hero { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: 24px; margin-bottom: 24px; }
.eyebrow { margin: 0 0 9px; color: var(--aqua); font-size: .75rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
h1 { max-width: 760px; margin: 0; font-size: clamp(2rem, 5vw, 4.25rem); line-height: .98; letter-spacing: -.055em; }
.lede { max-width: 720px; margin: 16px 0 0; color: var(--muted); font-size: clamp(.95rem, 1.7vw, 1.08rem); line-height: 1.65; }
.read-only {
  align-self: start; padding: 12px 15px; border: 1px solid rgba(81, 230, 207, .25);
  border-radius: 14px; background: rgba(81, 230, 207, .07); color: #b7fff2;
  font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; white-space: nowrap;
}
.trust-strip {
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(330px, .65fr); gap: 18px;
  align-items: center; margin: 24px 0 12px; padding: 16px 18px; border: 1px solid var(--line);
  border-left: 4px solid var(--muted); border-radius: 15px; background: rgba(5, 18, 25, .62);
  box-shadow: 0 16px 42px rgba(0, 0, 0, .18);
}
.trust-strip.current { border-left-color: var(--aqua); }
.trust-strip.paused, .trust-strip.checking { border-left-color: var(--amber); background: rgba(255, 209, 102, .035); }
.trust-strip.stale { border-left-color: var(--rose); background: rgba(255, 117, 143, .04); }
.trust-summary .eyebrow { margin-bottom: 6px; }
.trust-message { margin: 0; color: var(--text); font-size: .82rem; line-height: 1.55; }
.trust-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; margin: 0; }
.trust-facts div { padding: 10px 11px; border: 1px solid var(--line); border-radius: 11px; background: rgba(3, 13, 19, .42); }
.trust-facts dt { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.trust-facts dd { margin: 5px 0 0; color: #d8ebee; font-size: .78rem; font-weight: 750; line-height: 1.35; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 12px 0 28px; }
.metric, .panel {
  border: 1px solid var(--line); background: linear-gradient(145deg, rgba(18, 45, 59, .92), rgba(8, 24, 33, .9));
  box-shadow: var(--shadow);
}
.metric { min-height: 128px; padding: 18px; border-radius: var(--radius); }
.metric-label { color: var(--muted); font-size: .75rem; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
.metric-value { margin-top: 18px; font-size: clamp(1.8rem, 4vw, 2.65rem); font-variant-numeric: tabular-nums; font-weight: 800; letter-spacing: -.04em; }
.metric-note { margin-top: 5px; color: var(--muted); font-size: .76rem; }
.panel { overflow: hidden; border-radius: var(--radius); }
.panel + .panel { margin-top: 18px; }
.panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px 22px; border-bottom: 1px solid var(--line); }
.panel-head h2 { margin: 0; font-size: 1rem; letter-spacing: -.01em; }
.panel-head p { margin: 6px 0 0; color: var(--muted); font-size: .82rem; line-height: 1.5; }
.timestamp { color: var(--muted); font-size: .75rem; white-space: nowrap; }
.priority-pulse { display: flex; align-items: center; justify-content: space-between; gap: 18px; padding: 14px 22px; border-bottom: 1px solid var(--line); background: rgba(81, 230, 207, .035); }
.priority-pulse .eyebrow { margin-bottom: 5px; }
.priority-change { margin: 0; color: var(--text); font-size: .86rem; font-weight: 800; line-height: 1.45; }
.priority-boundary { max-width: 510px; margin: 0; color: var(--muted); font-size: .72rem; line-height: 1.5; text-align: right; }
.toolbar { display: grid; grid-template-columns: minmax(210px, 1fr) repeat(2, minmax(145px, .42fr)) auto; align-items: end; gap: 12px; min-width: 0; margin: 0; padding: 16px 22px; border: 0; border-bottom: 1px solid var(--line); background: rgba(4, 15, 21, .26); }
.toolbar:disabled { opacity: .76; }
.field { display: grid; gap: 7px; }
.field span { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
input, select, button { min-height: 42px; border: 1px solid var(--line); border-radius: 11px; font: inherit; }
input, select { width: 100%; padding: 9px 11px; background: rgba(3, 13, 19, .68); color: var(--text); }
input::placeholder { color: #6f8c95; }
button { padding: 9px 13px; border-color: rgba(81, 230, 207, .34); background: rgba(81, 230, 207, .13); color: #c8fff7; font-size: .78rem; font-weight: 800; cursor: pointer; }
button:hover:not(:disabled) { background: rgba(81, 230, 207, .2); }
button:disabled { opacity: .55; cursor: wait; }
.button-secondary { border-color: var(--line); background: rgba(110, 216, 255, .05); color: #c9e9f0; }
.button-secondary[aria-pressed="true"] { border-color: rgba(255, 209, 102, .4); background: rgba(255, 209, 102, .09); color: var(--amber); }
.toolbar-actions { display: flex; gap: 8px; }
.filter-status { grid-column: 1 / -1; margin: 0; color: var(--muted); font-size: .75rem; }
.triage-summary { display: flex; flex-wrap: wrap; gap: 8px; padding: 13px 22px 0; }
.summary-chip { padding: 6px 9px; border: 1px solid var(--line); border-radius: 999px; background: rgba(110, 216, 255, .045); color: #c9e9f0; font-size: .7rem; font-weight: 750; }
.timeline-section { padding: 14px 22px 18px; border-bottom: 1px solid var(--line); }
.timeline-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; }
.timeline-head h3 { margin: 0; font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; }
.timeline-head p { margin: 5px 0 0; color: var(--muted); font-size: .72rem; line-height: 1.45; }
.timeline { display: grid; grid-template-columns: repeat(auto-fit, minmax(54px, 1fr)); align-items: end; gap: 6px; min-height: 94px; margin-top: 13px; }
.timeline-bin { display: grid; grid-template-rows: 54px auto; align-items: end; gap: 6px; min-width: 0; min-height: 82px; padding: 6px; border-color: var(--line); background: rgba(110, 216, 255, .035); color: var(--muted); }
.timeline-bin:hover:not(:disabled) { background: rgba(110, 216, 255, .09); }
.timeline-bin[aria-pressed="true"] { border-color: var(--aqua); background: rgba(81, 230, 207, .14); color: var(--text); }
.timeline-bar { display: block; width: 100%; border-radius: 6px 6px 3px 3px; background: var(--cyan); opacity: .78; }
.timeline-bar.level-0 { height: 0; }
.timeline-bar:not(.level-0) { min-height: 5px; }
.timeline-bar.level-1 { height: 10%; } .timeline-bar.level-2 { height: 20%; } .timeline-bar.level-3 { height: 30%; }
.timeline-bar.level-4 { height: 40%; } .timeline-bar.level-5 { height: 50%; } .timeline-bar.level-6 { height: 60%; }
.timeline-bar.level-7 { height: 70%; } .timeline-bar.level-8 { height: 80%; } .timeline-bar.level-9 { height: 90%; } .timeline-bar.level-10 { height: 100%; }
.timeline-count { overflow: hidden; font-size: .68rem; font-variant-numeric: tabular-nums; font-weight: 850; text-overflow: ellipsis; }
.timeline-status { margin: 9px 0 0; color: var(--muted); font-size: .72rem; line-height: 1.45; }
.table-scroll { overflow-x: auto; scrollbar-color: var(--muted) rgba(3, 13, 19, .42); }
.table-scroll:focus-visible { outline-offset: -3px; }
table { width: 100%; border-collapse: collapse; }
caption { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
th, td { padding: 13px 16px; border-bottom: 1px solid rgba(148, 188, 202, .12); overflow-wrap: anywhere; text-align: left; font-size: .82rem; vertical-align: top; }
th { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .09em; text-transform: uppercase; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(110, 216, 255, .035); }
.empty { padding: 34px 20px; color: var(--muted); text-align: center; }
.severity { display: inline-flex; padding: 4px 8px; border: 1px solid currentColor; border-radius: 999px; font-size: .68rem; font-weight: 850; letter-spacing: .04em; }
.CRITICAL { color: var(--rose); } .HIGH { color: var(--orange); } .MEDIUM { color: var(--amber); } .LOW { color: var(--cyan); } .UNKNOWN { color: var(--muted); }
.offline-grid { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(280px, .9fr); }
.offline-main, .offline-side { padding: 22px; }
.offline-side { border-left: 1px solid var(--line); background: rgba(4, 15, 21, .32); }
.run-id { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .72rem; word-break: break-all; }
.facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 18px; }
.fact { padding: 12px; border: 1px solid var(--line); border-radius: 13px; background: rgba(5, 18, 25, .48); }
.fact b { display: block; margin-top: 5px; font-size: .92rem; word-break: break-word; }
.fact span { color: var(--muted); font-size: .68rem; font-weight: 750; letter-spacing: .06em; text-transform: uppercase; }
.subhead { margin: 24px 0 11px; font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.bars { display: grid; gap: 10px; }
.bar-row { display: grid; grid-template-columns: 58px minmax(80px, 1fr) auto; align-items: center; gap: 10px; font-size: .78rem; }
progress { width: 100%; height: 8px; overflow: hidden; border: 0; border-radius: 999px; background: rgba(148, 188, 202, .12); }
progress::-webkit-progress-bar { border-radius: 999px; background: rgba(148, 188, 202, .12); }
progress::-webkit-progress-value { border-radius: 999px; background: linear-gradient(90deg, var(--aqua), var(--cyan)); }
progress::-moz-progress-bar { border-radius: 999px; background: linear-gradient(90deg, var(--aqua), var(--cyan)); }
.chips { display: flex; flex-wrap: wrap; gap: 7px; }
.chip { padding: 6px 9px; border: 1px solid var(--line); border-radius: 999px; background: rgba(110, 216, 255, .05); color: #c9e9f0; font: 700 .72rem ui-monospace, SFMono-Regular, Menlo, monospace; }
.candidate-list, .limitations { display: grid; gap: 9px; margin: 0; padding: 0; list-style: none; }
.candidate-list li { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 11px 12px; border: 1px solid rgba(255, 209, 102, .2); border-radius: 12px; background: rgba(255, 209, 102, .045); font-size: .76rem; }
.candidate-list b { color: var(--amber); font-variant-numeric: tabular-nums; }
.limitations li { position: relative; padding-left: 17px; color: var(--muted); font-size: .76rem; line-height: 1.5; }
.limitations li::before { position: absolute; top: .53em; left: 0; width: 6px; height: 6px; border-radius: 50%; background: var(--cyan); content: ""; }
.offline-empty { padding: 28px 22px; color: var(--muted); font-size: .86rem; line-height: 1.65; }
.reference-warning { margin: 16px 22px 0; padding: 12px 14px; border: 1px solid rgba(255, 209, 102, .26); border-radius: 12px; background: rgba(255, 209, 102, .06); color: #ffe5a1; font-size: .78rem; line-height: 1.5; }
.reference-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 16px 22px 0; }
.reference-form { display: grid; align-content: start; gap: 10px; padding: 15px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .34); }
.reference-form h3 { margin: 0; font-size: .86rem; }
.reference-form p { min-height: 34px; margin: -3px 0 1px; color: var(--muted); font-size: .74rem; line-height: 1.45; }
.reference-form button { justify-self: start; }
.reference-status { margin: 16px 22px 0; color: var(--muted); font-size: .78rem; line-height: 1.5; }
.reference-status.ready { color: var(--aqua); }
.reference-status.empty { color: var(--muted); }
.reference-status.stale, .reference-status.integrity_failure, .reference-status.unavailable { color: var(--amber); }
.reference-result { margin: 12px 22px 22px; padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .28); }
.reference-empty { margin: 0; color: var(--muted); font-size: .78rem; }
.reference-meta { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 12px; }
.reference-meta .summary-chip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .68rem; }
.reference-records { display: grid; gap: 9px; margin: 0; padding: 0; list-style: none; }
.reference-record { display: grid; grid-template-columns: minmax(105px, .38fr) minmax(0, 1fr); gap: 12px; padding: 11px 12px; border: 1px solid var(--line); border-radius: 11px; background: rgba(110, 216, 255, .035); }
.reference-record dt { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
.reference-record dd { margin: 0; overflow-wrap: anywhere; font-size: .78rem; }
.reference-record dd + dt { margin-top: 6px; }
code { padding: 2px 5px; border: 1px solid var(--line); border-radius: 6px; background: rgba(0, 0, 0, .2); color: #c8f7ef; font-size: .85em; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
[hidden] { display: none !important; }
@media (max-width: 880px) {
  .hero { grid-template-columns: 1fr; } .read-only { justify-self: start; }
  .trust-strip { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .toolbar { grid-template-columns: minmax(0, 1fr) minmax(150px, .45fr); }
  .toolbar-actions { grid-column: 1 / -1; }
  .offline-grid { grid-template-columns: 1fr; }
  .offline-side { border-top: 1px solid var(--line); border-left: 0; }
  .reference-grid { grid-template-columns: 1fr; }
}
@media (max-width: 560px) {
  .shell { width: min(100% - 20px, 1240px); padding-top: 18px; }
  .topbar { align-items: flex-start; } .brand-subtitle { display: none; } .connection { max-width: 145px; }
  .trust-strip { padding: 14px; } .trust-facts { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: 1fr 1fr; } .metric { min-height: 108px; padding: 14px; }
  .panel-head { display: block; } .timestamp { display: block; margin-top: 7px; }
  .priority-pulse { display: block; padding: 14px; } .priority-boundary { margin-top: 8px; text-align: left; }
  .toolbar { grid-template-columns: 1fr; padding: 14px; }
  .toolbar-actions, .filter-status { grid-column: 1; }
  .toolbar-actions { display: grid; grid-template-columns: 1fr 1fr; }
  #clear-filters { grid-column: 1 / -1; }
  .triage-summary, .timeline-section { padding-right: 14px; padding-left: 14px; }
  .reference-warning, .reference-grid, .reference-status, .reference-result { margin-right: 14px; margin-left: 14px; }
  .reference-grid { padding-right: 0; padding-left: 0; }
  th, td { padding: 11px 12px; } .facts { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; } }
@media (forced-colors: active) {
  .timeline-bin[aria-pressed="true"] { border-width: 3px; }
  .timeline-bar { background: CanvasText; forced-color-adjust: none; }
}
"""


DASHBOARD_JS = r"""
'use strict';

const metricSpec = [
  ['events', 'Events', 'Validated metadata records'],
  ['detections', 'Detections', 'Fixed-rule findings'],
  ['high_or_critical', 'High / critical stored', 'Sequential stored count; not incident state'],
  ['actions', 'Action records', 'Audit decisions; no live application']
];
const summaryFields = ['actions', 'detections', 'events', 'high_or_critical'];
const eventFields = ['detected_at', 'message', 'rule_id', 'severity', 'src_ip'];
const knownSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const prioritySeverities = new Set(['CRITICAL', 'HIGH']);
const maxTimelineBins = 12;
const state = {
  events: [],
  activeBin: null,
  timelineBins: [],
  timelineNotice: '',
  lastPriorityTotal: null,
  paused: false,
  refreshing: false,
  timer: null,
  lastSuccessfulRefresh: null,
  lastRefreshFailed: false,
  configDegraded: false,
  config: {event_limit: 50, refresh_seconds: 5}
};
const referenceState = {
  available: null,
  status: 'loading',
  loading: false,
  lastResult: null,
  lastQuery: null
};
const referenceSourceFields = ['id', 'registry_url', 'registry_last_updated', 'retrieved_at', 'retrieved_at_basis'];
const referencePortFields = ['service_name', 'transport', 'port_start', 'port_end', 'record_kind', 'description', 'registration_date', 'modification_date', 'source_row'];
const referenceProtocolFields = ['keyword', 'protocol_name', 'decimal_start', 'decimal_end', 'record_kind', 'ipv6_extension_header', 'source_row'];

function byId(value) { return document.getElementById(value); }
function textNode(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = String(value);
  return node;
}
function formatNumber(value) { return new Intl.NumberFormat().format(Number(value)); }
const displayTimeFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  second: '2-digit', fractionalSecondDigits: 3, timeZoneName: 'short'
});
function displayTime(value) { return displayTimeFormatter.format(value); }
function timeNode(value) {
  const parsed = new Date(value);
  const node = textNode('time', Number.isNaN(parsed.valueOf()) ? String(value) : displayTime(parsed));
  if (!Number.isNaN(parsed.valueOf())) node.dateTime = parsed.toISOString();
  return node;
}
function severityPresentation(value) {
  const normalized = String(value || '').toUpperCase();
  return knownSeverities.has(normalized) ? normalized : 'UNKNOWN';
}
function validatedSummary(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid summary response');
  const keys = Object.keys(value).sort();
  if (keys.length !== summaryFields.length || !summaryFields.every((field, index) => keys[index] === field)) {
    throw new Error('invalid summary response');
  }
  if (!summaryFields.every(field => Number.isSafeInteger(value[field]) && value[field] >= 0)
      || value.high_or_critical > value.detections) {
    throw new Error('invalid summary response');
  }
  return value;
}
function validatedEvents(value) {
  if (!Array.isArray(value) || value.length > state.config.event_limit) throw new Error('invalid events response');
  const valid = value.every(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
    const keys = Object.keys(event).sort();
    if (keys.length !== eventFields.length || !eventFields.every((field, index) => keys[index] === field)) return false;
    return eventFields.every(field => typeof event[field] === 'string') && knownSeverities.has(event.severity);
  });
  if (!valid) throw new Error('invalid events response');
  return value;
}
async function requestJSON(path) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(path, {headers: {'Accept': 'application/json'}, cache: 'no-store', signal: controller.signal});
    if (!response.ok) {
      let payload = null;
      try { payload = await response.json(); } catch (_) {}
      const error = new Error(`request failed (${response.status})`);
      error.payload = payload;
      error.status = response.status;
      throw error;
    }
    return await response.json();
  } finally {
    window.clearTimeout(timeout);
  }
}

function renderMetrics(summary) {
  const cards = metricSpec.map(([key, label, note]) => {
    const card = document.createElement('article'); card.className = 'metric';
    card.append(textNode('div', label, 'metric-label'), textNode('div', formatNumber(summary[key]), 'metric-value'), textNode('div', note, 'metric-note'));
    return card;
  });
  byId('live-metrics').replaceChildren(...cards);
}
function hasActiveFilters() {
  return Boolean(
    byId('filter-query').value.trim()
    || byId('filter-severity').value !== 'ALL'
    || byId('filter-rule').value !== ''
    || state.activeBin !== null
  );
}
function baseFilteredEvents() {
  const severity = byId('filter-severity').value;
  const rule = byId('filter-rule').value;
  const query = byId('filter-query').value.trim().toLowerCase();
  return state.events.filter(event => {
    if (severity === 'PRIORITY' && !prioritySeverities.has(event.severity)) return false;
    if (severity !== 'ALL' && severity !== 'PRIORITY' && event.severity !== severity) return false;
    if (rule && event.rule_id !== rule) return false;
    if (!query) return true;
    return [event.detected_at, event.severity, event.rule_id, event.src_ip, event.message]
      .some(value => String(value || '').toLowerCase().includes(query));
  });
}
function buildTimeline(events) {
  const points = [];
  let invalidCount = 0;
  events.forEach((event, index) => {
    const timestamp = new Date(event.detected_at).valueOf();
    if (Number.isNaN(timestamp)) invalidCount += 1;
    else points.push({index, timestamp});
  });
  if (!points.length) return {bins: [], invalidCount};
  const oldest = Math.min(...points.map(point => point.timestamp));
  const newest = Math.max(...points.map(point => point.timestamp));
  const inclusiveSpan = newest - oldest + 1;
  const binCount = oldest === newest ? 1 : Math.min(maxTimelineBins, points.length, inclusiveSpan);
  const bins = Array.from({length: binCount}, (_, index) => ({
    start: oldest + Math.floor(inclusiveSpan * index / binCount),
    end: index === binCount - 1 ? newest : oldest + Math.floor(inclusiveSpan * (index + 1) / binCount) - 1,
    members: []
  }));
  points.forEach(point => {
    const index = oldest === newest
      ? 0
      : Math.min(binCount - 1, Math.ceil((((point.timestamp - oldest) + 1) / inclusiveSpan) * binCount) - 1);
    bins[index].members.push(point.index);
  });
  return {bins, invalidCount};
}
function timelineRange(bin) {
  const start = displayTime(new Date(bin.start));
  const end = displayTime(new Date(bin.end));
  return bin.start === bin.end ? start : `${start} to ${end}`;
}
function renderTimeline(model) {
  if (state.activeBin !== null && state.activeBin >= model.bins.length) state.activeBin = null;
  state.timelineBins = model.bins;
  const timeline = byId('timeline');
  const priorButtons = Array.from(timeline.children || []);
  const focusedIndex = priorButtons.indexOf(document.activeElement);
  const maximum = Math.max(1, ...model.bins.map(bin => bin.members.length));
  const buttons = model.bins.map((bin, index) => {
    const selected = state.activeBin === index;
    const count = bin.members.length;
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'timeline-bin';
    button.setAttribute('aria-pressed', String(selected));
    button.setAttribute('aria-label', `${count} returned detections from ${timelineRange(bin)}${selected ? '; selected' : ''}`);
    const level = count === 0 ? 0 : Math.max(1, Math.ceil((count / maximum) * 10));
    button.append(textNode('span', '', `timeline-bar level-${level}`), textNode('span', formatNumber(count), 'timeline-count'));
    button.addEventListener('click', () => {
      state.activeBin = selected ? null : index; state.timelineNotice = ''; applyFilters();
    });
    return button;
  });
  timeline.replaceChildren(...buttons);
  if (focusedIndex >= 0 && buttons.length) {
    const replacement = buttons[Math.min(focusedIndex, buttons.length - 1)];
    if (typeof replacement.focus === 'function') replacement.focus();
  }
  byId('clear-time-filter').hidden = state.activeBin === null;
  let status;
  if (!model.bins.length) status = 'No valid returned timestamps are available for the timeline.';
  else if (state.activeBin !== null) status = `Time filter selected: ${timelineRange(model.bins[state.activeBin])}.`;
  else status = `${formatNumber(model.bins.length)} chronological ${model.bins.length === 1 ? 'bin' : 'bins'} from the returned, non-time-filtered view.`;
  if (model.invalidCount) {
    status += ` ${formatNumber(model.invalidCount)} ${model.invalidCount === 1 ? 'row has' : 'rows have'} an invalid timestamp and ${model.invalidCount === 1 ? 'is' : 'are'} excluded from the timeline only.`;
  }
  if (state.timelineNotice) status += ` ${state.timelineNotice}`;
  if (byId('timeline-status').textContent !== status) byId('timeline-status').textContent = status;
}
function renderRuleOptions() {
  const select = byId('filter-rule');
  const selected = select.value;
  const rules = [...new Set(state.events.map(event => event.rule_id))]
    .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  const all = textNode('option', 'All rules'); all.value = '';
  const options = [];
  if (selected && !rules.includes(selected)) {
    const missing = textNode('option', `${selected} (not returned)`);
    missing.value = selected; missing.disabled = true; options.push(missing);
  }
  options.push(...rules.map(rule => { const option = textNode('option', rule); option.value = rule; return option; }));
  select.replaceChildren(all, ...options);
  select.value = selected;
}
function sameEvents(left, right) {
  return left.length === right.length && left.every((event, index) =>
    eventFields.every(field => event[field] === right[index][field])
  );
}
function renderReturnedSummary() {
  const count = state.events.length;
  byId('returned-status').textContent = count === state.config.event_limit
    ? `${formatNumber(count)} returned · configured maximum; older rows may be omitted`
    : `${formatNumber(count)} returned · ${formatNumber(state.config.event_limit)} configured maximum`;
  const priority = state.events.filter(event => prioritySeverities.has(event.severity)).length;
  byId('priority-status').textContent = `${formatNumber(priority)} high / critical ${priority === 1 ? 'row' : 'rows'} in returned set`;
  const rules = new Set(state.events.map(event => event.rule_id)).size;
  byId('rule-status').textContent = `${formatNumber(rules)} distinct ${rules === 1 ? 'rule' : 'rules'} in returned set`;
}
function updatePriorityChange(summary) {
  const current = summary.high_or_critical;
  const previous = state.lastPriorityTotal;
  let visible;
  let announcement = '';
  if (previous === null) visible = `Priority baseline established: ${formatNumber(current)} stored.`;
  else if (current > previous) {
    visible = `Stored high/critical count increased by ${formatNumber(current - previous)} to ${formatNumber(current)}.`;
    announcement = visible;
  } else if (current < previous) {
    visible = `Stored high/critical count decreased by ${formatNumber(previous - current)} to ${formatNumber(current)}.`;
    announcement = visible;
  } else visible = `No stored high/critical count change · ${formatNumber(current)} stored.`;
  if (byId('priority-change').textContent !== visible) byId('priority-change').textContent = visible;
  if (byId('priority-announcement').textContent !== announcement) {
    byId('priority-announcement').textContent = announcement;
  }
  state.lastPriorityTotal = current;
}
function renderEvents(events) {
  const body = byId('events');
  if (!events.length) {
    const filtered = state.events.length && hasActiveFilters();
    const row = document.createElement('tr');
    const cell = textNode('td', filtered ? 'No detections match these filters.' : 'No detections recorded.', 'empty');
    cell.colSpan = 5; row.append(cell); body.replaceChildren(row); return;
  }
  const rows = events.map(event => {
    const row = document.createElement('tr');
    const timeCell = document.createElement('td');
    timeCell.append(timeNode(event.detected_at));
    const severityCell = document.createElement('td');
    const severity = severityPresentation(event.severity);
    severityCell.append(textNode('span', severity, `severity ${severity}`));
    row.append(timeCell, severityCell, textNode('td', event.rule_id || ''), textNode('td', event.src_ip || ''), textNode('td', event.message || ''));
    return row;
  });
  body.replaceChildren(...rows);
}
function renderInitialUnavailable() {
  const row = document.createElement('tr');
  const cell = textNode('td', 'Recent detections are unavailable until a complete dashboard refresh succeeds.', 'empty');
  cell.colSpan = 5; row.append(cell); byId('events').replaceChildren(row);
  const filterStatus = 'No successful dashboard data refresh is available.';
  if (byId('filter-status').textContent !== filterStatus) byId('filter-status').textContent = filterStatus;
  byId('returned-status').textContent = 'Returned rows unavailable';
  byId('priority-status').textContent = 'Priority rows unavailable';
  byId('rule-status').textContent = 'Rule count unavailable';
  byId('timeline').replaceChildren();
  const timelineStatus = 'No successful returned-timestamp set is available.';
  if (byId('timeline-status').textContent !== timelineStatus) byId('timeline-status').textContent = timelineStatus;
  byId('priority-change').textContent = 'Stored priority baseline unavailable; retry refresh.';
}
function applyFilters() {
  if (!state.lastSuccessfulRefresh) { renderInitialUnavailable(); return; }
  const base = baseFilteredEvents();
  const model = buildTimeline(base);
  renderTimeline(model);
  const visible = state.activeBin === null
    ? base
    : base.filter((_, index) => model.bins[state.activeBin].members.includes(index));
  renderEvents(visible);
  const noun = state.events.length === 1 ? 'detection' : 'detections';
  const status = `${formatNumber(visible.length)} of ${formatNumber(state.events.length)} returned ${noun} shown${hasActiveFilters() ? ' with active filters' : ''}.`;
  if (byId('filter-status').textContent !== status) byId('filter-status').textContent = status;
}
function clearFilters() {
  byId('filter-query').value = '';
  byId('filter-severity').value = 'ALL';
  byId('filter-rule').value = '';
  state.activeBin = null;
  state.timelineNotice = '';
  applyFilters();
}
function fact(label, value) {
  const item = document.createElement('div'); item.className = 'fact';
  item.append(textNode('span', label), textNode('b', value)); return item;
}
function renderOffline(payload) {
  const empty = byId('offline-empty');
  const content = byId('offline-content');
  const status = byId('offline-status');
  if (!payload.available) { empty.hidden = false; content.hidden = true; status.textContent = 'Not selected'; return; }
  const data = payload.snapshot, run = data.run, summary = data.summary;
  empty.hidden = true; content.hidden = false; status.textContent = 'Schema-checked startup snapshot';
  byId('offline-case').textContent = `${run.case_id} · ${run.record_kind} summary`;
  byId('offline-run-id').textContent = `Run ${run.run_id}`;
  byId('offline-facts').replaceChildren(
    fact('Accepted records', formatNumber(run.accepted_records)), fact('Review candidates', formatNumber(run.candidate_count)),
    fact('Source adapter', run.adapter), fact('Tool provenance', `${run.source} ${run.tool_version}`),
    fact('Relative window', `${formatNumber(summary.relative_window_minutes)} min`), fact('Metadata volume', `${formatNumber(summary.total_bytes)} bytes`)
  );
  const denominator = Math.max(summary.record_count, 1);
  const bars = summary.protocols.map(item => {
    const row = document.createElement('div'); row.className = 'bar-row';
    const progress = document.createElement('progress'); progress.max = denominator; progress.value = item.count;
    progress.setAttribute('aria-label', `${item.protocol}: ${item.count} of ${summary.record_count} records`);
    row.append(textNode('span', item.protocol), progress, textNode('b', formatNumber(item.count))); return row;
  });
  byId('protocols').replaceChildren(...(bars.length ? bars : [textNode('p', 'No accepted records.', 'offline-empty')]));
  const ports = summary.destination_ports.map(item => textNode('span', `${item.protocol}/${item.port} · ${item.count}`, 'chip'));
  if (summary.destination_ports_truncated) ports.push(textNode('span', `+${summary.destination_ports_total - summary.destination_ports.length} more`, 'chip'));
  byId('ports').replaceChildren(...(ports.length ? ports : [textNode('span', 'No TCP/UDP destination ports', 'chip')]));
  const candidates = data.candidates.map(item => {
    const entry = document.createElement('li');
    entry.append(textNode('span', item.rule.replaceAll('_', ' ')), textNode('b', formatNumber(item.count))); return entry;
  });
  if (!candidates.length) candidates.push(textNode('li', 'No review candidates in this run.'));
  byId('candidates').replaceChildren(...candidates);
  byId('limitations').replaceChildren(...data.limitations.map(value => textNode('li', value)));
}
function renderOfflineError() {
  byId('offline-content').hidden = true;
  const empty = byId('offline-empty'); empty.hidden = false;
  empty.textContent = 'The configured offline summary could not be loaded. Recent SQLite telemetry is checked separately.';
  byId('offline-status').textContent = 'Unavailable';
}
function setConnection(label, className) {
  const connection = byId('connection');
  const nextClass = className ? `connection ${className}` : 'connection';
  if (connection.textContent !== label) connection.textContent = label;
  if (connection.className !== nextClass) connection.className = nextClass;
}
function formatRefreshTime(value) { return value.toLocaleString(); }
function setUpdatedTime(label, value = null) {
  const updated = byId('updated'); updated.textContent = label;
  if (value) updated.dateTime = value.toISOString();
  else updated.removeAttribute('datetime');
}
function renderScope() {
  byId('scope-status').textContent = `Newest ${formatNumber(state.config.event_limit)} detections maximum${state.configDegraded ? ' · safe defaults' : ''}`;
}
function referenceExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}
function validatedReferenceSources(value) {
  if (!Array.isArray(value) || value.length > 2) throw new Error('invalid reference sources');
  value.forEach(source => {
    if (!source || typeof source !== 'object' || Array.isArray(source) || !referenceExactKeys(source, referenceSourceFields)) {
      throw new Error('invalid reference source');
    }
    referenceSourceFields.forEach(field => {
      if (typeof source[field] !== 'string' || source[field].length < 1 || source[field].length > 256) throw new Error('invalid reference source');
    });
  });
  return value;
}
function validatedReferenceStatus(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.schema !== 'string') throw new Error('invalid reference status');
  if (value.schema !== 'reference-library-status-v1' || typeof value.available !== 'boolean' || typeof value.status !== 'string') throw new Error('invalid reference status');
  if (!value.available) {
    if (!referenceExactKeys(value, ['schema', 'available', 'status', 'error', 'network_access_performed', 'persistence_status', 'action_status'])) throw new Error('invalid reference status');
    if (!['unavailable', 'integrity_failure'].includes(value.status) || typeof value.error !== 'string') throw new Error('invalid reference status');
    return value;
  }
  if (!referenceExactKeys(value, ['schema', 'available', 'status', 'bundle_id', 'bundle_version', 'manifest_sha256', 'service_records', 'protocol_records', 'cache_entries', 'cache_limit', 'sources', 'warning', 'network_access_performed', 'persistence_status', 'action_status'])) throw new Error('invalid reference status');
  if (value.status !== 'ready' || ![value.service_records, value.protocol_records, value.cache_entries, value.cache_limit].every(item => Number.isSafeInteger(item) && item >= 0) || value.cache_entries > value.cache_limit) throw new Error('invalid reference status');
  if (![value.bundle_id, value.bundle_version, value.manifest_sha256, value.warning].every(item => typeof item === 'string' && item.length > 0 && item.length <= 512)) throw new Error('invalid reference status');
  if (value.network_access_performed !== false || value.persistence_status !== 'not_attempted' || value.action_status !== 'not_attempted') throw new Error('invalid reference status');
  validatedReferenceSources(value.sources);
  return value;
}
function validatedReferenceResult(value) {
  const expected = ['schema', 'status', 'available', 'kind', 'bundle_id', 'bundle_version', 'manifest_sha256', 'query', 'match_count', 'matches', 'truncated', 'sources', 'warning', 'network_access_performed', 'persistence_status', 'action_status'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || !referenceExactKeys(value, expected)) throw new Error('invalid reference result');
  if (value.schema !== 'reference-library-lookup-v1' || value.available !== true || !['no_match', 'one_match', 'multiple_matches'].includes(value.status) || !['port', 'protocol'].includes(value.kind)) throw new Error('invalid reference result');
  if (![value.bundle_id, value.bundle_version, value.manifest_sha256, value.warning].every(item => typeof item === 'string' && item.length > 0 && item.length <= 512)) throw new Error('invalid reference result');
  if (!Number.isSafeInteger(value.match_count) || value.match_count < 0 || value.match_count > 20000 || !Array.isArray(value.matches) || value.matches.length > 8 || value.matches.length > value.match_count || typeof value.truncated !== 'boolean') throw new Error('invalid reference result');
  const queryKeys = value.kind === 'port' ? ['port', 'transport'] : ['number'];
  if (!value.query || typeof value.query !== 'object' || Array.isArray(value.query) || !referenceExactKeys(value.query, queryKeys)) throw new Error('invalid reference result');
  if (value.kind === 'port' && (typeof value.query.transport !== 'string' || !Number.isSafeInteger(value.query.port))) throw new Error('invalid reference result');
  if (value.kind === 'protocol' && !Number.isSafeInteger(value.query.number)) throw new Error('invalid reference result');
  const fields = value.kind === 'port' ? referencePortFields : referenceProtocolFields;
  value.matches.forEach(match => {
    if (!match || typeof match !== 'object' || Array.isArray(match) || !referenceExactKeys(match, fields)) throw new Error('invalid reference result');
    fields.forEach(field => {
      const item = match[field];
      if (item !== null && typeof item !== 'string' && !Number.isSafeInteger(item)) throw new Error('invalid reference result');
      if (typeof item === 'string' && item.length > 512) throw new Error('invalid reference result');
    });
  });
  validatedReferenceSources(value.sources);
  if (value.network_access_performed !== false || value.persistence_status !== 'not_attempted' || value.action_status !== 'not_attempted') throw new Error('invalid reference result');
  return value;
}
function setReferenceStatus(message, mode) {
  const node = byId('reference-status');
  const nextClass = `reference-status ${mode || 'empty'}`;
  if (node.textContent !== message) node.textContent = message;
  if (node.className !== nextClass) node.className = nextClass;
}
function setReferenceFormsEnabled(enabled) {
  ['reference-transport', 'reference-port', 'reference-protocol'].forEach(id => { byId(id).disabled = !enabled; });
  ['reference-port-form', 'reference-protocol-form'].forEach(id => {
    const form = byId(id);
    Array.from(form.children || []).forEach(child => { if ('disabled' in child) child.disabled = !enabled; });
  });
}
function referenceChip(label) {
  return textNode('span', label, 'summary-chip');
}
function renderReferenceMeta(result) {
  const meta = byId('reference-meta');
  const query = result.kind === 'port' ? `${result.query.transport}/${result.query.port}` : `IP protocol ${result.query.number}`;
  const sourceText = result.sources.map(source => `${source.id} · updated ${source.registry_last_updated}`).join(' · ');
  meta.replaceChildren(
    referenceChip(`${result.status.replaceAll('_', ' ')} · ${formatNumber(result.match_count)} registered`),
    referenceChip(`Bundle ${result.bundle_id} · ${result.bundle_version}`),
    referenceChip(query),
    referenceChip(sourceText || 'Pinned source provenance available in manifest')
  );
  meta.hidden = false;
}
function renderReferenceResult(result) {
  const empty = byId('reference-empty');
  const results = byId('reference-results');
  renderReferenceMeta(result);
  if (!result.matches.length) {
    empty.textContent = 'No registration matches this exact lookup. This does not show that the observed endpoint is unknown or unsafe.';
    empty.hidden = false; results.hidden = true; results.replaceChildren(); return;
  }
  empty.hidden = true; results.hidden = false;
  const fields = result.kind === 'port' ? referencePortFields : referenceProtocolFields;
  const labels = {
    service_name: 'Service', transport: 'Transport', port_start: 'Port start', port_end: 'Port end', record_kind: 'Record kind', description: 'Description', registration_date: 'Registered', modification_date: 'Modified', source_row: 'Source row',
    keyword: 'Keyword', protocol_name: 'Protocol', decimal_start: 'Number start', decimal_end: 'Number end', ipv6_extension_header: 'IPv6 extension header'
  };
  const rows = result.matches.map(match => {
    const item = document.createElement('li'); item.className = 'reference-record';
    const definition = document.createElement('dl');
    fields.forEach(field => {
      if (match[field] === null || match[field] === '') return;
      definition.append(textNode('dt', labels[field] || field), textNode('dd', match[field]));
    });
    item.append(definition); return item;
  });
  const list = document.createElement('ul'); list.className = 'reference-records'; list.replaceChildren(...rows);
  results.replaceChildren(list);
}
function renderReferenceUnavailable(payload, fallbackMode = 'unavailable') {
  const mode = payload && payload.status === 'integrity_failure' ? 'integrity_failure' : fallbackMode;
  const message = mode === 'integrity_failure'
    ? 'Reference Library integrity failure. Manual lookup is disabled; no partial records are shown.'
    : 'Reference Library is unavailable. Manual lookup is disabled until the verified snapshot can be loaded.';
  referenceState.available = false; referenceState.status = mode; setReferenceFormsEnabled(false); setReferenceStatus(message, mode);
  byId('reference-bundle-label').textContent = mode === 'integrity_failure' ? 'Integrity failure' : 'Unavailable';
  byId('reference-empty').textContent = message; byId('reference-empty').hidden = false;
  byId('reference-meta').hidden = true; byId('reference-results').hidden = true; byId('reference-results').replaceChildren();
}
async function loadReferenceStatus() {
  try {
    const payload = validatedReferenceStatus(await requestJSON('/api/reference/status'));
    if (!payload.available) { renderReferenceUnavailable(payload, payload.status); return; }
    referenceState.available = true; referenceState.status = 'ready'; setReferenceFormsEnabled(true);
    byId('reference-bundle-label').textContent = `IANA ${payload.bundle_version} · ${payload.bundle_id}`;
    setReferenceStatus('Pinned IANA snapshot ready. Enter one value for a read-only context lookup.', 'ready');
  } catch (error) {
    renderReferenceUnavailable(error.payload, error.payload && error.payload.status ? error.payload.status : 'unavailable');
  }
}
function decimalReferenceInput(value, maximum) {
  const text = String(value);
  if (!/^[0-9]+$/.test(text) || text.length > String(maximum).length || String(Number(text)) !== text || Number(text) > maximum) throw new Error('invalid reference input');
  return Number(text);
}
async function lookupReference(kind) {
  if (!referenceState.available || referenceState.loading) return;
  let query;
  try {
    if (kind === 'port') query = {transport: byId('reference-transport').value, port: decimalReferenceInput(byId('reference-port').value, 65535)};
    else query = {number: decimalReferenceInput(byId('reference-protocol').value, 255)};
  } catch (_) {
    setReferenceStatus(kind === 'port' ? 'Enter a normalized transport and a decimal port from 0 through 65535.' : 'Enter a decimal IP protocol number from 0 through 255.', 'empty');
    return;
  }
  referenceState.loading = true; setReferenceStatus('Loading one bounded reference result…', 'empty');
  const params = kind === 'port' ? `transport=${encodeURIComponent(query.transport)}&port=${query.port}` : `number=${query.number}`;
  try {
    const result = validatedReferenceResult(await requestJSON(`/api/reference/${kind}?${params}`));
    referenceState.lastResult = result; referenceState.lastQuery = query; renderReferenceResult(result);
    const suffix = result.truncated ? ' The returned rows are capped.' : '';
    setReferenceStatus(result.status === 'no_match' ? `No registration found for this exact ${kind} lookup.${suffix}` : `Reference context loaded: ${formatNumber(result.match_count)} ${result.match_count === 1 ? 'registration' : 'registrations'}.${suffix}`, result.status === 'no_match' ? 'empty' : 'ready');
  } catch (error) {
    if (error.payload && (error.payload.status === 'integrity_failure' || error.payload.status === 'unavailable')) {
      renderReferenceUnavailable(error.payload, error.payload.status); return;
    }
    if (referenceState.lastResult) {
      setReferenceStatus('Lookup failed. Showing the last successful reference result as stale; no new data was applied.', 'stale');
    } else {
      setReferenceStatus('Lookup failed. No reference result is available.', 'unavailable');
    }
  } finally { referenceState.loading = false; }
}
function setSnapshotStatus(mode) {
  const strip = byId('trust-strip');
  const status = byId('snapshot-status');
  const nextClass = `trust-strip ${mode}`;
  if (strip.className !== nextClass) strip.className = nextClass;
  const healthLimit = 'Dashboard API reachability does not measure capture or ingestion health.';
  let message;
  if (mode === 'current') {
    message = `Dashboard data fetched successfully. Last-success time is shown below. ${healthLimit}`;
    setUpdatedTime(`Data fetched ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
  } else if (mode === 'paused') {
    if (state.lastSuccessfulRefresh) {
      message = `Automatic refresh paused. Showing preserved dashboard data from the last successful fetch. ${healthLimit}`;
      setUpdatedTime(`Paused · last success ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
    } else {
      message = `Automatic refresh paused. No successful dashboard data fetch is available. ${healthLimit}`;
      setUpdatedTime('Paused · no dashboard data available');
    }
  } else if (mode === 'checking') {
    if (state.lastSuccessfulRefresh) {
      const priorState = state.lastRefreshFailed
        ? 'Preserved dashboard data remains stale until a refresh succeeds.'
        : 'Preserved dashboard data is not treated as current until a refresh succeeds.';
      message = `Refresh resumed. Checking the dashboard API. ${priorState} ${healthLimit}`;
      setUpdatedTime(`Checking · last success ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
    } else {
      message = `Refresh resumed. Checking the dashboard API. No successful dashboard data fetch is available. ${healthLimit}`;
      setUpdatedTime('Checking · no successful dashboard data yet');
    }
  } else if (mode === 'stale') {
    const pauseContext = state.paused ? ' Automatic refresh remains paused.' : '';
    if (state.lastSuccessfulRefresh) {
      message = `Refresh failed.${pauseContext} Showing preserved stale dashboard data from the last successful fetch. ${healthLimit}`;
      setUpdatedTime(`Stale · last success ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
    } else {
      message = `Refresh failed.${pauseContext} No successful dashboard data fetch is available. ${healthLimit}`;
      setUpdatedTime('No successful dashboard data available');
    }
  } else {
    message = `No successful dashboard data fetch yet. ${healthLimit}`;
    setUpdatedTime('No successful dashboard data yet');
  }
  if (status.textContent !== message) status.textContent = message;
}
function scheduleNext() {
  if (state.timer !== null) window.clearTimeout(state.timer);
  state.timer = null;
  if (state.paused) return;
  state.timer = window.setTimeout(async () => {
    if (!document.hidden) await refresh(false);
    scheduleNext();
  }, state.config.refresh_seconds * 1000);
}
async function refresh(announce = true) {
  if (state.refreshing) return;
  state.refreshing = true;
  byId('triage-panel').setAttribute('aria-busy', 'true');
  if (!state.lastSuccessfulRefresh) byId('triage-controls').disabled = true;
  const button = byId('refresh-button'); button.disabled = true; button.textContent = 'Refreshing…';
  try {
    const [summaryResult, eventsResult] = await Promise.allSettled([
      requestJSON('/api/summary'), requestJSON(`/api/events?limit=${state.config.event_limit}`)
    ]);
    if (summaryResult.status !== 'fulfilled' || eventsResult.status !== 'fulfilled') {
      throw new Error('dashboard refresh failed');
    }
    const summary = validatedSummary(summaryResult.value);
    const events = validatedEvents(eventsResult.value);
    if (state.activeBin !== null && !sameEvents(state.events, events)) {
      state.activeBin = null;
      state.timelineNotice = 'Returned rows changed; the prior time filter was cleared.';
    }
    state.events = events;
    state.lastSuccessfulRefresh = new Date();
    state.lastRefreshFailed = false;
    renderMetrics(summary); renderRuleOptions(); renderReturnedSummary(); applyFilters(); renderScope();
    updatePriorityChange(summary);
    setSnapshotStatus(state.paused ? 'paused' : 'current');
    setConnection(state.paused ? 'Dashboard API · reachable, refresh paused' : 'Dashboard API · reachable', 'ok');
    if (announce) byId('refresh-announcement').textContent = 'Dashboard data refreshed.';
  } catch (_) {
    state.lastRefreshFailed = true;
    if (!state.lastSuccessfulRefresh) renderInitialUnavailable();
    setConnection(state.paused ? 'Dashboard API · unavailable, refresh paused' : 'Dashboard API · unavailable', 'error');
    setSnapshotStatus('stale');
    if (announce) {
      byId('refresh-announcement').textContent = state.lastSuccessfulRefresh
        ? 'Dashboard refresh failed. Existing rows were preserved.'
        : 'Dashboard refresh failed. No prior dashboard data is available.';
    }
  } finally {
    state.refreshing = false; button.disabled = false; button.textContent = 'Refresh now';
    byId('triage-controls').disabled = false;
    byId('triage-panel').setAttribute('aria-busy', 'false');
  }
}
function togglePause() {
  state.paused = !state.paused;
  const button = byId('pause-button'); button.setAttribute('aria-pressed', String(state.paused));
  button.textContent = state.paused ? 'Resume refresh' : 'Pause refresh';
  if (state.paused) {
    if (state.lastRefreshFailed) {
      setConnection('Dashboard API · unavailable, refresh paused', 'error');
      setSnapshotStatus('stale');
    } else {
      const pausedLabel = state.lastSuccessfulRefresh
        ? 'Dashboard API · reachable, refresh paused'
        : 'Dashboard API · refresh paused before first snapshot';
      setConnection(pausedLabel, state.lastSuccessfulRefresh ? 'ok' : '');
      setSnapshotStatus('paused');
    }
  } else {
    setConnection('Dashboard API · checking', '');
    setSnapshotStatus('checking');
  }
  if (state.paused) scheduleNext();
  else { refresh(false); scheduleNext(); }
}
function applyConfig(payload) {
  if (payload.schema !== 'dashboard-config-v1' || payload.read_only !== true) throw new Error('invalid dashboard config');
  const eventLimit = Number(payload.event_limit), refreshSeconds = Number(payload.refresh_seconds);
  if (!Number.isInteger(eventLimit) || eventLimit < 1 || eventLimit > 200) throw new Error('invalid event limit');
  if (!Number.isInteger(refreshSeconds) || refreshSeconds < 2 || refreshSeconds > 300) throw new Error('invalid refresh interval');
  state.config = {event_limit: eventLimit, refresh_seconds: refreshSeconds};
  renderScope();
}
async function bootstrap() {
  try { applyConfig(await requestJSON('/api/config')); }
  catch (_) {
    state.configDegraded = true; renderScope();
    setConnection('Dashboard API · using safe defaults', 'error');
  }
  try { renderOffline(await requestJSON('/api/offline-summary')); }
  catch (_) { renderOfflineError(); }
  loadReferenceStatus();
  await refresh(false); scheduleNext();
}

function applyBaseFilters() { state.activeBin = null; state.timelineNotice = ''; applyFilters(); }
byId('filter-query').addEventListener('input', applyBaseFilters);
byId('filter-severity').addEventListener('change', applyBaseFilters);
byId('filter-rule').addEventListener('change', applyBaseFilters);
byId('clear-filters').addEventListener('click', clearFilters);
byId('clear-time-filter').addEventListener('click', () => { state.activeBin = null; state.timelineNotice = ''; applyFilters(); });
byId('refresh-button').addEventListener('click', () => refresh(true));
byId('pause-button').addEventListener('click', togglePause);
byId('reference-port-form').addEventListener('submit', event => { event.preventDefault(); lookupReference('port'); });
byId('reference-protocol-form').addEventListener('submit', event => { event.preventDefault(); lookupReference('protocol'); });
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !state.paused) { refresh(false); scheduleNext(); }
});
bootstrap();
"""


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
        route = urlparse(self.path)
        if route.path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            return
        if route.path == "/assets/dashboard.css":
            self._send(200, "text/css; charset=utf-8", DASHBOARD_CSS.encode())
            return
        if route.path == "/assets/dashboard.js":
            self._send(200, "text/javascript; charset=utf-8", DASHBOARD_JS.encode())
            return
        if route.path == "/api/config":
            self._send_json(
                {
                    "schema": "dashboard-config-v1",
                    "read_only": True,
                    "refresh_seconds": self.refresh_seconds,
                    "event_limit": self.event_limit,
                    "offline_summary_available": self.offline_summary is not None,
                }
            )
            return
        if route.path == "/api/summary":
            try:
                summary = self.store.summary()
            except StorageSchemaError:
                self._send_json(
                    {"error": "telemetry unavailable"}, status=503
                )
                return
            self._send_json(summary)
            return
        if route.path == "/api/events":
            params = parse_qs(route.query, keep_blank_values=True)
            if set(params) - {"limit"}:
                self._send_json({"error": "unsupported query parameter"}, status=400)
                return
            values = params.get("limit")
            if values is None:
                limit = self.event_limit
            elif len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
                self._send_json({"error": "limit must be one decimal integer"}, status=400)
                return
            else:
                limit = int(values[0])
            if not 1 <= limit <= MAX_EVENT_LIMIT:
                self._send_json({"error": f"limit must be between 1 and {MAX_EVENT_LIMIT}"}, status=400)
                return
            try:
                events = _dashboard_events(self.store, limit)
            except StorageSchemaError:
                self._send_json(
                    {"error": "telemetry unavailable"}, status=503
                )
                return
            self._send_json(events)
            return
        if route.path == "/api/offline-summary":
            self._send_json(
                {"available": False}
                if self.offline_summary is None
                else {"available": True, "snapshot": self.offline_summary}
            )
            return
        if route.path == "/api/reference/status":
            if route.query:
                self._send_json({"error": "unsupported query parameter"}, status=400)
                return
            library = self._reference_library()
            payload = library.status()
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
            payload = self._reference_library().lookup_port(transport, int(port_text))
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
            payload = self._reference_library().lookup_protocol(int(number_text))
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
        params = parse_qs(query, keep_blank_values=True)
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
        self,
        status: int,
        content_type: str,
        payload: bytes,
        *,
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
    store: DashboardReader,
    host: str,
    port: int,
    *,
    enabled: bool = True,
    allow_remote: bool = False,
    offline_summary: dict[str, Any] | None = None,
    reference_library: ReferenceLibrary | None = None,
    refresh_seconds: int = 5,
    event_limit: int = 50,
) -> None:
    if not enabled:
        raise ValueError("dashboard is disabled by configuration")
    refresh_seconds = _bounded_dashboard_integer(
        refresh_seconds, "dashboard refresh_seconds", MIN_REFRESH_SECONDS, MAX_REFRESH_SECONDS
    )
    event_limit = _bounded_dashboard_integer(event_limit, "dashboard event_limit", 1, MAX_EVENT_LIMIT)
    host = loopback_host(host, allow_remote=allow_remote)
    handler = type(
        "BoundDashboardHandler",
        (DashboardHandler,),
        {
            "store": store,
            "offline_summary": offline_summary,
            "reference_library": reference_library,
            "refresh_seconds": refresh_seconds,
            "event_limit": event_limit,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    try:
        print(f"MEGALODON dashboard listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
