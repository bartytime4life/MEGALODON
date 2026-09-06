"""Local read-only dashboard. It exposes telemetry, never control actions."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlparse

from .storage import Store


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MEGALODON</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { margin: 0; background: #111827; color: #e5e7eb; }
    main { max-width: 1100px; margin: 0 auto; padding: 24px; }
    h1 { margin-top: 0; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(170px,1fr)); gap: 12px; }
    .card { background: #1f2937; border: 1px solid #374151; border-radius: 10px; padding: 16px; }
    .value { font-size: 2rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #1f2937; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid #374151; font-size: .9rem; }
    .CRITICAL { color: #fb7185; } .HIGH { color: #fb923c; } .MEDIUM { color: #facc15; }
    .muted { color: #9ca3af; }
  </style>
</head>
<body><main>
  <h1>MEGALODON</h1>
  <p class="muted">Local read-only telemetry · enforcement is controlled outside this page</p>
  <section class="cards" id="cards"></section>
  <table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Message</th></tr></thead>
  <tbody id="events"><tr><td colspan="5">Loading…</td></tr></tbody></table>
</main>
<script>
async function refresh() {
  const [summary, events] = await Promise.all([
    fetch('/api/summary').then(r => r.json()),
    fetch('/api/events?limit=50').then(r => r.json())
  ]);
  const cards = document.getElementById('cards');
  cards.replaceChildren();
  Object.entries(summary).forEach(([key, value]) => {
    const card = document.createElement('div'); card.className = 'card';
    const label = document.createElement('div'); label.className = 'muted'; label.textContent = key.replaceAll('_',' ');
    const number = document.createElement('div'); number.className = 'value'; number.textContent = String(value);
    card.append(label, number); cards.append(card);
  });
  const body = document.getElementById('events'); body.replaceChildren();
  if (!events.length) { const row = document.createElement('tr'); const cell = document.createElement('td'); cell.colSpan = 5; cell.textContent = 'No detections recorded.'; row.append(cell); body.append(row); return; }
  events.forEach(e => {
    const row = document.createElement('tr');
    [e.detected_at, e.severity, e.rule_id, e.src_ip, e.message].forEach((value, index) => {
      const cell = document.createElement('td'); cell.textContent = String(value ?? '');
      if (index === 1) cell.className = String(e.severity ?? '');
      row.append(cell);
    });
    body.append(row);
  });
}
refresh(); setInterval(refresh, 3000);
</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    store: Store

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path)
        if route.path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            return
        if route.path == "/api/summary":
            payload = json.dumps(self.store.summary()).encode()
            self._send(200, "application/json", payload)
            return
        if route.path == "/api/events":
            limit = 50
            if "limit=" in route.query:
                try:
                    limit = int(route.query.split("limit=", 1)[1].split("&", 1)[0])
                except ValueError:
                    limit = 50
            payload = json.dumps(self.store.recent(limit)).encode()
            self._send(200, "application/json", payload)
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def _send(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        return


def serve(store: Store, host: str, port: int, *, allow_remote: bool = False) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"} and not allow_remote:
        raise ValueError("dashboard must bind to localhost unless --allow-remote is explicit")
    handler = type("BoundDashboardHandler", (DashboardHandler,), {"store": store})
    server = ThreadingHTTPServer((host, port), handler)
    try:
        print(f"MEGALODON dashboard listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
