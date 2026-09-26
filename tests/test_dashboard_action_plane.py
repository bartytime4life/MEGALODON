"""The action plane previews fixed recurrences without execution authority."""

from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread

from megalodon.dashboard import DashboardHandler
from megalodon.dashboard_assets import DASHBOARD_JS, INDEX_HTML


@contextmanager
def preview_server(*, hud=True):
    handler = type("PreviewHandler", (DashboardHandler,), {
        "local_checks": object() if hud else None,
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def post(server, body, *, path="/api/automation-preview", headers=()):
    origin = f"http://127.0.0.1:{server.server_port}"
    request_headers = [("Host", origin[7:]), ("Origin", origin),
                       ("X-Megalodon-Preview", "1"), ("Content-Type", "application/json"),
                       ("Content-Length", str(len(body)))] + list(headers)
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        for key, value in request_headers:
            client.putheader(key, value)
        client.endheaders(body)
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


VALID = b'{"dtstart":"2026-09-28T09:00:00","schedule_timezone":"America/Chicago","preset":"weekly"}'


def test_action_plane_links_to_real_local_controls():
    for target in ("action-plane-title", "action-check-pc", "action-refresh-evidence",
                   "action-script-copy", "action-schedule-preview", "app-service-start-title"):
        assert f'id="{target}"' in INDEX_HTML
    assert 'id="workspace-tab-interfaces"' in INDEX_HTML
    assert '>Actions</button>' in INDEX_HTML
    assert "byId('setup-check').click()" in DASHBOARD_JS
    assert "byId('room-refresh').click()" in DASHBOARD_JS
    assert "requestBoundedJSON('/api/automation-preview', 4096" in DASHBOARD_JS


def test_preview_is_bounded_and_does_not_save_or_run():
    with preview_server() as server:
        status, result = post(server, VALID)
    assert status == 200
    assert result["schema_version"] == "megalodon-automation-preview-v1"
    assert result["status"] == "preview_only"
    assert len(result["occurrences"]) == 8
    assert result["occurrences"][0] == {
        "occurrence_at": "2026-09-28T14:00:00Z", "local_time": "2026-09-28T09:00:00", "dst_status": "normal",
    }


def test_preview_requires_hud_origin_and_explicit_header():
    with preview_server() as server:
        for extra in (("Origin", "http://evil.invalid"),
                      ("X-Megalodon-Preview", "1"),
                      ("Content-Type", "application/json"),
                      ("Transfer-Encoding", "chunked")):
            assert post(server, VALID, headers=(extra,))[0] == 403
        assert post(server, VALID, path="/api/automation-preview?x=1")[0] == 405
    with preview_server(hud=False) as server:
        assert post(server, VALID)[0] == 403


def test_preview_rejects_untrusted_instructions_and_ambiguous_body():
    bodies = (
        b'{"dtstart":"2026-09-28T09:00:00","schedule_timezone":"UTC","preset":"daily","script":"id"}',
        b'{"dtstart":"2026-09-28T09:00:00","schedule_timezone":"UTC","preset":"daily","preset":"weekly"}',
        b'{"dtstart":"2026-09-28T09:00:00","schedule_timezone":"UTC","preset":"FREQ=SECONDLY"}',
        b'{"dtstart":"2026-09-28T09:00:00","schedule_timezone":"../UTC","preset":"daily"}',
    )
    with preview_server() as server:
        for body in bodies:
            status, result = post(server, body)
            assert status == 400
            assert "occurrences" not in result
