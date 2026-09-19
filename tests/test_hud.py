"""First-launch HUD acceptance: missing data is unavailable, never fabricated."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
from threading import Thread

import pytest

from megalodon import cli, dashboard, readiness, runtime_status
from megalodon.config import Settings
from megalodon.storage import DashboardStore, StorageSchemaError, Store


def test_hud_launch_without_store_never_creates_files(tmp_path, monkeypatch):
    path = tmp_path / "missing" / "audit.db"
    monkeypatch.setattr(cli, "_load", lambda _: Settings(db_path=path))
    observed = []

    def serve(reader, host, port, **kwargs):
        observed.append(kwargs)
        assert isinstance(reader, dashboard.UnconfiguredDashboardReader)
        assert (host, port) == ("127.0.0.1", 8787)
        for method in (reader.summary, reader.recent, reader.ingestion_runs, reader.traffic):
            with pytest.raises(StorageSchemaError):
                method()

    monkeypatch.setattr(dashboard, "serve", serve)
    assert cli._dashboard(cli.build_parser().parse_args(["hud"])) == 0
    assert observed[0]["inspect_tools"] is True
    assert observed[0]["source_available"] is False
    assert not path.parent.exists()


def test_hud_existing_store_uses_read_only_reader(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path):
        pass
    before = path.read_bytes()
    with cli._dashboard_reader(path, allow_missing=True) as reader:
        assert isinstance(reader, DashboardStore)
        assert reader.summary()["events"] == 0
    assert path.read_bytes() == before


@pytest.mark.parametrize("reason", ["UNSAFE_DIRECTORY", "SCHEMA_MISMATCH", "UNSAFE_DATABASE", "BUSY", "AMBIGUOUS_PATH"])
def test_first_launch_does_not_suppress_store_refusals(monkeypatch, reason):
    def refuse(_):
        raise StorageSchemaError("DASHBOARD_STORE:" + reason)
    monkeypatch.setattr(cli, "DashboardStore", refuse)
    with pytest.raises(StorageSchemaError, match=reason):
        with cli._dashboard_reader(Path("unused"), allow_missing=True):
            pytest.fail("Unsafe source accepted")


def test_setup_receipt_is_cached_and_http_cannot_trigger_probes(monkeypatch):
    calls = []
    def check():
        calls.append(1)
        return {"test": "startup only"}
    monkeypatch.setattr(readiness, "readiness_report", check)
    monkeypatch.setattr(runtime_status, "runtime_report", lambda: calls.append(2) or {"runtime": "startup only"})
    snapshot = dashboard.setup_snapshot(inspect_tools=True, source_available=False)
    handler = type("HudTestHandler", (dashboard.DashboardHandler,), {
        "setup_evidence": snapshot, "store": dashboard.UnconfiguredDashboardReader(),
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        for target, method, expected in [
            ("/api/setup", "GET", 200), ("/api/setup", "GET", 200),
            ("/api/setup?refresh=true", "GET", 400), ("/api/setup", "POST", 405),
            ("/api/summary", "GET", 503), ("/api/events", "GET", 503),
        ]:
            conn = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            conn.request(method, target)
            response = conn.getresponse(); body = response.read(); conn.close()
            assert response.status == expected
            assert response.getheader("Cache-Control") == "no-store"
            if expected == 200:
                assert body == snapshot
                assert json.loads(body)["source_status"] == "not_configured"
        assert calls == [1, 2]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_ordinary_dashboard_setup_performs_no_readiness_check(monkeypatch):
    monkeypatch.setattr(readiness, "readiness_report", lambda: pytest.fail("Unexpected tool inspection"))
    monkeypatch.setattr(runtime_status, "runtime_report", lambda: pytest.fail("Unexpected runtime inspection"))
    receipt = json.loads(dashboard.setup_snapshot())
    assert receipt["schema"] == "dashboard-setup-v2"
    assert receipt["readiness"] is None
    assert receipt["runtime"] is None


def test_local_and_hosted_companion_assets_match():
    from megalodon import dashboard_tool_assets as assets
    root = Path(__file__).resolve().parents[1]
    if not (root / "site/dist").exists():
        pytest.skip("Site mirror is not part of the Python distribution")
    for key, file in {"LIFECYCLE_JS": "lifecycle.js", "READINESS_JS": "readiness.js", "CONTROLS_JS": "controls.js", "CONTROLS_CSS": "controls.css"}.items():
        assert getattr(assets, key) == (root / "site/dist" / file).read_text()


def test_launch_builder_quotes_paths_and_rejects_incomplete_values():
    import shutil
    from megalodon.dashboard_setup import SETUP_JS
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for command builder")
    start = SETUP_JS.index("function hudLaunchCommand")
    end = SETUP_JS.index("byId('setup-build')", start)
    harness = SETUP_JS[start:end] + r'''
const assert = require('node:assert/strict');
assert.equal(hudLaunchCommand({}), 'python -m megalodon hud');
assert.throws(() => hudLaunchCommand({offline: 'relative/path'}));
assert.throws(() => hudLaunchCommand({config: '/tmp/a\nb'}));
console.log(hudLaunchCommand({offline: "/tmp/one ' $(touch NEVER_EXECUTE)"}));
'''
    result = subprocess.run([node, "-e", harness], text=True, capture_output=True, timeout=5, check=True)
    import shlex
    assert shlex.split(result.stdout.strip()) == ["python", "-m", "megalodon", "hud", "--offline-run", "/tmp/one ' $(touch NEVER_EXECUTE)"]
