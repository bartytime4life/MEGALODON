"""Optional Suricata startup evidence stays bounded and separate from telemetry."""

from copy import deepcopy
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from megalodon import cli, dashboard
from megalodon.offline import suricata, suricata_consumer
from megalodon.suricata_projection import read_suricata_projection
from megalodon.suricata_store import initialize_suricata_store
from megalodon.storage import Store


@pytest.fixture
def projection(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)
    database = tmp_path / "private" / "suricata.db"
    initialize_suricata_store(database)
    fixtures = Path(__file__).parents[1] / "contracts/suricata-eve/v1/fixtures/accepted.json"
    cases = json.loads(fixtures.read_text())
    source = tmp_path / "synthetic.jsonl"
    source.write_text("".join(json.dumps(case["input"]) + "\n" for case in cases[:2]))
    source.chmod(0o600)
    publication = suricata.read_completed_file(str(source))
    result = suricata_consumer.consume_publication(
        database, publication, consumer_attempt_id="dashboard-fixture"
    )
    assert result["status"] == "committed"
    value = read_suricata_projection(database)
    assert value["status"] == "available"
    return value


@pytest.fixture
def server(projection):
    reader = Mock()
    reader.summary.return_value = {"events": 4, "detections": 2, "high_or_critical": 1, "actions": 0}
    handler = type("SuricataTestHandler", (dashboard.DashboardHandler,), {
        "store": reader, "suricata_evidence": json.dumps(projection).encode(),
    })
    instance = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield instance, reader
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def request(server, target="/api/suricata", *, method="GET", headers=None):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        connection.request(method, target, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_endpoint_serves_owned_evidence_without_reopening_store(server, projection, monkeypatch):
    instance, reader = server
    def forbidden(*_args, **_kwargs):
        raise AssertionError("HTTP request reopened the optional store")
    monkeypatch.setattr(dashboard, "read_suricata_projection", forbidden)
    for _ in range(2):
        status, headers, body = request(instance)
        assert status == 200 and json.loads(body) == projection
        assert len(body) <= 65536 and int(headers["Content-Length"]) == len(body)
        assert headers["Cache-Control"] == "no-store"
        assert "connect-src 'self'" in headers["Content-Security-Policy"]
        assert headers["X-Frame-Options"] == "DENY"
    assert reader.mock_calls == []
    assert json.loads(request(instance, "/api/summary")[2]) == reader.summary.return_value


@pytest.mark.parametrize("query", [
    "path=/private/store", "db=/tmp/store", "limit=1", "refresh=1", "action=apply", "x=1&x=2", "%FF=1", "x=" + "9" * 10000,
])
def test_query_never_selects_a_store_or_refreshes_snapshot(server, query):
    instance, reader = server
    status, _, body = request(instance, "/api/suricata?" + query)
    assert status == 400
    assert json.loads(body) == {"error": "unsupported query parameter"}
    assert reader.mock_calls == []


def test_host_method_and_target_guards_remain_in_force(server):
    instance, reader = server
    assert request(instance, headers={"Host": "attacker.example"})[0] == 400
    for target in ["http://127.0.0.1/api/suricata", "/api/suricata;x=1", "/api/suricata#private"]:
        assert request(instance, target)[0] == 400
    status, headers, body = request(instance, method="POST")
    assert status == 405 and headers["Allow"] == "GET"
    assert json.loads(body) == {"error": "method not allowed"}
    assert request(instance, "/api/suricata?")[0] == 200
    assert reader.mock_calls == []


def test_startup_owns_bytes_and_reads_optional_store_only_once(monkeypatch, projection):
    original = deepcopy(projection)
    read = Mock(return_value=projection)
    monkeypatch.setattr(dashboard, "read_suricata_projection", read)
    server = Mock()
    factory = Mock(return_value=server)
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    dashboard.serve(Mock(), "127.0.0.1", 8787, suricata_db="/private/selected.db")
    read.assert_called_once_with("/private/selected.db")
    handler = factory.call_args.args[1]
    projection["summary"]["stored_alerts"] = 999
    assert isinstance(handler.suricata_evidence, bytes)
    assert json.loads(handler.suricata_evidence) == original
    server.server_close.assert_called_once_with()


def test_missing_store_does_not_create_files_or_block_core_startup(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)
    path = tmp_path / "must-not-create" / "suricata.db"
    factory = Mock(return_value=Mock())
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    dashboard.serve(Mock(), "127.0.0.1", 8787, suricata_db=path)
    value = json.loads(factory.call_args.args[1].suricata_evidence)
    assert value["status"] == "unavailable" and value["failure_code"] == "STORE_UNAVAILABLE"
    assert not path.parent.exists() and str(tmp_path) not in json.dumps(value)
    assert json.loads(dashboard.suricata_snapshot(None))["status"] == "not_configured"


def test_serializer_budget_failure_remains_optional_and_path_free(monkeypatch):
    unavailable = read_suricata_projection(None)
    monkeypatch.setattr(dashboard, "read_suricata_projection", lambda path: {"unsafe": "x" * 65536} if path else deepcopy(unavailable))
    value = json.loads(dashboard.suricata_snapshot("/private/selected.db"))
    assert value["status"] == "unavailable" and value["failure_code"] == "RESPONSE_LIMIT"
    assert value["summary"] is None and value["recent_alerts"] == []
    assert "unsafe" not in value


def test_cli_only_explicitly_selected_path_reaches_dashboard(tmp_path, monkeypatch):
    core = tmp_path / "core" / "audit.db"
    with Store(core):
        pass
    settings = SimpleNamespace(db_path=core, dashboard=SimpleNamespace(
        host="127.0.0.1", port=8787, enabled=True, refresh_seconds=5, event_limit=50,
    ))
    monkeypatch.setattr(cli, "_load", lambda _: settings)
    serving = Mock()
    monkeypatch.setattr(dashboard, "serve", serving)
    for selection in ([], ["--suricata-db", "/private/suricata.db"]):
        args = cli.build_parser().parse_args(["dashboard", *selection])
        assert cli._dashboard(args) == 0
        assert serving.call_args.kwargs["suricata_db"] == (Path(selection[-1]) if selection else None)


def test_browser_revalidates_real_projection_and_clears_failed_evidence(projection):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for dashboard JavaScript behavior")
    harness = r"""
const vm = require('node:vm'); const assert = require('node:assert/strict');
let input = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', c => input += c);
process.stdin.on('end', async () => {
 try {
  const {code, projection, unconfigured} = JSON.parse(input);
  const nodes = new Map(); const paths = []; let reply = projection;
  function element(id='') { return {id, children: [], hidden: false, attrs: {}, textContent: '', value: '',
    set innerHTML(_) { throw new Error('unsafe HTML sink'); },
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
    setAttribute(key,value) { this.attrs[key] = value; }, removeAttribute(key) { delete this.attrs[key]; },
    addEventListener() {}}; }
  const document = {hidden:false, addEventListener() {}, createElement:element,
    getElementById(id) { if (!nodes.has(id)) nodes.set(id,element(id)); return nodes.get(id); }};
  const context = {document, TextDecoder, Uint8Array, AbortController, console,
    window:{location:{hash:''}, setTimeout() {return 1;}, clearTimeout() {}},
    fetch:async path => {
      paths.push(path); const bytes = new TextEncoder().encode(JSON.stringify(reply)); let done=false;
      return {ok:true, headers:{get:()=>String(bytes.length)}, body:{getReader:()=>({
        read:async()=>done ? {done:true} : (done=true,{done:false,value:bytes}), cancel:async()=>{}
      })}};
    }};
  vm.createContext(context); vm.runInContext(code.replace(/\nbootstrap\(\);\s*$/, '\n'),context,{timeout:1000});
  const run = value => vm.runInContext(value,context,{timeout:1000}); const get=id=>document.getElementById(id);
  context.input = projection; const accepted = run('validatedSuricataEnvelope(input)');
  assert.ok(Object.isFrozen(accepted)); assert.ok(Object.isFrozen(accepted.recent_alerts[0].rule));
  await run('loadSuricataEvidence()'); assert.deepEqual(paths,['/api/suricata']);
  assert.equal(get('suricata-content').hidden,false); assert.match(get('suricata-status').textContent,/Startup snapshot/);
  const stateBefore = run('JSON.stringify(state)');
  const changes = [v=>v.summary.shown_alerts++, v=>v.recent_alerts[0].action_status='applied',
    v=>v.recent_alerts[0].src_ip='<img src=x>', v=>v.recent_runs[0].sensor_id='bad\n',
    v=>v.recent_alerts[0].run_id='another-run', v=>v.recent_alerts[0].rule.severity=true,
    v=>v.recent_alerts[0].source_record_index=9999, v=>v.recent_runs[0].alert_count=0,
    v=>v.recent_alerts.reverse(), v=>v.recent_runs[0].declared_version='001.1.1',
    v=>v.recent_alerts[0].observed_at='2026-02-30T00:00:00.000000Z',
    v=>v.summary.stored_alerts=Number.MAX_SAFE_INTEGER+1, v=>v.recent_alerts.push(v.recent_alerts[0]),
    v=>v.limits.max_recent_alerts=51, v=>v.extra='forbidden', v=>v.status='healthy'];
  for (const change of changes) { const bad=JSON.parse(JSON.stringify(projection)); change(bad); context.input=bad;
    assert.throws(()=>run('validatedSuricataEnvelope(input)')); }
  reply = {...unconfigured,status:'unavailable',failure_code:'STORE_UNAVAILABLE'};
  await run('loadSuricataEvidence()'); assert.equal(get('suricata-content').hidden,true);
  assert.equal(get('suricata-alerts').children.length,0); assert.equal(get('suricata-runs').children.length,0);
  assert.equal(get('suricata-status').textContent,'Unavailable');
  reply=unconfigured; await run('loadSuricataEvidence()'); assert.equal(get('suricata-status').textContent,'Not configured');
  reply={...projection,recent_alerts:[{payload:'forbidden'}]}; await run('loadSuricataEvidence()');
  assert.equal(get('suricata-status').textContent,'Unavailable'); assert.equal(run('JSON.stringify(state)'),stateBefore);
  assert.ok(paths.every(path=>path==='/api/suricata'));
  process.stdout.write('suricata browser contract passed\n');
 } catch(error) {console.error(error);process.exitCode=1;}
});
"""
    result = subprocess.run(
        [node, "-e", harness],
        input=json.dumps({"code": dashboard.DASHBOARD_JS, "projection": projection, "unconfigured": read_suricata_projection(None)}),
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "suricata browser contract passed" in result.stdout
