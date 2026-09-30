"""Counter semantics and HTTP boundary of automatic, account-free PC telemetry."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
from threading import Thread

from megalodon.dashboard import DashboardHandler
from megalodon.host_telemetry import HostTelemetry, MAX_HISTORY


def write_proc(root, *, total=1000, idle=800, ticks=10, received=100, sent=50, start=100):
    root.mkdir(exist_ok=True)
    (root / 'net').mkdir(exist_ok=True)
    (root / 'stat').write_text(f'cpu {total-idle} 0 0 {idle} 0 0 0 0 0 0\n')
    (root / 'meminfo').write_text('MemTotal: 1000000 kB\nMemAvailable: 600000 kB\n')
    (root / 'net/dev').write_text('header\nheader\n eth0: ' + ' '.join(map(str, [received, 5, 0, 1, 0, 0, 0, 0, sent, 3, 0, 0, 0, 0, 0, 0])) + '\n')
    for table in ['tcp', 'tcp6', 'udp', 'udp6']:
        (root / 'net' / table).write_text('header\n')
    # localhost -> 192.0.2.1, one established connection (documentation IP).
    (root / 'net/tcp').write_text('header\n 0: 0100007F:1000 010200C0:01BB 01 0 0 0 0\n')
    process(root, 42, 'python', ticks, start=start)


def process(root, pid, name, ticks, start=100, parent=1, io=True):
    directory = root / str(pid)
    directory.mkdir(exist_ok=True)
    fields = ['S'] + ['0'] * 22
    fields[1], fields[11], fields[19], fields[21] = str(parent), str(ticks), str(start), '100'
    (directory / 'stat').write_text(f'{pid} ({name}) ' + ' '.join(fields))
    (directory / 'cmdline').write_bytes(b'python\0-m\0megalodon\0hud\0')
    if io:
        (directory / 'io').write_text(f'read_bytes: {ticks * 100}\nwrite_bytes: {ticks * 10}\n')


def test_counter_deltas_and_qualified_scope(tmp_path):
    root = tmp_path / 'proc'
    write_proc(root)
    sampler = HostTelemetry(root, own_pid=42)
    first = sampler.sample(10)
    assert first['status'] == 'warming'
    assert first['suite']['cpu_percent'] is None
    assert first['network']['interfaces'][0]['rx_bps'] is None
    assert first['system']['memory_percent'] == 40
    write_proc(root, total=1200, idle=900, ticks=30, received=600, sent=250)
    second = sampler.sample(12)
    assert second['status'] == 'ready'
    assert second['system']['cpu_percent'] == 50
    assert second['suite']['cpu_percent'] == 10  # total machine ticks, not one core
    assert second['suite']['rss_bytes'] == 100 * os.sysconf('SC_PAGE_SIZE')
    assert second['network']['interfaces'][0]['rx_bps'] == 250
    assert second['network']['interfaces'][0]['tx_bps'] == 100
    assert second['apps'][0]['read_bps'] == 1000
    assert second['sockets']['tcp'] == 1
    assert second['sockets']['remote_peers'] == [{'address': '192.0.2.1', 'connections': 1}]
    # HTTP projection includes neither process IDs, arguments nor filesystem paths.
    serialized = json.dumps(second)
    assert 'cmdline' not in serialized and str(root) not in serialized and '"pid"' not in serialized


def test_pid_reuse_resets_process_rates_and_network_reset_is_gap(tmp_path):
    root = tmp_path / 'proc'
    write_proc(root)
    sampler = HostTelemetry(root, own_pid=42)
    sampler.sample(10)
    write_proc(root, total=1200, idle=900, ticks=40, received=2, start=200)
    value = sampler.sample(12)
    assert value['suite']['cpu_percent'] is None
    assert value['apps'][0]['read_bps'] is None
    assert value['network']['interfaces'][0]['rx_bps'] is None
    # Resume after suspension does not average an unobserved period into Live.
    value = sampler.sample(100)
    assert value['system']['cpu_percent'] is None
    assert value['network']['interfaces'][0]['tx_bps'] is None


def test_app_buckets_are_disjoint_and_missing_io_is_not_zero(tmp_path):
    root = tmp_path / 'proc'
    write_proc(root)
    process(root, 50, 'nmap', 5, parent=42, io=False)
    process(root, 60, 'python3', 5, parent=42, io=False)
    (root / '60/cmdline').write_bytes(b'python3\0-c\0worker\0')
    process(root, 70, 'chrome', 5, parent=42)
    process(root, 80, 'python3', 5, parent=70)
    (root / '80/cmdline').write_bytes(b'python3\0-c\0unrelated\0')
    sampler = HostTelemetry(root, own_pid=42)
    sampler.sample(10)
    write_proc(root, total=1200, idle=900, ticks=30)
    value = sampler.sample(12)
    assert value['suite']['process_count'] == 3
    apps = {a['id']: a for a in value['apps']}
    assert apps['core']['process_count'] == 2
    assert apps['nmap']['process_count'] == 1
    assert apps['nmap']['read_bps'] is None
    assert apps['core']['io_status'] == 'unavailable'


def test_partial_process_visibility_and_unavailable_socket_table(tmp_path):
    root = tmp_path / 'proc'
    write_proc(root)
    process(root, 50, 'nmap', 5)
    (root / '50/stat').write_text('malformed counter')
    sampler = HostTelemetry(root, own_pid=42)
    sampler.sample(10)
    write_proc(root, total=1200, idle=900)
    (root / 'net/udp6').unlink()
    value = sampler.sample(12)
    assert value['status'] == 'partial'
    assert value['coverage']['processes'] == 'partial'
    assert value['sockets']['tcp'] is None
    assert value['sockets']['status'] == 'unavailable'


def test_history_bound_and_snapshot_isolation(tmp_path):
    root = tmp_path / 'proc'
    write_proc(root)
    sampler = HostTelemetry(root, own_pid=42)
    for index in range(MAX_HISTORY + 2):
        sampler.sample(10 + index * 2)
    assert len(sampler.snapshot()['history']) == MAX_HISTORY
    value = sampler.snapshot()
    value['history'].clear()
    assert len(sampler.snapshot()['history']) == MAX_HISTORY


def test_failed_sampler_clears_readings_and_can_stop(tmp_path):
    sampler = HostTelemetry(tmp_path / 'missing')
    sampler.start()
    sampler.stop()
    assert sampler.snapshot()['status'] == 'unavailable'
    assert sampler.snapshot()['system'] == {}
    assert not sampler._thread.is_alive()


def test_http_requires_local_host_header_and_no_query(tmp_path):
    root = tmp_path / 'proc'
    write_proc(root)
    sampler = HostTelemetry(root, own_pid=42)
    sampler.sample(10)
    handler = type('TestHostTelemetry', (DashboardHandler,), {'host_telemetry': sampler})
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def get(path, headers):
            connection = HTTPConnection(*server.server_address)
            connection.request('GET', path, headers=headers)
            response = connection.getresponse()
            result = response.status, response.read()
            connection.close()
            return result
        assert get('/api/host-telemetry', {})[0] == 403
        assert get('/api/host-telemetry?target=x', {'X-Megalodon-Check': '1'})[0] == 400
        assert get('/api/host-telemetry', {'Host': 'evil.example', 'X-Megalodon-Check': '1'})[0] == 400
        status, body = get('/api/host-telemetry', {'X-Megalodon-Check': '1'})
        assert status == 200 and json.loads(body)['schema'] == 'megalodon-host-telemetry-v1'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
