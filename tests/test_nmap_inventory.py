"""Synthetic reports only: no external executable, capture or source download."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from megalodon.nmap_inventory import MAX_BYTES, summarize_report
from megalodon.dashboard_inventory import INVENTORY_HTML, INVENTORY_JS, INVENTORY_CSS


def report(body=None):
    if body is None:
        body = '''<host><status state="up"/><address addr="192.0.2.1"/>
        <hostnames><hostname name="private.example"/></hostnames><ports>
        <extraports state="closed" count="997"/>
        <port protocol="tcp" portid="443"><state state="open"/>
        <service product="secret-banner"/><script output="private-script"/></port>
        <port protocol="udp" portid="53"><state state="open|filtered"/></port>
        </ports></host>'''
    return ('''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun>
    <?xml-stylesheet href="https://invalid.example/nmap.xsl"?>
    <nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05" start="1700000000" args="private-target">
    ''' + body + '''<runstats><finished exit="success" time="1700000010"/>
    <hosts up="1" down="2" total="3"/></runstats></nmaprun>''').encode()


def test_aggregate_projection_discards_private_content_and_preserves_units(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'socket', lambda *a, **k: pytest.fail('no networking'))
    value = summarize_report(report())
    assert value['hosts'] == [1, 2]
    assert value['represented_hosts'] == [1, 0]
    assert value['explicit_states'] == [1, 0, 0, 0, 1, 0]
    assert value['grouped_states'] == [0, 997, 0, 0, 0, 0]
    assert value['protocols'] == [1, 1, 0]
    encoded = json.dumps(value)
    for secret in ('192.0.2.1', 'private', 'secret-banner', '443', 'args', 'script'):
        assert secret not in encoded
    assert set(value) == {'schema', 'started_at', 'finished_at', 'hosts', 'represented_hosts', 'explicit_states', 'grouped_states', 'protocols'}


@pytest.mark.parametrize('old,new', [
    (b'exit="success"', b'exit="error"'),
    (b'xmloutputversion="1.05"', b'xmloutputversion="1.04"'),
    (b'version="7.95"', b'version="8.0"'),
    (b'<host>', b'<host timedout="true">'),
    (b'state="up"', b'state="unknown"'),
    (b'state="open"', b'state="safe"'),
    (b'protocol="tcp"', b'protocol="ip"'),
    (b'portid="443"', b'portid="65536"'),
    (b'count="997"', b'count="1000001"'),
    (b'count="997"', b'count="-1"'),
    (b'count="997"', b'count="1.5"'),
    (b'up="1"', b'up="0"'),
    (b'total="3"', b'total="4"'),
    (b'time="1700000010"', b'time="4102444800"'),
    (b'time="1700000010"', b'time="1699999999"'),
    (b'<state state="open"/>', b''),
    (b'<status state="up"/>', b'<status state="up"/><status state="up"/>'),
    (b'<state state="open"/>', b'<state state="open"/><state state="closed"/>'),
    (b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">'),
    (b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun [<!ENTITY x "expansion">]>'),
    (b'encoding="UTF-8"', b'encoding="UTF-16"'),
    (b'</nmaprun>', b''),
])
def test_rejects_unsupported_incomplete_or_inconsistent_reports(old, new):
    with pytest.raises(ValueError):
        summarize_report(report().replace(old, new))


def test_depth_size_count_and_duplicate_port_limits():
    for raw in [b'x' * (MAX_BYTES + 1), b'\xff', report('<x>'*17+'</x>'*17),
                report('<x/>'*50001), report('<host><status state="up"/></host>'*4097),
                report().replace(b'</ports>', b'<port protocol="tcp" portid="443"><state state="closed"/></port></ports>')]:
        with pytest.raises(ValueError):
            summarize_report(raw)


def test_empty_completed_report_is_zero_observation_not_failed_scan():
    value = summarize_report(report('').replace(b'up="1" down="2" total="3"', b'up="0" down="0" total="0"'))
    assert value['hosts'] == value['represented_hosts'] == [0, 0]
    assert sum(value['explicit_states']) == 0


def test_cli_roundtrip_and_closed_failure_diagnostic():
    accepted = subprocess.run([sys.executable, '-m', 'megalodon.nmap_inventory'], input=report(), capture_output=True, timeout=10)
    assert accepted.returncode == 0
    assert json.loads(accepted.stdout) == summarize_report(report())
    refused = subprocess.run([sys.executable, '-m', 'megalodon.nmap_inventory'], input=b'private secret malformed xml', capture_output=True, timeout=10)
    assert refused.returncode == 1 and not refused.stdout
    assert b'private secret' not in refused.stderr


def test_packaged_parser_and_both_hud_surfaces():
    from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
    assert INVENTORY_HTML in INDEX_HTML and INVENTORY_JS in DASHBOARD_JS and INVENTORY_CSS in DASHBOARD_CSS
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required for real export to browser validator')
    script = INVENTORY_JS + '\nconst fs=require("node:fs"); console.log(JSON.stringify(validateInventorySummary(fs.readFileSync(0,"utf8"))));'
    value = summarize_report(report())
    result = subprocess.run([node, '-e', script], input=json.dumps(value), text=True, capture_output=True, timeout=10, check=True)
    assert json.loads(result.stdout) == value


def test_repository_mirror():
    root = Path(__file__).resolve().parents[1]
    if not (root/'site/dist').is_dir():
        pytest.skip('Hosted source is separate from sdist')
    assert (root/'site/dist/inventory.js').read_text() == INVENTORY_JS
    assert (root/'site/dist/inventory.css').read_text() == INVENTORY_CSS
    assert INVENTORY_HTML in (root/'site/dist/index.html').read_text()
