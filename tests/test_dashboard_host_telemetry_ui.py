"""Live resource UI contract, failure handling, and shared asset integration."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_host_telemetry import (
    HOST_TELEMETRY_HTML, HOST_TELEMETRY_CSS, HOST_TELEMETRY_JS,
    HOST_TELEMETRY_HOSTED_HTML,
)


def fixture():
    interface = dict(name="enp11s0", rx_bps=1266798, tx_bps=56907, rx_pps=1021,
                     tx_pps=384, rx_errors=0, tx_errors=0, rx_drops=0, tx_drops=0)
    apps = [dict(id=name, name="MEGALODON" if name == "core" else name,
                 process_count=int(name == "core"), cpu_percent=0, rss_bytes=1024,
                 read_bps=0, write_bps=0, io_status="ready")
            for name in ("core", "tshark", "zeek", "suricata", "clamav", "osquery", "qwen", "nmap", "nftables")]
    return dict(schema="megalodon-host-telemetry-v1", status="ready",
                observed_at="2026-09-30T18:04:19.460Z", interval_seconds=2, history_seconds=600,
                system=dict(cpu_percent=7.125, memory_total_bytes=132566208512,
                            memory_used_bytes=16305704960, memory_percent=12.3),
                suite=dict(cpu_percent=0, rss_bytes=13541376, memory_percent=.01, process_count=1),
                apps=apps, network=dict(status="ready", interfaces=[dict(interface,name="lo"),interface]),
                sockets=dict(status="ready", tcp=245, udp=19, established=98, listening=31,
                             time_wait=116, remote_peers=[dict(address="127.0.0.1", connections=1)]),
                history=[dict(observed_at=f"2026-09-30T18:04:{second}.460Z", system_cpu_percent=7,
                              suite_cpu_percent=0, suite_rss_bytes=1024,
                              interfaces=[dict(name=name, rx_bps=None if second == 17 else 1024,
                                               tx_bps=None if second == 17 else 512)
                                          for name in ("lo", "enp11s0")]) for second in (17,19)],
                coverage=dict(processes="complete"), notes=[])


def test_host_telemetry_behavior():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable")
    result = subprocess.run([node, str(Path(__file__).with_name("host_telemetry_browser.cjs"))],
                            input=json.dumps(dict(code=HOST_TELEMETRY_JS, fixture=fixture())),
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_local_composition_and_hosted_source_parity():
    assert 'id="pc-live"' in INDEX_HTML
    assert 'class="ops-resource-detail"' in INDEX_HTML
    assert HOST_TELEMETRY_CSS in DASHBOARD_CSS
    assert HOST_TELEMETRY_JS in DASHBOARD_JS
    assert INDEX_HTML.index('id="pc-live-title"') < INDEX_HTML.index('id="room-traffic-grid"')
    assert 'prefers-reduced-motion:reduce' in HOST_TELEMETRY_CSS
    root = Path(__file__).resolve().parents[1]
    if not (root / "site/dist").exists():
        return
    assert (root / "site/dist/host-telemetry.css").read_text() == HOST_TELEMETRY_CSS
    hosted = (root / "site/dist/index.html").read_text()
    assert HOST_TELEMETRY_HOSTED_HTML in hosted
    assert '/api/host-telemetry' not in hosted
    assert 'host-telemetry.js' not in hosted
    assert 'Optional: explore a saved summary' in hosted
