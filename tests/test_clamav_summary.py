"""Completed synthetic clamscan reports; no scanner launched."""
import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from megalodon.clamav_summary import MAX_BYTES, summarize_report
from megalodon.dashboard_clamav import CLAMAV_CSS, CLAMAV_HTML, CLAMAV_JS


def report(infected=0, errors=""):
    return ("/private/secret-file: Example.Test FOUND\n" if infected else "/private/secret-file: OK\n") .encode() + f"""
----------- SCAN SUMMARY -----------
Known viruses: 8000000
Engine version: 1.4.3
Scanned directories: 2
Scanned files: 10
Infected files: {infected}
{errors}Data scanned: 1.23 MB
Data read: 0.80 MB (ratio 1.54:1)
Time: 1.200 sec (0 m 1 s)
Start Date: 2026:09:26 12:00:00
End Date:   2026:09:26 12:00:01
""".encode()


def test_counts_only_and_status_consistency():
    for matches in (0, 2):
        value = summarize_report(report(matches), 1 if matches else 0, exported_at=datetime(2026, 9, 26, tzinfo=timezone.utc))
        assert value["scanned_files"] == 10 and value["infected_files"] == matches
        assert value["errors"] == 0 and value["scan_end_local"] == "2026:09:26 12:00:01"
        assert value["exported_at"] == "2026-09-26T00:00:00Z"
        assert "secret" not in json.dumps(value) and "FOUND" not in json.dumps(value)


@pytest.mark.parametrize("raw,code", [
    (report(), 2), (report(), 1), (report(1), 0), (report(errors="Total errors: 1\n"), 0),
        (report(1).replace(b"Scanned files: 10", b"Scanned files: 0"), 1),
    (report().replace(b"End Date:   2026:09:26 12:00:01", b"End Date: 2026:09:26 11:00:01"), 0),
    (report().replace(b"2026:09:26", b"2026:02:30"), 0),
    (report() + b"----------- SCAN SUMMARY -----------", 0),
    (report() + b"\n/private/path: UNKNOWN\n", 0),
    (report() + b"\nScanned files: 11\n", 0),
    (report().replace(b"Engine version: 1.4.3", b"Engine version: private"), 0),
    (report() + b"\nNot removed: 1\n", 0),
    (report() + b"\xff", 0), (b"private\n", 0), (b"x"*(MAX_BYTES+1), 0),
])
def test_refuses_error_partial_or_unsupported_output(raw, code):
    with pytest.raises(ValueError):
        summarize_report(raw, code)


def test_cli_does_not_echo_private_report_on_failure():
    cmd = [sys.executable, "-m", "megalodon.clamav_summary", "--exit-code", "0"]
    ok = subprocess.run(cmd, input=report(), capture_output=True, timeout=10)
    assert ok.returncode == 0 and json.loads(ok.stdout)["scanned_files"] == 10
    bad = subprocess.run(cmd, input=b"private secret", capture_output=True, timeout=10)
    assert bad.returncode == 1 and not bad.stdout and b"private" not in bad.stderr


def test_shared_hud_and_browser_accept_export():
    from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
    assert CLAMAV_HTML in INDEX_HTML and CLAMAV_JS in DASHBOARD_JS and CLAMAV_CSS in DASHBOARD_CSS
    root = Path(__file__).resolve().parents[1]
    if (root/'site/dist').is_dir():
        assert (root/'site/dist/clamav.js').read_text() == CLAMAV_JS
        assert (root/'site/dist/clamav.css').read_text() == CLAMAV_CSS
        assert CLAMAV_HTML in (root/'site/dist/index.html').read_text()
    node = shutil.which('node')
    if node:
        js = CLAMAV_JS + '\nconst fs=require("node:fs");console.log(JSON.stringify(validateClamavSummary(fs.readFileSync(0,"utf8"))));'
        value = summarize_report(report(), 0)
        result = subprocess.run([node, '-e', js], input=json.dumps(value), text=True, capture_output=True, timeout=10, check=True)
        assert json.loads(result.stdout) == value
