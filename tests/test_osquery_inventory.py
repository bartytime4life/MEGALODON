"""Fixed saved osquery result; no local osquery process is started."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from megalodon.osquery_inventory import MAX_BYTES, summarize
from megalodon.dashboard_osquery import OSQUERY_HTML, OSQUERY_JS, OSQUERY_CSS


def test_count_and_private_fields_are_not_exported():
    value = summarize(b'[{"package_count":"137"}]', exported_at=datetime(2026, 9, 26, tzinfo=timezone.utc))
    assert value == {"schema": "megalodon-osquery-package-count-v2", "exported_at": "2026-09-26T00:00:00Z",
                     "collection_completed_at": None, "package_rows": 137}


def test_local_collection_completion_is_separate_from_processing_time():
    collected = datetime(2026, 9, 26, 6, tzinfo=timezone(timedelta(hours=-6)))
    processed = datetime(2026, 9, 26, 12, 0, 2, tzinfo=timezone.utc)
    value = summarize(b'[{"package_count":"137"}]', exported_at=processed,
                      collection_completed_at=collected)
    assert value["collection_completed_at"] == "2026-09-26T12:00:00Z"
    assert value["exported_at"] == "2026-09-26T12:00:02Z"


@pytest.mark.parametrize("completion", [datetime(2026, 9, 26), False, "2026-09-26T00:00:00Z",
                                        datetime(2026, 9, 27, tzinfo=timezone.utc)])
def test_collection_time_requires_an_aware_clock_no_later_than_processing(completion):
    with pytest.raises(ValueError):
        summarize(b'[{"package_count":"1"}]', exported_at=datetime(2026, 9, 26, tzinfo=timezone.utc),
                  collection_completed_at=completion)


@pytest.mark.parametrize("raw", [
    b'[{"package_count":"1","path":"/private/secret"}]', b'[{"package_count":"1"},{"package_count":"2"}]',
    b'[{"package_count":"1","package_count":"2"}]', b'[{"package_count":1}]',
    b'[{"package_count":"1","collection_completed_at":"2026-09-26T00:00:00Z"}]',
    b'[{"package_count":"-1"}]', b'[{"package_count":"01"}]', b'[{"package_count":"1000000000"}]',
    b'[]', b'{"package_count":"1"}', b'[{"package_count":"1"}] private', b'\xff', b' '*(MAX_BYTES+1),
])
def test_rejects_extra_data_and_bad_counts(raw):
    with pytest.raises(ValueError):
        summarize(raw)


def test_cli_and_shared_assets():
    cmd = [sys.executable, '-m', 'megalodon.osquery_inventory']
    good = subprocess.run(cmd, input=b'[{"package_count":"5"}]', capture_output=True, timeout=10)
    assert good.returncode == 0 and json.loads(good.stdout)['package_rows'] == 5
    assert json.loads(good.stdout)['collection_completed_at'] is None
    bad = subprocess.run(cmd, input=b'[{"package_count":"5","path":"secret"}]', capture_output=True, timeout=10)
    assert bad.returncode == 1 and not bad.stdout and b'secret' not in bad.stderr
    from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
    assert OSQUERY_HTML in INDEX_HTML and OSQUERY_JS in DASHBOARD_JS and OSQUERY_CSS in DASHBOARD_CSS
    root = Path(__file__).resolve().parents[1]
    if (root/'site/dist').is_dir():
        assert (root/'site/dist/osquery.js').read_text() == OSQUERY_JS
        assert (root/'site/dist/osquery.css').read_text() == OSQUERY_CSS
        assert OSQUERY_HTML in (root/'site/dist/index.html').read_text()
    node = shutil.which('node')
    if node:
        result = subprocess.run([node, '-e', OSQUERY_JS + '\nconsole.log(JSON.stringify(validateOsqueryCount(require("node:fs").readFileSync(0,"utf8"))))'],
                                input=good.stdout, capture_output=True, timeout=10)
        assert result.returncode == 0 and json.loads(result.stdout) == json.loads(good.stdout)
