"""Real synthetic AIDE projections rendered by the shipped read-only panel."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_recovery_readiness import RECOVERY_READINESS_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_JS
from megalodon.host_findings import aide_review
from megalodon.host_security import SCHEMA, stamp
from megalodon.recovery_readiness import review


def projections():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    result = {}
    for name, operation, code in [('baseline', 'baseline', 0), ('comparison', 'check', 7),
                                  ('no_differences', 'check', 0), ('legacy', 'check', 7),
                                  ('old', 'check', 4)]:
        checked = now - timedelta(days=8) if name == 'old' else now
        summary = dict(checked_at=stamp(checked), message='Synthetic private report.',
                       metrics={key + '_detected': int(bool(code & bit))
                                for key, bit in [('added', 1), ('removed', 2), ('changed', 4)]},
                       review=aide_review(b'synthetic report', operation,
                                          dict(created_at=stamp(checked - timedelta(days=1)), sha256='a' * 64), code))
        source = dict(schema=SCHEMA, audit=None, integrity=summary, feeds=[],
                      feed_state='unavailable', baseline_present=True, message='Context.',
                      action_authority='none', audit_state='missing', integrity_state='available')
        if name == 'legacy':
            source['integrity_state'] = 'legacy'
            del summary['review']
        result[name] = review(source, now=now)
    for state in ('missing', 'unavailable'):
        source['integrity_state'], source['integrity'], source['baseline_present'] = state, None, False
        result[state] = review(source, now=now)
    return result


def test_real_projections_render_and_forged_or_stale_readiness_is_cleared():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('recovery_readiness_browser.cjs'))],
                            input=json.dumps(dict(code=RECOVERY_READINESS_JS, payloads=projections())),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_existing_setup_route_renders_and_clears_panel_without_actions():
    assert 'id="recovery-readiness"' in SUPPORT_CONFIG_HTML
    assert "renderRecoveryReadiness(el('recovery-readiness'),v.recovery_readiness)" in SUPPORT_CONFIG_JS
    assert "function fail(error){renderRecoveryReadiness(el('recovery-readiness'),null)" in SUPPORT_CONFIG_JS
    assert 'fetch(' not in RECOVERY_READINESS_JS
    assert 'innerHTML' not in RECOVERY_READINESS_JS
    assert '<button' not in SUPPORT_CONFIG_HTML.split('id="recovery-readiness-title"', 1)[1].split('id="hardening-title"', 1)[0]
