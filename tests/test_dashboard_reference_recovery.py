"""Reference Library source-seam contract tests; not complete browser acceptance."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from megalodon.dashboard_assets import DASHBOARD_CSS, DASHBOARD_JS, INDEX_HTML


class ReferenceRecoveryAssetsTests(unittest.TestCase):
    def test_recovery_controls_and_provenance_are_in_existing_dashboard(self) -> None:
        for marker in (
            'id="reference-panel"', 'id="reference-retry"',
            'id="reference-clear"', 'id="reference-provenance"',
            'Snapshot provenance and verification limits',
        ):
            self.assertEqual(INDEX_HTML.count(marker), 1, marker)
        self.assertIn('role="status" aria-live="polite" aria-atomic="true"', INDEX_HTML)
        self.assertIn('.reference-provenance-facts', DASHBOARD_CSS)
        self.assertIn("byId('reference-retry').addEventListener('click', loadReferenceStatus)", DASHBOARD_JS)
        self.assertIn("byId('reference-clear').addEventListener('click'", DASHBOARD_JS)
        self.assertEqual(DASHBOARD_JS.count('const referenceExpectedSources ='), 1)
        self.assertLess(DASHBOARD_JS.index('const referenceExpectedSources ='), DASHBOARD_JS.rindex('bootstrap();'))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for JavaScript contract acceptance')
    def test_reference_recovery_javascript_source_seam(self) -> None:
        # Use the emitted production asset, not a separately implemented client.
        # The harness extracts named functions and uses a synthetic DOM/fetch.
        harness = Path(__file__).with_name('dashboard_reference_recovery.cjs')
        self.assertTrue(harness.is_file(), 'JavaScript harness must ship in source distributions')
        with tempfile.TemporaryDirectory(prefix='megalodon-reference-tests-') as directory:
            asset = Path(directory) / 'dashboard.js'
            asset.write_text(DASHBOARD_JS, encoding='utf-8')
            environment = dict(os.environ, MEGALODON_TEST_ASSET=str(asset))
            environment.pop('MEGALODON_TEST_BASELINE', None)
            result = subprocess.run(
                [shutil.which('node'), '--test', str(harness)],
                cwd=directory, env=environment, capture_output=True,
                text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('# tests 67', result.stdout)
            self.assertIn('# fail 0', result.stdout)
            self.assertIn('# skipped 0', result.stdout)


if __name__ == '__main__':
    unittest.main()
