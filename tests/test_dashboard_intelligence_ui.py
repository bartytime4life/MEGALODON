"""Current source/query identity and truthful local-learning status."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_intelligence import KNOWLEDGE_JS


@pytest.mark.parametrize('scenario', ['success', 'failure', 'edited', 'repeated', 'paused',
                                      'device-success', 'device-failure', 'device-deselected'])
def test_reference_search_and_learning_status(scenario):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('intelligence_browser.cjs'))],
                            input=json.dumps(dict(code=KNOWLEDGE_JS, scenario=scenario)),
                            text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
