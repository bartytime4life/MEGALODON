"""Static policy checks for the dedicated issue #446 exact-head gate."""

from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "qwen-zero-effect.yml"


def test_qwen_zero_effect_workflow_is_bounded_and_exact_head():
    raw = WORKFLOW.read_text(encoding="utf-8")
    value = yaml.safe_load(raw)
    job = value["jobs"]["scoped-disabled-and-unbound"]

    assert value["permissions"] == {"contents": "read"}
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 8
    assert "github.event.pull_request.head.sha || github.sha" in raw
    assert "persist-credentials: false" in raw
    assert "constraints/test-linux-cp311.txt" in raw
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD: \"1\"" in raw
    assert "tests/test_qwen_zero_effect.py" in raw
    assert "tests/test_qwen_runtime_gate.py" in raw
    assert "tests/test_model_lifecycle.py" in raw
    assert "tests/test_model_evaluation_manifest.py" in raw
    assert "tests/test_model_evaluation.py" in raw
    assert "tests/test_qwen_evaluation_input.py" in raw
    assert "qwen.unbound.json" in raw
    assert "OWNER_MODEL_BINDING_NOT_RECORDED" in raw
    assert "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" in raw
    assert "retention-days: 30" in raw
    for prohibited in ("ollama pull", "ollama run", "systemctl", "curl ", "wget "):
        assert prohibited not in raw
