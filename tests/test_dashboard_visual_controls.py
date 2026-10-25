"""Visual controls edit the same exact values and preserve explicit save paths."""
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from megalodon.dashboard_assets import DASHBOARD_JS, DASHBOARD_CSS, INDEX_HTML
from megalodon.dashboard_polish import POLISH_JS
from megalodon.dashboard_visual_controls import VISUAL_CONTROLS_JS, VISUAL_CONTROLS_CSS


def test_visual_editor_interactions_preserve_exact_values_and_dirty_events():
    node=shutil.which('node')
    if not node:pytest.skip('Node unavailable')
    result=subprocess.run([node,str(Path(__file__).with_name('visual_controls_browser.cjs'))],input=json.dumps({'code':VISUAL_CONTROLS_JS}),capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr


def test_exclusive_choices_use_native_radio_semantics_and_safe_label_activation():
    assert "radio.type='radio'" in POLISH_JS and "radio.name='choice-'+select.id" in POLISH_JS
    assert "group.setAttribute('role', 'radiogroup')" in POLISH_JS
    assert "group.setAttribute('aria-label', name)" in POLISH_JS
    assert "if(next!==key)" in POLISH_JS, 'unchanged options retain radio nodes and focus'
    assert "group.contains(event.target)" in POLISH_JS, 'outer labels cannot cancel nested radio clicks'
    assert "select.value = option.value; fire(select)" in POLISH_JS
    assert 'input[type="radio"]' in VISUAL_CONTROLS_CSS


def test_visual_controls_are_local_and_budget_matches_backend_precision():
    assert VISUAL_CONTROLS_JS in DASHBOARD_JS and DASHBOARD_CSS.endswith(VISUAL_CONTROLS_CSS)
    assert 'id="storage-cap" type="number" min="1" max="4096" step="any"' in INDEX_HTML
    for forbidden in ['fetch(', 'localStorage', 'innerHTML', 'XMLHttpRequest', '.click()']:
        assert forbidden not in VISUAL_CONTROLS_JS
    for source in ['storage-days','storage-cap','support-model-timeout','reports-time','network-enabled']:
        assert 'id="'+source+'"' in INDEX_HTML


def test_visual_component_states_override_setup_inputs_and_mobile_time_has_its_own_row():
    # The Setup ID rules are stronger than the global control treatment. Keep
    # state selectors at that scope so checked controls cannot become dark-on-dark.
    assert '#workspace-setup .vc-switch-control input[role="switch"]:checked { background:#67cbb1;' in VISUAL_CONTROLS_CSS
    assert '#workspace-setup .vc-switch-control input[role="switch"]:disabled' in VISUAL_CONTROLS_CSS
    assert '#workspace-setup label.polish-radio { display:inline-flex; flex-direction:row;' in VISUAL_CONTROLS_CSS
    assert '#workspace-setup label.polish-radio input[type="radio"]:checked { background:#91ead2;' in VISUAL_CONTROLS_CSS
    assert '#reports-schedule-form>label:has(.vc-preset-editor) { grid-column:1/-1; width:100%; }' in VISUAL_CONTROLS_CSS
    assert '#reports-schedule-save { grid-column:1/-1;' in VISUAL_CONTROLS_CSS
    assert 'grid-template-columns:minmax(145px,1fr) minmax(110px,.75fr)' in VISUAL_CONTROLS_CSS
