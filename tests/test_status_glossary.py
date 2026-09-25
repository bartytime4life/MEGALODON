"""The shared status glossary must stay complete and reachable from the HUD."""

from __future__ import annotations

import importlib
import sys

import pytest

from megalodon import capabilities, readiness, runtime_status, tool_heartbeat, tool_installer
from megalodon.status_glossary import (
    GLOSSARY_ANCHOR_ID,
    STATUS_GLOSSARY_CSS,
    STATUS_GLOSSARY_HTML,
)


def test_glossary_anchor_is_embedded_once():
    assert STATUS_GLOSSARY_HTML.count(f'id="{GLOSSARY_ANCHOR_ID}"') == 1


def test_glossary_css_defines_its_classes():
    for selector in (
        ".status-glossary", ".status-glossary-group", ".status-glossary-where",
        ".status-glossary-callout",
    ):
        assert selector in STATUS_GLOSSARY_CSS


def test_glossary_labels_present_for_each_surface():
    expected = [
        "Found candidate", "Not found", "Not checked",
        "Running", "Not running", "Not applicable",
        "Green", "Amber", "Red", "Grey",
        "Idle", "Succeeded", "Failed",
        "Implemented", "Optional", "Evaluation only", "Contract only",
        "Manual only", "Guest only", "Proposed", "Unsupported",
        "Connected", "Not configured", "Reconciliation required",
        "Degraded", "Unknown (quality)",
    ]
    for label in expected:
        assert f"<dt>{label}</dt>" in STATUS_GLOSSARY_HTML, f"missing glossary entry for {label!r}"


@pytest.mark.parametrize(
    "module_name, vocabulary",
    [
        ("readiness", readiness.STATUSES),
        ("runtime_status", runtime_status.STATUSES),
        ("capabilities", capabilities.STATUSES),
        ("tool_heartbeat", tool_heartbeat.LIGHTS),
        ("tool_installer", tool_installer.JOB_STATES),
    ],
)
def test_status_glossary_module_asserts_full_coverage(module_name, vocabulary):
    """Independently re-derive the covered raw values from status_glossary's
    own source and confirm they still equal the live vocabulary. This fails
    if either side changes without the other, before the shared module's own
    import-time assertion would (belt and suspenders on the anti-drift check).
    """
    import megalodon.status_glossary as glossary

    covered = {
        value
        for _heading, _where, source, terms in glossary._GROUPS  # noqa: SLF001
        if source is vocabulary
        for value, _label, _meaning in terms
        if value is not None
    }
    assert covered == set(vocabulary), (
        f"status_glossary group for {module_name} covers {sorted(covered)} "
        f"but {module_name}.STATUSES/LIGHTS/JOB_STATES is {sorted(vocabulary)}"
    )


def test_glossary_raises_when_a_vocabulary_gains_an_undocumented_value(monkeypatch):
    """Regression guard for the anti-drift check itself, not just its output."""
    monkeypatch.setattr(tool_installer, "JOB_STATES", frozenset(tool_installer.JOB_STATES | {"paused"}))
    sys.modules.pop("megalodon.status_glossary", None)
    try:
        with pytest.raises(AssertionError, match="status glossary group"):
            importlib.import_module("megalodon.status_glossary")
    finally:
        sys.modules.pop("megalodon.status_glossary", None)
        monkeypatch.undo()
        importlib.import_module("megalodon.status_glossary")


def test_glossary_reachable_from_hud_panels():
    from megalodon.dashboard_assets import INDEX_HTML

    assert "__GLOSSARY_ANCHOR__" not in INDEX_HTML
    assert "__STATUS_GLOSSARY__" not in INDEX_HTML
    assert f'href="#{GLOSSARY_ANCHOR_ID}"' in INDEX_HTML
    assert INDEX_HTML.count(f'id="{GLOSSARY_ANCHOR_ID}"') == 1


def test_glossary_hash_target_resolves_to_help_workspace():
    from megalodon.dashboard_assets import DASHBOARD_JS

    assert f"'{GLOSSARY_ANCHOR_ID}': 'help'" in DASHBOARD_JS
    assert "'help-language': 'help'" in DASHBOARD_JS
