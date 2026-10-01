"""Reports read the managed history independently of the HUD's short window."""
from megalodon.dashboard_assets import DASHBOARD_JS, INDEX_HTML
from megalodon.dashboard_reports import REPORTS_JS


def test_retired_browser_snapshot_builder_is_not_an_alternative_report_path():
    assert 'function reportSnapshot()' not in DASHBOARD_JS
    assert 'function roomReportDocument(' not in DASHBOARD_JS
    assert 'roomState.snapshot' not in REPORTS_JS
    assert 'state.ingestionRuns' not in REPORTS_JS
    assert 'id="report-scope"' not in INDEX_HTML
    assert "'/api/reports/'+action" in REPORTS_JS
    assert "selected dates across retained evidence" in INDEX_HTML
