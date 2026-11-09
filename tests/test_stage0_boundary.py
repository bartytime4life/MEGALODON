"""Scoped application fences, never native containment or model acceptance."""

import json
import pytest

from megalodon import ai_provider, cli, companion_automation, dashboard
from megalodon import execution_boundary as boundary
from megalodon import local_model_runtime, model_library, model_lifecycle, model_telemetry, support_config
from megalodon.offline import tshark, zeek
from megalodon.offline import suricata_eve
from megalodon.offline.__main__ import main as offline_main
from test_offline import conn, field_row
from test_qwen_zero_effect import no_effects
from test_suricata_raw_eve import _minimal


@pytest.fixture(autouse=True)
def isolated_mode(monkeypatch):
    # Test-only restoration; production has no reset or mode-lifting API.
    monkeypatch.setattr(boundary, "_stage0_selected", False)
    monkeypatch.setattr(boundary, "_effects_entered", False)


def assert_denied(call):
    with pytest.raises(boundary.Stage0Denied, match="^STAGE0_OFFLINE_EFFECT_DENIED$"):
        call()


def test_latch_is_one_way_and_ignores_ambient_authority(monkeypatch):
    monkeypatch.setenv("MEGALODON_RUNTIME_MODE", "installed_runtime")
    monkeypatch.setenv("MEGALODON_STAGE0_OFFLINE", "false")
    with no_effects(monkeypatch):
        assert boundary.status()["mode"] == "installed_runtime"
        assert not boundary.effects_denied()
        boundary.select_stage0()
        boundary.select_stage0()
        first = boundary.status()
        first["mode"] = "installed_runtime"
        assert boundary.status()["mode"] == "stage0_offline"
        assert boundary.status()["acceptance_authority"] is False
        assert_denied(boundary.require_effects_allowed)
        assert local_model_runtime.binding_failure() == "OWNER_MODEL_BINDING_NOT_RECORDED"


def test_late_selection_cannot_certify_an_initialized_installed_workflow(monkeypatch):
    with no_effects(monkeypatch):
        boundary.require_effects_allowed()
        assert_denied(boundary.select_stage0)
        assert boundary.status()["mode"] == "unavailable"
        assert_denied(boundary.require_effects_allowed)
        assert_denied(boundary.select_stage0)


def test_late_cli_selection_has_fixed_output_without_traceback(monkeypatch, capsys):
    boundary.require_effects_allowed()
    with no_effects(monkeypatch):
        with pytest.raises(SystemExit) as result:
            cli.main(["--stage0-offline", "stage0-status"])
    assert result.value.code == 2
    assert capsys.readouterr() == ("", boundary.DENIAL + "\n")
    assert boundary.status()["mode"] == "unavailable"


@pytest.mark.parametrize("state", [None, 0, 1, "stage0_offline", "installed_runtime", [], {}])
def test_invalid_mode_never_recovers_into_permission(monkeypatch, state):
    monkeypatch.setattr(boundary, "_stage0_selected", state)
    with no_effects(monkeypatch):
        assert boundary.status()["mode"] == "unavailable"
        assert_denied(boundary.select_stage0)
        assert_denied(boundary.require_effects_allowed)


def test_missing_mode_refuses(monkeypatch):
    monkeypatch.delattr(boundary, "_stage0_selected")
    with no_effects(monkeypatch):
        assert_denied(boundary.select_stage0)
        assert_denied(boundary.require_effects_allowed)


@pytest.mark.parametrize("arguments", [
    [], ["hud"], ["dashboard"], ["run"], ["ai", "ask"], ["firewall-install"],
    ["block", "--ip", "192.0.2.1", "--apply"], ["readiness"], ["database-migrate"],
    ["stage0-status", "--config", "/private/not-read"], ["--help"],
    ["--stage0-offline", "stage0-status"], ["STAGE0-STATUS"], ["unknown\nprivate"],
])
def test_stage0_cli_refuses_before_parse_or_dispatch(monkeypatch, capsys, arguments):
    monkeypatch.setattr(cli, "build_parser", lambda: pytest.fail("ordinary parser reached"))
    with no_effects(monkeypatch):
        with pytest.raises(SystemExit) as result:
            cli.main(["--stage0-offline", *arguments])
    assert result.value.code == 2
    assert capsys.readouterr() == ("", boundary.DENIAL + "\n")
    assert boundary.effects_denied()


def test_status_and_second_cli_call_cannot_lift_latch(monkeypatch, capsys):
    with no_effects(monkeypatch):
        with pytest.raises(SystemExit) as result:
            cli.main(["--stage0-offline", "stage0-status"])
        assert result.value.code == 0
    value = json.loads(capsys.readouterr().out)
    assert value == boundary.status()
    with no_effects(monkeypatch):
        with pytest.raises(SystemExit) as result:
            cli.main(["capabilities"])
    assert result.value.code == 2
    assert capsys.readouterr() == ("", boundary.DENIAL + "\n")


@pytest.mark.parametrize("selector", ["--stage0", "--stage0-off"])
def test_abbreviated_selector_cannot_dispatch_installed_runtime(monkeypatch, capsys, selector):
    monkeypatch.setattr(cli, "_dashboard", lambda *_: pytest.fail("HUD dispatched"))
    with no_effects(monkeypatch):
        with pytest.raises(SystemExit) as result:
            cli.main([selector, "hud"])
    assert result.value.code == 2
    assert capsys.readouterr() == ("", boundary.DENIAL + "\n")
    assert boundary.effects_denied()


def test_misplaced_exact_selector_still_latches_and_refuses(monkeypatch, capsys):
    with no_effects(monkeypatch):
        with pytest.raises(SystemExit) as result:
            cli.main(["hud", "--stage0-offline"])
    assert result.value.code == 2
    assert boundary.effects_denied()
    assert capsys.readouterr() == ("", boundary.DENIAL + "\n")


@pytest.mark.parametrize("constructor", [
    lambda: support_config.SupportConfiguration(None),
    lambda: model_library.ModelLibrary(None),
    lambda: companion_automation.CompanionAutomation(None, None),
    lambda: model_lifecycle.ModelLifecycle(None),
    lambda: model_telemetry.ModelTelemetry(None),
    lambda: dashboard.serve(None, None, None),
])
def test_construction_refuses_before_locks_settings_paths_or_threads(monkeypatch, constructor):
    boundary.select_stage0()
    def forbidden(*args, **kwargs):
        pytest.fail("synchronization object constructed")
    for module in (support_config, model_library, companion_automation, model_lifecycle, model_telemetry):
        for name in ("Lock", "RLock", "Event", "Thread"):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, forbidden)
    with no_effects(monkeypatch):
        assert_denied(constructor)


@pytest.mark.parametrize("action", list(support_config.ACTION_FIELDS) + [
    None, "MODEL_STAGE_DOWNLOAD", "model%5fstage%5fdownload", "unknown", "model_test\n",
])
@pytest.mark.parametrize("entry", ["start", "_work"])
def test_entire_support_action_matrix_refuses_without_object_state(monkeypatch, action, entry):
    boundary.select_stage0()
    # No paths, settings, locks or workers exist on this object.
    manager = object.__new__(support_config.SupportConfiguration)
    with no_effects(monkeypatch):
        assert_denied(lambda: getattr(manager, entry)({"action": action}))


def test_http_support_action_refuses_before_body_or_auth_state(monkeypatch):
    boundary.select_stage0()
    handler = object.__new__(dashboard.DashboardHandler)
    sent = []
    handler._send_json = lambda value, **kwargs: sent.append((value, kwargs))
    # No socket, headers, request body or manager exists.
    with no_effects(monkeypatch):
        handler._support_config_action()
    assert sent == [({"state": "denied", "error_code": boundary.DENIAL}, {"status": 403})]


@pytest.mark.parametrize("owner,method,args", [
    (support_config.SupportConfiguration, "resume", ()),
    (support_config.SupportConfiguration, "start_background_tools", ()),
    (model_library.ModelLibrary, "prepare", ()),
    (model_library.ModelLibrary, "execute", ()),
    (model_library.ModelLibrary, "reuse", (None, None, None, None)),
    (model_library.ModelLibrary, "cancel", ()),
    (companion_automation.CompanionAutomation, "start", ()),
    (companion_automation.CompanionAutomation, "request_collection", ()),
    (model_lifecycle.ModelLifecycle, "start", ()),
    (model_lifecycle.ModelLifecycle, "request", ()),
    (model_lifecycle.ModelLifecycle, "_step", ()),
    (model_telemetry.ModelTelemetry, "refresh_installed_models", ()),
    (model_telemetry.ModelTelemetry, "_refresh", (None, None)),
    (model_telemetry.ModelTelemetry, "snapshot", ()),
])
def test_retained_or_queued_entry_refuses_before_using_old_state(monkeypatch, owner, method, args):
    boundary.select_stage0()
    instance = object.__new__(owner)
    with no_effects(monkeypatch):
        assert_denied(lambda: getattr(instance, method)(*args))


def test_direct_provider_collector_and_report_entries_refuse(monkeypatch):
    boundary.select_stage0()
    raw_request = ai_provider._request
    with no_effects(monkeypatch):
        for entry in (
            ai_provider.model_choices,
            lambda: raw_request("/api/tags", "GET", None, 3, catalog_read=True),
            lambda: companion_automation._run_fixed([], 0, 0),
            lambda: tshark._bounded_process((), env={}, cwd="", limits=None),
            lambda: offline_main([]),
        ):
            assert_denied(entry)


def test_pure_packet_and_flow_normalizers_remain_available(monkeypatch):
    packet_row, flow_row, alert_row = field_row(), conn(), _minimal()
    source = {"sensor_id": "sensor-a", "run_id": "run-a", "ruleset_id": "ruleset-a",
              "engine": "suricata", "adapter_profile": "suricata-eve-alert-v1",
              "declared_version": "8.0.7", "version_basis": "operator_declared",
              "ruleset_basis": "operator_declared"}
    boundary.select_stage0()
    with no_effects(monkeypatch):
        packet = tshark.parse_fields(packet_row)
        flow = zeek.parse_flow(flow_row)
        alert = suricata_eve._normalize_raw(alert_row, source_identity=source, source_record_index=1)
    assert packet.src_ip == flow.src_ip == "192.0.2.10"
    assert packet.dst_ip == flow.dst_ip == "198.51.100.20"
    assert alert["src_ip"] == "192.0.2.10"


def test_default_cli_keeps_ordinary_dispatch(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "_capabilities", lambda args: called.append(args.command) or 0)
    with pytest.raises(SystemExit) as result:
        cli.main(["capabilities"])
    assert result.value.code == 0 and called == ["capabilities"]
    assert boundary.status()["mode"] == "installed_runtime"
