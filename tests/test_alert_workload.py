"""Hypothetical workload keeps exact units, honest denominators and no effects."""

from __future__ import annotations

import builtins
from fractions import Fraction
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import urllib.request

import pytest

from megalodon import config, evaluation, firewall, qwen_advisory, storage
from megalodon.alert_workload import WorkloadInputError, project_alert_workload
from megalodon.reference import loader


ASSUMPTIONS = {
    "population": 100_000,
    "prevalence_ppm": 1_000,
    "sensitivity_ppm": 900_000,
    "false_positive_ppm": 10_000,
    "unit": "source-window",
}


def project(**changes):
    return project_alert_workload(**(ASSUMPTIONS | changes))


def ratio(value):
    assert type(value["numerator"]) is str
    assert type(value["denominator"]) is str
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def argv(**changes):
    result = ["base-rate"]
    for name, value in (ASSUMPTIONS | changes).items():
        result.extend(["--" + name.replace("_", "-"), str(value)])
    return result


def test_rare_condition_example_has_more_false_than_true_alerts():
    report = project()
    counts = {key: ratio(value) for key, value in report["expected_counts"].items()}
    assert counts == {
        "condition_present": 100, "condition_absent": 99_900,
        "true_positive": 90, "false_positive": 999,
        "false_negative": 10, "true_negative": 98_901,
        "alerted_units": 1_089,
    }
    assert ratio(report["positive_predictive_value"]["ratio"]) == Fraction(10, 121)
    assert report["evidence_quality"] == ["hypothetical-only", "uncalibrated"]
    assert report["assumptions"] == ASSUMPTIONS | {
        "source": "operator-supplied", "rate_scale": 1_000_000, "decisions_per_unit": 1,
    }


@pytest.mark.parametrize("prevalence", [0, 1, 1_000, 999_999, 1_000_000])
@pytest.mark.parametrize("sensitivity,fpr", [(0, 0), (0, 1_000_000), (1_000_000, 0), (1_000_000, 1_000_000), (333_333, 7)])
def test_confusion_totals_conserve_population_and_denominators(prevalence, sensitivity, fpr):
    report = project(population=999_999_999, prevalence_ppm=prevalence,
                     sensitivity_ppm=sensitivity, false_positive_ppm=fpr)
    c = {key: ratio(value) for key, value in report["expected_counts"].items()}
    assert c["true_positive"] + c["false_negative"] == c["condition_present"]
    assert c["false_positive"] + c["true_negative"] == c["condition_absent"]
    assert sum(c[k] for k in ("true_positive", "false_positive", "true_negative", "false_negative")) == 999_999_999
    assert c["alerted_units"] == c["true_positive"] + c["false_positive"]
    assert all(value >= 0 for value in c.values())
    ppv = report["positive_predictive_value"]
    if c["alerted_units"]:
        assert ppv["status"] == "defined"
        assert ratio(ppv["ratio"]) * c["alerted_units"] == c["true_positive"]
    else:
        assert ppv == {"status": "undefined_no_expected_alerts", "ratio": None}
    assert len(json.dumps(report).encode("utf-8")) < 4096


def test_fractional_counts_and_json_roundtrip_do_not_round_away_rare_events():
    report = json.loads(json.dumps(project(population=1, prevalence_ppm=1, sensitivity_ppm=1)))
    assert ratio(report["expected_counts"]["true_positive"]) == Fraction(1, 10**12)
    large = project(population=999_999_999, prevalence_ppm=999_983, sensitivity_ppm=999_979)
    exact = ratio(large["expected_counts"]["true_positive"])
    assert exact == Fraction(999_999_999 * 999_983 * 999_979, 10**12)
    assert exact.numerator > 2**53


def test_prevalence_changes_precision_without_changing_detector_sensitivity():
    rare, common = project(), project(prevalence_ppm=10_000)
    assert ratio(common["positive_predictive_value"]["ratio"]) == Fraction(10, 21)
    assert ratio(rare["positive_predictive_value"]["ratio"]) < ratio(common["positive_predictive_value"]["ratio"])
    doubled = project(population=200_000)
    assert doubled["positive_predictive_value"] == rare["positive_predictive_value"]
    assert ratio(doubled["expected_counts"]["alerted_units"]) == 2_178


def test_max_population_and_zero_rates_are_valid_but_zero_duplicate_is_not(capsys):
    assert ratio(project(population=1_000_000_000)["expected_counts"]["condition_present"]) == 1_000_000
    with pytest.raises(SystemExit) as error:
        evaluation.main(argv(sensitivity_ppm=0) + ["--sensitivity-ppm", "1"])
    assert error.value.code == 2
    assert json.loads(capsys.readouterr().err)["error"] == "INVALID_ARGUMENTS"


class Hostile:
    def __eq__(self, other):
        raise AssertionError("untrusted equality executed")

    def __int__(self):
        raise AssertionError("untrusted conversion executed")

    def __str__(self):
        raise AssertionError("untrusted rendering executed")


class IntSubclass(int):
    pass


class StrSubclass(str):
    pass


@pytest.mark.parametrize("key", ["population", "prevalence_ppm", "sensitivity_ppm", "false_positive_ppm"])
@pytest.mark.parametrize("value", [True, False, None, 0.1, float("nan"), float("inf"), "1000", -1, 10**100, IntSubclass(1), Hostile()], ids=["true", "false", "null", "float", "nan", "infinity", "string", "negative", "huge", "subclass", "hostile"])
def test_invalid_numeric_assumptions_refuse_without_coercion(key, value):
    with pytest.raises(WorkloadInputError, match="^INVALID_BASE_RATE_INPUT$"):
        project(**{key: value})


@pytest.mark.parametrize("changes", [
    {"population": 0}, {"population": 1_000_000_001},
    {"prevalence_ppm": 1_000_001}, {"sensitivity_ppm": 1_000_001},
    {"false_positive_ppm": 1_000_001}, {"unit": "packet"},
    {"unit": "flow\nsecret"}, {"unit": "x" * 100_000},
    {"unit": StrSubclass("flow")}, {"unit": Hostile()},
], ids=["zero-population", "population-over", "prevalence-over", "sensitivity-over", "fpr-over", "unknown-unit", "newline", "oversized", "subclass", "hostile"])
def test_bounds_and_unit_vocabulary(changes):
    with pytest.raises(WorkloadInputError, match="^INVALID_BASE_RATE_INPUT$"):
        project(**changes)


@pytest.mark.parametrize("unit", ["event", "flow", "source-window"])
def test_cli_success_deterministic_owned_output(unit, capsys):
    assert evaluation.main(argv(unit=unit)) == 0
    first = capsys.readouterr().out
    assert evaluation.main(argv(unit=unit)) == 0
    assert capsys.readouterr().out == first
    result = json.loads(first)
    result["expected_counts"]["true_positive"]["numerator"] = "0"
    assert ratio(project(unit=unit)["expected_counts"]["true_positive"]) == 90


@pytest.mark.parametrize("value", ["", "01", "+1", "-1", "1.0", "1e3", " 1", "1 ", "١", "１", "NaN", "Infinity", "1000001", "9" * 100_000, "$(command)"])
def test_cli_numeric_denials_are_bounded_and_never_echo_input(value, capsys):
    with pytest.raises(SystemExit) as error:
        evaluation.main(argv(prevalence_ppm=value))
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == evaluation._failure("INVALID_ARGUMENTS")
    assert len(output.err) < 512


@pytest.mark.parametrize("name", ASSUMPTIONS)
def test_cli_requires_every_assumption_once(name, capsys):
    args = argv()
    option = "--" + name.replace("_", "-")
    index = args.index(option)
    for invalid in (args[:index] + args[index + 2:], args + args[index:index + 2]):
        with pytest.raises(SystemExit) as error:
            evaluation.main(invalid)
        assert error.value.code == 2
        assert json.loads(capsys.readouterr().err)["error"] == "INVALID_ARGUMENTS"


@pytest.mark.parametrize("extra", [["--endpoint", "https://invalid.example"], ["--prevalence", "1"], ["--apply"], ["@assumptions.json"]])
def test_cli_has_no_endpoint_file_expansion_or_action_options(extra, capsys):
    with pytest.raises(SystemExit) as error:
        evaluation.main(argv() + extra)
    assert error.value.code == 2
    assert json.loads(capsys.readouterr().err)["error"] == "INVALID_ARGUMENTS"


@pytest.mark.parametrize("unit", ["packet", "FLOW", "flow\n", "x" * 100_000])
def test_cli_invalid_units_produce_only_fixed_errors(unit, capsys):
    with pytest.raises(SystemExit) as error:
        evaluation.main(argv(unit=unit))
    assert error.value.code == 2
    assert json.loads(capsys.readouterr().err) == evaluation._failure("INVALID_ARGUMENTS")


def test_success_and_denial_do_not_load_data_models_or_cross_effect_boundaries(monkeypatch, capsys):
    def denied(*args, **kwargs):
        raise AssertionError("hypothetical projection crossed an effect boundary")

    with monkeypatch.context() as patch:
        for owner, name in (
            (builtins, "open"), (Path, "open"),
            (socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"),
            (http.client.HTTPConnection, "request"), (urllib.request, "urlopen"),
            (sqlite3, "connect"), (subprocess, "Popen"), (subprocess, "run"),
            (storage, "Store"), (storage, "DashboardStore"),
            (firewall, "NftablesFirewall"), (config, "load_settings"),
            (qwen_advisory, "invoke_qwen_advisory"),
            (evaluation, "load_iana"), (evaluation, "evaluate_corpus"),
            (loader, "_read_resource"),
        ):
            patch.setattr(owner, name, denied)
        assert evaluation.main(argv()) == 0
        with pytest.raises(WorkloadInputError):
            project(unit=Hostile())
        with pytest.raises(SystemExit):
            evaluation.main(argv(prevalence_ppm="secret\ncommand"))
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["network_access_performed"] is False
    for key in ("persistence_status", "action_status", "model_status"):
        assert result[key] == "not_attempted"
    assert "secret" not in output.err
