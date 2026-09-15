"""Exact, hypothetical binary-classifier workload; no telemetry or I/O."""

from __future__ import annotations

from fractions import Fraction


RATE_SCALE = 1_000_000
MAX_POPULATION = 1_000_000_000
UNITS = ("event", "flow", "source-window")


class WorkloadInputError(ValueError):
    """An assumption is outside the closed hypothetical input contract."""


def _ratio(value: Fraction) -> dict[str, str]:
    # Decimal strings preserve exact integers in JSON consumers, including JS.
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def project_alert_workload(
    *,
    population: int,
    prevalence_ppm: int,
    sensitivity_ppm: int,
    false_positive_ppm: int,
    unit: str,
) -> dict[str, object]:
    """Project one binary decision per unit from explicitly supplied assumptions.

    PPM rates are integers in [0, 1_000_000]. No rate is inferred from corpus
    matches, detector severities, model output, or observed telemetry. Expected
    counts can be fractional. The conditional ratio is undefined when no
    positive predictions are expected; that case is never reported as zero.
    """
    if type(population) is not int or not 1 <= population <= MAX_POPULATION:
        raise WorkloadInputError("INVALID_BASE_RATE_INPUT")
    for value in (prevalence_ppm, sensitivity_ppm, false_positive_ppm):
        if type(value) is not int or not 0 <= value <= RATE_SCALE:
            raise WorkloadInputError("INVALID_BASE_RATE_INPUT")
    if type(unit) is not str or len(unit) > 13 or unit not in UNITS:
        raise WorkloadInputError("INVALID_BASE_RATE_INPUT")

    present = Fraction(population * prevalence_ppm, RATE_SCALE)
    absent = population - present
    true_positive = present * Fraction(sensitivity_ppm, RATE_SCALE)
    false_positive = absent * Fraction(false_positive_ppm, RATE_SCALE)
    false_negative = present - true_positive
    true_negative = absent - false_positive
    alerts = true_positive + false_positive

    return {
        "schema": "alert-workload-projection-v1",
        "status": "projected",
        "evidence_quality": ["hypothetical-only", "uncalibrated"],
        "assumptions": {
            "source": "operator-supplied",
            "population": population,
            "unit": unit,
            "decisions_per_unit": 1,
            "rate_scale": RATE_SCALE,
            "prevalence_ppm": prevalence_ppm,
            "sensitivity_ppm": sensitivity_ppm,
            "false_positive_ppm": false_positive_ppm,
        },
        "expected_counts": {
            "condition_present": _ratio(present),
            "condition_absent": _ratio(absent),
            "true_positive": _ratio(true_positive),
            "false_positive": _ratio(false_positive),
            "false_negative": _ratio(false_negative),
            "true_negative": _ratio(true_negative),
            "alerted_units": _ratio(alerts),
        },
        "positive_predictive_value": {
            "status": "defined" if alerts else "undefined_no_expected_alerts",
            "ratio": _ratio(true_positive / alerts) if alerts else None,
        },
        "limitations": [
            "Hypothetical assumptions, not measured MEGALODON accuracy or calibration.",
            "One binary decision per unit, not raw alert volume after cooldown or aggregation.",
            "All rates must describe the same population, unit and time selection; unverified here.",
            "No incident likelihood, malicious-traffic verdict or response authority.",
        ],
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
        "model_status": "not_attempted",
    }
