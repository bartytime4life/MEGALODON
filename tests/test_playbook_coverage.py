"""Every HIGH or CRITICAL finding a scheduled check can raise on this machine reaches a playbook, as
docs/response-engine.md says. A rule the default policy cannot decide is listed here, with why."""
from __future__ import annotations

import re

import pytest

from megalodon import binary_integrity, log_integrity, response_engine as re_, tamper


def playbook(name):
    text = re_.DEFAULT_POLICY_TEXT
    text = text[text.index(f'name = "{name}"'):]
    return set(re.findall(r'"([A-Z][A-Z0-9_]{3,})"', text[:text.index("actions")]))


# Raised by the heartbeat monitor or `commands verify`, off the machine: the local engine never sees them.
OFF_THE_MACHINE = {"HEARTBEAT_FORGED", "HEARTBEAT_REPLAYED", "HEARTBEAT_REPORTS_TAMPER", "HEARTBEAT_SILENT",
                   "HEARTBEAT_GAP", "SENSOR_STATE_CHANGED", "TAMPER_BASELINE_LOST", "COMMAND_LOG_LOST",
                   "COMMAND_LOG_ROLLED_BACK", "COMMAND_LOG_RESTARTED"}


def test_every_high_tamper_finding_reaches_sensor_tampering():
    high = {rule for rule, value in tamper.RULES.items() if value[0] in ("HIGH", "CRITICAL")}
    high |= {rule for rule, severity, _ in tamper.CONFIG_KINDS.values() if severity in ("HIGH", "CRITICAL")}
    assert high - OFF_THE_MACHINE - playbook("sensor-tampering") == set()


@pytest.mark.parametrize("rule, shown", [
    ("PROGRAM_ADDED", "/usr/bin/sshd-helper"), ("PROGRAM_WRITABLE", "/usr/bin/passwd"),
    ("PACKAGE_MISMATCH", "/usr/bin/ls"), ("PACKAGE_RECORD_CHANGED", "/usr/bin/ls"),
])
def test_every_high_program_integrity_finding_reaches_a_playbook(rule, shown):
    assert binary_integrity._severity(shown, rule) in ("HIGH", "CRITICAL")
    assert rule in playbook("trojaned-program-or-wiped-log")


def test_high_log_findings_reach_the_wiped_log_playbook():
    from megalodon import journal_integrity
    high = {rule for rule, severity in log_integrity.SEVERITY.items() if severity in ("HIGH", "CRITICAL")}
    high |= {rule for rule, severity in journal_integrity.SEVERITY.items() if severity in ("HIGH", "CRITICAL")}
    assert high and high - playbook("trojaned-program-or-wiped-log") == set()
