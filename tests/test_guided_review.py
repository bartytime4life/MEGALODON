"""`megalodon review`: each finding, worst first, with numbered choices; a command runs only after you confirm it,
as the arguments shown, and every choice is logged."""
from __future__ import annotations

import json
import sys

import pytest

from megalodon import guided_review as gr
from megalodon import results
from test_security_report import AT, NOW, build, home, keep  # noqa: F401


def conversation(answers):
    queue = list(answers)
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return queue.pop(0) if queue else "q"
    return ask, asked


def go(report, answers, tmp_path, ran=None):
    said, ran = [], ran if ran is not None else []
    ask, asked = conversation(answers)
    done = gr.review(report, ask=ask, say=said.append, run=lambda argv: ran.append(argv) or 0,
                     log=tmp_path / "review.jsonl", now=NOW)
    return done, said, ran, asked


def report_with_findings():
    keep("hardening", [dict(rule_id="X", severity="MEDIUM", subject="s")])
    keep("persistence", [dict(change="added", category="cron", location="/etc/cron.d/x", severity="HIGH")])
    return build()


def test_the_worst_comes_first_and_nothing_runs_without_yes(home, tmp_path):  # noqa: F811
    done, said, ran, asked = go(report_with_findings(), ["4", "n", "s"], tmp_path)
    first = next(line for line in said if line.startswith("[1/"))
    assert "HIGH" in first and "PERSISTENCE_ADDED" in first
    assert ran == [] and done[0]["ran"] is False and "    Not run." in said


def test_a_confirmed_choice_runs_its_arguments_without_a_shell(home, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(gr, "_launcher", lambda: ["/opt/megalodon/bin/megalodon"])
    done, said, ran, asked = go(report_with_findings(), ["4", "y", "q"], tmp_path)
    assert ran == [["/opt/megalodon/bin/megalodon", "persistence", "accept"]]
    assert done == [dict(schema=gr.SCHEMA, at="2026-11-26T08:00:00Z", choice="expected",
                         label="It was you: record things as they are now", command="megalodon persistence accept",
                         check="persistence", rule_id="PERSISTENCE_ADDED", where="/etc/cron.d/x", ran=True,
                         exit_code=0)]
    assert "    Note: This records every current change of this check as expected, not only this one." in said
    log = tmp_path / "review.jsonl"
    assert log.stat().st_mode & 0o777 == 0o600 and json.loads(log.read_text()) == done[0]


def test_sudo_keeps_sudo_and_runs_this_installation(monkeypatch):
    monkeypatch.setattr(gr, "_launcher", lambda: [sys.executable, "-m", "megalodon"])
    assert gr.resolve(["sudo", "megalodon", "evidence", "collect"]) == [
        "sudo", sys.executable, "-m", "megalodon", "evidence", "collect"]
    assert gr.resolve(["systemctl", "status"]) == ["systemctl", "status"]


def test_a_choice_with_placeholders_is_printed_never_run(home, tmp_path):  # noqa: F811
    keep("vulns", [dict(rule_id="FIX_NOT_RUNNING", severity="MEDIUM", subject="sshd")])
    done, said, ran, asked = go(build(), ["2", "y"], tmp_path)
    assert ran == [] and done[0]["ran"] is False
    assert any(line.startswith("    Adapt and run this yourself: sudo systemctl restart SERVICE") for line in said)
    assert not any("Run it now" in prompt for prompt in asked)


def test_a_hostile_name_runs_as_one_argument(home, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(gr, "_launcher", lambda: ["megalodon"])
    keep("egress", [dict(rule_id="NEW_OUTBOUND_PROGRAM", severity="HIGH", program="/tmp/x; rm -rf ~",
                         address="9.9.9.9")])
    report = build()
    choices = next(c for c in report["checks"] if c["check"] == "egress")["findings"][0]["choices"]
    number = next(i for i, c in enumerate(choices, 1) if c["choice"] == "expected")
    done, said, ran, asked = go(report, [str(number), "y"], tmp_path)
    assert ran == [["megalodon", "egress", "allow", "/tmp/x; rm -rf ~"]]


def test_skipping_and_stopping(home, tmp_path):  # noqa: F811
    done, said, ran, asked = go(report_with_findings(), ["", "99", "q"], tmp_path)
    assert done == [] and ran == [] and not (tmp_path / "review.jsonl").exists()
    assert sum(prompt == "Your choice: " for prompt in asked) == 2, "a blank answer and an unknown number skip"


def test_incidents_are_gone_through_too(home, tmp_path):  # noqa: F811
    from megalodon import response_engine as engine
    engine.write_default_policy()
    report = dict(checked_at=AT, findings=[dict(rule_id="PACKAGE_MISMATCH", severity="CRITICAL", path="/usr/bin/ls")])
    engine.run(signals=engine.path_signals(report, "binaries", "path"), now=NOW, protected=set())
    built = build()
    titles = [item["heading"] for item in gr.items(built)]
    assert titles[0].startswith("Incident ") and "PACKAGE_MISMATCH" in titles[0]


def test_nothing_to_go_through(home, tmp_path):  # noqa: F811
    done, said, ran, asked = go(build(), [], tmp_path)
    assert done == [] and asked == [] and "There is nothing to go through." in said[0]


def test_the_command_needs_a_terminal(home, monkeypatch, capsys):  # noqa: F811
    from megalodon.cli import main
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit) as exit_:
        main(["review"])
    assert exit_.value.code == 2 and "run it in a terminal" in capsys.readouterr().err


@pytest.mark.parametrize("answer", ["", "maybe", "no"])
def test_only_yes_runs_a_command(home, tmp_path, answer):  # noqa: F811
    done, said, ran, asked = go(report_with_findings(), ["1", answer, "q"], tmp_path)
    assert ran == [] and done[0]["ran"] is False


def test_stopping_ends_the_review(home, tmp_path):  # noqa: F811
    done, said, ran, asked = go(report_with_findings(), ["q", "1", "y"], tmp_path)
    assert not any(line.startswith("[2/") for line in said) and ran == []


def test_the_worst_comes_first_whatever_check_found_it(home, tmp_path):  # noqa: F811
    # Persistence is listed before secrets; a CRITICAL exposed secret still comes before a MEDIUM entry.
    keep("persistence", [dict(change="changed", category="cron", location="/etc/cron.d/x", severity="MEDIUM")])
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="CRITICAL", path="/var/www/.env")])
    assert [item["severity"] for item in gr.items(build())] == ["CRITICAL", "MEDIUM"]


def test_findings_beyond_those_listed_are_pointed_to(home, tmp_path):  # noqa: F811
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="HIGH", path=f"/var/www/{n}.env") for n in range(30)])
    done, said, ran, asked = go(build(), ["q"], tmp_path)
    assert any("5 more finding(s) were not listed here; all of them: megalodon report --all" in line
               for line in said)
