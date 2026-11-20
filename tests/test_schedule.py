"""Scheduling: a plan first, units only with --yes, and only MEGALODON's units are ever removed."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from megalodon import schedule as sc


class Systemctl:
    def __init__(self, code=0):
        self.calls, self.code = [], code

    def __call__(self, system, *args):
        self.calls.append((system, args))
        return subprocess.CompletedProcess(["systemctl", *args], self.code, "", "" if not self.code else "no bus")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home/.config/megalodon").mkdir(parents=True)
    return tmp_path / "home"


def baselines(home, *names):
    for name in names:
        (home / ".config/megalodon" / name).write_text("{}")


def test_the_plan_lists_jobs_missing_baselines_and_cron_lines(home, tmp_path):
    baselines(home, "persistence.json")
    result = sc.plan(system=False, directory=tmp_path / "units", launcher=["/usr/bin/megalodon"])
    jobs = {row["job"]: row for row in result["jobs"]}
    assert "ancestry" not in jobs and {s["job"] for s in result["skipped"]} == {"ancestry", "ebpf", "containers", "enforce", "commands"}, \
        "the live ancestry watch, the eBPF and container checks and enforcement need root"
    assert jobs["persistence"]["baseline"] is None
    assert jobs["listeners"]["baseline"] == "/usr/bin/megalodon listeners baseline"
    assert jobs["rootkit"]["command"] == "/usr/bin/megalodon rootkit check --skip-ports --alert"
    assert jobs["binaries"]["cron"] == "17 3 * * * /usr/bin/megalodon binaries check --alert"
    assert not (tmp_path / "units").exists(), "plan writes nothing"
    system = {row["job"]: row for row in sc.plan(system=True, directory=tmp_path / "u2", launcher=["m"])["jobs"]}
    assert system["ancestry"]["every"] == "always running"


def test_install_refuses_missing_baselines_then_writes_and_enables(home, tmp_path):
    folder, systemctl = tmp_path / "units", Systemctl()
    with pytest.raises(sc.ScheduleError, match="missing baselines for listeners"):
        sc.install(system=False, only=["listeners"], directory=folder, launcher=["m"], runner=systemctl)
    assert systemctl.calls == [] and not folder.exists()
    baselines(home, "listeners.json")
    result = sc.install(system=False, only=["listeners", "rootkit"], directory=folder, launcher=["/x/megalodon"],
                        runner=systemctl)
    assert result["ok"] and result["enabled"] == ["megalodon-listeners.timer", "megalodon-rootkit.timer"]
    assert systemctl.calls == [(False, ("daemon-reload",)),
                               (False, ("enable", "--now", "megalodon-listeners.timer", "megalodon-rootkit.timer"))]
    service = (folder / "megalodon-listeners.service").read_text()
    assert sc.MARKER in service and "ExecStart=/x/megalodon listeners check --alert" in service
    assert "SuccessExitStatus=1" in service and "NoNewPrivileges=yes" in service
    assert "OnCalendar=*:0/10" in (folder / "megalodon-listeners.timer").read_text()


def test_a_unit_that_is_not_ours_is_never_overwritten_or_removed(home, tmp_path):
    folder = tmp_path / "units"
    folder.mkdir()
    (folder / "megalodon-rootkit.service").write_text("[Service]\nExecStart=/usr/local/bin/my-own\n")
    with pytest.raises(sc.ScheduleError, match="not MEGALODON's"):
        sc.install(system=False, only=["rootkit"], directory=folder, launcher=["m"], runner=Systemctl())
    (folder / "megalodon-other.service").write_text("[Service]\nExecStart=/bin/true\n")
    baselines(home, "webroot.json")
    sc.install(system=False, only=["webroot"], directory=folder, launcher=["m"], runner=Systemctl())
    systemctl = Systemctl()
    result = sc.remove(system=False, directory=folder, runner=systemctl)
    assert sorted(Path(p).name for p in result["removed"]) == ["megalodon-webroot.service", "megalodon-webroot.timer"]
    assert systemctl.calls[0] == (False, ("disable", "--now", "megalodon-webroot.timer"))
    assert sorted(p.name for p in folder.iterdir()) == ["megalodon-other.service", "megalodon-rootkit.service"]


def test_a_long_running_watch_is_a_restarting_service(tmp_path):
    files = sc.units(next(j for j in sc.JOBS if j.name == "ancestry"), ["m"], True)
    assert list(files) == ["megalodon-ancestry.service"]
    text = files["megalodon-ancestry.service"]
    assert "Restart=on-failure" in text and "WantedBy=multi-user.target" in text and "Type=oneshot" not in text


def test_cli_needs_yes_and_reports_failures(home, tmp_path, capsys, monkeypatch):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("schedule", "plan", "--user", "--unit-dir", str(tmp_path / "u")) == 0
    assert json.loads(capsys.readouterr().out)["scope"] == "user"
    assert code("schedule", "install", "--user", "--unit-dir", str(tmp_path / "u"), "--only", "rootkit") == 2
    assert "--yes" in capsys.readouterr().err and not (tmp_path / "u").exists()
    monkeypatch.setattr(sc, "_systemctl", Systemctl(code=1))
    assert code("schedule", "install", "--user", "--yes", "--unit-dir", str(tmp_path / "u"), "--only", "rootkit") == 1
    assert json.loads(capsys.readouterr().out)["errors"] == ["no bus", "no bus"]
    assert code("schedule", "plan", "--only", "nothing") == 2
