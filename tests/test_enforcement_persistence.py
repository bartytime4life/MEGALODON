"""disable_persistence: an entry the baseline did not have is moved aside, kept, and put back on undo."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from megalodon import response_engine as re_
from test_enforcement import Commands, decide, enable, enforce, p, stat_mode  # noqa: F401


class Machine:
    """A machine root and home under the test folder, and an executor that acts there."""

    def __init__(self, tmp_path, p, active=True):
        self.root, self.home = tmp_path / "root", tmp_path / "home"
        self.root.mkdir()
        self.home.mkdir()
        self.commands = Commands()
        if not active:
            original = self.commands.__call__

            def call(argv, data=None):
                result = original(argv, data)
                return SimpleNamespace(returncode=3, stdout="", stderr="") if "is-active" in argv else result
            self.commands = call
        self.executor = en.Executor(root=str(self.root), home=self.home, run=self.commands, quarantine=p["quarantine"])

    def path(self, location):
        return self.home / location[2:] if location.startswith("~/") else self.root / location[1:]

    def place(self, location, content=b"* * * * * root /tmp/.x\n", mode=0o644):
        path = self.path(location)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        os.chmod(path, mode)
        return path


def found(change, category, location, severity="MEDIUM"):
    report = dict(checked_at="2026-11-20T00:00:00Z", findings=[dict(
        change=change, category=category, location=location, severity=severity, technique="T1053.003")])
    return re_.persistence_signals(report)


def ran(machine):
    calls = machine.commands.ran if hasattr(machine.commands, "ran") else []
    return [c for c in calls if c[0] == "systemctl"]


def test_a_new_cron_job_is_moved_aside_and_put_back(p, tmp_path):
    machine = Machine(tmp_path, p)
    job = machine.place("/etc/cron.d/update-check", mode=0o640)
    digest = hashlib.sha256(job.read_bytes()).hexdigest()
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "cron", "/etc/cron.d/update-check"))
    result = enforce(p, executor=machine.executor)
    assert [r["action"] for r in result["applied"]] == ["disable_persistence"] and not job.exists()
    undo = result["applied"][0]["undo"]
    assert (undo["kind"], undo["sha256"], stat_mode(undo["kept"])) == ("file", digest, 0)
    assert ran(machine) == [], "a cron job needs no service manager"
    en.undo(result["applied"][0]["id"], journal=p["journal"], executor=machine.executor)
    assert hashlib.sha256(job.read_bytes()).hexdigest() == digest and stat_mode(job) == 0o640
    assert not Path(undo["kept"]).exists()


def test_a_timer_is_stopped_and_started_again(p, tmp_path):
    machine = Machine(tmp_path, p)
    timer = machine.place("/etc/systemd/system/sync.timer", b"[Timer]\nOnCalendar=minutely\n")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "systemd", "/etc/systemd/system/sync.timer"))
    result = enforce(p, executor=machine.executor)
    assert not timer.exists() and result["applied"][0]["undo"]["unit"] == dict(name="sync.timer", was_active=True)
    assert ran(machine) == [["systemctl", "daemon-reload"], ["systemctl", "is-active", "--quiet", "sync.timer"],
                            ["systemctl", "stop", "sync.timer"]]
    machine.commands.ran.clear()
    en.undo(result["applied"][0]["id"], journal=p["journal"], executor=machine.executor)
    assert timer.exists()
    assert ran(machine) == [["systemctl", "daemon-reload"], ["systemctl", "start", "sync.timer"]]


def test_a_service_keeps_running_and_an_enablement_link_is_recreated(p, tmp_path):
    machine = Machine(tmp_path, p)
    unit = machine.place("/etc/systemd/system/agent.service", b"[Service]\nExecStart=/tmp/.a\n")
    link = machine.path("/etc/systemd/system/multi-user.target.wants/agent.service")
    link.parent.mkdir(parents=True)
    link.symlink_to("/etc/systemd/system/agent.service")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "systemd", "/etc/systemd/system/agent.service")
           + found("added", "systemd", "/etc/systemd/system/multi-user.target.wants/agent.service"))
    result = enforce(p, executor=machine.executor)
    assert len(result["applied"]) == 2 and not unit.exists() and not os.path.lexists(link)
    assert ["systemctl", "stop", "agent.service"] not in ran(machine), \
        "a service is left running for its memory to be captured"
    by_kind = {r["undo"]["kind"]: r for r in result["applied"]}
    assert by_kind["link"]["undo"]["link_target"] == "/etc/systemd/system/agent.service"
    for record in result["applied"]:
        en.undo(record["id"], journal=p["journal"], executor=machine.executor)
    assert unit.exists() and os.readlink(link) == "/etc/systemd/system/agent.service"


def test_a_link_is_removed_never_followed(p, tmp_path):
    machine = Machine(tmp_path, p)
    precious = tmp_path / "shadow"
    precious.write_text("root:x:0\n")
    link = machine.path("/etc/profile.d/proxy.sh")
    link.parent.mkdir(parents=True)
    link.symlink_to(precious)
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "shell_startup", "/etc/profile.d/proxy.sh"))
    result = enforce(p, executor=machine.executor)
    assert result["applied"] and not os.path.lexists(link) and precious.read_text() == "root:x:0\n"


def test_an_entry_that_existed_before_is_never_moved(p, tmp_path):
    machine = Machine(tmp_path, p)
    sudoers = machine.place("/etc/sudoers", b"root ALL=(ALL) ALL\nbob ALL=(ALL) NOPASSWD: ALL\n", mode=0o440)
    # A playbook of your own that lists the action for changed entries: enforcement still refuses.
    with open(p["policy"], "a") as policy:
        policy.write('\n[[response.playbook]]\nname = "changed-entry"\nrules = ["PERSISTENCE_CHANGED"]\n'
                     'min_severity = "MEDIUM"\nactions = ["disable_persistence"]\n')
    en.init(p["enforce"], response_policy=p["policy"], replace=True)
    enable(p, ["disable_persistence"], ["changed-entry"])
    decide(p, found("changed", "sudoers", "/etc/sudoers", "HIGH"))
    result = enforce(p, executor=machine.executor)
    assert result["applied"] == [] and result["refused"][0]["reason"] == en.NOT_ADDED
    assert result["refused"][0]["status"] == "refused", "refused before anything is tried, not tried and failed"
    assert sudoers.read_bytes().startswith(b"root ALL")
    with pytest.raises(en.EnforcementError, match="did not have"):
        machine.executor.disable_persistence("sudoers:/etc/sudoers",
                                             dict(signal=dict(rule_id="PERSISTENCE_CHANGED")))


def test_only_watched_locations_and_never_megalodon(p, tmp_path):
    machine = Machine(tmp_path, p)
    machine.place("/etc/passwd", b"root:x:0:0::/root:/bin/bash\n")
    machine.place("/etc/systemd/system/megalodon-respond.timer", b"[Timer]\n")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "cron", "/etc/passwd")
           + found("added", "systemd", "/etc/systemd/system/megalodon-respond.timer"))
    decisions = [json.loads(line) for line in p["ledger"].read_text().splitlines()]
    reasons = sorted(a["guard"] for d in decisions for a in d["actions"] if a["action"] == "disable_persistence")
    assert reasons == ["MEGALODON's own: disabling it would turn off a watch",
                       "not a location the persistence watch covers"], "refused when decided, in shadow"
    assert enforce(p, executor=machine.executor)["applied"] == []
    assert machine.path("/etc/passwd").exists() and machine.path("/etc/systemd/system/megalodon-respond.timer").exists()
    from megalodon.persistence_watch import why_not_disabled
    assert why_not_disabled("systemd", "/etc/systemd/system/../shadow") == "not a plain path", \
        "a `..` that a two-level pattern would match is refused when decided, not only when carried out"
    for target in ("cron:/etc/cron.d/../passwd", "systemd:/etc/systemd/system/../shadow", "account:bob",
                   "kernel_module:evil", "cron:/tmp/x"):
        with pytest.raises(en.EnforcementError):
            machine.executor.disable_persistence(target, dict(signal=dict(rule_id="PERSISTENCE_ADDED")))


def test_undo_does_not_overwrite_what_is_there_now(p, tmp_path):
    machine = Machine(tmp_path, p)
    job = machine.place("~/.config/autostart/helper.desktop", b"[Desktop Entry]\nExec=/tmp/.h\n")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "autostart", "~/.config/autostart/helper.desktop"))
    result = enforce(p, executor=machine.executor)
    assert not job.exists(), "~ is the home of the account the persistence check ran as"
    job.write_bytes(b"[Desktop Entry]\nExec=/usr/bin/true\n")
    with pytest.raises(en.EnforcementError, match="exists again"):
        en.undo(result["applied"][0]["id"], journal=p["journal"], executor=machine.executor)
    assert job.read_bytes().endswith(b"/usr/bin/true\n") and Path(result["applied"][0]["undo"]["kept"]).exists()


def test_the_enforce_service_can_write_every_system_unit_folder():
    from megalodon import persistence_watch, schedule
    unit = schedule.units({j.name: j for j in schedule.JOBS}["enforce"], ["megalodon"], True)["megalodon-enforce.service"]
    systemd = next(p for c, _t, _s, p in persistence_watch.LOCATIONS if c == "systemd")
    system_folders = {pattern.split("/*")[0] for pattern in systemd if not pattern.startswith("~")}
    for folder in system_folders:
        if folder.startswith("/etc/"):
            assert "ReadWritePaths=/etc\n" in unit
        else:
            assert f"ReadWritePaths=-{folder}\n" in unit, f"{folder} is read-only under ProtectSystem=full"


def test_removing_the_link_that_enabled_a_timer_stops_it(p, tmp_path):
    machine = Machine(tmp_path, p)
    machine.place("/etc/systemd/system/sync.timer", b"[Timer]\nOnCalendar=minutely\n")     # in the baseline
    link = machine.path("/etc/systemd/system/timers.target.wants/sync.timer")
    link.parent.mkdir(parents=True)
    link.symlink_to("/etc/systemd/system/sync.timer")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "systemd", "/etc/systemd/system/timers.target.wants/sync.timer"))
    result = enforce(p, executor=machine.executor)
    assert not os.path.lexists(link) and ["systemctl", "stop", "sync.timer"] in ran(machine), \
        "a running timer keeps firing after its link is gone, until it is stopped"
    machine.commands.ran.clear()
    en.undo(result["applied"][0]["id"], journal=p["journal"], executor=machine.executor)
    assert os.path.islink(link) and ["systemctl", "start", "sync.timer"] in ran(machine)


def test_a_failed_stop_puts_the_entry_back(p, tmp_path):
    machine = Machine(tmp_path, p)
    timer = machine.place("/etc/systemd/system/sync.timer", b"[Timer]\nOnCalendar=minutely\n")
    calls = []

    def systemctl(argv, data=None):
        calls.append(list(argv))
        return SimpleNamespace(returncode=1 if argv[1:2] == ["stop"] else 0, stdout="", stderr="Access denied")
    machine.executor.run = systemctl
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "systemd", "/etc/systemd/system/sync.timer"))
    result = enforce(p, executor=machine.executor)
    assert result["applied"] == [] and result["refused"][0]["status"] == "failed"
    assert "put back as it was" in result["refused"][0]["reason"]
    assert timer.read_bytes() == b"[Timer]\nOnCalendar=minutely\n", "never left moved aside without an undo record"
    assert not any(p["quarantine"].glob("*/file")), "and no copy left behind"
    assert calls[-1] == ["systemctl", "daemon-reload"], "systemd is told the unit is back"


def test_global_user_units_are_not_the_system_managers(p, tmp_path):
    machine = Machine(tmp_path, p)
    unit = machine.place("/etc/systemd/user/sync.timer", b"[Timer]\nOnCalendar=minutely\n")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "systemd", "/etc/systemd/user/sync.timer"))
    result = enforce(p, executor=machine.executor)
    assert not unit.exists() and result["applied"][0]["undo"]["system_unit"] is False
    assert ran(machine) == [], "the system manager is never told to stop a unit of the same name"
    en.undo(result["applied"][0]["id"], journal=p["journal"], executor=machine.executor)
    assert unit.exists() and ran(machine) == []


def test_an_undo_stopped_by_systemd_can_be_run_again(p, tmp_path):
    machine = Machine(tmp_path, p)
    timer = machine.place("/etc/systemd/system/sync.timer", b"[Timer]\nOnCalendar=minutely\n")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "systemd", "/etc/systemd/system/sync.timer"))
    record = enforce(p, executor=machine.executor)["applied"][0]
    calls, failing = [], [True]

    def systemctl(argv, data=None):
        calls.append(list(argv))
        if argv[1:2] == ["daemon-reload"] and failing[0]:
            failing[0] = False
            return SimpleNamespace(returncode=1, stdout="", stderr="Transport endpoint is not connected")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    machine.executor.run = systemctl
    with pytest.raises(en.EnforcementError, match="Transport endpoint"):
        en.undo(record["id"], journal=p["journal"], executor=machine.executor)
    assert timer.exists() and [r["id"] for r in en.active(p["journal"])] == [record["id"]], \
        "the file is back, and the undo is not recorded as done"
    en.undo(record["id"], journal=p["journal"], executor=machine.executor)
    assert ["systemctl", "start", "sync.timer"] in calls and en.active(p["journal"]) == []
    # Something else at the path is still never taken for the entry put back.
    other = machine.place("/etc/cron.d/job")
    enable(p, ["disable_persistence"], ["new-persistence-entry"])
    decide(p, found("added", "cron", "/etc/cron.d/job"))
    job = enforce(p, executor=machine.executor)["applied"][0]
    other.write_bytes(b"something else\n")
    with pytest.raises(en.EnforcementError, match="exists again"):
        en.undo(job["id"], journal=p["journal"], executor=machine.executor)
