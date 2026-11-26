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
    assert "ancestry" not in jobs and {s["job"] for s in result["skipped"]} == {"ancestry", "ebpf", "containers", "enforce", "commands",
                                                                        "container-escapes"}, \
        "the live ancestry and container escape watches, the eBPF and container checks and enforcement need root"
    assert jobs["persistence"]["baseline"] is None
    assert jobs["listeners"]["baseline"] == "/usr/bin/megalodon listeners baseline"
    assert jobs["rootkit"]["command"] == "/usr/bin/megalodon rootkit check --skip-ports --alert"
    assert jobs["binaries"]["cron"] == "17 3 * * * /usr/bin/megalodon binaries check --alert"
    assert not (tmp_path / "units").exists(), "plan writes nothing"
    system = {row["job"]: row for row in sc.plan(system=True, directory=tmp_path / "u2", launcher=["m"])["jobs"]}
    assert system["ancestry"]["every"] == "always running"


def test_install_refuses_missing_baselines_then_writes_and_enables(home, tmp_path):
    folder, systemctl = tmp_path / "units", Systemctl()
    with pytest.raises(sc.ScheduleError, match="missing baselines for persistence"):
        sc.install(system=False, only=["persistence"], directory=folder, launcher=["m"], runner=systemctl)
    assert systemctl.calls == [] and not folder.exists()
    baselines(home, "persistence.json")
    result = sc.install(system=False, only=["persistence", "rootkit"], directory=folder, launcher=["/x/megalodon"],
                        runner=systemctl)
    assert result["ok"] and result["enabled"] == ["megalodon-persistence.timer", "megalodon-rootkit.timer"]
    assert systemctl.calls == [(False, ("daemon-reload",)),
                               (False, ("enable", "--now", "megalodon-persistence.timer", "megalodon-rootkit.timer"))]
    service = (folder / "megalodon-persistence.service").read_text()
    assert sc.MARKER in service and "ExecStart=/x/megalodon persistence check --alert" in service
    assert "SuccessExitStatus=1" in service and "NoNewPrivileges=yes" in service
    assert "OnCalendar=*:0/15" in (folder / "megalodon-persistence.timer").read_text()


@pytest.mark.parametrize("name, every, cron", [("listeners", "*:0/10", "*/10 * * * *"),
                                               ("webroot", "*:0/15", "*/15 * * * *")])
def test_the_live_watches_run_all_the_time_and_replace_their_old_timers(home, tmp_path, name, every, cron):
    job = next(j for j in sc.JOBS if j.name == name)
    assert job.calendar is None and job.command == (name, "watch", "--alert")
    folder, systemctl = tmp_path / "units", Systemctl()
    folder.mkdir()
    (folder / f"megalodon-{name}.timer").write_text(sc.MARKER + f"\n[Timer]\nOnCalendar={every}\n")
    baselines(home, f"{name}.json")
    result = sc.install(system=False, only=[name], directory=folder, launcher=["/x/megalodon"], runner=systemctl)
    assert result["retired"] == [str(folder / f"megalodon-{name}.timer")]
    assert not (folder / f"megalodon-{name}.timer").exists() and result["enabled"] == [f"megalodon-{name}.service"]
    service = (folder / f"megalodon-{name}.service").read_text()
    assert f"ExecStart=/x/megalodon {name} watch --alert" in service and "Restart=on-failure" in service
    # Without systemd there is no service to keep running: the crontab line runs the check, as before.
    row = next(r for r in sc.plan(system=False, only=[name], directory=folder, launcher=["/x/megalodon"])["jobs"])
    assert row["cron"] == f"{cron} /x/megalodon {name} check --alert"


def test_a_unit_that_is_not_ours_is_never_overwritten_or_removed(home, tmp_path):
    folder = tmp_path / "units"
    folder.mkdir()
    (folder / "megalodon-rootkit.service").write_text("[Service]\nExecStart=/usr/local/bin/my-own\n")
    with pytest.raises(sc.ScheduleError, match="not MEGALODON's"):
        sc.install(system=False, only=["rootkit"], directory=folder, launcher=["m"], runner=Systemctl())
    (folder / "megalodon-other.service").write_text("[Service]\nExecStart=/bin/true\n")
    baselines(home, "persistence.json")
    sc.install(system=False, only=["persistence"], directory=folder, launcher=["m"], runner=Systemctl())
    systemctl = Systemctl()
    result = sc.remove(system=False, directory=folder, runner=systemctl)
    assert sorted(Path(p).name for p in result["removed"]) == ["megalodon-persistence.service",
                                                              "megalodon-persistence.timer"]
    assert systemctl.calls[0] == (False, ("disable", "--now", "megalodon-persistence.timer"))
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


@pytest.mark.parametrize("name, cron", [("devices", "*/5 * * * *"), ("ancestry", "*/5 * * * *"),
                                        ("credentials", "*/5 * * * *"), ("egress", "*/5 * * * *"),
                                        ("listeners", "*/10 * * * *"), ("webroot", "*/15 * * * *")])
def test_without_systemd_each_live_watch_with_a_check_runs_it_from_crontab(tmp_path, name, cron):
    rows = {r["job"]: r for r in sc.plan(system=True, directory=tmp_path / "units", launcher=["/x/megalodon"])["jobs"]}
    job = next(j for j in sc.JOBS if j.name == name)
    assert job.calendar is None and job.command[1] == "watch", "with systemd, the watch runs all the time"
    assert rows[name]["cron"] == f"{cron} /x/megalodon {name} check --alert"


def test_a_watch_with_no_check_has_no_crontab_line(tmp_path):
    rows = {r["job"]: r for r in sc.plan(system=True, directory=tmp_path / "units", launcher=["m"])["jobs"]}
    assert rows["ransomware"]["cron"] is None and rows["commands"]["cron"] is None, "no one-shot check to run instead"


def _service(name, system=True):
    return sc.units(next(j for j in sc.JOBS if j.name == name), ["m"], system)[f"megalodon-{name}.service"]


@pytest.mark.parametrize("name, command", [
    ("ancestry", "m ancestry watch --alert --respond --trace-execs"),
    ("commands", "m commands record --trace-execs"),
    ("credentials", "m credentials watch --alert --respond --trace-execs"),
    # A connection too short for a scan, named by its program: a dropped tool is OUTBOUND_FROM_TEMPORARY.
    ("egress", "m egress watch --alert --respond --trace-connects"),
])
def test_the_watches_that_go_on_without_ebpf_trace_execs(name, command):
    # Each takes started programs from the kernel's record where eBPF loads, and the process events where not.
    service = _service(name)
    assert f"ExecStart={command}" in service
    assert "LimitMEMLOCK=64M" in service, "before Linux 5.11 the 8 MiB ring buffer counts against it"


def test_a_user_unit_does_not_raise_the_locked_memory_limit():
    # A user unit cannot raise it, and fails to start if it asks; without root there is no eBPF anyway.
    assert "--trace-execs" in _service("credentials", system=False)
    assert "LimitMEMLOCK" not in _service("credentials", system=False)


def test_the_container_escape_watch_runs_as_root_where_ebpf_can_run(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "ebpf_missing", lambda: None)
    rows = {r["job"]: r for r in sc.plan(system=True, directory=tmp_path / "units", launcher=["m"])["jobs"]}
    row = rows["container-escapes"]
    assert (row["command"], row["every"], row["cron"]) == ("m containers watch --alert --respond", "always running",
                                                           None), "without systemd, the containers check covers it"
    service = _service("container-escapes")
    # Restarted like the other watches: its exit 2 is also a settings error, which a later fix clears.
    assert "Restart=on-failure" in service and "LimitMEMLOCK=64M" in service
    assert "ReadWritePaths=/etc" in service, "its enforcement run writes what the enforce job writes"


def test_where_ebpf_cannot_run_the_container_escape_watch_is_left_out(home, tmp_path, monkeypatch):
    # Installed, it would stop at once and the tamper check would report it stopped every 15 minutes.
    monkeypatch.setattr(sc, "ebpf_missing", lambda: "the kernel has no type information (/sys/kernel/btf/vmlinux)")
    result = sc.plan(system=True, directory=tmp_path / "units", launcher=["m"])
    assert "container-escapes" not in {r["job"] for r in result["jobs"]}
    assert {"job": "container-escapes",
            "reason": "needs eBPF: the kernel has no type information (/sys/kernel/btf/vmlinux)"} in result["skipped"]
    assert {"ancestry", "commands", "credentials"} <= {r["job"] for r in result["jobs"]}, "these go on without it"
    folder = tmp_path / "units"
    result = sc.install(system=True, only=["container-escapes", "rootkit"], directory=folder, launcher=["m"],
                        runner=Systemctl())
    assert result["enabled"] == ["megalodon-rootkit.timer"]
    assert not (folder / "megalodon-container-escapes.service").exists()


@pytest.mark.parametrize("machine, release, btf, reason", [
    ("x86_64", "6.18.4", True, None),
    ("aarch64", "5.8.0-63-generic", True, None),
    ("riscv64", "6.1.0", True, "eBPF tracing supports x86-64 and arm64, not riscv64"),
    ("x86_64", "6.1.0", False, "the kernel has no type information (/sys/kernel/btf/vmlinux)"),
    ("x86_64", "5.4.0-150-generic", True, "BPF ring buffers need Linux 5.8 or later, not 5.4.0-150-generic"),
    ("x86_64", "5.4-rc7", True, "BPF ring buffers need Linux 5.8 or later, not 5.4-rc7"),
    ("x86_64", "custom", True, None),                 # a version it cannot read: the watch itself will say
])
def test_what_ebpf_needs_is_seen_without_loading_it(monkeypatch, machine, release, btf, reason):
    import platform
    from megalodon import connect_trace
    monkeypatch.setattr(platform, "machine", lambda: machine)
    monkeypatch.setattr(platform, "release", lambda: release)
    real = sc.os.path.exists
    monkeypatch.setattr(sc.os.path, "exists", lambda path: btf if path == connect_trace.BTF_PATH else real(path))
    assert sc.ebpf_missing() == reason
