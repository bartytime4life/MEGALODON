"""The ancestry, egress and credential watches answer each finding at once: the process is paused while it runs."""
from __future__ import annotations

import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

from megalodon import credential_watch as cw
from megalodon import egress_watch as ew
from megalodon import enforcement as en
from megalodon import process_ancestry as pa
from megalodon import respond_now
from test_enforcement import enable, p, state_of  # noqa: F401

PLAYBOOK = dict(ancestry="web-shell-or-exploited-service", egress="dropped-tool-phoning-home",
                credentials="credential-theft")


@pytest.fixture
def shell():
    """A shell that keeps running, as a web shell's would."""
    process = subprocess.Popen(["sh", "-c", "sleep 60; :"])
    time.sleep(0.1)
    yield process
    if state_of(process.pid) == "T":
        os.kill(process.pid, 18)
    process.kill()
    process.wait()


def finding(source, process):
    """A finding as each watch builds it, naming `process`."""
    exe, start = os.readlink(f"/proc/{process.pid}/exe"), en._start(process.pid)
    if source == "ancestry":
        child = pa.Proc(pid=process.pid, ppid=4242, path=exe, comm="sh", uid=33, start=start, argv=["sh", "-c", "id"])
        service = pa.Proc(pid=4242, ppid=1, path="/usr/sbin/nginx", comm="nginx", uid=33, start=1)
        found = pa.Judge().judge(child, [service], "2026-11-20T00:00:00Z")
        assert found and found["rule_id"] == "SERVICE_SPAWNED_SHELL"
        return found
    if source == "egress":
        connection = dict(protocol="tcp", address="93.184.215.66", port=4444, scope="public", pid=process.pid,
                          start=start, program=exe, executable=exe, script=None, deleted=True, argv=["sh"])
        return ew._finding("OUTBOUND_FROM_TEMPORARY", connection, "connects out")
    info = dict(path=exe, start=start, argv=["sh"])
    return cw.Judge._finding("CREDENTIAL_READ_BY_DROPPED_TOOL", process.pid, info, exe, "/root/.ssh/id_ed25519",
                             "ssh", "reads a key")


@pytest.mark.parametrize("source", ["ancestry", "egress", "credentials"])
def test_each_watch_names_the_exact_process(source, shell):
    [signal] = respond_now.signals_of(source, finding(source, shell))
    assert signal.entities["process_id"] == {f"{shell.pid}@{en._start(shell.pid)}:{os.readlink(f'/proc/{shell.pid}/exe')}"}


@pytest.mark.parametrize("source", ["ancestry", "egress", "credentials"])
def test_a_live_finding_pauses_the_process_while_it_runs(source, shell, p):
    enable(p, ["suspend_process"], [PLAYBOOK[source]])
    responder = respond_now.Responder(policy=p["policy"], ledger=p["ledger"], state=p["state"],
                                      enforcement_policy=p["enforce"], journal=p["journal"],
                                      enforcement_state=p["enforce_state"])
    answer = respond_now.answer(responder, source, finding(source, shell))
    [applied] = answer["enforcement"]["applied"]
    assert (applied["action"], applied["target"].split("@")[0]) == ("suspend_process", str(shell.pid))
    for _ in range(50):
        if state_of(shell.pid) == "T":
            break
        time.sleep(0.02)
    assert state_of(shell.pid) == "T"
    en.undo(applied["id"], journal=p["journal"])
    # Decided once: the timer's pass, seeing the same process later, finds the same signal already decided.
    again = respond_now.answer(responder, source, finding(source, shell))
    assert again["decisions"] == 0


class FakeWatcher:
    """Stands in for a live watch: emits one finding, then stops."""
    found = None

    def __init__(self, *args, **kwargs):
        self.emit = kwargs.get("emit") or next(a for a in args if callable(a))
        self.mode, self.stats, self.files, self.folders = "given", {}, [], []

    def run(self, stop):
        self.emit(FakeWatcher.found)

    def close(self):
        pass


@pytest.mark.parametrize("source,argv", [
    ("ancestry", ["ancestry", "watch", "--respond"]),
    ("egress", ["egress", "watch", "--respond", "--no-names"]),
    ("credentials", ["credentials", "watch", "--respond"]),
])
def test_the_cli_answers_each_finding_with_respond(source, argv, shell, monkeypatch, capsys, tmp_path):
    from megalodon.cli import main
    module = dict(ancestry=pa, egress=ew, credentials=cw)[source]
    FakeWatcher.found = finding(source, shell)
    monkeypatch.setattr(module, "Watcher", FakeWatcher)
    answered = []

    class Recorder:
        def answer(self, rule_id, signals):
            answered.append((rule_id, [sorted(s.entities["process_id"]) for s in signals]))
            return dict(rule_id=rule_id, decided=True, decisions=1, would_apply=1)
    monkeypatch.setattr(respond_now, "Responder", Recorder)
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(SystemExit) as exit_:
        main(argv + (["--manifest", str(tmp_path / "egress.json")] if source == "egress" else []))
    assert exit_.value.code == 0
    assert answered == [(FakeWatcher.found["rule_id"], [[f"{shell.pid}@{en._start(shell.pid)}:"
                                                         f"{os.readlink(f'/proc/{shell.pid}/exe')}"]])]
    err = capsys.readouterr().err
    assert "megalodon: response " in err
    # Without --respond, nothing is decided here: the timer's pass does it.
    answered.clear()
    with pytest.raises(SystemExit):
        main([a for a in argv if a != "--respond"] + (["--manifest", str(tmp_path / "egress.json")]
                                                      if source == "egress" else []))
    assert answered == []


def test_the_scheduled_live_watches_answer_at_once():
    from megalodon import schedule as sc
    jobs = {j.name: j for j in sc.JOBS}
    enforce = jobs["enforce"]
    for name in ("ancestry", "credentials", "egress", "devices"):
        assert "--respond" in jobs[name].command and jobs[name].calendar is None, name
        assert jobs[name].writable == enforce.writable, f"{name} carries out a whole enforcement run"
