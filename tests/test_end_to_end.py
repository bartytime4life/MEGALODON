"""The whole chain, on two machines and one collector, with nothing but placeholders standing in for an attack.

Each stage feeds the next exactly as it does in service:
detection -> response engine -> enforcement -> incident timeline -> command log ->
timeline and evidence pushed off the machine -> fleet view.

web-1: a program run from /tmp connects out to 203.0.113.50, and a cron job appears. The program is paused for
30 minutes and the address blocked; the cron job is disabled.
db-1: two hours later, root logs in from 203.0.113.50.
The collector must tell one incident across both machines, hold every action and undo, and keep a copy of the
command log and the evidence that still verifies after both are deleted on web-1.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import subprocess
import time

import pytest

from megalodon import command_log as cl
from megalodon import enforcement as en
from megalodon import evidence, fleet, persistence_watch, tamper
from megalodon import evidence_shipping as shipping
from megalodon import response_engine as re_
from megalodon import timeline as tl
from test_enforcement import Commands, state_of
from test_fleet import collector, machine  # noqa: F401

ADDRESS = "203.0.113.50"


class Host:
    """One machine: its own root and home, its own MEGALODON files, enrolled at the collector."""

    def __init__(self, tmp_path, url, data, name):
        self.name, self.dir = name, tmp_path / name
        self.root, self.home = self.dir / "root", self.dir / "home"
        for folder in (self.root / "etc/cron.d", self.home):
            folder.mkdir(parents=True)
        self.config, key = machine(tmp_path, url, name)
        fleet.enroll(name, key, data=data)
        f = self.dir
        self.policy, self.ledger, self.state = f / "respond.toml", f / "ledger.jsonl", f / "respond-state.json"
        self.enforce_policy, self.journal = f / "enforce.toml", f / "enforced.jsonl"
        self.enforce_state, self.quarantine = f / "enforce-state.json", f / "quarantine"
        self.evidence = f / "evidence"
        self.log, self.log_state = f / "commands.jsonl", f / "commands-state.json"
        self.persistence = f / "persistence.json"
        re_.write_default_policy(self.policy)
        # The one playbook setting this story needs beyond the defaults: pauses end after 30 minutes.
        text = self.policy.read_text()
        marker = 'name = "dropped-tool-phoning-home"\n'
        self.policy.write_text(text.replace(marker, marker + "suspend_minutes = 30\n"))
        en.init(self.enforce_policy, response_policy=self.policy)
        text = self.enforce_policy.read_text()
        for old, new in (("enabled = false", "enabled = true"),
                         ("actions = []", 'actions = ["collect_evidence", "suspend_process", "block_address", '
                                          '"disable_persistence"]'),
                         ("playbooks = []", 'playbooks = ["dropped-tool-phoning-home", "new-persistence-entry"]'),
                         (f'quarantine_folder = "{en.DEFAULT_QUARANTINE}"', f'quarantine_folder = "{self.quarantine}"')):
            assert old in text
            text = text.replace(old, new)
        self.enforce_policy.write_text(text)
        self.key = cl.init(state=self.log_state, log=self.log)["key"]
        persistence_watch.baseline(self.persistence, root=str(self.root), home=str(self.home), setuid_dirs=())
        self.executor = Executor(self, files_root=str(self.root), home=self.home, run=Commands(),
                                 quarantine=self.quarantine, settings=SimpleNamespace(alerts=name))

    def detect(self, signals, now=None):
        return re_.run(policy_path=self.policy, ledger=self.ledger, state_path=self.state, signals=signals,
                       protected=set(), now=now)

    def persistence_signals(self):
        report = persistence_watch.check(self.persistence, root=str(self.root), home=str(self.home), setuid_dirs=())
        return re_.persistence_signals(report)

    def enforce(self, now=None):
        return en.run(policy_path=self.enforce_policy, response_policy=self.policy, ledger=self.ledger,
                      journal=self.journal, state_path=self.enforce_state, executor=self.executor, now=now,
                      protected=set())

    def record(self, *programs):
        with cl.Recorder(state=self.log_state, log=self.log) as recorder:
            for number, program in enumerate(programs):
                recorder.add("exec", pid=3000 + number, uid=0, program=program, argv=[program])

    def heartbeat(self):
        settings, body = tamper.heartbeat(self.config, manifest=self.dir / "no-tamper.json",
                                          sequence_path=self.dir / "beats.json", runner=lambda *a: "",
                                          uptime=lambda: 1.0, command_state=self.log_state)
        tamper.send(settings, body)

    def push(self):
        events = tl.push(config=self.config, cursor_path=self.dir / "timeline-cursor.json", ledger=self.ledger,
                         journal=self.journal)
        shipped = shipping.push(config=self.config, cursor_path=self.dir / "evidence-cursor.json", log=self.log,
                                evidence_root=self.evidence)
        return events, shipped


class Executor(en.Executor):
    """The real executor, except evidence: a small bundle in the shape `evidence collect` writes, not a sweep of
    this test machine's /proc."""

    def __init__(self, host, **kw):
        super().__init__(**kw)
        self.host = host

    def collect_evidence(self, target, decision):
        base = self.host.evidence / f"bundle-{len(list(self.host.evidence.glob('*'))) if self.host.evidence.exists() else 0}"
        base.mkdir(parents=True)
        content = json.dumps(decision["signal"], sort_keys=True).encode()
        (base / "finding.json").write_bytes(content)
        (base / "manifest.json").write_text(json.dumps(dict(
            schema=evidence.SCHEMA, collected_at="2026-11-20T00:00:00Z",
            files=[dict(file="finding.json", size=len(content), sha256=hashlib.sha256(content).hexdigest())])))
        evidence._seal(base)
        return dict(bundle=str(base), memory=[])


@pytest.fixture
def tool():
    """A program run from a temporary folder, the way a dropped tool is."""
    folder = Path(f"/tmp/e2e-tool-{os.getpid()}")
    folder.mkdir(exist_ok=True)
    program = folder / "updater"
    shutil.copy("/bin/sleep", program)
    process = subprocess.Popen([str(program), "120"])
    time.sleep(0.1)
    yield process, str(program)
    process.kill()
    process.wait()
    shutil.rmtree(folder, ignore_errors=True)


def outbound(process, program, now):
    text = Path(f"/proc/{process.pid}/stat").read_text()
    start = int(text[text.rindex(")") + 2:].split()[19])
    report = dict(checked_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"), findings=[dict(
        rule_id="OUTBOUND_FROM_TEMPORARY", severity="HIGH", program=program, protocol="tcp", port=443,
        address=ADDRESS, detail=f"{program} connects to {ADDRESS}:443",
        evidence=dict(processes=[dict(pid=process.pid, start=start, program=program)]))])
    return re_.egress_signals(report)


def login(now):
    return re_.login_signals(dict(findings=[dict(
        rule_id="LOGIN_NEW_SOURCE", severity="HIGH", user="root", src_ip=ADDRESS,
        when=now.strftime("%Y-%m-%dT%H:%M:%SZ"), detail=f"root logged in from {ADDRESS}, never seen before")]))


def wait_for(pid, states):
    for _ in range(100):
        if state_of(pid) in states:
            break
        time.sleep(0.02)
    return state_of(pid)


def test_one_attack_across_two_machines_from_detection_to_the_fleet(collector, tmp_path, tool, monkeypatch):
    data, url, _view = collector
    from megalodon import alerts
    sent = []
    monkeypatch.setattr(alerts, "dispatcher_for", lambda machine: SimpleNamespace(
        submit=lambda notices, any_severity=False: sent.extend((machine, n) for n in notices)))
    process, program = tool
    web, db = Host(tmp_path, url, data, "web-1"), Host(tmp_path, url, data, "db-1")
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # 1. Detection on web-1: the dropped tool phones home, and a cron job appears beside it.
    (web.root / "etc/cron.d/updater").write_text(f"*/5 * * * * root {program}\n")
    web.record("/usr/bin/curl", program, "/usr/bin/crontab")
    signals = outbound(process, program, now) + web.persistence_signals()
    assert sorted(s.rule_id for s in signals) == ["OUTBOUND_FROM_TEMPORARY", "PERSISTENCE_ADDED"]

    # 2. The response engine decides, in shadow, and 3. enforcement carries out what the policy allows.
    decided = web.detect(signals, now=now)
    assert decided["decisions"] == 2
    enforced = web.enforce(now=now)
    done = sorted((r["action"], r["target"]) for r in enforced["applied"])
    assert [a for a, _t in done] == ["collect_evidence", "collect_evidence", "disable_persistence",
                                     "suspend_process"], (done, enforced["refused"])
    assert ("disable_persistence", "cron:/etc/cron.d/updater") in done
    assert next(t for a, t in done if a == "suspend_process").startswith(f"{process.pid}@")
    # The address is a documentation placeholder: the guard refuses to block it, as it would any address that
    # is not public, and says so in the decision.
    planned = [a for d in map(json.loads, web.ledger.read_text().splitlines()) for a in d["actions"]]
    assert [(a["status"], a["guard"]) for a in planned if a["action"] == "block_address"] == [
        ("refused", "not a public address: local attackers need switch-level controls")]
    assert wait_for(process.pid, "T") == "T", "the tool is paused, not killed"
    assert not (web.root / "etc/cron.d/updater").exists(), "the cron job is moved aside"
    assert all(r["incident"] for r in en.entries(web.journal)), "every action names its incident"
    pause = next(r for r in enforced["applied"] if r["action"] == "suspend_process")
    assert datetime.strptime(pause["until"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) == \
        now + timedelta(minutes=30)
    assert not [c for c in web.executor.run.ran if c[0] == "nft"], "nothing was sent to the firewall"

    # 4. The incident timeline on web-1 tells each incident in order.
    local = tl.incidents(ledger=web.ledger, journal=web.journal, now=now)["incidents"]
    assert len(local) == 2
    told = {tuple(sorted(i["sources"])): tl.show(i["incident"], ledger=web.ledger, journal=web.journal)
            for i in local}
    egress_story = [(e["kind"], e.get("action")) for e in told[("egress",)]["events"]]
    assert egress_story[:2] == [("finding", None), ("decision", None)] and \
        {("action", "suspend_process"), ("action", "collect_evidence")} <= \
        set(egress_story)
    assert ("action", "disable_persistence") in [(e["kind"], e.get("action")) for e in told[("persistence",)]["events"]]

    # db-1, two hours later: root logs in from the same address.
    later = now + timedelta(hours=2)
    assert db.detect(login(later), now=later)["decisions"] == 1

    # 5. Both machines push their timelines, command logs and evidence, and send a heartbeat.
    for host in (web, db):
        host.heartbeat()
        events, shipped = host.push()
        assert events["sent"] >= 1
    assert shipped["command_lines"] == 0, "db-1 has no command log lines yet"
    assert web.push()[1]["requests"] == 0, "nothing is sent twice"

    # 6. The fleet tells one incident across both machines, joined by the address.
    listed = fleet.fleet_timeline(data=data, now=later + timedelta(minutes=1))["incidents"]
    joined = next(i for i in listed if len(i["machines"]) == 2)
    assert (joined["machines"], joined["linked_by"]) == (["db-1", "web-1"], [ADDRESS])
    story = fleet.fleet_show(joined["incident"], data=data)["events"]
    assert [(e["machine"], e["kind"]) for e in story][:2] == [("web-1", "finding"), ("web-1", "decision")]
    assert {(e["machine"], e.get("action")) for e in story if e["kind"] == "action"} >= {
        ("web-1", "suspend_process"), ("web-1", "collect_evidence")}
    assert ("db-1", "finding") in [(e["machine"], e["kind"]) for e in story]
    persistence_incident = next(i for i in listed if i["sources"] == ["persistence"])
    assert persistence_incident["machines"] == ["web-1"]

    # 7. The collector's copies verify with the command log key, up to the line the heartbeat named.
    checked = shipping.verify(data, "web-1", key_hex=web.key)
    assert checked["findings"] == [] and checked["commands"]["verified"] == 3
    assert [b["intact"] for b in checked["bundles"]] == [True, True], "both evidence bundles arrived whole"
    # A line written and named by the next heartbeat, but not pushed yet. The collector cannot tell that from a
    # line cut from the machine: it knows where the log should end, and reports the copy as cut until it arrives.
    web.record("/usr/bin/shred")
    web.heartbeat()
    assert [f["rule_id"] for f in shipping.verify(data, "web-1", key_hex=web.key)["findings"]] == \
        ["COMMAND_LOG_TRUNCATED"]
    web.push()
    assert shipping.verify(data, "web-1", key_hex=web.key)["commands"]["verified"] == 4
    status = fleet.status(data=data, now=later)
    assert {r["machine"]: r["evidence"]["command_lines"] for r in status["machines"]} == {"db-1": 0, "web-1": 4}
    assert [f["rule_id"] for f in status["findings"] if f["rule_id"].startswith("SHIPPED_")] == []

    # 8. Undo on web-1: the cron job comes back, the pause ends on time, and the fleet hears of both.
    disabled = next(r for r in enforced["applied"] if r["action"] == "disable_persistence")
    en.undo(disabled["id"], journal=web.journal, executor=web.executor)
    assert (web.root / "etc/cron.d/updater").read_text() == f"*/5 * * * * root {program}\n"
    resumed = web.enforce(now=now + timedelta(minutes=31))["expired"]
    assert [(r["status"], r["reason"], r["notified"]) for r in resumed] == [("undone", "expired", True)]
    assert [(machine, n.rule_id) for machine, n in sent] == [("web-1", "PAUSE_ENDED")], \
        "you hear at once that the dropped tool runs again"
    assert pause["target"] in sent[0][1].message
    assert wait_for(process.pid, "SR") in "SR"
    web.push()
    undos = [e for e in fleet.fleet_events(data=data) if e["kind"] == "undo"]
    assert sorted(e["action"] for e in undos) == ["disable_persistence", "suspend_process"]
    assert [e.get("expired") for e in undos if e["action"] == "suspend_process"] == [True]
    assert any(e["kind"] == "undo" for e in fleet.fleet_show(joined["incident"], data=data)["events"]), \
        "the expiry is told in the joined incident"

    # 9. The intruder wipes web-1's log and evidence. What left the machine still verifies.
    for path in cl.log_files(web.log):
        path.unlink()
    for bundle in web.evidence.iterdir():
        for item in [bundle, *bundle.rglob("*")]:
            os.chmod(item, 0o700 if item.is_dir() else 0o600)
    shutil.rmtree(web.evidence)
    assert shipping.verify(data, "web-1", key_hex=web.key)["findings"] == []
