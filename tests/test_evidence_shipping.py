"""Evidence off the machine: command log lines and evidence bundles copied to the collector, kept as first sent."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import urllib.error
import urllib.request

import pytest

from megalodon import command_log as cl
from megalodon import evidence, fleet, tamper
from megalodon import evidence_shipping as shipping
from test_fleet import collector, machine  # noqa: F401


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


class Machine:
    """One enrolled machine with a command log and a folder of evidence bundles."""

    def __init__(self, tmp_path, url, data, name="web-1"):
        self.dir = tmp_path / name
        self.dir.mkdir()
        self.config, key = machine(tmp_path, url, name)
        fleet.enroll(name, key, data=data)
        self.name, self.data = name, data
        self.state, self.log, self.bundles = self.dir / "state.json", self.dir / "commands.jsonl", self.dir / "evidence"
        self.key = cl.init(state=self.state, log=self.log)["key"]
        self.clock = Clock()

    def run(self, *programs):
        with cl.Recorder(clock=self.clock, state=self.state, log=self.log) as recorder:
            for number, program in enumerate(programs):
                recorder.add("exec", pid=2000 + number, uid=1000, program=program, argv=[program])

    def bundle(self, name, files):
        """A sealed bundle the way `evidence collect` leaves one."""
        base = self.bundles / name
        base.mkdir(parents=True)
        listed = []
        for file, content in files.items():
            (base / file).parent.mkdir(parents=True, exist_ok=True)
            (base / file).write_bytes(content)
            listed.append(dict(file=file, size=len(content), sha256=hashlib.sha256(content).hexdigest()))
        (base / "manifest.json").write_text(json.dumps(dict(schema=evidence.SCHEMA, collected_at="2026-11-19T12:00:00Z",
                                                            files=listed)))
        evidence._seal(base)
        return base

    def push(self, **kw):
        return shipping.push(config=self.config, cursor_path=self.dir / "cursor.json", log=self.log,
                             evidence_root=self.bundles, **kw)

    def heartbeat(self):
        settings, body = tamper.heartbeat(self.config, manifest=self.dir / "none.json",
                                          sequence_path=self.dir / "beats.json", runner=lambda *a: "",
                                          uptime=lambda: 1.0, command_state=self.state)
        tamper.send(settings, body)


def unseal(path):
    for item in [path, *path.rglob("*")]:
        os.chmod(item, 0o700 if item.is_dir() else 0o600)


def rewrite_line(path, sequence, change):
    lines = [json.loads(line) for line in Path(path).read_text().splitlines()]
    for line in lines:
        if line["seq"] == sequence:
            change(line)
    Path(path).write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in lines))


def rules(report):
    return sorted(f["rule_id"] for f in report["findings"])


def test_the_log_and_a_bundle_leave_the_machine_and_verify_there(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id", "/usr/bin/uname", "/tmp/.x")
    big = os.urandom(shipping.CHUNK * 2 + 1000)        # more than one piece
    bundle = web.bundle("20261119T120000Z", {"processes.json": b"[]\n", "programs/dropped": big})
    result = web.push()
    assert (result["command_lines"], result["manifests"], result["files_completed"], result["bundles_incomplete"]) \
        == (3, 1, 2, 0), "three programs; the manifest; both files"
    assert web.push()["command_lines"] == 0 and web.push()["requests"] == 0, "nothing is sent twice"
    # The intruder deletes everything on the machine. The collector's copy still checks out with the key.
    unseal(bundle)
    shutil.rmtree(web.bundles)
    for path in cl.log_files(web.log):
        path.unlink()
    checked = shipping.verify(data, "web-1", key_hex=web.key)
    assert checked["findings"] == [] and checked["commands"]["verified"] == 3
    assert checked["bundles"] == [dict(bundle="20261119T120000Z", intact=True, problems=[])]
    copy = Path(shipping.held(data, "web-1")["bundles"][0]["path"])
    assert (copy / "programs/dropped").read_bytes() == big
    assert evidence.verify(copy)["intact"], "the copy is an ordinary bundle: `evidence verify` reads it too"
    row = fleet.status(data=data)["machines"][0]
    assert row["evidence"]["command_lines"] == 3 and row["evidence"]["bundles_complete"] == 1


def test_the_end_the_heartbeat_named_is_checked(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id")
    web.push()
    web.run("/usr/bin/curl", "/usr/bin/nc")              # recorded, and named by the heartbeat ...
    web.heartbeat()
    checked = shipping.verify(data, "web-1", key_hex=web.key)
    assert rules(checked) == ["COMMAND_LOG_TRUNCATED"], "... but cut from the machine before the next push"
    web.push()
    assert shipping.verify(data, "web-1", key_hex=web.key)["findings"] == []


def test_a_log_rewritten_after_it_left_is_caught(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id", "/tmp/.x", "/usr/bin/uname")
    web.push()
    original = Path(shipping.held(data, "web-1")["command_logs"][0]["path"])
    before = original.read_bytes()
    # The intruder rewrites the line that ran their tool, and clears the push record to have it sent again.
    rewrite_line(web.log, 3, lambda line: line.update(program="/usr/bin/true", mac="0" * 64))
    (web.dir / "cursor.json").unlink()
    web.push()
    assert original.read_bytes() == before, "the first copy is kept"
    assert rules(shipping.held(data, "web-1")) == ["SHIPPED_COMMANDS_REWRITTEN"]
    assert "SHIPPED_COMMANDS_REWRITTEN" in [f["rule_id"] for f in fleet.status(data=data)["findings"]]
    assert shipping.verify(data, "web-1", key_hex=web.key)["commands"]["findings"] == [], \
        "the copy itself still verifies: only the machine's log was changed"


def test_lines_removed_before_they_left(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id", "/usr/bin/w", "/tmp/.x", "/tmp/.y", "/usr/bin/uname")
    lines = web.log.read_text().splitlines()
    web.log.write_text("\n".join(lines[:2] + lines[4:]) + "\n")
    web.push()
    held = shipping.held(data, "web-1")
    assert rules(held) == ["SHIPPED_COMMANDS_GAP"] and held["command_logs"][0]["gaps"] == [[3, 4]]
    assert "COMMAND_LOG_GAP" in rules(shipping.verify(data, "web-1", key_hex=web.key))


def test_a_bundle_changed_on_the_machine(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    bundle = web.bundle("b1", {"network.json": b'{"sockets": 1}\n'})
    web.push()
    # Sent again after a change, with the push record gone: the first copy stays, the change is reported.
    unseal(bundle)
    (bundle / "network.json").write_bytes(b'{"sockets": 0}\n')
    (web.dir / "cursor.json").unlink()
    web.push()
    held = shipping.held(data, "web-1")
    assert rules(held) == ["SHIPPED_EVIDENCE_CHANGED"]
    assert (Path(held["bundles"][0]["path"]) / "network.json").read_bytes() == b'{"sockets": 1}\n'
    # A new manifest for the same bundle is refused, and kept aside.
    manifest = json.loads((bundle / "manifest.json").read_text())
    manifest["files"][0]["sha256"] = hashlib.sha256(b'{"sockets": 0}\n').hexdigest()
    (bundle / "manifest.json").write_text(json.dumps(manifest))
    web.push()
    assert rules(shipping.held(data, "web-1")) == ["SHIPPED_EVIDENCE_CHANGED"] * 2
    # A file changed before it was ever sent does not match its manifest: never placed in the bundle.
    other = web.bundle("b2", {"sessions.json": b"[]\n"})
    unseal(other)
    (other / "sessions.json").write_bytes(b"{}\n")
    web.push()
    held = shipping.held(data, "web-1")
    b2 = next(b for b in held["bundles"] if b["bundle"] == "b2")
    assert (b2["files_received"], len(held["findings"])) == (0, 3)
    checked = shipping.verify(data, "web-1")
    assert next(b for b in checked["bundles"] if b["bundle"] == "b2")["intact"] is None


def test_a_limited_push_resumes_even_without_its_record(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    content = os.urandom(shipping.CHUNK * 3)
    web.bundle("b1", {"programs/tool": content})
    first = web.push(budget=shipping.CHUNK)
    assert (first["file_bytes"], first["bundles_incomplete"]) == (shipping.CHUNK, 1)
    (web.dir / "cursor.json").unlink()                   # lost: the collector says where the file stands
    second = web.push(budget=2 * shipping.CHUNK)
    assert second["file_bytes"] == 2 * shipping.CHUNK, "the piece it already had, then the next"
    assert shipping.held(data, "web-1")["findings"] == [], "a piece sent again unchanged is no conflict"
    web.push()
    held = shipping.held(data, "web-1")
    assert held["findings"] == [] and held["bundles"][0]["files_received"] == 1
    assert (Path(held["bundles"][0]["path"]) / "programs/tool").read_bytes() == content


def post(url, body):
    request = urllib.request.Request(url + "/evidence", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, None


def test_forged_replayed_unknown_and_unsafe_batches(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id")
    bodies = []
    web.push(send=lambda settings, body: (bodies.append(body), shipping.send(settings, body))[1])
    assert post(url, bodies[0])[0] == 409, "a batch sent again adds nothing"
    forged = dict(bodies[0], sequence=bodies[0]["sequence"] + 10)
    forged["items"][0]["lines"][0]["program"] = "/usr/bin/true"
    assert post(url, forged)[0] == 401
    assert post(url, dict(forged, sensor="stranger"))[0] == 403
    assert post(url, dict(schema="other"))[0] == 400
    import http.client
    connection = http.client.HTTPConnection(url.split("//")[1], timeout=5)
    connection.putrequest("POST", "/evidence")
    connection.putheader("Content-Length", str(shipping.MAX_BODY + 1))
    connection.endheaders()
    assert connection.getresponse().status == 413, "the larger limit still has an end"
    connection.close()
    assert shipping.held(data, "web-1")["command_logs"][0]["lines"] == 1
    # A manifest naming a path outside its bundle is refused before anything is written.
    settings = json.loads(web.config.read_text())
    settings["url"] = url + "/evidence"
    bad = json.dumps(dict(schema=evidence.SCHEMA, files=[dict(file="../../machines.json", size=1, sha256="0")]))
    body = dict(schema=shipping.BATCH_SCHEMA, sensor="web-1", sequence=bodies[0]["sequence"] + 20,
                sent_at="2026-11-19T12:00:00Z",
                items=[dict(kind="manifest", bundle="evil", sha256="", data=shipping._b64(bad.encode())),
                       dict(kind="chunk", bundle="evil", file="../../machines.json", offset=0, size=1, sha256="0",
                            data=shipping._b64(b"x"))])
    body["mac"] = tamper._sign(settings["key"], body)
    status, answer = post(url, body)
    assert status == 200 and [i["ok"] for i in answer["items"]] == [False, False]
    assert shipping.held(data, "web-1")["bundles"] == []
    assert fleet.machines(data)["web-1"]["sensor"] == "web-1"


def test_the_cli_and_the_schedule(collector, tmp_path, capsys):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id")
    web.bundle("b1", {"processes.json": b"[]\n"})
    from megalodon import schedule
    from megalodon.cli import main
    common = ["--config", str(web.config), "--log", str(web.log), "--evidence-root", str(web.bundles),
              "--cursor", str(web.dir / "cursor.json")]
    with pytest.raises(SystemExit) as exit_:
        main(["evidence", "push", "--url", url + "/nowhere", *common])
    assert exit_.value.code == 0 and "keeps no evidence" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_:
        main(["evidence", "push", *common])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["command_lines"] == 1
    key_file = tmp_path / "commands.key"
    key_file.write_text(web.key + "\n")
    key_file.chmod(0o600)
    with pytest.raises(SystemExit) as exit_:
        main(["fleet", "evidence", "web-1", "--verify", "--key-file", str(key_file), "--data", str(data)])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["machines"][0]["commands"]["verified"] == 1
    with pytest.raises(SystemExit) as exit_:
        main(["fleet", "evidence", "--data", str(data)])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["machines"][0]["bundles"][0]["files"] == 1
    assert "evidence-push" in {job.name for job in schedule.JOBS}


def test_a_long_backlog_one_push_at_a_time_and_a_full_collector(collector, tmp_path, monkeypatch):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    with cl.Recorder(clock=web.clock, state=web.state, log=web.log) as recorder:
        for number in range(400):                       # about 2 MiB of long command lines
            recorder.add("exec", pid=number, uid=0, program="/usr/bin/env", argv=["env", "x" * 4000, str(number)])
    sizes = []
    result = web.push(send=lambda settings, body: (sizes.append(len(json.dumps(body))),
                                                     shipping.send(settings, body))[1])
    assert result["command_lines"] == 400 and len(sizes) > 1 and max(sizes) < shipping.MAX_BODY, \
        "split into requests the collector takes"
    assert shipping.verify(data, "web-1", key_hex=web.key)["commands"]["verified"] == 400
    with shipping._PushLock(web.dir / "cursor.json"):
        with pytest.raises(shipping.ShippingError, match="another evidence push"):
            web.push()
    # A full collector takes nothing more, and the machine keeps it for later.
    monkeypatch.setattr(shipping, "MAX_STORED", 0)
    web.run("/usr/bin/id")
    assert web.push()["command_lines"] == 0
    monkeypatch.setattr(shipping, "MAX_STORED", 1 << 40)
    assert web.push()["command_lines"] == 1


def test_a_resent_line_must_match_in_every_field(collector, tmp_path):
    """A rewrite that keeps the line's signature is still a rewrite."""
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id", "/tmp/.x")
    web.push()
    rewrite_line(web.log, 2, lambda line: line.update(program="/usr/bin/true"))     # mac kept as it was
    (web.dir / "cursor.json").unlink()
    web.push()
    assert rules(shipping.held(data, "web-1")) == ["SHIPPED_COMMANDS_REWRITTEN"]


def test_the_first_lines_removed_before_any_left(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.run("/usr/bin/id", "/tmp/.x", "/usr/bin/uname")
    web.log.write_text(web.log.read_text().splitlines()[2] + "\n")       # only line 3 is left
    web.push()
    held = shipping.held(data, "web-1")
    assert rules(held) == ["SHIPPED_COMMANDS_GAP"] and held["command_logs"][0]["gaps"] == [[1, 2]]
    checked = shipping.verify(data, "web-1", key_hex=web.key)
    assert "COMMAND_LOG_GAP" in rules(checked), "verified from line 1, not from what the machine kept"
    # A boundary the operator sets, for lines they moved off the machine on purpose, is honoured.
    bounded = shipping.verify(data, "web-1", key_hex=web.key, from_sequence=3)
    assert "COMMAND_LOG_GAP" not in rules(bounded) and bounded["commands"]["verified"] == 1


def test_an_empty_file_completes_its_bundle(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    web.bundle("b1", {"sessions.json": b"", "processes.json": b"[]\n"})
    web.push()
    held = shipping.held(data, "web-1")
    assert held["bundles"][0]["files_received"] == 2 and held["findings"] == []
    assert shipping.verify(data, "web-1")["bundles"][0]["intact"] is True


def test_refused_manifests_have_an_allowance(collector, tmp_path, monkeypatch):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    bundle = web.bundle("b1", {"processes.json": b"[]\n"})
    web.push()
    monkeypatch.setattr(shipping, "MAX_REJECTED", 600)
    unseal(bundle)
    for number in range(8):                              # eight different manifests for the same bundle
        manifest = json.loads((bundle / "manifest.json").read_text())
        manifest["collected_at"] = f"2026-11-19T12:00:0{number}Z"
        (bundle / "manifest.json").write_text(json.dumps(manifest))
        web.push()
    kept = list((data / "machines/web-1/shipped/evidence-rejected/b1").iterdir())
    assert 0 < len(kept) < 8, "kept until the allowance is spent, then only reported"
    usage = json.loads((data / "machines/web-1/shipped/usage.json").read_text())
    assert usage["rejected"] == sum(p.stat().st_size for p in kept) <= 600
