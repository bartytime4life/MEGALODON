"""Synthetic helper tests. No Suricata binary is invoked by this module."""

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

import pytest

pytest.importorskip("resource", reason="offline laboratory runner is Linux-only")
if not sys.platform.startswith("linux"):
    pytest.skip("offline laboratory runner is Linux-only", allow_module_level=True)

ROOT = Path(__file__).parents[1] / "contracts/suricata-eve/v1/qualification/experiment/harness"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def lab():
    return load("offline")


def event(sid=9900001):
    return {"event_type": "alert", "alert": {"signature_id": sid}, "app_proto": "tls",
            "src_ip": "192.0.2.10", "dest_ip": "192.0.2.20"}


def encoded(value):
    return json.dumps(value).encode() + b"\n"


def successful_runs(lab):
    return [dict(id=c["id"], state="completed", process_cpu_ns=1000,
                 oracle={"state": "oracle_satisfied"}) for c in lab.plan()]


def test_closed_input_inventory_and_reproduction(lab):
    manifest, data, manifest_digest = lab.verified_inputs()
    assert manifest_digest == lab.digest((ROOT / "inputs.json").read_bytes())
    assert len(manifest["artifacts"]) == len(data) == len(lab.REQUIRED_INPUTS)
    for name, raw in load("control_source").build_all().items():
        assert data["harness/" + name] == raw
    assert b"randomize-chunk-size: no" in data["harness/lab.yaml"]
    assert b"content:" not in data["harness/pcre.rules"]
    assert b'content:"*mcH"' in data["harness/pcre-mpm.rules"]


def tls_handshake(raw):
    # Walk PCAP independently, then validate all nested ClientHello/SNI lengths.
    offset, payloads = 24, []
    while offset < len(raw):
        size = struct.unpack_from("<I", raw, offset + 8)[0]
        frame = raw[offset + 16:offset + 16 + size]
        payload = frame[54:]
        if payload:
            payloads.append(payload)
        offset += 16 + size
    assert len(payloads) == 1
    record = payloads[0]
    assert len(record) == 5 + int.from_bytes(record[3:5], "big")
    hs = record[5:]
    assert hs[0] == 1 and len(hs) == 4 + int.from_bytes(hs[1:4], "big")
    body = hs[4:]
    assert len(body) == 43 + int.from_bytes(body[41:43], "big")
    extension = body[43:]
    assert extension[:2] == b"\0\0"
    assert len(extension) == 4 + int.from_bytes(extension[2:4], "big")
    sni = extension[4:]
    assert len(sni) == 2 + int.from_bytes(sni[:2], "big")
    assert len(sni) == 5 + int.from_bytes(sni[3:5], "big")
    return sni[5:]


def test_wrong_sni_control_is_valid_equal_length_tls():
    fixtures = load("control_source").build_all()
    good, wrong = fixtures["tls-unsplit.pcap"], fixtures["tls-wrong-sni.pcap"]
    assert len(good) == len(wrong)
    assert tls_handshake(good) == b"fragmented.example"
    assert tls_handshake(wrong) == b"mismatched.example"


def test_missing_or_modified_artifact_is_rejected(lab, tmp_path, monkeypatch):
    manifest = json.loads((ROOT / "inputs.json").read_text())
    manifest["artifacts"].pop()
    (tmp_path / "inputs.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(lab, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="artifact_set"):
        lab.verified_inputs()


def test_fifo_and_symlink_never_block_prerequisite_reads(lab, tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        lab.read_regular(fifo, 100)
    link = tmp_path / "link"
    link.symlink_to(fifo)
    with pytest.raises(OSError):
        lab.read_regular(link, 100)


def test_truncated_and_oversized_captures_are_rejected(lab):
    raw = (ROOT / "tls-unsplit.pcap").read_bytes()
    lab.pcap_check(raw)
    for broken in (raw[:-1], raw[:30], raw + b"x", b"x" * 262145):
        with pytest.raises(ValueError):
            lab.pcap_check(broken)


def test_plan_is_fixed_and_separates_pcre_prefilter_control(lab):
    cases = lab.plan()
    assert len(cases) == 22
    assert len({c["id"] for c in cases}) == 22
    assert sum(c["count"] == 0 for c in cases) == 2
    for c in cases:
        if c["id"].startswith("pcre-study"):
            assert c["rules"] == "harness/pcre.rules"
        if c["id"].startswith("pcre-mpm-control"):
            assert c["rules"] == "harness/pcre-mpm.rules"


@pytest.mark.parametrize("broken", [b'{"event_type":"alert"}', b"[]\n", b"bad\n"])
def test_incomplete_or_unexpected_eve_is_non_pass(lab, broken):
    assert lab.alert_oracle(broken, lab.plan()[0])["state"] != "oracle_satisfied"


def test_alert_identity_protocol_counts_and_negative_controls(lab):
    positive, _, negative, pcre_negative = lab.plan()[:4]
    assert lab.alert_oracle(encoded(event()), positive)["state"] == "oracle_satisfied"
    assert lab.alert_oracle(b"", positive)["state"] == "oracle_failed"
    assert lab.alert_oracle(encoded(event()) * 2, positive)["state"] == "unexpected_result"
    assert lab.alert_oracle(b"", negative)["state"] == "oracle_satisfied"
    assert lab.alert_oracle(encoded(event()), negative)["state"] == "oracle_failed"
    assert lab.alert_oracle(encoded(event(9900002)), pcre_negative)["state"] == "oracle_failed"
    for field, value in (("app_proto", "http"), ("dest_ip", "198.51.100.1"), ("event_type", "flow")):
        changed = event()
        changed[field] = value
        assert lab.alert_oracle(encoded(changed), positive)["state"] == "unexpected_result"


@pytest.mark.parametrize("state", ["timeout", "nonzero_exit", "output_limit", "launch_unavailable", "case_budget_exhausted"])
def test_any_failed_run_including_fragmented_tls_is_non_pass(lab, state):
    runs = successful_runs(lab)
    runs[1]["state"] = state
    assert lab.summarize(runs)["state"] == "non_pass"


def test_synthetic_timings_never_establish_complexity_pass(lab):
    runs = successful_runs(lab)
    summary = lab.summarize(runs)
    assert summary["state"] == "observations_only"
    assert summary["pcre_complexity_qualification"].startswith("inconclusive")
    assert lab.summarize(runs[:-1])["state"] == "incomplete"
    runs[1]["oracle"]["state"] = "incomplete_output"
    assert lab.summarize(runs)["state"] == "non_pass"


def test_fragmented_tls_duplicates_are_non_pass_but_zero_is_an_observation(lab):
    runs = successful_runs(lab)
    fragmented = lab.plan()[1]
    runs[1]["oracle"] = lab.alert_oracle(b"", fragmented)
    assert lab.summarize(runs)["state"] == "observations_only"
    runs[1]["oracle"] = lab.alert_oracle(encoded(event()) * 2, fragmented)
    assert lab.summarize(runs)["state"] == "non_pass"
    # Also reject a manually mislabeled duplicate count at the summary boundary.
    runs[1]["oracle"]["state"] = "oracle_failed"
    assert lab.summarize(runs)["state"] == "non_pass"


def test_kernel_limits_and_fixed_networkless_argv(lab, tmp_path):
    command = lab.sandbox_command("/usr/bin/bwrap", tmp_path, tmp_path, ["/input/producer", "-V"])
    assert "--unshare-all" in command and "--share-net" not in command
    assert command.count("--bind") == 2
    assert "--clearenv" in command and "--cap-drop" in command
    assert "--remount-ro" in command
    assert command[command.index("--") - 2:command.index("--")] == ["--remount-ro", "/"]
    source = (ROOT / "offline.py").read_text()
    assert '"--runmode", "single"' in source
    assert "RLIMIT_AS, (MAX_AS, MAX_AS)" in source
    assert "RLIMIT_FSIZE, (MAX_OUTPUT // 2, MAX_OUTPUT // 2)" in source


def test_real_helper_process_exit_and_cpu_measurement(lab, tmp_path):
    result = lab.bounded_process([sys.executable, "-c", "pass"], tmp_path)
    assert result["state"] == "completed" and result["exit_code"] == 0
    assert result["process_cpu_ns"] > 0 and result["wall_ns"] > 0


def test_real_helper_timeout_is_killed_and_reaped(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "WALL_SECONDS", 0.1)
    result = lab.bounded_process([sys.executable, "-c", "while True: pass"], tmp_path)
    assert result["state"] == "timeout" and result["exit_code"] != 0


def test_real_helper_file_limit_is_non_pass(lab, tmp_path):
    result = lab.bounded_process([sys.executable, "-c", "print('x' * 700000)"], tmp_path)
    assert result["state"] == "output_limit"
    assert result["output_bytes"] <= lab.MAX_OUTPUT // 2


def test_unexpected_output_is_non_pass_and_not_followed(lab, tmp_path):
    result = lab.bounded_process([sys.executable, "-c",
        "import os,sys; os.symlink('/nonexistent', sys.argv[1])", str(tmp_path / "alien")], tmp_path)
    assert result["state"] == "unexpected_output"


def test_default_and_missing_prerequisites_cannot_execute(lab, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("native producer started")
    monkeypatch.setattr(lab, "run_profile", forbidden)
    report_path = tmp_path / "report.json"
    assert lab.main(["--report", str(report_path)]) == 2
    report = json.loads(report_path.read_text())
    assert report["status"] == "not_run" and report["engine_execution"] == "not_attempted"
    assert report["acceptance_authority"] is False
    claimed = report.pop("report_sha256")
    assert claimed == hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(FileExistsError):
        lab.main(["--report", str(report_path)])
    blocked = tmp_path / "blocked.json"
    lab.main(["--execute", "--report", str(blocked)])
    assert json.loads(blocked.read_text())["unavailable_prerequisites"] == ["reviewed_inputs_digest_required_or_mismatched"]


def test_unavailable_namespace_is_recorded_without_engine(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(lab.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(lab, "bounded_process", lambda *a, **k: {"state": "nonzero_exit", "exit_code": 1})
    path = tmp_path / "report.json"
    assert lab.main(["--preflight", "--report", str(path)]) == 2
    report = json.loads(path.read_text())
    assert report["status"] == "prerequisite_unavailable"
    assert report["engine_execution"] == "not_attempted"
    assert report["unavailable_prerequisites"] == ["network_namespace_containment_unavailable"]


def test_identity_requires_reviewed_distinct_bound_builds(lab, tmp_path):
    binary = tmp_path / "producer"
    binary.write_bytes(b"\x7fELFsynthetic-not-executed")
    build = tmp_path / "build.json"
    build.write_bytes(b"synthetic build record; not native qualification")
    identity = {"binary": str(binary), "sha256": lab.digest(binary.read_bytes()),
                "version": "8.0.7", "source_commit": "1" * 40, "contains_commits": [],
                "build_record": str(build), "build_record_sha256": lab.digest(build.read_bytes()),
                "review_reference": "synthetic test reference; never native acceptance"}
    document = tmp_path / "identity.json"
    document.write_text(json.dumps(identity))
    bound, raw = lab.identity(document, "baseline")
    assert bound["sha256"] == lab.digest(raw)
    for field, wrong in (("version", "8.0.6"), ("sha256", "0" * 64),
                         ("build_record_sha256", "0" * 64), ("review_reference", "")):
        changed = deepcopy(identity)
        changed[field] = wrong
        document.write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            lab.identity(document, "baseline")
    document.write_text(json.dumps(identity))
    with pytest.raises(ValueError, match="both upstream"):
        lab.identity(document, "candidate")
