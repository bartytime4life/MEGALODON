"""Opt-in Linux laboratory runner, separate from MEGALODON's EVE consumer.

No installs, downloads, capture interfaces, shell commands, or network fallback.
The default is artifact verification only. Native results are observations,
never installed-producer acceptance or automatic promotion to a pass receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time
from statistics import median

ROOT = Path(__file__).resolve().parent
PACKET = ROOT.parent
MAX_OUTPUT = 1048576
MAX_AS = 536870912
WALL_SECONDS = 10
COMMITS = ["bea218e7b1dd8ffb09f250e62c096c6b3da749b4",
           "f87b8e64a5fb80788897f7a9073c5407a2f5bc96"]
REQUIRED_INPUTS = {"fixture_source.py", "manifest.json", "rules/local.rules", "suricata.yaml",
                   "fixtures/fragmented-tls-handshake-header.pcap",
                   *(f"fixtures/pcre-stream-{size}.pcap" for size in (32, 64, 128)),
                   "harness/control_source.py", "harness/offline.py", "harness/lab.yaml",
                   "harness/tls.rules", "harness/pcre.rules", "harness/pcre-mpm.rules",
                   "harness/tls-unsplit.pcap", "harness/tls-wrong-sni.pcap", "harness/pcre-negative.pcap"}


class PrerequisiteError(ValueError):
    """A fixed, privacy-safe failure category for the observation report."""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_regular(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file grew beyond bound")
    return data


def pcap_check(raw: bytes) -> None:
    if len(raw) > 262144 or raw[:24] != struct.pack(
            "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1):
        raise ValueError("PCAP size or header")
    offset, count = 24, 0
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise ValueError("truncated PCAP record")
        _, _, captured, original = struct.unpack_from("<IIII", raw, offset)
        if captured != original or captured < 54 or captured > 65535:
            raise ValueError("incomplete PCAP packet")
        offset += 16 + captured
        count += 1
    if offset != len(raw) or not 1 <= count <= 512:
        raise ValueError("PCAP truncation or packet ceiling")


def verified_inputs() -> tuple[dict, dict[str, bytes], str]:
    manifest_raw = read_regular(ROOT / "inputs.json", 65536)
    manifest = json.loads(manifest_raw)
    if (len(manifest["artifacts"]) != len(REQUIRED_INPUTS)
            or {item["path"] for item in manifest["artifacts"]} != REQUIRED_INPUTS):
        raise PrerequisiteError("input_artifact_set_mismatch")
    data = {}
    for item in manifest["artifacts"]:
        relative = item["path"]
        # Fixed repository-relative artifact set, no caller-selected PCAP/config.
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("artifact path escapes packet")
        raw = read_regular(PACKET / relative, 262144)
        if len(raw) != item["bytes"] or digest(raw) != item["sha256"]:
            raise ValueError("artifact identity mismatch:" + relative)
        if relative.endswith(".pcap"):
            pcap_check(raw)
        data[relative] = raw
    return manifest, data, digest(manifest_raw)


def plan() -> list[dict]:
    cases = [
        ("tls-unsplit", "harness/tls-unsplit.pcap", "harness/tls.rules", 9900001, 1),
        ("tls-fragmented", "fixtures/fragmented-tls-handshake-header.pcap", "harness/tls.rules", 9900001, 1),
        ("tls-negative", "harness/tls-wrong-sni.pcap", "harness/tls.rules", 9900001, 0),
        ("pcre-negative", "harness/pcre-negative.pcap", "harness/pcre.rules", 9900002, 0),
    ]
    for mode in ("study", "mpm-control"):
        for size in (32, 64, 128):
            for rep in (1, 2, 3):
                cases.append((f"pcre-{mode}-{size}-{rep}", f"fixtures/pcre-stream-{size}.pcap",
                              "harness/pcre.rules" if mode == "study" else "harness/pcre-mpm.rules",
                              9900002, -1))
    return [dict(id=name, capture=capture, rules=rules, sid=sid, count=count)
            for name, capture, rules, sid, count in cases]


def identity(path: Path, role: str) -> tuple[dict, bytes]:
    identity_raw = read_regular(path, 65536)
    value = json.loads(identity_raw)
    required = {"binary", "sha256", "version", "source_commit", "contains_commits",
                "build_record", "build_record_sha256", "review_reference"}
    if set(value) != required:
        raise ValueError("identity fields do not match reviewed build contract")
    for name in ("sha256", "build_record_sha256"):
        if not isinstance(value[name], str) or not re.fullmatch("[0-9a-f]{64}", value[name]):
            raise ValueError("identity digest malformed")
    if not re.fullmatch("[0-9a-f]{40}", value["source_commit"]):
        raise ValueError("source commit malformed")
    if role == "baseline" and value["version"] != "8.0.7":
        raise ValueError("baseline must be declared Suricata 8.0.7")
    if role == "candidate" and value["contains_commits"] != COMMITS:
        raise ValueError("candidate build attestation must cover both upstream commits")
    if not isinstance(value["review_reference"], str) or not value["review_reference"].strip():
        raise ValueError("independent build review reference unavailable")
    build = read_regular(Path(value["build_record"]), MAX_OUTPUT)
    if digest(build) != value["build_record_sha256"]:
        raise ValueError("build record identity mismatch")
    binary = read_regular(Path(value["binary"]), 256 * 1024 * 1024)
    if digest(binary) != value["sha256"]:
        raise ValueError("binary identity mismatch")
    if binary[:4] != b"\x7fELF":
        raise ValueError("local ELF producer required")
    # Do not retain local paths, build-record content, or operator details.
    producer = {key: value[key] for key in ("sha256", "version", "source_commit",
                                          "contains_commits", "build_record_sha256")}
    producer["identity_document_sha256"] = digest(identity_raw)
    return producer, binary


def sandbox_command(bwrap: str, inputs: Path, output: Path, args: list[str]) -> list[str]:
    command = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"]
    for directory in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(directory).exists():
            command += ["--ro-bind", directory, directory]
    return command + ["--proc", "/proc", "--remount-ro", "/proc",
                      "--dev", "/dev", "--remount-ro", "/dev",
                      "--tmpfs", "/tmp", "--remount-ro", "/tmp",
                      "--ro-bind", str(inputs), "/input", "--ro-bind", str(output), "/out",
                      "--bind", str(output / "eve.json"), "/out/eve.json",
                      "--bind", str(output / "diagnostic.log"), "/out/diagnostic.log",
                      "--chdir", "/out", "--clearenv", "--setenv", "LC_ALL", "C",
                      "--setenv", "HOME", "/tmp", "--remount-ro", "/", "--"] + args


def child_limits() -> None:
    # Applied before exec and inherited by bwrap and its producer descendants.
    resource.setrlimit(resource.RLIMIT_AS, (MAX_AS, MAX_AS))
    # Only two precreated files are writable in the sandbox. Splitting the
    # hard per-file limit makes their aggregate ceiling at most 1 MiB.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT // 2, MAX_OUTPUT // 2))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})


def output_size(directory: Path) -> int:
    total = 0
    for path in directory.rglob("*"):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.name not in {"eve.json", "diagnostic.log"}:
            raise ValueError("unexpected output type")
        total += info.st_size
    return total


def bounded_process(command: list[str], output: Path, *, budget_ns: int | None = None) -> dict:
    started = time.monotonic_ns()
    state = "completed"
    ceiling_ns = min(WALL_SECONDS * 1_000_000_000, budget_ns) if budget_ns is not None else WALL_SECONDS * 1_000_000_000
    (output / "eve.json").touch(mode=0o600, exist_ok=False)
    with (output / "diagnostic.log").open("xb") as log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=log, env={"LC_ALL": "C"},
                                   start_new_session=True, preexec_fn=child_limits)
        waited = 0
        try:
            while True:
                waited, status, usage = os.wait4(process.pid, os.WNOHANG)
                if waited:
                    break
                if time.monotonic_ns() - started >= ceiling_ns:
                    state = "timeout"
                    break
                if output_size(output) >= MAX_OUTPUT:
                    state = "output_limit"
                    break
                time.sleep(0.005)
        except (OSError, ValueError):
            state = "unexpected_output"
        finally:
            if not waited:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
    wall = time.monotonic_ns() - started
    try:
        total = output_size(output)
    except (OSError, ValueError):
        total = 0
        state = "unexpected_output"
    if total >= MAX_OUTPUT or any(path.stat().st_size >= MAX_OUTPUT // 2
                                  for path in output.iterdir() if path.is_file() and not path.is_symlink()):
        state = "output_limit"
    elif wall > ceiling_ns:
        state = "timeout"
    elif process.returncode != 0 and state == "completed":
        state = "nonzero_exit"
    return {"state": state, "exit_code": process.returncode, "wall_ns": wall,
            "process_cpu_ns": int((usage.ru_utime + usage.ru_stime) * 1_000_000_000),
            "output_bytes": total, "max_rss_kib": usage.ru_maxrss}


def alert_oracle(raw: bytes, case: dict) -> dict:
    if raw and not raw.endswith(b"\n"):
        return {"state": "incomplete_output"}
    alerts = []
    try:
        for line in raw.splitlines():
            event = json.loads(line)
            if (event.get("event_type") != "alert"
                    or event.get("alert", {}).get("signature_id") != case["sid"]
                    or event.get("src_ip") != "192.0.2.10"
                    or event.get("dest_ip") != "192.0.2.20"
                    or (case["sid"] == 9900001 and event.get("app_proto") != "tls")):
                return {"state": "unexpected_result"}
            alerts.append(event)
    except (ValueError, AttributeError, TypeError):
        return {"state": "incomplete_output"}
    count = len(alerts)
    correct = count >= 1 if case["count"] == -1 else count == case["count"]
    return {"state": "oracle_satisfied" if correct else "oracle_failed", "alert_count": count,
            "eve_sha256": digest(raw), "eve_bytes": len(raw)}


def summarize(runs: list[dict]) -> dict:
    # These whole-process timings include initialization and sandbox overhead.
    # No small/flat ratio is promoted to a complexity or remediation pass.
    if len(runs) != 22 or {r["id"] for r in runs} != {c["id"] for c in plan()}:
        return {"state": "incomplete"}
    if any(r["state"] != "completed" for r in runs):
        return {"state": "non_pass"}
    controls = [r for r in runs if r["id"] != "tls-fragmented"]
    fragmented = next(r for r in runs if r["id"] == "tls-fragmented")
    if fragmented.get("oracle", {}).get("state") not in ("oracle_satisfied", "oracle_failed"):
        return {"state": "non_pass"}
    if any(r["state"] != "completed" or r.get("oracle", {}).get("state") != "oracle_satisfied"
           for r in controls):
        return {"state": "non_pass"}
    medians = {}
    for mode in ("study", "mpm-control"):
        medians[mode] = {str(size): int(median(
            r["process_cpu_ns"] for r in runs if r["id"].startswith(f"pcre-{mode}-{size}-")))
                         for size in (32, 64, 128)}
    ratios = {mode: [{"numerator_ns": values[str(b)], "denominator_ns": values[str(a)],
                      "within_3x": 0 < values[str(a)] and values[str(b)] <= 3 * values[str(a)]}
                     for a, b in ((32, 64), (64, 128))] for mode, values in medians.items()}
    return {"state": "observations_only", "cpu_medians_ns": medians, "ratios": ratios,
            "pcre_complexity_qualification": "inconclusive_startup_overhead_not_removed",
            "tls_fragmented": next(r["oracle"]["state"] for r in runs if r["id"] == "tls-fragmented")}


def run_profile(binary: bytes, producer: dict, inputs: dict[str, bytes], bwrap: str) -> dict:
    runs = []
    with tempfile.TemporaryDirectory(prefix="suricata-offline-") as temporary:
        work = Path(temporary)
        staged = work / "input"
        staged.mkdir(mode=0o700)
        for name, raw in inputs.items():
            target = staged / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (staged / "producer").write_bytes(binary)
        (staged / "producer").chmod(0o500)
        # Version parsing is native and receives the same containment and bounds.
        version_dir = work / "version"
        version_dir.mkdir(mode=0o700)
        check = bounded_process(sandbox_command(bwrap, staged, version_dir,
                                                ["/input/producer", "-V"]), version_dir)
        text = read_regular(version_dir / "diagnostic.log", MAX_OUTPUT).decode("utf-8", "replace")
        observed = re.search(r"Suricata version (\S+)", text)
        if check["state"] != "completed" or not observed or observed[1] != producer["version"]:
            return {"producer": producer, "version_check": check, "runs": [],
                    "summary": {"state": "identity_mismatch_or_version_unavailable"}}
        for case in plan():
            output = work / case["id"]
            output.mkdir(mode=0o700)
            args = ["/input/producer", "-c", "/input/harness/lab.yaml", "-S", "/input/" + case["rules"],
                    "-r", "/input/" + case["capture"], "--runmode", "single", "-l", "/out"]
            family = "tls" if case["id"].startswith("tls-") else "pcre"
            spent = sum(r.get("wall_ns", 0) for r in runs if r["id"].startswith(family + "-"))
            remaining_ns = WALL_SECONDS * 1_000_000_000 - spent
            if remaining_ns <= 0:
                runs.append({"id": case["id"], "state": "case_budget_exhausted",
                             "oracle": {"state": "not_evaluated"}})
                continue
            try:
                result = bounded_process(sandbox_command(bwrap, staged, output, args), output,
                                         budget_ns=remaining_ns)
            except (OSError, ValueError, subprocess.SubprocessError):
                runs.append({"id": case["id"], "state": "launch_unavailable",
                             "oracle": {"state": "not_evaluated"}})
                continue
            result["id"] = case["id"]
            if result["state"] == "completed":
                try:
                    result["oracle"] = alert_oracle(read_regular(output / "eve.json", MAX_OUTPUT), case)
                except (OSError, ValueError):
                    result["oracle"] = {"state": "incomplete_output"}
            else:
                result["oracle"] = {"state": "not_evaluated"}
            runs.append(result)
    return {"producer": producer, "version_check": check, "runs": runs, "summary": summarize(runs)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="opt into contained local binaries")
    parser.add_argument("--preflight", action="store_true", help="probe namespace isolation without an engine")
    parser.add_argument("--baseline-identity", type=Path)
    parser.add_argument("--candidate-identity", type=Path)
    parser.add_argument("--expected-inputs-sha256", help="independently reviewed inputs.json digest")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    report = {"schema_version": "suricata-offline-lab-observations-v1", "status": "not_run",
              "engine_execution": "not_attempted", "acceptance_authority": False,
              "producer_acceptance": "not_established", "network_access": False,
              "profiles": {}, "unavailable_prerequisites": []}
    try:
        _, inputs, manifest_digest = verified_inputs()
        report["inputs_sha256"] = manifest_digest
        if args.execute and args.expected_inputs_sha256 != report["inputs_sha256"]:
            raise PrerequisiteError("reviewed_inputs_digest_required_or_mismatched")
        if args.execute or args.preflight:
            bwrap = shutil.which("bwrap")
            if not bwrap:
                raise PrerequisiteError("bubblewrap_unavailable")
            with tempfile.TemporaryDirectory(prefix="suricata-isolation-") as temporary:
                directory = Path(temporary)
                probe = bounded_process(sandbox_command(bwrap, directory, directory,
                                                        ["/usr/bin/true"]), directory)
                report["containment_probe"] = probe
                if probe["state"] != "completed":
                    raise PrerequisiteError("network_namespace_containment_unavailable")
        if args.execute:
            if not args.baseline_identity or not args.candidate_identity:
                raise PrerequisiteError("both_reviewed_binary_identities_required")
            # Verify both identities before any producer starts.
            producers = {role: identity(path, role) for role, path in (
                ("baseline", args.baseline_identity), ("candidate", args.candidate_identity))}
            if producers["baseline"][0]["sha256"] == producers["candidate"][0]["sha256"]:
                raise ValueError("comparison binaries must have distinct identities")
            report["engine_execution"] = "attempted"
            for role, (producer, binary) in producers.items():
                report["profiles"][role] = run_profile(binary, producer, inputs, bwrap)
            report["status"] = ("native_observations_only" if all(
                p["summary"]["state"] == "observations_only" for p in report["profiles"].values())
                else "non_pass")
            report["pcre_qualification"] = "inconclusive"
        else:
            report["unavailable_prerequisites"] = ["execution_not_requested",
                "reviewed_baseline_binary_identity", "reviewed_candidate_binary_identity",
                "native_containment_not_verified"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["status"] = ("non_pass" if report["engine_execution"] == "attempted"
                            else "prerequisite_unavailable")
        # Fixed category only: exceptions may contain private filesystem paths.
        report["unavailable_prerequisites"].append(str(error) if isinstance(error, PrerequisiteError)
                                                  else type(error).__name__)
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["report_sha256"] = digest(canonical)
    # Do not overwrite a previous observation or follow a report symlink.
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0 if report["status"] == "native_observations_only" else 2


if __name__ == "__main__":
    raise SystemExit(main())
