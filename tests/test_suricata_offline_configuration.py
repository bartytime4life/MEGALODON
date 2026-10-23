"""Preparation only: no native Suricata process or privileged host operation."""

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

import pytest
import yaml

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/configure-suricata-offline.py"
spec = importlib.util.spec_from_file_location("suricata_config_script", SCRIPT)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)
pytestmark = pytest.mark.skipif(script.sys.platform != "linux", reason="Linux-only file preparation helper")


def test_deterministic_bundle_and_receipt():
    first = script.build_bundle("192.0.2.0/24", script.EMPTY_RULES, False)
    assert first == script.build_bundle("192.0.2.0/24", script.EMPTY_RULES, False)
    receipt = json.loads(first["configuration-receipt.json"])
    identity = receipt.pop("receipt_id")
    assert identity == hashlib.sha256(script.canonical(receipt)).hexdigest()
    for name, artifact in receipt["artifacts"].items():
        assert artifact == {"sha256": hashlib.sha256(first[name]).hexdigest(), "bytes": len(first[name])}
    assert receipt["rules_state"] == "empty_no_detection"
    assert receipt["native_validation"] == "not_run"
    assert receipt["binary_identity"] == "unbound"
    assert receipt["acceptance_authority"] is False
    assert receipt["suricata_executed"] is False


def test_yaml_has_only_private_alert_output():
    config = yaml.safe_load(script.build_bundle("2001:db8::/32", script.EMPTY_RULES, False)["suricata.yaml"])
    assert config["vars"]["address-groups"]["HOME_NET"] == "[2001:db8::/32]"
    assert config["runmode"] == "single"
    assert config["unix-command"]["enabled"] is False
    assert config["stats"]["enabled"] is False
    assert config["default-rule-path"] == "rules"
    assert config["rule-files"] == ["local.rules"]
    assert len(config["outputs"]) == 1
    eve = config["outputs"][0]["eve-log"]
    assert eve["filetype"] == "regular"
    assert eve["filename"] == "megalodon-alerts.json"
    assert eve["threaded"] is False
    assert eve["pcap-file"] is False
    assert len(eve["types"]) == 1
    assert all(value is False for value in eve["types"][0]["alert"].values())
    assert not {"include", "af-packet", "pcap", "nfq", "file-store"} & config.keys()


@pytest.mark.parametrize("network", ["192.168.1.1/24", "192.0.2.1", "any", "[192.0.2.0/24]", '192.0.2.0/24"\ninclude: evil', "not-a-network"])
def test_rejects_noncanonical_networks(network):
    with pytest.raises(ValueError):
        script.build_bundle(network, script.EMPTY_RULES, False)


def test_private_creation_and_no_overwrite(tmp_path):
    bundle = script.build_bundle("192.0.2.0/24", script.EMPTY_RULES, False)
    destination = tmp_path / "new bundle"
    script.write_bundle(str(destination), bundle)
    for name, content in bundle.items():
        assert (destination / name).read_bytes() == content
        assert stat.S_IMODE((destination / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "rules").stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        script.write_bundle(str(destination), bundle)
    assert (destination / "configuration-receipt.json").read_bytes() == bundle["configuration-receipt.json"]


@pytest.mark.parametrize("value", ["relative/path", "/", "/tmp/../escape", "/tmp/./escape"])
def test_refuses_ambiguous_paths(value):
    with pytest.raises(ValueError):
        script.absolute_parts(value)


def test_refuses_symlink_parent_and_destination(tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    bundle = script.build_bundle("192.0.2.0/24", script.EMPTY_RULES, False)
    with pytest.raises(OSError):
        script.write_bundle(str(alias / "new"), bundle)
    broken = tmp_path / "broken"
    broken.symlink_to(tmp_path / "missing")
    with pytest.raises(FileExistsError):
        script.write_bundle(str(broken), bundle)
    assert not (tmp_path / "new").exists()
    assert not (tmp_path / "missing").exists()


def test_refuses_shared_parent(tmp_path):
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(ValueError, match="not be group/other writable"):
            script.write_bundle(str(tmp_path / "new"), {})
        assert not (tmp_path / "new").exists()
    finally:
        tmp_path.chmod(0o700)


def test_rules_are_bounded_digest_bound_bytes(tmp_path):
    path = tmp_path / "input.rules"
    data = b'alert tcp any any -> any 443 (msg:"Synthetic only"; sid:9900001; rev:1;)\n'
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    assert script.read_rules(str(path), digest) == data
    bundle = script.build_bundle("192.0.2.0/24", data, True)
    assert bundle["rules/local.rules"] == data
    assert json.loads(bundle["configuration-receipt.json"])["rules_state"] == "operator_supplied_unvalidated"
    with pytest.raises(ValueError):
        script.read_rules(str(path), "0" * 64)
    for args in [(str(path), None), (None, digest), (str(path), "INVALID")]:
        with pytest.raises(ValueError):
            script.read_rules(*args)
    path.write_bytes(b"x" * (script.MAX_RULE_BYTES + 1))
    with pytest.raises(ValueError):
        script.read_rules(str(path), "0" * 64)


def test_rules_refuse_symlink_fifo_and_nontext(tmp_path):
    path = tmp_path / "rules"
    path.write_bytes(b"\x00")
    with pytest.raises(ValueError):
        script.read_rules(str(path), hashlib.sha256(b"\x00").hexdigest())
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        script.read_rules(str(alias), "0" * 64)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        script.read_rules(str(fifo), "0" * 64)


def test_preview_is_read_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(script.os, "geteuid", lambda: 1234)
    monkeypatch.setattr(script.os, "getuid", lambda: 1234)
    destination = tmp_path / "absent"
    assert script.main(["--output", str(destination), "--home-net", "192.0.2.0/24"]) == 0
    assert not destination.exists()
    assert "PREVIEW ONLY" in capsys.readouterr().out


def test_cli_requires_write_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(script.os, "geteuid", lambda: 1234)
    monkeypatch.setattr(script.os, "getuid", lambda: 1234)
    writes = []
    monkeypatch.setattr(script, "write_bundle", lambda path, files: writes.append((path, files)))
    arguments = ["--output", str(tmp_path / "new"), "--home-net", "192.0.2.0/24"]
    assert script.main(arguments) == 0
    assert not writes
    assert script.main(arguments + ["--write"]) == 0
    assert len(writes) == 1


def test_cli_refuses_root(tmp_path, monkeypatch):
    monkeypatch.setattr(script.os, "geteuid", lambda: 0)
    destination = tmp_path / "new"
    assert script.main(["--output", str(destination), "--home-net", "192.0.2.0/24", "--write"]) == 2
    assert not destination.exists()


def test_only_standard_library_file_preparation_imports():
    tree = ast.parse(SCRIPT.read_text())
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
    assert imports <= {"__future__", "argparse", "hashlib", "ipaddress", "json", "os", "pathlib", "re", "stat", "sys"}
    forbidden = {"system", "popen", "spawnv", "spawnve", "execv", "execve", "fork"}
    assert not any(isinstance(node, ast.Attribute) and node.attr in forbidden for node in ast.walk(tree))


def test_script_is_in_source_distribution():
    assert "include scripts/configure-suricata-offline.py" in (ROOT / "MANIFEST.in").read_text()
