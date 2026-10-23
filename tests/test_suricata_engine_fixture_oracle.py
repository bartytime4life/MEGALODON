"""Static and deterministic checks for the unexecuted Suricata fixture packet."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct

from jsonschema import Draft202012Validator
import yaml


ROOT = (
    Path(__file__).parents[1]
    / "contracts"
    / "suricata-eve"
    / "v1"
    / "qualification"
    / "experiment"
)
MANIFEST_BYTES = (ROOT / "manifest.json").read_bytes()
MANIFEST = json.loads(MANIFEST_BYTES)
MANIFEST_SCHEMA = json.loads((ROOT / "manifest.schema.json").read_text(encoding="utf-8"))
RECEIPT = json.loads((ROOT / "receipt-template.json").read_text(encoding="utf-8"))
RECEIPT_SCHEMA = json.loads((ROOT / "receipt.schema.json").read_text(encoding="utf-8"))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _load_generator():
    path = ROOT / "fixture_source.py"
    spec = importlib.util.spec_from_file_location("suricata_fixture_source", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pcap_frames(raw: bytes) -> list[bytes]:
    assert len(raw) >= 24
    magic, major, minor, zone, sigfigs, snaplen, linktype = struct.unpack_from(
        "<IHHIIII", raw
    )
    assert (magic, major, minor, zone, sigfigs, snaplen, linktype) == (
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    frames: list[bytes] = []
    offset = 24
    while offset < len(raw):
        assert offset + 16 <= len(raw)
        _, micros, captured, original = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        assert micros == 0 and captured == original and captured <= 65535
        assert offset + captured <= len(raw)
        frames.append(raw[offset : offset + captured])
        offset += captured
    assert offset == len(raw)
    return frames


def _tcp_payload(frame: bytes) -> tuple[str, str, bytes]:
    assert len(frame) >= 54 and frame[12:14] == b"\x08\x00"
    ip_offset = 14
    ihl = (frame[ip_offset] & 0x0F) * 4
    assert ihl == 20 and frame[ip_offset + 9] == 6
    ip_header = frame[ip_offset : ip_offset + ihl]
    assert _checksum(ip_header) == 0
    src = str(ipaddress.IPv4Address(frame[ip_offset + 12 : ip_offset + 16]))
    dst = str(ipaddress.IPv4Address(frame[ip_offset + 16 : ip_offset + 20]))
    tcp_offset = ip_offset + ihl
    tcp_len = (frame[tcp_offset + 12] >> 4) * 4
    assert tcp_len == 20
    tcp_segment = frame[tcp_offset:]
    pseudo = (
        frame[ip_offset + 12 : ip_offset + 20]
        + struct.pack("!BBH", 0, 6, len(tcp_segment))
    )
    assert _checksum(pseudo + tcp_segment) == 0
    return src, dst, frame[tcp_offset + tcp_len :]


def test_manifest_validates_and_binds_every_input_artifact() -> None:
    Draft202012Validator.check_schema(MANIFEST_SCHEMA)
    assert list(Draft202012Validator(MANIFEST_SCHEMA).iter_errors(MANIFEST)) == []
    expected_paths = {
        "fixture_source.py",
        "fixtures/fragmented-tls-handshake-header.pcap",
        "fixtures/pcre-stream-32.pcap",
        "fixtures/pcre-stream-64.pcap",
        "fixtures/pcre-stream-128.pcap",
        "rules/local.rules",
        "suricata.yaml",
    }
    artifacts = {artifact["path"]: artifact for artifact in MANIFEST["artifacts"]}
    assert set(artifacts) == expected_paths
    for relative, artifact in artifacts.items():
        content = (ROOT / relative).read_bytes()
        assert artifact["bytes"] == len(content)
        assert artifact["sha256"] == hashlib.sha256(content).hexdigest()


def test_checked_in_pcaps_are_exact_generator_outputs() -> None:
    generator = _load_generator()
    built = generator.build_all()
    assert set(built) == {path.name for path in (ROOT / "fixtures").glob("*.pcap")}
    for name, content in built.items():
        assert (ROOT / "fixtures" / name).read_bytes() == content


def test_pcaps_use_only_documentation_addresses_and_declared_bounds() -> None:
    cases = {case["id"]: case for case in MANIFEST["cases"]}
    declarations = {
        cases["fragmented_tls_handshake_header"]["capture"]: (
            cases["fragmented_tls_handshake_header"]["packet_count"],
            cases["fragmented_tls_handshake_header"]["payload_bytes"],
        )
    }
    for capture in cases["pcre_only_stream_progress"]["captures"]:
        declarations[capture["path"]] = (
            capture["packet_count"],
            capture["payload_bytes"],
        )

    allowed = {"192.0.2.10", "192.0.2.20"}
    for relative, (packet_count, payload_bytes) in declarations.items():
        raw = (ROOT / relative).read_bytes()
        assert len(raw) <= MANIFEST["limits"]["max_fixture_bytes"]
        frames = _pcap_frames(raw)
        decoded = [_tcp_payload(frame) for frame in frames]
        assert len(frames) == packet_count <= MANIFEST["limits"]["max_packets"]
        assert sum(len(payload) for _, _, payload in decoded) == payload_bytes
        assert {address for src, dst, _ in decoded for address in (src, dst)} == allowed


def test_tls_fixture_splits_header_across_records_and_carries_synthetic_sni() -> None:
    raw = (ROOT / "fixtures" / "fragmented-tls-handshake-header.pcap").read_bytes()
    payloads = [payload for frame in _pcap_frames(raw) for _, _, payload in [_tcp_payload(frame)] if payload]
    assert len(payloads) == 2
    first, second = payloads
    assert first[:5] == b"\x16\x03\x03\x00\x02"
    assert first[5:] == b"\x01\x00"
    assert second[:3] == b"\x16\x03\x03"
    assert second[5:7] == b"\x00\x46"
    assert b"fragmented.example" in second


def test_pcre_fixtures_double_completed_stream_without_content_prefilter() -> None:
    for count in (32, 64, 128):
        raw = (ROOT / "fixtures" / f"pcre-stream-{count}.pcap").read_bytes()
        payloads = [payload for frame in _pcap_frames(raw) for _, _, payload in [_tcp_payload(frame)] if payload]
        assert len(payloads) == count
        assert all(len(payload) == 512 for payload in payloads)
        assert payloads[-1].endswith(b"mc")

    rules = (ROOT / "rules" / "local.rules").read_text(encoding="utf-8").splitlines()
    assert len(rules) == 2
    assert "tls.sni; content:\"fragmented.example\"" in rules[0]
    assert 'pcre:"/.*mc|\\H+$/"' in rules[1]
    assert "content:" not in rules[1]


def test_candidate_configuration_is_alert_only_and_has_no_external_sink() -> None:
    config = yaml.safe_load((ROOT / "suricata.yaml").read_text(encoding="utf-8"))
    assert config["suricata-version"] == "8.0"
    assert config["vars"]["address-groups"]["HOME_NET"] == "[192.0.2.0/24]"
    assert config["stats"]["enabled"] is False
    assert config["outputs"] == [
        {
            "eve-log": {
                "enabled": True,
                "filetype": "regular",
                "filename": "eve.json",
                "threaded": False,
                "pcap-file": False,
                "community-id": False,
                "types": [
                    {
                        "alert": {
                            "payload": False,
                            "packet": False,
                            "metadata": {
                                "app-layer": False,
                                "flow": False,
                                "rule": {
                                    "metadata": False,
                                    "raw": False,
                                    "reference": False,
                                },
                            },
                        }
                    }
                ],
            }
        }
    ]
    serialized = json.dumps(config, sort_keys=True).lower()
    for forbidden in ("redis", "syslog", "unix_stream", "af-packet", "nfq", "interface"):
        assert forbidden not in serialized


def test_not_run_receipt_validates_and_cannot_be_promoted_by_status_change() -> None:
    assert hashlib.sha256(MANIFEST_BYTES).hexdigest() == RECEIPT["packet_sha256"]
    Draft202012Validator.check_schema(RECEIPT_SCHEMA)
    validator = Draft202012Validator(RECEIPT_SCHEMA)
    assert list(validator.iter_errors(RECEIPT)) == []

    forged = deepcopy(RECEIPT)
    forged["status"] = "pass"
    assert list(validator.iter_errors(forged))

    partially_forged = deepcopy(forged)
    partially_forged["producer"].update(
        {
            "role": "candidate",
            "version": "8.0.7-candidate",
            "sha256": "0" * 64,
            "exact_identity_verified": True,
        }
    )
    assert list(validator.iter_errors(partially_forged))


def test_packet_has_zero_operational_effects_and_generator_has_no_network_or_process_capability() -> None:
    assert MANIFEST["execution_status"] == "not_run"
    assert MANIFEST["producer_acceptance"] == "not_established"
    assert set(MANIFEST["effects"].values()) == {False}
    assert set(RECEIPT["effects"].values()) == {False}
    assert RECEIPT["acceptance_authority"] is False

    source = (ROOT / "fixture_source.py").read_text(encoding="utf-8")
    for forbidden in ("subprocess", "socket", "urllib", "requests", "scapy"):
        assert forbidden not in source.lower()
