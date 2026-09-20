"""Tests for the read-only Qwen/Ollama provider posture observer."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
import socket

import pytest

import megalodon.provider_containment as pc


@pytest.fixture(autouse=True)
def unprivileged(monkeypatch):
    monkeypatch.setattr(pc, "require_unprivileged_linux", lambda: None)


def _as_plain(value):
    if isinstance(value, Mapping):
        return {key: _as_plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_as_plain(item) for item in value]
    return value


# --- structural guarantees: this module never contacts anything ------------

def test_module_never_imports_or_calls_a_network_client() -> None:
    source = Path(pc.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    for forbidden_module in ("http.client", "urllib", "urllib.request", "requests", "subprocess"):
        assert forbidden_module not in imported
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {"connect", "sendall", "send", "recv", "Popen"}:
            pytest.fail(f"forbidden call to .{node.attr} found in provider_containment.py")


def test_qwen_advisory_module_does_not_import_this_one() -> None:
    import megalodon.qwen_advisory as qwen_advisory

    source = Path(qwen_advisory.__file__).read_text(encoding="utf-8")
    assert "provider_containment" not in source


# --- observational behavior against real sockets ---------------------------

def test_nothing_listening_is_reported_as_no() -> None:
    # An arbitrary high port that is not bound during the test.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()

    result = pc.qwen_provider_posture(host="127.0.0.1", port=free_port)
    assert result["listening"] == "no"
    assert result["bindings"] == ()
    assert result["loopback_only"] is None
    assert result["owning_process"]["resolution"] == "not_attempted"


def test_loopback_listener_is_observed_and_self_owned() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        result = pc.qwen_provider_posture(host="127.0.0.1", port=port)
        assert result["listening"] == "yes"
        assert len(result["bindings"]) == 1
        binding = result["bindings"][0]
        assert binding["family"] == "ipv4"
        assert binding["address"] == "127.0.0.1"
        assert binding["is_loopback"] is True
        assert binding["uid_matches_self"] is True
        assert result["loopback_only"] is True
        assert result["owning_process"]["resolution"] == "resolved"
        assert result["owning_process"]["pid"] is not None
        assert result["owning_process"]["distinct_net_namespace_from_self"] is False
    finally:
        server.close()


def test_wildcard_listener_breaks_loopback_only(tmp_path, monkeypatch) -> None:
    port = 48_765
    tcp_table = tmp_path / "tcp"
    tcp_table.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: 00000000:{port:04X} 00000000:0000 0A 00000000:00000000 "
        f"00:00000000 00000000 {pc.os.geteuid()} 0 12345\n",
        encoding="ascii",
    )
    monkeypatch.setattr(pc, "_TCP_TABLES", (("ipv4", str(tcp_table), 4),))

    result = pc.qwen_provider_posture(host="127.0.0.1", port=port)
    assert result["listening"] == "yes"
    assert result["loopback_only"] is False
    assert result["bindings"][0]["is_loopback"] is False


def test_result_is_a_fully_immutable_snapshot() -> None:
    result = pc.qwen_provider_posture()
    with pytest.raises(TypeError):
        result["listening"] = "yes"  # type: ignore[index]
    assert isinstance(result["bindings"], tuple)
    for binding in result["bindings"]:
        with pytest.raises(TypeError):
            binding["uid"] = 0  # type: ignore[index]


def test_result_is_json_serializable_and_closed_shape() -> None:
    import json

    result = pc.qwen_provider_posture()
    encoded = json.dumps(_as_plain(result))
    decoded = json.loads(encoded)
    assert set(decoded) == {
        "schema_version", "checked_at", "observation_mode", "target",
        "listening", "bindings", "loopback_only", "owning_process", "caveats",
    }
    assert decoded["schema_version"] == pc.SCHEMA_VERSION
    assert decoded["listening"] in {"yes", "no", "unknown"}


def test_defaults_match_the_qwen_advisory_fixed_destination() -> None:
    from megalodon.qwen_advisory import LOOPBACK_HOST, LOOPBACK_PORT

    result = pc.qwen_provider_posture()
    assert dict(result["target"]) == {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT}


# --- fail-closed on uncertainty, never guesses -----------------------------

def test_unreadable_proc_reports_unknown_not_no(monkeypatch) -> None:
    monkeypatch.setattr(pc, "_TCP_TABLES", (("ipv4", "/nonexistent/tcp", 4), ("ipv6", "/nonexistent/tcp6", 16)))
    result = pc.qwen_provider_posture(host="127.0.0.1", port=59999)
    assert result["listening"] == "unknown"
    assert result["loopback_only"] is None


def test_existing_but_denied_proc_reports_unknown_not_no(monkeypatch) -> None:
    monkeypatch.setattr(pc, "_TCP_TABLES", (("ipv4", "/proc/net/tcp", 4),))

    def denied_open(*args, **kwargs):
        raise PermissionError("simulated proc denial")

    monkeypatch.setattr("builtins.open", denied_open)
    result = pc.qwen_provider_posture(host="127.0.0.1", port=59999)
    assert result["listening"] == "unknown"
    assert result["loopback_only"] is None


def test_partial_tables_never_claim_loopback_only(tmp_path, monkeypatch) -> None:
    port = 48_766
    tcp_table = tmp_path / "tcp"
    tcp_table.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 "
        f"00:00000000 00000000 {pc.os.geteuid()} 0 12346\n",
        encoding="ascii",
    )
    monkeypatch.setattr(pc, "_TCP_TABLES", (
        ("ipv4", str(tcp_table), 4),
        ("ipv6", "/nonexistent/tcp6", 16),
    ))

    result = pc.qwen_provider_posture(host="127.0.0.1", port=port)
    assert result["listening"] == "yes"
    assert result["loopback_only"] is None


def test_binding_cap_never_claims_complete_loopback_scope(tmp_path, monkeypatch) -> None:
    port = 48_767
    tcp_table = tmp_path / "tcp"
    tcp_table.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 "
        f"00:00000000 00000000 {pc.os.geteuid()} 0 12347\n"
        f"   1: 00000000:{port:04X} 00000000:0000 0A 00000000:00000000 "
        f"00:00000000 00000000 {pc.os.geteuid()} 0 12348\n",
        encoding="ascii",
    )
    monkeypatch.setattr(pc, "MAX_BINDINGS", 1)
    monkeypatch.setattr(pc, "_TCP_TABLES", (("ipv4", str(tcp_table), 4),))

    result = pc.qwen_provider_posture(host="127.0.0.1", port=port)
    assert result["listening"] == "yes"
    assert len(result["bindings"]) == 1
    assert result["loopback_only"] is None


def test_permission_denied_pid_scan_is_reported_honestly(monkeypatch) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        real_listdir = pc.os.listdir

        def denied_listdir(path, *args, **kwargs):
            if path == "/proc":
                return real_listdir(path, *args, **kwargs)
            raise PermissionError("simulated denial")

        monkeypatch.setattr(pc.os, "listdir", denied_listdir)
        result = pc.qwen_provider_posture(host="127.0.0.1", port=port)
        assert result["owning_process"]["resolution"] == "permission_denied"
        assert result["owning_process"]["pid"] is None
        assert result["owning_process"]["exe_basename"] is None
    finally:
        server.close()


@pytest.mark.parametrize(("host", "port"), [
    (127001, 11434),
    ("127.0.0.1", 0),
    ("127.0.0.1", 70000),
    ("127.0.0.1", "11434"),
])
def test_invalid_target_is_rejected(host, port) -> None:
    with pytest.raises(ValueError):
        pc.qwen_provider_posture(host=host, port=port)


def test_platform_gate_is_actually_invoked(monkeypatch) -> None:
    def deny():
        raise Exception("PLATFORM_GATE_TRIGGERED")

    monkeypatch.setattr(pc, "require_unprivileged_linux", deny)
    with pytest.raises(Exception, match="PLATFORM_GATE_TRIGGERED"):
        pc.qwen_provider_posture()


def test_caveats_are_present_and_non_empty() -> None:
    result = pc.qwen_provider_posture()
    assert len(result["caveats"]) >= 3
    assert all(isinstance(item, str) and item for item in result["caveats"])
