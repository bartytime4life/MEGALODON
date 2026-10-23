"""Independent deterministic controls; no real traffic or engine operations."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fixture_source", ROOT.parent / "fixture_source.py")
assert spec is not None and spec.loader is not None
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


def tls_control(*, wrong_sni: bool = False) -> bytes:
    first, second = source._tls_client_hello()
    handshake = first[5:] + second[5:]
    if wrong_sni:
        handshake = handshake.replace(b"fragmented.example", b"mismatched.example")
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    frames = source._handshake()
    frames.append(source._frame(from_client=True, seq=1001, ack=5001, flags=0x18,
                                payload=record, identification=4))
    frames.append(source._frame(from_client=False, seq=5001, ack=1001 + len(record),
                                flags=0x10, identification=5))
    return source._pcap(frames)


def pcre_negative() -> bytes:
    # Horizontal whitespace matches neither .*mc nor \H+$, at every window.
    frames = source._handshake()
    frames.append(source._frame(from_client=True, seq=1001, ack=5001, flags=0x18,
                                payload=b" " * 512, identification=4))
    frames.append(source._frame(from_client=False, seq=5001, ack=1513,
                                flags=0x10, identification=5))
    return source._pcap(frames)


def build_all() -> dict[str, bytes]:
    return {"tls-unsplit.pcap": tls_control(),
            "tls-wrong-sni.pcap": tls_control(wrong_sni=True),
            "pcre-negative.pcap": pcre_negative()}


if __name__ == "__main__":
    for name, content in build_all().items():
        (ROOT / name).write_bytes(content)
