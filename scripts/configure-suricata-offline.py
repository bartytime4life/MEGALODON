#!/usr/bin/env python3
"""Prepare private Stage 0 configuration files; never execute Suricata.

Linux / Python 3.11+, standard library only. Preview is the default. See
docs/installing-suricata.md before using --write. No installation or host control.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_RULE_BYTES = 1024 * 1024
EMPTY_RULES = b"# No detection rules selected. This bundle cannot provide detection coverage.\n"
CONFIG = """%YAML 1.1
---
# Operator-owned offline profile; NOT /etc/suricata/suricata.yaml.
# Run only after separate native validation and isolated-host authorization.
suricata-version: "8.0"
runmode: single
unix-command:
  enabled: no
vars:
  address-groups:
    HOME_NET: "[{home_net}]"
    EXTERNAL_NET: "any"
  port-groups: {{}}
default-log-dir: .
default-rule-path: rules
rule-files:
  - local.rules
stats:
  enabled: no
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: megalodon-alerts.json
      threaded: false
      pcap-file: false
      community-id: false
      ethernet: no
      types:
        - alert:
            payload: no
            payload-printable: no
            payload-length: no
            packet: no
            metadata: no
            http-body: no
            http-body-printable: no
            tagged-packets: no
            verdict: no
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: no
flow:
  memcap: 32mb
stream:
  memcap: 32mb
  checksum-validation: yes
  midstream: false
  async-oneside: false
  reassembly:
    memcap: 64mb
    depth: 256kb
"""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def absolute_parts(value: str) -> tuple[str, ...]:
    if not value.startswith("/") or any(p in {".", ".."} for p in value.split("/")):
        raise ValueError("Use an absolute path without dot or parent components.")
    parts = Path(value).parts[1:]
    if not parts:
        raise ValueError("The filesystem root is not a bundle or rules file.")
    return parts


def open_directory(parts: tuple[str, ...]) -> int:
    """Walk with pinned directory descriptors, refusing symlink components."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        for part in parts:
            following = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def read_rules(path: str | None, expected: str | None) -> bytes:
    if path is None and expected is None:
        return EMPTY_RULES
    if path is None or expected is None or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Supply --rules with its exact lowercase --rules-sha256 (64 hex digits).")
    parts = absolute_parts(path)
    parent = open_directory(parts[:-1])
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RULE_BYTES:
            raise ValueError("Rules must be a regular file of at most 1 MiB.")
        data = stream.read(MAX_RULE_BYTES + 1)
    if len(data) > MAX_RULE_BYTES or digest(data) != expected:
        raise ValueError("Rules exceed 1 MiB or do not match the supplied SHA-256.")
    data.decode("utf-8")
    if b"\x00" in data:
        raise ValueError("Rules must not contain NUL bytes.")
    return data


def build_bundle(home_net: str, rules: bytes, selected: bool) -> dict[str, bytes]:
    if "/" not in home_net:
        raise ValueError("HOME_NET must include an explicit CIDR prefix length.")
    network = str(ipaddress.ip_network(home_net, strict=True))
    files = {
        "suricata.yaml": CONFIG.format(home_net=network).encode(),
        "rules/local.rules": rules,
    }
    receipt = {
        "schema": "megalodon-suricata-config-v1",
        "status": "prepared_not_validated",
        "target_producer_version": "8.0.7",
        "home_net": network,
        "rules_state": "operator_supplied_unvalidated" if selected else "empty_no_detection",
        "artifacts": {name: {"sha256": digest(data), "bytes": len(data)} for name, data in files.items()},
        "native_validation": "not_run",
        "binary_identity": "unbound",
        "acceptance_authority": False,
        "suricata_executed": False,
        "system_configuration_changed": False,
    }
    receipt["receipt_id"] = digest(canonical(receipt))
    files["configuration-receipt.json"] = canonical(receipt)
    return files


def write_bundle(output: str, files: dict[str, bytes]) -> None:
    parts = absolute_parts(output)
    parent = open_directory(parts[:-1])
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("Output parent must belong to you and not be group/other writable.")
        # mkdir is exclusive: even an empty existing directory or broken symlink fails.
        os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
        folder = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        os.fchmod(folder, 0o700)
        os.mkdir("rules", mode=0o700, dir_fd=folder)
        rules_dir = os.open("rules", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
        try:
            os.fchmod(rules_dir, 0o700)
            for name, data in files.items():
                directory = rules_dir if name.startswith("rules/") else folder
                fd = os.open(name.rsplit("/", 1)[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with os.fdopen(fd, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
        finally:
            os.close(rules_dir)
    finally:
        os.close(folder)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New absolute bundle directory; parent must exist")
    parser.add_argument("--home-net", required=True, help="One exact IPv4/IPv6 network CIDR; no host bits")
    parser.add_argument("--rules", help="Optional reviewed local UTF-8 rules file (absolute path, <=1 MiB)")
    parser.add_argument("--rules-sha256", help="Required exact digest when --rules is supplied")
    parser.add_argument("--write", action="store_true", help="Create files; default is a read-only preview")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux" or os.geteuid() == 0 or os.geteuid() != os.getuid():
            raise ValueError("Use Linux as your ordinary user, without sudo or elevated identity.")
        absolute_parts(args.output)
        rules = read_rules(args.rules, args.rules_sha256)
        files = build_bundle(args.home_net, rules, args.rules is not None)
        if args.write:
            write_bundle(args.output, files)
        print("Created private configuration bundle." if args.write else "PREVIEW ONLY: no files written; destination has not been checked.")
        print(files["configuration-receipt.json"].decode(), end="")
        print("Suricata was NOT run. No package, service, firewall, model or system configuration was changed.")
        return 0
    except (OSError, ValueError) as error:
        print(f"Refused: {error}. Existing files are never replaced; inspect any partial new bundle before retrying.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
