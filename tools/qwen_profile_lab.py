#!/usr/bin/env python3
"""Offline CLI for MEGALODON Ollama/Qwen profile candidates."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from megalodon.model_profile import (
    ModelProfileError,
    binding_candidate_packet,
    canonical_json,
    compare_profiles,
    parse_profile_bytes,
    validate_profile,
)


def _read(path: Path):
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ModelProfileError("PROFILE_READ") from exc
    return validate_profile(parse_profile_bytes(data))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate operator-supplied Ollama/Qwen profile candidates without "
            "contacting Ollama, starting a model, or granting admission."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate one closed profile")
    validate.add_argument("profile", type=Path)

    packet = sub.add_parser(
        "packet", help="emit a non-authoritative binding-candidate packet"
    )
    packet.add_argument("profile", type=Path)

    compare = sub.add_parser(
        "compare", help="rank two or more self-reported candidates"
    )
    compare.add_argument("profiles", type=Path, nargs="+")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            profile = _read(args.profile)
            result = {
                "schema": "megalodon-local-model-profile-validation-v1",
                "state": "VALID",
                "profile_id": profile.profile_id,
                "profile_sha256": profile.canonical_sha256,
                "hard_gate_passed": profile.hard_gate_passed,
                "gate_failures": list(profile.gate_failures),
                "network_performed": False,
                "provider_started": False,
            }
        elif args.command == "packet":
            result = binding_candidate_packet(_read(args.profile))
        else:
            result = compare_profiles([_read(path) for path in args.profiles])
    except ModelProfileError as exc:
        print(
            canonical_json(
                {
                    "schema": "megalodon-local-model-profile-error-v1",
                    "state": "REFUSED",
                    "error_code": exc.code,
                    "network_performed": False,
                    "provider_started": False,
                }
            )
        )
        return 2

    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
