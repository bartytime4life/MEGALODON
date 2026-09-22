#!/usr/bin/env python3
"""Validate explicit Ollama identity snapshots without contacting Ollama."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from megalodon.ollama_identity import (
    OllamaIdentityError,
    canonical_json,
    identity_receipt,
    parse_observation_bytes,
    validate_observation,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Validate an operator-supplied, privacy-minimized Ollama identity "
            "observation. This tool performs no provider or host inspection."
        ),
    )
    parser.add_argument("observation", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        try:
            raw = args.observation.read_bytes()
        except OSError as exc:
            raise OllamaIdentityError("OBSERVATION_READ") from exc
        result = identity_receipt(
            validate_observation(parse_observation_bytes(raw))
        )
    except OllamaIdentityError as exc:
        print(
            canonical_json(
                {
                    "schema": "megalodon-ollama-identity-error-v1",
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
