#!/usr/bin/env python3
"""Validate one deterministic Ollama generate-request input without networking."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from megalodon.ollama_generate_contract import (
    GenerateContractError,
    build_generate_request,
    canonical_json,
    parse_input_bytes,
    request_receipt,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Validate and hash one explicit Ollama generate-request input. "
            "This tool performs no provider or host operation."
        ),
    )
    parser.add_argument("request_input", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        try:
            raw = args.request_input.read_bytes()
        except OSError as exc:
            raise GenerateContractError("INPUT_READ") from exc
        result = request_receipt(build_generate_request(parse_input_bytes(raw)))
    except GenerateContractError as exc:
        print(
            canonical_json(
                {
                    "schema": "megalodon-ollama-generate-request-error-v1",
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
