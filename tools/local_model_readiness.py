#!/usr/bin/env python3
"""Assess one explicit local Ollama/Qwen evidence set without operating it."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from megalodon.local_model_readiness import (
    LocalModelReadinessError,
    assess_readiness,
    canonical_json,
)
from megalodon.model_evaluation import (
    ModelEvaluationError,
    parse_receipt_bytes,
    validate_evaluation_receipt,
)
from megalodon.model_profile import (
    ModelProfileError,
    parse_profile_bytes,
    validate_profile,
)
from megalodon.ollama_generate_contract import (
    GenerateContractError,
    build_generate_request,
    parse_input_bytes,
)
from megalodon.ollama_identity import (
    OllamaIdentityError,
    parse_observation_bytes,
    validate_observation,
)
from tools.local_model_binding import BindingError, load_json, validate as validate_binding
from tools.local_model_containment import (
    ContainmentError,
    load as load_containment,
    validate as validate_containment,
)


class ReadinessInputError(ValueError):
    """Fixed-code file/read error that does not expose a path."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _read(path: Path, code: str, *, maximum: int = 128 * 1024) -> bytes:
    try:
        data = path.read_bytes()
    except OSError:
        raise ReadinessInputError(code) from None
    if not 1 <= len(data) <= maximum:
        raise ReadinessInputError(code)
    return data


def _binding(path: Path) -> dict:
    try:
        return validate_binding(load_json(path))
    except BindingError:
        raise ReadinessInputError("BINDING_INVALID") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Cross-bind already generated local-model evidence without "
            "contacting Ollama, invoking Qwen, or changing the host."
        ),
    )
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--containment", type=Path)
    parser.add_argument("--evaluation", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument(
        "--require-consistent",
        action="store_true",
        help="return exit 3 unless the packet is CANDIDATE_PACKET_CONSISTENT",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        binding = _binding(args.binding)
        identity = (
            None
            if args.identity is None
            else validate_observation(
                parse_observation_bytes(_read(args.identity, "IDENTITY_INVALID"))
            )
        )
        profile = (
            None
            if args.profile is None
            else validate_profile(
                parse_profile_bytes(_read(args.profile, "PROFILE_INVALID"))
            )
        )
        containment = (
            None
            if args.containment is None
            else validate_containment(
                load_containment(_read(args.containment, "CONTAINMENT_INVALID"))
            )
        )
        evaluation = (
            None
            if args.evaluation is None
            else validate_evaluation_receipt(
                parse_receipt_bytes(
                    _read(args.evaluation, "EVALUATION_INVALID")
                )
            )
        )
        request = (
            None
            if args.request is None
            else build_generate_request(
                parse_input_bytes(_read(args.request, "REQUEST_INVALID"))
            )
        )
        result = assess_readiness(
            binding,
            identity=identity,
            profile=profile,
            containment=containment,
            evaluation=evaluation,
            request=request,
        )
    except ReadinessInputError as exc:
        code = exc.code
    except BindingError:
        code = "BINDING_INVALID"
    except OllamaIdentityError:
        code = "IDENTITY_INVALID"
    except ModelProfileError:
        code = "PROFILE_INVALID"
    except ContainmentError:
        code = "CONTAINMENT_INVALID"
    except ModelEvaluationError:
        code = "EVALUATION_INVALID"
    except GenerateContractError:
        code = "REQUEST_INVALID"
    except LocalModelReadinessError as exc:
        code = exc.code
    else:
        print(canonical_json(result))
        if args.require_consistent and result["state"] != "CANDIDATE_PACKET_CONSISTENT":
            return 3
        return 0

    print(
        canonical_json(
            {
                "schema": "megalodon-local-model-readiness-error-v1",
                "state": "REFUSED",
                "error_code": code,
                "network_performed": False,
                "provider_started": False,
                "host_changed": False,
            }
        )
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
