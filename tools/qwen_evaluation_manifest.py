#!/usr/bin/env python3
"""Validate a privacy-minimized Qwen adversarial evaluation corpus manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from megalodon.model_evaluation import (
    ModelEvaluationError,
    canonical_json,
    manifest_projection,
    parse_manifest_bytes,
    validate_corpus_manifest,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Validate one frozen, canonical corpus manifest without reading "
            "fixtures, invoking a model or verifying signatures."
        ),
    )
    parser.add_argument("manifest", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        try:
            raw = args.manifest.read_bytes()
        except OSError as exc:
            raise ModelEvaluationError("MANIFEST_READ") from exc
        result = manifest_projection(
            validate_corpus_manifest(parse_manifest_bytes(raw))
        )
    except ModelEvaluationError as exc:
        print(
            canonical_json(
                {
                    "schema": "megalodon-local-model-evaluation-manifest-error-v1",
                    "state": "REFUSED",
                    "error_code": exc.code,
                    "provider_request_performed": False,
                    "signature_verified_by_tool": False,
                }
            )
        )
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
