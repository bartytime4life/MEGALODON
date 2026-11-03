#!/usr/bin/env python3
"""Verify an explicit local Qwen store without contacting or enabling Ollama."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from megalodon.model_artifact import ArtifactError, SCHEMA, observe_artifact


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--store', required=True, type=Path, help='Actual absolute OLLAMA_MODELS directory; links are refused')
    parser.add_argument('--model', required=True, help='One exact Qwen tag, never :latest')
    parser.add_argument('--provider', type=Path, default=Path('/usr/local/bin/ollama'), help='Provider executable to hash, never execute')
    parser.add_argument('--manifest-sha256', help='Optional independently retained manifest comparison pin')
    parser.add_argument('--provider-sha256', help='Optional independently retained executable comparison pin')
    args = parser.parse_args(argv)
    try:
        value = observe_artifact(args.store, args.model, args.provider,
                                 manifest_pin=args.manifest_sha256, provider_pin=args.provider_sha256)
    except ArtifactError as exc:
        value = {'schema': SCHEMA, 'state': 'REFUSED', 'error_code': str(exc),
                 'binding_status': 'UNBOUND', 'provider_contacted': False, 'model_started': False}
        print(json.dumps(value, sort_keys=True, separators=(',', ':')))
        return 2
    print(json.dumps(value, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
