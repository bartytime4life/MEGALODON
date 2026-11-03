#!/usr/bin/env python3
"""Compatibility entry point for the generic local Ollama artifact verifier."""
from __future__ import annotations

from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from local_model_artifact import main


if __name__ == '__main__':
    raise SystemExit(main())
