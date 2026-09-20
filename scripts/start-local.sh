#!/usr/bin/env bash
# Run this reviewed checkout without changing the user's Python installation.
set -euo pipefail

checkout_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$checkout_dir"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'HELP'
Usage: ./scripts/start-local.sh [--check | HUD options]

Launch the local, read-only HUD in this terminal. Open the printed localhost
address in your browser; press Ctrl+C here to stop it.

  --check                 Check Python, SQLite and the default data path; no server
  --port 8788             Use another localhost port
  --config /path/app.toml  Select an existing configuration (HUD options)

Uses .venv312, .venv, or an available Python >=3.11. Set MEGALODON_PYTHON
to one interpreter path to choose explicitly. No packages are installed,
no data is created, and no sensor or automatic startup is enabled.
HELP
  exit 0
fi

compatible_python() {
  "$1" -c 'import sys; assert sys.version_info >= (3, 11); import sqlite3, tomllib' >/dev/null 2>&1
}

local_python=""
if [[ -n "${MEGALODON_PYTHON:-}" ]]; then
  if compatible_python "$MEGALODON_PYTHON"; then
    local_python="$MEGALODON_PYTHON"
  else
    echo 'MEGALODON_PYTHON must name Python 3.11 or newer with SQLite and TOML support.' >&2
    exit 2
  fi
else
  for candidate in "$checkout_dir/.venv312/bin/python" "$checkout_dir/.venv/bin/python" python3 python3.13 python3.12 python3.11; do
    if compatible_python "$candidate"; then
      local_python="$candidate"
      break
    fi
  done
fi

if [[ -z "$local_python" ]]; then
  echo 'Python 3.11 or newer with SQLite and TOML support is required. See docs/local-pc-setup.md.' >&2
  exit 2
fi

if [[ "${1:-}" == "--check" ]]; then
  shift
  if (( $# )); then
    echo '--check accepts no HUD options; it checks the default checkout data path.' >&2
    exit 2
  fi
  exec "$local_python" -m megalodon.local_setup
fi

echo "Using Python: $local_python"
exec "$local_python" -u -m megalodon hud "$@"
