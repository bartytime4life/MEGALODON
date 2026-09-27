#!/usr/bin/env bash
# Single reviewed checkout entry point for optional companion plans and actions.
set -euo pipefail

checkout_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$checkout_dir"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
  cat <<'HELP'
Usage: ./scripts/manage-companion.sh TOOL [plan|install|uninstall|configure|verify] [--apply]

Preview a fixed recipe or read the configuration/verification instructions.
Install --apply executes the selected fixed recipe. Uninstall --apply requires
an interactive terminal and the exact tool ID typed again; package managers
may ask for confirmation. Ubuntu package removals first show an unprivileged
read-only dependency plan. Review the package manager's final plan too.
Guided tools have no automatic removal recipe.

For the MEGALODON application itself, use ./scripts/install-local.sh install
or ~/.local/bin/megalodon-manage uninstall (preserves settings and data).

Uses the reviewed checkout's .venv312/.venv if present, else Python 3.11+.
Set MEGALODON_PYTHON to choose a specific interpreter. Run as your ordinary
user; this script does not start scans, capture or firewall actions.
HELP
  exit 0
fi

if (( $# < 1 || $# > 3 )); then
  echo 'Expected TOOL, optional action, and optional --apply.' >&2
  exit 2
fi

compatible_python() {
  "$1" -c 'import sys; assert sys.version_info >= (3, 11); import sqlite3, tomllib' >/dev/null 2>&1
}

local_python=""
if [[ -n "${MEGALODON_PYTHON:-}" ]]; then
  if compatible_python "$MEGALODON_PYTHON"; then
    local_python="$MEGALODON_PYTHON"
  else
    echo 'MEGALODON_PYTHON must name Python 3.11+ with SQLite and TOML support.' >&2
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
  echo 'Python 3.11+ is required. See docs/local-pc-setup.md.' >&2
  exit 2
fi

exec "$local_python" -m megalodon.tool_setup "$@"
