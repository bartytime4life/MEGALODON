#!/usr/bin/env bash
# Install the reviewed checkout as a user-scoped Linux desktop application.
set -euo pipefail

checkout_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$checkout_dir"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'HELP'
Usage: ./scripts/install-local.sh [install | status [--json] | repair | uninstall]

  install     Build a private application environment and add MEGALODON to the
              current user's application menu. This is the default action.
  status      Check the installed release, launchers, settings, and desktop icon.
  repair      Restore missing managed launchers; preserve data and settings.
  uninstall   Remove managed code and launchers; preserve data and settings.

Installation is Linux-only and refuses root/sudo. It may download Python build
requirements while installing this reviewed checkout. It does not install
optional tools, start sensors, create telemetry, or enable automatic startup.
Set MEGALODON_PYTHON to one absolute Python 3.11+ interpreter path if needed.
HELP
  exit 0
fi

compatible_python() {
  "$1" -I -c 'import sys; assert sys.version_info >= (3, 11); import sqlite3, tomllib, venv' >/dev/null 2>&1
}

local_python=""
if [[ -n "${MEGALODON_PYTHON:-}" ]]; then
  if compatible_python "$MEGALODON_PYTHON"; then
    local_python="$MEGALODON_PYTHON"
  else
    echo 'MEGALODON_PYTHON must name Python 3.11 or newer with SQLite, TOML and venv support.' >&2
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
  echo 'Python 3.11 or newer with SQLite, TOML and venv support is required.' >&2
  echo 'See docs/local-pc-setup.md for supported installation choices.' >&2
  exit 2
fi

if (( $# == 0 )); then
  set -- install
fi

case "$1" in
  install)
    if (( $# != 1 )); then
      echo 'install accepts no additional arguments.' >&2
      exit 2
    fi
    exec "$local_python" -E -s -m megalodon.local_install install --source "$checkout_dir"
    ;;
  status|repair|uninstall)
    exec "$local_python" -E -s -m megalodon.local_install "$@"
    ;;
  *)
    echo 'Choose install, status, repair, or uninstall. Use --help for details.' >&2
    exit 2
    ;;
esac
