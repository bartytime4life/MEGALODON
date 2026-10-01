#!/usr/bin/env bash
# Install once, then open this computer's local MEGALODON workspace.
set -euo pipefail

checkout_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$checkout_dir"

case "${1:-}" in
  --help|-h)
    echo 'Double-click this script and choose Run in Terminal, or run ./Start-MEGALODON.sh.'
    echo 'The first run installs MEGALODON. Later runs reopen the local HUD.'
    echo 'Use --update to install this checkout again, or --check to check the installation.'
    exit 0 ;;
  ''|--update|--check) ;;
  *) echo 'Use no options, --update, --check, or --help.' >&2; exit 2 ;;
esac
if (( $# > 1 )); then echo 'Only one option is accepted.' >&2; exit 2; fi
if [[ "$(uname -s)" != Linux || "$EUID" == 0 ]]; then
  echo 'Run MEGALODON as your regular Linux desktop user, without sudo.' >&2
  exit 2
fi

local_python=""
for candidate in "${MEGALODON_PYTHON:-}" "$checkout_dir/.venv312/bin/python" "$checkout_dir/.venv/bin/python" python3 python3.13 python3.12 python3.11; do
  [[ -n "$candidate" ]] || continue
  if "$candidate" -E -s -c 'import sys, sqlite3, tomllib, venv; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
    local_python="$candidate"; break
  fi
done
if [[ -z "$local_python" ]]; then
  echo 'MEGALODON needs Python 3.11 or newer with venv. See docs/local-pc-setup.md.' >&2
  exit 2
fi
if [[ "${1:-}" == --check ]]; then
  exec "$local_python" -E -s -m megalodon.local_install status
fi
if [[ "${1:-}" == --update ]] || ! "$local_python" -E -s -m megalodon.local_install status --json >/dev/null 2>&1; then
  echo 'Installing MEGALODON for this user…'
  "$local_python" -E -s -m megalodon.local_install install --source "$checkout_dir"
fi

# The fixed user service keeps the HUD alive after the launch terminal closes.
# Starting it here does not enable login startup or restart an existing session.
if command -v systemctl >/dev/null 2>&1; then
  if ! "$local_python" -E -s -m megalodon.hud_autostart start; then
    echo 'Background startup is unavailable; opening a foreground HUD. Keep this terminal open.' >&2
  fi
fi
exec "$HOME/.local/bin/megalodon-hud"
