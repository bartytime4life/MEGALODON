#!/usr/bin/env bash
# Invoke only the running HUD's fixed local defense API.
set -euo pipefail
defense_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
defense_installed="${XDG_DATA_HOME:-$HOME/.local/share}/megalodon/current/venv/bin/python"
if [[ -x "$defense_installed" ]] && "$defense_installed" -I -c 'import megalodon.defense' >/dev/null 2>&1; then
  exec "$defense_installed" -I -m megalodon.defense "$@"
fi
cd -- "$defense_root"
exec "$defense_root/.venv312/bin/python" -m megalodon.defense "$@"
