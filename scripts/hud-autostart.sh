#!/usr/bin/env bash
# Enable or disable the installed HUD at desktop sign-in, for this user only.
set -euo pipefail

case "${1:-}" in
  start|enable|disable) ;;
  *) echo 'Usage: ./scripts/hud-autostart.sh start | enable [--start] | disable' >&2; exit 2 ;;
esac

release_python="${XDG_DATA_HOME:-$HOME/.local/share}/megalodon/current/venv/bin/python"
if [[ ! -x "$release_python" ]]; then
  echo 'Install the local MEGALODON application first.' >&2
  exit 2
fi
exec "$release_python" -I -m megalodon.hud_autostart "$@"
