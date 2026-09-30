#!/usr/bin/env bash
# Use the installed support launcher, with a reviewed checkout fallback.
set -euo pipefail
support_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
support_installed="${XDG_DATA_HOME:-$HOME/.local/share}/megalodon/current/venv/bin/python"
if [[ -x "$support_installed" ]] && "$support_installed" -I -c 'import megalodon.support_apps' >/dev/null 2>&1; then
  exec "$support_installed" -I -m megalodon.support_apps "$@"
fi
cd -- "$support_root"
for support_python in "$support_root/.venv312/bin/python" "$support_root/.venv/bin/python" python3; do
  if "$support_python" -c 'import megalodon.support_apps' >/dev/null 2>&1; then
    exec "$support_python" -m megalodon.support_apps "$@"
  fi
done
echo 'Install MEGALODON or activate its Python environment first.' >&2
exit 2
