#!/usr/bin/env bash
# Start one supported live metadata writer alongside the loopback HUD.
set -euo pipefail

checkout_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$checkout_dir"

usage() {
  cat <<'HELP'
Usage: ./scripts/start-hud-data.sh --interface IFACE [options]

Start MEGALODON's bounded Scapy metadata capture and the local read-only HUD.
Both use the same checkout, Python and configuration. Press Ctrl+C to stop both.
No companion service, firewall action, package installation or sudo is started.

  --interface IFACE          Existing Linux network interface to observe (required)
  --max-events N             Stop capture at N accepted events (default: 1000000)
  --config /absolute/file    Existing MEGALODON TOML configuration
  --port N                   Override the HUD's loopback port
  --geoip-db /absolute/file  Existing private offline IP region database
  --suricata-db /absolute/file
                             Existing private Suricata evidence store; startup snapshot
  --open-browser             Open the HUD after it binds
  --check                    Validate launch prerequisites without starting anything

Scapy must already be installed in the selected Python, and that interpreter
must already have permission to capture on IFACE. Use MEGALODON_PYTHON to select
one interpreter. The capture may end at its event ceiling; the HUD then stops
so it cannot appear to be receiving live data.
HELP
}

interface=""
max_events=1000000
config=""
port=""
geoip_db=""
suricata_db=""
open_browser=false
check=false
while (( $# )); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --interface|--max-events|--config|--port|--geoip-db|--suricata-db)
      option="$1"
      if (( $# < 2 )) || [[ "$2" == --* ]]; then
        echo "Missing value for $option" >&2; exit 2
      fi
      case "$option" in
        --interface) interface="$2" ;;
        --max-events) max_events="$2" ;;
        --config) config="$2" ;;
        --port) port="$2" ;;
        --geoip-db) geoip_db="$2" ;;
        --suricata-db) suricata_db="$2" ;;
      esac
      shift 2 ;;
    --open-browser) open_browser=true; shift ;;
    --check) check=true; shift ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "$interface" =~ ^[A-Za-z0-9_.:@-]{1,15}$ ]] || [[ ! -e "/sys/class/net/$interface" ]]; then
  echo 'Choose an existing Linux network interface with --interface.' >&2; exit 2
fi
if [[ ! "$max_events" =~ ^[0-9]{1,8}$ ]] || (( 10#$max_events < 1 || 10#$max_events > 10000000 )); then
  echo '--max-events must be between 1 and 10000000.' >&2; exit 2
fi
if [[ -n "$port" ]] && { [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); }; then
  echo '--port must be between 1 and 65535.' >&2; exit 2
fi
for selected_path in "$config" "$geoip_db" "$suricata_db"; do
  if [[ -n "$selected_path" ]] && { [[ "$selected_path" != /* ]] || [[ ! -f "$selected_path" ]]; }; then
    echo 'Selected configuration and evidence paths must be existing absolute files.' >&2
    exit 2
  fi
done

compatible_python() {
  "$1" -c 'import sys, sqlite3, tomllib; assert sys.version_info >= (3, 11)' >/dev/null 2>&1
}
local_python=""
if [[ -n "${MEGALODON_PYTHON:-}" ]]; then
  if compatible_python "$MEGALODON_PYTHON"; then
    local_python="$MEGALODON_PYTHON"
  else
    echo 'MEGALODON_PYTHON must name Python 3.11 or newer with SQLite and TOML.' >&2
    exit 2
  fi
else
  for candidate in "$checkout_dir/.venv312/bin/python" "$checkout_dir/.venv/bin/python" python3 python3.13 python3.12 python3.11; do
    if compatible_python "$candidate"; then local_python="$candidate"; break; fi
  done
fi
if [[ -z "$local_python" ]]; then
  echo 'Python 3.11 or newer with SQLite and TOML is required.' >&2; exit 2
fi
if ! "$local_python" -c 'import scapy.all' >/dev/null 2>&1; then
  echo 'Scapy is unavailable in the selected Python; install the optional capture extra in that environment.' >&2
  exit 2
fi

capture=("$local_python" -u -m megalodon run --source scapy --interface "$interface" --max-events "$max_events")
hud=("$local_python" -u -m megalodon hud)
if [[ -n "$config" ]]; then capture+=(--config "$config"); hud+=(--config "$config"); fi
if [[ -n "$port" ]]; then hud+=(--port "$port"); fi
if [[ -n "$geoip_db" ]]; then hud+=(--geoip-db "$geoip_db"); fi
if [[ -n "$suricata_db" ]]; then hud+=(--suricata-db "$suricata_db"); fi
if $open_browser; then hud+=(--open-browser); fi

echo "Using Python: $local_python"
echo "Live metadata source: Scapy on $interface, up to $max_events accepted events."
if [[ -n "$suricata_db" ]]; then
  echo 'Suricata evidence: selected startup snapshot only; this script does not operate its sensor or consumer.'
fi
if $check; then
  echo 'Prerequisites found. Capture permission, source health and HUD data are not established until launch.'
  exit 0
fi
if [[ ! -t 1 ]]; then
  echo 'The HUD requires an interactive terminal to show its sign-in password.' >&2
  exit 2
fi

capture_pid=""
hud_pid=""
stop_children() {
  trap - INT TERM EXIT
  if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then kill -TERM "$capture_pid" 2>/dev/null || true; fi
  if [[ -n "$hud_pid" ]] && kill -0 "$hud_pid" 2>/dev/null; then kill -TERM "$hud_pid" 2>/dev/null || true; fi
  if [[ -n "$capture_pid" ]]; then wait "$capture_pid" 2>/dev/null || true; fi
  if [[ -n "$hud_pid" ]]; then wait "$hud_pid" 2>/dev/null || true; fi
}
trap stop_children EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${capture[@]}" &
capture_pid=$!
# Give the writer time to create or validate its store and fail on missing
# capture permission before displaying a HUD that appears connected.
sleep 1
if ! kill -0 "$capture_pid" 2>/dev/null; then
  set +e
  wait "$capture_pid"
  result=$?
  set -e
  capture_pid=""
  echo 'Capture stopped before HUD startup; no live feed was established.' >&2
  exit "${result:-2}"
fi

"${hud[@]}" &
hud_pid=$!
set +e
wait -n -p stopped_pid "$capture_pid" "$hud_pid"
result=$?
set -e
if [[ "$stopped_pid" == "$capture_pid" ]]; then
  echo 'Capture stopped. Stopping the HUD so its data is not presented as live.' >&2
else
  echo 'HUD stopped. Stopping capture.' >&2
fi
exit "$result"
