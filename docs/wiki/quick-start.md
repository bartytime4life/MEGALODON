# Quick Start

Use MEGALODON as a normal user in private local storage. Do not run it as root or Administrator for the synthetic core demonstration.

## Linux synthetic core

From a reviewed checkout with no existing `.venv`:

```bash
(
  set -euo pipefail
  umask 077
  [ "$(id -u)" -ne 0 ] || { echo 'Use a non-root account.'; exit 1; }
  [ ! -e .venv ] && [ ! -L .venv ] || { echo '.venv already exists; stop.'; exit 1; }
  python3 -m venv .venv
  .venv/bin/python -m pip install -e ".[test]"
  .venv/bin/python -m megalodon run --source sample --max-events 13
  .venv/bin/python -m megalodon run --source sample --demo-threat --max-events 114
  .venv/bin/python -m megalodon dashboard --host 127.0.0.1 --port 8787
)
```

Open <http://127.0.0.1:8787/> only while the foreground dashboard process is running. Stop it with Ctrl+C.

The first run is benign. `--demo-threat` adds synthetic metadata so the UI has detections to display; it is not a diagnosis of the host network.

## First checks

```bash
.venv/bin/python -m megalodon capabilities --platform linux
.venv/bin/python -m megalodon hub-plan --platform linux
.venv/bin/python -m pytest -q
```

These commands do not authorize capture, a firewall action, a model request, or a remote listener. For pinned Linux and native Windows evaluation recipes, use the [platform baseline](../platform-baseline.md).
