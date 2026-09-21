# Quick Start

Use MEGALODON as an ordinary user in private local storage. The synthetic core
does not require a capture driver, firewall privilege, companion application,
GPU, cloud account, or local model.

## Install for this Linux user

From a reviewed checkout:

```bash
./scripts/install-local.sh
```

Open **MEGALODON** from the application menu. The terminal window owns the local
server; Ctrl+C stops it. The browser opens after loopback binding succeeds.
Installation does not create data, add automatic startup, or install companion
tools.

## Run the checkout without installing

```bash
./scripts/start-local.sh
```

The launcher selects an existing Python 3.11+ environment, stays in the foreground,
and leaves missing data absent. Open its printed localhost URL on the same PC;
Ctrl+C stops it. See [local PC setup](../local-pc-setup.md) for Home → Data and
tools, desktop maintenance, and next-launch settings. It does not install
packages or start capture. Other installed environments can still use
`python -m megalodon hud`.

Choose **Home → Data and tools → Check this computer** to check the runtime,
selected data file and optional tools using the GUI. The same panel has official
download buttons, search and workflow choices. Start with the
[visual walkthrough](../gui-quick-start.md) or [software downloads](../software-downloads.md).
The optional `./scripts/start-local.sh --check` preflight remains available if
the HUD cannot start.

The following recipe is a separate, optional synthetic walkthrough for a new
environment. Do not recreate an existing environment merely to open the HUD.

## Prerequisites for the synthetic walkthrough

- a reviewed MEGALODON checkout;
- Python 3.11 or newer;
- `venv` and `pip`;
- no existing `.venv` at the path used below.

For pinned Linux and native Windows evaluation recipes, use the
[platform baseline](../platform-baseline.md). Native Windows remains an
evaluation target rather than a support-parity claim.

## Linux synthetic core

From the repository root:

```bash
(
  set -euo pipefail
  umask 077
  [ "$(id -u)" -ne 0 ] || { echo 'Use a non-root account.'; exit 1; }
  [ ! -e .venv ] && [ ! -L .venv ] || { echo '.venv already exists; stop.'; exit 1; }
  python3 -m venv .venv
  .venv/bin/python -m pip install -e .
  .venv/bin/python -m megalodon run --source sample --max-events 13
  .venv/bin/python -m megalodon run --source sample --demo-threat --max-events 114
  .venv/bin/python -m megalodon hud
)
```

Open <http://127.0.0.1:8787/> on the same computer while the foreground HUD is
running. Stop it with Ctrl+C.

The first run is benign. `--demo-threat` adds synthetic metadata so fixed-rule
findings appear; it does not inspect or diagnose the host network. Repeated runs
append to the configured audit database until an explicit storage limit or
operator action intervenes.

## What `hud` does on first launch

`hud` opens the local workspace even when the default audit store is absent. In
that case measurements remain unavailable and no database or demo data is
created. It also takes bounded startup snapshots of executable presence and
process names without launching or probing companion tools.

The original `dashboard` command keeps the stricter existing-store behavior and
does not take the tool-presence snapshot. Both interfaces stay loopback-bound and
read-only.

## First checks

```bash
.venv/bin/python -m megalodon --version
.venv/bin/python -m megalodon posture --platform linux
.venv/bin/python -m megalodon capabilities --platform linux
.venv/bin/python -m megalodon hub-plan --platform linux
```

These commands do not start capture, launch a companion tool, call Qwen, apply a
firewall change, or authorize a remote listener. `--platform` selects a static
documentation profile; it is not host detection or compatibility evidence.

## Add only what the workflow needs

```bash
.venv/bin/python -m pip install -e ".[capture]"  # optional Scapy capture path
.venv/bin/python -m pip install -e ".[test]"     # contributor checks
```

Do not install every cataloged application. Each adapter has its own platform,
input, privacy, and acceptance boundary. Continue with the [operator
guide](operator-guide.md) before interpreting the HUD.
