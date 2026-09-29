# Install and check optional companion tools

**Start here:** opening MEGALODON needs Python 3.11+ with SQLite and the
[local application](local-pc-setup.md), not every product in the catalog.
Scapy is optional.

This walkthrough targets **Ubuntu 24.04** and a normal, non-root terminal.
Upstream instructions were consulted on **2026-09-22**; package versions remain mutable. These are operator-run instructions, not evidence
that anything is installed or accepted on your computer. Do not run the whole
page as one script. Stop at an error and use the troubleshooting table.

In **Home → Data and tools**, open Scapy, then **Easy setup and
verification**. The local HUD and repository Site mirror share these cards.
Copy buttons copy text only: they do not install, execute, probe, or mark a
tool as verified. The hosted Site cannot inspect your computer.

## What the indicators actually mean

| Observation | What it proves | What to do next |
| --- | --- | --- |
| Executable found | A representative executable was found in the HUD server's PATH | Check the version, installation method and intended data handoff |
| Not found | That executable was not found in the checked PATH | Check your virtual environment, container or private installation prefix before reinstalling |
| Not checked / unknown | No usable observation was made | Follow the tool-specific checks below; do not read this as absent |
| Scapy package metadata | A distribution is registered in the Python environment you checked | This is not an import, capture-permission or MEGALODON-environment test |

The fixed [readiness report](tool-readiness.md) intentionally does not import
Scapy or inspect Python packages.

## Scapy: install without capture privileges

Scapy supports Linux. On Linux, native Scapy does not require libpcap for basic
operation; `libpcap-dev` is an optional dependency for features such as BPF
filters. Neither root nor a live packet capture is needed for the package
metadata check in this guide.
Source: [Scapy installation documentation](https://scapy.readthedocs.io/en/latest/installation.html).

### 1. Check the existing environment first

In the local HUD, the Scapy card's **Check HUD Python package** command uses
the Python interpreter serving that HUD. On the hosted Site, activate your
reviewed MEGALODON virtual environment before using its `python3` example.

For the standalone environment from the earlier setup instructions, run this
from **any directory**:

```bash
"$HOME/scapy/.venv/bin/python" -I -c "from importlib.metadata import version; print('Scapy package:', version('scapy'))"
```

A version means package metadata was found **in that environment only**.
`No such file` means the interpreter path is missing; `PackageNotFoundError`
means this interpreter has no registered Scapy distribution. Neither proves
Scapy is absent from all other environments.

### 2. Prepare a standalone environment only when needed

This changes your Python setup and accesses Ubuntu's package repositories.
Review the package-manager prompt; do not use `sudo pip` or
`--break-system-packages`.

```bash
sudo apt update && sudo apt install python3-venv
```

Then, from any directory:

```bash
if test -e "$HOME/scapy/.venv" || test -L "$HOME/scapy/.venv"; then
  printf '%s\n' 'Environment already exists. Inspect it and use step 1; nothing was replaced.'
else
  python3 -m venv "$HOME/scapy/.venv"
fi
```

### 3. Install Scapy into that environment

This downloads a package into the selected virtual environment:

```bash
"$HOME/scapy/.venv/bin/python" -m pip install 'scapy>=2.5,<3'
```

Repeat step 1 to check it. The range matches MEGALODON's optional extra; it is
not a pinned artifact. Installing here does **not** install Scapy into the
separate MEGALODON desktop application's environment.

For a **developer checkout**, use its existing development environment instead:
from the reviewed MEGALODON repository root containing `pyproject.toml`, run
`.venv/bin/python -m pip install -e ".[capture]"`. Do not run that in an arbitrary
directory or modify managed desktop releases by guessing their internal paths.
A managed desktop capture-extra lifecycle is not supplied by this walkthrough.

Keep verification non-root. Do not add capture capabilities, run `sniff()`, or
send packets to prove installation. MEGALODON's optional live-capture acceptance
and explicit interface authorization remain separate.

## Troubleshooting without guessing

| Symptom | Next check |
| --- | --- |
| `externally-managed-environment` | Use the selected virtual environment; do not bypass system Python protection |
| Scapy installed, HUD still says not checked | Expected for the PATH-only report; run the exact HUD Python package check and keep standalone/desktop environments separate |

Return to **Check this computer** for the existing local checks. Restart the HUD
from an updated environment when its PATH changed. These observations do not
connect third-party telemetry, prove tool trust, or authorize sensors, model
operation, firewall changes, remote exposure, release or deployment.

## Source and review boundary

The software catalog remains [software-downloads.md](software-downloads.md);
the installation baseline remains [platform-baseline.md](platform-baseline.md).
This guide adds a narrower walkthrough, not a new required dependency, version
lock, installed-host receipt or automatic installer. Publishing repository Site
assets is separate from deploying the existing owner-private hosted Site.
