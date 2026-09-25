# Install and check optional companion tools

**Start here:** opening MEGALODON needs Python 3.11+ with SQLite and the
[local application](local-pc-setup.md), not every product in the catalog.
Scapy is optional. Docker Engine and Compose are prerequisites only for the
Greenbone container route below. Greenbone is a separate scanner, not a
MEGALODON telemetry adapter.

This walkthrough targets **Ubuntu 24.04** and a normal, non-root terminal.
Upstream instructions were consulted on **2026-09-22**; package versions and
image tags remain mutable. These are operator-run instructions, not evidence
that anything is installed or accepted on your computer. Do not run the whole
page as one script. Stop at an error and use the troubleshooting table.

In **Home → Data and tools**, open Scapy or Greenbone, then **Easy setup and
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
| Greenbone containers listed | Containers exist in the explicitly selected local Compose project | Inspect status, feed readiness and login separately |

The fixed [readiness report](tool-readiness.md) intentionally does not import
Scapy or inspect Python packages. Its Greenbone representative is the host's
`gvmd`; container installations normally require a different check. Docker
being installed does not mean Greenbone is installed. A missing `docker` group
does not, by itself, prove Docker Engine is absent.

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

## Docker and Compose: a Greenbone prerequisite, not a core dependency

### 1. Check the client and plugin

From any directory:

```bash
command -v docker && docker --version && docker compose version
```

Both versions must print. This checks the CLI and Compose plugin, not the daemon.
Do not substitute the older `docker-compose` command for the required plugin.

For this guide's **rootful Docker Engine** profile, check only the local socket:

```bash
env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock info --format '{{.ServerVersion}}'
```

An existing daemon version is not Greenbone health. Permission denied and a
stopped daemon are different from missing packages. Rootless Docker, Docker
Desktop and Podman may use other sockets; stop and follow their matching
installation guide instead of silently switching or replacing them.

### 2. Install only after reviewing host effects

Use the [official Docker Engine Ubuntu guide](https://docs.docker.com/engine/install/ubuntu/)
for its signed apt repository and the five packages:
`docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin` and
`docker-compose-plugin`. Installing only `curl` and `ca-certificates` does
**not** install Docker. Review conflicts with existing Docker/containerd
packages rather than automatically removing them.

**Separate host-change gate:** Docker installation can start a privileged daemon
and change host networking/firewall behavior. This is outside MEGALODON's
offline evaluation setup. Review existing firewall/virtualization managers;
use a dedicated evaluation VM when those effects are not approved on your
workstation. This guide does not disable a firewall or enable a Docker TCP API.

Repeat step 1 after installation. Do not create a group merely to make an
earlier `usermod` error disappear. The
[Docker post-install guide](https://docs.docker.com/engine/install/linux-postinstall/)
explains that membership in the `docker` group grants root-level privileges.
Adding yourself to that group is a separate security decision, not a prerequisite
for MEGALODON. Do not make the Docker socket world-writable. Where the operator
has explicitly approved privileged Docker access, prepend `sudo` to the `env`
command for that one operation; do not run MEGALODON as root.

## Greenbone: prepare, inspect, then explicitly start

This recipe assumes the reviewed **local rootful Docker Engine** above and the
official project name `greenbone-community-edition`. It does not target remote
Docker contexts or custom existing deployments. Existing installations need
their original project name, socket and files; do not create a second deployment
to make a status check pass.

The [official Greenbone Community Container guide](https://greenbone.github.io/docs/latest/22.4/container/)
is the source for the Compose file, resource requirements and startup procedure.
Check available space on **Docker's storage filesystem**, not just your home
directory. The upstream recommendation is 4 CPU cores, 8 GB RAM and 60 GB storage.

### 1. Download an unformatted Compose file

The example below refuses an existing destination rather than intentionally
overwriting your configuration. Inspect existing files separately. Use your
own trusted home directory; this is an interactive recipe, not a hardened
multi-user file installer.

```bash
mkdir -p "$HOME/greenbone-community-edition" &&
if test -e "$HOME/greenbone-community-edition/compose.yaml" || test -L "$HOME/greenbone-community-edition/compose.yaml"; then
  printf '%s\n' 'Compose file already exists. Inspect it before updating; nothing was downloaded.'
else
  curl --fail --location --proto '=https' --proto-redir '=https' \
    https://greenbone.github.io/docs/latest/_static/compose.yaml \
    --output "$HOME/greenbone-community-edition/compose.yaml"
fi
```

If a download fails, do not validate or start its partial file. Inspect it and
explicitly replace it through the upstream download procedure.
Do not paste YAML containing Markdown escapes such as `FEED\_RELEASE` or
formatted hyperlinks into a Compose file.

### 2. Review, then validate without starting containers

```bash
less "$HOME/greenbone-community-edition/compose.yaml"
```

Press `q` to leave `less`. Review image origins, mounts, network settings and
privileges before letting Compose read the file. Keep management port bindings
on `127.0.0.1`; the upstream scanner requests `NET_ADMIN`, `NET_RAW` and relaxed
seccomp/AppArmor confinement. This is not MEGALODON's unprivileged Stage 0
boundary and is not a production-security acceptance.

From any directory, for the reviewed file:

```bash
env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock compose --env-file /dev/null --project-name greenbone-community-edition --file "$HOME/greenbone-community-edition/compose.yaml" config --quiet
```

A silent zero exit means configuration validation passed, **not** that services
are installed, running or secure. The explicit file/project/socket avoids
accidentally inspecting a different working directory or remote Docker context.
It does not authenticate the file, Docker client, daemon or image contents.
The empty env-file avoids implicitly loading a project's `.env`; review any
custom environment substitutions separately.

### 3. Operator decision: download images, then start services

Only after the host effects and Compose file have been reviewed, run these
**separately**. The first downloads images; the second starts the multi-service
scanner stack. Neither is a verification command or a HUD action.

```bash
env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock compose --env-file /dev/null --project-name greenbone-community-edition --file "$HOME/greenbone-community-edition/compose.yaml" pull
```

```bash
env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock compose --env-file /dev/null --project-name greenbone-community-edition --file "$HOME/greenbone-community-edition/compose.yaml" up -d
```

Do not continue after a failed pull. An existing custom deployment needs its own
change/backup plan, not this fresh-install recipe.

### 4. Inspect the selected local project

```bash
env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock compose --env-file /dev/null --project-name greenbone-community-edition --file "$HOME/greenbone-community-edition/compose.yaml" ps --all
```

No rows do not prove the product is absent elsewhere. A successfully completed
initialization container may show exit code 0; a failed exit or unhealthy service
requires investigation. Container state alone does not prove feed readiness.

Open **https://127.0.0.1** in a browser on the same Linux machine, only after
confirming it is the intended local service. The vendor guide describes a
self-signed certificate and initial `admin` account with password `admin`.
Change that password immediately using the vendor procedure. Do not post
passwords, raw logs or scan results to the HUD, repository, chat or cloud.
Wait for feed loading to finish before any separately authorized scan of
systems you own or have permission to assess.

Stopping the project is also an explicit operator action. Follow the original
deployment's retention/backup procedure; do not use `down -v`, volume pruning
or data deletion as troubleshooting.

## Troubleshooting without guessing

| Symptom | Next check |
| --- | --- |
| `group 'docker' does not exist` | Check Docker CLI/Compose installation first; group membership is a separate root-level access decision |
| Docker socket permission denied | Review access to the intended local daemon; do not use `chmod 666` or switch to a remote context |
| `docker compose` unavailable | Install the Compose plugin for the existing Docker installation; do not replace a working engine blindly |
| `externally-managed-environment` | Use the selected virtual environment; do not bypass system Python protection |
| Scapy installed, HUD still says not checked | Expected for the PATH-only report; run the exact HUD Python package check and keep standalone/desktop environments separate |
| Greenbone not found in HUD | Host `gvmd` discovery does not inspect containers; use the explicit Compose project check |
| Port 443/9392 already in use | Identify the conflict; do not kill an unknown service or bind the management UI to all interfaces |
| Containers up, feed data missing | Wait for and inspect feed initialization through the official guide; do not report scan readiness yet |

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
