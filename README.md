<p align="center">
  <img src="assets/megalodon-github-hero-compact.png" alt="MEGALODON defensive network telemetry shark and shield emblem" width="760">
</p>

# MEGALODON Defense MVP

**MEGALODON** = **M**alware **E**limination **G**ateway **A**nd **L**ayered
**O**perations **D**efense **O**nline **N**etwork.

MEGALODON is a local-first defensive network telemetry MVP with a Python
metadata core and separately scoped tool integrations. It validates bounded
network metadata, applies three fixed detection heuristics, stores an SQLite
audit trail, and offers a read-only localhost dashboard projection. Live capture, offline
analysis, and firewall planning are separate choices, not mandatory parts of
every configuration. The evaluation-release candidate is plan-only and does
not support live firewall application.

Linux is the current implementation and CI reference, not a claim that every
workflow requires Ubuntu or every platform has equal support. Native Windows
core use is an unverified evaluation target; Linux-specific adapters remain
Linux-specific. Choose a workflow and then check its platform boundary below.

MEGALODON is not an autonomous antivirus, malware-attribution engine,
threat-intelligence service, packet-forensics suite, or authorization to change
a host. A detection or offline candidate is evidence for review, not proof of
malicious activity.

## Safety defaults

The [offline anomaly pipeline](docs/anomaly-pipeline.md) is available with
optional, explicitly enabled Qwen explanations. Its [result-integrity checks](docs/advisory-result-integrity.md)
reject non-normal completions and misleading text controls, while preserving
deterministic evidence on malformed AI results. Anomaly dashboard display,
installed-model acceptance and measured detection accuracy remain separate gates.

- observe only: a fresh configuration does not mutate the firewall;
- metadata only: packet payloads and payload-derived hashes are not represented;
- closed event extensions: `PacketEvent.metadata` is limited to reviewed adapter
  provenance and cannot carry arbitrary payload-like fields;
- local only: the dashboard defaults to `127.0.0.1:8787` and has no write API;
- isolated dashboard storage: on POSIX, reading telemetry requires an existing compatible private
  database opened with SQLite `mode=ro`, `query_only`, and a deny-by-default SQL
  authorizer; it cannot create or migrate the audit database;
- no egress: there are no threat-feed, cloud analytics, SIEM, or SOAR calls;
  bundled reference verification and synthetic evaluation perform no runtime
  download or update;
- no shell interpolation: untrusted event values never become shell code;
- finite response: block plans require validated global targets and an expiry;
- contained application: retained firewall `--apply` options explicitly refuse
  before configuration, host, executable, privilege, or process handling;
- allowlist first: loopback, private IPv4, and unique-local IPv6 are protected by
  default.

Read [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) for the threat assessment and
[`SPECIFICATION.md`](SPECIFICATION.md) for the implemented MVP contract and
production-readiness gaps.

The private [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site)
is a hosted reference surface with no network feed connected. It shows unavailable
telemetry until a separately reviewed real-data connection exists; it does not
substitute generated traffic or zeros for missing observations. Its deployable source and
alignment record are versioned under [`site/`](site/README.md); the repository
contracts remain authoritative.

## Documentation map

Use one document as the authority for each kind of decision. Issue and PR pages
record delivery state; they do not override the checked-in contracts.

| Need | Canonical document |
| --- | --- |
| Product boundary, commands, and first run | This README |
| Runtime behavior and acceptance boundary | [`SPECIFICATION.md`](SPECIFICATION.md) |
| Threat model and production controls | [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) |
| Red/blue/purple validation and future AI gates | [`docs/red-blue-security-guide.md`](docs/red-blue-security-guide.md) |
| Platform choices and installation evidence | [`docs/platform-baseline.md`](docs/platform-baseline.md) |
| Native Windows core acceptance matrix | [`docs/windows-core-acceptance.md`](docs/windows-core-acceptance.md) |
| Offline analyst operation and report semantics | [`docs/offline-analysis.md`](docs/offline-analysis.md) |
| Resource-informed advancement decisions | [`docs/resource-informed-advancement.md`](docs/resource-informed-advancement.md) |
| Static integration vocabulary | [`docs/integration-hub.md`](docs/integration-hub.md) |
| Offline reference data and synthetic detector evaluation | [`docs/reference-data.md`](docs/reference-data.md) |
| Hypothetical alert workload and base-rate assumptions | [`docs/alert-workload-lab.md`](docs/alert-workload-lab.md) |
| Automation design and Stage 0 schema | [`docs/automation-contract.md`](docs/automation-contract.md) and [`contracts/automation/v1`](contracts/automation/v1/README.md) |
| Local Qwen advisory boundary | [`megalodon/qwen_advisory.py`](megalodon/qwen_advisory.py), [`docs/local-model-advisory-contract.md`](docs/local-model-advisory-contract.md), and [`contracts/local-model-advisory/v1`](contracts/local-model-advisory/v1/README.md) |
| Future alert lifecycle and delivery boundary | [`docs/alert-lifecycle-contract.md`](docs/alert-lifecycle-contract.md) and [`contracts/alert-lifecycle/v1`](contracts/alert-lifecycle/v1/README.md) |
| Suricata record, reader, durable-consumer, and reconciliation gates | [`contracts/suricata-eve/v1`](contracts/suricata-eve/v1/README.md), [`reader`](contracts/suricata-eve/v1/reader/README.md), [`consumer`](contracts/suricata-eve/v1/consumer/README.md), and [`reconciliation`](contracts/suricata-eve/v1/reconciliation/README.md) |
| Detector and storage evidence receipts | [`docs/detector-acceptance.md`](docs/detector-acceptance.md) and [`docs/storage-failure-policy.md`](docs/storage-failure-policy.md) |
| Per-event ingestion atomicity and orphan recovery | [`docs/ingestion-integrity.md`](docs/ingestion-integrity.md) |
| Claim corrections and evidence scope | [`docs/evidence-alignment-review.md`](docs/evidence-alignment-review.md) |
| Static Defense Console source mirror | [`site/README.md`](site/README.md) and [`site/dist`](site/dist) |

## Choose a configuration

Start with the work you need, rather than installing every listed utility.
These are combinations of existing commands and documented evaluation targets,
not new named profiles, automatic installers, or a universal security suite.

| Workflow | Components and output | Availability and boundary |
| --- | --- | --- |
| Learn or develop with synthetic data | Core Python package; sample/JSONL metadata, fixed detections, SQLite; optional local UI | Implemented on Linux; native Windows core evaluation only. No capture tool, driver, firewall privilege, GPU, or cloud account required |
| Verify bundled reference data or exercise detector boundaries | Separate `megalodon-evaluate` command; pinned IANA context and deterministic synthetic corpus | Read-only, offline, in-memory evaluation. It does not use the service store, alter Stage 0 ingestion, or establish operational detection accuracy |
| Replay authorized metadata, without live capture | `run --source jsonl`; audit database; optional local UI | Existing Linux core path. Windows evaluation uses synthetic fixtures only until native acceptance; arbitrary sensor logs are not this input contract |
| Observe an explicitly selected interface | Core plus the optional Scapy `capture` extra | Linux capture path; separate capture authority and permission review. Not enabled by installation or sample replay |
| Analyze saved packet captures | Separate `megalodon.offline --source tshark`; private local reports | Linux-only adapter and fixed system TShark path; non-root isolated analyst environment. Windows desktop Wireshark use is separate, not adapter support |
| Analyze separately produced connection logs | Separate offline `zeek-json` or `zeek-tsv` adapter; flow reports | Linux-only importer; MEGALODON does not launch Zeek. Packet, flow, and alert counts are different units |
| Validate a completed Suricata contract-envelope file | `megalodon.offline.suricata.read_completed_file`; immutable alert batch and receipt | Main thread of a single-threaded Linux process, reusing the guarded `SIGALRM` deadline; one private file, no raw-EVE conversion, persistence, dashboard projection, sensor launch, or IPS |
| Persist one validated Suricata publication | `megalodon.offline.suricata_consumer.consume_publication`; explicit pre-created private store | One fixed-capacity local transaction with durable replay identity, terminal receipt, and exact commit readback. No migration, retention, watcher, CLI, dashboard projection, sensor launch, model call, network access, or response action |
| Reconcile one unknown Suricata consumer attempt | `megalodon.offline.suricata_consumer.reconcile_publication`; exact immutable publication and attempt ID | Explicit query-only readback returns only `committed`, `not_committed`, or `indeterminate`. It never retries, repairs, migrates, creates, deletes, projects, or acts |
| Inspect integration or response plans | Static `capabilities` / `hub-plan`, or the separate nftables planner | Catalog/hub output executes nothing. Firewall plans are Linux-backend plans and record local audit decisions; live application is unsupported in the evaluation-release candidate |

The core can run **headless**: `run` does not start `dashboard`. A local desktop
can use both commands, and the dashboard can be started later against the same
configured SQLite database. Offline reports remain a separate data path; only
one explicitly selected completed run can supply a startup-only UI summary.
Installing an upstream tool does not create a MEGALODON importer or orchestrator.

## Platform and environment choices

[`docs/platform-baseline.md`](docs/platform-baseline.md) remains the canonical
installation and configuration guide: feature matrix, software/license choices,
pinned recipes, storage permissions, and acceptance gates. This README is the
entry point, not a replacement platform contract.

| Environment | What can be considered | Evidence / support boundary |
| --- | --- | --- |
| Linux workstation or headless host | Core metadata workflows, optional capture, separate offline analysis, and plan-only nftables response | Current reference implementation. CI uses Ubuntu 24.04 / Python 3.11; L1 proposes Ubuntu 24.04 x86-64 / Python 3.12. Neither validates every installed tool or host; live firewall application is unsupported |
| Other Linux distributions or architectures | Evaluate the same bounded workflows where prerequisites and safety checks hold | Not certified by the Ubuntu CI lane. Validate Python, filesystem/privilege behavior, tool paths, and each selected integration; do not remove guards to make a recipe run |
| Native Windows 11 x64 | W1: Python 3.13 synthetic sample/JSONL, SQLite, and loopback UI evaluation; separately operated companion tools | **UNVERIFIED / evaluation only.** No native MEGALODON capture, offline adapter, or Windows firewall backend. Windows acceptance is tracked separately |
| A separately prepared Linux VM | Linux workflow inside the guest; W2 documents a Windows-host evaluation option | **PROPOSED configuration / guest validation required.** Not native host support, complete host-traffic visibility, or host-firewall authority; other host/guest pairings need their own evidence |
| WSL2 | Development evaluation under the documented W2 limits | Not the hostile-capture isolation baseline or proof of Windows-host monitoring/enforcement |
| macOS, BSD, and other native systems | Read the `other` catalog and identify future port/acceptance work | Core runtime and network adapters are **unsupported in the current catalog**; Python or upstream-tool availability alone does not establish support |
| Containers or unattended services | Possible future packaging/operations work | No supported deployment profile is established here. Container privilege, mounts, networking, lifecycle, and isolation need separate review; no service or scheduler is installed by these instructions |

The catalog distinguishes `implemented`, `optional`, `evaluation_only`,
`contract_only`, `manual_only`, `guest_only`, `proposed`, and `unsupported`.
Inspect alternative profiles from an already working runtime:

```text
python -m megalodon capabilities --platform linux
python -m megalodon capabilities --platform windows
python -m megalodon capabilities --platform other
python -m megalodon hub-plan --platform windows
```

`--platform` selects a **static description**, not a runtime backend, host probe,
portability test, or permission to execute a tool. The default follows the Python
runtime's platform family, so a Linux guest describes Linux, not its host.
See [`docs/integration-hub.md`](docs/integration-hub.md) for the closed workflow map.
For an explicit Linux executable-presence check, run
`python -m megalodon readiness`. Its bounded JSON report can be selected locally
in the Defense Console. It executes no companion tool and reports presence,
not installation integrity, compatibility, or running status. See
[`docs/tool-readiness.md`](docs/tool-readiness.md) for exact bounds and limitations.
The baseline excludes Npcap from its open-source dependencies and omits native
Windows live capture; manual saved-capture analysis is a different workflow.

## Implemented capabilities

| Area | Capability in this revision |
| --- | --- |
| Inputs | Built-in sample metadata, bounded JSONL replay, and optional Linux interface-specific Scapy capture |
| Detection | Fixed `SYN_FLOOD`, `PORT_SCAN`, and `DNS_TUNNELING` metadata heuristics with bounded per-source state and cooldowns |
| Audit | SQLite events, detections, and action decisions using parameterized WAL writes; each accepted event decision and its run counters commit atomically |
| Dashboard | Read-only loopback UI pinned to one viewport with persistent **Live review**, **Analysis**, and **Tools & consoles** workspace tabs. The internally scrolling workspaces separate stored telemetry/triage, Reference Library/offline context, and 14 static application-interface slots. No vendor console is embedded. **Deep analysis & context** may display one startup-supplied, immutable Qwen advisory receipt through a bounded same-origin GET; the dashboard cannot request analysis, poll the provider, load a receipt from disk, or perform host/network action |
| Firewall boundary | Plan-only isolated `inet megalodon` nftables proposals; retained `--apply` options refuse before configuration or host/process interaction |
| Offline analysis | Separate, Linux-only non-root TShark PCAP/PCAPNG replay and Zeek JSON/TSV `conn.log` import with private redacted reports |
| Capability catalog | Static, read-only Linux/Windows/other status for 14 selected free/open-source tools and planned interface slots; performs no host probe or installation |
| Local posture receipt | Bounded package-level profile and reference-data status; no host probe, database, capture, listener, or host mutation |
| Integration hub | Closed, machine-readable workflow plans for every selected utility; plan-only and non-executing |
| Suricata completed-file reader | Single-threaded Linux main-thread Python API for one private closed-envelope file; immutable normalized batch and terminal receipt, with no raw-EVE conversion, persistence, dashboard, or sensor operation |
| Suricata durable evidence | Closed transaction/replay/receipt and reconciliation contracts; strict immutable-publication validation; fixed 512 MiB capacity policy with no freelist credit; explicit create-only exact-schema store; atomic run/alert/receipt commit; exact commit readback; and explicit read-only unknown-commit classification. No existing-store migration, reconciliation command, automatic consumer startup, watcher, or retention; the read-only view below is separate |
| Suricata evidence view | Explicit `dashboard --suricata-db /absolute/private/store.sqlite3` loads a separate bounded read-only startup snapshot. Shows source-qualified recent runs and external alerts; unavailable stays distinct from empty. No polling of this store, consumer invocation, sensor health inference, or response control. See [projection contract](docs/suricata-evidence-projection.md) |
| Automation design | Stage 0 normative-draft JSON Schema, accepted/rejected fixtures, and deterministic schema tests; no scheduler or executor |
| Local Qwen advisory | The original run-count policy is a manual Python API. A separately versioned [offline anomaly command](docs/anomaly-triage.md) can explicitly request one bounded Qwen explanation at `127.0.0.1:11434/api/generate`; no scheduler, discovery, pull/start, retry, redirect, tool use, detector authority, or response authority |
| Anomaly evidence | [One-shot baseline triage](docs/anomaly-pipeline.md) reports supported new ports and distribution shifts, abstaining on stale, incomplete or incompatible windows. Qwen is off by default; evidence survives model denial/failure. Descriptive, uncalibrated candidates only |
| Alert lifecycle contract | Draft projection, transition, outbox-intent, and receipt shapes with deterministic fixtures; no alert mutation, notifier, delivery adapter, or credential path |
| Reference and evaluation | Manifest-pinned, privacy-minimized IANA service/port and protocol context plus a bounded synthetic detector corpus; separate read-only CLI with no network, store, persistence, action, or subprocess path |
| CI | Ubuntu 24.04 / Python 3.11 install, dependency check, compilation, pytest, and non-mutating CLI smokes, plus Python 3.12 sdist/wheel builds, an extracted-sdist full test, and installed-package smokes, on pushes to `main` and pull requests |

## Requirements and programs used

| Requirement | Purpose | Status |
| --- | --- | --- |
| Python 3.11 or newer | CLI, validation, detectors, SQLite store, dashboard, and offline adapters | Package minimum, not proof of every Python/OS combination |
| Python `venv` and `pip` | Isolated editable installation | Recommended |
| SQLite (`sqlite3`) | Local audit database | Included in the Python standard library; the dashboard refuses SQLite older than 3.22.0 because read-only WAL support is required |
| Scapy `>=2.5,<3` | Optional Linux live metadata capture | Install with the `capture` extra only for that workflow |
| Qwen through a local Ollama provider | Optional manual advisory explanation only | Operator-installed and separately run; the adapter and one-shot anomaly command never configure a service, background monitor, remote endpoint, tool-use mode, or automatic response |
| TShark at `/usr/bin/tshark` | Optional Linux offline `.pcap`/`.pcapng` adapter | Reviewed system package; not a Python dependency or a portable executable-path setting |
| Zeek | Producing optional `conn.log` input | Not invoked or required by MEGALODON; the producer version is operator-declared |
| Suricata | Optional external producer for the closed alert envelope | The Linux file reader and durable consumer never invoke or require the Suricata binary; they accept only the separately prepared contract envelope/publication |
| ClamAV | Separate manual file scanning | Optional companion; no MEGALODON file intake, quarantine, or result importer |
| osquery | Future endpoint-metadata evaluation | Proposed only; no query pack, scheduler, remote enrollment, or importer |
| nftables | Review of Linux firewall table/block plans | Optional; not invoked by the evaluation-release candidate, and no firewall privilege is needed for plan mode |
| pytest `>=8,<10` and jsonschema `>=4.23,<5` | Repository tests and automation-contract validation | Install with the `test` extra |

The core Python package currently has no third-party runtime dependency. Git is
needed for a source checkout; no analyzer, antivirus, capture driver, or firewall
package is required for the synthetic core demonstration. The list above is a
menu of roles, not an install-all bundle. Install only the extras needed for the
selected, reviewed workflow, using that environment's Python:

```bash
python -m pip install -e .                 # core MVP
python -m pip install -e ".[test]"        # development and validation
python -m pip install -e ".[capture]"     # optional Scapy capture
python -m pip install -e ".[capture,test]" # both optional groups
```


## Ubuntu 24.04 companion-tool setup

This is an **operator-managed installation guide**, not a MEGALODON installer.
Install only what an approved workflow requires. The commands below do not
start a capture, scanner, IDS/IPS sensor, service, scheduler, firewall rule,
remote listener, rule download, or telemetry upload. They do not change
MEGALODON's capability status.

| Tool | MEGALODON relationship after installation | Do not configure or start for MEGALODON |
| --- | --- | --- |
| SQLite and Python | Core local store and runtime | Nothing beyond private local storage |
| Scapy | Optional Linux live-metadata capture extra | Packet crafting/injection or unattended capture |
| TShark | Implemented Linux-only offline packet adapter at /usr/bin/tshark | Live-capture permission or a public capture directory |
| Zeek | Implemented offline importer for the closed conn.log profile | A service, cluster, or automatic producer |
| Suricata | Implemented Linux reader plus explicit transaction into one pre-created private durable store; no raw-EVE converter | Rule updates, sensor mode, IPS mode, watcher, or its service |
| ClamAV | Manual companion only; no file/result/quarantine integration | A daemon, automatic update, quarantine, or deletion |
| osquery | Proposed endpoint-inventory work; no importer | A daemon, schedule, query pack, or remote enrollment |
| nftables | Plan-only review vocabulary; retained live application is refused | Ruleset loading, a service, or host-firewall changes |

The static catalog remains the source of truth. From the activated project
environment, inspect it without probing or launching any companion tool:

~~~bash
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
~~~

### 1. Install the base packages without starting services

Run this on **Ubuntu 24.04** in an ordinary terminal. It is deliberately
failure-checked and stops if the machine already has a package-install policy
guard. The temporary guard prevents package post-install scripts from starting
a service while software is being installed; it is removed even when the
command fails.

~~~bash
(
  set -euo pipefail

  guard=/usr/sbin/policy-rc.d
  if sudo test -e "$guard"; then
    echo "An existing package service-start guard is present at $guard; review it and stop."
    exit 1
  fi

  cleanup() { sudo rm -f "$guard"; }
  trap cleanup EXIT HUP INT TERM

  printf '%s\n' '#!/bin/sh' 'exit 101' | sudo tee "$guard" >/dev/null
  sudo chmod 0755 "$guard"

  printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean false' |
    sudo debconf-set-selections

  sudo apt-get update
  sudo apt-get install -y --no-install-recommends \
    ca-certificates curl gpg git \
    python3 python3-venv python3-pip \
    sqlite3 tshark nftables \
    cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev \
    python3-dev swig zlib1g-dev software-properties-common

  sqlite3 --version
  /usr/bin/tshark --version | sed -n '1p'
  nft --version
)
~~~

Keep the TShark capture-permission answer at **No**. MEGALODON's offline
adapter does not need live-capture permission, and installation should not
grant it. ClamAV is a separate manual companion, not a prerequisite for this
guide. Do not install it from this recipe: Ubuntu packaging can add its
signature-update service, which exceeds MEGALODON's no-service/no-egress
boundary.

### 2. External producer packages remain operator-managed

Suricata and osquery remain **unmanaged** companion tools. This repository
does not approve adding third-party APT repositories, signing keys, package
sources, services, rule updaters, schedules, or configuration files for either
tool. Their packages can create service units and other host state even when a
service is not started.

If a separate, approved evaluation needs one of these tools, use that tool's
current vendor documentation and a host-specific package/repository review.
Record the exact repository, signing-key fingerprint, package version, service
state, and removal/rollback plan outside MEGALODON. Do not infer runtime
support from an installed binary: MEGALODON has a completed contract-envelope
file reader, an explicit create-only durable-store schema initializer, and an
operator-invoked transaction for one immutable publication. It still has no
sensor integration, raw-EVE conversion, watcher, scheduler, or IPS path;
osquery remains proposed with no MEGALODON reader, importer, scheduler, or enrollment.

### 3. Build Zeek as a private, non-service producer

Ubuntu 24.04's standard package sources may not provide a usable Zeek executable.
Build the reviewed release as the current user under the local prefix shown
below; do not use a system prefix, create a service, or initialize ZeekControl.
The Zeek project documents the prerequisites and supported source-build flow.

Before setting the version below, obtain the corresponding release source and
checksum/signature from the [official Zeek downloads page](https://zeek.org/get-zeek/).
Record the exact version and verification result with the case evidence.

~~~bash
(
  set -euo pipefail
  umask 077

  ZEEK_VERSION=8.0.10
  # Set this to the exact SHA-256 published for the selected release by Zeek.
  # Leave it empty to fail closed; never copy an unverified value from a mirror.
  ZEEK_SHA256=''
  source_root="$HOME/src/zeek-build"
  prefix="$HOME/.local/zeek-$ZEEK_VERSION"
  archive="$source_root/zeek-$ZEEK_VERSION.tar.gz"
  source_dir="$source_root/zeek-$ZEEK_VERSION"

  [ ! -e "$prefix" ] && [ ! -L "$prefix" ] ||
    { echo "Zeek prefix already exists; do not overwrite it."; exit 1; }
  [ ! -e "$source_dir" ] && [ ! -L "$source_dir" ] ||
    { echo "Zeek source directory already exists; do not overwrite it."; exit 1; }

  case "$ZEEK_SHA256" in
    [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*) ;;
    *) echo "Set ZEEK_SHA256 to the reviewed 64-character release digest; stop."; exit 1 ;;
  esac
  [ "$(printf %s "$ZEEK_SHA256" | wc -c)" -eq 64 ] ||
    { echo "ZEEK_SHA256 must contain exactly 64 hexadecimal characters; stop."; exit 1; }
  [ ! -e "$archive" ] && [ ! -L "$archive" ] ||
    { echo "Zeek archive already exists; verify or remove it deliberately."; exit 1; }

  install -d -m 700 "$source_root"
  curl -fL --proto '=https' --tlsv1.2 \
    -o "$archive" "https://download.zeek.org/zeek-$ZEEK_VERSION.tar.gz"
  printf '%s  %s\n' "$ZEEK_SHA256" "$archive" | sha256sum -c -
  tar -xzf "$archive" -C "$source_root"
  cd "$source_dir"
  ./configure --prefix="$prefix"
  make -j"$(nproc)"
  make install

  "$prefix/bin/zeek" --version
)
~~~

For the current shell only, expose the private Zeek build with:

~~~bash
export PATH="$HOME/.local/zeek-8.0.10/bin:$PATH"
zeek --version
~~~

Persist a PATH change only after verifying the version and prefix. MEGALODON
never launches Zeek: it imports a separately produced, closed-profile conn.log
in offline analysis. Preserve original producer output; an unsupported record
must be treated as an input-contract problem, not silently altered in place.
See [Zeek's source-build documentation](https://docs.zeek.org/en/v8.0.8/building-from-source.html).

### 4. Install and configure the MEGALODON Python environment

Create the virtual environment inside an already reviewed checkout. This
creates a private configuration copy with a database outside a project,
synced, or shared directory. It leaves every integration disabled by default.

~~~bash
(
  set -euo pipefail
  umask 077
  cd "$HOME/Projects/MEGALODON"

  [ "$(id -u)" -ne 0 ] || { echo "Use a non-root account."; exit 1; }
  [ ! -e .venv312 ] && [ ! -L .venv312 ] ||
    { echo ".venv312 already exists; reuse it or choose a new name."; exit 1; }

  python3 -m venv .venv312
  .venv312/bin/python -m pip install --upgrade pip
  .venv312/bin/python -m pip install -e '.[capture,test]'
  .venv312/bin/python -m pip check

  install -d -m 700 "$HOME/.config/megalodon" "$HOME/.local/share/megalodon"
  config="$HOME/.config/megalodon/local-settings.toml"
  [ ! -e "$config" ] && [ ! -L "$config" ] ||
    { echo "Local settings already exist; do not overwrite them."; exit 1; }
  install -m 600 /dev/null "$config"

  .venv312/bin/python - "$config" <<'PY'
from pathlib import Path
import sys

source = Path("config/settings.toml").read_text(encoding="utf-8")
old = 'db_path = "data/megalodon.db"'
new = f'db_path = "{Path.home()}/.local/share/megalodon/megalodon.db"'
if source.count(old) != 1:
    raise SystemExit("Expected default db_path not found exactly once; stop.")
Path(sys.argv[1]).write_text(source.replace(old, new), encoding="utf-8")
PY
  chmod 600 "$config"

  .venv312/bin/python -m pytest -q
  .venv312/bin/python -m megalodon capabilities --platform linux
  .venv312/bin/python -m megalodon hub-plan --platform linux
  .venv312/bin/python -m megalodon run \
    --config "$config" --source sample --max-events 13
)
~~~

If .venv312 already exists, do not recreate it. Refresh only the package and
run the same safe checks:

~~~bash
cd "$HOME/Projects/MEGALODON"
.venv312/bin/python -m pip install -e '.[capture,test]'
.venv312/bin/python -m pip check
.venv312/bin/python -m pytest -q
~~~

### 5. Bounded adapter verification

The checks below verify only the two implemented offline integrations. They
operate on already authorized, locally stored evidence and do not initiate
capture or start an upstream program:

~~~bash
cd "$HOME/Projects/MEGALODON"
MEGALODON_TEST_TSHARK=1 \
  .venv312/bin/python -m pytest -q tests/test_offline.py -k system_tshark_headers_only

export PATH="$HOME/.local/zeek-8.0.10/bin:$PATH"
zeek --version
.venv312/bin/python -m megalodon.offline --help
~~~

For an explicit offline run, follow
[docs/offline-analysis.md](docs/offline-analysis.md) and use a fresh, private
output directory. The adapter intentionally fails closed on missing, oversized,
malformed, or out-of-profile inputs. It is not a live-capture, packet-decoding,
or arbitrary-log ingestion tool.

### 6. Start the local dashboard only when needed

After a successful local run, this starts a foreground, loopback-only
dashboard. It does not expose a network service beyond the local machine; stop
it with Ctrl+C.

~~~bash
cd "$HOME/Projects/MEGALODON"
.venv312/bin/python -m megalodon dashboard \
  --config "$HOME/.config/megalodon/local-settings.toml" \
  --host 127.0.0.1 --port 8787
~~~

Open <http://127.0.0.1:8787/> locally. Do not use remote-listening options,
port forwarding, a reverse proxy, or a tunnel. Re-run the static catalog after
any tool update; successful installation does not expand the supported
integration boundary.


## Installation and first run

For a **new checkout**, use the pinned, failure-checked
[Linux recipe](docs/platform-baseline.md#4-l1-linux-installation-and-validation)
or [Windows evaluation recipe](docs/platform-baseline.md#5-w1-windows-installation-and-evaluation).
Check the recipe's recorded revision before use; it is not a floating-current-main
installation claim. Do not overwrite an existing checkout or virtual environment.

The following are shorter **synthetic core** examples from the root of an
already reviewed checkout, with a suitable Python installed and no existing
`.venv`. Record `git rev-parse HEAD`. Run as an ordinary user in private local
storage, not as root/Administrator or in a cloud-synced/shared folder. Follow the
baseline's POSIX permission or Windows NTFS ACL checks first.

### Linux reference — Bash

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
  .venv/bin/python -m megalodon dashboard --host 127.0.0.1 --port 8787
)
```

### Native Windows evaluation — PowerShell

**UNVERIFIED W1 recipe, synthetic data only.** Use the baseline's standard
CPython 3.13 and `py` launcher. Stop on failure; do not change execution policy,
install a capture driver, disable protection, or elevate to make it work.

```powershell
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '.venv') { throw '.venv already exists; stop.' }
py -3.13 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
& .\.venv\Scripts\python.exe -m pip install -e .
if ($LASTEXITCODE -ne 0) { throw 'Package installation failed.' }
& .\.venv\Scripts\python.exe -m megalodon run --source sample --max-events 13
if ($LASTEXITCODE -ne 0) { throw 'Synthetic sample failed.' }
& .\.venv\Scripts\python.exe -m megalodon run --source sample --demo-threat --max-events 114
if ($LASTEXITCODE -ne 0) { throw 'Synthetic detection sample failed.' }
& .\.venv\Scripts\python.exe -m megalodon dashboard --host 127.0.0.1 --port 8787
if ($LASTEXITCODE -ne 0) { throw 'Dashboard failed.' }
```

Skip the final dashboard command for headless use. When started, it remains in
the foreground; stop it with Ctrl+C. In later generic examples, `python` means
the selected virtual environment's interpreter: `.venv/bin/python` on Linux or
`& .\.venv\Scripts\python.exe` in Windows PowerShell. A virtual environment can
be used without activation; see the [Python venv documentation](https://docs.python.org/3/library/venv.html).
Bash pipelines and Linux-only adapter/firewall examples are not Windows recipes.

### Start the HUD with one command

From the environment where this MEGALODON revision is installed:

```bash
python -m megalodon hud
```

Open **http://127.0.0.1:8787** on the same computer. No account, subscription,
configuration file, companion installation, or readiness-report export is needed
to open the workspace. Existing default audit data is read automatically. If
that store does not exist, the HUD opens with **unavailable** measurements and
working tool controls and reference lookup; it creates no database or demo data.
Real network evidence still requires a separately operated supported input.

**Tools & consoles** shows one startup executable-presence snapshot, official
setup links, optional saved companion-console addresses, and the same reviewed
copy-only maintenance controls as the hosted Site. Console links open the real
companion app in another tab; they do not connect its data or grant MEGALODON
control. Commands remain visible for review and execution in your terminal.
Qwen invocation, sensor startup, package changes and firewall application are
not HUD actions.

The optional **Choose existing data for the next launch** form prepares a quoted
command for a settings file, completed offline run, or Suricata store. It never
opens a path or launches the command. Stop with **Ctrl+C**, then restart when you
change inputs or want a new presence snapshot. The original `dashboard` command
keeps its strict existing-store requirement and performs no presence check.
See [HUD operation](docs/dashboard-operations.md) for details.

### Local dashboard and storage

Open <http://127.0.0.1:8787/> after starting the dashboard. The first sample run
is benign. `--demo-threat` adds synthetic SYN-flood and long-DNS-query metadata
so detections appear in the audit store and UI; it is not a diagnosis of the
host network.

The default database is `data/megalodon.db`. Repeated runs append to the same
database until the operator deliberately uses another configuration/database,
reaches the configured storage high-water stop (256 MiB by default), or an
operator applies a reviewed retention procedure. The store marks its current layout with
SQLite `user_version = 3`. New databases include a versioned ingestion-run
ledger and detection/action links. On POSIX, the writer creates a missing leaf directory with mode `0700`
and database with mode `0600`; it refuses symlinked ancestors, hard-linked or
foreign-owned databases, and an immediate database directory with group/other
access. Every ancestor must be owned by root or the runtime user and must not be
group/world-writable unless it is a trusted sticky directory. Both writer and
reader require a stable `/proc/self/fd` or `/dev/fd` SQLite path on POSIX so the
opened inode cannot drift from SQLite's journal path. Existing exact v1,
unversioned-v1, or v2 databases require the explicit
`database-migrate` command; ordinary startup does not migrate them. The command
first creates and verifies a sibling backup ending in `.pre-v3.bak`, never
overwrites an existing backup, and then applies the schema migration in one
transaction. Its JSON receipt reports only `backup: created`, not the configured
filesystem path. The backup is created mode `0600` on POSIX; Windows confidentiality
still depends on the private-directory/NTFS ACL acceptance tracked separately.
POSIX migration also requires an operator-owned mode-`0700` parent and mode-`0600`
regular, single-link database, and keeps no-follow source/backup descriptors bound
through backup verification. Stop other MEGALODON processes before migrating and
retain the backup until the new database has been operationally verified.
Partial, altered, extended, or newer application schemas are refused rather than
repaired or downgraded.

The dashboard command refuses a disabled configuration before reading an offline
projection or opening storage. When enabled, it requires that database to exist
with the exact current schema and private path boundary. A no-sidecar immutable
schema preflight prevents failed compatibility checks from creating SQLite
coordination files. An unserved normal connection then establishes and validates
any required private WAL coordination before the final `mode=ro` connection can
serve committed WAL rows. On supported POSIX hosts, the opened descriptor pins
the database inode while SQLite's own `database_list` must resolve it to the
configured private path. The parent directory's entry generation must remain
stable from final open through every served read; replacement or sidecar-entry
changes force a fixed refusal and a generic HTTP `503` rather than a path-bearing
traceback. `PRAGMA query_only=ON` and a closed SQL authorizer block writes, DDL,
`ATTACH`, internal row-ID reads, and private-column reads. Summary counts come from
one SQLite statement, and recent detections select and order only by public data:
`detected_at`, `rule_id`, `severity`, `src_ip`, and `message`. Compatible WAL
reads may create or update private `-wal`/`-shm` coordination files inside the
verified mode-`0700` directory; they do not change the main database, schema,
`user_version`, or journal mode. Native Windows ACL enforcement remains unproved; closed issue #27 delivered
the acceptance handoff, not native execution evidence.

For an existing POSIX installation, stop every MEGALODON process before the
first post-upgrade open. Inspect the literal configured directory, database, and
any `-wal`/`-shm` files: each must be owned by the runtime user, must not be a
symlink or non-regular file, and the database/sidecars must have exactly one hard
link. Only after those checks, a conventional `data/megalodon.db` installation
can be normalized with `chmod 700 -- data` and
`chmod 600 -- data/megalodon.db`. Do not apply those commands to an unverified,
shared, linked, or redirected path; preserve unexpected sidecars for recovery
review or copy the stopped database to a newly created private location. Writer
startup normalizes an already owner-controlled database and sidecars to mode
`0600`, but deliberately refuses to change an existing public parent directory.
Use a dedicated private database directory: while a dashboard reader is serving,
any directory-entry addition, removal, or rename requires a reader restart.
The [`storage-failure-policy`](docs/storage-failure-policy.md) keeps SQLite audit
and standalone offline-report retention separate and defines fail-closed
outcomes. Its internal Python API previews and applies at most one finite,
identity-bound SQLite batch at a time, refuses stale previews or active/ambiguous
ingestion runs, and emits path-free receipts. It selects no cutoff or deletion
value and exposes no CLI, scheduler, or automatic job.

Each `run` command writes a closed lifecycle receipt before consuming input.
Natural exhaustion records `completed/source_exhausted`; an operator event limit
records `incomplete/event_limit_reached`; handled interruption and bounded
failures have distinct reasons. Every accepted event, all detections, one
non-executing action decision per detection, their links, and the event/detection/
action counters commit in one transaction. Detector windows and cooldowns advance
only after that transaction succeeds. Raw exceptions, input paths, command lines,
packet contents, and credentials are not stored in the run ledger or echoed by
the run failure diagnostic. A row left `running` means completion is unknown and
blocks another run until explicit, target-pinned reconciliation. See
[`docs/ingestion-integrity.md`](docs/ingestion-integrity.md) for the exact state,
migration, ambiguous-commit, and recovery boundaries.

On the Linux analysis profile, add one completed offline run to the read-only
dashboard by selecting its absolute private report directory when the server starts:

```bash
python -m megalodon dashboard \
  --offline-run "$HOME/Analysis/case001/run001"
```

The dashboard loads and validates the summary inputs once; it does not browse
directories, watch files, read or serve record rows, launch an analyzer, expose
candidate evidence details, or add a control endpoint. All dashboard binds are
loopback-only; the legacy `--allow-remote` flag now refuses startup. Restart
the dashboard to select another run.

Every dashboard `GET` request also requires one `Host` header that names the
exact numeric loopback listener, optionally with its actual port. `localhost` is
accepted only for a `127.0.0.1` listener. Missing, duplicate, foreign,
non-canonical, and wrong-port values are rejected before routing or audit-store
reads, limiting DNS-rebinding exposure. This check does not turn a proxy,
tunnel, or port forward into a supported remote-access path.

The recent-detection triage view operates only on the bounded array returned by
`/api/events`. It combines local search, grouped or exact severity, a dynamically
derived exact-rule filter, and at most 12 chronological timestamp bins. Invalid
timestamps remain visible in an otherwise unfiltered table but are excluded
from the timeline with an explicit count. Returned-row, high/critical-row, and
distinct-rule chips describe that array only; they are not full-history rates.
Filters exist only in browser memory and do not alter SQLite, write files, or
add an export path. Polling is suspended while the page is hidden, requests time
out after five seconds, and an in-flight refresh is never overlapped. The safe
built-in defaults can be replaced by an explicit `--config` file or overridden
for one launch:

```bash
python -m megalodon dashboard --refresh-seconds 12 --event-limit 125
```

`refresh_seconds` accepts 2–300 and `event_limit` accepts 1–200. The dashboard
serves its CSS and JavaScript from same-origin, no-store asset endpoints so its
content-security policy does not require inline-script or inline-style access.
The recent-events API projects only detection time, rule ID, severity, source IP,
and message. Destination IP, evidence, recommendation, and suppression details
remain in the local audit store and are not served to the browser.

The Deep analysis workspace also reads at most eight newest ingestion-run
receipts from `/api/ingestion-runs`. Each item preserves the recorded source,
status, counts, receipt version, terminal reason, failure code, and start/finish
times without reading event rows or inventing missing values. This view is a
bounded receipt inspector, not evidence that a sensor is live, the source was
complete beyond its receipt, or protection is active.

The dashboard also exposes a manual **Reference Library** panel backed by the
installed, manifest-verified IANA snapshot. It accepts one normalized transport
plus decimal port or one decimal IP protocol number, returns at most eight
registration rows, and shows bundle/source provenance and an interpretation
warning. The panel is deliberately separate from detection evidence: a
registration is not proof of an observed service, safety, malicious intent, or
an alert. `/api/reference/status`, `/api/reference/port`, and
`/api/reference/protocol` are GET-only, loopback-bound, no-store reads; they
have no update, database, notifier, subprocess, firewall, or external-network
path. Invalid, repeated, unknown, non-canonical, or out-of-range query fields
fail closed, while a later failed lookup marks any preserved result stale.

After each successful summary fetch, the page compares the stored
`high_or_critical` count with the preceding successful value. It reports an
initial baseline or a sequential increase/decrease only. This is not unique-new
alert detection, deduplication, acknowledgement, assignment, resolution,
incident state, or evidence that capture/ingestion is healthy. Summary and event
rows come from separate HTTP reads and are never presented as one coherent
snapshot. A partial or malformed refresh preserves the prior rows, filters,
last-success timestamp, and count baseline while marking the display stale.

## Commands

| Command | Effect |
| --- | --- |
| `capabilities [--platform linux\|windows\|other]` | Print a static support/free-software catalog without probing or changing the host |
| `hub-plan [--platform ...] [--workflow ...]` | Print a closed integration workflow plan; never probes, installs, launches, networks, or mutates |
| `run --source sample [--demo-threat] [--max-seconds N]` | Process built-in synthetic metadata; optionally apply the Linux source-lifetime deadline |
| `run --source jsonl --max-events N [--max-seconds N] [--input FILE]` | Replay validated JSONL from a file or stdin under an explicit finite accepted-event ceiling and optional Linux source-lifetime deadline |
| `run --source scapy --interface IFACE --max-events N` | Perform optional Linux live metadata capture under an explicit finite accepted-event ceiling; the threaded adapter refuses `--max-seconds` |
| `database-migrate [--config PATH]` | Explicitly back up and migrate an exact v1 or v2 audit database to v3; never overwrites its backup |
| `database-reconciliation-status [--config PATH]` | Read bounded metadata for `running` or reconciliation-required run receipts; does not mutate them |
| `database-reconcile RUN_ID --started-at UTC [--config PATH]` | After stopping ingestion, mark one exactly pinned running receipt as reconciliation-required while preserving evidence |
| `dashboard` | Serve the loopback dashboard from an existing compatible database through the separate read-only projection |
| `firewall-plan IP` | Validate a target and print a non-mutating, time-limited block plan |
| `firewall-install` | Print the isolated nftables table plan; the retained `--apply` option explicitly refuses and executes nothing |
| `block IP --reason TEXT` | Print one block plan; the retained `--apply` option explicitly refuses and executes nothing |
| `python -m megalodon.offline ...` | Run the separate Linux-only private offline-analysis workflow |
| `megalodon-evaluate reference verify` | Validate every declared bundled IANA shard, count, digest, and record before reporting the snapshot summary |
| `megalodon-evaluate reference port TRANSPORT PORT` | Return bounded registration context for one validated service/port key |
| `megalodon-evaluate reference protocol NUMBER` | Return bounded registration context for one validated IP protocol number |
| `megalodon-evaluate corpus [--scenario ID]` | Validate the complete bundled synthetic corpus and run the fixed detector in memory, optionally reporting one scenario |
| `megalodon-evaluate base-rate --population N --unit UNIT --prevalence-ppm P --sensitivity-ppm S --false-positive-ppm F` | Project hypothetical true/false alert counts and exact PPV from explicit assumptions; no telemetry, model request or measured-accuracy claim |

The operational main CLI subcommands accept optional `--config PATH`; omitting
it uses the complete safe built-in settings and works from an installed wheel.
The static
`capabilities` and `hub-plan` commands do not read configuration.
`run --max-events N` provides an accepted-event stop limit from 1 through 10,000,000.
It is required for JSONL/stdin and Scapy sources; the repository-owned sample
generator is finite and may omit it. Zero and missing limits on non-sample
sources fail before the audit store or source is opened. Use `python -m megalodon --help` and
`python -m megalodon.offline --help` for the complete operational argument
surface, and `megalodon-evaluate --help` for the separate evaluation surface.

On supported Linux runtimes, `run --max-seconds N` adds an optional one-shot deadline from
1 through 86,400 seconds around event-source acquisition, iteration, event
processing, and source cleanup. Expiry fails closed with the existing
`CAPTURE_ERROR` class after cleanup is attempted and preserves the committed
prefix in a `failed/failed` receipt. Supplying the option on a runtime without
`SIGALRM`, `ITIMER_REAL`, `pthread_sigmask`, `sigpending`, and `/proc/self/task`
inspection is refused before configuration, storage, or source work. A blocked
or pre-existing pending `SIGALRM`, or a process with more than one OS thread, is refused at the same boundary because the
timer and handler are process-wide while signal masks are thread-local; both are
checked again inside the signal-protected setup boundary before handler or timer
installation. A pending alarm is checked again after arming and delivered under
the deadline handler as `CAPTURE_ERROR` if the new deadline already expired.
An interruption while entering the setup mask restores the observed pre-call
mask; an interrupted protected pending-signal inspection restores that mask;
interrupted handler installation is conservatively restored; and an
interrupted timer-arm call is conservatively cancelled during teardown. An
interrupted competing-timer restoration is read back: a confirmed restored
timer is preserved, while an incomplete swap cancels the MEGALODON timer and
restores the displaced timer before the prior handler returns.
An already active process interval timer also causes a pre-I/O refusal; the
timer value returned while arming is checked so a concurrent timer is restored
and refused rather than discarded; `SIGALRM` is blocked across that handler and
timer swap. Teardown blocks `SIGALRM` before cancellation and keeps the deadline
handler installed until the original mask is restored, so a just-pending alarm
cannot reach the prior handler. A deadline dispatched while cleanup masking begins
is preserved, teardown completes, and the interruption is then re-raised.
An interruption dispatched as setup unmasking returns is recorded so teardown
reblocks before cancellation. An interruption during post-cancel timer
inspection is also preserved until the remaining mask and handler decisions
complete.
Cancellation restores that handler only after
cancellation succeeds or timer inactivity is confirmed; a failed disarm with a
still-live or uninspectable timer retains the deadline handler. Threaded Scapy capture refuses
the option because a worker created after setup cannot inherit the proven
single-thread boundary. The option does not
claim a Windows deadline, interrupt kernel-level
uninterruptible sleep, or bound configuration, store setup, final receipt, or
summary work outside the source-ownership region.

The bundled reference snapshot contains 12,577 normalized IANA service/port
records and 152 protocol-number records in deterministic data shards no larger
than 76 KiB. Registrations are analyst context hints: they do not establish the
service observed on a port, endorsement, safety, malicious intent, or a detector
verdict. The separate corpus contains 6,492 metadata-only events across 12
scenarios, uses only RFC 5737 IPv4 and RFC 3849 IPv6 documentation addresses,
and is labeled `synthetic-only` and `uncalibrated`. Manifests, the complete
declared shard set, counts, digests, and records are validated before lookup or
detector execution. See [`docs/reference-data.md`](docs/reference-data.md).

## Event input

JSONL replay accepts one JSON object per line:

```json
{"observed_at":"2026-09-06T15:00:00Z","src_ip":"8.8.8.8","dst_ip":"192.0.2.10","protocol":"TCP","src_port":40000,"dst_port":22,"tcp_flags":["SYN"],"byte_count":60}
```

```bash
python -m megalodon run --source jsonl --input examples/events.jsonl --max-events 100
cat examples/events.jsonl | python -m megalodon run --source jsonl --max-events 100
```

The adapter caps each JSONL record at 64 KiB and refuses the first blank or
comment line beyond a fixed 65,536-line skipped-input budget. Internal callers
may lower, but cannot raise, those limits. Every physical line, including blank
and comment lines, counts toward a fixed 256 MiB aggregate input budget; the
first line that crosses it is refused before classification or parsing. Together with the required
accepted-event ceiling, this bounds the number of physical lines examined after
reads return and the cumulative bytes returned by them. Without the optional Linux `--max-seconds` control, it does not
interrupt a blocking read or impose an elapsed-time deadline. IP addresses,
ports, timestamps, flags, text, byte counts, detector
evidence, action details, severities, and action statuses are typed and bounded
before persistence. SQLite-facing counts cannot
exceed its signed 64-bit integer range, and mutable JSON fields are revalidated
at the storage boundary. Successful CLI output reports run-scoped `processed`
and `detections` counts plus a separate `totals` object for the whole database.
Detector state is capped at 4,096 tracked sources and 4,096 events per source
window by default. Port-scan distinctness is maintained incrementally with one
bounded frequency index per tracked source; expiry, capacity eviction, and
source eviction update the queue and index together instead of rebuilding a set
from the full window for every TCP event. These are processing and memory
bounds, not evidence that a source is scanning or that traffic was blocked.

For optional Linux live capture (`eth0` is an example, not an assumed interface):

```bash
python -m pip install -e ".[capture]"
python -m megalodon run --source scapy --interface eth0 --max-events 100000
```

Live capture requires the normal Linux permissions for the selected interface.
The adapter extracts addresses, ports, protocol, TCP flags, sizes, and DNS-name
length; it does not persist or print payloads. Scapy's compact TCP flag value is
decoded from its numeric bitmask into the closed FIN/SYN/RST/PSH/ACK/URG/ECE/CWR
event vocabulary; unsupported bits discard that malformed packet. The callback
queue holds at most 1,024 metadata events. Its first overflow stops publication
with a fixed error instead of blocking the capture callback, growing memory, or
silently continuing after loss. Use only on traffic the operator is authorized
to observe.

## Detection rules

| Rule | Default trigger | Severity | Response |
| --- | --- | --- | --- |
| `SYN_FLOOD` | At least 100 TCP SYN-without-ACK events from one source in 10 seconds | HIGH | Alert only |
| `PORT_SCAN` | At least 20 distinct TCP destination ports from one source in 5 seconds | MEDIUM | Alert only |
| `DNS_TUNNELING` | DNS/UDP query metadata length of at least 50 | CRITICAL | Alert only |

[`config/rules.toml`](config/rules.toml) documents these fixed rules. It is a
reference, not an arbitrary rule-expression engine. Runtime thresholds and
bounds use safe built-in defaults or an explicitly selected
[`config/settings.toml`](config/settings.toml).

## Settings and configuration composition

To customize a workflow, start with a private copy of the complete
[`config/settings.toml`](config/settings.toml) and change only the settings
needed. These are ordinary TOML files, not a profile inheritance/merge system.
Pass `--config PATH` **after**
the operational subcommand; use the same configuration for `run` and `dashboard`
when they should share an audit database. CLI source/interface and dashboard
view options override the corresponding settings for that invocation.

| Choice | Configuration mechanism | Boundary |
| --- | --- | --- |
| Synthetic demo or JSONL replay | `[capture].source` or `run --source`; JSONL file via `--input`, otherwise stdin | `--max-events N` is a CLI stop limit; it is not a total disk quota |
| Headless or local UI | Run only the processing command; start `dashboard` separately when needed | `[dashboard].enabled` controls serving, not automatic startup; retain loopback-only binding |
| Separate lab/case audit stores | A complete private TOML per context with a distinct `[app].db_path` | Repeated runs append; retention is operator-owned, not an automatic purge |
| Offline packet/flow reports | Separate offline command with explicit input root and new output directory | Not configured by the service TOML, not SQLite ingestion, and not input to automatic response |
| Observe or review a response plan | Preserve conservative `[blocking]` defaults; use the separate Linux planner for manual review | A plan is not application. Firewall CLI plan commands can write SQLite audit records without changing firewall state |

Default configuration and database paths are relative to the **working directory**,
not the TOML file's directory. Use a deliberate working directory or literal
absolute paths; TOML does not expand `~`, `$HOME`, or `%LOCALAPPDATA%`. On Windows,
use forward slashes or TOML literal strings for paths. Do not add imaginary
`platform`, `suricata`, or `windows_firewall` keys: changing text settings cannot
supply a missing backend. Keep the existing allowlist and bounded defaults unless
a separately reviewed change requires otherwise.

| Section | Important defaults | Notes |
| --- | --- | --- |
| `[app]` | `db_path = "data/megalodon.db"`, `log_level = "INFO"` | Writer startup creates a missing private leaf directory; dashboard startup never creates the directory or database |
| `[storage]` | `max_database_bytes = 268435456` | Writer stops event intake before observed SQLite main/WAL/SHM size plus its one-write reserve crosses the configured high-water budget; it never purges or redirects evidence |
| `[capture]` | `source = "sample"`, empty `interface` | The CLI can override the source and interface per run |
| `[detection]` | 10-second/100-event SYN threshold; 5-second/20-port scan threshold; DNS length 50; cooldown 30 seconds | TOML integers only; windows max at 3,600s, cooldown at 86,400s, DNS length at 65,535, and both state ceilings at 65,536. Thresholds cannot exceed the per-source event ceiling |
| `[blocking]` | `enabled = false`, `dry_run = true`, `auto_block = false`, timeout 900 seconds, `public_only = true` | Timeout is a TOML integer from 1–604,800s; `auto_block = true` is rejected unless `dry_run = true`; detections can plan but cannot apply |
| `[dashboard]` | `enabled = true`, `host = "127.0.0.1"`, `port = 8787`, `refresh_seconds = 5`, `event_limit = 50` | Polling accepts 2–300 seconds; recent rows accept 1–200; only numeric IPv4 loopback or the literal `localhost` alias is accepted; `--allow-remote` refuses startup |

The dashboard accepts dotted-decimal IPv4 addresses in `127.0.0.0/8`. The
literal `localhost` is mapped directly to `127.0.0.1`, without DNS resolution.
Other hostnames, wildcard/LAN/public addresses, and IPv6 (including mapped and
scoped forms) are refused by this IPv4 server. The legacy `--allow-remote` flag
is retained only to give a fixed startup refusal, even with a loopback host.
Remove it and use `--host 127.0.0.1`; do not expose the unauthenticated server
through proxies, tunnels or port forwarding. Firewall allowlist changes,
and public-target policy changes require separate review. Live application is
unsupported; any future restoration must satisfy the gate below.

## Dashboard UI and API

The current UI is a responsive dark-theme status view with:

- summary cards for stored events, detections, action records, and high/critical
  counts, with action records explicitly distinguished from live application;
- a five-column recent-detections table: time, severity, rule, source, and message;
- combined local search, priority/exact-severity and exact-rule filters, plus a
  maximum 12-bin timeline over valid timestamps in the returned set;
- returned-set scope chips and a sequential stored high/critical count-change
  signal that explicitly does not claim unique alerts or incident state;
- manual refresh, clear-filter controls, and pause/resume polling;
- bounded five-second polling by default, suspended while the page is hidden;
- an optional schema-checked, privacy-bounded summary of one explicitly selected
  completed offline run;
- a truthful operator-status strip that separates dashboard API reachability
  from unmeasured capture/ingestion health and marks preserved data stale; and
- DOM text-node rendering rather than raw HTML insertion.

The server exposes only these read routes:

| Route | Response |
| --- | --- |
| `GET /` | Static dashboard HTML |
| `GET /assets/dashboard.css`, `GET /assets/dashboard.js` | Same-origin no-store assets |
| `GET /api/config` | Immutable polling, row-budget, and offline-summary availability metadata |
| `GET /api/summary` | SQLite event, detection, action, and severity counts from one read snapshot |
| `GET /api/events?limit=N` | Five-field recent-detection projections with strict query validation and a 200-row ceiling |
| `GET /api/offline-summary` | Availability plus one startup-validated, capped offline summary; never record rows or capture paths |

Responses use `Cache-Control: no-store`, a self-only Content Security Policy
without `unsafe-inline`, opener/resource isolation headers,
`X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`. The UI cannot
start capture, run analysis, apply firewall actions, edit settings, choose a
filesystem path, or browse local files. [Issue #7](https://github.com/bartytime4life/MEGALODON/issues/7)
preserves the implementation and validation handoff.

## Linux firewall boundary

This optional backend is not a prerequisite for metadata analysis. Inspect plans
without root or firewall mutation; these CLI commands still record local audit rows:

```bash
python -m megalodon firewall-plan 8.8.8.8 --reason "manual review"
python -m megalodon firewall-install
python -m megalodon block 8.8.8.8 --reason "manual review"
```

Detection-driven policy can record a proposed block only when configured. It
never supplies confirmation or invokes `nft`. The retained
`firewall-install --apply` and `block IP --apply` options explicitly refuse
before reading configuration, probing the host, resolving an executable,
checking privilege, or creating a process. No host mutation is attempted and no
`applied` receipt is written; plan and audit receipts remain the only supported
firewall outcomes in the evaluation-release candidate.

Preserve the host's existing firewall manager and endpoint protection on every
platform. An nftables plan is not a Windows Firewall or macOS/BSD firewall rule.
Live application may be restored only through a separately reviewed change that
adds durable intent before mutation, terminal outcome and reconciliation states,
finite expiry, and operator recovery. It must also bind process construction to
a reviewed absolute executable and fixed environment, then pass disposable
Linux network-namespace tests for failure handling, PATH hijacking, expiry,
readback, rollback, and recovery. Plan-mode success alone does not satisfy this
restoration gate.

## Isolated offline analysis

The offline command is separate from `megalodon run` and must run on Linux as a
non-root, capability-free account. It neither writes the SQLite service database
nor drives live dashboard polling or firewall policy. A completed report can
separately supply the startup-only, operator-selected dashboard summary; record
rows are not ingested or served.

```bash
python -m megalodon.offline \
  --source tshark \
  --input-root /absolute/private/input \
  --input capture.pcap \
  --output /absolute/private/new-run-directory \
  --case case001 \
  --max-records 10000 \
  --timeout 30
```

Use `--source zeek-json` or `--source zeek-tsv` with
`--zeek-version X.Y.Z` for a separately produced `conn.log`. An optional reviewed
`baseline.json` under the input root can be selected with
`--reference-baseline RELATIVE_PATH`.

Compare two existing baselines without running an analyzer or creating reports:
`python -m megalodon.offline.compare --input-root /absolute/private/input --reference before.json --current after.json`.
The bounded JSON receipt shows sample sizes, protocol shares, and changed
destination-port shares using exact counts. Matching adapter and record units
are required; contradictory per-protocol counts fail closed in comparison,
candidate analysis, and the dashboard. The result is uncalibrated descriptive
context, with no threat probability or network action. See the
[comparison contract](docs/offline-analysis.md#read-only-baseline-comparison).

The command accepts one nonempty regular input file up to 64 MiB, uses fixed
adapter schemas and limits, and creates a new mode-0700 output directory with
mode-0600 files:

- `records.jsonl` and `records.csv` with deterministic per-run host labels and
  relative times;
- `baseline.json` with source-qualified deterministic distributions;
- `candidates.jsonl` with bounded `NEW_DESTINATION_PORT`, `REGULAR_INTERVAL`, and
  `PORT_53_BURST` review candidates;
- `manifest.json`, written last as the completion marker.

Redaction is not anonymization and does not authorize sharing. No exporter is
implemented. See [`docs/offline-analysis.md`](docs/offline-analysis.md) for the
full isolation model, fixed limits, typed adapter fields, report semantics,
failure behavior, and optional installed-TShark compatibility probe.

## Automation contract: schema only

[`contracts/automation/v1`](contracts/automation/v1/README.md) contains the
dependency-closed Stage 0 contract now present on `main`: JSON Schema Draft
2020-12 definitions plus positive/negative fixtures for draft definitions,
activated definitions, and immutable run snapshots.

This is a normative draft data contract, not a scheduler. It does not calculate
recurrences, resolve DST, persist automation definitions/runs, invoke models,
publish output, expose a CLI/API, or execute jobs. Network and firewall
capabilities are fixed to `false`, `requested_actions` is empty, and no arbitrary
command, path, endpoint, or tool field exists. See
[`docs/automation-contract.md`](docs/automation-contract.md) for the proposed
staged design.

## Development status and remaining evidence

Historical tickets in this selected table retain their closed dispositions;
issues #196, #221, and #231 were read back as closed/completed on 2026-09-16.
Closure records a bounded disposition, not every operational property named in
an original issue. Review live GitHub state before acting because branches,
checks, reviews, and remaining evidence can change.

| Issue | Delivered or closed disposition | Still not established |
| --- | --- | --- |
| [#3 — independent-review enforcement](https://github.com/bartytime4life/MEGALODON/issues/3) | Closed `not planned`: the owner-directed, AI-reviewed workflow retains strict CI and explicit PR-numbered owner merge decisions | A server-enforced independent-human approval floor |
| [#7 — dashboard acceptance](https://github.com/bartytime4life/MEGALODON/issues/7) | Closed `completed`: loopback, privacy, read-only, HTTP, and headed-browser acceptance are on `main` | Native Windows and screen-reader acceptance |
| [#9 — Suricata EVE contract](https://github.com/bartytime4life/MEGALODON/issues/9) and [#24 — bounded reader contract](https://github.com/bartytime4life/MEGALODON/issues/24) | Closed `completed`: closed record schemas, bounded-reader policy, fixtures, receipts, oracles, and the narrow Linux completed-file reader are on `main` | Raw-EVE conversion, installed-producer compatibility, sensor operation, IPS, or response |
| [#212 — durable-consumer contract](https://github.com/bartytime4life/MEGALODON/issues/212) | Closed contract delivery: transactional policy and receipts, accepted/rejected fixtures, and synthetic SQLite rollback/reconciliation oracle | Operational acceptance, migration, dashboard projection, sensor operation, IPS, or response |
| [#215 — durable-store schema](https://github.com/bartytime4life/MEGALODON/issues/215) | Closed delivery: explicit create-only production schema initializer and read-only exact-layout validator | Existing-store migration, retention, dashboard projection, sensor operation, IPS, or response |
| [#221 — durable-consumer capacity and transaction](https://github.com/bartytime4life/MEGALODON/issues/221) | Fixed 512 MiB/no-freelist-credit capacity policy and one atomic publication transaction with replay checks and exact commit readback | CLI/background entry point, dashboard projection, installed-producer and operational acceptance |
| [#231 — commit-unknown reconciliation](https://github.com/bartytime4life/MEGALODON/issues/231) | Closed delivery: explicit read-only API with exact committed/absence proof, fail-closed indeterminate results, and descriptor-pinned OFD snapshot locking | CLI/background entry point, dashboard projection, installed-producer and operational acceptance |
| [#25 — installed TShark compatibility](https://github.com/bartytime4life/MEGALODON/issues/25) | Closed `completed`: one prepared-host UID-1000 header-only probe passed at [`main@7ad539c`](https://github.com/bartytime4life/MEGALODON/commit/7ad539ccd33687725d18ee8a8cedcc84073c3609) with `/usr/bin/tshark` from Wireshark 4.2.2 package `4.2.2-1.1build3` | Arbitrary-capture containment, live capture, installation authority, or compatibility of another release/revision |
| [#26 — detector acceptance](https://github.com/bartytime4life/MEGALODON/issues/26) | Closed `completed`: deterministic bounded synthetic evaluation and evidence-quality reporting are on `main` | Representative accuracy, calibrated thresholds, or operational interpretation |
| [#27 — Windows core acceptance](https://github.com/bartytime4life/MEGALODON/issues/27) | Closed `completed`: the Linux-preserving Windows capability and acceptance handoff is recorded | Native Windows, NTFS ACL, browser, and exact-platform execution receipts |
| [#28 — retention and storage failure policy](https://github.com/bartytime4life/MEGALODON/issues/28) | Closed `completed`: data-class/failure matrices and bounded preview-bound retention transactions are on `main` | Selected operator retention values, automatic cleanup, secure erasure, or native failure recovery |
| [#65 — firewall containment](https://github.com/bartytime4life/MEGALODON/issues/65) | Closed `completed`: retained apply routes fail closed before host inspection or subprocess creation; plan-only receipts remain | A live backend or crash-consistent restoration design |
| [#66 — dashboard read isolation](https://github.com/bartytime4life/MEGALODON/issues/66) | Closed `completed`: a least-data reader validates private storage and constrains SQL to the dashboard projection | Native Windows ACL evidence or remote dashboard authority |
| [#67 — atomic ingestion receipts](https://github.com/bartytime4life/MEGALODON/issues/67) | Closed `completed`: per-event evidence commits, terminal reasons, rollback behavior, and bounded orphan reconciliation are on `main` | Exactly-once intake, native power-loss recovery, alert lifecycle, or delivery |
| [#68 — whole-service resource bounds](https://github.com/bartytime4life/MEGALODON/issues/68) | Closed `completed`: detector accounting, storage high-water refusal, Scapy lifecycle bounds, and finite retention batches are on `main` | Installed-Scapy loss evidence, native long-running exhaustion results, selected retention values, or notifier behavior |
| [#196 — POSIX ingestion deadline](https://github.com/bartytime4life/MEGALODON/issues/196) | Closed delivery: optional source-lifetime alarm, fixed failure receipt, blocking-stdin proof, cleanup-order tests, and refusal to replace an active process timer | Windows/portable interruption, uninterruptible native/kernel stalls, whole-command deadlines, installed-capture loss evidence, and sustained native capacity |
| [#69 — CI dependency and artifact hygiene](https://github.com/bartytime4life/MEGALODON/issues/69) | Closed `completed`: repository hygiene, hashed constrained CI inputs, isolated-build constraints, and exact-tree checks are on `main` | Automatic update trust, release provenance, or independent approval |
| [#154 — Qwen Airlock preflight](https://github.com/bartytime4life/MEGALODON/issues/154) and [#165 — literal-loopback provider boundary](https://github.com/bartytime4life/MEGALODON/issues/165) | Closed `completed`: pinned metadata-only admission and the bounded internal `127.0.0.1:11434` provider adapter are on `main` | An operator-verified model artifact/Ollama lifecycle, CLI or dashboard exposure, persistence, background execution, or action authority |

Issue and branch records are coordination and evidence surfaces, not release or
deployment approval. A closed ticket must not be read as broader authority than
its recorded acceptance and non-effects.

The [unified roadmap reconciliation](docs/unified-roadmap-currentness.md)
separates supplied architecture proposals from this pinned implementation,
including capacity versus retention, provider containment, and native-platform
acceptance.

## Validation

Repository-native checks for the existing **Linux reference lane** are below.
Install the `test` extra in that environment first. Windows requires its separate
core/ACL/UI/unsupported-operation acceptance work; do not treat this full suite
as a portable Windows recipe or suppress Linux-specific failures to claim parity.

```bash
python -m compileall -q megalodon tests
python -m pytest
python -m megalodon capabilities --platform linux
python -m megalodon capabilities --platform windows
python -m megalodon hub-plan --platform linux
python -m megalodon run --source sample --max-events 13
python -m megalodon run --source sample --demo-threat --max-events 114
python -m megalodon firewall-plan 8.8.8.8 --reason "CLI smoke"
megalodon-evaluate reference verify
megalodon-evaluate reference port tcp 443
megalodon-evaluate reference protocol 6
megalodon-evaluate corpus
```

The reference and corpus commands validate their complete respective bundles
before performing bounded lookups or an in-memory detector run. The separate
[Alert Workload Lab](docs/alert-workload-lab.md) consumes only explicit numerical
assumptions and a declared unit, returning hypothetical counts and exact ratios.
These evaluation commands do not fetch updates, use SQLite,
persist output, invoke a response action, or start a subprocess. The smoke
commands use synthetic data and a non-mutating firewall plan. They do
not prove live-capture compatibility, installed-TShark behavior, firewall safety
on a specific host, corpus representativeness, calibrated detection accuracy,
independent review, or production readiness. Printing a Windows/other catalog
on Linux is not execution on those platforms. Record the exact revision,
OS/architecture, Python and dependency versions, selected extras, passed
checks, and skips for every configuration claim.

## Project layout

```text
.github/workflows/           hosted CI
config/                      conservative typed defaults and fixed-rule reference
contracts/automation/v1/     inert automation schema, fixtures, and contract notes
contracts/alert-lifecycle/v1/ inert alert lifecycle schema, fixtures, and contract notes
contracts/suricata-eve/v1/   alert, bounded-reader, and durable-consumer contracts
docs/                        platform baseline, integration hub, automation design, offline analyst guide
examples/                    bounded JSONL replay fixture
megalodon/                   validation, capability/hub catalogs, capture, detection, storage, policy, CLI, UI
megalodon/offline/           isolated TShark/Zeek adapters, Suricata reader/consumer, and private reports
megalodon/reference/         pinned offline IANA context and synthetic evaluation corpus
site/                        static Defense Console source mirror and Sites identity
tests/                       safety, behavior, offline, and schema contract tests
SECURITY_REVIEW.md           architecture threat assessment and required controls
SPECIFICATION.md             implemented MVP contract and acceptance boundary
```

## Current limits

This is a defensive MVP, not a finished enterprise IDS/IPS. The fixed detections
are simple heuristics. There is no authenticated remote UI, arbitrary rule
authoring, threat-feed or SIEM/SOAR integration, distributed sensor management,
automatic retention job, production rollback orchestration, background model execution,
active scheduler, Suricata watcher/sensor control or reconciliation CLI/background
command, alert acknowledgement/resolution/escalation lifecycle, notification
dispatcher, or continuous capture-health monitor on `main`.

The bundled IANA snapshot is not runtime service discovery or a vulnerability
feed, and it has no automatic update path. The synthetic corpus tests deterministic
boundary behavior; it is not representative traffic, a benchmark against named
products, an accuracy claim, or evidence that an alert is malicious.

Before operational deployment, use representative authorized replay data to
measure false positives; validate live capture and TShark separately; define
retention and data-sharing policies; keep firewall operation plan-only unless
the restoration gate above is implemented and independently reviewed; and
obtain independent security/operations review.
