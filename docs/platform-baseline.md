# Windows and Linux platform baseline

**Baseline v1 — immutable inspected configuration and delivery plan.**
Repository state was observed at 2026-09-10T02:06:08Z against
`adff346c55fb41be9e51be3cea0c7d8701175c2f` on `main` (tree
`f2bcd4d39723a80d163aa1cd1271daf3020676f9`) as the executable base. This is
an immutable observation, not a floating claim about current `main`. The merged
firewall-containment changes from PRs #72–#74 and the first bounded #66
dashboard-reader slice from PR #75 are implemented at this pin. Merged state
and green CI do not establish independent approval; issues #3, #65, and #66
remain open. This document is the canonical platform configuration entry point.
It does not install software, activate sensors, certify Windows support, or
authorize a license decision, tag, release, package publication, deployment,
protection/ruleset change, firewall restoration, ready transition, or future
merge. Google Drive carries coordination and historical evidence, not another
runtime configuration authority. Recheck live repository state before use.

## 1. Platform decision and feature status

Keep Linux as the reference implementation and add Windows in bounded stages.
Application availability on an operating system is not MEGALODON integration or
a passing compatibility test. The requirements in this document are proposed
unless explicitly identified as implemented in the pinned repository.

| Profile | Selected environment | Intended use | Evidence boundary |
| --- | --- | --- | --- |
| L1: Linux reference | Ubuntu 24.04 LTS, x86-64, maintained distribution Python 3.12 | Existing metadata MVP; isolated Linux offline analysis | Repository CI is Ubuntu 24.04 with Python 3.11, not the complete L1 workstation combination |
| W1: native Windows evaluation | Maintained Windows 11, x64, standard CPython 3.13 | Synthetic sample/JSONL, fixed detections, SQLite, loopback dashboard evaluation | PROPOSED; no Windows CI or native Windows execution evidence is supplied by this change |
| W2: Windows with Linux analysis guest | L1 inside a separately prepared Linux VM; WSL2 only for development evaluation | Reuse the Linux offline workflow without weakening its Linux checks | Guest validation is required; neither the VM nor WSL is proof of Windows-host traffic visibility or enforcement |

Ubuntu 24.04 is a deliberate maintained reference, not a claim that it is the
newest Ubuntu release. Other distributions, Windows Server, Windows 10, ARM64,
and other Python versions need their own evidence before inclusion. [S1, S2]

| Feature | Pinned Linux implementation | Native Windows baseline |
| --- | --- | --- |
| Sample and bounded JSONL metadata; three fixed rules | Implemented | Evaluation target, unverified |
| SQLite audit and read-only dashboard | First bounded exact-v2, `mode=ro`, `query_only` slice merged in #75; `127.0.0.1` by default; #66 replacement/concurrency, WAL-sidecar, Windows ACL, and independent-review gates remain open | Evaluation target; private NTFS storage and loopback checks required |
| Scapy live metadata capture | Optional `capture` extra; separate capture permission/authority | Not selected; driver, privilege, and adapter compatibility remain unreviewed |
| Offline TShark packet metadata and Zeek connection-log import | Separate Linux-only command and private reports | Unsupported by the current offline implementation; use a validated L1 guest instead |
| Firewall plans | Merged #72–#74 containment is plan-only; every retained live-apply route returns a fixed unsupported diagnostic before configuration, privilege, or subprocess work | No Windows firewall backend; an nftables plan is not a Windows rule |
| Offline-run dashboard projection | Implemented for one complete private report set on loopback | Native core evaluation target; remote projection is refused |
| Suricata EVE integration | Inert record and bounded-reader contracts/tests on main; no runtime reader/importer | Contract only; native Suricata availability does not change this |
| Scheduling and automated response | Automation schema exists; no scheduler/executor | Not implemented; no Task Scheduler installation or automatic blocking |

Implementation evidence: [package metadata](../pyproject.toml),
[CI](../.github/workflows/ci.yml), [CLI](../megalodon/cli.py),
[static capability catalog](../megalodon/capabilities.py),
[Linux file boundary](../megalodon/offline/common.py),
[fixed TShark runner](../megalodon/offline/tshark.py), and
[nftables plan backend](../megalodon/firewall.py).
The offline code checks Linux/non-root/capability-free execution, uses Linux
file descriptors and `/proc`, and invokes `/usr/bin/tshark`. Changing that path
to `tshark.exe` is not a safe port. In the pinned revision, #72 removed the live
executor and #73–#74 closed parser-preflight spellings. Every retained
`--apply` route and direct backend apply entry point returns the fixed
unsupported diagnostic before configuration, platform, executable, privilege,
database, or subprocess work. This is containment, not a completed
crash-consistent response design; #65 remains open pending independent review
and its restoration gate.

## 2. Open-source application selection

Install only the core first. Optional tools stay separate until their specific
capability and privacy gates pass. No cloud analytics or paid threat service is
required by this baseline.

| Component | Linux choice | Windows choice | Role and integration status |
| --- | --- | --- | --- |
| Python, Git, SQLite | Distribution Python/venv and Git; Python `sqlite3` | Official CPython and Git for Windows; Python `sqlite3` | Core development/runtime tools; no separate `pip install sqlite3` [S2, S3] |
| Wireshark / TShark | Reviewed distribution packages; adapter requires `/usr/bin/tshark` | Official signed x64 installer; desktop/TShark offline use | Open-source analyzer; Windows desktop use is separate from the Linux-only MEGALODON adapter [S4] |
| Scapy | Repository `capture` extra only when capture is approved | Omit from W1 | Open-source Python tool; upstream Windows support does not validate MEGALODON capture [S5] |
| Suricata | Maintained upstream-supported Linux package | Official x64 Windows installer for separately reviewed offline analysis | Open-source signature IDS; EVE alert contract/tests are present, but runtime import is not implemented [S6] |
| Zeek | Linux producer of separately scoped `conn.log` | Use the Linux guest for this baseline | Open-source network metadata producer; this is a baseline choice, not a claim that no Windows build exists [S7] |
| ClamAV | Optional separate manual file scanner | Optional separate manual file scanner | Open-source supplementary file scanning; no MEGALODON file-content intake, quarantine, or antivirus replacement claim [S8] |
| osquery | Later optional local host-inventory evaluation | Later optional local host-inventory evaluation | Open-source endpoint metadata tool; no importer, daemon, scheduled query pack, or remote enrollment in this slice [S9] |
| Host firewall | Preserve the plan-only firewall manager; merged #72–#74 containment emits inert nftables-shaped plans and refuses live application | Preserve Windows Firewall and existing endpoint protection | Windows built-in security is not an open-source MEGALODON component; do not replace or disable it |

**Npcap is an exception, not an open-source dependency.** Its source availability
and free-use cases do not make its license open source. Windows Wireshark can
open saved captures without Npcap; Suricata documents that offline PCAP
processing can omit it. The open-source application baseline therefore omits
Npcap and native Windows live capture. Any later driver installation/use or
redistribution needs separate license and privilege review; do not assume a
Wireshark-specific free-use exception covers MEGALODON/Scapy. [S4, S6, S10]

Do not substitute WinPcap, an unreviewed capture driver, or an IPS/diversion
backend to bypass that decision. A Windows host is not an entirely open-source
stack. Also, the pinned repository has no root license file and no project
license field in `pyproject.toml`: MEGALODON's own distribution/license decision
remains for its owner. This documentation does not select a license or grant
redistribution rights for it or bundled third-party components.

At this source check, Suricata's download page lists stable **8.0.6** and marks
**7.0.17** end-of-life. Those are upstream observations, not tested producer
versions for MEGALODON. Do not turn the older 8.0.1 documentary field baseline
from the now-closed issue #9 contract gate into an installation pin. Record and
review the actual package, rule-set version/license, and advisories before
deployment. [S6]

The repository exposes these distinctions without probing the host:

```bash
python -m megalodon capabilities --platform linux
python -m megalodon capabilities --platform windows
```

This is a static catalog. It does not detect an installation, start a process,
access the network, approve a platform, or change configuration.

## 3. Shared configuration and data boundary

Use the complete [settings file](../config/settings.toml) from the pinned
checkout. The following is a review checklist excerpt, **not a replacement
configuration**. Keep the existing allowlist and detector bounds unchanged.

```toml
[capture]
source = "sample"
interface = ""

[blocking]
enabled = false
dry_run = true
auto_block = false
public_only = true
timeout_seconds = 900

[dashboard]
enabled = true
host = "127.0.0.1"
port = 8787
```

Run from the checkout root: configuration and `data/megalodon.db` are relative
to the working directory. Do not add imaginary `platform`, `suricata`, or
`windows_firewall` settings. For a different data directory, deliberately edit
a private copy of the full TOML and pass `--config` after the subcommand.
Use literal paths; do not assume shell variables or `~` are expanded in TOML.
For Windows, forward slashes or TOML literal strings avoid backslash escapes.

Keep source, SQLite/WAL files, input evidence, and reports out of cloud-synced
folders, public shares, Git commits, and Drive uploads. On Linux use a private
owned directory and `umask 077`; offline reports enforce additional 0700/0600
modes. On Windows use a local NTFS directory whose ACL has been reviewed for the
operator and necessary system/administrator access, not broad user access.
`chmod` semantics are not a substitute for a Windows ACL review.

The baseline is foreground/manual operation. Do not install systemd units,
Windows services, scheduled tasks, startup hooks, firewall rules, or public
listeners. Do not run the core as root/Administrator. No capture is needed for
the sample demonstration. Existing `--allow-remote` is not an approved exposure
mode: do not use it, port forwarding, a reverse proxy, or a tunnel.

Set a local retention period and review the configured disk budget before real
telemetry. The writer applies a 256 MiB default total SQLite main/WAL/SHM
high-water stop and refuses the next event before its transaction when the
observed budget would be crossed. There is no automatic retention job or purge;
review deletion separately rather than silently purging evidence. Redacted reports are not anonymous or share-approved.

Package downloads and signature/rule updates are maintenance network activity,
not permission to upload telemetry. Prepare dependencies before isolated
analysis. Validate source/signature/checksum provenance for software artifacts;
never calculate or publish capture/payload-derived hashes in MEGALODON records.

## 4. L1: Linux installation and validation

An administrator separately provisions Git, distribution Python 3.12, `venv`,
and applicable security updates. On Ubuntu the core package names are `git`,
`python3`, and `python3-venv`. TShark, Scapy, Zeek, Suricata, ClamAV, and nftables
are not prerequisites for the synthetic core demonstration. Do not grant
capture capabilities to the Python interpreter or run an analyzer as root.

These commands create a **new** private evaluation checkout; they do not update
an existing workstation checkout. Run in an ordinary Bash terminal, starting
from your home directory. The runtime pin is the inspected base, not floating
`main`; choose a newer pin only after review and repeat validation.

```bash
set -euo pipefail
umask 077
[ "$(id -u)" -ne 0 ] || { echo 'Use a non-root account.'; exit 1; }
mkdir -p "$HOME/Projects"
cd "$HOME/Projects"
[ ! -e MEGALODON-platform-baseline ] || { echo 'Target already exists; stop.'; exit 1; }
git clone --no-checkout https://github.com/bartytime4life/MEGALODON.git MEGALODON-platform-baseline
cd MEGALODON-platform-baseline
BASE=adff346c55fb41be9e51be3cea0c7d8701175c2f
git checkout --detach "$BASE"
[ "$(git rev-parse HEAD)" = "$BASE" ]
/usr/bin/python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
/usr/bin/python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q megalodon tests
.venv/bin/python -m pytest
.venv/bin/python -m megalodon run --source sample --max-events 13
.venv/bin/python -m megalodon run --source sample --demo-threat --max-events 114
.venv/bin/python -m megalodon run --source jsonl --input examples/events.jsonl --max-events 100
.venv/bin/python -m megalodon firewall-plan 8.8.8.8 --reason 'baseline smoke only'
```

The last command prints a plan; it must not apply a block. Synthetic HIGH or
CRITICAL findings are demonstration output, not a diagnosis of the workstation.
Then, in the same checkout, start the foreground UI:

```bash
.venv/bin/python -m megalodon dashboard --host 127.0.0.1 --port 8787
```

Visit `http://127.0.0.1:8787/`, check summary/detection rendering, and stop with
Ctrl+C. In another terminal, `ss -ltn 'sport = :8787'` can inspect the listener;
only the selected loopback address is acceptable. No port-opening rule is needed.
A passing ordinary suite does not prove the optional installed-TShark lane ran.

## 5. W1: Windows installation and evaluation

**UNVERIFIED native platform recipe; synthetic data only.** Use maintained
Windows 11 x64, Git for Windows, and a patched standard CPython 3.13 installation
with `pip`, `venv`, and the `py` launcher. Obtain them from official sources and
verify the installer publisher. Do not install a free-threaded/embedded Python
variant for this baseline. Keep existing firewall and endpoint protection on.
[S2, S3]

Start in a **non-elevated PowerShell** session. Review the ACL and confirm
`LOCALAPPDATA` is local/private and not redirected or synced before proceeding.
The commands avoid activation scripts, execution-policy changes, global Python
changes, and automatic elevation. Every native command is checked for failure.

```powershell
$ErrorActionPreference = 'Stop'
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Program ($LASTEXITCODE)" }
}
$Target = Join-Path $env:LOCALAPPDATA 'MEGALODON-platform-baseline'
if (Test-Path -LiteralPath $Target) { throw 'Target already exists; stop.' }
Invoke-Checked -Program 'git' -Arguments @('clone', '--no-checkout', 'https://github.com/bartytime4life/MEGALODON.git', $Target)
Set-Location -LiteralPath $Target
$Base = 'adff346c55fb41be9e51be3cea0c7d8701175c2f'
Invoke-Checked -Program 'git' -Arguments @('checkout', '--detach', $Base)
$Actual = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $Actual -ne $Base) { throw 'Revision mismatch.' }
Get-Acl -LiteralPath $Target | Format-List Owner, AccessToString
Invoke-Checked -Program 'py' -Arguments @('-3.13', '-m', 'venv', '.venv')
$Python = Join-Path $Target '.venv\Scripts\python.exe'
Invoke-Checked -Program $Python -Arguments @('-m', 'pip', 'install', '-e', '.[test]')
Invoke-Checked -Program $Python -Arguments @('-m', 'pip', 'check')
Invoke-Checked -Program $Python -Arguments @('-m', 'compileall', '-q', 'megalodon', 'tests')
Invoke-Checked -Program $Python -Arguments @('-m', 'megalodon', 'run', '--source', 'sample', '--max-events', '13')
Invoke-Checked -Program $Python -Arguments @('-m', 'megalodon', 'run', '--source', 'sample', '--demo-threat', '--max-events', '114')
Invoke-Checked -Program $Python -Arguments @('-m', 'megalodon', 'run', '--source', 'jsonl', '--input', 'examples/events.jsonl', '--max-events', '100')
Invoke-Checked -Program $Python -Arguments @('-m', 'megalodon', 'dashboard', '--host', '127.0.0.1', '--port', '8787')
```

The last command stays in the foreground; visit `http://127.0.0.1:8787/` and stop
with Ctrl+C. A separate PowerShell session can inspect the listener with
`Get-NetTCPConnection -State Listen -LocalPort 8787`; require loopback only.
The ACL command displays permissions; it does **not** certify or repair them.
Stop if the location/ACL is unsafe, a command fails, or a security exception is
requested. Do not disable protections to make a smoke check pass.

This is not a supported Windows test lane: compilation and a sample run cannot
establish full portability. The existing full pytest suite includes Linux
filesystem, privilege, and process assumptions. Record those failures honestly;
do not suppress them to declare Windows support. W1 excludes all firewall
commands, `megalodon.offline`, live capture, services, and real telemetry until
the acceptance work in section 8 is complete.

## 6. Optional analyzers and W2 guest configuration

**Wireshark/TShark:** use maintained official/distro packages, record the actual
version, and keep them outside the Python dependency list. On Windows select
the GUI/TShark components and omit Npcap for offline-only use. Do not select
remote capture/extcap components for this baseline. Use a separate analyst
profile with network name resolution disabled; do not export packet bytes,
credentials, raw protocol trees, or captures into MEGALODON or collaboration
tools. The typical Windows executable is under `C:\Program Files\Wireshark`,
but that path is not accepted by the current Linux adapter. [S4]

**Linux offline workflow:** first follow the isolation, file limits, output
modes, and optional real-tool probe in [offline-analysis.md](offline-analysis.md).
Use a non-root, capability-free account with approved inputs in a scoped private
root, a new output directory, no egress, and external resource containment.
MEGALODON's bounds do not by themselves sandbox a native analyzer. Do not use
a live capture or live firewall as a compatibility fixture.

**Windows analysis guest:** prepare an isolated L1 VM with dependencies installed
before analysis; use its own private Linux filesystem and a browser inside the
guest for the guest-local dashboard. Disconnect analysis networking and avoid
shared folders, clipboard, host credentials, and broad host mounts. Transfer
only separately authorized inputs by a reviewed process. No VM is provisioned
by these instructions and no hypervisor isolation claim has been tested here.

WSL2 is an optional development convenience, not the hostile-capture isolation
baseline. Use guest-local storage rather than `/mnt/c` for Linux permission and
file-boundary evaluation. WSL NAT/mirrored networking, localhost forwarding,
and Windows/Hyper-V firewall behavior require explicit checks. Never infer
that a WSL capture sees all Windows-host traffic, that guest nftables protects
the Windows host, or that a working guest UI authorizes remote binding. [S11]

**Suricata/Zeek:** installing either does not create a MEGALODON input source.
Keep their producer configuration, rule updates, retention, and raw logs in the
separate analyst environment. Select passive/offline operation only; do not
install IPS, diversion, or packet-modification paths. Zeek import accepts only
the documented connection mapping, not arbitrary protocol logs. Stock Suricata
`eve.json` is not the repository contract's input envelope: do not pipe it into the
core JSONL command. Before a producer is connected, review explicit field
allowlists and prohibit payload/file extraction, payload hashes, unrestricted
labels, and unintended DNS/HTTP/TLS identifiers. [S6, S7]

**ClamAV/osquery:** optional complementary tools, not default dependencies.
ClamAV is a separate operator-run file scan with no automatic removal/quarantine
or upload; its findings do not enter the network event model. osquery requires
a future bounded field/table allowlist: no arbitrary SQL from events/prompts,
process command-line/environment dumping, remote enrollment, or scheduling.
Neither integration is implemented or enabled by this baseline. [S8, S9]

## 7. Evidence receipt and operational limits

For each evaluation record locally: source commit; OS edition/build,
architecture and guest/host identity; Python and package versions; installed
analyzer versions and software provenance; selected profile; reviewed settings;
working/data locations and permission review; exact commands and exit results;
passed/failed/skipped tests; loopback listener result; and action-state evidence.
Include a full-suite receipt before calling a platform supported. A screenshot
or installer success alone is insufficient.

Do not attach real captures, SQLite databases, raw sensor logs, credentials,
source paths containing personal information, or packet-derived hashes to a PR
or Drive document. Share only a separately reviewed, bounded synthetic receipt.
Keep `not_attempted`, `suppressed`, `planned`, and `failed` distinct. The
#65's pinned implementation does not produce an `applied` firewall receipt. A `failed`
receipt records a planning or validation refusal, never an attempted mutation.
A producer reporting a blocked event does not mean MEGALODON applied a rule.

## 8. Dependency-ordered implementation plan

All entries below are **PROPOSED**, not changes made by this documentation.

| Stage | Smallest deliverable | Required exit evidence |
| --- | --- | --- |
| P0: review and baseline | Review this document and reconcile issue #3's independent-review control | Current ruleset and independent review evidence; retain strict required `test` gate and historical lifecycle receipts |
| P1: Windows core | Complete #27 bounded platform capability/error handling and synthetic core tests; retain Linux behavior | Static catalog is prerequisite evidence only; exact-head Linux full suite plus Windows core tests and install/UI/ACL receipts; explicit failures for unsupported paths, no new privileges |
| P2: analyzer compatibility | Complete #25 for a maintained Linux TShark package; separately review Windows offline design | Installed-tool synthetic fixtures; Windows design covers handle identity, reparse points, UNC/device/alternate-stream rejection, private ACLs, process-tree termination, pipe/resource bounds, no-egress containment; never remove Linux guards as a shortcut |
| P3: optional sensor intake | Treat closed #9 record and #24 reader contracts as prerequisites, then propose one bounded runtime Suricata slice; handle #7 UI independently | Production descriptor/resource/replay tests, source/version/framing/field rejection, transactional persistence and privacy review; packet/flow/alert counts stay distinct |
| P4: response restoration decision | Separate design only if explicitly requested | Durable intent and terminal outcome, startup reconciliation, expiry and operator recovery, validated absolute executable and fixed environment, plus disposable-namespace failure, rollback, conflict, and PATH-hijack tests; no implementation until these are resolved |
| P5: packaging/operations | Optional service/installer work after supported-platform evidence | Least-privilege account, update/retention/uninstall contracts and reproducible artifacts; no silent firewall/driver changes |

A Windows scheduled cleanup is not automatically equivalent to nftables timeout
sets. Until reliable finite expiry and recovery are proven, Windows response
remains unavailable. Scheduling, model execution, SIEM/SOAR/cloud export,
remote dashboards, permanent blocks, and autonomous response are not authorized
by any stage here. Green CI is not independent approval or deployment authority.

## 9. Source basis

Primary sources consulted 2026-09-07; recheck before installing. Source facts are
OBSERVED upstream statements, not reproduced MEGALODON compatibility results.

- S1: [Ubuntu maintained release list](https://ubuntu.com/project/docs/release-team/list-of-releases/).
- S2: [CPython 3.13 on Windows](https://docs.python.org/3.13/using/windows.html).
- S3: [Git for Windows](https://gitforwindows.org/).
- S4: [Wireshark Windows installation](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html), [Wireshark manual](https://www.wireshark.org/docs/wsug_html/), and [security advisories](https://www.wireshark.org/security/).
- S5: [Scapy installation and platform dependencies](https://scapy.readthedocs.io/en/latest/installation.html).
- S6: [Suricata releases](https://suricata.io/download/) and [8.0.6 Windows requirements](https://docs.suricata.io/en/suricata-8.0.6/install/windows.html).
- S7: [Zeek documentation](https://docs.zeek.org/en/current/) and [connection-log guidance](https://docs.zeek.org/en/current/tutorial/logs.html).
- S8: [ClamAV supported-platform documentation](https://docs.clamav.net/).
- S9: [osquery project and platform support](https://osquery.io/).
- S10: [Npcap distribution terms](https://npcap.com/) and [license](https://github.com/nmap/npcap/blob/master/LICENSE).
- S11: [Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking).

At the repository-state readback recorded above, PRs
[#72](https://github.com/bartytime4life/MEGALODON/pull/72),
[#73](https://github.com/bartytime4life/MEGALODON/pull/73),
[#74](https://github.com/bartytime4life/MEGALODON/pull/74), and
[#75](https://github.com/bartytime4life/MEGALODON/pull/75) were merged.
PRs #72–#74 establish plan-only firewall containment; #75 delivers only the
first bounded #66 dashboard-reader slice. The only submitted review returned
for #75 was an automated `COMMENTED` review, not an approval or independent
review.

Selected platform/release follow-ups observed open included
[#3](https://github.com/bartytime4life/MEGALODON/issues/3),
[#7](https://github.com/bartytime4life/MEGALODON/issues/7),
[#23](https://github.com/bartytime4life/MEGALODON/issues/23),
[#25](https://github.com/bartytime4life/MEGALODON/issues/25),
[#27](https://github.com/bartytime4life/MEGALODON/issues/27),
[#65](https://github.com/bartytime4life/MEGALODON/issues/65),
[#66](https://github.com/bartytime4life/MEGALODON/issues/66),
[#67](https://github.com/bartytime4life/MEGALODON/issues/67),
[#68](https://github.com/bartytime4life/MEGALODON/issues/68),
[#69](https://github.com/bartytime4life/MEGALODON/issues/69), and
[#70](https://github.com/bartytime4life/MEGALODON/issues/70). Issue #65 retains
its independent-review and restoration-design gates; #66 retains unsatisfied
reader/privacy acceptance; #69 retains sensitive-artifact, CI dependency, and
required-check hygiene work; #70 leaves licensing and evaluation-release
decisions to the owner. [#9](https://github.com/bartytime4life/MEGALODON/issues/9),
[#24](https://github.com/bartytime4life/MEGALODON/issues/24), and
[#28](https://github.com/bartytime4life/MEGALODON/issues/28) are closed
design/test gates, not proof of a runtime capability or completed operational
policy. Read live state before acting; this baseline does not freeze branch
heads or turn proposals into shipped work. No license decision, tag, release,
package publication, deployment, protection/ruleset change, ready transition,
or future merge is authorized by this baseline.
