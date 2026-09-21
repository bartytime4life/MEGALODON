# macOS core acceptance

Status: **Proposed M-track; hosted M1 sample CI probe currently fails; native
macOS acceptance unproved.**

This document is the macOS counterpart to `docs/windows-core-acceptance.md`.
It tracks what has and has not been evaluated on macOS, following the same
acceptance-gate discipline used for the Linux reference lane and the Windows
W-track: a recipe or adapter is described as available only once it has a
recorded, reproducible acceptance result on this platform. An installed
Python interpreter or upstream tool does not by itself establish support.

macOS is currently listed as **unsupported in the platform catalog** (see the
main `README.md`, "Platform and environment choices", and
`docs/platform-baseline.md`). This document proposes a staged M-track to close
that gap in the same order and with the same evidence bar as the existing
Windows track, starting from the narrowest, lowest-risk surface.

## Track overview

| Stage | Scope | Status |
| --- | --- | --- |
| M0 | This document; no code change | Proposed |
| M1 | Synthetic/JSONL-only core evaluation; no capture, no adapters, no firewall backend | Hosted sample probe failed; M1 remains open |
| M2 | Offline TShark adapter, mirroring the Linux contract | Not started |
| M3 (deferred) | Native live capture evaluation (BPF-based) | Not proposed; gated on M1/M2 evidence and a separate permission/isolation review |

Each stage requires its own recorded acceptance evidence (macOS version,
architecture, Python version, exact commands run, and pass/fail) before the
platform table in the README is updated. Closing M1 does not imply M2 is
supported, and closing M2 does not imply M3 is proposed, let alone accepted.

## M1 — synthetic core evaluation

Mirrors the existing W1 recipe. Scope: the core package only, using the
built-in sample generator or a bounded JSONL replay. No capture extra, no
offline adapter, no firewall backend.

| Requirement | Note |
| --- | --- |
| macOS version | Track the two most recent major releases at time of evaluation; record the exact version tested (`sw_vers`) |
| Python | 3.11 or newer, from python.org or Homebrew (`python@3.12`); record `python3 --version` and installation source |
| Architecture | Apple Silicon (arm64) and Intel (x86_64) are separate acceptance rows; a pass on one is not evidence for the other |
| Dependencies | None beyond the core package; the `capture` and `test` extras are out of scope for M1 |

Proposed evaluation commands (synthetic data only, no network, no elevated
privilege):

```
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m megalodon run --source sample --max-events 14
.venv/bin/python -m megalodon run --source sample --demo-threat --max-events 115
.venv/bin/python -m megalodon dashboard --host 127.0.0.1 --port 8787
```

Record `sw_vers`, `python3 --version`, `uname -m`, and the pass/fail of each
command, matching the evidence format used for the existing W1 acceptance
record.

The caps exceed the finite 13- and 114-event sample lengths by one so the
terminal receipt can record `source_exhausted` rather than `event_limit_reached`.
The PR-only `macos-m1-sample` job records its exact candidate head/tree,
hosted runner image, `sw_vers`, architecture, Python, and outcomes for the two
built-in sample commands above. It installs only the core package and runs in a
private temporary directory. It does not run JSONL replay or a dashboard
listener/browser check. `macos-latest` is a mutable hosted runner label, and a
result on one architecture cannot satisfy the separate Apple Silicon and Intel
rows or operator review. The unsupported platform catalog remains unchanged.

At PR #339 head `af43e527fdaeb17bc7fea7bbd70b7969b743ab96`, hosted
[run 35639424857](https://github.com/bartytime4life/MEGALODON/actions/runs/35639424857)
recorded macOS 26.6.2 (build 25G83), arm64, Python 3.12.10, and a failed first
sample command with `STORAGE_PATH:DATABASE_CHANGED`. The demo-threat command
did not run. This is a failure receipt, not a diagnosed cause or M1 acceptance.
The storage path-identity guard must not be relaxed to make the probe pass;
investigate the macOS descriptor/SQLite behavior and review any runtime change
separately.

## M2 — offline TShark adapter

Mirrors the Linux `megalodon.offline --source tshark` contract exactly:
non-root, private input/output directories, a fixed and reviewed executable
path, no live-capture permission, no raw-EVE conversion, no persistence
beyond the isolated report.

| Item | Linux | Proposed macOS equivalent |
| --- | --- | --- |
| Install source | Ubuntu `tshark` package | Homebrew `wireshark` formula (CLI-only; the GUI app is not required) |
| Fixed path | `/usr/bin/tshark` | `/opt/homebrew/bin/tshark` (Apple Silicon default prefix) or `/usr/local/bin/tshark` (Intel default prefix) — record which prefix the evaluation host used; do not treat one as canonical for both architectures |
| Capture permission | Declined at install (`wireshark-common/install-setuid boolean false`) | Not requested; this adapter never touches `/dev/bpf*` |
| First-run friction | None | Homebrew-installed binaries can carry a quarantine attribute; record the exact Gatekeeper/notarization state observed rather than instructing operators to disable Gatekeeper |

This is not only a path-resolution or packaging change. The current adapter
explicitly requires Linux and verifies capability state through
`/proc/self/status` in `megalodon/offline/common.py`; TShark receives its pinned
input as `/proc/self/fd/<fd>` in `megalodon/offline/tshark.py`. Those interfaces
are not a macOS admission or descriptor-identity contract.

M2 first requires a separately reviewed native design for unprivileged
admission, private descriptor-bound input, child-process ownership and cleanup,
timeouts, and output/resource limits. Reusing the closed metadata parser may be
possible, but neither its reuse nor a Homebrew executable proves those controls.
Do not weaken the Linux gate or substitute an unpinned pathname to make a macOS
probe pass. Until exact-platform negative fixtures and installed-tool receipts
exist, M2 remains not started and the adapter must refuse macOS.

## M3 — native live capture (deferred, not proposed)

macOS packet capture rides on the BSD BPF devices (`/dev/bpf*`) rather than a
third-party driver, which avoids the Npcap licensing question this project
deliberately sidestepped on Windows. That is a genuine long-term advantage —
but it is not evaluated here, and this document does not propose enabling it.
Before any M3 proposal:

- BPF device access on modern macOS requires either running as root or a
  dedicated helper that adjusts device group/permissions at boot (the model
  Wireshark's own `ChmodBPF` launch daemon uses) — that helper is
  out-of-scope infrastructure this repository has not built or reviewed;
- the same single-thread, bounded-queue, fail-closed discipline used for the
  Linux Scapy adapter would need its own macOS-specific review, not an
  assumption that the Linux adapter runs unmodified;
- as with Linux, an operator's authorization to observe the traffic in
  question is a precondition, not a technical detail.

## Non-goals

This document does not propose macOS support for the firewall-plan backend.
macOS's packet filter (`pf`) is architecturally distinct from Linux
`nftables` and would need its own plan-only design, not a port. This document
also does not change any existing Linux or Windows acceptance record.
