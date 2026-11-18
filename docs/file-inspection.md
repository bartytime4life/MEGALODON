# Inspect a downloaded program

In the local Linux HUD, choose **Inspect a file** beside the ClamAV Files
summary. Choose one file, then select **Inspect**. Selection alone sends
nothing. The HUD receives the selected bytes on localhost and reports
executable structure and identification clues, without launching the program.

Read **What this file is**, **Clues worth reviewing**, **What remains unknown**
and **Suggested next step**. Technical counts and each tool's completion are
under **Technical details and coverage**. A packing/compiler label is a
signature-based lead; legitimate files can share those features. No label,
absence of clues, or successful inspection establishes safety or malware.
The separate ClamAV aggregate does not prove this file was scanned.

Expand **Why this appears** beneath a clue to see the supporting observation,
its tool and completion state, a reviewed local explanation and its limits.
Writable/executable clues name the affected executable slices and region counts;
identification clues show the matching packer, protector, compiler or linker
labels. Packing and protection share one explanation. Missing tool results stay
visible as information gaps; a clue without supporting metadata receives no
inferred explanation. These disclosures use only the current report already in
the browser: opening them starts no request, analysis or AI operation. JSON export
is the version-2 metadata report, which adds the `rules` section described in
[Your own YARA rules](#your-own-yara-rules).

File inspection requires a signed-in local HUD. In the HUD's **Local sign-in**
section, select **Prepare protected launch** and copy the command. **Stop the
current HUD**, then run the copied command, keep its terminal open and sign in
at the new printed address. HUDs for this account share one managed evidence
store; choosing a different port does not release it. For a foreground HUD,
use **Ctrl+C** in its launch terminal. For the installed background HUD, follow the
[protected-launch handoff](local-pc-setup.md#optional-require-a-password-for-a-launch).
Stopping the HUD also stops its in-process collection. Setting a saved password
alone does not enable sign-in for a running HUD.
Sessions launched without sign-in cannot read inspection reports, receive an
inspection nonce, submit a file or request cancellation.

## Optional setup

Use **Install file inspector** through the existing authorized Setup installer,
then **Check inspector**. The fixed recipe downloads approximately 29 MB into
a private, versioned companion runtime. It does not start inspection, resolve
pip dependencies, replace system libraries, or install a desktop app. Core
MEGALODON dependencies remain empty. A changed/incomplete existing runtime is
preserved and refused; there is no silent overwrite or unconfined fallback.

Initial support is non-root Linux x86-64, glibc 2.38 or newer, Python 3.11/3.12,
Linux 6.3+ non-executable memfd support, bubblewrap with required user/PID/network
namespace features, libseccomp, dpkg-deb, cgroup v2 and a functioning user systemd
manager with memory/task controls. Check prerequisites through your operating
system's package manager. Inspector installation never changes kernel settings,
adds privileges, installs those prerequisites implicitly, or disables host policy.
Missing prerequisites or isolation restrictions refuse inspection.

The optional terminal equivalent, from the installed application's environment,
is:

```bash
~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.file_inspection_runtime
```

That is an explicit download/install action. Ordinary HUD startup, page loads,
status checks and restarts never download the inspector or scan a file.

## Your own YARA rules

The inspector can also apply YARA rules you write or choose. Put `.yar` or
`.yara` files in `~/.config/megalodon/yara-rules/`; each file becomes a
namespace named after the file. Install the pinned YARA runtime once, then
check the folder:

```bash
megalodon yara install
```

```bash
megalodon yara check
```

`check` reports the rule files, their combined digest and, when the runtime is
ready, whether the rules compile inside the sandbox (exit 1 when configured
rules cannot be used). The HUD then shows **YARA · your rules** beside the other
tools and a **Your YARA rule matched** clue that lists each matching
`namespace / rule` and its tags.

- Rules are read on the host into one bounded bundle (at most 64 files, 1 MiB
  each, 4 MiB together; UTF-8 text). The folder and each file must be owned by
  you and not writable by others. Links, FIFOs, devices, unsafe names and
  duplicate namespaces refuse the whole bundle rather than silently dropping a
  rule. Hidden files and other extensions are ignored.
- The bundle is copied into sealed anonymous memory. Compilation and matching
  happen only inside the same confined sandbox as the sample, with the same
  limits, no threads and a separate 15-second deadline (10-second match
  timeout). `include` is disabled, so a rule cannot read other files, and
  `console` module output is discarded. Nothing on the host imports YARA.
- Only rule identifiers, namespaces and up to 16 tags per match leave the
  sandbox, with the compiled rule count and the number matched (at most 32
  matches are listed, in a stable order). Matched strings, offsets and rule
  metadata are never reported, because they can carry arbitrary text.
- Rules read bytes, not structure, so they also check scripts, documents and
  other files the structural tools do not support. Such a file with a completed
  rule scan is reported as **Partial coverage**.
- The rules section's state is `completed`, `not_configured` (no folder or no
  rule files), `unavailable` (runtime missing or changed), `invalid_rules`
  (refused folder or a rule that does not compile), `failed`, `timed_out` or
  `cancelled`. Configured rules that cannot run make the inspection partial;
  an empty or absent folder changes nothing.

A match is as good as the rule that produced it: it is a lead to review, not a
malware verdict, and no match does not mean the file is safe.

The YARA runtime is pinned separately in `megalodon/assets/yara-runtime.json`
(yara-python 4.5.4 wheels for CPython 3.11 and 3.12, by size, SHA-256 and
extracted file-set digest) and installs to
`~/.local/share/megalodon/support/file-inspector/yara-v1-cpXY`. Only the
extension module, its bundled crypto library and the license are extracted;
the LIEF and Detect It Easy pins are unchanged. yara-python is Apache-2.0 (its
license file is retained); the YARA engine it embeds is BSD-3-Clause, and the
wheel bundles an OpenSSL 1.1 `libcrypto`, which upstream no longer maintains and
which runs only inside the sandbox
([yara-python 4.5.4](https://pypi.org/project/yara-python/4.5.4/)).

## Coverage and limits

The first version supports ELF executable/shared objects, PE EXE/DLL, and thin
or universal Mach-O executable/library files. Object files, core dumps,
archives, APKs, scripts and firmware extraction are unsupported. Identification
uses the pinned basic Detect It Easy database; recursive, deep, aggressive and
heuristic modes and custom/extra signature paths are disabled. Universal
Mach-O is limited to 16 non-overlapping, complete executable slices; incomplete
structural coverage is refused rather than silently reporting only one slice.

- One file/job per HUD; input 1 byte–64 MiB; upload deadline 10 seconds with a
  0.5-second socket inactivity limit; analysis deadline 30 seconds total, plus
  15 seconds for your YARA rules when configured.
- Separate confined adapters, 15 CPU seconds each and 64 KiB output each;
  normalized report at most 64 KiB. LIEF address space is capped at 512 MiB.
- Detect It Easy's QtScript engine reserves 2 GiB of virtual address space.
  The operator approved a 2.5 GiB address-space cap for this adapter, with a
  separately verified cgroup hard memory cap of 512 MiB, zero swap and at most
  32 tasks. Missing cgroup enforcement fails before starting the adapter.
- Both adapters have no network or host sockets, no home-directory access,
  read-only runtime/input, empty environment, restricted process creation,
  disabled core dumps and a 1 MiB disposable temporary filesystem.
  LIEF cannot create threads or processes; DIE can create only threads within
  its independently checked 32-task cgroup limit.

Each report lists `completed`, `unavailable`, `unsupported`, `failed`,
`timed_out` or `cancelled` for each adapter. One successful adapter and one
failure yields **Partial coverage**, retaining the successful metadata.
Unsupported input yields an unsupported report; the enclosing job is marked
failed because no supported inspection completed.

**Cancel inspection** remains reachable during receipt and parsing. The job
slot stays occupied until receipt exits or the worker namespace is reaped.
Disconnect during upload aborts it. Once a complete upload is accepted, closing
the tab does not cancel the bounded authorized job; its latest report can be
read again during the same HUD process. Shutdown cancels work. Restart never
resumes it.

## Privacy, persistence and action boundaries

The submitted filename stays in browser presentation. Requests accept bytes,
not server paths, URLs, filenames, command arguments or model-selected tools.
No file hashes, strings, disassembly, raw tool diagnostics or full identification
output enter the report. Only allowlisted format/architecture/structural counts
and bounded compiler/packer/protector/linker labels cross the worker boundary.
Explanations are fixed local text; no AI or external submission occurs.

Raw input uses sealed anonymous memory and read-only anonymous sandbox data;
there is no intentional raw-file disk persistence. Anonymous memory may be
swapped by the operating system outside the adapter's zero-swap cgroup. This
feature does not promise forensic erasure or protection against a compromised
operator account or kernel. No sample bytes, raw diagnostics or result history
are written into core telemetry, application logs or the inspector runtime.

The last normalized report exists only in the HUD's memory. **Export JSON**
downloads that report only, without the sample, filename/path, sample digest,
operator token or job envelope. A previous report is labeled separately from a
new selection. No automatic firewall, quarantine, deletion, unpacking or
program execution is added.

## Dependency evidence

The packaged `megalodon/assets/file-inspection-runtime.json` pins release URLs,
sizes and SHA-256 identities for LIEF 1.0.0 wheels, Detect It Easy 3.21's Ubuntu
24.04 archive, and the Qt 5.15.13/ICU 74.2 runtime libraries from Ubuntu Noble.
Only regular CLI/basic-database/library/license files are selected. Package
maintainer scripts, GUI launchers, plugins and extra databases are not run or
installed. Exact file-set digests cover both CPython profiles. The optional
runtime has no effect on the existing reviewed core CI lock profiles.
These checks establish byte identity against the catalog, not signed publisher
provenance, an independent source audit or absence of vulnerabilities.

Primary sources: [LIEF releases](https://github.com/lief-project/LIEF/releases/tag/1.0.0),
[Detect It Easy 3.21](https://github.com/horsicq/DIE-engine/releases/tag/3.21),
[Qt base source](https://packages.ubuntu.com/noble/libqt5core5t64),
[Qt Script source](https://packages.ubuntu.com/noble/libqt5script5),
[ICU source](https://packages.ubuntu.com/noble/libicu74).
LIEF is Apache-2.0 and Detect It Easy is MIT. Original Qt/ICU copyright and
license notices are retained in the private runtime. Qt remains dynamically
linked; the linked Ubuntu pages provide the corresponding source packages.

## Validation boundaries

Focused tests use synthetic executable headers, bounded mock failures and real
localhost HTTP. Opt-in native tests use the exact private runtime and kernel
isolation; they never read personal downloads. Browser acceptance exercises the
shipped UI at desktop/mobile sizes. These establish the named behavior, not
malware-detection accuracy, a host-clean verdict, independent review, merge,
release or installed-HUD acceptance.
