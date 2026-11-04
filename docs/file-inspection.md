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

## Coverage and limits

The first version supports ELF executable/shared objects, PE EXE/DLL, and thin
or universal Mach-O executable/library files. Object files, core dumps,
archives, APKs, scripts and firmware extraction are unsupported. Identification
uses the pinned basic Detect It Easy database; recursive, deep, aggressive and
heuristic modes and custom/extra signature paths are disabled. Universal
Mach-O is limited to 16 non-overlapping, complete executable slices; incomplete
structural coverage is refused rather than silently reporting only one slice.

- One file/job per HUD; input 1 byte–64 MiB; upload deadline 10 seconds with a
  0.5-second socket inactivity limit; analysis deadline 30 seconds total.
- Separate confined adapters, 15 CPU seconds each and 64 KiB output each;
  normalized report at most 64 KiB. LIEF address space is capped at 512 MiB.
- Detect It Easy's QtScript engine reserves 2 GiB of virtual address space.
  The operator approved a 2.5 GiB address-space cap for this adapter, with a
  separately verified cgroup hard memory cap of 512 MiB, zero swap and at most
  32 tasks. Missing cgroup enforcement fails before starting the adapter.
- Both adapters have no network or host sockets, no home-directory access,
  read-only runtime/input, empty environment, restricted process creation,
  disabled core dumps and a 1 MiB disposable temporary filesystem.

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
