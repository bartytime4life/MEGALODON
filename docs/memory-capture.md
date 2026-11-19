# Process memory

Fileless tools leave nothing on disk to scan. Instead they:
- load an ELF program image straight into memory;
- run code from a memory-only file (memfd);
- map a library from a temporary folder, or from a file they then delete;
- inject into a process that is already running.

ATT&CK covers these as T1620, T1055 and T1070.004. Once the process ends, or
is suspended and killed, that code is gone. `megalodon memory` finds it and
saves it first.

```bash
sudo megalodon memory sweep
```

```bash
sudo megalodon memory inspect PID
```

```bash
sudo megalodon memory capture PID --start START
```

* **`sweep`** inspects every process and reports what it finds, most severe
  first. It exits 1 on findings.
* **`inspect PID`** lists a process's executable memory regions, flags the
  suspicious ones and reports findings for them.
* **`capture PID`** saves a process's memory into a new evidence bundle under
  `~/.local/share/megalodon/evidence/` (or `--output`). By default it saves the
  suspicious regions; `--all` saves every readable region.
  - **`--start`** takes the start time from a finding. The capture refuses if
    that PID now names a different process.
  - **One process only.** Every read goes through one handle on that
    process. If its PID is reused partway through, the capture still reads the
    original process. If the original exits, the capture stops rather than
    save someone else's memory.
  - **Execute-only regions,** as loaders often leave an image, are saved too.
  - **The size limit** is 256 MiB by default; set it with `--limit-mb`.
    Regions that do not fit are listed as gaps.
  - **Contents:** the bundle holds the saved regions, the memory map, the
    process status, and a `manifest.json` with every file's SHA-256. The
    bundle is then made read-only, and the manifest's own SHA-256 is printed.
  - **`megalodon evidence verify BUNDLE`** checks it, as for any evidence
    bundle.
  - **The command line** is saved only with `--with-command-line`, because it
    can hold passwords and tokens.

Memory is read through `/proc/<pid>/mem`, which does not stop or change the
process. **A capture can hold passwords, keys and tokens the process had in
memory.** The bundle is readable only by its owner; handle it like the secrets
it may contain.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `MEMORY_ELF_IN_ANONYMOUS` | CRITICAL | An ELF program image sits in executable memory that no file backs, as reflective loaders and injected implants leave it |
| `MEMORY_EXECUTABLE_MEMFD` | HIGH | Code runs from a memory-only file |
| `MEMORY_EXECUTABLE_TEMPORARY` | HIGH | Code is mapped from `/tmp`, `/var/tmp` or `/dev/shm` |
| `MEMORY_EXECUTABLE_DELETED` | MEDIUM | Code runs from a file outside the system folders that was deleted after it was loaded. Libraries under `/usr`, `/lib` and `/opt` are left out, since updates replace them while programs run. |

`inspect` also lists two kinds of region without reporting them, because
just-in-time compilers in browsers, Java, Node.js and other runtimes make
them all the time:
- executable memory with no file behind it (`anonymous_executable`);
- memory that is both writable and executable (`writable_executable`).

## Response

* **code-loaded-into-memory** covers `MEMORY_ELF_IN_ANONYMOUS`. It plans to
  collect evidence, suspend that process by PID and start time, and notify you.
  Capture its memory first: suspending keeps the code in memory, but stopping
  the process loses it.
* **code-run-from-memory** covers the HIGH rules. It plans to collect evidence
  and notify you.

The [response engine](response-engine.md) sweeps memory on each pass only
with `memory_sweep = true` in `[response.sources]`. Some sandboxes and
runtimes run from memory on purpose, and would otherwise be reported on every
pass. The sweep is not scheduled for the same reason. Run it when you
investigate, or turn it on once you have reviewed what it reports on your
machines.

## Limits

* **Root is needed** to read other accounts' processes. Some sandboxes hide
  other processes' memory even from root; the report counts them as gaps.
* **Unchecked regions are listed as gaps.** That covers a region whose first
  bytes cannot be read, and processes with more than 4096 executable anonymous
  regions, beyond which the rest are not checked.
* **Only the first bytes of each anonymous executable region are checked** for
  an ELF header. Code without a header, such as shellcode or a stripped image,
  is listed by `inspect` but not reported.
* **Saved regions are raw memory.** Analyse them with your own tools, such as
  YARA, `strings` or a disassembler. MEGALODON does not run code from them.
