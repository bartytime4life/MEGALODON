# Evidence collection

When an alert fires, the first minutes matter. A reboot, a cleanup or a
response action destroys what an investigator needs: which processes ran,
what they were connected to, and which files changed. `megalodon evidence
collect` saves that first, read-only, into a sealed bundle.

```bash
sudo megalodon evidence collect
```

```bash
megalodon evidence verify ~/.local/share/megalodon/evidence/20261118T232901Z --expected <manifest_sha256>
```

* **`collect`** writes a new folder under
  `~/.local/share/megalodon/evidence/` (or `--output`). It prints the bundle
  path and its `manifest_sha256`. `megalodon evidence push` copies the whole
  bundle, digest included, to the fleet collector
  ([evidence off the machine](evidence-shipping.md)). Without a collector,
  **keep that digest somewhere off the machine**, or pass `--alert` to send it to your
  [off-machine alerts](off-machine-alerts.md), as `EVIDENCE_COLLECTED`. The digest is sent whatever
  the alert minimum severity and detail level are; if alerts are off, `collect` says so and
  exits 1. Run it as root to see every process.
* **`verify`** re-checks every file against the manifest and, with
  `--expected`, the manifest against the digest you kept. It exits 1 if
  anything was changed, added or removed.

A collection takes under a minute, most of it the package check of
installed programs. `--skip-program-verification` skips that check.

## What is in a bundle

| File | Contents |
| --- | --- |
| `processes.json` | Each process: process and parent IDs, user, state, start time, program path, SHA-256 of the running program (even when its file was deleted), working folder and socket inodes. Command lines only with `--with-command-lines`, because they can contain passwords and tokens |
| `programs/` and `programs.json` | Copies of each running program whose file was **deleted**, that lives only **in memory** (`memfd`), or that runs from a **temporary folder**, read from `/proc/<pid>/exe`. This is often the only copy of a dropped tool. Each copy is checked against the running program's hash, stored read-only and never executable. `--no-program-copies` turns this off |
| `network.json` | Every TCP and UDP socket, including loopback: addresses, state, owner and the processes holding it |
| `sessions.json` | Logged-in users from utmp |
| `recent_files.json` | Files changed in the last `--hours` (default 24) in `/tmp`, `/var/tmp`, `/dev/shm`, `/etc`, program folders, `/usr/local`, systemd, cron, `/root`, `/home`, `/opt`, `/srv` and `/var/www`, with metadata, link targets and a SHA-256 of each file up to 16 MiB |
| `report_*.json` | The [persistence](persistence-watch.md), [listener](listener-watch.md) and [log](log-integrity.md) snapshots, the [program package check](binary-integrity.md), the reverse-shell review, and each watch's `check` against its baseline when one exists |
| `manifest.json` | Collection time, host, boot ID and uptime, options, counts, coverage gaps, and every file's size and SHA-256 |

After writing, every file is made read-only (400) and every folder unwritable
(500), so the bundle is not changed by accident.

## What it never does

It changes nothing on the machine. It starts no process, stops or signals
none, and deletes, moves or edits no file outside its own new bundle. A test
fails if the collector's code ever gains any of those abilities. It never
overwrites an existing bundle.

## Limits

* **It is a snapshot.** Anything that ran and ended before the collection is
  not in it, except in its traces (recent files, logs, persistence).
* **Root sees everything; others see their own processes.** The manifest
  lists what could not be read.
* **Bounded.** Program hashing stops at 4 GiB in all, recent-file hashing at
  512 MiB, program copies at 512 MiB, and the recent-file scan at 5,000 files
  or 500,000 entries, even inside a single folder. A file that
  grows while it is read is skipped with a reason, not read to its end.
  Reaching a limit is listed in the bundle's gaps.
* **No memory images.** Process memory and kernel state are not captured.
  Use a dedicated memory-forensics tool if you need them.
* **A root attacker can lie to the collector.** A kernel rootkit can hide
  processes and files from every program. The digest you keep off the
  machine proves the bundle was not changed afterwards, not that the
  machine told the truth.
* **Bundles contain sensitive data**: program copies that may be malware,
  file names, addresses and, with `--with-command-lines`, possible secrets.
  They are owner-only; store and share them as such.
