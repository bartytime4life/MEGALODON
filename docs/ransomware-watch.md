# Ransomware watch

`megalodon ransomware watch` watches folders you choose and raises an alarm
while files are being encrypted. It doesn't wait for the ransom note. It runs
on Linux, uses inotify and needs no extra package.

```bash
megalodon ransomware selftest
```

```bash
megalodon ransomware watch --dir ~/Documents --dir ~/Pictures --dir /srv/share
```

`selftest` encrypts throwaway files in a temporary folder and confirms both
alarms fire. Run it after installing and after changes. `watch` runs until you
stop it. It prints each finding as one JSON line, and sends it to your
[off-machine alerts](off-machine-alerts.md) when `[alerts]` is configured in
`~/.config/megalodon/settings.toml` (or the file given with `--config`), so a
phone push or SIEM still gets it if the machine is lost.

## What raises the alarm

| Finding | Severity | When |
| --- | --- | --- |
| `RANSOMWARE_ENCRYPTION` | CRITICAL | At least `--min-files` (default 10) files turned from a recognized format into encrypted-looking data within `--window` seconds (default 60) |
| `RANSOMWARE_MASS_WRITE` | HIGH | Three times that many new encrypted-looking files with no recognized predecessor in one window |
| `RANSOM_NOTE` | HIGH | A file named like a ransom note was created (`_readme.txt`, `HOW_TO_DECRYPT.txt`, `!!!READ_ME_TO_DECRYPT!!!.txt`, `RESTORE_FILES.html`, ...) |

All three map to ATT&CK T1486 (Data Encrypted for Impact).

* **How a file is judged.** The first 64 KiB of each written file is sampled.
  It counts as *recognized* when it starts with a known format signature
  (PDF, Office/ZIP, JPEG, PNG, GIF, audio and video, gzip, 7z, SQLite,
  executables and more) or is readable text. It counts as *encrypted-looking*
  when it has no signature, isn't text and its byte entropy is at least
  7.5 bits per byte. Files under 1 KiB are not judged.
* **What counts toward the alarm.** An encrypted-looking write counts when:
  * the same file was recognized before, which is in-place encryption;
  * it replaces a file just deleted or renamed in the same folder: the same
    name, the old name plus an extension (`report.docx.locked`) or the same
    stem with a new extension; or
  * it carries a ransomware extension (`.locked`, `.crypt`, `.encrypted`, ...).

  The watch records what existing files look like when it starts, so
  in-place rewrites can be compared.
* **Who is doing it.** Each finding lists, best effort, the processes that
  held files open under the watched folders while encrypted-looking files
  were written, read from `/proc`. Ransomware closes each file as it goes, so
  the watch looks every time such a file is written (at most five times a
  second) and keeps what it saw for the window, not only at the alarm. Each
  process is named by process ID, start time, name and program path, so one
  process can be paused without pausing everything else running the same
  program. `writing` says whether it held one of those files open for
  writing. `samples` says how often it was seen. Writers come first. Run as
  an ordinary user, the watch sees that user's processes. Run it as root to
  see everyone's.
* **Acts only with `--respond`.** On its own, the watch blocks, kills and
  restores nothing. With `--respond`, each finding goes to the
  [response engine](response-engine.md) and then to
  [enforcement](enforcement.md) as soon as it is raised. See
  [answer it at once](#answer-it-at-once). Either way, on an alarm, take the
  machine off the network, stop the listed process and restore from an
  offline backup.

Everyday activity does not count: new or copied photos, archives and Office
files all carry signatures, text edits stay text, and an ordinary
`README.txt` is not a ransom note. The tests check this with a mixed burst.

## Run it all the time

Save the folders once, then let the [scheduler](scheduling.md) keep the watch
running:

```bash
sudo megalodon ransomware init --dir /home --dir /srv
```

```bash
sudo megalodon schedule install --yes
```

`init` writes `~/.config/megalodon/ransomware.json` (mode 600), with
`--min-files` and `--window` if you give them. The watch refuses the file
unless you own it and nobody else can change it, because whoever can edit it
chooses what is watched. `watch` without `--dir` reads it. `--folders-file`
names another file. The `megalodon-ransomware` service runs
`ransomware watch --respond` and starts again if it stops. As root, it sees
every account's processes.

Findings appear in `journalctl -u megalodon-ransomware` (or
`journalctl --user -u megalodon-ransomware` for a user unit), and in your
configured alerts.

## Answer it at once

When separately installed and running, the [response engine](response-engine.md)'s
timer reads the other checks every five minutes, and the
[enforcement](enforcement.md) timer schedules a pass every minute. Those timers
are separate from the watch. With `--respond`, the watch decides each finding as
soon as it is raised, then hands it to enforcement before reading the next file
event:

```bash
megalodon ransomware watch --dir ~/Documents --respond
```

1. The finding is decided under the response policy, with the same guards and
   ledger as the timer's pass. The default `ransomware` playbook plans to
   collect evidence, pause each process seen writing in the watched folders,
   and send a notice. A process seen only reading, such as a viewer or a
   backup, is listed but never paused.
2. New enforcement carries out only what `~/.config/megalodon/enforce.toml`
   allows: enforcement must be on, and
   `suspend_process` and the `ransomware` playbook must be listed. The pause
   is SIGSTOP to the exact process, checked again by PID and start time. The
   process keeps its memory for [capture](memory-capture.md), and
   `megalodon enforce undo ID` resumes it.
3. What was decided and done is written to standard error as one
   `megalodon: response {...}` line, beside the start message. Standard output
   stays one finding per line.

A policy that cannot be read is reported on that line, and the watch keeps
watching and alerting. A ransom note alone matches no playbook, so it creates no
new action. Existing suspension recovery is separate from that decision.

Turn it on for real like this:

```bash
megalodon respond init
```

```bash
megalodon enforce init
```

Then, in `~/.config/megalodon/enforce.toml`, set `enabled = true`, add
`"suspend_process"` to `actions` and `"ransomware"` to `playbooks`. Run
`megalodon ransomware selftest` and `megalodon drill` afterwards.

### Recovery while the watch is running

With `--respond`, the watch checks for due suspension expirations at startup
and at 30-second intervals measured by a monotonic clock. It checks during
quiet polling and between events in a busy batch. This periodic callback runs
only recovery; it does not ingest findings or apply new enforcement decisions.
Ordinary `watch` without `--respond` does not run it.

Recovery reads the existing enforcement journal even when the enforcement
policy is missing, disabled or invalid, or no finding produces a new decision.
Failed SIGCONT attempts leave the hold available for another attempt. The
normal PID, start-time and pidfd checks still apply. A suspension with no finite
expiry remains active until explicitly undone.

Periodic recovery results and errors appear as `megalodon: recovery {...}` on
standard error, leaving standard output as finding JSON lines. Successful
checks with nothing due do not emit a recovery line. An expired hold is not
necessarily a resumed process: another hold can keep that process paused, or
the original process may have exited or been replaced. Read each result's
`status` and `note`. If the signal outcome could not be persisted,
`recovery_status` and `journal_error` retain the distinction between the
recovery operation and its audit failure. Per-finding output also preserves
expiry results and policy errors; a finding that produces no decision can
still report a separate `recovery` result.

These checks are best effort while the watch keeps running. Startup work, a
blocked event handler or recovery operation, scheduling delays, and interruption
can delay them; there is no independent watchdog or maximum resume deadline.
Stopping the watch leaves recovery to a later invocation or a separately
running enforcement timer that uses the same account and journal. The scheduler's
enforcement job is root-only; a user ransomware watch does not receive a user
enforcement timer automatically, and a root timer does not read that user's
default journal. Source and synthetic checks do not establish real systemd
service recovery; see [recovery acceptance](enforcement-recovery-acceptance.md).

## Limits

* **It's an alarm, not prevention.** Some files are encrypted before the
  threshold is reached: about `--min-files`, plus whatever is written while
  you respond. Keep offline or versioned backups.
* **Coverage is what inotify sees.** Hidden folders (starting with `.`) are
  skipped. At most 8,192 folders are watched; the start message says when that
  limit cut coverage, and the kernel's `fs.inotify.max_user_watches` may need
  raising. Network shares only report changes made from this machine. Changes
  made while the watch is not running are not seen.
* **Partial or format-preserving encryption.** Ransomware that leaves the
  first 64 KiB intact, or wraps its output in a recognized container, is not
  judged encrypted. A ransom note or `MASS_WRITE` may still fire.
* **Look-alikes.** Encrypting many of your own files (GnuPG, `age`, VeraCrypt
  containers, encrypted backups written into a watched folder) looks exactly
  like this. Point the watch at the folders you care about, not at backup
  destinations.
* **Process list.** The list is best effort. A process that did not hold a
  watched file open at any of the watch's looks is not listed, and a process
  that does all its work through another one, such as a file server writing
  for a remote client, is listed as that other one. Being listed as writing
  never proves which process wrote what. A legitimate writer caught in the
  same window, such as an editor saving a document, is paused too. Undo it
  with `megalodon enforce undo ID`.
* **One process per decision.** A pause stops the processes listed. A child
  started after the alarm, or another program it hands the work to, keeps
  going until a later finding names it, and the same alarm is raised at
  most once every five minutes. Disconnect the machine as well.
