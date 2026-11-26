# Log integrity

Logs are the record of what happened. Wiping them is a common way to cover
tracks (ATT&CK T1070.002). `megalodon logwatch` notices when a system log is
deleted, cut short, swapped for another file or rewritten, and when systemd
journal files are deleted, cut back or edited.

```bash
megalodon logwatch baseline
```

```bash
megalodon logwatch check
```

```bash
megalodon logwatch accept
```

* **`baseline`** records each log's identity in
  `~/.config/megalodon/log-integrity.json` (mode 600).
* **`check`** reports findings, plus normal rotations, which raise no finding.
  It exits 1 when anything is found and 2 on an error. With `--alert`, a
  summary also goes to your [off-machine alerts](off-machine-alerts.md).
  With `--advance`, every log without a finding is then recorded as it is
  now (see [below](#keeping-up-with-the-logs)).
* **`accept`** records the current logs as the new baseline, after you have
  reviewed a report or after rotation.

Run it as root to read every log. [`megalodon schedule install`](scheduling.md)
runs `logwatch check --alert --advance` every 15 minutes. By hand:

```bash
( sudo crontab -l 2>/dev/null; echo '*/15 * * * * /usr/local/bin/megalodon logwatch check --alert --advance >/dev/null' ) | sudo crontab -
```

Adjust the program path to where MEGALODON is installed for root.

## What it reports

| Finding | Severity | Meaning |
| --- | --- | --- |
| `LOG_DELETED` | HIGH | A recorded log is gone, and no rotated copy holds its earlier content |
| `LOG_TRUNCATED` | HIGH | The same file got smaller, and no rotated copy holds its earlier content |
| `LOG_REWRITTEN` | HIGH | The file kept or grew its size, but content it already had changed, such as one line removed from the middle. Logs only append. `changed_from_byte` is where the first changed piece starts |
| `LOG_REPLACED` | MEDIUM | A different file now has the log's name, and no rotated copy explains it |
| `LOG_PERMISSIONS` | MEDIUM | The log became writable by everyone, or changed owner |

Watched logs, where present: `auth.log`, `secure`, `syslog`, `messages`,
`kern.log`, `daemon.log`, `user.log`, `audit/audit.log`, `sudo.log`, `wtmp`,
`btmp`, `lastlog`, `faillog`, `dpkg.log`, `apt/history.log`, `yum.log`,
`dnf.log`, `cron` and `cron.log`. Logs the current user cannot read are
listed as gaps.

## The systemd journal

The same commands cover the systemd journal's files in `/var/log/journal`
and `/run/log/journal`. Each file's header
([format](https://systemd.io/JOURNAL_FILE_FORMAT/)) names the file, the
sequence its entries are numbered in, the first and last entry numbers and
the number of entries. Within a file those only grow, and an archived file is
never written again.

| Finding | Severity | Meaning |
| --- | --- | --- |
| `JOURNAL_FILE_DELETED` | HIGH | A recorded journal file is gone, and not as journald's vacuuming deletes them: archived files only, oldest first in their folder (by entry number within a sequence, by time across sequences). The file journald writes to is never vacuumed |
| `JOURNAL_ENTRIES_REMOVED` | HIGH | The same file holds fewer entries, its first entry number changed or its last one went back, or it is shorter than its header says |
| `JOURNAL_ARCHIVE_CHANGED` | HIGH | An archived (or `~` corrupt) file's content changed |

Files are followed by their file ID, so rotation to an `@` name is not a
change. The vacuum order is judged among archived files only, since
vacuuming never touches the files being written. `journalctl --vacuum-time=`
and `--vacuum-size=` rotate the active files first, then delete the oldest
archives. A vacuum that also deletes the files that were being written at the
previous check removes the newest records, and is reported: that is how
`journalctl` can be used to wipe the journal. These stay quiet, and are listed under `journals.explained`:
vacuuming, an empty file removed at rotation, and an in-memory journal
flushed to disk (when persistent files hold every entry number it held) or
cleared at boot. Files journald renamed with `~` after
finding them damaged are listed under `journals.corrupt`. Journal files that
cannot be read are listed under `journals.gaps` and keep their record.

The baseline stores each file's header fields and a SHA-256 digest of each
archived file, never journal content. A baseline made before journal support
records the journal at the next `accept` or check with `--advance`.

## Rotation stays quiet

logrotate renames a log (`auth.log` → `auth.log.1` or `auth.log-20261118`),
compresses it (`auth.log.1.gz`) or copies and truncates it (`copytruncate`).
A change is reported as *rotated*, not as a finding, when a sibling with one
of those names still holds the whole recorded content, unchanged. That also
covers a `copytruncate` log that has grown past its old size again. A rotated
copy that was emptied afterwards is reported as `LOG_TRUNCATED`, and one that
was edited as `LOG_REWRITTEN`, naming the copy. A log edited and then rotated
is not a rotation. Compressed siblings are read transparently.

## Keeping up with the logs

A check compares the logs with the baseline. Without `--advance`, lines
written after the baseline are not covered, and once logrotate deletes the
recorded copy, the log is reported as replaced or deleted until you run
`accept`.

With `--advance`, each log without a finding is recorded as it is after the
check. The next check then covers everything written up to this one, and a
rotation is followed instead of piling up. A log with a finding keeps its old
record, so it is reported at every check until you review it and run
`accept`. A log that cannot be read keeps its record too, even when a rotated
copy explains its absence, and is compared again once it can be read.

The logs as a check with `--advance` last saw them are kept beside the
baseline, in `~/.config/megalodon/log-integrity-progress.json` (mode 600),
and the next check compares with that. The baseline itself changes only at
`baseline` and `accept`, which also remove the progress file and start again
from the logs as they are. So the [tamper check](tamper-detection.md), which
watches the baseline, is not set off by every scheduled check, and still
reports a baseline that was changed.

The progress file is not watched, so it is not trusted on its own: anything
able to write MEGALODON's files could rewrite it to match a log it cut back.
The reviewed baseline is the floor. Every check also compares with the
baseline, and reports what the progress hid, with
`compared_with: the reviewed baseline`:

* each log that is still the same file (the same inode) as when you
  reviewed it: it can only have grown since, or its earlier content must be
  in a rotated copy;
* each log that is gone: a rotated copy must hold it;
* each journal file still present, by its file ID, with its digest taken
  from the review (while its inode, size and change times are the reviewed
  ones) or read again, never from the progress;
* each journal archive that is gone: journald deletes archives only by
  vacuuming, oldest first.

This has one cost. A log rotated by copying and emptying it in place
(logrotate's `copytruncate`) stays the same file, so once no rotated copy
holds what the baseline recorded, it is reported as truncated until you run
`accept`. So is a new log that the file system gave the old one's inode,
and a log no longer written at all once its rotated copies are deleted. The
finding says so. A log rotated the usual way (a new file) is followed by the
progress alone, and so is a journal file that was being written at the review.

## What is stored

For each log, the baseline stores its inode, device, size, owner, mode, a
SHA-256 digest of its first 4 KiB, and SHA-256 digests of its whole content
in pieces: 1 MiB each, or larger for a log over 128 MiB, so that a log has at
most 128. No log content is stored. `lastlog` and `faillog` are rewritten in
place on every login by design, so only their identity and size are compared.

A baseline made before the content digests compares only the first 4 KiB.
`accept`, or a check with `--advance`, records the digests.

## Limits

* **Only what was recorded.** Lines written since the last record (the last
  check with `--advance`, or `accept`) can be removed or changed unseen until
  then. With the schedule, that is the last 15 minutes. Forwarding logs to
  another machine, or auditd and journald sealing, cover them as they are
  written.
* **Rotated copies are followed, not watched.** Once a check with `--advance`
  has followed a rotation, `auth.log.1` and older copies are no longer
  compared.
* **Each check reads the logs in full.** That takes a moment for logs of
  hundreds of megabytes; the schedule runs it at low CPU and I/O priority.
* **Edits inside the journal file being written** that keep its entry count
  and numbers are not seen: that file changes all the time, so it is not
  hashed. Only once it is archived is its content fixed. Forward-secure
  sealing (`journalctl --setup-keys`, verified with the key kept off the
  machine) covers entries as they are written.
* **Deleting the oldest journal archives by hand looks like vacuuming,**
  down to deleting every archive while the active files stay. Only a deletion
  out of order, or of a file that was being written, is reported.
* **An archived journal is read again only when its size or change times
  change.** Writing to a file sets its change time, which cannot be set back
  without changing the system clock.
* **Without `--advance`, rotations add up.** Several rotations between
  checks may leave the recorded copy past `.1`. Siblings up to 64 per log are
  compared, but run `accept` after rotation to keep reports clean.
* **A root attacker can edit the baseline too.** Keep a copy off the machine,
  or send `--alert` summaries off it.
