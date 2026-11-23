# Log integrity

Logs are the record of what happened. Wiping them is a common way to cover
tracks (ATT&CK T1070.002). `megalodon logwatch` notices when a system log is
deleted, cut short, swapped for another file or rewritten.

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
* **The systemd journal is not covered.** It rewrites its own header and
  rotates under new names. Use `journalctl --verify`, with forward-secure
  sealing (`journalctl --setup-keys`) for tamper evidence.
* **Without `--advance`, rotations add up.** Several rotations between
  checks may leave the recorded copy past `.1`. Siblings up to 64 per log are
  compared, but run `accept` after rotation to keep reports clean.
* **A root attacker can edit the baseline too.** Keep a copy off the machine,
  or send `--alert` summaries off it.
