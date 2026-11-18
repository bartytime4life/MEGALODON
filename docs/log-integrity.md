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
* **`accept`** records the current logs as the new baseline, after you have
  reviewed a report or after rotation.

Run it as root to read every log, from a timer shortly before your rotation
schedule, and `accept` after rotation:

```bash
( sudo crontab -l 2>/dev/null; echo '41 * * * * /usr/local/bin/megalodon logwatch check --alert >/dev/null' ) | sudo crontab -
```

Adjust the program path to where MEGALODON is installed for root.

## What it reports

| Finding | Severity | Meaning |
| --- | --- | --- |
| `LOG_DELETED` | HIGH | A recorded log is gone, and no rotated copy holds its earlier content |
| `LOG_TRUNCATED` | HIGH | The same file got smaller, and no rotated copy holds its earlier content |
| `LOG_REWRITTEN` | HIGH | The file kept or grew its size, but its beginning changed. Logs only append |
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
of those names still holds the recorded content: at least the recorded size,
starting with the recorded first bytes. That also covers a `copytruncate` log
that has grown past its old size again. A rotated copy that was emptied
afterwards is reported as `LOG_TRUNCATED`, naming the copy. Compressed
siblings are read transparently.

## What is stored

For each log, the baseline stores its inode, device, size, owner, mode and a
SHA-256 digest of its first 4 KiB. No log content is stored. `lastlog` and
`faillog` are rewritten in place on every login by design, so only their
identity and size are compared.

## Limits

* **Appended records are not checked.** It sees whole-file changes, not a
  single line removed from the middle of a log that kept growing. For that,
  forward logs to another machine, or use auditd and journald sealing.
* **The systemd journal is not covered.** It rewrites its own header and
  rotates under new names. Use `journalctl --verify`, with forward-secure
  sealing (`journalctl --setup-keys`) for tamper evidence.
* **Rotations add up.** Several rotations between checks may leave the
  recorded copy past `.1`. Siblings up to 64 per log are compared, but run
  `accept` after rotation to keep reports clean.
* **A root attacker can edit the baseline too.** Keep a copy off the machine,
  or send `--alert` summaries off it.
