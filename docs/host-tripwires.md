# Host tripwires: canary files and login review

Two host-side checks complement the network detectors. Both are explicit
operator commands that read local state, write nothing outside the paths you
name, contact no network service and take no action.

## Canary files

Canaries are bait files placed where an intruder or ransomware would look.
Nobody legitimate opens them, so any contact is worth investigating.

```bash
megalodon canary plant --dir ~/Documents/Finance --manifest ~/.config/megalodon/canary.json
```

```bash
megalodon canary check --manifest ~/.config/megalodon/canary.json
```

```bash
megalodon canary rearm --manifest ~/.config/megalodon/canary.json
```

`plant` writes up to five believable files (`passwords.txt`,
`ssh-key-backup.txt`, `wallet-recovery.txt`, `vpn-client.ovpn`,
`cloud-credentials.bak`). Each contains its own random marker and **no real
credential**. It never overwrites an existing file, and it records each
file's identity in an owner-private (0600) manifest. Keep the manifest
outside the bait directory; `plant` refuses otherwise.

`check` reports:

| Finding | Severity | Meaning |
| --- | --- | --- |
| `CANARY_REMOVED` | CRITICAL | The file was deleted, moved or renamed, or another file replaced it. |
| `CANARY_MODIFIED` | CRITICAL | Content, size, timestamps or permissions changed. This is the typical trace of ransomware encryption or tampering. |
| `CANARY_READ` | HIGH | The file was opened and read. |

`check` exits **1** when anything tripped, 0 when clean and 2 on an error, so
it can run from cron or a systemd timer and alert on a non-zero exit.

### How read detection works and where it is blind

After planting, each file's access time is set two days before its
modification time. Under Linux's default `relatime` mount option, the next
read updates the access time, and `check` sees that.

`check` itself never disturbs it. It uses `stat` and hashes content with
`O_NOATIME`, which the file's owner may use.

`plant` tests the target filesystem and reports `read_detection`. On
`noatime` mounts reads cannot be detected, but removal and change still are.
After you review a read, run `rearm` so the next read is detected again.

Backup, file indexing and antivirus tools also read files. Exclude the bait
directory from them, or expect benign `CANARY_READ` trips. A trip shows that
something touched the file, not who or why.

## Login review (`auth-review`)

```bash
megalodon auth-review --input /var/log/auth.log
```

```bash
journalctl _COMM=sshd _COMM=sudo -o short-iso --since "24 hours ago" | megalodon auth-review --input -
```

Use `/var/log/secure` on RHEL-family systems. Reading auth logs usually
requires membership in the `adm` group.

| Finding | Severity | Default trigger |
| --- | --- | --- |
| `AUTH_SUCCESS_AFTER_FAILURES` | CRITICAL | A login succeeded from an address with ≥ 5 failures in the previous hour |
| `AUTH_FAILURE_BURST` | HIGH | ≥ 6 failed logins from one address within 10 minutes |
| `PASSWORD_SPRAY` | HIGH | One address tried ≥ 4 different usernames within an hour |
| `SUDO_DENIED` | HIGH | A user who is not in sudoers tried sudo |
| `PRIVILEGE_GRANT` | HIGH | An account joined `sudo`, `wheel`, `admin`, `root`, `adm`, `docker`, `lxd`, `libvirt`, `disk` or `shadow` |
| `SUDO_FAILURES` | MEDIUM | ≥ 3 wrong sudo passwords by one user within 10 minutes |
| `ACCOUNT_CREATED` | MEDIUM | A new local account appeared |

`AUTH_SUCCESS_AFTER_FAILURES` is the signal to act on first: a guessed
password that worked.

Each finding repeats at most once per hour for the same subject. The command
exits **1** when any HIGH or CRITICAL finding exists, so it can drive
alerting.

### Feed attackers into the network watchlist

```bash
megalodon auth-review --input /var/log/auth.log --emit-watchlist ~/.config/megalodon/attackers.txt --replace
```

This writes the addresses behind brute-force, spraying and
success-after-failure findings (loopback excluded) to an owner-private
watchlist. Point `threat_detection.watchlist_path` at it, and every later
connection to or from those addresses raises `IOC_MATCH` in the network view.

### Parsing details and limits

- **Input formats:** classic syslog (`Nov 17 22:01:02 host sshd[1]: …`), high-precision ISO-8601 and `journalctl -o short-iso`.
- **Classic timestamps:** these carry no year or zone, so this computer's local time and the current year are assumed (a December line read in January rolls back a year). Pass `--utc` when the log was written in UTC.
- **Counting:** one connection that logs both `Invalid user X` and `Failed password for invalid user X` counts once. Repeated password guesses on one connection each count.
- **Untrusted usernames:** attackers choose them, so they are bounded to 64 printable characters and only reported as data.
- **Size and state limits:** input up to 64 MiB, lines up to 4 KiB (longer lines are counted and skipped), at most 50 000 tracked addresses, and at most 500 findings (`truncated` is set when the limit is hit).
- **Blind spots:** logins outside the supplied log (rotated files, other hosts, services that do not log through syslog) are invisible. A quiet log does not establish that a host is safe.
