# Persistence watch

After getting in, an attacker makes sure they can get back in, through a
service, a scheduled job, a startup script, an SSH key or a hidden setuid
program. `megalodon persistence` records those places once, then reports
everything that changes.

```bash
megalodon persistence baseline
```

```bash
megalodon persistence check
```

```bash
megalodon persistence accept
```

```bash
megalodon persistence scan
```

* **`baseline`** records the current state in
  `~/.config/megalodon/persistence.json` (mode 600). Take it on a system you
  trust. Entries with [signs of an intruder's](#signs-of-an-intruders-entry)
  are listed under `suspicious`, and the command then exits 1: they are
  recorded, but not without being reported.
* **`check`** reports every entry added, changed or removed since the
  baseline, most severe first. It exits 1 when anything changed and 2 on an
  error. With `--alert`, a one-line summary also goes to the
  [off-machine alerts](off-machine-alerts.md) configured in the settings
  file.
* **`accept`** records the current state as the new baseline once you have
  reviewed the changes, for example after a software update. It lists
  suspicious entries as `baseline` does.
* **`scan`** lists entries with signs of an intruder's now, reading and
  writing no baseline. It exits 1 if there are any.

Run `check` from cron or a systemd timer, or let the
[scheduler](scheduling.md) do it. Run as root, it covers every account's home
folder, not only root's: see [every account's home](#every-accounts-home). Run
as an ordinary user, it covers that user's own home, and lists the other homes
as a gap.

```bash
( crontab -l 2>/dev/null; echo '23 * * * * $HOME/.local/share/megalodon/current/venv/bin/python -I -m megalodon persistence check --alert >/dev/null' ) | crontab -
```

## What is watched

| Category | Locations | ATT&CK | Severity |
| --- | --- | --- | --- |
| systemd | `/etc/systemd/system`, `/etc/systemd/user`, `/usr/local/lib/systemd/system`, `~/.config/systemd/user` (units, timers and enablement links) | T1543.002 | MEDIUM |
| cron | `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron`, `/etc/anacrontab` | T1053.003 | MEDIUM |
| at | `/var/spool/cron/atjobs`, `/var/spool/at` | T1053.002 | MEDIUM |
| autostart | `/etc/xdg/autostart`, `~/.config/autostart` | T1547.013 | MEDIUM |
| shell startup | `~/.bashrc`, `~/.profile`, `~/.zshrc` and similar; `/etc/profile`, `/etc/profile.d`, `/etc/bash.bashrc`, `/etc/zsh`, `/etc/environment` | T1546.004 | MEDIUM |
| ssh | `authorized_keys` (yours and root's; as root, every account's), `~/.ssh/rc`, `/etc/ssh/sshd_config` and `sshd_config.d` | T1098.004 | HIGH; CRITICAL for a new key |
| preload | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d` | T1574.006 | CRITICAL |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d` | T1548.003 | HIGH |
| pam | `/etc/pam.d`, `/etc/security/pam_env.conf` | T1556.003 | HIGH |
| init | `/etc/rc.local`, `/etc/init.d`, `/etc/udev/rules.d` | T1037.004 | MEDIUM |
| kernel modules | loaded modules (`/proc/modules`), `/etc/modules`, `/etc/modules-load.d`, `/etc/modprobe.d` | T1547.006 | HIGH (new module) |
| setuid | setuid/setgid programs in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/*bin`, `/usr/lib`, `/usr/libexec`, `/opt` | T1548.001 | HIGH |
| accounts | `/etc/passwd`: new accounts; a new UID 0; a login shell given to a service account | T1136.001 | MEDIUM; HIGH; CRITICAL for UID 0 |

Removals are reported as LOW.

## Signs of an intruder's entry

What an entry runs is read for a few signs that are rare in legitimate
entries and common in an intruder's. Only the lines it runs are read: a
unit's or autostart file's `Exec` lines, a crontab's commands, a udev rule's
`RUN`, and every line of a script, an at job, a shell startup file or
`~/.ssh/rc`. Comments and settings are skipped. A program counts as run when it
starts a command (after `;`, `&&`, `|`, `$(`), when it is handed to a shell or
interpreter as a script (also on its input, `sh < file`), or when it is run
from a `sh -c "..."` string (also combined options such as `-ec` or `-lc`).
Each interpreter's own options are read, up to the script: a shell's
`-o errexit` or `--rcfile FILE`, Python's `-W`, Ruby's and Perl's `-I DIR`
take an argument, while Python's `-I` does not; Perl's `-e`, Python's `-c`
and `-m` run code, not a file. Whatever follows the script is the script's
own arguments. A file a command writes to or reads from
(`> /tmp/log`, `< /tmp/input`) is not a program it runs.

| Sign | Severity | What it means |
| --- | --- | --- |
| `runs_from_temporary` | HIGH | A program is run from `/tmp`, `/var/tmp` or `/dev/shm`, or the entry is a link into one |
| `runs_from_hidden_folder` | HIGH | A program is run from a hidden folder in a system location, such as `/var/lib/.cache/agent` |
| `download_into_shell` | HIGH | A download (`curl`, `wget`...) is piped into a shell or interpreter, or substituted where its output is run: as the command (also behind `nohup`, `env`, `sudo` or `VAR=value`), by `eval`, by `sh -c` or `sh -ec`, or through `source <(...)` or `sh <(...)`. A download stored in a variable or passed as an argument is not |
| `decoded_into_shell` | HIGH | `base64 -d` (or base32) output is piped into a shell |
| `shell_network_redirect` | CRITICAL | A shell opens a network connection through `/dev/tcp` or `/dev/udp` |
| `preload_library` | CRITICAL | `/etc/ld.so.preload` lists a library: every program loads it |
| `second_uid_0` | CRITICAL | An account other than `root` has UID 0 |

Each sign is stored as its name and line number, never the line. An added or
changed entry with a sign is reported at the sign's severity, if that is
higher than its category's. A baseline taken before entries were read for
signs never reviewed them: `check` lists the entries that have one under
`suspicious` until you run `accept`.

On this project's test machine, 775 legitimate files (every vendor systemd
unit, the init scripts, udev rules, cron jobs, shell startup files and shell
scripts in `/usr/bin` and `/usr/sbin`) showed no sign.

## Every account's home

The `~/` locations above are your own home folder. Run as root, each one is
also read in every other account's home, as `/etc/passwd` gives it. Each such
entry is recorded under that account's name: `~alice/.ssh/authorized_keys`,
`~bob/.config/systemd/user/helper.service`. A key added to another account's
`authorized_keys`, or a user service dropped in their home, is reported like
one in root's.

* **Which homes.** Each account whose home is a real folder, once each. If
  two accounts share a folder, the one with the lower UID names it. Homes of
  `/`, `/nonexistent`, or folders under `/proc`, `/sys`, `/dev` or `/run`
  are not homes, and are skipped. So are account names that `useradd` would
  refuse. Service accounts with a real home, such as `postgres` in
  `/var/lib/postgresql`, are included: a key added there is just as much a
  way back in. `baseline` lists the homes it covered under `homes`.
* **An older baseline.** A baseline taken before this, or taken without
  root, never read the other homes. Their files are not reported as added.
  `check` lists them under `newly_watched`: each account, its home, how many
  entries it has, and the fingerprints of the SSH keys already there. Review
  those, then run `accept`. Until you do, changes in those homes are not
  compared.
* **A new account.** An account created after the baseline is reported as an
  added account, and the entries in its home as added.
* **Without root.** Other accounts' homes cannot be read. They are listed as
  a gap, and what the baseline recorded there is not reported as removed.
* **Response.** The [response engine](response-engine.md) joins a finding in
  `~alice/` to alice's other findings, such as her logins. With the
  `new-persistence-entry` playbook, [enforcement](enforcement.md) can disable
  an added entry in any account's home, and puts it back on undo.

## What is recorded

Only metadata is stored: a content digest, size, line count, mode, owner,
the [signs](#signs-of-an-intruders-entry) found (name and line number) and,
for links, the link target. Links are recorded, never followed. For SSH keys,
the key type, a SHA-256 fingerprint and the comment are stored, so a report
can name the new key. For accounts, the name, UID, GID, home folder and shell
are stored. File contents are never copied into the baseline or a report.

Locations the current user cannot read, such as `/etc/sudoers.d` for an
ordinary user, are listed under `gaps` rather than silently skipped. The
baseline file must be a regular file owned by you with mode 600. Links, FIFOs
and shared files are refused. Nothing on the system is changed or removed.

## Limits

* **Changes since the baseline only.** Persistence that was already present
  when the baseline was taken is part of the baseline, and reported only if it
  carries one of the signs above. An intruder's entry that looks ordinary,
  such as a service running a program installed under `/usr/local/bin`, is
  recorded like any other. Take the baseline on a freshly installed or
  otherwise trusted system.
* **Signs are read from the text.** A command built at run time (from
  variables or an encoded string) or run by another script the entry calls is
  not followed.
* **Updates change things.** Package updates change units, PAM files and
  setuid programs too. Review the report, then run `accept`.
* **Folder coverage.** Files are hashed up to 4 MiB. The setuid scan stops
  after 400,000 files and says so. Persistence outside these folders, such as
  a modified program or browser extensions, is not covered. Use
  [host security](host-security.md) for file integrity.
* **A root attacker can hide.** Someone with root can also edit the baseline,
  or hide from `/proc`. Keep a copy of the baseline off the machine, or send
  `--alert` summaries off it.
