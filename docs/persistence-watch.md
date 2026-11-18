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

* **`baseline`** records the current state in
  `~/.config/megalodon/persistence.json` (mode 600). Take it on a system you
  trust.
* **`check`** reports every entry added, changed or removed since the
  baseline, most severe first. It exits 1 when anything changed and 2 on an
  error. With `--alert`, a one-line summary also goes to the
  [off-machine alerts](off-machine-alerts.md) configured in the settings
  file.
* **`accept`** records the current state as the new baseline once you have
  reviewed the changes, for example after a software update.

Run `check` from cron or a systemd timer. Run it as root to cover every
account's files, and as each user for their own home folder.

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
| ssh | `authorized_keys` (yours and root's), `~/.ssh/rc`, `/etc/ssh/sshd_config` and `sshd_config.d` | T1098.004 | HIGH; CRITICAL for a new key |
| preload | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d` | T1574.006 | CRITICAL |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d` | T1548.003 | HIGH |
| pam | `/etc/pam.d`, `/etc/security/pam_env.conf` | T1556.003 | HIGH |
| init | `/etc/rc.local`, `/etc/init.d`, `/etc/udev/rules.d` | T1037.004 | MEDIUM |
| kernel modules | loaded modules (`/proc/modules`), `/etc/modules`, `/etc/modules-load.d`, `/etc/modprobe.d` | T1547.006 | HIGH (new module) |
| setuid | setuid/setgid programs in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/*bin`, `/usr/lib`, `/usr/libexec`, `/opt` | T1548.001 | HIGH |
| accounts | `/etc/passwd`: new accounts; a new UID 0; a login shell given to a service account | T1136.001 | MEDIUM; HIGH; CRITICAL for UID 0 |

Removals are reported as LOW.

## What is recorded

Only metadata is stored: a content digest, size, line count, mode, owner and,
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
  when the baseline was taken is part of the baseline. Take it on a freshly
  installed or otherwise trusted system.
* **Updates change things.** Package updates change units, PAM files and
  setuid programs too. Review the report, then run `accept`.
* **Folder coverage.** Files are hashed up to 4 MiB. The setuid scan stops
  after 400,000 files and says so. Persistence outside these folders, such as
  a modified program or browser extensions, is not covered. Use
  [host security](host-security.md) for file integrity.
* **A root attacker can hide.** Someone with root can also edit the baseline,
  or hide from `/proc`. Keep a copy of the baseline off the machine, or send
  `--alert` summaries off it.
