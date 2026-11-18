# Program integrity

An attacker with root can replace `sshd`, `sudo`, `ps` or `ls` with a
backdoored copy, or swap a PAM module or `libkeyutils` for one that steals
passwords. Every other check would then keep trusting them.
`megalodon binaries` finds programs and libraries that were changed.

```bash
sudo megalodon binaries verify
```

```bash
sudo megalodon binaries baseline
```

```bash
sudo megalodon binaries check
```

```bash
sudo megalodon binaries accept
```

* **`verify`** needs no baseline. It compares every installed program, and
  the libraries attackers usually backdoor, with the checksums their Debian
  package recorded, as `dpkg --verify` does. A machine that was already
  trojaned before MEGALODON ran is caught on the first run.
* **`baseline`** records a SHA-256 of every program, packaged or not, in
  `~/.config/megalodon/binaries.json` (mode 600). It also prints what
  `verify` finds; review those before trusting the baseline.
* **`check`** runs `verify`, then reports what changed since the baseline.
  A program changed by a package upgrade is listed under `updated` and is
  not a finding.
* **`accept`** records the current programs as the new baseline after you
  have reviewed a report.

Every command exits 1 when it has findings and 2 on an error. `verify` and
`check` take `--alert` to send a summary to your
[off-machine alerts](off-machine-alerts.md). `--all-libraries` verifies every
packaged shared library, not only the commonly backdoored ones; it takes
longer.

Run it as root so every program can be read, from a daily timer:

```bash
( sudo crontab -l 2>/dev/null; echo '29 3 * * * /usr/local/bin/megalodon binaries check --alert >/dev/null' ) | sudo crontab -
```

Adjust the program path to where MEGALODON is installed for root.

## What it reports

| Finding | Severity | Meaning | ATT&CK |
| --- | --- | --- | --- |
| `PACKAGE_MISMATCH` | CRITICAL or HIGH | A packaged program or library no longer matches its package | T1554, plus T1014 for tools used to look at the system |
| `PACKAGE_RECORD_CHANGED` | HIGH | A program and its package's checksum record both changed, but the package was not upgraded | T1554 |
| `PROGRAM_ADDED` | HIGH, or MEDIUM under `/usr/local` | An unpackaged program appeared in a program folder | T1036.005 |
| `PROGRAM_CHANGED` | MEDIUM | An unpackaged program's content changed | T1554 |
| `PROGRAM_WRITABLE` | HIGH | A program is writable by everyone, or is not owned by root | T1574.010 |
| `PACKAGE_FILE_MISSING` | LOW | A packaged program or critical library was removed | T1554 |

`PACKAGE_MISMATCH` is CRITICAL for programs that control logins, privileges
or what an administrator sees:
* `sshd`, `sudo`, `su`, `login`, `passwd`, `cron`, `systemd` and the shells;
* `ps`, `ls`, `netstat`, `ss`, `lsof`, `top`, `find`, `who` and `last`;
* PAM modules, the dynamic loader, `libc` and `libkeyutils` (as in Ebury);
* `liblzma` (as in the xz backdoor) and similar libraries.

`PACKAGE_RECORD_CHANGED` catches an attacker who edited the package's
checksum list (`/var/lib/dpkg/info/*.md5sums`) to match the trojaned file.
`verify` alone can't see that, but the baseline remembers which package
version each program came from.

## What is covered

* **Programs:** executable files in `/usr/bin`, `/usr/sbin`, `/usr/local/bin`,
  `/usr/local/sbin` and `/usr/libexec`, and any packaged executable under
  `/usr`, `/lib` or `/opt`. `/bin` and `/sbin` are usually links to `/usr`; real
  paths are compared, so each file counts once.
* **Libraries:** PAM modules, and the loader, `libc`, `libpam`, `libkeyutils`,
  `libcrypt`, `libnss_*`, `libaudit`, `libselinux`, `libsystemd`, `libssl`,
  `libcrypto`, `liblzma`, Kerberos and GSSAPI libraries, and every packaged
  library with `--all-libraries`.
* **dpkg diversions** are followed: a file another package diverted away is
  checked at its new name. A packaged file that is missing is reported only
  for programs and critical libraries, since container images often strip
  documentation.

Only paths, sizes, modes, owners, digests and package versions are stored.
Nothing is changed, removed or restored. Reinstall a package
(`apt install --reinstall <package>`) after you have investigated.

## Limits

* **dpkg only for package checks.** On RPM systems, `verify` reports a gap
  and the baseline still works. Use `rpm -Va` for package verification.
* **The package's own checksums are MD5.** They detect changes, but a
  determined attacker could forge an MD5 match. The baseline uses SHA-256.
* **A root attacker can edit the baseline too.** Keep a copy off the
  machine, or send `--alert` summaries off it. For the strongest check, run
  it from trusted boot media against the mounted disk.
* **A kernel rootkit can lie to every program,** this one included. Files
  are read through the running kernel.
* **Programs elsewhere** (home folders, `/tmp`, containers, snaps, Flatpaks,
  language package managers) are not covered. The
  [persistence watch](persistence-watch.md) covers setuid programs and
  startup locations.
