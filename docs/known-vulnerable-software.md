# Known-vulnerable software

Most break-ins use a flaw that already has a fix the machine has not taken.
The fix is published, and often already downloaded, but not installed, not
restarted, or not booted. `megalodon vulns check` lists the fixes that are
waiting, and shows first the ones that matter most: services anyone can
reach, running code with a known flaw (ATT&CK T1190, T1210, T1068).

```bash
sudo megalodon vulns check
```

It exits 1 on findings and sends them to the
[off-machine alerts](off-machine-alerts.md) with `--alert`. The
[scheduler](scheduling.md) runs it daily at 06:41.

## What it reads

Everything comes from the package manager's own local data; nothing is
fetched or installed:
* **Waiting security updates.**
  - On apt systems, from a simulated upgrade (`apt-get -s dist-upgrade`).
    It takes no lock and changes nothing. Security updates are those offered
    from a `-security` suite.
  - On dnf systems, from the cached update notices
    (`dnf --cacheonly updateinfo list --security`), with their severity.
* **The kernel.** A newer kernel in `/boot` than the one running, or a
  reboot the system asked for (`/run/reboot-required`), together with the
  packages that asked.
* **Code still running after an update.** Programs that still map a program
  or library from the system folders which an update has since replaced on
  disk. The fix is installed but not in effect for them until they restart.
* **What is exposed.** Each process's program and libraries are matched to
  packages through dpkg's file lists, including on merged-`/usr` systems.
  Its sockets show whether it listens beyond loopback.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `VULNERABLE_EXPOSED_SERVICE` | CRITICAL | A service that listens beyond this machine runs a program or library whose package has a security update waiting |
| `FIX_NOT_RUNNING_EXPOSED` | HIGH | A service that listens beyond this machine still runs code an update replaced; restart it |
| `KERNEL_FIX_NOT_RUNNING` | HIGH | A newer kernel is installed than the one running, or a reboot was asked for |
| `SECURITY_UPDATES_PENDING` | HIGH | Security updates are waiting, listed by package |
| `FIX_NOT_RUNNING` | MEDIUM | Another program still runs code an update replaced |
| `PACKAGE_LISTS_STALE` | MEDIUM | The package lists are a week or more old, so newer fixes are not known here |

The report also gives the number of updates, the number of security
updates, the age of the lists in days, and the running and newest kernels.

## Limits

* **The lists are only as new as the last refresh.** Run `apt update` or
  `dnf makecache` regularly, for example from unattended upgrades. The check
  says how old the lists are, and flags lists older than a week.
* **Packages only.** Software installed outside the package manager, such as
  language packages, containers, `/usr/local` and `/opt`, is not matched. Use
  each ecosystem's own audit, such as `pip-audit` or `npm audit`, and scan
  container images separately.
* **Exposure is per process,** matched to its own program and loaded
  libraries. A flaw in a helper the service starts later is not linked.
* **No CVE numbers on apt systems.** The distribution's security suite
  decides what counts as a security fix. On dnf systems the advisory ID and
  severity are given.
