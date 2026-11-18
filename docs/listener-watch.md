# Listener watch

A backdoor has to be reachable. Bind shells, remote-access tools and dropped
servers all start listening on a port. `megalodon listeners` records which
programs listen on this machine, and where they can be reached from, then
reports what changes.

```bash
megalodon listeners baseline
```

```bash
megalodon listeners check
```

```bash
megalodon listeners accept
```

* **`baseline`** records every listening TCP port and every bound UDP
  service port in `~/.config/megalodon/listeners.json` (mode 600). Take it on
  a system you trust.
* **`check`** reports what changed since the baseline, most severe first. It
  exits 1 when anything changed and 2 on an error. With `--alert`, a one-line
  summary also goes to the [off-machine alerts](off-machine-alerts.md)
  configured in the settings file. Listeners that stopped are listed under
  `closed` and are not findings.
* **`accept`** records the current listeners as the new baseline once you
  have reviewed the changes, for example after installing a service.

Run it as root so every program's sockets can be matched to their owner, and
run `check` from cron or a systemd timer:

```bash
( sudo crontab -l 2>/dev/null; echo '17 * * * * /usr/local/bin/megalodon listeners check --alert >/dev/null' ) | sudo crontab -
```

Adjust the program path to where MEGALODON is installed for root.

## What it reports

| Finding | Severity | Meaning | ATT&CK |
| --- | --- | --- | --- |
| `NEW_LISTENER` | HIGH, MEDIUM or LOW | A port that was not listening at the baseline | T1571, plus T1059 for a shell or relay tool |
| `LISTENER_PROGRAM_CHANGED` | MEDIUM, or HIGH | A known port is now served by a different program | T1543 |
| `LISTENER_EXPOSED` | MEDIUM, or HIGH | A known port became reachable more widely: from loopback to a network address, to every interface, or on another address or address family (such as IPv6) that it did not listen on before | T1133 |

The ATT&CK mappings are the closest fit; none of these is proof of an attack.

**Severity follows the owner and the reach.** A finding is HIGH when the
program that owns the port is:

* a shell such as `sh` or `bash`;
* a network relay tool such as `nc`, `ncat` or `socat`;
* running from a temporary folder (`/tmp`, `/var/tmp`, `/dev/shm`), from
  memory, or from a file that was deleted after it started.

Otherwise a new listener is MEDIUM when other machines can reach it and LOW
when it only listens on loopback. A script interpreter (Python, Node, Perl...)
is noted in the finding's reasons, but it doesn't raise the severity on its
own, because development servers are written in those languages too.

## What is recorded

For each listener: protocol, port, the local addresses it is bound to, its
reach (`loopback`, `specific` or `all` interfaces), and each owning program's
executable path and process name. Command lines, process IDs, connections and
traffic are never read or stored. Nothing is stopped, closed or changed.

## Limits

* **Root sees every owner.** Without root, sockets of other accounts' and
  system services' processes have no visible owner. The report lists that as
  a coverage gap, and a change of owner is not reported for those ports. A
  port where only some sockets have a visible owner is listed too.
* **This network namespace only.** Containers in their own network namespace
  are not covered. A port Docker publishes appears only while `docker-proxy`
  listens for it on the host; with Docker's userland proxy turned off,
  firewall rules forward it and no listener is seen.
* **UDP services only.** An unconnected UDP socket on a port in the kernel's
  outgoing range (`ip_local_port_range`, usually 32768 to 60999) is treated
  as a client and skipped. A UDP backdoor on such a port is missed.
* **Changes between checks.** A listener that opens and closes between two
  checks is not seen. The
  [programs on the network](host-security.md#programs-on-the-network) review
  shows live sockets, including reverse-shell shapes.
* **Desktops change often.** Browsers, chat apps and development tools open
  listeners as they run. `accept` after review keeps the reports clean.
* **A root attacker can edit the baseline too.** Keep a copy off the machine,
  or send `--alert` summaries off it.
