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
megalodon listeners watch
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
* **`watch`** checks every `--interval` seconds (default 10) and prints each
  change as a JSON line, once while it lasts and again if it comes back or
  becomes reachable more widely. Coverage gaps, such as owners it cannot
  see without root, are told once on standard error. As
  root it also hears listeners that opened and closed between two checks
  (see below). With `--alert`, each finding also goes to the off-machine
  alerts. An `accept` made while it runs is picked up at the next check.
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
| `LISTENER_OPENED_AND_CLOSED` | MEDIUM | `watch`, as root: a TCP port reachable from other machines opened and closed between two checks, as a bind shell that takes one connection does | T1571 |

The ATT&CK mappings are the closest fit; none of these is proof of an attack.

**Listeners between checks.** As root, `watch` hears every TCP socket the
kernel closes, in this network namespace and every other one a check has
read, the way the [egress watch](egress-watch.md) hears short connections. A
socket that closed without a peer, on an address other machines reach, is a
listener, most likely; one the baseline records or a check of this watch has
already seen is left out, and so is one on loopback only. The kernel's
announcement names no program, so the finding has none. Each port is
reported at most once every five minutes, and at most 30 an hour in all,
since an FTP server opens and closes a passive data port for every transfer.
Past that, they are counted and a warning says so.

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

## Containers and other network namespaces

Run as root, the listeners of every network namespace are read, not only this
one's, through one of each namespace's processes (`/proc/PID/net`). A listener
in a container is recorded as `container/tcp:8080`, one in another namespace
as `namespace/tcp:8080`. It never merges with the host's `tcp:8080`. All
containers share one key per port, so a container recreated with a new ID is
not a new listener. Each entry, and each finding, lists the containers or
namespaces that hold it now under `where`.

A bind shell started inside a container is a `NEW_LISTENER` on
`container/tcp:4444`, rated as on the host. A baseline taken before this, or
without root, never read other namespaces. `check` lists their listeners
under `newly_watched` until you run `accept`. A check without root cannot
read them, so they are a gap, not a closed port.

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
* **Root reads every namespace.** Without root, only this namespace and
  those of your own processes are read. A port Docker publishes on the host
  appears there only while `docker-proxy` listens for it. With Docker's
  userland proxy turned off, firewall rules forward it, and only the
  container's own listener is seen.
* **UDP services only.** An unconnected UDP socket on a port in the kernel's
  outgoing range (`ip_local_port_range`, usually 32768 to 60999) is treated
  as a client and skipped, unless a shell, a relay tool such as `nc` or
  `socat`, or a program run from a temporary folder, from memory or from a
  deleted file holds it: then it is reported like any other port. A UDP
  backdoor on such a port that runs as an ordinary installed program, or
  whose owner cannot be seen without root, is missed.
* **Changes between checks.** `check` misses a listener that opens and
  closes between two runs. `watch`, as root, hears TCP ones as they close,
  but without their program, and not UDP sockets or loopback-only
  listeners. A TCP socket that was only bound to a port, never listening,
  looks the same when it closes. The
  [programs on the network](host-security.md#programs-on-the-network) review
  shows live sockets, including reverse-shell shapes.
* **Desktops change often.** Browsers, chat apps and development tools open
  listeners as they run. `accept` after review keeps the reports clean.
* **A root attacker can edit the baseline too.** Keep a copy off the machine,
  or send `--alert` summaries off it.
