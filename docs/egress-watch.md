# Egress watch

The [listener watch](listener-watch.md) covers incoming connections. Most
compromises also need the other direction:
- an implant phoning home to its controller;
- an info-stealer uploading what it took;
- a trojaned updater fetching its next stage.

Each is a program making outgoing connections it never made before (ATT&CK
T1071, T1041, T1105). `megalodon egress` learns which programs connect out,
and to which ports, and reports the first time something new does.

```bash
sudo megalodon egress learn --minutes 60
```

```bash
sudo megalodon egress watch
```

```bash
sudo megalodon egress check
```

* **`learn`** records the programs connecting out now, and for `--minutes`
  more, in `~/.config/megalodon/egress.json` (mode 600). Run it on a system
  you trust, for long enough to see the programs that connect only now and
  then, such as package updates. It can be run again later to add to the
  baseline. A program running from a temporary folder, a deleted file or
  memory is never learned as normal. Connections too short for a scan are
  learned by their port and network (see [Short connections](#short-connections)).
* **`watch`** scans the kernel's socket tables every `--interval` seconds
  (default 1) and prints each new finding as a JSON line, at most once an
  hour for the same program and port. It picks up `allow` and `learn`
  changes without a restart.
  With `--respond`, it decides each finding itself, at once, and runs
  [enforcement](enforcement.md) before it reads the next event, so the
  process it names can be paused while it still runs. What was decided and
  done is written to standard error as one `megalodon: response {...}`
  line. The scheduled `megalodon-egress` job runs it this way:

  ```bash
  sudo megalodon egress watch --respond
  ```

  The five-minute response pass still reads `check`. The same process is
  decided only once, whichever sees it first. Enforcement acts only when its
  policy is on and lists the action and the playbook.

* **`check`** reviews the connections open now and exits 1 on findings. The
  response engine runs it on every pass.
* **`allow PROGRAM [--port tcp/443]`** records a program you reviewed, on
  any port or only on the one given.
* **`allow --destination tcp/443@203.0.113.0/24`** records a port and network
  you reviewed, for connections too short to name their program. Start it
  with `[container] ` or `[namespace] ` for connections in other namespaces.
  `0.0.0.0/0` allows that port everywhere.

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md).

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `OUTBOUND_FROM_TEMPORARY` | HIGH | A program running from `/tmp`, `/var/tmp`, `/dev/shm`, a deleted file or memory connects out |
| `NEW_OUTBOUND_PROGRAM` | HIGH (MEDIUM for a private address) | A program not in the baseline connects out |
| `NEW_OUTBOUND_PORT` | MEDIUM | A known program connects out on a port it has not used |
| `OUTBOUND_TO_WATCHLISTED_NAME` | CRITICAL | Any program, known or not, connects to a name on your watchlist, or a subdomain of one (`watch` only) |
| `OUTBOUND_TO_GENERATED_NAME` | MEDIUM | A program connects to a name spelled the way generated (DGA) or encoded names are, with at least two spelling signals and not under a cloud provider's generated names (`watch` only) |
| `BRIEF_OUTBOUND_CONNECTION` | MEDIUM (LOW for a private address) | A connection opened and closed between two scans, to a port and network no learned program uses (`watch` as root only) |

A program is its executable. For a script interpreter or shell, it is the
executable and the script it runs, so `python3 /opt/app/backup.py` and
`python3 /tmp/stage2.py` are different programs. A script given by a relative
name (`python3 backup.py`) is placed in the process's working folder, and
`python3 -m module` counts the module. A script in a temporary folder makes
the connection `OUTBOUND_FROM_TEMPORARY` even when the interpreter is
installed normally.

Outgoing means a TCP connection that is established or being opened, or a
UDP socket connected to a remote address. A connection that arrived on a port
this machine listens on is incoming and is left out. Connections to loopback,
link-local and multicast addresses are left out. Private (LAN) destinations
are left out unless `learn --include-private` was used.

Each finding names the program, its process ID and start time, its command
line (up to 512 bytes), and the address and port.

## Names

An address alone says little: one cloud address serves thousands of names,
and an implant's server looks like any other. While `watch` runs as root, it
also reads, passively, the two places the machine says which name it means:

* **DNS answers** (UDP from port 53, on every interface, including the local
  resolver's on loopback). Each address is mapped to the name that was looked
  up, for as long as the answer's time to live: at least a minute, at most a
  day.
* **The server name in each TLS ClientHello** a program sends. This is kept
  for that one connection (the address, the port and this machine's port) for
  an hour, and shown first. Another program reaching the same address and port
  may have asked for a different service, and does not get this name.

A packet that cannot be read is skipped; it never stops the listener.

A classic BPF filter in the kernel passes only those packets, so other
traffic never reaches MEGALODON. Nothing is sent, blocked or changed, and
nothing else in the packets is kept or shown.

Findings then name the destination (`updates.example.org
(93.184.216.34):443/tcp`) and carry `names`. Two more rules apply:
- **Watchlisted names.** A name is checked against the domain indicators of
  the [watchlist](threat-detection.md). It is read from `--watchlist`, or else from
  `[threat_detection] watchlist_path` in the settings.
- **Generated names.** A name is checked for the spelling signals of
  generated names.

Pass `--no-names` to skip all of this.

## Containers and other network namespaces

Each network namespace has socket tables of its own, and a container with its
own network (Docker and Podman by default, every Kubernetes pod) never shows in
the host's. Run as root, the watch reads every namespace's tables through one
of its processes (`/proc/PID/net`), without entering it or changing anything.

* **Named apart.** A connection from another namespace says which container
  it is in, from the process's control group (`docker:ab12cd34ef56`,
  `podman:...`, `containerd:...`), or which namespace when it is not a
  container, for example a VPN's. Its detail starts `in container ...`.
* **Learned apart.** Its program is recorded as `[container] /usr/bin/python3
  /app/server.py` or `[namespace] /usr/bin/openvpn`, never merged with the
  host's own `/usr/bin/python3`. Containers are recreated with new IDs, so
  all containers share one set of entries: what any container may run.
* **The process itself.** A finding names the process by PID and start time,
  as for the host's, so `suspend_process` pauses that one process.
* **Blocked inside the container.** This machine's own address blocks drop
  its own traffic. A container's traffic is routed through it, and those
  blocks do not stop it. So for a finding from another namespace, the
  response engine plans `block_address` for `ADDRESS@net:[ID]`. Enforcement
  then adds the same time-limited block to MEGALODON's table inside that
  namespace, entered with `nsenter --net` through one of the namespace's own
  processes. That process is checked to still be in the namespace just
  before. Only that container loses the address: this machine, other
  containers and the rest of the network keep it. `enforce undo` deletes it
  there. If the container is gone, its block went with it, and undo has
  nothing to do. The same guards apply as on the host: public addresses
  only, never this machine's gateway, DNS servers or own addresses, never
  anything in `never_touch_addresses`. The remote address is also a `peer`,
  so it still links incidents.
* **An older baseline.** A baseline learned before this, or without root,
  never saw other namespaces. Their programs are not reported as new. `check`
  lists them under `newly_watched` until you run `megalodon egress learn` as
  root. A program run from a temporary folder, a deleted file or memory is
  reported whatever the baseline knows.

## Short connections

A scan reads the socket tables once a second. A connection opened, used and
closed in between is never in them: a beacon that checks in for a few
milliseconds, a quick upload, one fetch of a second stage. As root, `watch`
also listens for the kernel's announcement of each TCP and UDP socket it
frees. These are the sock_diag destroy groups. The kernel sends each
announcement as the socket closes, and the watch judges it at once, without
waiting for the next scan. On this project's test machine, a refused
connection was reported 13 ms after it was made.

* **What an announcement says.** It gives the addresses and ports and, for
  TCP, about how many bytes went each way. The kernel counts the opening and
  closing of the connection as a byte each. It does not say which program or
  account opened the socket: the kernel leaves both empty, and the program
  may have exited already. So these findings name the destination and the
  amount, and their program is `(closed before it was seen)`. They carry
  `closed: true`, `sent` and `received`.
* **What is left out.** A connection a scan saw open was already judged with
  its program, and is not reported again. Left out like a scan's are
  incoming connections (their port is one listened on), loopback, link-local
  and multicast, and the LAN unless `learn --include-private` was used.
* **What is normal.** A port and network that a learned program uses is
  normal. So is one learned from a short connection during `learn
  --minutes`, or allowed with `allow --destination`. Ports and networks are
  kept apart for each program, so the check is whether some program uses
  both. A network is a /24 for IPv4, a /48 for IPv6.
* **Names.** DNS answers and TLS server names name these connections too. A
  watchlisted name is reported as `OUTBOUND_TO_WATCHLISTED_NAME` even
  without a program, so the response engine still blocks the address.
* **Containers.** The announcements are per network namespace. For each
  namespace a scan finds, a short-lived helper process enters it, opens a
  listening socket there and hands it back. This process never changes
  namespace. The namespace is checked through the open descriptor, so a
  reused process number cannot point the helper at another namespace. A
  namespace that refuses is listed once as a gap and not tried again while
  it exists. A namespace that is gone is let go. Containers are judged
  against container programs and `[container] ` destinations only.
* **Gaps.** Without root nothing is heard, and `watch` says so on standard
  error once. If more sockets close at once than the 4 MiB buffer holds,
  some announcements are lost, and the watch says how many bursts were.

### Naming the program: `watch --trace-connects`

```bash
sudo megalodon egress watch --trace-connects
```

With `--trace-connects`, the watch loads a small eBPF program into the
kernel that names the program behind every outgoing TCP connection as it is
made. A short connection heard closing is then judged as a scanned one is:
by its program, against the baseline. A program run from a temporary folder
is `OUTBOUND_FROM_TEMPORARY` (HIGH), a program never seen before is
`NEW_OUTBOUND_PROGRAM`, and a learned program on a learned port is quiet,
instead of `BRIEF_OUTBOUND_CONNECTION` for its destination alone. The
finding's `evidence.traced` gives the process and its parent's IDs, the
user ID, the command name and, as the kernel saw it, the end of the
program's path.

* **How.** The program is attached to the kernel's `inet_sock_set_state`
  tracepoint, and acts only when a socket moves into or out of SYN_SENT.
  Moving in happens in the connecting process: it records the process.
  Moving out (connected, or failed) comes once the local port is chosen: it
  records the addresses, ports and network namespace. The watch reads the
  process from `/proc` as soon as its connect is reported, while it normally
  still runs, and matches each closing by its whole identity: namespace,
  protocol, and both addresses and ports. A connection that fails has no local port by then; its closing
  is matched by its other addresses and ports.
* **Gone already.** If the process exited before it could be read, the
  kernel's record of its executable's path is used. The kernel gives the
  file's name and up to five parent folders, up to the root of the file
  system it is on, and the mount it is on: a separate file system such as
  `/dev/shm` is put back under its mount point. A full path names a plain
  program as a scan would, and a shell or interpreter copied into a
  temporary folder is named too: running from there is the finding. An
  installed interpreter, whose script is unknown, or a path the kernel saw
  only in part (`…/.x/agent`: more than five names, a name of 63 bytes or
  more that may have been cut short, or on a mount of another mount
  namespace, such as a container's), cannot be: the finding
  stays `BRIEF_OUTBOUND_CONNECTION`, with `evidence.traced` as a lead.
* **What it changes.** This and the
  [exec trace](credential-watch.md#naming-readers-gone-at-once-watch---trace-execs)
  are the parts of MEGALODON that change the running kernel. The program only reads;
  nothing on disk is changed, and it is removed when the watch stops,
  however it stops. It needs root, a
  kernel built with BTF (`/sys/kernel/btf/vmlinux`) and BPF ring buffers
  (Linux 5.8 or later), on x86-64 or arm64. Where it cannot be loaded, the
  watch says why on standard error and goes on without it. The
  [scheduler](scheduling.md) runs `egress watch` with it. The eBPF program
  is generated by MEGALODON at start, with field offsets read from the
  running kernel's own type information; no compiler or library is used.
  The in-kernel program declares the license "Dual BSD/GPL", which the
  kernel requires for the helpers it calls.
* **Cost.** The kernel runs the program on every TCP state change on the
  machine; it returns at once unless the socket is connecting, and then
  writes two records of about 540 bytes for each connect, into a 1 MiB
  ring buffer the watch empties as they arrive. If connects come faster
  than that, the kernel drops records, and those connections are reported
  by destination as before.

## Response

* **dropped-tool-phoning-home** covers `OUTBOUND_FROM_TEMPORARY`. It plans
  to collect evidence, suspend that process (by PID and start time), block
  the address for 60 minutes and notify you.
* **Names link incidents.** A watchlisted or generated-looking name is kept as
  a `name` entity, in lower case without a final dot. It joins this machine's
  incidents that reached it, and other machines' on the
  [fleet collector](fleet.md#incidents-across-machines).
* **watchlisted-name** covers `OUTBOUND_TO_WATCHLISTED_NAME`, like a dropped
  tool. It plans to collect evidence, suspend that process, block the address
  for 60 minutes and notify you.
* **new-outbound-program** covers HIGH `NEW_OUTBOUND_PROGRAM`. It plans to
  collect evidence and notify you, because new software does the same.
* `BRIEF_OUTBOUND_CONNECTION` is MEDIUM and has no playbook of its own. With
  no process to pause, the response engine links its address to incidents
  as for other egress findings.

## Limits

* **Root sees every process.** Without root, connections owned by other
  accounts cannot be matched to a program, and the report counts them under
  `gaps`.
* **Short connections have no program, unless traced.** As root, `watch`
  hears a connection opened and closed between two scans, but only by its
  destination. With `--trace-connects`, TCP connections are named by their
  program; short UDP exchanges, and `learn --minutes`, still have only their
  destination. Without root, or with `check` and `learn` without
  `--minutes`, such connections are not seen at all. Protocols other than TCP and UDP, such as ICMP and raw sockets, are
  not announced.
* **Names need `watch` and root.** `check` and `learn` see only addresses.
  A name looked up before the watch started is unknown until it is looked up
  again, or until a program sends its server name.
* **Encrypted lookups and hellos hide names.** DNS over HTTPS or TLS hides
  answers, so only the TLS server name is seen. Encrypted Client Hello and
  QUIC hide that too: those connections are shown by address. So are
  connections to bare addresses, which is itself worth a look for a new
  program.
* **The baseline keeps ports and address ranges,** not names. Names describe
  findings; they do not decide which programs are new.
* **Programs that run code from elsewhere.** A known program that loads
  hostile code, such as a browser extension or a plugin, connects out as
  itself and is not new.
* **Root reads every namespace.** Without root, only this namespace and
  those of your own processes are read, and the report says how many
  processes it could not see.
