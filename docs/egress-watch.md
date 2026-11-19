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
  memory is never learned as normal.
* **`watch`** scans the kernel's socket tables every `--interval` seconds
  (default 1) and prints each new finding as a JSON line, at most once an
  hour for the same program and port. It picks up `allow` and `learn`
  changes without a restart. Pipe it into the
  [response engine](response-engine.md):

  ```bash
  sudo megalodon egress watch | megalodon respond ingest
  ```

* **`check`** reviews the connections open now and exits 1 on findings. The
  response engine runs it on every pass.
* **`allow PROGRAM [--port tcp/443]`** records a program you reviewed, on
  any port or only on the one given.

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
* **The server name in each TLS ClientHello** a program sends. This maps the
  address and port to the service the program asked for, and it is kept for an
  hour. It is shown first, because it is what that program asked that address
  for.

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

## Response

* **dropped-tool-phoning-home** covers `OUTBOUND_FROM_TEMPORARY`. It plans
  to collect evidence, suspend that process (by PID and start time), block
  the address for 60 minutes and notify you.
* **watchlisted-name** covers `OUTBOUND_TO_WATCHLISTED_NAME`, like a dropped
  tool. It plans to collect evidence, suspend that process, block the address
  for 60 minutes and notify you.
* **new-outbound-program** covers HIGH `NEW_OUTBOUND_PROGRAM`. It plans to
  collect evidence and notify you, because new software does the same.

## Limits

* **Root sees every process.** Without root, connections owned by other
  accounts cannot be matched to a program, and the report counts them under
  `gaps`.
* **Short connections can be missed.** A connection opened and closed
  between two scans is not seen. A 1-second scan catches most programs that
  phone home, which keep a connection or retry.
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
* **One network namespace.** Containers with their own network namespace
  are not covered by a watch running outside them.
