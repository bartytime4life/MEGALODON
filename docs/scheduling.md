# Scheduling the host watches

Each host watch only helps if it runs regularly. `megalodon schedule` sets
them all up as systemd timers, each with `--alert`, plus the response
engine's shadow pass and, as root, the live
[process ancestry watch](process-ancestry.md) and
[container escape watch](container-watch.md#escapes-as-they-start-containers-watch).

```bash
sudo megalodon schedule plan
```

```bash
sudo megalodon schedule install --yes
```

```bash
sudo megalodon schedule remove --yes
```

* **`plan`** shows every job: its command, how often it runs, the unit files
  it would write, any baseline it still needs, and an equivalent crontab
  line. It writes nothing.
* **`install --yes`** writes the units and enables them. It refuses while a
  baseline is missing. Take baselines yourself on a system you trust, or
  pass `--take-baselines` to have it take them first. A unit file with the
  same name that MEGALODON did not write is left alone, and the install
  stops.
* **`remove --yes`** disables and deletes MEGALODON's units, and only those:
  each unit it writes carries a marker line.

As root, units go to `/etc/systemd/system` and run as root, which sees every
process, socket and file. Otherwise they are user units in
`~/.config/systemd/user`, and the jobs that need root are left out. Choose with `--system` or `--user`, and limit the jobs with `--only`
(repeatable).

## The jobs

| Job | Runs | Command |
| --- | --- | --- |
| respond | every 5 minutes | `respond run` (shadow mode; nothing is carried out) |
| enforce | scheduled every minute (root) | `enforce run`; new actions need an enabled policy; existing timed pauses are still recovered with a missing or valid disabled policy ([enforcement](enforcement.md)) |
| heartbeat | every 5 minutes | `heartbeat send`, after `megalodon heartbeat init --url ...` ([tamper detection](tamper-detection.md)) |
| timeline-push | every 5 minutes | `timeline push`, to the [fleet collector](fleet.md#incidents-across-machines); sends nothing to a plain heartbeat monitor |
| evidence-push | every 5 minutes | `evidence push`: command log lines and evidence bundles to the fleet collector ([evidence off the machine](evidence-shipping.md)); sends nothing to a plain heartbeat monitor |
| logins | every 5 minutes | `logins check --alert` ([login watch](login-watch.md)) |
| devices | always running | `devices watch --alert --respond`: checks as each device is plugged in, and cuts off what the enforcement policy allows ([device watch](device-watch.md#cut-it-off-at-once)). An earlier install's `megalodon-devices.timer` is removed |
| listeners | always running | `listeners watch --alert`: each listener change once while it lasts, and as root the ports that open and close between checks ([listener watch](listener-watch.md)). An earlier install's `megalodon-listeners.timer` is removed. Without systemd, the crontab line runs `listeners check --alert` every 10 minutes instead |
| persistence | every 15 minutes | `persistence check --alert` |
| tamper | every 15 minutes | `tamper check --alert`; its baseline is taken after the others and the units |
| logwatch | every 15 minutes | `logwatch check --alert --advance` |
| webroot | always running | `webroot watch --alert`: each file judged as it is written, and a script dropped and soon deleted reported ([web-root watch](webroot-watch.md)). An earlier install's `megalodon-webroot.timer` is removed. Without systemd, the crontab line runs `webroot check --alert` every 15 minutes instead |
| ebpf | every 15 minutes (root) | `ebpf check --alert` ([eBPF watch](ebpf-watch.md)) |
| hardening | hourly | `hardening check --alert` ([hardening drift](hardening-drift.md)) |
| packages | hourly | `packages check --alert` ([package sources](package-sources.md)) |
| secrets | daily at 04:23 | `secrets check --alert` ([exposed secrets](exposed-secrets.md)) |
| containers | every 15 minutes (root) | `containers check --alert` ([container watch](container-watch.md)) |
| boot | hourly | `boot check --alert` ([boot integrity](boot-integrity.md)) |
| rootkit | hourly | `rootkit check --skip-ports --alert` |
| vulns | daily at 06:41 | `vulns check --alert` ([known-vulnerable software](known-vulnerable-software.md)) |
| binaries | daily at 03:17 | `binaries check --alert` |
| ancestry | always running (root) | `ancestry watch --alert --respond --trace-execs`: each service starting a shell or tool is decided at once, and the process paused if the enforcement policy allows; a command gone before it is read is judged from the exec trace ([process ancestry](process-ancestry.md)) |
| commands | always running (root) | `commands record --trace-execs`, after `megalodon commands init --key-file ...`; a program gone at once keeps its arguments ([command log](command-log.md)) |
| credentials | always running | `credentials watch --alert --respond --trace-execs` ([credential access watch](credential-watch.md); as root it names every reader, also one gone at once; each finding is decided at once) |
| container-escapes | always running (root, eBPF) | `containers watch --alert --respond`: each program started on the host from a container, as it starts, decided at once ([container watch](container-watch.md#escapes-as-they-start-containers-watch)). Left out where eBPF cannot run; the 15-minute `containers check` covers those machines, and without systemd too |
| egress | always running | `egress watch --alert --respond`, after `megalodon egress learn --minutes 60` ([egress watch](egress-watch.md); each finding is decided at once) |
| ransomware | always running | `ransomware watch --respond`, after `megalodon ransomware init --dir FOLDER ...`; each finding is decided and enforced as it is raised ([ransomware watch](ransomware-watch.md#answer-it-at-once)) |

**The exec trace.** `--trace-execs` loads the
[exec trace](credential-watch.md#naming-readers-gone-at-once-watch---trace-execs)
(eBPF), so a program gone before a watch reads it is still seen. Where it
cannot be loaded (no root, no kernel type information, before Linux 5.8, not
x86-64 or arm64), each of those watches says why on standard error and goes
on as without it. The container escape watch has no such fallback:
`schedule plan` lists it as skipped where the kernel lacks what it needs.
If it cannot be loaded anyway, it exits 2 and is restarted every 10
seconds, as the other watches are, and the tamper check reports it
stopped. Each
service has a mount namespace of its own (`ProtectSystem=full`), whose
copies of the host's mounts have other IDs. So the trace names each
program from init's mount table too. No other table is read: a program in
a mount namespace of its own (a container's, or one it made, which can put
any folder at `/usr/bin`) keeps a partial path, `…/`, as before. Each job
that loads it is allowed 64 MiB of locked memory, which kernels before
5.11 count BPF maps against. Each loads its own copy, with an 8 MiB ring
buffer: four, as root.

Timers add a random delay of up to a minute, so that machines set up the same
way do not all run at once, and they catch up after the machine was off.
Systemd's timer accuracy, an already-running job, and lock contention can
delay execution further. The calendar interval is not a recovery deadline.
Checks run at low CPU and I/O priority, cannot gain privileges, and see
`/usr`, `/boot` and `/etc` read-only. A check that exits 1 has found
something. That is reported through `--alert`, and systemd does not count it
as a failure. **Enforcement is different:** exit 1 means an action or a resume
failed, so the generated `megalodon-enforce` service leaves it unsuccessful.
Its JSON output names the failure, and a failed resume remains eligible for
the next recovery attempt. New enforcement can be disabled while timed-pause
recovery continues; stopping its timer stops those attempts too.

These are generated-unit settings. Changing source does not update an
installed service or prove that it uses the expected account, journal, or
installed package revision. Service updates and native acceptance remain
separate operator actions.

## Notes

* **Alerts need destinations.** Configure `[[alerts.destination]]` first, as
  described in [off-machine alerts](off-machine-alerts.md). Run
  `megalodon alerts test` to check them.
* **The response engine's audit store.** Under a timer, `respond run` starts
  in `/`. Give `audit_db` an absolute path in the response policy, or turn
  it off.
* **The rootkit port test** briefly binds every free port, so scheduled runs
  leave it out. Run `megalodon rootkit check` yourself when nothing is
  starting.
* **After installing more units,** run `megalodon tamper accept` so the tamper
  check records them. `install` says so when it applies.
* **Without systemd,** `install` refuses. Add the crontab lines that `plan`
  prints instead. A live watch cannot run from cron, so its line runs the
  matching one-shot check instead: `devices`, `ancestry`, `credentials` and
  `egress` every 5 minutes, `listeners` every 10 and `webroot` every 15.
  These see what is there when they run, not what came and went between
  runs. `ransomware` and the command log (`commands`) have no check, so
  they have no line.
