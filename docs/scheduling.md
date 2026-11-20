# Scheduling the host watches

Each host watch only helps if it runs regularly. `megalodon schedule` sets
them all up as systemd timers, each with `--alert`, plus the response
engine's shadow pass and, as root, the live
[process ancestry watch](process-ancestry.md).

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
`~/.config/systemd/user`, and the ancestry watch, which needs root, is left
out. Choose with `--system` or `--user`, and limit the jobs with `--only`
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
| devices | every 5 minutes | `devices check --alert` |
| listeners | every 10 minutes | `listeners check --alert` |
| persistence | every 15 minutes | `persistence check --alert` |
| tamper | every 15 minutes | `tamper check --alert`; its baseline is taken after the others and the units |
| logwatch | every 15 minutes | `logwatch check --alert` |
| webroot | every 15 minutes | `webroot check --alert` |
| ebpf | every 15 minutes (root) | `ebpf check --alert` ([eBPF watch](ebpf-watch.md)) |
| hardening | hourly | `hardening check --alert` ([hardening drift](hardening-drift.md)) |
| packages | hourly | `packages check --alert` ([package sources](package-sources.md)) |
| secrets | daily at 04:23 | `secrets check --alert` ([exposed secrets](exposed-secrets.md)) |
| containers | every 15 minutes (root) | `containers check --alert` ([container watch](container-watch.md)) |
| boot | hourly | `boot check --alert` ([boot integrity](boot-integrity.md)) |
| rootkit | hourly | `rootkit check --skip-ports --alert` |
| vulns | daily at 06:41 | `vulns check --alert` ([known-vulnerable software](known-vulnerable-software.md)) |
| binaries | daily at 03:17 | `binaries check --alert` |
| ancestry | always running (root) | `ancestry watch --alert` |
| commands | always running (root) | `commands record`, after `megalodon commands init --key-file ...` ([command log](command-log.md)) |
| credentials | always running | `credentials watch --alert` ([credential access watch](credential-watch.md); as root it names every reader) |
| egress | always running | `egress watch --alert`, after `megalodon egress learn --minutes 60` ([egress watch](egress-watch.md)) |
| ransomware | always running | `ransomware watch --respond`, after `megalodon ransomware init --dir FOLDER ...`; each finding is decided and enforced as it is raised ([ransomware watch](ransomware-watch.md#answer-it-at-once)) |

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
  prints instead.
