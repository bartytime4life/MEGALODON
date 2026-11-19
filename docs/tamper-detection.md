# Tamper detection

An intruder's first move is often to switch the defenses off (ATT&CK
T1562.001):
- stop the timers;
- edit a baseline so a backdoor looks normal;
- add an allow-list entry;
- point the alerts somewhere else;
- replace MEGALODON's own code.

Each of these turns every other watch silent. Tamper detection has two
halves: a local check, and a signed heartbeat whose silence another machine
notices.

## The local check

```bash
megalodon tamper baseline
```

```bash
megalodon tamper check
```

```bash
megalodon tamper accept
```

`baseline` records the following in `~/.config/megalodon/tamper.json`
(mode 600):
- the SHA-256 of every MEGALODON program file;
- the scheduled units from [`megalodon schedule`](scheduling.md);
- the files that decide what MEGALODON reports: the settings, the URL and
  token files its alert destinations point to (only their digests), the
  response policy, the process ancestry allow list, the heartbeat
  configuration, every watch's baseline, and the YARA rules.

The dashboard's own settings files change in normal use and are not
recorded.

`check` exits 1 on findings and 2 on an error, and `--alert` sends them off
the machine. Tamper alerts are sent whatever the alert minimum severity is.
`accept` records the current state after an upgrade, or after you accepted a
watch's baseline yourself.

| Rule | Severity | When |
| --- | --- | --- |
| `SENSOR_CODE_CHANGED` | CRITICAL | A MEGALODON program file changed |
| `SENSOR_CODE_ADDED`, `SENSOR_CODE_REMOVED` | HIGH | A program file appeared or was removed |
| `SCHEDULE_REMOVED`, `SCHEDULE_CHANGED` | HIGH | A scheduled unit was removed or edited, for example its command |
| `WATCH_DISABLED`, `WATCH_STOPPED` | HIGH | systemd reports a scheduled unit as not enabled or not running |
| `WATCH_OVERDUE` | HIGH | A timer has not run for more than three of its intervals |
| `ALERTS_CONFIG_CHANGED` | HIGH | The settings changed, or a URL or token file an alert destination points to changed or was removed |
| `ALLOW_LIST_CHANGED` | HIGH | The process ancestry or credential reader allow list changed |
| `DETECTION_RULES_CHANGED` | HIGH | A YARA rule file changed |
| `HEARTBEAT_CONFIG_CHANGED` | HIGH | The heartbeat destination or key changed |
| `CONFIG_REMOVED` | HIGH | A recorded baseline or configuration file was removed |
| `BASELINE_CHANGED` | MEDIUM | A watch's baseline changed, as `accept` does after review |
| `POLICY_CHANGED` | MEDIUM | The response policy changed |
| `CONFIG_ADDED` | LOW | A new baseline or configuration file |

## The heartbeat

A local check cannot report that the machine was switched off, cut off, or
taken over entirely. A heartbeat can, because the silence is noticed
elsewhere.

```bash
megalodon heartbeat init --url https://monitor.example/ping/9f3c...
```

```bash
megalodon heartbeat send
```

* **`init`** records the destination and a new random signing key in
  `~/.config/megalodon/heartbeat.json` (mode 600). It prints the key once:
  store it on the machine that checks the heartbeats. The URL must be
  `https`, or `http` to a private or loopback address.
* **`send`** posts one JSON heartbeat:
  - the sensor name and an increasing sequence number;
  - the time;
  - a SHA-256 digest of everything the local check records;
  - the local check's current findings;
  - an HMAC-SHA256 signature over all of it.

  It exits 1 if the heartbeat could not be delivered. `--print` prints the
  heartbeat instead.

`megalodon schedule install` sends one every 5 minutes and runs the tamper
check every 15, once both are set up.

### Watching for silence

Use either of these:

* **A dead-man's-switch service**, such as Healthchecks.io, Uptime Kuma's
  push monitor or Cronitor. These alert you when pings stop. Give
  `heartbeat init` the service's ping URL. This is the simplest way to
  catch silence.
* **`megalodon heartbeat monitor` on another machine.** Point it at the
  received heartbeats, one JSON body per line, for example the log of a
  webhook collector:

  ```bash
  megalodon heartbeat monitor --input received.jsonl --key-file heartbeat.key --max-gap 900
  ```

  It exits 1 on findings, and `--alert` sends them through that machine's
  own alerts. Run it from that machine's scheduler.
* **`megalodon fleet serve` on a collector.** It receives heartbeats and
  alerts from every enrolled machine and applies these rules to each. See the
  [fleet view](fleet.md).

| Rule | Severity | When |
| --- | --- | --- |
| `HEARTBEAT_SILENT` | CRITICAL | No valid heartbeat within `--max-gap` seconds (default 900) |
| `HEARTBEAT_FORGED` | CRITICAL | A heartbeat's signature does not match the key: it was edited or made without it |
| `HEARTBEAT_REPLAYED` | HIGH | A heartbeat repeated, or went back in the sequence |
| `HEARTBEAT_REPORTS_TAMPER` | HIGH | The machine's own tamper check reported findings (once per new set), including a removed tamper baseline |
| `TAMPER_BASELINE_LOST` | HIGH | Heartbeats that carried a tamper baseline stopped carrying one, even if the sender's own records were wiped too |
| `SENSOR_STATE_CHANGED` | MEDIUM | The state digest changed between heartbeats |
| `HEARTBEAT_GAP` | MEDIUM | Sequence numbers are missing: lost deliveries, or a restarted sender |

The [response engine](response-engine.md) reads the local check and plans to
collect evidence and notify you of HIGH and CRITICAL findings.

## Limits

* **A root intruder can change the local baseline.** They can also read the
  signing key and forge heartbeats from then on. What they cannot take back:
  - the heartbeats already sent;
  - the moment the state digest changed;
  - silence, if they stop MEGALODON instead of imitating it.

  Watch the off-machine record, not only the local report.
* **Upgrades change the code.** After upgrading MEGALODON, run
  `megalodon tamper accept`. Likewise, after `accept` in another watch,
  `BASELINE_CHANGED` is expected.
* **The heartbeat proves the sender holds the key and is running.** It does
  not prove the machine is uncompromised.
