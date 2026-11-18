# Self-test drill

`megalodon drill` checks that MEGALODON's detections still fire on this
machine and version, end to end. It doesn't rely on unit tests passing
somewhere else.

```bash
megalodon drill
```

```bash
megalodon drill --alerts
```

Each line on the screen reads `PASSED`, `FAILED` or `SKIPPED`, followed by
what was exercised. The full JSON report goes to standard output. The command
exits 1 when any check failed, so it can run after updates or from a monthly
timer.

## What each check does

| Check | Exercises | Must report |
| --- | --- | --- |
| network | The built-in demo sample (`run --source sample --demo-threat`) through the real service into a temporary audit store | `SYN_FLOOD`, `DNS_TUNNELING`, `BRUTE_FORCE`, `HOST_SWEEP`, `DATA_EXFILTRATION`, `BEACONING`, each also recorded in the store |
| canary | Plants one bait file in a temporary folder, changes it, then runs `check` | `CANARY_MODIFIED` |
| ransomware | The ransomware self-test: throwaway files encrypted under a live inotify watch (Linux) | `RANSOMWARE_ENCRYPTION`, `RANSOM_NOTE` |
| persistence | Baselines a throwaway folder tree, then adds a comment-only cron file and a comment line in a profile | `cron`, `shell_startup` changes |
| listeners | Baselines this machine's listeners into a temporary manifest, then listens on a loopback port of its own (Linux) | `NEW_LISTENER` for that port |
| alerts | With `--alerts`: the same labeled test notice as `megalodon alerts test`, sent to every configured destination | Every destination accepts it |

## What it never touches

* **Your data.** Every check runs in a fresh temporary folder that is
  removed afterwards. Your audit database, canaries, watched folders,
  persistence and listener baselines and system files are not changed. The
  listeners check reads the kernel's socket tables, as `megalodon listeners
  check` does.
* **Your network.** No packet is sent or captured. The network check feeds
  stored sample metadata through the detector. The listeners check opens one
  loopback port for a moment, reachable only from this machine.
* **Destinations, without `--alerts`.** Nothing is sent to an alert
  destination unless you pass `--alerts`. The notice then says plainly that it
  is a test.

## Limits

* **It proves the detection logic, not the sensor.** It doesn't show that your
  capture interface, TShark, inotify limits or cron schedule are working on
  live data. Use the HUD's capture status and each tool's own status output
  for that.
* **Some layers are not covered.** Opt-in DNS, TLS and LAN rules, the IOC
  watchlist, login review and YARA file inspection have their own tests, but
  no drill check yet.
* **A passing drill is not proof of safety.** It shows the alarms can ring.
  It doesn't show that nothing has happened.
