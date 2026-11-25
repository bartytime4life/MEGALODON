# Command log

Shell history is the first thing an intruder deletes. It never covered
commands run by scripts, cron jobs, services or a web shell anyway.
`megalodon commands` records every program the kernel starts, in a log the
intruder cannot quietly rewrite. Deleting history to hide activity is ATT&CK
T1070.003.

```bash
sudo megalodon commands init --key-file /media/usb/megalodon-commands.key
```

```bash
sudo megalodon commands record
```

```bash
megalodon commands verify --key-file /media/usb/megalodon-commands.key --expect-sequence 48211
```

```bash
sudo megalodon commands show --since 2026-11-19T12:00 --uid 1000
```

* **`init`** starts a log and writes its first key once, to `--key-file`, or
  prints it. **Move the key off this machine and keep no copy here.** Whoever
  holds the key can check every line; on the machine, it would let an intruder
  sign lines of their own.
* **`record`** writes one line for every program started, until it is
  stopped. The [scheduler](scheduling.md) runs it as an always-running root
  service once `init` has been run.
* **`verify`** checks every line against the key. Run it where the key is: off
  the machine, on a copy of the log. It exits 1 on findings.
* **`show`** lists what was recorded, filtered by time, account (`--uid`
  matches the account a program ran as or the one it logged in as) and text.
  `show` reads; it does not check. Use `verify` for that.
* **`status`** prints the last line written and the key's fingerprint.

Never pass the key on a command line: the log would record it.

### Programs gone at once: `record --trace-execs`

```bash
sudo megalodon commands record --trace-execs
```

The kernel's process events give only a process ID. The recorder then reads
the program from `/proc`, and a program that has exited by then is recorded
without its arguments or folder. On this machine, 300 small programs started at
once were all recorded that way, or not at all.
`--trace-execs` loads the [exec trace](credential-watch.md#naming-readers-gone-at-once-watch---trace-execs)
instead: two small eBPF programs that record each program as the kernel starts
it. With it, all 300 were recorded with their arguments.

* **What each line holds then.** The program, its arguments, working folder,
  account, parent and start time come from the kernel's own record of the
  exec, and so do the account that logged in and the login session. `/proc`
  adds only the terminal, while it shows the same process running the same
  program. A command line longer than the 512 bytes the trace reads is
  completed from `/proc` only when `/proc` shows the same start of it;
  otherwise it ends with `[cut]`. A line for a program that was gone, or
  running something else, by the time it was read has `"exited": true`.
* **Lost records.** If programs start faster than the recorder reads, the
  kernel has no room for some records. The programs count each one, and the
  recorder writes a `lost` line with how many, which `verify` reports as
  `COMMAND_LOG_EVENTS_LOST`.
* **What it changes.** As with the other watches, the programs only read, and
  are removed when recording stops. It needs root, a kernel with BTF and BPF
  ring buffers (Linux 5.8 or later), on x86-64 or arm64. Where they cannot be
  loaded, the recorder says why and records from the process events instead.
  The [scheduler](scheduling.md) runs `commands record` with it.

## What each line holds

Each line records:
- **when** the program started;
- **who:**
  - the account it ran as;
  - the account that logged in, which stays the same through `sudo` and `su`;
  - the login session;
- **where:** the terminal and the working folder;
- **what:** the program and its arguments, its process ID and its parent's.

The recorder also writes a line when it starts, when it stops, and when the
kernel dropped process events on a busy machine.

**Secrets are blanked before they are written.** A value given with
`--password` or `--token`, `mysql -p...`, `sshpass -p`, `curl -u user:pass`,
or any token shape the [exposed secrets scan](exposed-secrets.md) recognizes
is replaced by its length. `--keep-secrets` turns this off. Do so only if the
log is kept as carefully as the secrets themselves.

The log is `~/.local/state/megalodon/commands.jsonl` (mode 600; for the
root service, root's home). Past 64 MiB it moves aside under a name of its own,
`commands.jsonl.000000048211` after its first line. No rotated file is ever
written over, and `verify` reads them all in order.

To keep less on the machine, move the oldest rotated files off it, for
example next to the key. Then verify the rest with `--from-sequence`, the first
line of the oldest file you kept. That boundary comes from you, off the
machine. It is not written in the log, where an intruder holding the current
key could write one too.

Only one recorder runs at a time. A second `commands record` for the same log
is refused, because two would sign different lines with the same key.

## Why it cannot be quietly rewritten

* **Forward-secure signatures.** Each line is signed (HMAC-SHA-256) with its
  own key. The next key is a one-way hash of the last, and the last is then
  thrown away, so the machine only ever holds the key for the next line. An
  intruder who gets root at 14:00 holds the 14:00 key. From it they can make
  every later key but no earlier one, so lines written before 14:00 cannot be
  changed or added to.
* **Each line names the one before.** A line's signature covers the previous
  line's signature. Removed, reordered or spliced lines are reported even
  though the lines around them are genuine.
* **The end is carried off the machine.** The
  [heartbeat](tamper-detection.md) carries the last line's sequence and
  signature. The heartbeat monitor and the [fleet view](fleet.md) report the
  log:
  - going back between heartbeats (cut off, or replaced);
  - disappearing;
  - starting over with a new key.

  Pass the last sequence they saw to `verify --expect-sequence`, and a log
  that ends earlier is reported as cut.
* **The lines themselves can leave too.** `megalodon evidence push` copies
  each line to the fleet collector within minutes, and the collector keeps the
  first copy of each. Deleting or rewriting the log on the machine then loses
  nothing that already left. See [evidence off the machine](evidence-shipping.md).
* **Crashes are handled.** Lines reach the disk before the key that comes
  after them is saved. After a crash the recorder carries on from the last
  line it wrote, and never signs two lines with one key.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `COMMAND_LOG_FORGED` | CRITICAL | A line does not match its signature, does not follow the line before it, or is not a signed record at all: it was changed, inserted, reordered, spliced or overwritten |
| `COMMAND_LOG_GAP` | HIGH | Lines are missing from the middle: they were removed |
| `COMMAND_LOG_TRUNCATED` | HIGH | The log ends before `--expect-sequence`: its end was cut off |
| `COMMAND_LOG_STOPPED_UNCLEANLY` | MEDIUM | The recorder started again without having stopped: it crashed or was killed, and programs in between are not recorded |
| `COMMAND_LOG_EVENTS_LOST` | MEDIUM | The kernel dropped process events on a busy machine, or with `--trace-execs` had no room for some records: some programs were not recorded |

These are reported by the heartbeat monitor and the fleet view:

| Rule | Severity | When |
| --- | --- | --- |
| `COMMAND_LOG_ROLLED_BACK` | CRITICAL | The last line went back between heartbeats |
| `COMMAND_LOG_LOST` | HIGH | Heartbeats stopped carrying the command log |
| `COMMAND_LOG_RESTARTED` | MEDIUM | The log was started over with a new key (`init --replace`, or an intruder hiding what came before) |

## Limits

* **After a compromise, anything goes.** An intruder with root can stop the
  recorder, and can forge lines from the moment they got in. What the log
  guarantees is the past: everything up to then, and evidence that it stopped
  or was cut.
* **Root is needed.** Without it, the recorder polls `/proc` four times a
  second. It misses programs that exit sooner, and other accounts' arguments
  and folders.
* **Very short programs** may be recorded without their arguments or folder,
  unless the recorder runs with `--trace-execs`. They are gone before the
  recorder reads them; the line still records that they ran.
* **The key's safety is yours.** A key left on the machine makes the log
  rewritable by whoever finds it. A lost key makes it impossible to verify.
