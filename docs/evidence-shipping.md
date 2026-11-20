# Evidence off the machine

The [command log](command-log.md) and [evidence bundles](evidence-collection.md)
are only as safe as root on the machine that holds them. An intruder who gets
root can delete them, or cut the log short. Deleting evidence is ATT&CK T1070,
and changing it is T1565.001. `megalodon evidence push` copies them to the
[fleet collector](fleet.md) as they are written, and the collector keeps the
first copy of everything.

On each machine:

```bash
sudo megalodon evidence push
```

On the collector:

```bash
megalodon fleet evidence
```

```bash
megalodon fleet evidence web-1 --verify --key-file /media/usb/megalodon-commands.key
```

* **`evidence push`** sends what has not been sent yet, most valuable first:
  1. command log lines, exactly as the recorder signed them;
  2. every bundle's manifest, which holds each file's size and SHA-256;
  3. the files the manifests list, in pieces, newest bundle first.

  Each request is signed with the machine's heartbeat key, so enrolling the
  machine is all it needs. Requests go to the heartbeat address with
  `/evidence` in place of `/heartbeat` (or `--url`).

  By default one push sends at most 64 MiB of file pieces (`--max-mib`); the
  rest goes next time. The [scheduler](scheduling.md) runs it every five
  minutes. A heartbeat monitor that is not a fleet collector answers 404, and
  the push then sends nothing and does not fail. Run it as root, the account
  that writes the command log and the bundles.
* **`fleet evidence`** lists, for each machine, what the collector holds:
  - each copy of its command log, with its first and last line and when the
    last one arrived;
  - each bundle, and how many of its files have arrived;
  - anything reported, as below.

  It exits 1 when something is reported.
* **`fleet evidence MACHINE --verify`** checks the collector's copies:
  - **The command log**, with `--key-file`: the key that `commands init` wrote.
    It checks the copy from line 1 up to the line the machine's last heartbeat
    named. A copy that starts later is reported as having a gap, and one that
    ends earlier as cut (`COMMAND_LOG_TRUNCATED`). If you moved the oldest
    lines off the machine yourself before the first push, give the first line
    you kept with `--from-sequence`. That boundary comes from you, never from
    the machine.
  - **Every bundle** whose files have all arrived, against the manifest digest
    recorded when the manifest arrived.

  It exits 1 on findings. A bundle on the collector is an ordinary bundle
  folder, so `megalodon evidence verify FOLDER` reads it too.

## The first copy is kept

The collector never replaces anything it already holds:
- a command log line sent again must match the first copy in every field, not
  only its signature;
- a manifest sent again must match the first one;
- a file piece sent again must match the bytes that arrived first;
- a finished file must match the SHA-256 in its manifest, or it is not placed
  in the bundle. An empty file is placed when the manifest arrives, if the
  manifest gives it the digest of empty content.

Anything else is kept aside and reported. An intruder who gets root later can
stop the copying. They can also send whatever they like from then on, because
they hold the heartbeat key too. What they cannot do is change what already
left the machine.

| Rule | Severity | When |
| --- | --- | --- |
| `SHIPPED_COMMANDS_REWRITTEN` | CRITICAL | A command log line the collector holds was sent again with other content, or a line missing from the copy was sent later: the log on the machine was rewritten |
| `SHIPPED_EVIDENCE_CHANGED` | CRITICAL | A bundle's manifest or file was sent again with other content, a file did not match its manifest, or the collector's copy no longer matches its manifest |
| `SHIPPED_COMMANDS_GAP` | HIGH | Lines were already missing when the machine sent the lines after them, or the first line to arrive was not line 1: they were removed before they left the machine |

These appear in [`fleet status`](fleet.md), and put the machine in `attention`.
`--verify` adds the [command log's own rules](command-log.md#what-is-reported)
for the copy.

## The batches

* **Checked like timeline batches.** A batch must:
  - come from an enrolled machine (else 403);
  - be signed with that machine's key (else 401, and nothing is kept);
  - be newer than the last batch accepted from it (a replay gets 409).
* **The collector answers item by item.** For a file piece, it says how much of
  the file it holds, and the machine resumes from there. A machine that lost
  its record of what it sent (`~/.local/state/megalodon/evidence-push.json`)
  carries on where the collector is, without sending everything again.
* **Paths stay inside their bundle.** A manifest whose file names are absolute,
  contain `..`, contain anything but plain name characters, or name the
  manifest itself is refused before anything is written.
* **The log arrives in order.** When the collector does not take a batch of
  command log lines, for example because it is full, it takes no later batch
  of that log in the same request. The machine sends no later batch either,
  and records nothing as sent past it. Nothing is skipped: the next push starts
  again at the batch that was not taken.
* **Sizes are bounded.** `/evidence` takes bodies up to 1 MiB, and pieces are
  384 KiB before base64. Heartbeats, alerts and timelines keep the 64 KiB
  limit. The collector keeps at most 64 GiB per machine and then takes nothing
  more; the machine keeps what was not taken for later. A machine sending
  rewrite after rewrite stops being recorded once 8 MiB of reports are kept,
  and refused lines and manifests stop being kept once 64 MiB of them are,
  within the 64 GiB.
* **One push at a time.** A second push while one runs is refused.

## Where the collector keeps it

Under the collector's data folder, in `machines/NAME/shipped/`:

| Path | What |
| --- | --- |
| `commands/KEY_ID/commands.jsonl` | The copy of the command log started with that key, rotated past 64 MiB the way the machine rotates it |
| `commands/KEY_ID/rewritten.jsonl` | Lines that arrived again with other content, for comparison |
| `evidence/BUNDLE/` | Each bundle: its manifest and the files that have arrived and matched it |
| `evidence-rejected/BUNDLE/` | Manifests and files that did not match what was held, or their manifest |
| `conflicts.jsonl` | Everything reported above |

Every file is mode 600 or read-only, and every folder 700.

## Limits

* **Only what was written before the push.** Lines and bundles written after an
  intruder got root, and before the next push, can be held back or changed
  before they leave. With the scheduler, that is at most five minutes of
  activity. The heartbeat still carries the log's last line, so a copy that
  ends early is reported.
* **The collector cannot check signatures without the key.** It keeps lines as
  signed. Only `--verify --key-file`, run where the key is, proves them genuine.
  Keep the key off both machines if you can.
* **Logs started over.** After `commands init --replace`, the old log is moved
  aside on the machine and its lines not yet sent stay there. The new log is
  copied under its own key.
* **Very large manifests.** A manifest over about 640 KiB, such as a memory
  capture listing thousands of regions, is not sent and is counted as
  `too_large`. The bundle stays on the machine.
* **One collector.** If it is down, pushes fail and are retried on the next
  run, from where the collector stands.
