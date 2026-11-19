# Incident timeline

Every scheduled check feeds the [response engine](response-engine.md). The
engine ties findings that share an address, process, file, port, persistence
location or account into **incidents**. `megalodon timeline` tells each
incident as one story, in the order things happened:

- **findings**, from every check, with the addresses, programs, files and
  accounts each one named;
- **decisions**: the playbook that matched, each action it would take, and why
  a guard refused one;
- **actions** that [enforcement](enforcement.md) carried out, refused or failed,
  the evidence bundles it collected, and undos.

```bash
megalodon timeline list
```

```bash
megalodon timeline show 3f9c2a
```

```bash
megalodon timeline show --entity address:203.0.113.7
```

```bash
megalodon timeline show 3f9c2a --format html --output incident.html
```

* **`list`** shows incidents with activity in the last `--hours` (168 by
  default), worst first. Each line gives when the incident started and ended,
  its worst severity, which checks saw it, and how many actions were carried
  out.
* **`show ID`** tells one incident, from first finding to last action. The
  start of an ID is enough. An incident that the engine later merged into
  another opens the one it became part of.
* **`show --entity KIND:VALUE`** follows one address, process, file, port or
  account across every incident that involved it. A peer address counts as
  the address it is.
* **`--format`** is `text` (the default), `json`, or, for `show`, `html`. The
  HTML page is static: it has no scripts and loads nothing from elsewhere.
* **`--output FILE`** writes the result mode 600. A timeline names addresses,
  programs, files and accounts, so keep exports where only you can read them.

## Where it comes from

The timeline reads only what was already recorded. Each file below is mode 600
and refused if it is readable by others.

| File | Written by | Holds |
| --- | --- | --- |
| `~/.local/state/megalodon/observations.jsonl` | `megalodon respond run` | Every new finding with its incident, and every time two incidents were merged |
| `~/.local/state/megalodon/response-shadow.jsonl` | `megalodon respond run` | Each decision a playbook made, with its incident |
| `~/.local/state/megalodon/enforced.jsonl` | `megalodon enforce` | Each action carried out, refused, failed or undone, with its incident |

The rotated copies (`.1`) are read too, and every file is read to its end,
however large. Older ledgers and journals, written before findings and actions
carried their incident, are still read. Their actions are matched to their
decisions by time, rule, playbook, action and target. An action that matches
decisions in two incidents is left unassigned rather than guessed; it still
shows with `--entity`.

## Limits

* **Only what the engine saw.** A check that is not a response engine source,
  or a source that is off, adds nothing. The [scheduler](scheduling.md) runs the
  engine every five minutes.
* **New findings, once a day.** A finding that stays true is recorded when it is
  first seen and again a day later, not on every pass.
* **Incidents are the engine's.** Findings join an incident when they share
  something within `correlation_minutes` (30 by default). Findings further apart
  are separate incidents; `--entity` shows them together.
* **Local only.** The [fleet view](fleet.md) shows other machines; their timelines
  are on each machine.
