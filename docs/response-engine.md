# Response engine (shadow mode)

`megalodon respond` decides how MEGALODON would respond to what it finds and
records each decision. It **carries nothing out**. Run it for a few weeks,
compare its decisions with what you would have done, and adjust the policy.
Automatic action is a later, separate step, and the evidence for it is the
ledger this produces.

```bash
megalodon respond init
```

```bash
megalodon respond run
```

```bash
megalodon respond report
```

* **`init`** writes the default policy to
  `~/.config/megalodon/response-policy.toml` (mode 600). Read and edit it:
  it is the only thing that decides what the engine plans.
* **`run`** collects findings once, decides, and appends the decisions to the
  ledger, `~/.local/state/megalodon/response-shadow.jsonl` (mode 600).
* **`watch --interval 300`** repeats `run` until stopped.
* **`ingest`** decides on findings read as JSON lines from standard input,
  for example from the ransomware watch:

  ```bash
  megalodon ransomware watch --dir ~/Documents | megalodon respond ingest
  ```

* **`report --hours 168`** summarizes the last week: decisions per
  playbook, actions that would apply or were refused, the guards that
  refused them, and the most frequent targets.

`mode = "enforce"` is refused. Only shadow mode exists.

## How a decision is made

1. **Collect.** Findings come from:
   * the network audit store (`audit_db`), reading only detections not seen
     before;
   * the process-and-network review: reverse-shell shapes, and programs
     running from memory, from a deleted file or from a temporary folder;
   * the [listener](listener-watch.md), [persistence](persistence-watch.md),
     [program integrity](binary-integrity.md) and [log](log-integrity.md)
     checks, and canaries.

   Each check needs its baseline. A source that can't be read is listed
   under `gaps`.
2. **Correlate.** Findings that share an address, program, file, port,
   persistence location or account within `correlation_minutes` form one
   incident. An incident with findings from two different sources is
   *corroborated*.
3. **Match.** The first playbook whose `rules` include the finding's rule,
   at or above `min_severity`, applies. A playbook can also require
   particular `sources` or `categories`, or `require_corroboration`.
4. **Plan and guard.** Each of the playbook's actions is planned against the
   finding's concrete targets, then checked by the guards. A plan is
   recorded as `would_apply`, or as `refused` with the guard's reason.
5. **Record.** Each decision is one ledger line with the finding, the
   incident, the playbook, each planned action and the policy's SHA-256.
   `carried_out` is always `false`.

The same finding is decided at most once a day.

## Actions

| Action | Target | What it would do |
| --- | --- | --- |
| `collect_evidence` | — | Save a hashed, read-only snapshot of the programs, sockets and files involved, before anything else: what [`megalodon evidence collect`](evidence-collection.md) does |
| `notify` | — | Send a summary to the [off-machine alerts](off-machine-alerts.md) |
| `block_address` | address | Drop traffic to and from the address for `block_minutes` |
| `suspend_process` | process, or program | Pause (SIGSTOP) the process, keeping it for investigation |
| `quarantine_file` | file | Move the file aside with no permissions, recording its hash |
| `disable_persistence` | persistence entry | Disable a service, job or startup entry without deleting it |
| `lock_account` | account | Lock the account's password and logins |

Every action is designed to be reversible.

## Guards

Guards apply whatever the playbooks say:

* **Addresses.** Only public addresses are blocked. Attackers on the local
  network need switch-level controls. This machine's gateways, DNS servers
  and own addresses, and anything in `never_touch_addresses`, are refused.
* **Programs.** init, systemd, sshd and dbus, and anything in
  `never_touch_programs`, are never suspended. A plan names the processes
  behind the finding (`pid@start:program`; the start time keeps a reused
  process ID from matching). Without one, a whole program is planned only
  when nothing else shares it: a shell, an interpreter or anything in a
  system folder is refused, because pausing `/usr/bin/bash` would pause
  every login.
* **Files.** Files in system folders (`/usr`, `/etc`, `/var/lib`,
  `/var/log`...) are never quarantined; reinstall the package instead.
  Only files under `quarantine_roots` are.
* **Accounts.** `root`, the account running MEGALODON and
  `never_touch_accounts` are never locked.
* **Rates.** At most `max_actions_per_hour` actions an hour, the same action
  on the same target at most `max_actions_per_target_per_day` times a day,
  and no block longer than `max_block_minutes`. Evidence collection and
  notification are not counted.

## Default playbooks

| Playbook | Findings | Would do |
| --- | --- | --- |
| reverse-shell | `STDIO_SHELL_ON_NETWORK`, `SHELL_HOLDS_SOCKET`, `PIPED_TO_SHELL` | Collect evidence, suspend the program, block the remote address for 15 minutes, notify |
| ransomware | `RANSOMWARE_ENCRYPTION`, `RANSOMWARE_MASS_WRITE` | Collect evidence, suspend the suspect programs, notify |
| bind-shell-or-dropped-listener | HIGH `NEW_LISTENER`, `LISTENER_PROGRAM_CHANGED` | Collect evidence, suspend the program, notify |
| program-from-memory | `EXECUTABLE_IN_MEMORY` | Collect evidence, notify |
| attacker-at-the-door | HIGH `BRUTE_FORCE`, `HOST_SWEEP`, `DECOY_TOUCH`, `SYN_FLOOD`, `PORT_SCAN` | Block the source for 30 minutes, notify |
| command-and-control-or-exfiltration | HIGH `BEACONING`, `DATA_EXFILTRATION`, `IOC_MATCH`, DNS rules | Only when corroborated: collect evidence, block for 60 minutes, notify |
| new-backdoor-account | CRITICAL account changes in the persistence watch | Collect evidence, lock the account, notify |
| trojaned-program-or-wiped-log | Program integrity, log integrity and canary findings | Collect evidence, notify |

Findings no playbook matches, such as `DNS_BYPASS`, are not decided.

## Where the local AI fits

The engine does not use the local model. Its inputs are shaped by
attackers: domain names, file names, log lines and server names. A model
reading them can be steered. When AI triage is added, it may only hold a
decision or escalate it to you, never start an action.

## Limits

* **Nothing is carried out.** There is no apply route. A `would_apply` plan
  shows what a future enforcement step would do with this policy, and
  nothing more.
* **Correlation is by shared values.** Two findings about the same attack
  with nothing in common stay separate incidents.
* **Process targets name processes where the source knows them.** The
  process review and the process ancestry watch name the processes; the
  listener watch names only programs, so its plans are limited by the
  shared-program guard.
* **The policy file is protected by its permissions only.** It must be owned
  by you and writable only by you, and every decision records its SHA-256.
  Cryptographic signing comes with enforcement.
* **Sources are read when `run` runs.** A reverse shell that opens and closes
  between passes is missed. The ransomware watch is real-time only when
  piped into `ingest`.
