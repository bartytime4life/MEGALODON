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
  ledger, `~/.local/state/megalodon/response-shadow.jsonl` (mode 600). Every
  new finding, decided on or not, goes with its incident to
  `observations.jsonl` beside it, and so does each merge of two incidents. The
  [incident timeline](incident-timeline.md) reads both.
* **`watch --interval 300`** repeats `run` until stopped.
* **`ingest`** decides on findings read as JSON lines from standard input,
  for example from the credential access watch:

  ```bash
  megalodon credentials watch | megalodon respond ingest
  ```

  A process a finding lists with `"writing": false` is kept as evidence and
  is never a target. The ransomware watch lists readers, such as a viewer
  or a backup, that way. MEGALODON's own live watches do not need this pipe.
  With `--respond` (process ancestry, egress, credential access, devices,
  ransomware and container escapes), each decides its findings itself and
  then runs enforcement, as the [scheduler](scheduling.md) runs them. `ingest` is for findings from
  other tools, or a watch you run by hand.

* **`report --hours 168`** summarizes the last week: decisions per
  playbook, actions that would apply or were refused, the guards that
  refused them, and the most frequent targets.

`mode = "enforce"` is refused: this engine only records decisions. The
separate [enforcement](enforcement.md) step carries out the ones its own
policy allows, each with a way to undo it.

When enforcement carries out a decision, it pauses the process and blocks
the address first, then does the rest in the playbook's order: collecting
evidence takes a while, and a process encrypting files or holding a shell
would otherwise go on meanwhile.

## How a decision is made

1. **Collect.** Findings come from:
   * the network audit store (`audit_db`), reading only detections not seen
     before;
   * the process-and-network review: reverse-shell shapes, and programs
     running from memory, from a deleted file or from a temporary folder;
   * the [process ancestry](process-ancestry.md) check: services running
     shells or attack tools. Its live `watch` can be piped into `ingest`;
   * the [rootkit cross-checks](rootkit-check.md), without the port test
     unless `rootkit_ports = true`;
   * the [listener](listener-watch.md), [persistence](persistence-watch.md),
     [program integrity](binary-integrity.md), [log](log-integrity.md),
     [device](device-watch.md), [web-root](webroot-watch.md),
     [tamper](tamper-detection.md), [egress](egress-watch.md),
     [credential](credential-watch.md), [login](login-watch.md),
     [boot](boot-integrity.md), [eBPF](ebpf-watch.md), [container](container-watch.md),
     [hardening drift](hardening-drift.md), [package sources](package-sources.md) and
     [exposed secrets](exposed-secrets.md) checks, and
     canaries;
   * the auth log (`auth_log`, which `respond init` sets to `/var/log/auth.log` or
     `/var/log/secure` when the system keeps one): [login review](host-tripwires.md#login-review-auth-review)'s failed
     login bursts, password spraying, logins that succeeded after many failures, sudo
     misuse and new or privileged accounts. Each pass reads the log and decides only
     findings newer than the last it read, every one of them, not only the 500
     `auth-review` shows; up to 5000 a pass, the rest the next. A first pass looks
     back a day. Reading the
     log usually needs membership in the `adm` group. The usernames an attacker tried
     never link incidents (every attacker tries `root`); the address does, and so does
     a real local account.

   Each check needs its baseline. A source that can't be read is listed
   under `gaps`.
2. **Correlate.** Findings that share an address, program, file, port,
   persistence location or account within `correlation_minutes` form one
   incident. An incident with findings from two different sources is
   *corroborated*. One address trying many different kinds of attack within
   minutes is also raised as an [automated campaign](automated-campaigns.md)
   (`AUTOMATED_CAMPAIGN`), a finding of its own that joins the incident; it is
   made from the others, so it never corroborates them.
3. **Match.** The first playbook whose `rules` include the finding's rule,
   at or above `min_severity`, applies. A playbook can also require
   particular `sources` or `categories`, or `require_corroboration`.
   `block_minutes` sets how long its blocks last, and `suspend_minutes` (0 to
   10080, 0 by default) how long its pauses last; 0 means until undone.
4. **Plan and guard.** Each of the playbook's actions is planned against the
   finding's concrete targets, then checked by the guards. A plan is
   recorded as `would_apply`, or as `refused` with the guard's reason.
5. **Record.** Each decision is one ledger line with the finding, the
   incident, the playbook, each planned action and the policy's SHA-256.
   `carried_out` is always `false`.

The same finding is decided at most once a day.

Passes take turns. Collecting runs on its own, so a long collection never holds
up a live watch. Correlating, deciding and recording run one pass at a time:
each pass reads the incidents, seen findings and rate counts the last pass
wrote. The timer's pass and a ransomware finding can be decided at the same
moment without either losing the other's state.

## Actions

| Action | Target | What it would do |
| --- | --- | --- |
| `collect_evidence` | — | Save a hashed, read-only snapshot of the programs, sockets and files involved, before anything else: what [`megalodon evidence collect`](evidence-collection.md) does |
| `notify` | — | Send a summary to the [off-machine alerts](off-machine-alerts.md) |
| `block_address` | address | Drop traffic to and from the address for `block_minutes`. For a finding from a container (`ADDRESS@net:[ID]`), only inside that container's network namespace |
| `suspend_process` | process, or program | Pause (SIGSTOP) the process, keeping it for investigation; with `suspend_minutes`, only for that long |
| `quarantine_file` | file | Move the file aside with no permissions, recording its hash |
| `disable_persistence` | persistence entry | Disable a service, job or startup entry without deleting it. Refused for locations the [persistence watch](persistence-watch.md) does not cover, and for MEGALODON's own units |
| `lock_account` | account | Lock the account's password and logins |
| `block_device` | device | Cut off one plug-in of one USB device (`PORT#NUMBER@identity`): its drivers let go, so it cannot type, store or carry traffic |

Every action is designed to be reversible.

## Guards

Guards apply whatever the playbooks say:

* **Addresses.** Only public addresses are blocked. Attackers on the local
  network need switch-level controls. This machine's gateways, DNS servers
  and own addresses, and anything in `never_touch_addresses`, are refused.
  A finding from another network namespace, such as a container's
  connection, names its remote address as a `peer`, which links incidents,
  and as `ADDRESS@net:[ID]`, which is what `block_address` blocks. This
  machine's own blocks do not stop routed traffic, so the block is made
  inside that namespace, under the same guards.
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
| ransomware | `RANSOMWARE_ENCRYPTION`, `RANSOMWARE_MASS_WRITE` | Collect evidence, suspend the processes seen writing in the watched folders, notify |
| bind-shell-or-dropped-listener | HIGH `NEW_LISTENER`, `LISTENER_PROGRAM_CHANGED` | Collect evidence, suspend the program, notify |
| web-shell-or-exploited-service | HIGH `SERVICE_SPAWNED_SHELL`, `SERVICE_SPAWNED_TOOL` | Collect evidence, suspend the started process, notify |
| rootkit | `HIDDEN_PROCESS`, `HIDDEN_MODULE`, `HIDDEN_PORT`, `HIDDEN_DIRECTORY`, `HIDDEN_FILE`, `PRELOAD_LIBRARY` | Collect evidence, notify: a machine that hides things from itself cannot be trusted to clean itself |
| web-shell-file | HIGH `SCRIPT_IN_UPLOAD_FOLDER`, `CODE_IN_NON_SCRIPT_FILE`, `WEB_SHELL_PATTERN` | Collect evidence, quarantine the file, notify |
| ebpf-rootkit | `EBPF_HIDDEN_PROGRAM`, `EBPF_LOADED_BY_DROPPED_TOOL` | Collect evidence, suspend the holding process, notify |
| ebpf-change | HIGH `EBPF_NEW_PROGRAM`, `EBPF_PROGRAM_CHANGED`, `EBPF_UNPRIVILEGED_ENABLED` | Collect evidence, notify |
| container-escape | `CONTAINER_ESCAPE`, `ESCAPE_HOOK_SET`, `RUNTIME_API_EXPOSED`, `RUNTIME_SOCKET_WORLD_WRITABLE` | Collect evidence, suspend the escaped process, notify |
| watchlisted-name | `OUTBOUND_TO_WATCHLISTED_NAME` | Collect evidence, suspend the process, block the address 60 minutes, notify |
| code-loaded-into-memory | `MEMORY_ELF_IN_ANONYMOUS` (with `memory_sweep = true`) | Collect evidence, suspend the process, notify |
| code-run-from-memory | HIGH `MEMORY_EXECUTABLE_MEMFD`, `MEMORY_EXECUTABLE_TEMPORARY` | Collect evidence, notify |
| hardening-drift | HIGH `FILE_CAPABILITY_BACKDOOR`, `FILE_CAPABILITY_ADDED`, `PROGRAM_WRITABLE`, `PATH_FOLDER_WRITABLE`, `PATH_HAS_RELATIVE_ENTRY`, `HARDENING_WEAKENED` | Collect evidence, notify |
| secret-exposed | HIGH `SECRET_FILE_IN_WEB_ROOT`, `VERSION_CONTROL_IN_WEB_ROOT`, `SECRET_IN_WEB_ROOT`, `PRIVATE_KEY_EXPOSED`, `CREDENTIAL_FILE_EXPOSED`, `SECRET_IN_COMMAND_LINE`, `SECRET_IN_EXPOSED_FILE` | Notify: restrict or move the secret, then replace it |
| package-trust-changed | HIGH `PACKAGE_SIGNATURES_OFF`, `PACKAGE_CONFIG_WRITABLE`, `SIGNING_KEY_ADDED`, `PACKAGE_SOURCE_REDIRECTED`, `PACKAGE_SOURCE_CHANGED`, `PACKAGE_CONFIG_REDIRECTED`, `PACKAGE_MANAGER_HOOK_ADDED`, `PACKAGE_MANAGER_HOOK_SUSPICIOUS`, `PACKAGE_SIGNATURE_CHECK_WEAKENED` | Collect evidence, notify |
| container-exposure | HIGH `CONTAINER_PRIVILEGED`, `CONTAINER_RUNTIME_SOCKET`, `CONTAINER_HOST_PATH_MOUNTED`, `CONTAINER_DANGEROUS_CAPABILITY`, `CONTAINER_HOST_PID`, `ESCAPE_HOOK_CHANGED`, `RUNTIME_GROUP_MEMBER_ADDED` | Collect evidence, notify |
| boot-tampering | HIGH and CRITICAL [boot integrity](boot-integrity.md) findings | Collect evidence, notify |
| service-account-login | `LOGIN_SERVICE_ACCOUNT` | Collect evidence, lock the account, block the source for 60 minutes, notify |
| unusual-login | HIGH `LOGIN_NEW_KEY`, `LOGIN_NEW_SOURCE`, `LOGIN_ROOT_REMOTE`, `LOGIN_NEW_ACCOUNT`, `SUDO_FIRST_USE` | Collect evidence, notify |
| credential-theft | `CREDENTIAL_SWEEP`, `CREDENTIAL_READ_BY_DROPPED_TOOL` | Collect evidence, suspend the process, notify |
| credential-read | HIGH `CREDENTIAL_READ` | Collect evidence, notify |
| dropped-tool-phoning-home | `OUTBOUND_FROM_TEMPORARY` | Collect evidence, suspend the process, block the address for 60 minutes, notify |
| new-outbound-program | HIGH `NEW_OUTBOUND_PROGRAM` | Collect evidence, notify |
| sensor-tampering | HIGH and CRITICAL [tamper](tamper-detection.md) findings this machine's tamper check raises (those of the heartbeat monitor are raised off the machine) | Collect evidence, notify |
| new-hardware | HIGH `NEW_USB_KEYBOARD`, `NEW_NETWORK_ADAPTER`, `NEW_THUNDERBOLT_DEVICE`, `DEVICE_GAINED_FUNCTIONS` | Cut off the USB device, notify: only you know whether you plugged it in, and `enforce undo` lets it back |
| program-from-memory | `EXECUTABLE_IN_MEMORY` | Collect evidence, notify |
| automated-campaign | [`AUTOMATED_CAMPAIGN`](automated-campaigns.md): one address, many different kinds of attack within minutes | Collect evidence, block the address for 60 minutes, notify |
| lure-followed | `LURE_FOLLOWED`: a login was tried as the account an [agent lure](host-tripwires.md#agent-lures-catching-an-ai-agent-at-work) names | Collect evidence, block the address for 60 minutes, notify. Needs `canary_manifest` and `auth_log` |
| guessed-login | `AUTH_SUCCESS_AFTER_FAILURES`: a login succeeded from an address that had just failed many times | Collect evidence, block the address for 60 minutes, notify. The account is a real person's, so it is not locked: change its password |
| attacker-at-the-door | HIGH `BRUTE_FORCE`, `DECOY_TOUCH`, `SYN_FLOOD`, `AUTH_FAILURE_BURST`, `PASSWORD_SPRAY` | Block the source for 30 minutes, notify. `PORT_SCAN` and `HOST_SWEEP` are listed too, but are always MEDIUM, so they are alerted, not acted on |
| command-and-control-or-exfiltration | HIGH `DATA_EXFILTRATION`, `IOC_MATCH`, `DNS_TUNNELING`, `DNS_TUNNEL_CHURN` | Only when corroborated: collect evidence, block for 60 minutes, notify. `BEACONING` and `DGA_DOMAIN` are listed too, but are always MEDIUM, so they are alerted, not acted on |
| new-backdoor-account | CRITICAL account changes in the persistence watch | Collect evidence, lock the account, notify |
| new-persistence-entry | `PERSISTENCE_ADDED`: a service, timer, cron or at job, startup file, SSH key file, preload, sudoers, PAM, init or module file the baseline did not have | Collect evidence, disable the entry, notify |
| trojaned-program-or-wiped-log | HIGH and CRITICAL program integrity (including an unpackaged program in a system folder, or a writable one), log and journal integrity, and canary findings | Collect evidence, notify |

Findings no playbook matches, such as `DNS_BYPASS`, are not decided.

## Where the local AI fits

The engine does not use the local model. Its inputs are shaped by
attackers: domain names, file names, log lines and server names. A model
reading them can be steered. When AI triage is added, it may only hold a
decision or escalate it to you, never start an action.

## Limits

* **The engine itself carries nothing out.** A `would_apply` plan is what
  the [enforcement](enforcement.md) step does, if its own policy lists that
  action and playbook; with enforcement off, as it is until you turn it on,
  nothing is done.
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
  between passes is missed by the pass. The live watches, run with
  `--respond` as the scheduler runs them, decide each finding as it arrives:
  process ancestry, egress, credential access, devices and ransomware, and
  `containers watch --respond` where you run it. So are findings piped into
  `ingest`. A live watch and the pass decide the
  same finding once.
