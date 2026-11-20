# Enforcement

The [response engine](response-engine.md) decides what to do about each
finding and records it in shadow mode. It never acts. `megalodon enforce` is
the separate step that carries those decisions out: only the ones you
allowed, only while they are fresh, and each with a recorded way back.

```bash
sudo megalodon enforce init
```

```bash
sudo megalodon enforce run --dry-run
```

```bash
sudo megalodon enforce list
```

```bash
sudo megalodon enforce undo ID
```

## Turning it on

Watch the shadow decisions first: run `megalodon respond report --hours 168`
for a week or more, and adjust the response policy until what it would do is
what you want done. Then:

1. **`enforce init`** writes `~/.config/megalodon/enforce.toml` (mode 600),
   **off**. It pins the SHA-256 of the response policy you reviewed.
2. **Edit it.** Set `enabled = true`, then list the `actions` and `playbooks`
   to carry out. Start narrow, for example:

   ```toml
   [enforce]
   enabled = true
   actions = ["collect_evidence", "suspend_process", "notify"]
   playbooks = ["dropped-tool-phoning-home", "code-loaded-into-memory"]
   ```

3. **`enforce run --dry-run`** shows what would be carried out now, and
   changes nothing.
4. **The scheduler's `enforce` job** runs `enforce run` every minute as root.
   With no policy, or one that is off, it does nothing.

`enforce.toml` is one of the files the [tamper check](tamper-detection.md)
watches: a change to it is reported as `ENFORCEMENT_CHANGED` (HIGH).

## When a decision is carried out

A decision is carried out only when every check passes:
* **Enabled:** the enforcement policy is on.
* **Listed:** both the action and the decision's playbook are in the
  enforcement policy.
* **Pinned:** the response policy's SHA-256 is still the one pinned. Once you
  edit the response policy, nothing more is carried out until you review it
  and run `enforce init --replace` to pin it again.
* **Planned:** the response engine recorded the action as `would_apply`.
* **Recent:** the decision is less than `max_age_minutes` old (10 by
  default).
* **Still allowed:** the response engine's guards pass again now. These cover
  the never-touch lists, your gateway and DNS servers, this machine's own
  addresses, system programs and folders, and `quarantine_roots`.
* **Within the rate limit:** at most `max_actions_per_hour` actions an hour
  (5 by default). Evidence and notices do not count.
* **Allowed in this process:** the process is not in Stage 0.

Each action is carried out once, and recorded in
`~/.local/state/megalodon/enforced.jsonl` (mode 600). The record holds what
was done, to what, for which finding and incident, and what undoing it takes.
The [incident timeline](incident-timeline.md) shows each one in its incident. A refused
decision is reported with its reason. A failed one is recorded, and makes
`run` exit 1. It is not tried again.

One run or undo happens at a time. A run started while another is going, by
hand or by the scheduler, waits for it, so no decision is carried out twice.
A run that is off, a `--dry-run`, and a run or undo refused in Stage 0 create
no files and wait for nothing.
The scheduled `megalodon-enforce` service keeps `ProtectSystem=full` but can
write to `/etc`. `usermod` needs this to lock an account, because it writes
lock and temporary files beside `/etc/shadow`.

## What each action does

| Action | What happens | Undo |
| --- | --- | --- |
| `suspend_process` | SIGSTOP to the one process named by PID and start time. It is sent through a pidfd after checking that the start time and program still match, so a reused PID is never signalled. Program-wide targets are never signalled. The process is paused, not killed: its memory and files stay for [capture](memory-capture.md). With the playbook's `suspend_minutes`, the pause ends by itself: see below. | SIGCONT |
| `block_address` | A time-limited element in MEGALODON's own nftables table (`inet megalodon`), dropping traffic to and from the address. It expires by itself after the playbook's `block_minutes`. | The element is deleted |
| `quarantine_file` | The file is copied into the quarantine folder with no permissions, checked to be the same file, and removed. Its SHA-256, owner and mode are recorded. The path is opened one folder at a time without following symlinks, so a folder swapped for a symlink after the decision cannot lead outside the folders the guards checked. | Restored with its mode and owner, if the copy still matches its hash, nothing new is at that path, and no folder on the way is now a symlink |
| `lock_account` | `usermod --lock --expiredate 1`. A locked password alone still lets SSH keys in; an expired account does not. Accounts with UID 0 are never locked. | Its previous expiry put back; the password is unlocked only if it was not already locked before |
| `collect_evidence` | An [evidence bundle](evidence-collection.md), plus the [memory](memory-capture.md) of up to four processes the finding names | Nothing to undo |
| `notify` | A summary of what was enforced, to the alert destinations | Nothing to undo |

| `disable_persistence` | For an entry the [persistence](persistence-watch.md) baseline did not have (`PERSISTENCE_ADDED`): the file is moved into the quarantine folder like a quarantined file. A symlink, such as a systemd enablement link, is removed and where it led is recorded; what it leads to is never touched. For a unit in the system manager's folders (`/etc/systemd/system`, `/usr/local/lib/systemd/system`), systemd is told to reload, and a timer, socket or path unit is also stopped, so it fires no more. That holds whether the new entry was the unit's own file or the link that enabled it. A service is left running, so its memory can be captured: pause it with `suspend_process`. Units in `/etc/systemd/user` and `~/.config/systemd/user` belong to each user's own manager: they are moved aside but not stopped, and stop running at that user's next login. If reloading or stopping fails, the entry is put back as it was and the action is recorded as failed. If systemd fails during an undo, after the entry is back, run the undo again: an entry already put back, with the same content or link target, is taken as done, and the systemd steps are finished. | The file or link is put back if nothing is at that path now, systemd reloads, and a timer, socket or path unit that was running is started again |

`disable_persistence` never moves an entry that existed before and was
changed, such as an edited `/etc/sudoers`, `sshd_config` or `.bashrc`. Moving
it would also remove what was there before, so it is refused with the reason
recorded, whatever the playbook says. It acts only on locations the
persistence watch covers, never on accounts, kernel modules or setuid
programs, and never on MEGALODON's own units. The default
`new-persistence-entry` playbook decides it for new entries; list
`disable_persistence` and that playbook in `enforce.toml` to have it carried
out. After an undo, run `megalodon persistence accept` if the entry is wanted,
or it is reported, and decided, again.

`enforce list` shows the applied actions that have not been undone.

## Pauses that end on time

A playbook's `suspend_minutes` in the response policy (0, the default, means
until undone) sets how long a pause lasts. The record then carries `until`.
Every `enforce run` first resumes the pauses whose time is up, before it
carries out new decisions:

* **Even when enforcement is off**, or its policy has been removed, so turning
  it off never leaves a process paused past its time.
* **With the same checks as an undo.** SIGCONT goes through a pidfd, and only
  if the start time and program still match. A process that has exited, or
  whose PID now names another process, is not signalled, and its pause is
  recorded as over.
* **A process paused twice stays paused until both end.** When another
  decision paused the same process, for longer or until undone, the pause
  that ended is recorded as over, with `still paused by ID`, and the process
  is resumed only when the last pause ends.
* **A resume that fails**, for example for lack of permission, is reported as
  failed and makes `run` exit 1. The process stays listed by `enforce list`,
  and the next run tries again.
* **Recorded like an undo**, with `reason = "expired"`. The
  [incident timeline](incident-timeline.md) shows it as ended on time.
  `--dry-run` lists what it would resume, and resumes nothing, also when
  the enforcement policy has been removed.

Resuming is a trade-off. It frees a process paused by a wrong decision, but it
also frees a real intruder's process. The default playbooks set no
`suspend_minutes`: set it on the playbooks where a wrong pause costs more than
a resumed attacker, and capture the process's memory before the time is up.

## Limits

* **Root is needed** for every action except notices and evidence about your
  own processes.
* **A paused process stays paused** until you undo it or stop it yourself,
  unless its playbook sets `suspend_minutes`.
* **`~/` is one account's home.** A persistence location under `~/` is in the
  home of the account that ran the persistence check, and enforcement resolves
  it in its own home. The [scheduler](scheduling.md) runs both as the same
  account. Other accounts' startup files are not reached this way.
* **A disabled service keeps running** until it is paused or stopped. Its unit
  file is gone, so it does not start again at the next boot.
* **Quarantine keeps one copy.** The quarantine folder is on the local disk,
  so keep it off the machine if the file matters.
* **Decisions are only as good as the findings.** Every rule here can be
  wrong. That is why enforcement starts off, acts only on what you list, and
  keeps a way back for each action.
