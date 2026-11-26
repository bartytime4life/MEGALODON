# Security report: the whole machine, in plain language

`megalodon report` puts everything MEGALODON knows about this machine on one
page, written for the person who owns it rather than for a security analyst:

- **a verdict**: act now, review, parts not running (or not looked at), or all clear;
- **what to do next**, most important first, each step with its command;
- **every check**, grouped as break-ins and backdoors, tampering and
  integrity, and weak spots, with what it watches and what it last found;
- **each finding**: what it means, how serious it is, and your choices;
- **incidents**: findings the [response engine](response-engine.md) joined
  into one story, and what [enforcement](enforcement.md) did about them;
- **how you are protected**: the schedule, the baselines, alerts, the
  response and enforcement policies, and the heartbeat.

```bash
megalodon report
```

```bash
megalodon report --format html --output ~/report.html
```

```bash
megalodon report --format json
```

* **Text** (the default) is for the terminal.
* **`--format html`** is one self-contained page, light or dark with the
  system, that works on a phone. It loads nothing from anywhere.
* **`--format json`** is for programs.
* **`--output`** writes the report to a file, mode 600, and prints the
  verdict. It names programs, files and addresses on this machine.

The [scheduler](scheduling.md) writes the HTML page to
`~/.local/state/megalodon/report.html` every morning (the `report` job).

## Where it comes from

The report runs no check itself, so it is quick and changes nothing. It reads:

* **Each check's latest result.** Every `megalodon CHECK check` keeps what it
  found, when, and its exit code in `~/.local/state/megalodon/results/`
  (mode 600, in a mode-700 folder). The scheduled jobs so keep the report
  current. Only a check of the machine's own baseline is kept: one given
  `--manifest` checks another baseline, not this machine's state.
* **The live watches.** Credentials, process ancestry, listeners, egress, the
  web root and devices run all the time once scheduled. The report says
  whether their service is running. The listener and web-root watches add
  what they see, as they see it, to their check's last result, listed under
  the check with when; a restarted watch keeps what it saw before. The next
  `check` replaces that result, and `accept` or a new baseline clears it. The
  latest 500 are listed and every one is counted. The other watches pass what
  they find to the response engine, and it reaches the incidents.
* **Incidents** of the last week (`--hours` to change), from the response
  engine's ledger and the enforcement journal, as `megalodon timeline` tells
  them.
* **The setup**: which scheduled jobs are installed, which still need a
  baseline, the alert settings, the response and enforcement policies, and
  the heartbeat. Each is read by the module that uses it, so a policy that
  module would refuse is reported as not working, and enforcement pinned to a
  response policy that has changed since is reported as carrying nothing out.
  Without systemd the schedule is crontab lines you add yourself; the report
  cannot see them, and says so.
* **Whatever form a finding takes**: suspicious entries a persistence baseline
  recorded without review are findings too, and a check that exited with
  findings this report cannot list is shown as such, never as nothing found.
  A result file that cannot be opened is that one check's error.
* **Never all clear on missing information**: incidents that cannot be read,
  a watch that stopped, a check that failed after finding something, or a
  check that could not look everywhere (an unmounted partition, processes it
  could not read) keep the verdict from "all clear", and each is among the
  next steps. Any finding at all, LOW and INFO included, is "review".

Each check is shown as:

| Status | Means |
| --- | --- |
| clear | Its last run found nothing |
| to review | Its last run found something; the findings follow, worst first |
| watching | A live watch is installed and running |
| not run | It has never run; run it, or schedule it |
| broken | Its last run failed (the report gives the reason it printed, or the error it stopped on), its watch is installed but stopped, or its saved result cannot be trusted |

A check whose last run is more than three of its scheduled intervals old is
marked out of date: its timer may have stopped.

What a check found still counts when something else went wrong: a run that
found something and then failed (an alert it could not send), or a live
watch that has stopped, shows its findings and says what went wrong, and
that problem is among the next steps.

## Your choices for each finding

Every finding lists what you can do, each as the exact command. Nothing is
carried out by the report.

* **Look closer**: the check's full report, and everything recorded about
  the same file, address or persistence entry, in order
  (`megalodon timeline show --entity ...`).
* **Keep evidence** before anything changes, for serious break-in and
  tampering findings (`sudo megalodon evidence collect`).
* **It is expected**: for most checks, `accept` records the current state as
  the new baseline (all of that check's current changes, not only this one).
  The process ancestry, egress and credential watches allow the one program
  instead, and the login watch learns the logins seen since.
* **Fix it**, where there is one fix: install waiting updates, restart a
  service still running replaced code, refresh the package lists.
* **Contain it**: see what the response engine would do
  (`megalodon enforce run --dry-run`). Containment is carried out only for the
  actions and playbooks you list in `~/.config/megalodon/enforce.toml`.
* **Undo** what enforcement did: `megalodon enforce list`, then
  `megalodon enforce undo ID`.

## Going through it: `megalodon review`

```bash
megalodon review
```

`review` goes through the same findings and incidents one at a time, worst
first. For each, it shows what happened and what it means, then your
choices as a numbered list. Pick one and it shows the exact command, then
asks before running it: only `y` or `yes` runs it. The command runs as the
arguments shown, without a shell, and as this installation's `megalodon`.
A choice with a placeholder or alternatives (`sudo systemctl restart
SERVICE`, apt or dnf) is printed for you to adapt and run, never run for
you. `s` or a blank answer skips a finding; `q` stops.

Each choice you make, and the exit code of what ran, is appended to
`~/.local/state/megalodon/review.jsonl` (mode 600): a record of how each
finding was handled. `review` needs a terminal; without one it refuses, and
`megalodon report` prints the same choices.

## Safety

Everything a finding names (a path, a program, an address, a log line) can
be chosen by an attacker. In the report:

* control and text-direction characters are replaced, and long values cut;
* every value in a command is shell-quoted, so a file name cannot run a
  second command when you copy the line;
* the HTML page escapes everything, runs no script, and forbids loading
  anything (a Content-Security-Policy of `default-src 'none'`).

Read a command before you run it all the same.

## Limits

* **As fresh as the last run.** A check that has not run since a change
  cannot report it. The scheduled jobs keep it current.
* **One account's view.** Results are kept in the home of the account that
  ran the check. Run the report as the account the schedule runs as (root
  for the full schedule).
* **Most live watches report through incidents.** The credential, ancestry,
  egress, device and container watches' findings are in the incidents,
  decided by the response engine, not listed per check.
* **The dashboard does not show it yet.** Open the HTML page instead.
* **Choices are commands, not judgments.** "It was you" accepts what the
  check sees now; only you know whether a change was yours.
