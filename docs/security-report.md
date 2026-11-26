# Security report: the whole machine, in plain language

`megalodon report` puts everything MEGALODON knows about this machine on one
page, written for the person who owns it rather than for a security analyst:

- **a verdict**: act now, review, parts not running, or all clear;
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
  whether their service is running; what they find reaches the incidents.
* **Incidents** of the last week (`--hours` to change), from the response
  engine's ledger and the enforcement journal, as `megalodon timeline` tells
  them.
* **The setup**: which scheduled jobs are installed, which still need a
  baseline, the alert settings, the response and enforcement policies, and
  the heartbeat.

Each check is shown as:

| Status | Means |
| --- | --- |
| clear | Its last run found nothing |
| to review | Its last run found something; the findings follow, worst first |
| watching | A live watch is installed and running |
| not run | It has never run; run it, or schedule it |
| broken | Its last run failed, its watch is installed but stopped, or its saved result cannot be trusted |

A check whose last run is more than three of its scheduled intervals old is
marked out of date: its timer may have stopped.

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
* **Live watches report through incidents.** Their individual findings are
  in the incidents, decided by the response engine, not listed per check.
* **The dashboard does not show it yet.** Open the HTML page instead.
