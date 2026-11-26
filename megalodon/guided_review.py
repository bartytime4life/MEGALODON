"""`megalodon review`: go through the security report's findings one at a time, and choose what to do.

For each finding and incident, worst first, it shows what happened and what it means, then your choices as
numbered commands. Pick one and it shows the exact command; it runs only after you confirm, as the arguments
shown, without a shell. A choice with placeholders or alternatives (restart SERVICE, apt or dnf) is printed for
you to adapt and run.

Each choice you make, and how its command ended, is written to ``~/.local/state/megalodon/review.jsonl``
(mode 600): a record of how each finding was handled. Nothing is done without your answer.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import security_report as sr

DEFAULT_LOG = '~/.local/state/megalodon/review.jsonl'
SCHEMA = 'megalodon-review-choice-v1'


def items(report):
    """Every finding and incident, worst first: (heading, what it means, details, choices, record)."""
    found = []
    for check in report['checks']:
        for finding in check['findings']:
            where = f' — {finding["where"]}' if finding['where'] else ''
            found.append(dict(severity=finding['severity'], heading=f'{check["title"]}: {finding["rule_id"]}{where}',
                              meaning=finding['meaning'], detail=finding['detail'], choices=finding['choices'],
                              record=dict(check=check['check'], rule_id=finding['rule_id'], where=finding['where'])))
    for incident in report['incidents']:
        found.append(dict(severity=incident['severity'],
                          heading=f'Incident {incident["incident"]}: {", ".join(incident["rules"])}',
                          meaning=f'Findings from {", ".join(incident["checks"])} that the response engine joined '
                                  'into one story' + (f'; {incident["actions_applied"]} action(s) were carried out'
                                                      if incident['actions_applied'] else ''),
                          detail=None, choices=incident['choices'], record=dict(incident=incident['incident'])))
    found.sort(key=lambda item: sr.RANK.index(item['severity']))
    return found


def _launcher():
    found = shutil.which('megalodon')
    return [found] if found else [sys.executable, '-m', 'megalodon']


def resolve(argv):
    """The arguments to run: `megalodon` as this installation's command, so the choice runs this version."""
    if argv[:1] == ['megalodon']:
        return _launcher() + argv[1:]
    if argv[:2] == ['sudo', 'megalodon']:
        return ['sudo'] + _launcher() + argv[2:]
    return list(argv)


def _log(path, entry):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(entry, sort_keys=True) + '\n')


def review(report, *, ask=input, say=print, run=None, log=DEFAULT_LOG, now=None):
    """Go through `report`'s findings with the person at the terminal. Returns what was chosen and done."""
    run = run or (lambda argv: subprocess.run(argv, check=False).returncode)
    todo = items(report)
    done = []
    if not todo:
        say(f'{report["headline"]} There is nothing to go through.')
        return done
    say(f'{report["headline"]} {len(todo)} to go through, worst first. Nothing runs without your answer.')
    for number, item in enumerate(todo, 1):
        say('')
        say(f'[{number}/{len(todo)}] {item["severity"]}  {item["heading"]}')
        if item['meaning']:
            say(f'    {item["meaning"]}')
        if item['detail']:
            say(f'    {item["detail"]}')
        for index, choice in enumerate(item['choices'], 1):
            say(f'  {index}) {choice["label"]}')
        say('  s) skip    q) stop here')
        answer = ask('Your choice: ').strip().lower()
        if answer in ('q', 'quit'):
            break
        if not answer.isdigit() or not 1 <= int(answer) <= len(item['choices']):
            continue
        choice = item['choices'][int(answer) - 1]
        entry = dict(schema=SCHEMA, at=(now or datetime.now(timezone.utc)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                     choice=choice['choice'], label=choice['label'], command=choice['command'], **item['record'])
        if choice.get('note'):
            say(f'    Note: {choice["note"]}')
        if not choice.get('argv'):
            say(f'    Adapt and run this yourself: {choice["command"]}')
            entry['ran'] = False
        else:
            say(f'    This runs: {choice["command"]}')
            if ask('    Run it now? [y/N] ').strip().lower() in ('y', 'yes'):
                code = run(resolve(choice['argv']))
                say(f'    It finished with exit code {code}.')
                entry.update(ran=True, exit_code=code)
            else:
                say('    Not run.')
                entry['ran'] = False
        _log(log, entry)
        done.append(entry)
    say('')
    ran = sum(1 for entry in done if entry.get('ran'))
    say(f'{len(done)} choice(s) made, {ran} command(s) run. Run `megalodon report` again to see where things '
        'stand.')
    return done
