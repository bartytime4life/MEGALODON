"""Decide a live watch's finding at once, then carry out what enforcement allows.

The scheduled response pass reads the other sources every five minutes, and enforcement runs every minute. Some
findings cannot wait that long: files being encrypted, or a keyboard that types on its own the moment it is plugged
in. A live watch hands each such finding here as soon as it is raised. Nothing is done that the timer would not do:
the same response policy decides, under the same guards and ledger, and enforcement acts only when it is on and lists
the action and the playbook.
"""
from __future__ import annotations

from pathlib import Path


class Responder:
    """Called with a finding's rule and its response-engine signals; returns what was decided and done."""

    def __init__(self, *, policy=None, ledger=None, state=None, enforcement_policy=None, journal=None,
                 enforcement_state=None, executor=None):
        from . import enforcement, response_engine
        self.policy = Path(policy or response_engine.DEFAULT_POLICY).expanduser()
        self.ledger = Path(ledger or response_engine.DEFAULT_LEDGER).expanduser()
        self.state = Path(state or response_engine.DEFAULT_STATE).expanduser()
        self.enforcement_policy = Path(enforcement_policy or enforcement.DEFAULT_POLICY).expanduser()
        self.journal = Path(journal or enforcement.DEFAULT_JOURNAL).expanduser()
        self.enforcement_state = Path(enforcement_state or enforcement.DEFAULT_STATE).expanduser()
        self.executor = executor

    def recover(self):
        """Resume due suspensions without reading policies or admitting new actions."""
        from . import enforcement
        try:
            return dict(expired=enforcement.expire(journal=self.journal))
        except (enforcement.EnforcementError, OSError, ValueError) as exc:
            return dict(expired=[], error=f'could not recover suspensions: {exc}'[:300])

    def _with_recovery(self, out):
        recovery = self.recover()
        if recovery['expired'] or recovery.get('error'):
            out['recovery'] = recovery
        return out

    def carry(self, rule_id, decide):
        """Decide with `decide()` (a response engine pass), then run enforcement when anything was decided.

        A finding that decides nothing, or that cannot be decided, still lets an earlier pause end on time.
        Enforcement runs even without its policy: it then only recovers what is due, and says so.
        """
        from . import enforcement, response_engine
        out = dict(rule_id=rule_id)
        try:
            decided = decide()
        except (response_engine.ResponseError, OSError, ValueError) as exc:
            return self._with_recovery(dict(out, decided=False, error=f'not decided: {exc}'[:300]))
        out.update(decided=True, decisions=decided['decisions'], would_apply=decided['would_apply'])
        if not decided['decisions']:
            return self._with_recovery(out)  # no new action, but an earlier pause may still be due
        try:
            ran = enforcement.run(policy_path=self.enforcement_policy, response_policy=self.policy,
                                  ledger=self.ledger, journal=self.journal, state_path=self.enforcement_state,
                                  executor=self.executor)
        except (enforcement.EnforcementError, response_engine.ResponseError, OSError, ValueError) as exc:
            return dict(out, enforcement=f'not carried out: {exc}'[:300])
        carried = dict(
            enabled=ran['enabled'],
            applied=[dict(id=r['id'], action=r['action'], target=r.get('target')) for r in ran['applied']],
            refused=[dict(action=r['action'], target=r.get('target'), reason=r.get('reason'),
                          status=r.get('status')) for r in ran['refused']],
            expired=ran.get('expired', []))
        for key in ('policy_error', 'note'):
            if key in ran:
                carried[key] = ran[key]
        return dict(out, enforcement=carried)

    def answer(self, rule_id, signals):
        """Decide a finding's response-engine signals at once, and carry out what enforcement allows."""
        from . import response_engine
        return self.carry(rule_id, lambda: response_engine.run(signals=signals, policy_path=self.policy,
                                                               ledger=self.ledger, state_path=self.state))
