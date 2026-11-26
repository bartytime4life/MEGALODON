"""Automated attack campaigns: one address trying many different attacks at machine speed.

A person at a keyboard tries a few things and waits on each. An attack tool, or an AI agent driving one, tries many
kinds of attack against many targets within minutes, and moves to the next as soon as one fails. Each attempt is
already a finding of its own (a port scan, a password guess, a decoy touched, a login burst); what no single
finding shows is how many different ones came from the same address, how quickly, and through how many sensors.

This module watches the findings every sensor reports to the response engine, per address, and raises
AUTOMATED_CAMPAIGN when, within a window:

* there are at least `min_attempts` distinct attempts (a rule against a target; repeats of the same one are not
  counted, since each sensor already holds those back), and
* of at least `min_kinds` different kinds (rules).

It is CRITICAL when the attempts span at least `broad_kinds` kinds, or were seen by at least two sensors (the
network and the login records, for example): breadth no single scanner produces.

It measures pace and breadth. It cannot tell an AI agent from an attack framework or a scripted scanner, and does
not claim to: all three are automated, and all three are answered the same way. A scanner you run yourself is
reported too; list its address in the detector's allow list, whose findings never reach the response engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import statistics

RULE_ID = 'AUTOMATED_CAMPAIGN'
SOURCE = 'campaign'
MAX_ADDRESSES = 1024          # addresses followed at once; the least recently active is dropped first
MAX_ATTEMPTS = 256            # attempts kept per address, newest kept
KEEP_HOURS = 24               # an address with nothing newer than this is forgotten
SUMMARY_ROOM = 300 - 47       # a finding's summary is kept to 300 characters; an address and ': ' take up to 47


@dataclass(frozen=True)
class Settings:
    enabled: bool = True
    window_seconds: int = 600
    min_attempts: int = 8
    min_kinds: int = 3
    broad_kinds: int = 5
    cooldown_minutes: int = 30


BOUNDS = dict(window_seconds=(60, 86400), min_attempts=(2, 1000), min_kinds=(2, 100), broad_kinds=(2, 100),
              cooldown_minutes=(1, 1440))


def _time(text, default):
    try:
        moment = datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    except ValueError:
        return default
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _followed(address):
    """An address a campaign can come from: not this machine's loopback, nor an unspecified or multicast one."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast)


def _target(signal, address):
    """What one attempt was aimed at: every entity of the finding but the attacker's own address. The other end
    counts whichever role it was given ('peer' from the network store, 'address' when both ends are piped in)."""
    parts = sorted(f'{"address" if kind == "peer" else kind}:{value}' for kind, values in signal.entities.items()
                   for value in values if value != address)
    return hashlib.sha256('\n'.join(parts).encode()).hexdigest()[:12]


def observe(state, signals, now, settings, make_signal, *, exclude=frozenset()):
    """Record the fresh `signals` per address in `state['campaigns']`, and return a campaign signal (built with
    `make_signal(key, severity, observed_at, summary, address)`) for each address that has just become one.

    Addresses in `exclude` (this machine's own, its gateways and DNS servers) are never followed: a finding piped in
    names both ends, and the end under attack is not the attacker."""
    if not settings.enabled:
        return []
    book = state.setdefault('campaigns', {})
    touched = set()
    for signal in signals:
        if signal.source == SOURCE or signal.rule_id == RULE_ID:
            continue
        at = _time(signal.observed_at, now)
        for address in sorted(signal.entities.get('address', ())):
            if address in exclude or not _followed(address):
                continue
            entry = book.setdefault(address, dict(attempts=[], raised_at=None, raised_severity=None))
            entry['attempts'].append([_iso(at), signal.rule_id, signal.source, _target(signal, address)])
            touched.add(address)
    raised = []
    for address in sorted(touched):
        entry = book[address]
        attempts = sorted(entry['attempts'])
        latest = _time(attempts[-1][0], now)
        start = latest - timedelta(seconds=settings.window_seconds)
        attempts = [a for a in attempts if _time(a[0], now) >= start][-MAX_ATTEMPTS:]
        entry['attempts'] = attempts
        found = _assess(attempts, settings)
        if found is None:
            continue
        severity, summary = found
        last = entry.get('raised_at')
        quiet = last is None or _time(last, now) <= now - timedelta(minutes=settings.cooldown_minutes)
        rising = entry.get('raised_severity') == 'HIGH' and severity == 'CRITICAL'
        if not (quiet or rising):
            continue
        entry.update(raised_at=_iso(now), raised_severity=severity)
        raised.append(make_signal(f'{SOURCE}:{address}:{attempts[0][0]}:{severity}', severity, attempts[-1][0],
                                  f'{address}: {summary}', address))
    _prune(book, now)
    return raised


def _assess(attempts, settings):
    distinct = {}
    for at, rule, source, target in attempts:
        distinct.setdefault((rule, target), (at, rule, source))
    if len(distinct) < settings.min_attempts:
        return None
    kinds = sorted({rule for _, rule, _ in distinct.values()})
    if len(kinds) < settings.min_kinds:
        return None
    sensors = sorted({source for _, _, source in distinct.values()})
    first, last = attempts[0][0], attempts[-1][0]
    span = max((_time(last, None) - _time(first, None)).total_seconds(), 1.0)
    # How soon a different kind of attack followed the previous one: an agent moves on in seconds.
    ordered = sorted(distinct.values())
    pivots = [(_time(b[0], None) - _time(a[0], None)).total_seconds()
              for a, b in zip(ordered, ordered[1:]) if a[1] != b[1]]
    severity = 'CRITICAL' if len(kinds) >= settings.broad_kinds or len(sensors) >= 2 else 'HIGH'
    pace = len(distinct) * 60 / span
    head = (f'{len(distinct)} different attacks of {len(kinds)} kinds in {int(span)} s ({pace:.1f} a minute), '
            f'seen by {", ".join(sensors)}'
            + (f'; next kind after {statistics.median(pivots):.0f} s (median)' if pivots else '') + ': ')
    tail = '. Machine speed: an attack tool or an AI agent, not a person.'
    # As many of the kinds as fit what the ledger keeps of a summary, with room for the address before it.
    listed = list(kinds)
    while listed and len(head + ', '.join(listed) + ', ...' + tail) > SUMMARY_ROOM:
        listed.pop()
    summary = head + ', '.join(listed) + (', ...' if len(listed) < len(kinds) else '') + tail
    return severity, summary


def _prune(book, now):
    cutoff = now - timedelta(hours=KEEP_HOURS)
    for address in [a for a, e in book.items() if not e.get('attempts')
                    or _time(e['attempts'][-1][0], now) < cutoff]:
        del book[address]
    if len(book) > MAX_ADDRESSES:
        by_latest = sorted(book, key=lambda a: book[a]['attempts'][-1][0])
        for address in by_latest[:len(book) - MAX_ADDRESSES]:
            del book[address]
