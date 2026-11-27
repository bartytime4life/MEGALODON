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
LURE_RULE = 'LURE_FOLLOWED'       # a login tried as an agent lure's account: the evidence an AI agent is at work
SOURCE = 'campaign'
MAX_ADDRESSES = 512           # addresses followed at once; the least recently active is dropped first
MAX_NETWORKS = 256            # networks followed at once, the same way
MAX_ATTEMPTS = 256            # different attempts kept per address, newest kept, with room for repeats
PER_ATTEMPT = 16              # times one attempt is kept at most
KEEP_HOURS = 24               # attempts this much older than an address's newest are dropped; so is an address
                              # with nothing newer than this
SUMMARY_ROOM = 300 - 47       # a finding's summary is kept to 300 characters; an address and ': ' take up to 47


@dataclass(frozen=True)
class Settings:
    enabled: bool = True
    window_seconds: int = 600
    min_attempts: int = 8
    min_kinds: int = 3
    broad_kinds: int = 5
    cooldown_minutes: int = 30
    ignore_addresses: tuple = ()      # networks, as text: the owner's own scanners
    # One campaign spread over several addresses of one network (an attacker rotating through a cloud range or a
    # provider's block) is judged as one too, when at least min_addresses of them took part.
    networks: bool = True
    min_addresses: int = 3
    network_prefix_v4: int = 24
    network_prefix_v6: int = 64


BOUNDS = dict(window_seconds=(60, 86400), min_attempts=(2, MAX_ATTEMPTS), min_kinds=(2, 100), broad_kinds=(2, 100),
              cooldown_minutes=(1, 1440), min_addresses=(2, 64), network_prefix_v4=(8, 32),
              network_prefix_v6=(16, 128))


def _time(text, default):
    try:
        moment = datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    except ValueError:
        return default
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _actors(signal):
    """The address a finding's activity came from: the one it names as its actor, or its only address. A finding
    naming several addresses and no actor says nothing about which of them attacked, so it is not counted: an
    address under attack is never taken for the attacker."""
    if getattr(signal, 'actor', ''):
        return [signal.actor]
    addresses = signal.entities.get('address', ())
    return list(addresses) if len(addresses) == 1 else []


def _within(address, networks):
    parsed = ipaddress.ip_address(address)
    return any(parsed.version == network.version and parsed in network for network in networks)


def _followed(address):
    """An address a campaign can come from: not this machine's loopback, nor an unspecified or multicast one."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast)


def _network(address, settings):
    """The network an address is judged with: its /24 (IPv4) or /64 (IPv6) by default."""
    parsed = ipaddress.ip_address(address)
    prefix = settings.network_prefix_v4 if parsed.version == 4 else settings.network_prefix_v6
    return str(ipaddress.ip_network(f'{parsed}/{prefix}', strict=False))


def _target(signal, address):
    """What one attempt was aimed at: every entity of the finding but the attacker's own address. The other end
    counts whichever role it was given ('peer' from the network store, 'address' when both ends are piped in)."""
    parts = sorted(f'{"address" if kind == "peer" else kind}:{value}' for kind, values in signal.entities.items()
                   for value in values if value != address)
    return hashlib.sha256('\n'.join(parts).encode()).hexdigest()[:12]


def observe(state, signals, now, settings, make_signal, *, exclude=frozenset()):
    """Record the fresh `signals` per address in `state['campaigns']`, and return a campaign signal (built with
    `make_signal(key, severity, observed_at, summary, address)`) for each address that has just become one.

    Addresses in `exclude` (this machine's own, its gateways and DNS servers) are never followed: a gateway stands for
    everyone behind it, and none of them may be blocked."""
    if not settings.enabled:
        return []
    book = state.setdefault('campaigns', {})
    touched, new = set(), {}
    ignored = [ipaddress.ip_network(network) for network in settings.ignore_addresses]
    for signal in signals:
        if signal.source == SOURCE or signal.rule_id == RULE_ID:
            continue
        at = _time(signal.observed_at, now)
        for address in _actors(signal):
            if address in exclude or not _followed(address) or _within(address, ignored):
                continue
            book.setdefault(address, dict(attempts=[], raised_at=None, raised_severity=None, raised_lured=False))
            new.setdefault(address, []).append([_iso(at), signal.rule_id, signal.source, _target(signal, address)])
            touched.add(address)
    raised = [signal for address in sorted(touched)
              for signal in _raise(book, address, new[address], now, settings, make_signal, 1)]
    _prune(book, now, MAX_ADDRESSES)
    if settings.networks:
        # The same attempts, by network: each kept with the address it came from, so a window counts how many of
        # its addresses took part. Different attempts are still one rule against one target, whoever made them.
        nets, fresh = state.setdefault('campaign_networks', {}), {}
        for address in sorted(touched):
            for at, rule, source, target in new[address]:
                fresh.setdefault(_network(address, settings), []).append([at, rule, source, target, address])
        for network in sorted(fresh):
            entry = nets.setdefault(network, dict(attempts=[], raised_at=None, raised_severity=None,
                                                  raised_lured=False))
            # An address protected or ignored since its attempts were kept is no longer counted, nor named.
            entry['attempts'] = [a for a in entry['attempts'] if a[4] not in exclude and not _within(a[4], ignored)]
            raised += _raise(nets, network, fresh[network], now, settings, make_signal, settings.min_addresses)
        _prune(nets, now, MAX_NETWORKS)
    return raised


def _raise(book, name, new, now, settings, make_signal, min_addresses):
    """The campaign signal `name` (an address, or a network with at least `min_addresses` of its addresses) has
    just become, with its `new` attempts, if any; its book entry is brought up to date."""
    entry = book[name]
    # Every window holding a new attempt, not only the latest: findings read late can hold a campaign that ended
    # before the newest. A window of earlier attempts only was assessed when they arrived.
    marked = sorted([(a, False) for a in entry['attempts']] + [(a, True) for a in new])
    attempts = [a for a, _ in marked]
    found = _worst_window(attempts, [fresh for _, fresh in marked], settings, min_addresses)
    entry['attempts'] = _kept(attempts, settings)
    if found is None:
        return []
    severity, summary, last_at, lured, addresses = found
    last = entry.get('raised_at')
    quiet = last is None or _time(last, now) <= now - timedelta(minutes=settings.cooldown_minutes)
    # Raised again within the cooldown only when it says more: CRITICAL after HIGH, or an AI agent after neither.
    rising = ((entry.get('raised_severity') == 'HIGH' and severity == 'CRITICAL')
              or (lured and not entry.get('raised_lured')))
    if not (quiet or rising):
        return []
    entry.update(raised_at=_iso(now), raised_severity=severity, raised_lured=lured)
    # Each raise is a finding of its own: a key of its own, or the engine's daily dedupe would drop a repeat. A
    # network's names the addresses that took part, never the network itself: they, not their neighbours, attacked.
    return [make_signal(f'{SOURCE}:{name}:{_iso(now)}:{severity}', severity, last_at, f'{name}: {summary}',
                        addresses or [name])]


def _worst_window(attempts, fresh, settings, min_addresses=1):
    """The most severe window of `window_seconds` that holds a `fresh` attempt and is a campaign, of those the one
    that followed a lure, and the latest of equals: (severity, summary, last attempt's time, lured, the addresses
    that took part, for a network's attempts); or None. A network's window needs `min_addresses` of them."""
    width = timedelta(seconds=settings.window_seconds)
    times = [_time(a[0], None) for a in attempts]
    keys, rules, sources, actors = {}, {}, {}, {}
    fresh_in = 0

    def add(counter, key, step):
        counter[key] = counter.get(key, 0) + step
        if not counter[key]:
            del counter[key]
    best, first = None, 0
    def parts(attempt):
        _, rule, source, target = attempt[:4]
        return ((keys, (rule, target)), (rules, rule), (sources, source), (actors, attempt[4] if len(attempt) > 4 else None))
    for last, attempt in enumerate(attempts):
        for counter, key in parts(attempt):
            add(counter, key, 1)
        fresh_in += fresh[last]
        while times[last] - times[first] > width:
            for counter, key in parts(attempts[first]):
                add(counter, key, -1)
            fresh_in -= fresh[first]
            first += 1
        if (not fresh_in or len(keys) < settings.min_attempts or len(rules) < settings.min_kinds
                or len(actors) < min_addresses):
            continue
        # Ranked as _assess will judge it: a followed lure makes it CRITICAL, and of CRITICAL windows the one that
        # followed a lure says the most, that an AI agent is driving it.
        lured = LURE_RULE in rules
        rank = (lured or len(rules) >= settings.broad_kinds or len(sources) >= 2, lured)
        if best is None or rank >= best[0]:
            best = (rank, first, last)
    if best is None:
        return None
    window = attempts[best[1]:best[2] + 1]
    addresses = sorted({a[4] for a in window if len(a) > 4})
    severity, summary = _assess(window, settings, len(addresses))
    return severity, summary, window[-1][0], best[0][1], addresses


def _kept(attempts, settings):
    """What a later pass can still use, from up to KEEP_HOURS before the newest attempt: findings arrive out of order,
    so the rest of an earlier campaign can still come, and any window can still be completed.

    Of the times one attempt (a rule against a target) was seen, a time is dropped only when the times kept on
    either side of it are at most a window apart: any window holding it holds one of them, so every window counts
    the same. At most PER_ATTEMPT times are kept for one attempt, the latest. Then the latest time of up to
    MAX_ATTEMPTS different attempts, the newest, and as many of their earlier times as there is room for: repeats
    never push out a different attempt."""
    if not attempts:
        return []
    start = _time(attempts[-1][0], None) - timedelta(hours=KEEP_HOURS)
    width = timedelta(seconds=settings.window_seconds)
    seen = {}
    for attempt in attempts:
        if _time(attempt[0], None) >= start:
            # One attempt is a rule against a target, and for a network, from one of its addresses.
            seen.setdefault((attempt[1], attempt[3], *attempt[4:5]), []).append(attempt)
    groups = {}
    for key, times in seen.items():
        thinned = [times[0]]
        for here, after in zip(times[1:-1], times[2:]):
            if _time(after[0], None) - _time(thinned[-1][0], None) > width:
                thinned.append(here)
        if len(times) > 1:
            thinned.append(times[-1])
        groups.setdefault(key[:2], []).append(thinned[-PER_ATTEMPT:])
    # Different attacks first, the newest time of each; then, for a network, the latest time of each other address
    # that made one; then earlier times. However many addresses repeat one attack, it takes one place of the first.
    latest, others, earlier = [], [], []
    for timelines in groups.values():
        lasts = sorted(timeline[-1] for timeline in timelines)
        latest.append(lasts[-1])
        others += lasts[:-1]
        earlier += [attempt for timeline in timelines for attempt in timeline[:-1]]
    latest = sorted(latest)[-MAX_ATTEMPTS:]
    # Room for the rest is left only when no different attempt was dropped, so all of it is of kept ones.
    room = MAX_ATTEMPTS - len(latest)
    rest = sorted(others)[-room:] if room else []
    room -= len(rest)
    rest += sorted(earlier)[-room:] if room else []
    return sorted(latest + rest)


def _assess(attempts, settings, addresses=0):
    """The severity and summary of a window `_worst_window` found to be a campaign; of a network's, from how many
    of its `addresses`."""
    distinct = {}
    for at, rule, source, target in (a[:4] for a in attempts):
        distinct.setdefault((rule, target), (at, rule, source))
    kinds = sorted({rule for _, rule, _ in distinct.values()})
    sensors = sorted({source for _, _, source in distinct.values()})
    first, last = attempts[0][0], attempts[-1][0]
    span = max((_time(last, None) - _time(first, None)).total_seconds(), 1.0)
    # How soon a different kind of attack followed the previous one: an agent moves on in seconds.
    ordered = sorted(distinct.values())
    pivots = [(_time(b[0], None) - _time(a[0], None)).total_seconds()
              for a, b in zip(ordered, ordered[1:]) if a[1] != b[1]]
    # A followed agent lure among the attempts: something read a note to AI agents and acted on it.
    lured = LURE_RULE in kinds
    severity = 'CRITICAL' if lured or len(kinds) >= settings.broad_kinds or len(sensors) >= 2 else 'HIGH'
    pace = len(distinct) * 60 / span
    head = ((f'{addresses} addresses, ' if addresses else '')
            + f'{len(distinct)} different attacks of {len(kinds)} kinds in {int(span)} s ({pace:.1f} a minute), '
            f'seen by {", ".join(sensors)}'
            + (f'; next kind after {statistics.median(pivots):.0f} s (median)' if pivots else '') + ': ')
    tail = ('. It followed an agent lure: an AI agent is driving it.' if lured
            else '. Machine speed: an attack tool or an AI agent, not a person.')
    # As many of the kinds as fit what the ledger keeps of a summary, with room for the address before it.
    listed = list(kinds)
    while listed and len(head + ', '.join(listed) + ', ...' + tail) > SUMMARY_ROOM:
        listed.pop()
    summary = head + ', '.join(listed) + (', ...' if len(listed) < len(kinds) else '') + tail
    return severity, summary


def _prune(book, now, most):
    cutoff = now - timedelta(hours=KEEP_HOURS)
    for address in [a for a, e in book.items() if not e.get('attempts')
                    or _time(e['attempts'][-1][0], now) < cutoff]:
        del book[address]
    if len(book) > most:
        by_latest = sorted(book, key=lambda a: book[a]['attempts'][-1][0])
        for address in by_latest[:len(book) - most]:
            del book[address]
