# Automated attack campaigns

A person at a keyboard tries a few things and waits on each one. An attack tool, or an AI agent driving one, tries
many kinds of attack against many targets within minutes, and moves to the next as soon as one fails. Each attempt
is already a finding of its own: a port scan, password guesses, a decoy touched, a sweep of the network, a login from
a new place. What no single finding shows is how many *different* ones came from the same address, how fast, and
through how many sensors.

The [response engine](response-engine.md) sees the findings of every sensor, so it is where this is measured. For
each address it keeps the last `window_seconds` of what was reported about it, and raises `AUTOMATED_CAMPAIGN` when:

* there were at least `min_attempts` **different** attempts, one rule against one target each. Repeats of the same
  attempt are not counted, since each sensor already holds those back; and
* they were of at least `min_kinds` different kinds (rules).

It is **CRITICAL** when the attempts span `broad_kinds` kinds or more, or were seen by two sensors or more (the network
and the login records, for example): breadth no single scanner produces. Otherwise it is HIGH.

Attempts are placed by when they happened, not when a pass read them, so findings read late, or across several
passes, are counted the same. Every window that holds a new attempt is looked at, not only the latest: a backlog
read at once can hold a campaign that ended before its newest finding. When several qualify, the most severe is
raised, and of equals the latest.

This machine's own addresses, its gateways and its DNS servers are never followed: a finding piped in names both
ends, and the end under attack is not the attacker.

## What you see

The campaign is a finding of its own, about the attacker's address. It joins the incident of the findings it was
made from, so:

* **`megalodon report`** lists the incident first among those that need you, with what it means in plain words. It
  adds a warning when a login was part of the same incident, since the attacker may have got in;
* **`megalodon timeline show INCIDENT`** lists each attempt in order, then the campaign. Its summary reads, for example:

  ```
  203.0.114.9: 9 different attacks of 4 kinds in 96 s (5.6 a minute), seen by logins, network; next kind after
  8 s (median): BRUTE_FORCE, DECOY_TOUCH, HOST_SWEEP, PORT_SCAN. Machine speed: an attack tool or an AI agent,
  not a person.
  ```

  "Next kind after" is how soon a different kind of attack followed the one before. An agent moves on in seconds.

## What is done

The default `automated-campaign` playbook would collect evidence, block the address for 60 minutes and notify you.
As with every playbook, the response engine only records this. [Enforcement](enforcement.md) carries it out only if
you list `automated-campaign` in its policy, and every block can be undone with `megalodon enforce undo ID`.

Port scans, host sweeps, beaconing and generated domain names are always MEDIUM, so on their own they are alerted
and not acted on. Many of them from one address, of several kinds, within minutes, are a campaign, and that is HIGH.

A campaign finding is not a second, independent source. It is made from the findings it counts, so it never
corroborates a playbook that waits for one (`require_corroboration`).

## Settings

In the response policy (`megalodon respond init` writes them out):

```toml
[response.campaign]
enabled = true
window_seconds = 600      # 60 to 86400
min_attempts = 8          # 2 to 256: different attempts within the window
min_kinds = 3             # 2 to 100: different kinds of attack among them
broad_kinds = 5           # 2 to 100, at least min_kinds: CRITICAL from this many kinds
cooldown_minutes = 30     # 1 to 1440: before the same address is raised again
```

An address is raised again within `cooldown_minutes` only if its campaign becomes CRITICAL. A policy without the
table uses these values. A policy written before this table existed also needs the `automated-campaign` playbook
added before campaigns are decided. Until then they are still recorded, and reach the timeline and the report.

The engine follows up to 1024 addresses and their last 256 different attempts each; an attempt repeated is kept
once, at its latest, so repeats never push the others out. An address with nothing new for a day is forgotten.

## Limits

* **It measures pace and breadth, not who is typing.** An AI agent, an attack framework and a scripted scanner are
  all automated, and are answered the same way. The detector does not claim to tell them apart.
* **A scanner you run yourself is a campaign too.** Put its address in the network detector's allow list. Findings
  about allowlisted sources never reach the response engine.
* **It sees what the sensors report.** It counts the network detections and the findings of the host checks that
  name an address, such as logins. Failed logins from `megalodon auth review` are not a response engine source, and
  nor are Suricata's alerts. There is no web request log sensor, so web attacks count only as far as the network
  rules see them.
* **One address at a time.** A campaign spread over many addresses, each staying below the thresholds, is not joined
  into one.
