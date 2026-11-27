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

When a followed [agent lure](host-tripwires.md#agent-lures-catching-an-ai-agent-at-work) (`LURE_FOLLOWED`) from the same
address is among the attempts, the campaign is CRITICAL and its summary ends "It followed an agent lure: an AI agent
is driving it." That is evidence, not pace alone: the address read a note written for automated agents and acted on
it. A campaign already raised, HIGH or CRITICAL, is raised again once it follows a lure.

Attempts are placed by when they happened, not when a pass read them, so findings read late, or across several
passes, are counted the same. Every window that holds a new attempt is looked at, not only the latest: a backlog
read at once can hold a campaign that ended before its newest finding. When several qualify, the most severe is
raised, of those one that followed a lure, and of equals the latest.

A finding is counted against the address it says the activity came from: the source of a finding piped in, or the
one address a finding names. A finding that names several addresses and no source is not counted, so an address
under attack is never taken for the attacker. This machine's own addresses, its gateways and its DNS servers are
never followed: a gateway stands for everyone behind it, and none of them may be blocked.

### Spread over one network

An attacker can rotate through the addresses of one cloud range or provider block, each staying below the thresholds.
So each network (a /24, or an IPv6 /64) is judged the same way as an address, over its addresses' findings together,
when at least `min_addresses` of them (three by default) took part. A different attempt is still one rule against one
target: the same attempt made from many addresses counts once. The campaign is about the network, for example:

```
203.0.113.0/24: 4 addresses, 9 different attacks of 3 kinds in 64 s (8.4 a minute), seen by network; ...
```

It names the addresses that took part, never the network, so the `automated-campaign` playbook would block those
addresses (up to eight), not their neighbours. An address that is a campaign on its own is raised as well, by itself.

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
ignore_addresses = []     # your own scanners and test machines: addresses or networks
networks = true           # also judge each network over its addresses together
min_addresses = 3         # 2 to 64: addresses of one network that must take part
network_prefix_v4 = 24    # 8 to 32: the size of an IPv4 network
network_prefix_v6 = 64    # 16 to 128: the size of an IPv6 network
```

An address is raised again within `cooldown_minutes` only if its campaign becomes CRITICAL, or first follows a lure.
A policy without the
table uses these values. A policy written before this table existed also needs the `automated-campaign` playbook
added before campaigns are decided. Until then they are still recorded, and reach the timeline and the report.

The engine follows up to 512 addresses and 256 networks, and for each the last 256 different attempts from up to a day before its
newest, so findings that arrive out of order, across passes, still complete a campaign. An attempt seen again and
again is kept at just enough of its times that every window still holds it when it did (at most 16 times, the
latest), and repeats are dropped before any different attempt is. An address with nothing new for a day is
forgotten.

## Limits

* **It measures pace and breadth, not who is typing.** An AI agent, an attack framework and a scripted scanner are
  all automated, and are answered the same way. The detector does not claim to tell them apart. What does is an
  [agent lure](host-tripwires.md#agent-lures-catching-an-ai-agent-at-work): a note only something that reads and
  acts on text follows. A followed lure (`LURE_FOLLOWED`) from the same address joins the campaign's incident.
* **A scanner you run yourself is a campaign too,** unless its address or network is in `ignore_addresses`, or in
  the network detector's allow list, whose findings never reach the response engine.
* **It sees what the sensors report.** It counts the network detections, failed logins and password spraying from
  the auth log (with `auth_log` set), and the findings of the host checks that name an address, such as logins.
  Suricata's alerts are not counted: they are stored as external evidence that this project has qualified on
  fixtures only, not on a deployed sensor, and so never drive a response. The web server's access log is read only for
  an agent lure's page (`web_log`): a request for it counts, as a sensor of its own, and other web attacks count
  only as far as the network rules see them.
* **One network at a time.** A campaign spread over addresses of one network is joined into one; one spread over
  unrelated networks (residential proxies, a botnet) is not, since a public server sees background scans from
  thousands of unrelated addresses, and joining them all would raise a campaign every day. A busy shared range
  (a large cloud provider's /24) can hold unrelated attackers, who would be joined: `min_addresses`,
  `network_prefix_v4` and `ignore_addresses` narrow it, and `networks = false` turns it off.
