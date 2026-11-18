# Threat-feed refresh

`megalodon feeds refresh` keeps the IOC watchlist current from threat feeds
you choose. It downloads each feed and writes one owner-private watchlist
file: your own entries first, then each feed's indicators labeled
`feed:<name>`. The threat-signal layer then raises `IOC_MATCH` for matching
addresses, domains (with `dns_names` or `tls_fingerprints` on) and JA3
fingerprints.

Nothing is refreshed by default, and no feed is built in. Feeds change
address and terms, so pick and verify your own.

## Configure

```toml
[feeds]
output = "~/.config/megalodon/feeds.watchlist"   # generated; do not edit
base = "~/.config/megalodon/watchlist.txt"       # optional: your own entries, kept first
state_dir = "~/.local/state/megalodon/feeds"     # last good copy of each feed
stale_hours = 48

[[feeds.source]]
name = "feodo"
url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
format = "ip"

[[feeds.source]]
name = "urlhaus"
url = "https://urlhaus.abuse.ch/downloads/hostfile/"
format = "hosts"

[[feeds.source]]
name = "sslbl-ja3"
url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
format = "ja3"

[threat_detection]
watchlist_path = "~/.config/megalodon/feeds.watchlist"
```

The URLs above are examples of well-known public feeds; check each
provider's current address and terms of use before relying on it.

| `format` | Reads | Examples |
| --- | --- | --- |
| `ip` | the first IP or CIDR on each line; `#` and `;` comments | Feodo Tracker, Spamhaus DROP (text), FireHOL, CINS Army |
| `domain` | the first domain on each line | plain domain blocklists |
| `hosts` | hosts-file lines (`0.0.0.0 name`, `127.0.0.1 name`) or bare names | URLhaus hostfile, many DNS blocklists |
| `ja3` | the first CSV column as a JA3 MD5 | abuse.ch SSLBL JA3 |

A feed that needs a key takes `header_name = "Auth-Key"` and
`token_file = "~/.config/megalodon/feeds/abusech.key"`. The token file holds
one line, is owned by you and has mode 600, and the key is never logged. The
key is never sent on a redirect, whatever its header name. Header names the
client sets itself (`User-Agent`, `Accept`, `Host`, `If-None-Match` and
similar) are refused.

## Run on a schedule

```bash
megalodon feeds refresh
```

```bash
megalodon feeds status
```

`refresh` exits 1 if any source failed, and `status` exits 1 if any source is
older than `stale_hours`, so both work from cron or a systemd timer. With
`--if-older 360`, a source checked within the last six hours is skipped.
A user crontab entry that refreshes every six hours, using the installed application's environment:

```bash
( crontab -l 2>/dev/null; echo '17 */6 * * * $HOME/.local/share/megalodon/current/venv/bin/python -I -m megalodon feeds refresh --if-older 300 >/dev/null' ) | crontab -
```

The service reads the watchlist when `megalodon run` or a HUD capture starts,
so a refreshed list applies from the next start.

## What a refresh does

* **Fetching.** HTTPS only, or plain HTTP to a literal private or loopback
  address. Up to three redirects are followed, only to HTTPS, and the key
  header is dropped on a redirect. Each feed is capped at 16 MiB and a
  20-second timeout, and compressed responses are refused. Requests are
  conditional (`If-None-Match`, `If-Modified-Since`), so an unchanged feed
  costs a 304.
* **Parsing.** Feed content is untrusted text. Each line goes through the
  watchlist's own validation: networks broader than IPv4 /8 or IPv6 /16 and
  bare TLDs are refused, and lines over 512 characters are skipped. Labels
  from the feed are not used; every indicator is labeled `feed:<name>`.
* **Last good copy.** A source fails when its download fails, it is not
  UTF-8, it yields no indicators, or more of its lines are unreadable than
  readable, such as an HTML error page. A failed source keeps its last good
  copy in `state_dir`, so a bad download never empties coverage. `status`
  reports each source's age since its last successful check, a download or a
  304 confirming nothing changed; failed attempts do not count. A cached copy
  belongs to one URL and format: changing either starts the source over.
* **Bounds.** Each source keeps at most `max_entries` (default 50,000)
  indicators, and the report counts the rest as `truncated`. The output stays
  under the watchlist's limits of 200,000 indicators and 8 MiB. The base list
  comes first, then the feeds in order; anything over the limits is counted
  as `dropped_over_limit`.
* **Output.** Written atomically with mode 600, after checking that it parses
  exactly as the service will read it. The state folder must be a private
  directory you own. The base list gets the same owner-private checks as any
  watchlist.

## Limits

* Feed quality decides finding quality. Lists go stale, and shared hosting,
  CDNs and NAT put innocent traffic behind listed addresses. An `IOC_MATCH`
  from a feed is a reason to look, not attribution.
* Only line-based formats are read. STIX bundles still go through
  `megalodon watchlist import-stix` with a pinned digest, and TAXII is not
  supported.
* A refresh has no signature check. It trusts HTTPS and the provider.
