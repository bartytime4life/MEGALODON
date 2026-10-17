# Local host security and dated threat context

Lynis and AIDE are free Ubuntu packages, without a trial or vendor account.
Setup → Apps & connections contains their installation controls. Setup → Host
security and threat context contains four explicit, fixed actions. Existing
loopback sign-in, Origin, configuration nonce and serialized job checks apply.
No new listener, model permission or privileged response path is added.

The inspected Ubuntu `lynis` 3.1.6-1 package also installs and enables its own
`lynis.timer` (daily, with a randomized delay) and may immediately start its
system audit during package configuration. That native audit runs as a system
service and writes its own reports; it is separate from the unprivileged HUD
workflow and its coverage. Inspect it with `systemctl status lynis.timer`.
The fixed `aide` recipe excludes recommended packages such as `aide-common`;
its HUD baseline and checks remain explicit. Package installation still uses
the normal OS authorization dialog. No MEGALODON feed-refresh timer is created.

## Checks and scope

- **Run Lynis audit** runs the packaged auditor as the HUD user, with plugins
  disabled, a five-minute deadline and bounded private output. It saves warning
  and suggestion counts plus a private report. Root-only/unreadable checks are
  outside coverage. Suggestions are not confirmed vulnerabilities or threats.
- **Create initial AIDE baseline** records readable files in `/usr/bin`,
  `/usr/sbin`, `/etc/ssh` and `/etc/systemd/system`, using SHA-256 and selected
  attributes. The baseline describes the current system; it does not certify
  the system is clean. Creation refuses an existing baseline or database.
- **Check file changes** verifies the baseline digest, checks the same scope and
  saves a report without updating the baseline. Result metrics ending in
  `_detected` are boolean change-category flags, not file counts. Package
  upgrades and administrator changes can produce legitimate differences.
- **Refresh threat references** downloads only the fixed Spamhaus DROP v4/v6
  and IPsum HTTPS resources. There are no redirects, proxies, credentials,
  uploads, arbitrary URLs or automatic response actions. Each source is bounded
  to 8 MiB and 200,000 lines/indicators, with connection/read and total download
  deadlines. IPsum occurrences must be at least three; overlapping source lists
  are not independent evidence. Multiple SBL references for a DROP range remain
  attached to that range.

Refresh is explicit and limited to one attempt per 24 hours, including failures.
A later failed download or validation leaves the active cache in place. The
previous valid cache is retained on successful replacement. Source URL, terms,
publisher date, retrieval date, raw-body SHA-256 and byte size accompany the
normalized indicators. Latest downloaded bodies are bounded troubleshooting
candidates and may differ from the active cache after a failed refresh. They
are not admitted detection evidence. A hash detects identity; it does not
supply an independent publisher signature or establish indicator accuracy.

References expire 48 hours after the **publisher's** date, rather than receiving
new freshness merely because they were downloaded. Missing, future-dated,
malformed, private-address and stale source data cannot activate a new cache.
Matching uses the local cache only and sends no observed addresses to a service.
Expired sources stop supplying matches. The endpoint inspector displays matches
separately from sensor findings, with source and expiry. A match does not prove
compromise or identify an actor. No match does not establish safety.

Reference admission rejects catch-all, multicast, private, reserved and mixed-scope
ranges both on download and when reloading an existing cache. The same policy
excludes scoped/mapped addresses and IPsum non-unicast entries. It conservatively
excludes IPv4 special-purpose blocks (including their public exceptions), and
limits IPv6 to ordinary `2000::/3` unicast outside special-purpose, documentation
and retired transition/test space. A supernet overlapping excluded space is
refused as a whole; it is never silently split or partially accepted. This is
input admission, not proof that an address is reachable or hostile. An unsafe
previously saved cache becomes unavailable without being rewritten or deleted.
The closed policy needs review if IANA allocations change; no runtime lookup is
performed. Sources: [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IANA IPv6 address space](https://www.iana.org/assignments/ipv6-address-space/), and
[IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).

## Command line

Use the Python environment containing this release:

```bash
python -m megalodon.host_security status
python -m megalodon.host_security audit
python -m megalodon.host_security baseline
python -m megalodon.host_security check
python -m megalodon.host_security refresh
python -m megalodon.host_security match --ip 1.1.1.1
```

The last address is an input example, not an allegation. `match` accepts at most
256 literal addresses and never queries them over the network. Commands can run
independently of the HUD. A private cross-process lock prevents overlapping
mutations. Tool execution requires the root-owned packaged executable; it does
not run a program supplied by a feed, browser request or PATH entry.

These tools prepare context for the existing reviewed defense workflow. They
cannot invoke containment, quarantine/delete files, replace a baseline, submit
reports to a publisher or execute model output. The existing five-minute
containment workflow still requires its separate operator review and OS action.

## Placement, compatibility and rollback

Implementation stays in the existing `megalodon/` package; behavior tests stay
under `tests/`; this guide stays under `docs/`. This follows the responsibility
and existing-root placement principle in KFM's canonical
`docs/doctrine/directory-rules.md`; the legacy architecture path redirects there.
MEGALODON's actual package and runtime conventions govern these non-KFM files.
No KFM root, canonical policy, contract registry or publication lane is created.

Runtime files are private local working context under the existing support
area, `~/.local/share/megalodon/support/host-security`. They are not promoted into
MEGALODON's admitted alert store or KFM's governed evidence lifecycle. Reports
and baseline persist through app restarts. The active/previous feed cache and
latest downloads are fixed-name replacements, not an accumulating archive.

The tool registry adds Lynis and AIDE. Archived ten-tool browser presence and
runtime receipts retain their timestamps and show the new entries as unknown.
This does not upgrade their historical observations. Windows and other native
platform execution remain unsupported.

Rollback uses the prior installed MEGALODON release; it leaves the private host
security files available for review. AIDE checks never refresh their own
baseline. Archive and review an old baseline explicitly before any later
replacement. No package removal, service enablement, DNS or firewall change is
needed to stop using these checks. Feed refresh has no scheduler by default.

## Publisher references

- [Lynis](https://cisofy.com/lynis/), GPL, local audit; Enterprise is optional.
- [AIDE](https://aide.github.io/), GPL-2.0 file integrity checker.
- [Spamhaus DROP terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/):
  free under terms, including retained rights and currentness obligations;
  do not use the publisher name for commercial promotion.
- [IPsum](https://github.com/stamparm/ipsum) and its repository license: aggregated
  IP reputation context, rather than attacker identity or a probability score.
