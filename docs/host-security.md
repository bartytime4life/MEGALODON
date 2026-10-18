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
  upgrades and administrator changes can produce legitimate differences. New
  reports request `list_entries` before `report_url`, so the bounded private
  report can identify added, removed and changed paths for operator review;
  these paths are not returned by the dashboard projection.
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
An explicit successful refresh may replace semantically invalid/obsolete cache
content after all replacement sources validate. That invalid content is not
promoted to the previous-valid slot; an existing previous-valid cache is retained.
Filesystem/ownership failures remain refusals, and a failed replacement-source
validation still leaves the active cache untouched. This does not repair or
rewrite an audit/evidence store.
The closed policy needs review if IANA allocations change; no runtime lookup is
performed. Sources: [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IANA IPv6 address space](https://www.iana.org/assignments/ipv6-address-space/), and
[IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).

## Hardening posture review

`python -m megalodon.hardening_review` reads a fixed set of live settings and
reports each as `pass`, `fail`, `review`, `unknown` or `not_applicable`, with
the observed value, the expected value, an ATT&CK mitigation ID and a
remediation note. It runs as the HUD user, executes nothing and changes
nothing; applying a remediation is a separate operator decision. This lane is
command-line only for now.

| Area | Checks | ATT&CK mitigation |
| --- | --- | --- |
| Kernel | `kernel.randomize_va_space = 2`, `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `fs.suid_dumpable = 0` | M1050, M1028 |
| Filesystem | `fs.protected_symlinks`, `fs.protected_hardlinks` | M1028 |
| Network stack | `tcp_syncookies`, `rp_filter`, IPv4 and IPv6 `accept_redirects`, `accept_source_route`; `ip_forward` is `review`, not `fail`, because container runtimes, VPNs and routers enable it on purpose | M1037 |
| OpenSSH server | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, using OpenSSH defaults when unset | M1026, M1032, M1027 |
| Updates | APT `Unattended-Upgrade`, last setting in `/etc/apt/apt.conf.d` wins; other package managers are `not_applicable` | M1051 |
| Listeners | Non-loopback TCP listeners from `/proc/net/tcp` and `tcp6`, at most 64, reported as `review` | M1042 |

Kernel values come from `/proc/sys`, so they are what is running now, which
can differ from boot configuration. Every file is opened without following a
final symlink. Settings files are read to at most 64 KiB and the socket tables
to at most 16 MiB; a cut-off read is never treated as complete. The SSH reader
accepts space, tab or `=` separators, applies the first value of each keyword,
follows `Include` only for paths that stay under `/etc/ssh`, refuses symlinked
include files, and stops at the first `Match` block because conditional
settings are not evaluated. At most 256 APT configuration files are read in
name order, ignoring `/* */`, `//` and `#` comments. Each check's note says
when any of these limits applied, and the listener check sets
`listeners_complete`.

Incomplete evidence never produces a pass. A missing IPv4 socket table, or a
missing IPv6 table while `/proc/net/if_inet6` exists, makes the listener check
`unknown`. An unavailable `ip_forward` is reported as `unknown` rather than
omitted. sshd reads includes in place and keeps the first value, so the review
tracks where any SSH text was skipped: a truncated file, a refused or
unreadable include, an include outside `/etc/ssh`, or an include pattern
matching more than 32 files. A value found before the first skip is
evaluated; a value found after one is `unknown`, because the skipped text
could set it first; and a keyword not found at all after a skip is `unknown`
instead of its OpenSSH default. Automatic
updates enabled in the files that were read are `unknown` when any APT file was
unreadable, truncated or past the 256-file bound, since a later file could
disable them. A listening socket is not proof of
exposure, since a firewall may still block it, and process names need root,
so they are not shown.

A pass does not establish that the host is secure, and a fail does not
establish compromise. Firewall rules, root-only files and per-interface
sysctl overrides are not evaluated. Each check carries
`action_status: not_attempted`, and the result carries `action_authority: none`.

## Command line

### Host findings to review

Setup → Host security and threat context → **Host findings to review** presents
saved local observations separately from admitted detector findings and the
network inspector's dated reputation context. This adds no incident-confirmation
authority. Significance comes from the source's warning/suggestion or change
category; no CVSS score, inferred incident severity or compromise verdict is
assigned.

| Observation | Evidence shown | Operator follow-up |
| --- | --- | --- |
| Lynis configuration warning | Test ID, bounded description, original report line, observation time and report SHA-256 | Review the named rule and intended configuration in the private report; use Review audit controls to reach the existing explicit audit button |
| Lynis hardening suggestion | The same identity fields, labeled advisory | Assess whether the suggestion fits this host; independently review any proposed configuration change |
| AIDE file-change categories | Actual exit status and its boolean added/removed/changed flags, report identity, baseline time/SHA-256 and fixed readable scope | Inspect the private report's paths and compare with expected package/operator changes; use Review comparison controls for an explicit recheck |
| Initial AIDE baseline | Labeled baseline creation, with baseline/report identity | Preserve it as an observation, not a clean-system certificate; choose a later explicit comparison |
| Reputation match | Existing network inspector, publisher and expiry dates | Review related network evidence under the existing separate defense workflow; a match does not authorize a block |

Every saved result retains its own UTC observation time. A result older than
seven days carries a recheck reminder; this is a presentation threshold, not a
security assurance or a freshness guarantee for newer results. The view does not
monitor the host continuously or claim that any observation verifies an incident.
Its follow-up links only navigate to existing controls. Viewing, expanding or
refreshing findings cannot run tools, modify the baseline, quarantine/delete
files, refresh feeds, invoke a model or apply a firewall action. Host changes
still require the separate explicit operator-reviewed workflow and authorization.

New summaries add `review` with schema `megalodon-host-review-v1` to the existing
private `audit.json` / `integrity.json` files. The outer host-security snapshot
stays v1 and adds per-source `audit_state` / `integrity_state`: `missing`,
`unavailable`, `legacy` or `available`. Missing or invalid data never becomes a
zero-findings result. Legacy aggregates remain readable but cannot establish
report identity, rule detail, or whether AIDE created a baseline or compared it.
Run a new explicit check to obtain those fields. Earlier releases may refuse
extended summaries on rollback; preserve the private evidence rather than
editing it to satisfy an older reader.

The Lynis parser accepts report format 1.0 and four pipe-delimited finding fields
(with or without a terminal separator). It retains only the rule ID and
description, never the tool's details, solution command or external URL fields.
Descriptions are limited to 240 UTF-8 bytes, lines to 4,096 characters and totals
to 10,000 observations. The view retains at most 16 entries, warnings first,
and explicitly reports omitted entries. Unknown versions, duplicate version
fields, invalid/control text, excessive observations and unsupported finding
formats refuse the run before replacing its previous result.

Reports are written before their summaries. Each read revalidates the private
report identity; Lynis findings/counts are recomputed against the same report.
Partial replacement, malformed summaries or a later report mismatch makes that
source unavailable, independently of the other source or feed cache. A SHA-256
binds local file identity; it is not a publisher signature, authenticated host
attestation or proof that a recommendation is correct. The existing private-file,
ownership, size, fixed executable, deadline and output bounds remain in force.
Raw reports, file contents and AIDE entry paths are not served to the browser.

Repository regressions use fabricated reports, fake tool runners and inert DOM
execution. They cover source separation, validation, missing/legacy/stale states,
report mismatch, AIDE exit flags, preserved baselines and zero rendering effects.
The opt-in `tests/browser_acceptance.py` suite also calls the findings journey
in `tests/browser_host_findings.py` through the existing Linux browser workflow.
It serves synthetic configuration GET responses to the shipped page, exercises
keyboard disclosure, navigation, reflow, state transitions and failed-read
clearing, and refuses any browser action request after sign-in. Passing this
journey establishes rendered fixture behavior only; it does not exercise the
host-summary filesystem reader or run a native audit.
These checks do not prove installed Lynis/AIDE compatibility, actual host posture,
native scan success or recovery of the installed audit store. Those require a
separate controlled Linux workstation acceptance after
exact-head review and repository checks. No trial, subscription, cloud service
or new runtime dependency is added.

### Read-only reference coverage

The endpoint inspector separates missing, unavailable, expired, partially current
and current cached references. The operations GET projection validates and reads
one cache for both coverage and matching, limited to its retained endpoint list.
It exposes fixed source IDs, publisher/expiry times, indicator counts and the
local check time. It does not expose raw feed bodies or perform a refresh.
The coverage projection identifies the public-unicast addresses actually checked.
Private and other policy-excluded selections cannot display a no-match result.
Expiry is exclusive: a source expiring at the current instant supplies no match.
Each endpoint retains one representative match per source: for overlapping DROP
prefixes, the most-specific matching range and its SBL references are shown.
This bounds output without omitting a later endpoint's positive match.

The browser rejects malformed or contradictory source summaries independently
of packet telemetry, rechecks freshness/expiry against its clock, and binds a
displayed match to the selected IP and the same source dates. A stale telemetry
snapshot or selection absent from the retained endpoint list cannot present
current matching coverage, even if the network workspace observed it earlier.
No match is always scoped to the available cached sources; incomplete coverage
is visibly unknown. No new browser action, model request or host effect is added.
Synthetic backend and inert-DOM tests cover these states; rendered-browser and
installed-host acceptance remain separate gates.

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

## Persistence location review

`python -m megalodon.persistence_review review` inventories a fixed set of
common Linux persistence locations, and `... baseline` records what is present
now for later comparison. Both run as the HUD user, read only, and execute
nothing. This lane is command-line only for now; it has no HUD route.

| Category | Locations | ATT&CK |
| --- | --- | --- |
| Autostart | `~/.config/autostart`, `/etc/xdg/autostart` | T1547.013 |
| systemd units | `~/.config/systemd/user`, `~/.local/share/systemd/user`, `/etc/systemd/system`, `/etc/systemd/user` (one level of `.wants` and drop-in directories) | T1543.002 |
| cron | `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}` | T1053.003 |
| Shell startup | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.bash_logout`, `~/.profile`, `~/.zshrc`, `~/.zprofile`, `/etc/profile`, `/etc/bash.bashrc`, `/etc/profile.d` | T1546.004 |
| Session scripts | `~/.xprofile`, `~/.xsessionrc`, `/etc/rc.local` | T1037.004 |
| SSH | `~/.ssh/authorized_keys`, `~/.ssh/authorized_keys2`, `~/.ssh/rc` | T1098.004 |
| Loader preload | `/etc/ld.so.preload` | T1574.006 |

Locations are code constants, never operator or browser input. Each regular
file is opened without following a final symlink and without blocking on a
FIFO or device, and is hashed over at most its first 256 KiB. A symlink records
its target without being followed. Directories, including nested `.wants` and
drop-in directories, list at most their 128 smallest names in bounded memory,
and any overflow is named in `gaps`. The 512-item bound is checked before every
read; when it stops a review, `inventory_truncated` is true and the first gap
says so.
Desktop `Exec` and systemd `ExecStart*` lines keep only the executable and an
argument count, because arguments can carry tokens or passwords.
`authorized_keys` keeps each key's type and `ssh-keygen`-style SHA-256
fingerprint; key comments and options are dropped.

Review findings are `ADDED`, `CHANGED` and `REMOVED` against the baseline, plus
three checks that need no baseline: `PRELOAD_PRESENT` (a non-empty loader
preload list), `WORLD_WRITABLE` (a startup file any account can change) and
`UNEXPECTED_OWNER` (owned by neither root nor this account). Each finding
carries `action_status: not_attempted`, and the result carries
`action_authority: none`. At most 64 findings are listed; `findings_total`
counts all of them, and `findings_truncated` plus the first gap disclose any
that were not listed.
`REMOVED` is reported only for locations that were fully enumerated. A path
under a truncated, unlistable or never-reached location is listed in
`incomplete_locations`, and the gaps count such baseline entries as
unconfirmed instead of removed. Change identity compares state, SHA-256,
size, mode, owner, symlink target and SSH key fingerprints; for a file larger
than the 256 KiB hashed prefix it also compares the modification time. At most
32 gaps are listed; `gaps_total` and `gaps_truncated` report any beyond that,
and the missing-baseline and truncation notices always come first. Package updates and the operator's own edits also
add and change these files, so a finding is a reason to look, not proof of
compromise.

The baseline is a private `0600` file at
`~/.local/share/megalodon/support/persistence-review/baseline.json`, read and
written through the same private-file checks as the host security files. It
records `trust: observed_not_known_clean`. A tampered, broadly readable or
symlinked baseline fails closed. Recording a new baseline replaces the old one,
so archive a baseline you want to keep first.

Coverage limits: user crontabs in the system spool, root-only files, other
accounts' homes, and in-memory or kernel persistence are not reviewed. Package
unit files under `/usr/lib/systemd` belong to the AIDE and package-manager
lanes, not to this review.

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
- [Ubuntu AIDE report options](https://manpages.ubuntu.com/manpages/jammy/man5/aide.conf.5.html):
  report levels and the required placement before `report_url`; native acceptance
  of the installed package remains separate.
- [Lynis report writer](https://github.com/CISOfy/lynis/blob/master/lynis) and
  [finding helpers](https://github.com/CISOfy/lynis/blob/master/include/functions):
  upstream format references inspected 2026-10-17, not pinned runtime dependencies.
- [Spamhaus DROP terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/):
  free under terms, including retained rights and currentness obligations;
  do not use the publisher name for commercial promotion.
- [IPsum](https://github.com/stamparm/ipsum) and its repository license: aggregated
  IP reputation context, rather than attacker identity or a probability score.
