# Prompt: grow MEGALODON into the defense its name describes

Status: ◐ **Proposed**. This is a reusable prompt for an AI coding agent (or a
human contributor). It authorizes nothing by itself: every slice it produces
still needs its own PR, tests, evidence badge and owner merge decision.

**How to use it:** paste everything under "The prompt" into a coding-agent
session opened on a fresh checkout of this repository. Ask for one slice per
session, either a slice you choose or the first one in the backlog that is
still open. Keep each pillar's work on its own branch and PR.

---

## The prompt

You are a senior defensive-security engineer working in the MEGALODON
repository. MEGALODON stands for **M**alware **E**limination **G**ateway
**A**nd **L**ayered **O**perations **D**efense **O**nline **N**etwork. Today it
is a local-first Linux defensive telemetry MVP: a Python metadata core, three
fixed detectors (`SYN_FLOOD`, `PORT_SCAN`, `DNS_TUNNELING`), a private SQLite
audit trail, a loopback HUD, offline importers (TShark, Zeek `conn.log`,
Suricata EVE, Nmap XML, STIX 2.1, ClamAV summaries, Lynis/AIDE reports), an
offline ATT&CK/ATLAS/D3FEND/OWASP/CISA KEV library, ECS/OCSF export, a
plan-only nftables boundary, a five-minute operator-approved single-IP
containment workflow, and a bounded local Qwen advisor that can propose but
never authorize.

Your mission is to make MEGALODON live up to each word of its name by adding
real defensive features, solutions and capabilities, one reviewable slice at a
time. Capability must grow without growing silent authority.

### Step 0: establish the baseline (do this before you write any code)

1. Read `README.md`, `SPECIFICATION.md` (especially §1 Mission, §2 Safety
   invariants, §4 Fixed rules), `CONTRIBUTING.md`, `SECURITY_REVIEW.md`,
   `docs/integration-hub.md`, `docs/red-blue-security-guide.md`,
   `docs/system-opportunity-map.md` and `docs/adr/0006-evidence-status-badges.md`.
2. Record the `main` commit, your branch head, the open issues and any open PRs
   that overlap your slice. Don't duplicate or contradict work in flight.
3. Find the existing module you will extend, for example `detector.py`,
   `detector_registry.py`, `security_patterns.py`, `host_security.py`,
   `host_findings.py`, `threat_context.py`, `defense.py`, `firewall.py`,
   `osquery_inventory.py`, `nmap_inventory.py`, `clamav_summary.py`,
   `suricata_store.py`, `flow_ingestion.py`, `alert_lifecycle.py`,
   `siem_export.py` or `knowledge.py`. Extend before you add something new.

### Non-negotiable guardrails

These come from the specification and contributing guide. A slice that breaks
one is wrong, however useful it looks.

- **Defensive only.** Don't add exploit code, payload crafting, packet
  injection, credential attacks, scanning of third-party hosts, detection
  evasion or any offensive tool. Red-team work means synthetic fixtures that
  try to break a MEGALODON invariant. It never means attacking a live system.
- **Evidence, not verdicts.** A detection, match or model explanation is a
  hypothesis for operator review. Don't claim attribution, proof of malice or
  complete visibility. The README's "not an autonomous antivirus" statement
  stays true until code and native receipts prove otherwise.
- **Metadata only.** Store no payloads or payload hashes in the core event
  model. File-level malware work stays in its own owner-private store with
  explicit retention limits.
- **Validate before persisting.** Parse every IP, port, flag, timestamp,
  domain, hash and path into a typed value and bound its size. Network-derived
  values never reach a shell. Build fixed argv lists only.
- **Host changes need a person.** Anything that changes the host (blocking,
  quarantine, a DNS sinkhole, killing a process, disabling a service) is a plan
  first. Applying it needs explicit operator approval through OS
  authorization, a finite expiry, an allowlist check where protected networks
  always win, an audit record, readback, and a one-click release or restore.
  Copy the pattern in `defense.py` and `docs/visual-operations-defense.md`.
  Never apply automatically.
- **AI stays advisory.** Local model output can't become a detection, target,
  command, query, path, rule or action. New AI tools go through the closed
  broker in `ai_broker.py` with fixed schemas and receipts.
- **Local first, loopback only.** No new listener beyond loopback, no remote
  control, and no required cloud account. New outbound fetches are limited to
  the approved public reference sources, are scheduled, checksum-bound and
  attributable, and never send private observations off the PC.
- **Atomic and fail-closed.** Keep the transactional event/detection/action
  commit, the chronology checks and the bounded memory structures. Under load
  or uncertainty, refuse and record the reason. Never guess.
- **One coherent slice per PR.** Use `.github/PULL_REQUEST_TEMPLATE.md`, pick
  exactly one ADR-0006 badge, and list the negative controls along with what
  stays unproved.

### Capability backlog, organized by the name

Pick **one** item per session. Each item lists the smallest useful first
slice. Later slices can deepen it.

#### M: Malware elimination (host and file defense)

1. **ClamAV result importer.** Grow `clamav_summary.py` from counts into a
   bounded, checksum-bound importer for one completed `clamscan` report. Keep
   the detection name and path in an owner-private store, show them in the HUD
   as findings, and map each one to an ATT&CK/D3FEND reference where the
   library has one. Run no scanner and delete nothing.
2. **Operator-approved quarantine.** Add a quarantine *plan* for a flagged file:
   move it into a private `0700` vault, record its SHA-256, owner, mode and
   original path, and support one-click restore. Apply it only through
   OS-authorized operator approval, with an audit record and readback, never
   automatically.
3. **YARA rule matching (offline).** Run operator-supplied, size-bounded YARA
   rules over an operator-selected file or directory with fixed limits on
   files, bytes and time. Store the rule ID, file hash and path only.
   Rule text is untrusted input and needs a timeout and a crash boundary.
4. **Persistence review.** *First slice delivered:*
   `megalodon/persistence_review.py` inventories fixed autostart, systemd,
   cron, shell-startup, session, SSH and loader-preload locations read-only,
   and compares them with a private operator-recorded baseline. See
   `docs/host-security.md`. Next slices: a HUD Setup or host-findings view
   with an approval-gated "record baseline" action, and new SUID binaries,
   which need a bounded filesystem walk and an owner decision on scope.
5. **Process-to-connection correlation.** Link a live connection to its owning
   process (PID, executable path, hash, parent) using fixed `/proc` reads, so
   an unexpected outbound connection names its binary. Store no command-line
   secrets: redact arguments by default.

#### G: Gateway (network edge and egress defense)

6. **Beaconing detector.** A review-only `REGULAR_INTERVAL` cadence check
   already exists in `security_patterns.py` for connection summaries. Extend
   that check rather than adding a parallel rule: for example, per-destination
   jitter statistics, a payload-size regularity signal, or HUD presentation.
   Promote it to a fixed detector in `detector_registry.py` only with
   thresholds kept in code, synthetic positive and negative fixtures, a bounded
   per-pair state, and an owner decision to change the three fixed rules.
7. **DGA and suspicious-domain scoring.** *First slice delivered:*
   `megalodon/domain_signals.py` scores the hostnames the HUD already observes
   (DNS answers, TLS SNI, HTTP Host) for spelling signals and shows them as
   review-only `name_review` records in the endpoint inspector. See
   `docs/visual-operations-defense.md`. Next slices: n-gram rarity from a
   pinned offline corpus, and carrying the signal as context on the existing
   `DNS_TUNNELING` alert. That alert needs a decision first: the core event
   stores only the DNS query length, so retaining names is a privacy and
   data-model change.
8. **Egress policy plan.** Generate a reviewable nftables egress allowlist or
   denylist from observed destinations, with a dry run and a diff against
   current rules. It stays plan-only unless it goes through the existing
   approved containment workflow.
9. **DNS sinkhole plan.** Match observed domains against an offline,
   checksum-bound blocklist such as a fetched abuse feed. Produce a time-limited
   sinkhole plan for the operator to approve, with release and audit.
10. **LAN gateway integrity.** Detect a change in the default gateway's MAC,
    duplicate-IP or ARP spoofing indicators, a rogue DHCP server, and a new
    unknown device on the local subnet, all from passive metadata only.

#### LOD: Layered operations defense (detection engineering and response)

11. **Alert lifecycle wiring.** Persist the states new, triaged, investigating,
    contained, resolved and false positive, plus operator notes, for the
    in-memory `alert_lifecycle.py`. Follow `docs/alert-lifecycle-wiring-survey.md`,
    with atomic migrations, rollback and HUD actions behind tokens.
12. **Detection-as-code and replay.** Give every rule a versioned spec, an
    ATT&CK technique, a D3FEND countermeasure and a fixture corpus. Extend
    `tools/replay_security_patterns.py` so CI fails when a rule's precision or
    recall changes on the corpus.
13. **Sigma subset importer (offline).** Translate a small, closed subset of
    Sigma network and DNS rules into review-only pattern checks. Unsupported
    fields fail closed with a clear reason. Imported rules never get
    containment authority.
14. **Response playbooks.** Write plan-only runbooks per detection (what to
    check, what evidence to keep, which approved action applies), shown in the
    HUD next to each finding. Playbooks can link only to existing approved
    actions.
15. **Hardening posture checks.** *First slice delivered:*
   `megalodon/hardening_review.py` reports read-only pass, fail, review,
   unknown or not-applicable results for fixed kernel, OpenSSH, APT
   automatic-update and listening-socket settings, each with an ATT&CK
   mitigation and a remediation note. See `docs/host-security.md`. Next
   slices: a HUD view, firewall default-policy checks (which need a
   privileged read), and non-APT update services.

#### ON: Online network (visibility, intelligence and exposure)

16. **Exposure correlation.** Join imported Nmap service and version results
    with the offline CISA KEV and CVE references to list "known-exploited
    service versions on my network" as review items, with a confidence level
    and source dates.
17. **Offline indicator matching.** Match observed IPs and domains against
    IPv4, IPv6 and domain indicators from the bounded STIX reader in
    `threat_context.py`. A match is context on a finding, never a new
    detection or action by itself, and the receipt names the bundle's
    checksum.
18. **Threat-level summary.** Add a single explainable HUD gauge computed from
    open findings by severity, age and corroboration. Show the formula in the
    UI. The model never computes it.
19. **Incident report export.** Bundle one incident's findings, timeline,
    operator notes and actions into a signed local report in Markdown or PDF,
    plus ECS/OCSF records through `siem_export.py`. Deliver nothing over the
    network.
20. **Encrypted-traffic metadata.** Import JA3/JA4, SNI and certificate issuer
    and expiry fields from Suricata or Zeek output to flag self-signed,
    expired or rare-fingerprint TLS sessions, without decrypting anything.

### What every slice must deliver

1. **Design note.** A short section in the owning doc, or a new
   `docs/<feature>.md`, covering the operator task, inputs and their bounds,
   outputs, the authority class (read-only, plan or approved action), the
   ATT&CK/D3FEND mapping, failure behavior and what stays unproved.
2. **Code.** The smallest change that does the job, matching the surrounding
   style: typed and validated inputs, fixed limits as module constants, no new
   runtime dependency unless `docs/dependency-policy.md` allows it.
3. **Tests.** Focused unit tests with synthetic positive fixtures plus negative
   controls: oversized input, malformed fields, hostile strings, chronology
   violations, allowlisted targets, a missing tool, a timeout and an
   attempted authority escalation. Run the full suite:
   `python -m pytest -q`, `python -m compileall -q megalodon tests` and
   `python tools/check_repository_hygiene.py`.
4. **HUD surfacing** where the slice is operator-facing. Keep data views
   read-only, put actions behind the existing per-service tokens and
   same-origin checks, and check the layout at phone width.
5. **Docs honesty.** Update the README, the integration hub table and the
   specification only to the level the code supports. Use the ADR-0006 badge
   that matches.
6. **PR.** A draft PR that follows the template: the evidence level, the
   operator task, exact paths, verification commands with results, negative
   controls, and what still needs a native receipt.

### Definition of done for the overall mission

MEGALODON earns its name when an operator on one Linux PC can:

- see which **malware** a scan found, where it lives, and quarantine it
  reversibly with approval;
- see what crosses the **gateway**, including beacons, suspicious domains,
  known-bad indicators and new devices, and apply a time-limited block or
  sinkhole they approved;
- triage every alert through a **layered** lifecycle with mapped techniques,
  countermeasures, playbooks and a regression-tested rule set;
- understand the **online network**'s exposure: known-exploited services,
  weak hardening and an explainable threat level;
- export a complete incident record;

and every step leaves an audit trail, can be undone, and never acts without a
person.

Start now: complete Step 0, state which single backlog item you will
implement and why it is the best next slice, then build it.
