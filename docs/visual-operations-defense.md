# Visual operations and local defense

The main HUD combines live captured traffic, the globe, a compact PC resource
strip and an IP inspector. Setup contains installation, downloads, interface and
location configuration. Sensors shows current tool status. Historical records
and saved computer observations are progressively disclosed inside the HUD.

## What IP details mean

`GET /api/operations` projects up to 128 retained connections into at most 64
IP rows. It includes addresses, address class, exact interface-local membership,
observed ports, directional byte/packet counts, first/last observation, TCP
flags and approximate offline geography when configured. Per-IP sent/received
is relative to that endpoint; overview direction is relative to this PC.
The traffic pulse uses five-second bins of accepted metadata, retained for up
to a minute. Gaps, evictions and capture drops limit coverage. These are neither
complete network totals nor a measure of link capacity.

The inspector reads at most 256 KiB / 1,000 complete recent EVE records.
Explicit DNS A/AAAA answers can associate a name with their returned address;
a DNS question does not associate its hostname with the resolver. TLS SNI and
HTTP hostname observations associate with the recorded destination. Names do
not prove ownership or safety. Port names are hints, not application detection.
Sensor findings carry their source and time and stay separate from the strict
admitted-detection workflow. No WHOIS, reverse DNS or reputation lookup uploads
observed addresses. No application-to-IP attribution is claimed.

EVE field semantics follow the [Suricata format documentation](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html).

## Qwen and fixed scripts

Analyze IP sends a bounded typed observation to the pinned local model. Qwen
returns an explanation and one closed proposal: observe, refresh inventory,
scan files, or prepare containment. A proposal never executes. The operator
chooses the fixed workflow from the HUD. Refresh inventory and scan files use
the existing configured targets/folders and collectors.

Interactive analysis uses a fixed two-field JSON schema, a 128-token output
budget, a 240-character explanation and a 64-token prompt batch to limit compute
buffer memory. The application validates the answer independently. Local model
busy, unavailable, invalid and failed responses remain visible and never trigger
a proposal. The schema transport follows [Ollama structured outputs](https://docs.ollama.com/api/generate).

Terminal equivalents use the running HUD's same local controls:

```bash
./scripts/defense.sh status
./scripts/defense.sh analyze --ip PUBLIC_IP_FROM_HUD
./scripts/defense.sh refresh_inventory
./scripts/defense.sh scan_files
./scripts/defense.sh plan_containment --ip PUBLIC_IP_FROM_HUD
./scripts/defense.sh apply_containment --plan-id ID_FROM_PREVIEW
./scripts/defense.sh release_containment --ip PREVIOUSLY_CONTAINED_IP
```

The CLI prints action state; `status` retrieves completion. The fixed script
does not accept shell commands, executable paths, remote scan scopes or model
generated code. Defense acts on this PC; there is no retaliation against remote
systems, exploit delivery, credential collection, or traffic flooding.

## Temporary containment

A preview must name a currently observed public endpoint. Local/reserved,
allowlisted, observed DNS, SSH and RDP service endpoints are protected. A preview
expires after 60 seconds and can be used once. Apply is a separate operator
action and requires the OS authorization prompt. All applications using the
selected IP may lose connectivity, including unrelated sites sharing that IP.

The fixed helper creates only `inet megalodon_guard`, with two 64-element timeout
sets and input/output drop rules. Each element has a five-minute kernel timeout.
An existing table must match the expected comment, chains, expressions, types,
sizes and timeouts before it can be used. Other tables are neither flushed nor
rewritten. Add and release perform readback. Release removes only that managed
element. Legacy `firewall-install` / `firewall-block --apply` routes still refuse.

The kernel timeout continues if the HUD exits. After the displayed expiry,
`expiry_elapsed` means the expected expiry has passed; the UI does not invent
a fresh ruleset inspection. A new OS-authorized release verifies absence.
An ambiguous helper failure is reported as an outcome needing review. No host
block is applied merely to demonstrate the feature.

Every requested action is recorded before execution in the private
`~/.local/share/megalodon/defense/receipts.db` ledger, followed by the observed,
applied or failed result. Its hash chain detects accidental changes against
a trusted head; it is not protection against an owner rewriting the ledger.
Unavailable or invalid audit storage stops actions. Model output is untrusted
advice and never becomes privilege or authorization.

## HTTP boundary

Both new GET endpoints require one `X-Megalodon-Check: 1`, the existing local
Host/sign-in checks and a non-root Linux HUD. GET performs no model request or
host change. POST `/api/defense` also requires exact same Origin, JSON media
type, one 32-character `X-Megalodon-Defense-Token`, a bounded 512-byte body and
a closed request shape. Duplicate keys/headers and caller-supplied commands are
refused. Status polling has no privileged firewall read or password prompt.

## Acceptance limits

Backend/unit and DOM fixture checks cover empty/error/stale states and action
boundaries. Real native nftables tests are run in a disposable network namespace,
including IPv4/IPv6 apply/release, packet drop/recovery, timed expiry and unrelated
table preservation. These tests do not establish complete attack prevention,
universal host compatibility or browser visual acceptance. Browser access was
administratively blocked during this iteration; source and inert fixtures were
used for design evaluation.
