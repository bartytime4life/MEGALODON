# HawkScan setup for MEGALODON

Status: **offline preparation implemented; active scanning HELD**. This is an
optional commercial application-security companion, outside the existing
free/open-source tool catalog and its ten-tool readiness exports. It does not
replace TShark, Zeek, Suricata, ClamAV, CodeQL or MEGALODON detections.

HawkScan performs dynamic application security testing (DAST) by sending attack
requests to a running web application. StackHawk warns that scanning can create,
update and delete application data. Its normal workflow needs a StackHawk
account, application ID and API key and sends results to the StackHawk platform.
Treat requests, responses, logs and findings as potentially sensitive. A local
target does not make the scanner offline.

## 1. Review the plan without changing your computer

From a reviewed MEGALODON checkout, use its existing Python >=3.11 environment:

```bash
python -m megalodon.hawkscan_setup
python -m megalodon.hawkscan_setup check
```

The first command prints the setup plan. The second checks filesystem metadata
for the fixed executable name `hawk` in bounded, validated Linux PATH entries.
It never executes the binary, reads its contents or contacts StackHawk.
`executable_found` means found, not trusted, healthy, configured or accepted.
`not_found` covers only checked locations; inaccessible/invalid PATH input gives
`not_checked`. Metadata calls can still stall on a filesystem. Neither command
reads credentials, writes a file, opens SQLite or starts a service/scan.

The local HUD exposes these instructions in **Setup → HawkScan application
scanner**. No scan/install button, model tool or background worker is added.

## 2. Prepare the Linux installation separately

OBSERVED 2026-10-14: the publisher documents HawkScan **6.5.0** and native Linux
`x64`/`aarch64` binaries. Version 6 bundles Java; no additional JDK is needed.
Use the [official downloads page](https://docs.stackhawk.com/downloads/hawkscan/)
to select the exact stable version/architecture and its publisher SHA-256.
Do not substitute `latest`, a development release, or an unverified digest.
The digest values were not available in the text readback used for this change;
this repository does not invent a hash or claim artifact verification.

After an explicit installation decision, download in a separate private lab
account/VM, compare `sha256sum` with that exact publisher value, and place the
verified binary in that user's private executable directory. Never execute a
download to verify its provenance. Keep the original version, architecture,
source URL and expected/observed SHA-256 in the operator record. This setup
module performs no download, chmod, package installation, sudo or Docker work.

`hawk version` is a **manual third-party execution**, not the metadata check
above. The publisher says first execution extracts a runtime into `~/.hawk/bin`;
HawkScan also writes configuration/logs/session state beneath `~/.hawk`.
Use the disposable account, never the account holding live MEGALODON data.
Docker host networking or mounting your repository/home is not a containment
substitute. This slice does not introduce a Docker recipe.

## 3. Select a safe application and approve data sharing

Before any authentication or scan, record all of these owner decisions:

- The exact owned disposable application/revision, numeric loopback port,
  synthetic dataset, permitted routes and reset/recovery method.
- Isolation from the working PC HUD, real databases, captures, reports,
  telemetry, model provider, sensors and host-management capabilities. Start
  from synthetic data, not a copy of sensitive production records.
- The StackHawk organization/application and credential owner; approved data
  categories, recipients, retention and deletion policy; allowed outbound
  destinations and independent enforcement in the lab.
- One explicit manual scan window, request budget, stop condition, and
  post-scan reset/readback. Permission to prepare configuration is not this
  authorization.

The active local HUD has protected write/control routes. Do not scan it with
its operator tokens. The owner-private hosted PC Snapshot Console is a separate
browser-only viewer, **not an approved scan target or scanner control plane**.
Do not weaken either interface's auth, CSRF or loopback controls to make a scan
work. Scanner YAML is scope guidance, not proof of process/redirect/egress
containment. Log/header redaction is not a reviewed no-sensitive-data policy.

## 4. Generate the initial configuration offline

Replace the example UUID with the application ID from the approved StackHawk
application. This UUID is synthetic, not an account or authorization. From the
reviewed checkout:

```bash
python -m megalodon.hawkscan_setup config \
  --application-id 11111111-2222-4333-8444-555555555555 \
  --port 18080
```

The command prints YAML only; no scanner is run and no file is created. Save
the reviewed output as `stackhawk.yml` in the separate private lab directory
only after selecting the actual application. There is no root `stackhawk.yml`
in the repository for CI or a third-party tool to discover accidentally.

The generator accepts only a nonzero canonical-form UUID and an integer port
1024–65535. The host is always literal `http://127.0.0.1:<port>`; it accepts no
hostname, remote URL, proxy, credential, script, custom command or imported
configuration. This is a **root-only wiring profile**, with API routes excluded,
basic spider limited to one minute, five-minute active phase, one-minute rule
limit, one concurrent request and a 250-ms request delay. These are documented
scanner settings, not a tested whole-process wall-clock guarantee. Expiry and
containment require independent lab enforcement.

Only `/` is included. There is no authenticated, API, complete-HUD or live
network coverage claim. Broader coverage needs a separately reviewed target
fixture and route/authentication contract. No OpenAPI, HAR, AJAX browser,
MCP, custom discovery, external authentication command or scripts are enabled.

## 5. Manual scan gate and review

After the decisions in step 3 and binary/config review, follow the publisher's
[authentication and scan guide](https://docs.stackhawk.com/getting-started/install-and-run/)
inside the approved lab. Its `hawk init` and `hawk scan` commands are networked
third-party operations. They are intentionally not executed or wrapped by
MEGALODON. Keep API keys out of command arguments, repository files, HUD tokens,
screenshots, PRs, Drive documents, Sites and AI prompts. The setup command
accepts no key and never inspects `HAWK_API_KEY` or `~/.hawk`.

Review findings as candidates, reproduce relevant issues against synthetic
fixtures, and fix them through normal exact-head PR review. Raw request/response
evidence and scanner logs must not enter MEGALODON's metadata ledger, Qwen or
the hosted snapshot schema. Result ingestion, aggregate projections, automated
CI scans and schedules require separate contracts and approval; none exists in
this slice. Keep the required repository test gate unchanged.

For removal, select the exact lab binary/state you installed using the recorded
inventory. Do not recursively delete a shared `~/.hawk` or change routes, DNS,
firewalls or other services. Removing this optional companion must not affect
MEGALODON's existing telemetry workflows.

## Verification and next gate

Repository tests cover output bounds, UUID/port injection refusals, fixed target
and scope, metadata-only discovery, no process/socket/SQLite operations, and no
credential reads. They use synthetic data; no HawkScan binary, cloud account,
vendor YAML validator, scan, upload or operational acceptance was exercised.
The safest next gate is owner selection of the disposable target and reviewed
StackHawk data-sharing policy, followed by exact-artifact verification.

Primary sources checked on 2026-10-14:

- [HawkScan overview and active-scan warning](https://docs.stackhawk.com/hawkscan/)
- [Configuration, route scopes, timing/concurrency and redaction](https://docs.stackhawk.com/hawkscan/configuration/)
- [CLI installation, first-run state and commands](https://docs.stackhawk.com/stackhawk-cli/)
- [Downloads and publisher hash guidance](https://docs.stackhawk.com/downloads/hawkscan/)
