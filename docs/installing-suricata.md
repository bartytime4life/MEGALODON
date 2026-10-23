# Installing Suricata: offline configuration

Use this guide for **MEGALODON Stage 0 saved-capture analysis**, not the separate
live/background sensor workflow. Preparing files does not install Suricata,
start it, qualify a producer, or grant permission to execute it.

## 1. Obtain and review the software separately

Use [OISF's official downloads](https://suricata.io/download/) and review the
package source, signature/checksum, dependencies, license and service behavior
for your operating system. Package installers can start a service. Do not use
the HUD's package-install or background-start controls for a strict no-egress,
no-service Stage 0 session. Obtain approved artifacts outside that session.

The completed raw-EVE converter currently pins **Suricata 8.0.7**. This is a
compatibility target, not a statement that it is the latest or security-qualified
release. A different version needs separate qualification. Record the actual
binary hash and provenance; this script does not discover or execute a binary.

## 2. Get the configuration script

**[Open/download configure-suricata-offline.py](../scripts/configure-suricata-offline.py)**
from the same reviewed repository revision as this guide. The script is
self-contained, uses Python 3.11+ standard library only, and targets Linux.
Run it as your ordinary user, **without sudo**. Review the downloaded source;
do not pipe a remote download into a shell or interpreter.

From the root of your reviewed checkout, preview:

```bash
python3 scripts/configure-suricata-offline.py \
  --output "$HOME/megalodon-suricata-offline" \
  --home-net 192.0.2.0/24
```

`192.0.2.0/24` is a documentation-only network, suitable for the synthetic
fixtures. Replace it with the exact network CIDR represented in your approved
saved capture when appropriate (for example `192.168.1.0/24`). IPv6 CIDRs are
also accepted. Host addresses with nonzero host bits, lists and YAML fragments
are rejected. `EXTERNAL_NET` deliberately remains `any`; choose rules accordingly.

Preview writes nothing and prints the planned receipt. It does not check whether
the destination is writable or absent. When the preview is correct, create files:

```bash
python3 scripts/configure-suricata-offline.py \
  --output "$HOME/megalodon-suricata-offline" \
  --home-net 192.0.2.0/24 \
  --write
```

The output parent must already exist, belong to you, and not be group/other
writable. Symlink path components and existing destinations are refused. A
second invocation never overwrites the first bundle: choose a new directory.

| Created file | Purpose |
| --- | --- |
| `suricata.yaml` | Single-runmode profile; regular-file, alert-only EVE output; payload, packet, application metadata, tagged packets, stats and command socket disabled |
| `rules/local.rules` | Empty placeholder by default: **no detection coverage** |
| `configuration-receipt.json` | Exact file hashes/sizes, normalized HOME_NET, deterministic receipt ID and explicit `prepared_not_validated` status |

Directories are owner-only `0700`; files are `0600`. On a disk/write error, a
partial **new** bundle may remain. It is not accepted output; inspect it and
use a different new destination. The script never cleans up existing data.

## 3. Supply reviewed rules when ready

To prepare a bundle with rules instead of the empty placeholder, provide both
an absolute local file path and its independently recorded lowercase SHA-256:

```bash
python3 scripts/configure-suricata-offline.py \
  --output "$HOME/megalodon-suricata-with-rules" \
  --home-net 192.0.2.0/24 \
  --rules /absolute/path/to/reviewed.rules \
  --rules-sha256 REPLACE_WITH_64_LOWERCASE_HEX_DIGITS \
  --write
```

The placeholder digest above intentionally fails until replaced. Rules are
read as a regular UTF-8 file, bounded to 1 MiB, copied byte-for-byte, and checked
against the supplied digest. The script does **not** parse, approve or test
them. A matching hash proves byte identity, not trust, rule safety or coverage.
Review rule licensing and any dependencies, Lua/file-writing features or costly
patterns before native validation. No rules are fetched or updated automatically.
Changing generated files invalidates the receipt; generate a fresh bundle with
the newly reviewed inputs instead of treating an old receipt as current.

## 4. Stop at prepared files until execution is authorized

The generated YAML uses paths relative to the bundle working directory:
`rules/local.rules` and `megalodon-alerts.json`. A separately reviewed native
runner must use that directory and an exact binary/configuration/rules identity.
This guide intentionally supplies no service-start, live-interface or PCAP-run
command. Existing `/etc/suricata`, installed services, permissions and firewall
rules are not modified. The script makes no network connection or model call.

Before any future native run, separately authorize configuration/rule validation
and saved-PCAP replay on an already isolated, non-root, capability-free host.
Bind the PCAP and binary hashes, one packet-processing thread, resource limits,
private output, completion and output hash to an execution receipt. The YAML
memory caps are **not** whole-process CPU/memory/time/disk enforcement and do
not establish no-egress containment. This preparation script enforces no native
run limits because it starts no engine. A settings file cannot prevent someone
from separately launching a capture or overriding flags.

Only a completed private alert file with the required identity can enter the
[pinned producer profile](../contracts/suricata-eve/v1/producer/README.md).
Alert tuples remain sensitive metadata even with payload logging disabled;
keep them local. No native Suricata validation or operational acceptance is
claimed by these generated files or the preparation receipt.

Configuration references checked October 23, 2026:
[OISF EVE JSON options, 8.0.7](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html)
and [Suricata YAML configuration, 8.0.7](https://docs.suricata.io/en/suricata-8.0.7/configuration/suricata-yaml.html).

For the separate operator-managed live sensor, see
[support configuration](support-configuration.md); do not conflate that workflow
with this offline preparation or with qualified alert admission.
