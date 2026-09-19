# Local tool readiness receipt

`python -m megalodon readiness` prints a bounded JSON receipt describing whether
one fixed executable name for each companion tool can be found on the current
Linux process's `PATH`. It never runs those executables. The separate
`capabilities` command remains a static support catalog and performs no host
probe.

From the MEGALODON checkout, using its existing Python environment:

```bash
.venv/bin/python -m megalodon readiness
```

To save an operator-selected snapshot for manual local viewing or a compatible
browser's local import:

```bash
.venv/bin/python -m megalodon readiness > megalodon-readiness.json
```

The command only writes stdout; shell redirection creates or replaces the named
file. The receipt contains no executable paths, hostnames, usernames, version
strings, network metadata or model artifacts. It is an unauthenticated
self-report, can be edited, and may immediately become stale. It grants no
authority to execute, install or enable anything.

## What the statuses mean

| Status | Exact meaning |
| --- | --- |
| `executable_found` | At least one fixed-name candidate in an accepted absolute PATH directory is a regular file and passes the current effective user's executable-access check. Symlinks may resolve to such a file. |
| `not_found` | The fixed executable was not discoverable in the accepted PATH directories at the time of the check. This does not prove the product is absent elsewhere. |
| `not_checked` | The tool has no executable-only probe, the platform is not Linux, PATH fails validation, or a filesystem error prevents establishing absence. |

None of these statuses establish installation integrity, provenance, a supported
version, compatibility, a running process, an active integration, a trusted
binary, or operational acceptance. A substituted executable can satisfy the
presence check. No executable contents, digests, output or version commands are
read. In particular, finding `tshark` does not satisfy the separate adapter's
fixed `/usr/bin/tshark` path or installed-tool acceptance gate, and finding
`ollama` says nothing about a Qwen model or provider availability.

| Capability ID | Fixed executable name |
| --- | --- |
| `python-sqlite` | Not checked; an active interpreter is not proof of SQLite support |
| `wireshark-tshark` | `tshark` |
| `zeek` | `zeek` |
| `suricata` | `suricata` |
| `scapy` | Not checked; package imports are intentionally omitted |
| `nftables` | `nft` |
| `clamav` | `clamscan` |
| `osquery` | `osqueryi` |
| `qwen-ollama` | `ollama` |
| `nmap` | `nmap` |
| `ossec` | `ossec-control` |
| `greenbone` | `gvmd` |
| `zabbix` | `zabbix_agentd` |
| `nagios-core` | `nagios4` (Ubuntu package executable) |

For tools with multiple separately installed components, this checks only the
named representative; it does not infer the other components' state. Neither
Python package discovery nor imports of Scapy, Ollama or other companion packages
are attempted.

## Closed receipt and bounds

The closed object contains exactly `schema`, `checked_at`, `platform`,
`probe_mode`, `tools` and `boundaries`. `schema` is
`megalodon-tool-readiness-v1`; `probe_mode` is `path_presence_only`;
`checked_at` is the process clock's UTC `YYYY-MM-DDTHH:MM:SSZ` time; and
`platform` is `linux`, `windows` or `other`. The clock is not independently
authenticated. `tools` contains exactly the 14 capability IDs above, in that
order, each with only `id` and `status`. `boundaries` contains the five fixed
strings in `megalodon.readiness.BOUNDARIES`. The serialized report including its
stdout newline is at most 8,192 UTF-8 bytes.

Before any filesystem lookup, the complete PATH must satisfy all limits:

- At most 16,384 UTF-8 bytes and 64 colon-separated entries.
- Every directory is absolute and at most 4,096 UTF-8 bytes.
- No empty or relative entries, leading double slash, `.` or `..` components,
  ASCII control characters, DEL, or invalid UTF-8 text.

Any failed PATH condition makes all executable probes `not_checked`; the
command never falls back to a default PATH or the current directory. Duplicate
directories are removed. At most 768 candidate `stat` calls and 768 executable
access checks occur. Directories are never enumerated. Errors and paths do not
appear in the output. No arbitrary executable, PATH or platform override is
accepted by the CLI.

These are input and operation-count bounds, not a wall-clock deadline: the
operating system, symlink targets and mounted filesystems can delay metadata
lookups. No application socket is opened, but underlying mounted filesystems
retain their own behavior. The receipt performs no subprocess, package import,
model request, service management, capture, configuration change, database
operation or firewall action. A compatible browser should parse it locally in
memory, reject oversized or non-closed input, label it as a user-supplied
snapshot, and never treat an imported status as permission to control a host.

## Validation scope

`tests/test_readiness.py` checks exact input and operation bounds, closed output,
catalog alignment, rejection before probes, unsupported-platform behavior,
redaction, error currentness, representative file/symlink handling and prohibited
process/network/store/configuration paths. These tests do not validate actual
installed companion-tool versions or satisfy those tools' acceptance gates.
