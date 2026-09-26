# Check core configuration before startup

The setup guide now has an executable configuration check:

```sh
python -m megalodon.config_check < config/settings.toml
```

Run it in the installed MEGALODON Python environment, substituting your actual
settings filename. Shell redirection selects the file; the checker reads stdin
and never opens the configured database, device, log path or provider endpoint.
It does not modify the file or start any service. No companion installation or
subscription is required.

To check built-in defaults without reading a file:

```sh
python -m megalodon.config_check --defaults
```

Exit **0** means configuration validation passed. Exit **1** means invalid or
unavailable input. CLI usage errors return **2**. A valid configuration is not a
running-health, permissions, database-readiness or sensor-coverage receipt.
`runtime_verified` remains false. Readiness and operational acceptance remain
separate; no valid result starts capture, AI, installation or firewall work.

## What it checks

The input is UTF-8 TOML, at most 64 KiB. Empty input, malformed TOML and duplicate
keys are refused. The checker requires known tables and setting names, so a typo
such as `dashboard.refresh_second` cannot silently pass as the default refresh
interval. Typed values, ranges and interdependent thresholds use the existing
runtime configuration validator. The dashboard binding must match the server's
existing numeric IPv4 loopback/localhost policy. Scapy configuration must name an
interface, but no device is queried and capture permissions are not checked.

The closed JSON receipt contains fixed diagnostic categories and per-check
`passed`, `failed` or `not_checked` states. Validation stops at the first failed
stage. A valid receipt includes only capture source, dashboard enabled state,
refresh interval, event limit, AI enabled state and the fixed fact that firewall
application is unsupported. Names, addresses, paths, interface names, model
identifiers, digests, raw configuration and parser exception text are omitted.

| Code | What to inspect locally |
| --- | --- |
| `input_empty_or_too_large`, `input_not_utf8` | File contents, encoding and 64 KiB limit |
| `input_unavailable` | Shell input/read failure |
| `invalid_toml` | Syntax, duplicate keys or excessively nested values |
| `unknown_table`, `unknown_setting`, `table_required` | Names and structure against `config/settings.toml` |
| `invalid_setting_value` | Types, supported values, numeric bounds and related thresholds |
| `unsupported_dashboard_binding` | Literal IPv4 loopback or `localhost`; no DNS lookup or IPv6 listener |
| `capture_interface_required` | Explicit interface name when source is Scapy |

`python -m megalodon.tool_setup core configure` prints this check as the next
setup step. Other companion configuration commands still provide guidance;
this change does not claim to validate vendor configuration formats.

The preflight is deliberately stricter about unknown fields than the historical
runtime loader, which retains its compatibility behavior. Both use the same
underlying typed-value checks. An explicit `--defaults` checks defaults and
ignores stdin; it does not validate a selected file.
