# Hosted snapshot viewer and local application

The **local Linux HUD remains the host application**. Double-click
[`Start-MEGALODON.sh`](../Start-MEGALODON.sh) to install or open it directly.

The existing owner-private [MEGALODON Site](https://megalodon-defense-console.blackbart-55.chatgpt.site)
is restored as a separate browser-only snapshot viewer at the owner's
request. It imports the address-free `megalodon-hud-snapshot-v1` summary from
the local HUD's Advanced exports. Import keeps the data in tab memory; Clear
or reload removes it. The Site starts empty, performs no local network requests,
and cannot start sensors, services, models or firewall actions.

The dated summary describes a bounded evidence window, not live PC activity
or proof that a network is safe. IP addresses, ports, packet payloads, raw
records, device names, account data and operator tokens are outside the import
schema. No telemetry is committed to Site source or deployment output.

The separate Site source repository owns the current static viewer under
`web/`, its tests under `tests-current/`, and generated `dist/` output.
See [the source alignment record](../docs/site-source-alignment.md) for recorded
publication identity and validation. The later October 22 documentation pass re-read Sites metadata: v67 and the
existing owner-private audience were observed. It did not render the viewer,
re-read its source or prove current source/deployment parity. The publication
record retains the existing project identity; this repository does not build
or deploy the separate viewer.

`retired/worker.mjs` preserves the historical empty HTTP 410 handler. It is not
the restored viewer's deployment entry point. The former static console and
its Site-only tests remain recoverable from Git commit `4b5f8f8`. Shared control
and input-validation tests exercise the canonical Python package. No local
runtime or build step reads a hosted asset mirror.
