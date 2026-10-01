# Retired hosted console

The **local Linux HUD is the sole supported application**. Double-click
[`Start-MEGALODON.sh`](../Start-MEGALODON.sh) to install or open it directly.
There is no hosted replacement page or redirect.

The retirement worker in `retired/worker.mjs` returns HTTP 410. Hosting identity
metadata is retained to identify the retired deployment; it is not a live-data
connection. See the dated [retirement receipt](../docs/site-source-alignment.md).

The former static UI and its Site-only tests are recoverable from Git commit
`4b5f8f8`. Shared control and input-validation tests now exercise the canonical
Python package. No runtime or build step reads a hosted asset mirror.
