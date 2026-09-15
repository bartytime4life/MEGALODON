# Local posture receipt

The posture command reports one bounded package-level receipt. It combines a
selected static capability profile with the installed reference bundle's
verified, unavailable, or integrity-failure state.

Run it from an installed MEGALODON package:

    python -m megalodon posture
    python -m megalodon posture --platform windows

The platform option selects only a documented static profile. It does not probe
the host, detect installed tools, test permissions, inspect SQLite, read
configuration, start a listener, capture traffic, or change a firewall.

The receipt is not host-health, deployment, compatibility, or operational
readiness evidence. It has no network, persistence, action, or host-change
path. A verified reference bundle is registration context only; it is not an
observed-service or safety verdict.
