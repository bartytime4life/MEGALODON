# Source build-input inventory

contracts/build-inputs/v1/inventory.json is a deterministic inventory of the
committed source inputs used by MEGALODON's reviewed Linux CI lock profiles. It
is generated and verified by a Python-standard-library-only tool:

    python tools/build_input_inventory.py --check

The normal check performs no network access, package resolution, package
installation, or subprocess execution. To inspect a freshly rendered candidate
without changing the committed artifact:

    python tools/build_input_inventory.py --output /tmp/megalodon-build-input-inventory.json

After reviewing an intentional source-input change, regenerate the committed
artifact explicitly, inspect the resulting diff, and run the focused tests and
the exact-head CI:

    python tools/build_input_inventory.py --output contracts/build-inputs/v1/inventory.json

## Bounded scope

The inventory covers only:

- project build-system, declared runtime, and declared optional dependencies
  from pyproject.toml;
- the committed source bytes and direct hash-pinned entries of the reviewed
  build-linux-cp312, test-linux-cp311, test-linux-cp312, and
  browser-linux-cp311 profiles; and
- the browser profile's one reviewed, relative source include.

Its parser intentionally rejects URLs, arbitrary requirement operators,
markers, extras, alternate hashes, duplicate packages, unreviewed includes, and
new package names. Extending those inputs requires a separate, explicit review
of both the CI profile and this contract.

## What it does not prove

This is source metadata, not a release or acquisition receipt. It is not an
artifact SBOM, a signed provenance statement, publisher-signature verification,
or a reproducible-build attestation. It does not identify downloaded wheel
bytes or source archives, package indexes, Python/pip bootstrap tools, runner
images, operating systems, browser binaries, or inputs outside the declared
source profiles. Those remain separate exact-head CI and release-governance
evidence.
