# License decision — 2026-09-20

This is the owner decision record required by
[issue #255](https://github.com/bartytime4life/MEGALODON/issues/255). It selects
repository terms and aligns source/package metadata. It does not publish a tag,
package, release, deployment, or host installation.

## Decision

| Field | Value |
| --- | --- |
| Owner | `bartytime4life` |
| Decision date | 2026-09-20 |
| Selection | Apache License, Version 2.0 (`Apache-2.0`) |
| Alternatives considered | MIT; another counsel-approved license; remain all-rights-reserved |
| Review trigger | Before changing the project license; before bundling a new third-party dependency or asset; or before a redistribution plan whose license obligations have not been reviewed |

Apache-2.0 was selected because it supplies explicit copyright and patent
license terms plus redistribution conditions suitable for an open-source,
security-adjacent project. MIT was simpler, but it did not include the same
explicit patent grant and termination language. Remaining all-rights-reserved
would conflict with the owner's open-source direction. This is a project
decision, not legal advice.

## Repository changes

- `LICENSE` contains the Apache License, Version 2.0 text.
- `pyproject.toml` declares the SPDX expression and `LICENSE` as a license file.
  Its build requirement is raised to `setuptools>=77`, the first Setuptools
  series with PEP 639 license-expression and license-file support.
- `MANIFEST.in` explicitly includes `LICENSE` in the source distribution.
- `README.md` and `CONTRIBUTING.md` expose the project license and preserve the
  separate-license rule for third-party material.
- `tests/test_license_metadata.py` binds these surfaces and verifies built
  wheel/sdist metadata when distribution paths are supplied by CI.
- `contracts/build-inputs/v1/inventory.json` is regenerated because the
  declared build-system requirement changes.

## Bounded third-party review

The current core runtime dependency list is empty. The `capture` extra declares
`scapy>=2.5,<3`; `megalodon/capture.py` imports Scapy inside `iter_scapy()` only
after that optional path is selected. Scapy is not copied into MEGALODON's wheel
and remains under its own license. This record does not make a legal
compatibility determination for a redistributor's chosen Scapy version or
distribution arrangement.

The bundled IANA registry snapshot is separately recorded as `CC0-1.0` in
`docs/reference-data.md`. The detector corpus is repository-authored synthetic
fixture data. Test and build tools are not MEGALODON runtime dependencies;
repository test source is intentionally present in the source distribution.

This is a source-tree review, not a release SBOM or counsel opinion. A release
candidate still requires exact-artifact license-file checks, a dependency and
asset inventory, required-notice review, and the separate evidence gates tracked
by issue #260.

## Acceptance boundary

A green pull request proves only that the candidate source and package metadata
agree under the exercised build. Issue #255 may close only after an authorized
merge and immutable post-merge readback. Release publication, deployment, and
host authority remain separate decisions.
