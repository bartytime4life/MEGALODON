# Ubuntu 24.04 evidence contract v1

This contract defines a bounded, non-publishing evidence packet for an exact
MEGALODON source checkout on Ubuntu 24.04. It advances issue
[#260](https://github.com/bartytime4life/MEGALODON/issues/260) without declaring
a release candidate accepted or authorizing a tag, release, package upload,
deployment, service installation, sensor, model, firewall change, or restored
database activation.

The accepted fixture is synthetic contract evidence, not a host receipt. A
real packet must compare an externally supplied expected commit and the tree
bound by that commit with one clean checkout, record exact platform/tool
identities, preserve bounded command outcomes, and keep unavailable work
explicit. Optional analyzers and Qwen are
not required for core operation and can never be reported healthy merely
because an executable was found or a component was absent.

The closed check set is:

1. Python compilation;
2. repository tests;
3. non-mutating CLI smoke;
4. read-only loopback browser acceptance;
5. bounded sample/JSONL processing;
6. backup and restore-to-new-destination;
7. native failure paths;
8. ephemeral wheel install smoke; and
9. ephemeral source-distribution install smoke.

`candidate_evidence` is rejected for a synthetic fixture and accepted by the
semantic validator only when an observed basis has all nine checks passed and
both ephemeral subjects were built. Even then, license,
operator-recovery, SBOM, provenance, independent/owner acceptance, and release
authority remain separate gates. New identity packets report the license gate
as `not_assessed` with a null blocker: the collector does not inspect license
or artifact metadata. The repository Apache-2.0 decision merged in #298 and
#255 is closed. The schema also accepts the original `blocked` / #255 pair
solely to preserve historical receipts and the byte-identical synthetic fixture;
that pair is not a current repository claim. Neither shape permits a `passed`
license gate. Remaining gates stay `not_run` or `not_authorized`.

`tools/ubuntu_release_evidence.py collect` reads only bounded local platform
facts and fixed Git/systemd commands. It creates an incomplete skeleton: it
does not run tests, build artifacts, inspect optional executables, use a network
fallback, or write a file. `validate` accepts one packet, rejects duplicate
keys and oversized/nested input, enforces the exact ordered identities and
source equality, then emits canonical JSON plus a SHA-256. Errors use one closed
reason and never echo input or local paths. Validation remains structural and
self-asserted: the configured-origin check prevents an accidental unrelated
checkout, but it is not attestation; packet SHA-256 binds canonical bytes, not
their provenance or truth. Independent evidence must retain and recompute the
underlying logs and artifact subjects.

`verify-packet` accepts the complete emitted wrapper, recomputes its manifest
digest, and compares its validated source identity with required external
commit/tree pins. It performs no host command or network operation and does
not authenticate self-asserted observations. The PR identity job retains its
verified incomplete JSON as one 30-day Actions artifact; this is CI evidence
retention, not a package upload or release. See
[the retention and offline verification guide](../../../docs/ubuntu-release-evidence.md#retain-and-verify-the-identity-packet).

This is not a CycloneDX SBOM, SLSA provenance statement, signature, reproducible
build claim, redistribution decision, operator recovery drill, release, or
deployment receipt.
