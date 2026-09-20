# Ubuntu 24.04 release-evidence boundary

Issue [#260](https://github.com/bartytime4life/MEGALODON/issues/260)
requires an exact-platform evidence packet before MEGALODON can be evaluated as
a Linux release candidate. The v1 contract is deliberately narrower than a
release workflow: it makes missing evidence machine-readable and refuses every
publication or host-authority claim.

The contract and fixtures are under `contracts/release-evidence/v1`. The local
collector records an exact clean commit/tree plus Ubuntu, kernel, architecture,
CPython, pip, and systemd identity. It performs three fixed read-only commands:
Git commit identity, Git tree identity/status, and `systemd --version`. It does
not run the nine acceptance checks, inspect optional tools, build artifacts,
contact a network, or write an evidence file. Every omitted result stays
`not_run` or `not_checked`.

Validate the synthetic contract fixture:

```bash
python tools/ubuntu_release_evidence.py validate \
  contracts/release-evidence/v1/fixtures/accepted/synthetic-incomplete.json
```

Collect an incomplete local identity packet from a clean checkout:

```bash
python tools/ubuntu_release_evidence.py collect \
  --checkout . \
  --declared-commit "$(git rev-parse --verify HEAD)" \
  --declared-tree "$(git rev-parse --verify 'HEAD^{tree}')"
```

The command writes canonical JSON to standard output. Redirecting it is an
operator choice; the collector itself creates no file. A dirty checkout,
declared/observed Git mismatch, non-Ubuntu-24.04 platform, duplicate JSON key,
unexpected check/component/artifact identity, false optional-health claim,
oversized output, or any effect/authority claim fails closed with one bounded
reason.

## What remains before candidate evidence

- Run the exact nine checks on an authorized Ubuntu 24.04 host or runner and
  retain bounded, digest-bound outcomes.
- Build wheel and source distribution only as ephemeral subjects, bind their
  sizes and SHA-256 values, and install/test them in disposable environments.
- Retain the complete operator backup/restore/read-only-inspection drill.
- Produce and review the canonical CycloneDX SBOM and provenance subjects.
- Resolve the owner license decision in #255 and align package/repository
  metadata.
- Obtain the required owner/independent disposition for the exact candidate.

Even a structurally valid `candidate_evidence` packet is not a tag, GitHub
release, package publication, deployment, installation, supported-platform
promise, sensor/model operation, firewall authority, or operator acceptance.
