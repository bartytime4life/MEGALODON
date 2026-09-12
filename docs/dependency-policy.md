# CI dependency and action policy

Status: implemented for the required pull-request validation inputs; the
compatibility lane is non-required discovery work. This document does not change
the runtime dependency boundary, add a vendor account, or authorize network
telemetry.

## Deterministic pull-request lane

The .github/workflows/ci.yml and the Linux browser-acceptance workflow use
constraints/ci.txt for their Python test/build resolver. The integrated policy
is present on current `main@fb2563ba97ee05526c60c45cadbd68f790a5236c` after the
isolated-build correction in PR #108 and the subsequent capture merge in PR #106.
The constraint entries retain their original provenance from green workflow run
`34663054911` on `main@a0d8b535d6958435abcb575e855784ce784e557e`; the resolver
propagation was revalidated in full PR run `34669482416` on the tested tree.
The file is intentionally a constraints file rather than a full lockfile:
runner images, Python, pip, platform wheels, package indexes, and hash-verified
artifact selection remain separate evidence.

The constraints file is packaged into source distributions so the extracted-sdist
test exercises the same policy file. The core package still has no third-party
runtime dependency, and developer installs remain explicit choices.

## Isolated build constraint boundary

A command-line `-c constraints/ci.txt` applies to its pip installation, not
necessarily to an isolated backend resolver. Historical PR #105 packaging run
`34665291138`, job `103475830445`, installed setuptools 80.9.0 in the outer
environment but resolved setuptools 84.0.0 inside the sdist/wheel build
environments. That was a build-input drift defect, not a runtime dependency or
application defect. The historical passing tests do not prove constrained builds.

Both deterministic workflows now set two workflow-scoped environment variables
to the absolute `${{ github.workspace }}/constraints/ci.txt` path:

- `PIP_CONSTRAINT` constrains ordinary installs, including the pip install
  subprocesses that `python -m build` uses to populate its temporary environment.
- `PIP_BUILD_CONSTRAINT` separately constrains pip's isolated backend dependency
  installs, including editable-install preparation. pip 25.3 introduced build
  constraints; pip 26.2 stopped propagating ordinary constraints into its own
  isolated build environments. Setting just the ordinary variable is insufficient.

The same file covers the existing listed pins; no dependency version or product
build-system range is changed by this wiring correction. Absolute paths avoid
silently losing the policy when a build or installed-package check changes its
working directory. Each job prints pip's version and requires its install help
to expose `--build-constraint` before package installation. An older pip fails
that setup step; there is no automatic pip upgrade or unconstrained fallback.
Build isolation remains enabled for editable installation and the primary
sdist/wheel build. The pre-existing offline installation of the resulting sdist
continues to use its already provisioned environment.

The workflow regression checks protect both variables, workflow scope, absolute
paths, absence of narrower overrides, and all three jobs' prerequisite checks.
Their mutation controls detect missing/relative/mis-scoped policy and an omitted
pip prerequisite. These are static configuration tests, not resolver execution.
The exact-head hosted build log must also show the expected setuptools pin in
both isolated build environments, followed by the full test/package/browser
receipts. Do not accept an outer-environment version alone as that proof.

This is not a complete lock, an offline build, or a reproducibility attestation.
Unlisted dependencies, indexes, build bootstrap tools, runner/OS/browser images,
Python/pip versions and package hashes remain separate work. A new or dynamic
build requirement needs review and appropriate constraints rather than an
assumption that this file already covers it. The scheduled compatibility workflow
is intentionally outside this environment policy and remains unchanged.

Primary references: [pip build constraints](https://pip.pypa.io/en/stable/user_guide/#build-constraints),
[pip build-system interface](https://pip.pypa.io/en/stable/reference/build-system/),
and [build environment variables](https://build.pypa.io/en/latest/reference/environment-variables.html).

## Hash-verified Linux build-tool profile

`constraints/build-linux-cp312.txt` is a **requirements lock**, consumed with
`-r`, not a second constraints file. Its scope is the `wheel-smoke` build tools
on Linux x86_64 / CPython 3.12: `build`, `packaging`, `pyproject-hooks`, and
`setuptools`, including the frontend's dependency closure for that profile.
Their versions match `constraints/ci.txt`; the lock does not upgrade them.
Each entry admits one exact PyPI wheel using SHA-256, with its filename and
source page recorded beside the pin. Source archives are not admitted.

The job refuses other platform/interpreter profiles before installation. It
then downloads into a new temporary wheelhouse with `--require-hashes`,
`--only-binary=:all:`, and dependency resolution enabled. An omitted dependency,
missing hash, or mismatched artifact fails the step. It prints the lock and wheel
digests, then installs all four using the same hash policy, `--no-index`, and
`--force-reinstall`; an already installed tool cannot satisfy that verification
without its wheel being checked again. The source distribution includes the
exact lock bytes and the packaging job compares them with the checkout.

The primary sdist/wheel build retains isolation. For that command only,
`PIP_NO_INDEX=1`, `PIP_FIND_LINKS` naming the verified wheelhouse, and
`PIP_ONLY_BINARY=:all:` constrain its pip dependency installs to the staged
wheels. Existing ordinary/build constraints remain in force. A new backend
requirement absent from the wheelhouse fails rather than falling back to an
index. The already provisioned source-distribution install keeps its existing
`--no-index --no-deps --no-build-isolation` behavior. No package archive, new
installer, or third-party source is committed or published.

This separates acquisition from the index-free resolver/build phase; it is
**not OS-level network containment**, a complete CI lock, a signed provenance
attestation, or a byte-reproducible build claim. pip/Python bootstrap, the outer
test dependencies, the runner and operating system, editable installs in the
other jobs, and browser-only dependencies remain outside this four-wheel lock.
The trusted CI workspace must preserve the verified wheelhouse; this is not a
defense against a malicious runner replacing files after verification. PyPI's
published digest is an artifact identity input, not independent publisher
signature verification or a security verdict about the package contents.

`tests/test_build_input_lock.py` checks lock shape, uniqueness, version parity,
manifest inclusion, and the reviewed workflow sequence. Mutation controls must
reject omitted checks and policy weakening. Separate offline tests give real pip
small metadata-only synthetic wheels: the valid hashed wheel must download,
while corrupted bytes, a missing hash, and an unhashed transitive dependency
must fail. These tests use `--no-index`, local fixtures, no package installation,
and no sensor or product telemetry. They do not prove the real PyPI artifacts;
that requires the exact-head hosted hash-checked acquisition/build log.

For a maintenance update, verify the exact wheel on its recorded PyPI source
page, review the package/version and dependency changes, update both pin files
where necessary, and rerun the synthetic refusals plus full CI, package smoke,
and browser acceptance. Do not replace a hash merely to clear a mismatch or
regenerate it from an unreviewed local archive. Expand to another interpreter
or dependency family only in a separate reviewed profile.

Primary basis: [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
and the four exact-version PyPI pages recorded in the lock. The ordinary
constraints' historical provenance above is retained, not rewritten as a
complete artifact-lock or release receipt.

## Compatibility drift lane

.github/workflows/compatibility-drift.yml runs weekly and by manual dispatch.
It deliberately resolves the declared ranges without constraints/ci.txt,
compiles and tests the repository, and builds temporary distributions without
uploading or publishing them. It is not a required check and does not change
the ruleset. A drift failure is a maintenance signal, not permission to weaken a
required check or update constraints automatically.

Action references in every workflow remain full commit SHAs, checkout credentials
are disabled, and workflow permissions stay read-only. Updating an action,
constraint, Python version, or runner requires a separate reviewed change with
the exact observed run and any new compatibility or security evidence recorded.

## Boundaries

These workflows run package-installation/build/test activity in GitHub Actions.
That setup-time network access is separate from normal MEGALODON operation, which
remains local-first, loopback-only, observe-only by default, and free of required
runtime egress. No dependency or action update enables live capture, firewall
application, alert delivery, remote dashboard access, telemetry upload, or model
authority.
