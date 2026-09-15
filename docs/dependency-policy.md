# CI dependency and action policy

Status: implemented for the required pull-request validation inputs; the
compatibility lane is non-required discovery work. This document does not change
the runtime dependency boundary, add a vendor account, or authorize network
telemetry.

## Deterministic pull-request lane

The .github/workflows/ci.yml and the Linux browser-acceptance workflow use
constraints/ci.txt for their Python test/build resolver. The integrated policy
was recorded at `main@fb2563ba97ee05526c60c45cadbd68f790a5236c` after the
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
Their versions match `constraints/ci.txt`; the lock admits the reviewed
setuptools 84.0.0 maintenance update.
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

## Hash-verified packaging-test profile

The `wheel-smoke` job also consumes `constraints/test-linux-cp312.txt` with
`-r`. This separate requirements lock covers `pytest`, `jsonschema`, and their
nine transitive requirements on **Linux glibc x86_64 / CPython 3.12**. Its eleven
versions match the revised resolver constraints, including the reviewed pytest
9.1.1 maintenance update.
Each entry records one exact wheel filename, PyPI source page, and SHA-256.
In particular, `rpds-py` admits the CPython 3.12 manylinux x86_64 wheel, not
Windows, macOS, musl, another architecture/interpreter, or a source archive.
A missing compatible wheel or dependency fails acquisition, not a source build.

After the existing platform/interpreter preflight, the job downloads the full
test closure into a separate fresh temporary wheelhouse with mandatory hashes,
wheel-only policy, no cache, and dependency resolution enabled. It requires
exactly eleven wheels, records their hashes and the lock digest, then installs
with `--require-hashes --no-index --force-reinstall` from that directory and runs
`pip check`. Already installed packages cannot bypass artifact verification.
The original four-wheel build-tool acquisition and isolated builds then run
unchanged. Both locks must agree on the shared `packaging` version **and hash**.
The extracted source distribution byte-matches both locks before running tests.

The existing lock tests now exercise both closed profiles, protect verification
before use and the independent wheelhouses, and reject test-only weakening even
when all build-tool controls remain intact. The offline real-pip fixtures also
include a fully hashed transitive dependency that succeeds, alongside the
unhashed dependency that fails. These metadata-only probes install nothing;
exact artifact closure still requires the hosted eleven-wheel acquisition log.

This extends the packaging job's input coverage, not the entire CI environment.
The Python 3.11 test and browser jobs have separate profiles below.
Compatibility discovery is intentionally unconstrained. Python/pip bootstrap,
preinstalled runner packages and plugins,
OS/browser binaries, publisher authenticity, signed provenance, and byte-for-byte
reproducibility remain separate. No project dependency, runtime integration,
sensor, service, or update scheduler is added. Acquisition uses network access;
index-free installation is not whole-process or OS-level network containment.

Maintain both profiles explicitly: verify the named wheel on the recorded source
page, review dependency and tag changes, retain hash-failure controls, and read
full hosted test/package/browser results before accepting a revised lock. Do not
relax hashes, use `--no-deps` for dependency acquisition, or add alternate
artifacts merely to make an unsupported profile pass. The primary hash-policy
basis is [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/);
the exact-version PyPI pages are provenance observations, not signature checks.

## Hash-verified Python 3.11 test profile

The required `test` job consumes `constraints/test-linux-cp311.txt` with `-r`.
This profile covers **Linux glibc x86_64 / CPython 3.11**: the eleven pytest and
jsonschema dependency wheels plus the existing setuptools editable-build backend.
All twelve versions match `constraints/ci.txt`, including the reviewed pytest
9.1.1 and setuptools 84.0.0 maintenance updates. Pure-Python wheel hashes agree
with the existing packaging profiles; `rpds-py` instead admits exactly its
CPython 3.11 manylinux x86_64 wheel. This is not a cross-platform lock; Python
3.12 packaging continues to use its own profile-specific locks.

The job checks the interpreter, OS, architecture, and libc before acquisition.
It creates a fresh `test-cp311-wheelhouse`, downloads the full requirements with
mandatory SHA-256 hashes, binary-only policy, no cache, and dependency resolution,
and requires twelve wheels. It prints the lock and artifact digests, then
force-reinstalls from that directory with hashes and index lookup disabled.
`pip check` follows. Existing installs cannot short-circuit wheel verification.
A failed acquisition may leave a staged prefix; the nonzero result stops the
job before installation or editable preparation.

Only after this verification does pip install the repository's local
`.[test]` editable target. That separate command retains build isolation,
ordinary/build constraints, and dependency resolution, but receives
`PIP_NO_INDEX=1`, an absolute `PIP_FIND_LINKS` pointing to the verified wheelhouse,
and `PIP_ONLY_BINARY=:all:`. A missing backend or newly required third-party
package fails rather than falling back to an index or source distribution.
Verbose output records the isolated backend's actual local wheel/version.
The local repository itself is the pinned Git input, not a downloaded wheel;
this editable command does not claim that pip hash mode supports editable inputs.

The packaging lane includes and byte-compares this lock in the sdist, but does
not install its CPython 3.11 wheels. Static regression tests protect the exact
profile, closure/version/hash parity, verification order, source packaging, and
index-free isolated editable boundary. Mutation controls distinguish broken
Python 3.11 wiring even when the older packaging controls remain present. The
existing real-pip offline hash refusal tests remain a separate control; hosted
logs must establish twelve actual wheel matches, isolated setuptools selection,
full pytest and safe CLI results, plus unchanged packaging/browser acceptance.

The browser profile below adds its driver dependencies. These locks do not pin
Python/pip bootstrap, ambient packages or pytest plugins, external Node,
runner/OS binaries, or publisher authenticity. This is not a
signed provenance/SBOM, hermetic-build, reproducibility, or network-containment
claim. The CI workspace is trusted to preserve verified artifacts until use.
Runtime dependencies, captures, firewall behavior, and operator-host setup are
unchanged. Maintenance must review wheel identity and dependency changes across
profiles; never broaden admitted hashes solely to silence a failed build.
The primary hash-policy reference remains
[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/).

## Hash-verified browser-test profile

`constraints/browser-linux-cp311.txt` composes the existing twelve-wheel
`test-linux-cp311.txt` requirements through one fixed relative `-r` include, plus
three exact browser wheels: Playwright 1.62.0, greenlet 3.5.5, and pyee 13.0.1.
The Playwright wheel is admitted with an accompanying exact-byte native-focus
driver-profile review; its hash and filename come from the exact PyPI page
recorded beside the pin.
Reusing the test profile keeps shared dependency identities in one place.

The browser job requires Linux glibc x86_64 / CPython 3.11. After its existing
pip prerequisite, it acquires all fifteen wheels into a fresh separate directory
with mandatory hashes, wheel-only policy, no cache, and dependency resolution.
It records both requirements-file digests and the wheel digests, then performs
hash-required force-reinstallation with index lookup disabled. The subsequent
local editable install retains build isolation and dependency resolution, using
only this verified wheelhouse for pip's backend requirements. A missing include,
new dependency, incompatible wheel, or bad hash fails before acceptance starts;
there is no source-build or index fallback. Both composition files are packaged
and byte-compared in the sdist; CPython 3.12 does not install the browser profile.

This lock verifies the distributed Playwright wheel before the version-pinned
`playwright-1.62.0-native-focus-v1` helper checks and copies its driver module.
It does not replace that helper's exact-byte checks or modify its one-setting
native-focus correction. The real application still must pass all browser
assertions. `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`, the prepared Chrome binary,
Openbox readiness, sandbox request, native visibility observations, failure
propagation, and test deadlines remain unchanged. No browser download is added.

Static tests protect composition, exact artifacts, source packaging, verification
order, and the isolated editable boundary. Offline real-pip fixtures separately
prove relative inclusion from another working directory and refusal of a missing
include, missing child hash, or altered included wheel. Those synthetic probes
install nothing and make no index request. Hosted execution must additionally
show fifteen real wheel matches, the staged editable backend, and complete
browser, ordinary test, and packaging receipts for the exact candidate.

This closes the declared Python wheel inputs for the three deterministic jobs,
not their whole execution environments. Python/pip bootstrap, ambient installed
packages/plugins, external Node, the OS and apt repositories, Chrome, Xvfb and
Openbox remain separate provenance/isolation work. The Playwright wheel digest
covers its bundled driver files, not independently authenticated upstream
components. Acquisition uses network; index-free pip use is not OS-level egress
containment. Hash identity is not a publisher signature or package-safety verdict.
Do not widen hashes or change the native-focus digests to clear a failure;
review an update across both composed profiles and the driver helper first.
Normal MEGALODON operation still requires no Playwright, provider account,
subscription, cloud service, or new runtime dependency.

## Compatibility drift lane

.github/workflows/compatibility-drift.yml runs weekly and by manual dispatch.
It deliberately resolves the declared ranges without constraints/ci.txt,
compiles and tests the repository, and builds temporary distributions without
uploading or publishing them. It is not a required check and does not change
the ruleset. A drift failure is a maintenance signal, not permission to weaken a
required check or update constraints automatically.

Action references in every workflow remain full commit SHAs, checkout credentials
are disabled, and the build/test workflow permissions stay read-only. Updating
an action, constraint, Python version, or runner requires a separate reviewed
change with the exact observed run and any new compatibility or security evidence
recorded.

## Source-only CodeQL scanning

`.github/workflows/codeql.yml` uses the pinned CodeQL v4 action to analyze the
checked-out Python source on pull requests targeting `main` and on pushes to
`main`. It deliberately selects `build-mode: none`, so the workflow does not
install dependencies, build distributions, run the test suite, invoke a
MEGALODON command, or launch a MEGALODON analyzer. The checkout remains
read-only from the workflow's perspective: persisted Git credentials are
disabled, and the only write permission is `security-events: write`, which
CodeQL needs to upload its analysis result to GitHub's code-scanning surface.

The pinned action revision and this source-only shape are regression-checked in
`tests/test_repository_hygiene.py`. A CodeQL result is static-analysis input,
not a secret/history scan, dependency-vulnerability inventory, independent
review, release receipt, or proof that every execution path is safe. Findings
need exact-head human triage; a clean result does not authorize a merge,
deployment, publication, live capture, alert delivery, or any other product
authority.

## Bounded update intake

`.github/dependabot.yml` asks GitHub's native Dependabot service to open review
pull requests for the root Python package metadata on Tuesday and GitHub Actions
references on Wednesday. Both schedules are weekly at 04:17 UTC, target only
`main`, allow at most three open pull requests per ecosystem, and disable
automatic rebases. The configuration supplies no registry, credential, reviewer,
assignee, label, or auto-merge path. It does not grant workflow write permission
or add a new repository workflow. A generated pull request is still subject to
the repository's existing `pull_request` checks.

For Python metadata, `increase-if-necessary` may propose a declared range change
when the current declaration excludes an available version. It does not safely
regenerate the repository's platform-specific hash locks. A Python update pull
request is therefore only an intake signal: it may correctly fail the existing
lock-parity or hosted acquisition checks until a maintainer verifies exact wheel
identity and dependency closure, updates every affected profile in the same
reviewed change, and records the new evidence. Never weaken hashes or add an
alternate artifact merely to make an automated proposal green.

For Actions, Dependabot may propose changing a checked-in action reference. The
existing repository-hygiene test still requires every resulting `uses` value to
be one full 40-character commit SHA and every checkout to keep
`persist-credentials: false`; a tag or shortened reference fails CI. The update
must also preserve read-only workflow permissions, job names, constraints,
timeouts, and the separation of required and compatibility lanes.

Dependabot authorship is not independent security approval, passing CI is not
merge authorization, and an update pull request is not a release/provenance
receipt. A human must review upstream changes and the exact candidate tree. The
repository ruleset and independent-review gate remain separate controls.

## Boundaries

These workflows run package-installation/build/test activity in GitHub Actions.
That setup-time network access is separate from normal MEGALODON operation, which
remains local-first, loopback-only, observe-only by default, and free of required
runtime egress. No dependency or action update enables live capture, firewall
application, alert delivery, remote dashboard access, telemetry upload, or model
authority.
