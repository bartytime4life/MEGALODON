# CI dependency and action policy

Status: implemented for the required pull-request validation inputs; the
compatibility lane is non-required discovery work. This document does not change
the runtime dependency boundary, add a vendor account, or authorize network
telemetry.

## Deterministic pull-request lane

The .github/workflows/ci.yml and the Linux browser-acceptance workflow use
constraints/ci.txt for their Python test/build resolver. The constraint entries
are pinned to versions observed in green workflow run
34663054911 on main@a0d8b535d6958435abcb575e855784ce784e557e. The file is
intentionally a constraints file rather than a full lockfile: runner images,
Python, pip, platform wheels, package indexes, and hash-verified artifact
selection remain separate evidence.

The constraints file is packaged into source distributions so the extracted-sdist
test exercises the same policy file. The core package still has no third-party
runtime dependency, and developer installs remain explicit choices.

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
