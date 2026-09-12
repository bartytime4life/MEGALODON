# Contributing to MEGALODON

MEGALODON is a local metadata-analysis application, not a remote administration
console. A contribution must improve useful evidence without silently increasing
execution authority. Start with the [README](README.md), the
[integration contract](docs/integration-hub.md), and the
[dashboard HTTP contract](docs/dashboard-http-contract.md).

## Establish the exact baseline

Record the current main commit, the working branch head, relevant open issues,
and overlapping pull requests before changing code. A Drive plan is design input;
GitHub source, checks, and submitted reviews determine implementation state.
Retain historical checkpoints rather than rewriting them as current evidence.

Keep one coherent review surface per PR. Describe the defect or operator task,
what changes, the negative controls, and what remains unproved. Mark proposed work
as draft. A merged commit, green workflow, automated comment, or author statement
is not independently attributable approval. The outstanding review-control problem
is tracked in [issue #3](https://github.com/bartytime4life/MEGALODON/issues/3);
this guide does not claim that GitHub settings enforce the intended policy.
Do not close that issue or change rulesets as a side effect of a code cleanup.

## Development environment

Use the Python versions exercised by `.github/workflows/ci.yml`; do not silently
raise the runtime floor. In a trusted checkout on Linux, create an isolated
virtual environment and install development dependencies explicitly:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q megalodon tests
.venv/bin/python -m pytest -q
```

This installation can access package indexes. That setup action is distinct from
normal application operation, which must not acquire a required vendor account,
secret, subscription, cloud service, or outbound integration connection.

For the reviewed Linux dependency versions, add the checked-in CI constraints
while retaining the same test extra:

```bash
.venv/bin/python -m pip install -c constraints/ci.txt -e ".[test]"
```

`constraints/ci.txt` is evidence-bound to the reviewed Ubuntu CI toolchain; it is
not a runtime lockfile or a native-Windows compatibility claim. The scheduled
compatibility-drift workflow intentionally omits it and is non-required discovery
work, so a newly released compatible tool is reported separately before any
constraints change.
Do not install the capture extra or launch an analyzer merely to run unit tests.
The command above selects versions only. The CI wheel hashes, platform checks,
and index-free build preparation are defined in the
[dependency policy](docs/dependency-policy.md); this command does not reproduce
those artifact-verification steps.

For native Windows development, use an isolated environment without changing
PowerShell execution policy or enabling unsupported capture:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
```

These commands are a developer setup, **not a native Windows acceptance receipt**.
Linux/guest execution does not prove Windows ACL, SQLite locking, process cleanup,
or browser behavior. Preserve that distinction in reports.

## Contribution boundaries

The browser is loopback-only and read-only. Do not add a command box, arbitrary
URL connector, upload-to-vendor action, tool installer, acknowledgement write,
firewall application, scanner launch, scheduler, or hidden notifier. Optional
capabilities must remain visibly optional; contract-only or proposed software
must not look installed or connected.

Use versioned, bounded inputs and fixed diagnostic categories. Preserve units,
source kind, accepted/rejected counts, completeness, redaction, and terminal
status. Flow counts are not packet counts; registrations are not observations;
detection counters are not incident identities; API reachability is not sensor
health. Never turn a display label into an authorization decision.

Synthetic fixtures and redistributable public reference material belong in the
repository only with their existing schema, provenance, integrity, size, and
packaging rules. Real captures, private paths, credentials, personal telemetry,
working databases, generated reports, and installed-tool receipts with sensitive
content do not belong in a public test fixture. Do not alter the project license
or third-party distribution posture without the separate owner decision.

## Validation and review evidence

For dashboard changes, run both existing and new behavior tests:

```bash
python -m pytest -q tests/test_dashboard.py tests/test_dashboard_boundaries.py
```

Node must be available for browserless JavaScript behavior checks. A skipped Node
harness is missing coverage, not a pass. The full repository suite and the current
wheel/sdist jobs remain necessary: moving an asset into a Python module must work
from an installed distribution, not only from a checkout.

Test success, empty results, malformed types, bounds, duplicate arguments,
unavailable dependencies, stale preservation, timeout, retry, and refusal before
side effects. Prefer tests against stable public behavior to matching source text.
Keep one final dashboard bootstrap call so behavior harnesses can disable startup
without altering the code under test.

The [operator runbook](docs/dashboard-operations.md) defines rendered-browser
checks. Node mocks do not measure layout, contrast, screen-reader output, platform
privacy, or installed-tool containment. Report those evidence classes separately.
A PR receipt should identify exact commit, commands, environment, outcomes,
skips, hosted run IDs, and remaining acceptance gates. Never upgrade local or
partial-checkout evidence into full-repository or native-platform proof.

## Controlled pytest execution in CI

Verifying dependency wheels does not prevent pytest from discovering unrelated
plugins already installed on a runner. The ordinary CI workflow therefore sets
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, and clears `PYTEST_PLUGINS` and
`PYTEST_ADDOPTS` at workflow scope. This applies to both the Python 3.11 test run
and the Python 3.12 extracted-source tests. Built-in pytest fixtures and trusted
repository configuration still load; the repository's `-q` option is preserved.
Both invocations add `-ra` so nonpassing outcomes, including skip reasons, appear
in the terminal summary instead of an unidentified skipped-test count.

From the repository root, after explicitly preparing your development environment,
the equivalent test-launch policy is:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS= PYTEST_ADDOPTS= \
  .venv/bin/python -m pytest -ra
```

The regression probes use real pytest with inert, temporary entry-point metadata.
They show that an autoload tripwire executes without the policy, is not imported
with it, and cannot return through inherited plugin/argument variables. They also
prove built-in fixtures still work, a known skip reason remains visible, and an
actual assertion failure still exits nonzero. Metadata discovery is restricted to
the synthetic distribution in each child process; no third-party package is
installed or fetched. These are plugin-loading tests, not full runner isolation.

Explicit `-p` options, repository `conftest.py` or `pytest_plugins` declarations,
Python startup hooks, imported packages, and the runner itself remain trusted
inputs. Any required external plugin must have a reviewed lock and explicit load
path, not a restoration of ambient autoload. This policy does not isolate all
installed packages, hash-lock Python/pip, disable product tests, certify the runner,
or authorize capture to eliminate an installed-tool skip. The browser and
compatibility-discovery workflows are unchanged. Developer plugin choices outside
CI remain explicit local choices; they do not alter the CI evidence requirements.

Primary behavior reference: [pytest plugin loading and autoload controls](https://docs.pytest.org/en/stable/how-to/plugins.html).

## Isolated source-distribution test environment

The Python 3.12 `wheel-smoke` job creates a fresh `sdist-venv` without
`--system-site-packages`. It refuses an existing directory or symlink rather
than reusing an environment. The existing verified test and build wheelhouses
supply its fourteen third-party dependencies; the shared `packaging` wheel
appears in both unchanged locks. Installation requires hashes, admits only
wheels, disables the index/cache, and retains dependency resolution. There is
no new download, version upgrade, or fallback to runner-installed packages.

Before installing the generated sdist, the job runs
`tools/check_sdist_environment.py` with the venv interpreter's `-I` flag. The
read-only check requires a real isolated interpreter, disabled user/system site
packages, and metadata origins inside that venv for every expected dependency.
It emits a bounded receipt or a nonzero fixed diagnostic, never raw paths or
package metadata. The helper itself is byte-compared with its sdist copy.
Python/pip bootstrap is still supplied by the runner and `ensurepip`; pip's
version is reported, not newly pinned or upgraded by this step.

The two packaging run blocks clear inherited `PYTHONPATH`/`PYTHONHOME` and disable
user-site loading. The extracted-source pytest run still deliberately imports
MEGALODON from the extracted sdist, not the original checkout; its full selection,
plugin policy and `-ra` skip report are unchanged. Separately, an isolated import
outside either source tree must resolve the installed MEGALODON package inside
`sdist-venv` before the existing installed-command smokes execute. Do not describe
the extracted-source test run as a full installed-wheel test suite.

Regression tests cover changed workflow ordering and weakened flags, missing or
external dependency metadata, and actual temporary virtual environments with
synthetic metadata only. These fixtures fetch/install no third-party package.
The exact-head hosted result must additionally prove both real hashed lock
installations, the fourteen-dependency origin receipt, installed-project origin,
full source tests and unchanged browser acceptance. Missing installed-TShark
acceptance remains a visible skip, not permission to enable capture.

This closes source-distribution environment inheritance only. The outer build,
Python 3.11 and browser environments, approved package code/startup hooks,
Python/pip and OS provenance remain trusted and separately reviewable. Metadata
location is not code-integrity or publisher-authenticity verification, and a
virtual environment is not process/network containment or a reproducible-build
attestation. All product, sensor, firewall and release authority is unchanged.

Primary references: [Python virtual environments](https://docs.python.org/3.12/library/venv.html)
and [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/).

## Connection design and dated review

The [connection advancement plan](docs/connection-advancement-plan.md) is
**PROPOSED**, not a runtime integration contract or source-admission decision.
It separates capability, loaded evidence, and action authority, and prohibits
raw-input or payload-derived hashes as a retention workaround.

The [source-pinned correction review](docs/repository-review-2026-09-11.md)
records the original ZIP preparation separately from GitHub delivery. The
[Reference Library implementation and recovery runbook in PR #91](https://github.com/bartytime4life/MEGALODON/pull/91)
have their own exact-head checks and review gate. These documents do not require
that PR to be merged; refresh its live lifecycle before relying on its behavior.
