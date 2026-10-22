# Development and Validation

> [Documentation field guide](https://github.com/bartytime4life/MEGALODON/blob/main/docs/README.md) · [Complete catalog](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-map.md). Preserve historical pins and counts; update maintained guides when behavior changes.

Keep changes narrow, source-pinned, and reviewable. Documentation, plans, issue
state, and model output are inputs; repository source, tests, and explicit human
decisions determine implementation status.

## Contributor setup

Use Python 3.11 or newer in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q megalodon tests
.venv/bin/python -m pytest -q
```

Do not add the capture extra or launch an external analyzer merely to run the
unit suite. Never use real captures, credentials, private paths, databases, or
sensitive telemetry as fixtures.

## Validation by change type

- **Core input or storage:** exercise success, rejection, interruption, capacity, identity, and no-side-effect paths.
- **Dashboard or HUD:** run focused dashboard/control-room suites, JavaScript syntax checks, real-browser acceptance when available, and a narrow mobile viewport check.
- **Adapters and integrations:** prove closed schemas, fixed arguments/endpoints, limits, provenance, and refusal of unreviewed execution or egress.
- **Security boundaries:** add exact refusal assertions and demonstrate that the prohibited side effect did not occur.
- **Documentation:** verify every command and link against the same revision; distinguish delivered code from operational acceptance.

For documentation changes, run the existing currentness and static-catalog
checks as well as Wiki projection; retain skipped/environment-only checks:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  .venv/bin/python -m pytest -q tests/test_documentation_currentness.py \
  tests/test_wiki_sync.py tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py
python tools/build_input_inventory.py --check
```

Useful focused Wiki checks:

```bash
bash .github/scripts/sync-wiki.sh --validate
.venv/bin/python -m pytest -q tests/test_wiki_sync.py
git diff --check
```

The Wiki publisher transforms `docs/wiki/README.md` into `Home.md`, converts
Wiki-local links, regenerates `_Sidebar.md` and `_Footer.md`, and records an
ownership manifest. The native Wiki is a projection; edit the source packet so a
later publication cannot reintroduce stale content.

## Before review

- Record the exact base commit and branch head.
- List changed behavior, unchanged boundaries, negative controls, commands, outcomes, skips, and remaining gates.
- Check for overlapping work and preserve unrelated local changes.
- Keep proposed capabilities labeled as proposed.
- Treat green CI as revision evidence, not independent review, release approval, or deployment authorization.

The full contribution contract is in [CONTRIBUTING.md](../../CONTRIBUTING.md).
