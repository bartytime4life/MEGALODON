# Development and Validation

Keep changes narrow, source-pinned, and reviewable. Documentation, plans, and model output are design input; repository source, checks, and submitted human reviews determine implementation state.

## Linux contributor setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q megalodon tests
.venv/bin/python -m pytest -q
```

Do not install the capture extra or run an external analyzer merely to execute unit tests.

## Before opening a pull request

- Record the exact `main` commit, branch head, related issues, and overlapping PRs.
- State what changes, the negative controls, validation commands, outcomes, skips, and remaining gates.
- Keep real captures, private paths, credentials, generated reports, databases, and sensitive telemetry out of fixtures and commits.
- Use a draft PR for proposed work.
- Treat green CI as test evidence, not as independent review or release approval.

For dashboard changes, run the focused dashboard suites plus the full repository suite. For any change that touches a safety boundary, add explicit refusal and no-side-effect tests.

The full contribution contract is in [CONTRIBUTING.md](../../CONTRIBUTING.md).
