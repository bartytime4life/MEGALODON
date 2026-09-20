# Manual startup on a local Linux PC

Use this guide for an existing, reviewed MEGALODON checkout. The core HUD needs
Python 3.11 or newer with the standard `sqlite3` and `tomllib` modules. It has no
third-party runtime dependencies. Optional capture and analysis tools are
separate choices; the HUD can open before any data exists.

## Check and launch

From the repository directory:

```bash
./scripts/start-local.sh --check
./scripts/start-local.sh
```

Open the localhost address printed in the terminal, normally
<http://127.0.0.1:8787/>. Keep that terminal open. Press **Ctrl+C** there to stop
the HUD cleanly. Run the launcher again whenever you want to use it; it does not
add a login item or background service. From another directory, use the full
path to `scripts/start-local.sh`.

The launcher tries the checkout's `.venv312`, then `.venv`, then compatible
Python commands on PATH. It skips incompatible interpreters, anchors the working
directory to this checkout, and runs its source directly. This prevents an old
default Python or a different terminal directory from selecting the wrong code
or default database. It does not install or upgrade packages.

Choose an interpreter explicitly with an absolute path if needed:

```bash
MEGALODON_PYTHON=/usr/bin/python3.12 ./scripts/start-local.sh --check
```

An explicit incompatible interpreter fails instead of falling back. An existing
activated installation can also use `python -m megalodon hud`. Do not recreate
an existing virtual environment just to launch the HUD. See the
[platform baseline](platform-baseline.md) for installing a new environment.

## What the check establishes

`--check` prints the actual Python and SQLite versions, checks Linux, and opens
the default `data/megalodon.db` through the same read-only admission path as the
HUD. An existing store must also pass a bounded summary read. A missing store is
reported as not configured and is left absent. No sample events, migrations,
tool processes or network listeners are created. The check covers only the
default checkout data path; it rejects extra arguments to avoid implying that a
different configuration was checked.

Port availability, sensor health, capture permissions, installed optional-tool
acceptance and native Windows support are outside this check.

## Use your data

Home → **Data and tools** shows the selected source and startup tool observations.
Open **Change data for the next launch** to prepare a command for an existing
configuration or completed offline report. These controls prepare text; they do
not change the running server's sources. Stop and relaunch with the selected
options. The launcher also passes HUD options through:

```bash
./scripts/start-local.sh --config /absolute/path/settings.toml
```

Relative paths in HUD options are relative to the checkout because the launcher
always starts there. Prefer absolute paths for explicit configuration and data.

The existing sample audit history stays separate from qualified Traffic and
Findings. An empty or sample-only store may correctly show **No qualified data**.
To learn the authorized JSONL import options, run the chosen interpreter with
`-m megalodon run --help`; use the [README](../README.md) for the input contract.
After the first import into a previously missing store, restart the HUD.

The hosted Defense Console is a disconnected reference site. Opening it does
not connect this PC, and this launcher does not publish site changes.

## Troubleshooting

| Message or symptom | Next step |
| --- | --- |
| Python 3.11 or newer is required | Use a compatible interpreter with SQLite support. Upgrading pip does not upgrade Python. |
| Address already in use | Stop your existing HUD, or run `./scripts/start-local.sh --port 8788` and use its printed URL. The launcher does not terminate another process. |
| `DASHBOARD_STORE:UNSAFE_ANCESTOR` | Check ownership and write permissions of the path's ancestors. In a remapped development sandbox, run from a normal local terminal. Keep the ownership checks enabled. |
| `UNSAFE_DIRECTORY` or `UNSAFE_DATABASE` | Inspect the chosen path. The database's leaf directory must be owner-private (0700), and the database must be an owner-owned, single-link regular file (0600). Do not recursively change permissions or relocate live data as a shortcut. |
| `SCHEMA_MISMATCH` | Preserve the database and review the explicit migration/recovery workflow in the README. Startup never migrates it. |
| No qualified data | Inspect Home's source status and Evidence's audit history; sample or unlinked rows do not count as qualified observations. |

## Developer verification

Use your existing compatible test environment:

```bash
.venv312/bin/python -m pip check
.venv312/bin/python -m pytest -o addopts='' -q
node --test site/tests/*.test.cjs
git diff --check
```

The full suite creates isolated synthetic fixtures in temporary directories.
Run it in the ordinary host environment so ownership checks see real filesystem
owners. Keep actual local databases, reports and virtual environments untracked.
