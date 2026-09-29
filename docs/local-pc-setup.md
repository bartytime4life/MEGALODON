# Install or run MEGALODON on a local Linux PC

Use this guide with an existing, reviewed MEGALODON checkout. The core HUD needs
Python 3.11 or newer with the standard `sqlite3` and `tomllib` modules. It has no
third-party runtime dependencies. Optional capture and analysis tools are
separate choices; the HUD can open before any data exists.

This is the account-free route: install the core for your user, launch the
loopback HUD, and work with local data. No vendor, cloud, hosted Site, or
companion-console account is required. The HUD opens without sign-in by default
on this computer. If you want local sign-in, launch it with `--require-sign-in`.
That mode prints a random password in its terminal, or uses a reusable password
you set for the installed HUD. Neither mode creates a user account. The hosted reference Site remains
owner-private and is not needed for local operation. OSSEC and Zabbix are retired from current
support; the optional catalog contains ten tools including the core.

## Recommended: install for this user

From the repository directory:

```bash
./scripts/install-local.sh
```

Open **MEGALODON** from the Linux application menu. A terminal window owns the
local server and stays open while you work. The browser opens only after the
loopback server binds successfully. Press **Ctrl+C** in that terminal to stop.
No background service or login startup is installed.

### Optional: require a password for a launch

The normal desktop launch opens directly. To require sign-in for one launch,
run `~/.local/bin/megalodon-hud --require-sign-in` in a terminal. If no reusable
password is configured, that terminal shows a random password for this launch.
Sign-in is limited to loopback and is not a remote access feature.

To choose or change the password used by opt-in installed HUD launches:

From a terminal on this PC, run:

```bash
~/.local/bin/megalodon-manage password set
```

Enter the new password twice at the hidden prompts. Use 8 to 64 printable
ASCII characters. Do not put the password in a command argument, environment
variable, file you edit by hand, or chat message. MEGALODON stores only a
salted password verifier in the owner-only file
`~/.config/megalodon/hud-password.json`; it never prints the chosen password.
Start a HUD with `--require-sign-in` and enter the password you chose on its
sign-in page. The password protects only that local HUD launch and is
separate from your computer password and the optional AI/tool-management tokens.

To check the mode without revealing the password, run
`~/.local/bin/megalodon-manage password status`. To return to a fresh random
password for each opt-in launch, run `~/.local/bin/megalodon-manage password clear`.
Keep the HUD bound to loopback; this password does not
authorize remote exposure.

The installer:

- refuses root and `sudo`;
- builds a new private application release before selecting it;
- installs only the MEGALODON core package, without capture or test extras;
- creates a stable HUD launcher, maintenance launcher, desktop entry, and icon;
- serializes install, repair, and uninstall actions with an owner-private lock;
- requires root/current-user-owned directory ancestry, allowing writable
  ancestors only when the sticky bit protects entries, and rejects symlinked
  ancestry, writable artifact directories, changed managed file modes, and pip
  options that redirect the install destination;
- writes a conservative owner-private settings file only when one is absent;
- leaves the selected release usable when build or import checks fail;
- never creates telemetry, starts a sensor, changes a firewall, or installs an
  optional companion program.

Python's package installer may download the declared build requirements. A
source checkout alone is not an offline installation artifact. The installer
ignores pip configuration files and destination-changing `PIP_*`/Python import
variables. It preserves only explicit package-source and network values such as
`PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, proxy, certificate,
and timeout settings. Review the terminal output and source selection before
installing.

| Item | Default location |
| --- | --- |
| Private application releases and data | `~/.local/share/megalodon/` |
| Settings | `~/.config/megalodon/settings.toml` |
| Stable launchers | `~/.local/bin/megalodon-hud` and `megalodon-manage` |
| Application-menu entry | `~/.local/share/applications/megalodon.desktop` |

Absolute `XDG_DATA_HOME` and `XDG_CONFIG_HOME` values are honored. Relative
values, unsafe or writable application directories, symlink substitutions,
root execution, concurrent maintenance, changed managed file modes, and
untracked files occupying managed artifact names are refused.

### Check, repair, upgrade, or remove the installation

```bash
~/.local/bin/megalodon-manage status
~/.local/bin/megalodon-manage status --json
~/.local/bin/megalodon-manage repair
~/.local/bin/megalodon-manage uninstall
```

**Repair** restores missing managed launchers but refuses modified or unsafe
artifacts. To upgrade, review a newer checkout and run its
`./scripts/install-local.sh`; activation happens only after the new installed
package passes an import and origin check. **Uninstall** removes the managed
application releases, launchers, desktop entry, and icon. It preserves the data
directory and settings file.

## Alternative: check and run this checkout

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
environment can also use `python -m megalodon hud`. Do not recreate
an existing virtual environment just to launch the HUD. See the
[platform baseline](platform-baseline.md) for installing a new environment.

### Start live metadata and the HUD together

For an authorized Linux interface, the separate launcher starts MEGALODON's
bounded Scapy metadata writer and the loopback HUD against the same checkout and
configuration:

```bash
./scripts/start-hud-data.sh --interface IFACE --check
./scripts/start-hud-data.sh --interface IFACE --max-events 1000000 --open-browser
```

Replace `IFACE` with an existing interface name. Scapy must already be installed
in the selected Python, and that interpreter must already have capture
permission. The check confirms only local prerequisites. It does not prove
permission, sensor health, complete network visibility, or arriving events.
The writer stores validated metadata only; the HUD reads those stored records
every five seconds while its tab is visible. Press Ctrl+C to stop both. When
the writer reaches its event ceiling or fails, the launcher stops the HUD so
it does not continue to appear live. It never invokes `sudo` or grants capture
permission.

Use `--config /absolute/path/settings.toml` when the intended audit store is
configured elsewhere. Optional `--geoip-db /absolute/path/regions.mmdb` loads
an existing offline region database. Optional
`--suricata-db /absolute/path/store.sqlite3` selects an existing private
Suricata evidence store for one read-only HUD startup snapshot. The script does
not start or connect a Suricata sensor or consumer. Other companion apps retain
their separately documented manual input paths or presence-only status.

## What the source preflight establishes

`--check` prints the actual Python and SQLite versions, checks Linux, and opens
the default `data/megalodon.db` through the same read-only admission path as the
HUD. An existing store must also pass a bounded summary read. A missing store is
reported as not configured and is left absent. No sample events, migrations,
tool processes or network listeners are created. The check covers only the
default checkout data path; it rejects extra arguments to avoid implying that a
different configuration was checked.

The direct entry point, `python -m megalodon.local_setup`, has the same
default-path-only scope. It rejects options such as `--config` and positional
arguments before opening a store. Use `python -m megalodon.local_setup --help`
for help without inspecting data; pass HUD options to the launcher without
`--check` when you intend to start the HUD with a selected configuration.

Port availability, sensor health, capture permissions, installed optional-tool
acceptance and native Windows support are outside this check.

## Use your data

Home → **Data and tools** shows the selected source and a live status light for
each optional tool, with **Install** and **Start service** buttons where a fixed
package or service unit exists (see [tool heartbeat](tool-heartbeat.md)).
Choose **Check this computer** for a fresh, explicit metadata check. Home then
shows current results; Apps keeps its startup observations until the HUD is
reopened. **Unable to check** is a neutral result when executable discovery
could not assess the eligible tools; it is never presented as success.
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
| Python 3.11 or newer is required | Use a compatible interpreter with SQLite, TOML, and venv support. Upgrading pip does not upgrade Python. |
| Installer refuses root or `sudo` | Run it as the ordinary desktop user who will open MEGALODON. |
| Build or package installation failed | Preserve the terminal output. Check Python venv support, network/package-source access, and declared build requirements; the selected release is unchanged. |
| Installation needs repair | Run `~/.local/bin/megalodon-manage status`, then `repair`. Modified artifacts are refused so they can be reviewed instead of overwritten. |
| MEGALODON is missing from the application menu | Run `status`; if ready, sign out/in or refresh the desktop application cache. The stable `~/.local/bin/megalodon-hud` launcher remains available. |
| Address already in use | Stop your existing HUD, or run `./scripts/start-local.sh --port 8788` and use its printed URL. The launcher does not terminate another process. |
| `DASHBOARD_STORE:UNSAFE_ANCESTOR` | Check ownership and write permissions of the path's ancestors. In a remapped development sandbox, run from a normal local terminal. Keep the ownership checks enabled. |
| `UNSAFE_DIRECTORY` or `UNSAFE_DATABASE` | Inspect the chosen path. The database's leaf directory must be owner-private (0700), and the database must be an owner-owned, single-link regular file (0600). Do not recursively change permissions or relocate live data as a shortcut. |
| `SCHEMA_MISMATCH` | Preserve the database and review the explicit migration/recovery workflow in the README. Startup never migrates it. |
| No qualified data | Inspect Home's source status and Evidence's audit history; sample or unlinked rows do not count as qualified observations. |

## Developer verification

Use your existing compatible test environment:

```bash
.venv312/bin/python -m pip check
.venv312/bin/python -m pytest -o addopts='' -q tests/test_local_install.py tests/test_local_setup.py tests/test_dashboard_checks.py
node --test site/tests/*.test.cjs
git diff --check
```

The full suite creates isolated synthetic fixtures in temporary directories.
Run it in the ordinary host environment so ownership checks see real filesystem
owners. Keep actual local databases, reports and virtual environments untracked.
