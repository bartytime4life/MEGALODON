# Install or run MEGALODON on a local Linux PC

Use this guide with an existing, reviewed MEGALODON checkout. The core HUD needs
Python 3.11 or newer with the standard `sqlite3` and `tomllib` modules. It has no
third-party runtime dependencies. Optional capture and analysis tools are
separate choices; the HUD can open before any data exists.

The desktop installer includes the `geo` extra's small `maxminddb` reader for the
[live connection atlas](live-connection-globe.md). The geographic database and
public internet-exit lookup are a separate explicit setup choice in the HUD.

This is the account-free route: install the core for your user, launch the
loopback HUD, and work with local data. No vendor, cloud, hosted Site, or
companion-console account is required. The HUD opens without sign-in by default
on this computer. If you want local sign-in, launch it with `--require-sign-in`.
That mode prints a random password in its terminal, or uses a reusable password
you set for the installed HUD. Neither mode creates a user account. The separate
[PC Snapshot Console](../site/README.md) imports an address-free summary and
cannot operate this PC. OSSEC and Zabbix are retired from current support.
The static catalog contains twelve entries including the core, Lynis and AIDE.
See [current state](current-state.md) for the documentation basis and open gates.

## Recommended: install for this user

Double-click **Start-MEGALODON.sh** in the repository folder and choose
**Run in Terminal** when prompted. If your file manager opens it as text, use
**Run as a Program**, or run this from the repository directory:

```bash
./Start-MEGALODON.sh
```

This installs once, starts the local HUD in a user background service, and opens
your browser. Repeating it reopens that workspace. It does not enable startup
at login or restart an existing session. The installed **MEGALODON** application
menu entry follows the same startup behavior. Without a user service manager,
the foreground fallback keeps the terminal open; **Ctrl+C** stops that session.
Use `./Start-MEGALODON.sh --check` for status and `--update` to install the current
checkout again. The lower-level `./scripts/install-local.sh` remains available
for installation without launching.

### Optional: start the installed HUD at login

From the root of the reviewed checkout, after installing for this Linux user:

```bash
./scripts/hud-autostart.sh start
./scripts/hud-autostart.sh enable
```

`start` starts the managed service now. `enable` adds startup when this user
signs in; `enable --start` combines both operations. To disable login startup
and stop the managed HUD now:

```bash
./scripts/hud-autostart.sh disable
```

These commands require the installed release and the user's systemd manager.
They verify the managed unit, reject unexpected overrides, and require an
IPv4 loopback listener at `127.0.0.1`. They do not enable system-wide startup
or user lingering. Stopping the HUD stops its in-process collectors; separately
managed companion services retain their own lifecycle.

Service startup does not create a new capture authorization. Previously saved
monitoring choices can resume collection, while fixed companion/report jobs
have their own defaults. Inspect Sensors and [background-tool scope](background-tools.md).
The source preflight (`start-local.sh --check`) reads status without enabling
login startup. This guide records commands, not an inspection of your installed
service or autostart state.

### Open a separate session with explicit options

The installed launcher reopens an active background HUD only when called
without options. Any explicit options, including `--help`, go to a new
foreground invocation. They never change an already-running session.
Before opening the browser, it checks that the user service manager loaded the
managed, unmodified unit from the current `XDG_CONFIG_HOME` with no drop-ins,
and that the configured listener belongs to that service's own process. If
either check fails, for example because another local program holds that port,
it reports that the service is not ready and opens nothing. The background
service requires `[dashboard] host = "127.0.0.1"`; the HUD server listens on
IPv4 only, so `::1` is refused for background startup and reopen.

To open a separate HUD with companion collection disabled, run this from any
directory, choosing an unused port:

```bash
~/.local/bin/megalodon-hud --port 8798 --no-auto-companions
```

For a different data source, add `--config /absolute/private/settings.toml`.
For local sign-in, add `--require-sign-in` and use the new launch terminal's
password instructions. Open the address printed by that new session; an old
browser tab still points at the old HUD. `--no-auto-companions` disables
collection only in the new session. The background HUD keeps its original
collection and sign-in settings.

In **Data and tools → Change data for the next launch**, the optional **Local
port** field prepares the same bounded port option. Blank keeps the launcher's
configured port. Preparing or copying a command does not execute it.

If the selected port is occupied, launch exits with an error before opening a
browser or starting companion collection. Choose another unused port, or stop
a foreground HUD with Ctrl+C in its own terminal first. The launcher never
stops, restarts, or reconfigures the existing background service.

### Optional: require a password for a launch

The normal desktop launch opens directly. To require sign-in for one launch,
run `~/.local/bin/megalodon-hud --require-sign-in` in a terminal. If no reusable
password is configured, that terminal shows a random password for this launch.
Sign-in is limited to loopback and is not a remote access feature.

In the HUD, **Setup → Local sign-in** provides buttons to copy this installation's
password setup/status commands and prepare a protected relaunch with an optional
unused port. The buttons only prepare or copy commands. Password entry stays in
the terminal, and the running HUD is unchanged. Source launches can prepare a
protected session with a random terminal password; reusable password buttons
are available only for the installed desktop HUD.

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
- installs the core plus the declared `geo` and `knowledge` extras; a fresh
  install omits capture/test extras, while upgrades can preserve an existing
  supported capture extra. The readers do not themselves download a location
  database or connect a sensor;
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
directory and settings file. If uninstall is interrupted after it starts
removing files, run it again to finish; because the launchers may already be
gone, use `./scripts/install-local.sh uninstall` from a reviewed checkout. An
install interrupted during its package build removes its partial release.

The startup unit is looked for under the current `XDG_CONFIG_HOME`. Uninstall
and upgrade also ask the user service manager which unit file it loaded for
`megalodon-hud.service`. If it is loaded from another file (for example, the
unit was enabled under a different `XDG_CONFIG_HOME`), or is running without
the managed file, they refuse before changing anything. Stop and disable it
where it was enabled, then retry. If no user service manager answers, they
proceed as before. A `megalodon-hud.service.d/` drop-in directory (for example,
from `systemctl --user edit`) can replace the unit's command, so startup,
upgrade and uninstall refuse while it exists. They also refuse when the user
service manager reports any drop-in it loaded for the unit (its `DropInPaths`),
including ones under `/etc/systemd/user/`, runtime directories or a type-wide
`service.d/`. The one exception is a root-owned, not group- or world-writable
type-wide `service.d/` drop-in in the distribution's `/usr/lib/systemd/user/`
(or `/lib/systemd/user/`), such as Fedora's `10-timeout-abort.conf`, which
applies to every user service rather than overriding this one. Review and
remove any other drop-in yourself.

## Alternative: check and run this checkout

From the repository directory:

```bash
./scripts/start-local.sh --check
./scripts/start-local.sh
```

Open the localhost address printed in the terminal, normally
<http://127.0.0.1:8797/>. Keep that terminal open. Press **Ctrl+C** there to stop
the HUD cleanly. Run the launcher again whenever you want to use it; it does not
add a login item or background service. From another directory, use the full
path to `scripts/start-local.sh`.

The HUD's copied reopen, protected-session, and tool-management restart commands
use this checkout's absolute launcher path and preserve the Python interpreter
serving the current session. They work from another terminal directory without
an editable package installation. If the checkout launcher is missing, replaced
by a symlink, or not executable, the HUD leaves its copied launch command
unavailable; review the checkout before launching it again. Installed desktop
HUDs continue to copy their own installed launcher. A launcher path copied from
another user's account or another computer is not portable to this computer.

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

`--check` validates the core configuration, checks Linux, and opens its core
audit store through the HUD's existing read-only admission path. An existing
store must pass a bounded summary read. A missing store is reported as
`not_configured` and left absent. Without a configuration option, it uses
built-in defaults and `data/megalodon.db` in this checkout.

From the reviewed checkout, explicitly select another configuration:

```bash
./scripts/start-local.sh --check --config "$HOME/.config/megalodon/settings.toml"
./scripts/start-local.sh --check --config "$HOME/.config/megalodon/settings.toml" --json
```

Use the actual settings path if your installation uses `XDG_CONFIG_HOME`.
Relative configuration and database paths are relative to the checkout because
the source launcher changes there. The direct module preserves its caller's
working directory, matching the runtime loader. An absolute `app.db_path`
avoids ambiguity. This launcher checks source code, not installed package identity.

The direct entry point accepts the same options:

```bash
python -m megalodon.local_setup --config /absolute/private/settings.toml --json
python -m megalodon.local_setup --help
```

Run it with the intended Python environment. After this change is explicitly
installed, it is also available in that environment; an older installed module
may still reject the new options. Nothing here installs or updates it.
`Start-MEGALODON.sh --check` and `megalodon-manage status` retain their separate
installation-artifact checks.

The selected input must be one regular UTF-8 TOML file of at most 64 KiB.
Missing files, directories, FIFOs, leaf symlinks, oversized files and changes
detected during reading are refused. The same in-memory snapshot passes the
existing [strict configuration validator](config-preflight.md). Unknown fields,
invalid types, unsupported listener bindings and missing Scapy interfaces fail
before database inspection. Explicit-file failures never fall back to defaults.
Help and unsupported/duplicate options are handled before file access. HUD
options such as `--port` and `--offline-run` are unavailable with `--check`.

Text output includes local paths and a quoted launch command using the selected
file. `--json` emits one `megalodon-local-preflight-v1` receipt with fixed codes,
configuration selection (`defaults` or `explicit`) and the core store's status.
It omits paths, database contents, configuration values and raw exception text.
This is a local self-report, not authenticated host-health or release evidence.
Both modes exit **0** when the scoped check passes, including an explicitly
reported missing store; **2** means refusal or usage error. Invalid CLI syntax
writes a fixed stderr diagnostic rather than JSON.

| Result code | Meaning |
| --- | --- |
| `data_readable` | Core store admission and a bounded read passed |
| `data_not_configured` | Configuration passed; no core store exists at that path |
| `configuration_unavailable` | Selected file/path could not be admitted or changed during reading |
| Configuration-validator code | Inspect the fixed diagnostic in the [configuration guide](config-preflight.md) |
| `database_unavailable` | Admission or summary read failed; preserve the store and inspect ownership/schema locally |
| `unsupported_platform` | This check supports Linux only |

No sample events, migrations, tools or listeners are started. This checks the
selected **core audit store**, not the installed HUD's managed-history catalog.
`runtime_verified` remains false. Running package identity, port availability,
sensor health, capture permissions, installed-tool acceptance, AI readiness and
native Windows support remain outside its scope. Finite byte and operation
counts do not impose a wall-clock deadline on a slow filesystem; use a normal
local filesystem for the selected configuration and store.

## Start support apps

For actual capture permissions and tool configuration, use **Configure apps**
beside the Start button. See [support configuration](support-configuration.md)
for the live packet feed, Wireshark controls and saved collection scope.

Open the local HUD and choose **Start background tools** at the top of **HUD**,
directly above the resource strip. **Copy command** copies the equivalent
installed launcher. From this checkout, run:

```bash
./scripts/start-support-apps.sh
```

The script starts the installed HUD user service if necessary, then invokes
the same fixed action as the button. `--check` only reads startup status. If
the HUD refuses the start because startup is already in progress, tool
maintenance is running, or the last start was under five seconds ago, the
script says so and exits 1 instead of reporting an earlier job's results; a
reply that is not the HUD's startup status is refused as unexpected.

- TShark supplies continuous metadata; Zeek supplies separate bounded CLI samples.
  Wireshark, Zenmap and ClamTk windows are optional Advanced actions only.
- Configured Suricata and Ollama services start if inactive. First-time setup uses
  Configure apps; a system authorization prompt may appear.
- Nmap, ClamAV and osquery refresh their configured jobs without duplicating
  running work. Reports continue to be watched.
- Scapy remains an alternative capture engine. Optional nftables containment
  is available through the IP inspector after preview and OS authorization.
  Neither needs a separate window or redundant background process.
- Current workflow observations and metrics appear in Sensors. Sensor samples,
  saved collector results and qualified packet/detection evidence stay distinct.

Startup does not install packages, change firewall rules or select new scan
targets. Results distinguish **Running**, **Launched**, **Queued**, **Missing**
and **Needs setup**. Review the collector panels for completed data. The button
is available in a normal non-root Linux HUD without a tool-management token;
installation controls keep their separate authorization. Optional HUD sign-in
also protects this action. On a signed-in HUD, use the button in the browser.

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
| Capture permission required | On this computer, open **Setup → Configure local tools → Configure capture access** and complete the operating-system administrator prompt, then retry capture. Reading the message does not grant permissions. Other capture or storage failures keep their separate diagnostics. |
| Address already in use | Another program or HUD holds that port, and the requested settings were not applied. Choose an unused port once with `--port 8798` (or another free port) on your installed or source launcher, or for every launch by setting `port` under `[dashboard]` in `settings.toml`, then open the printed URL. Existing sessions keep their settings; only a foreground HUD can be stopped with Ctrl+C in its launch terminal. |
| `DASHBOARD_STORE:UNSAFE_ANCESTOR` | Check ownership and write permissions of the path's ancestors. In a remapped development sandbox, run from a normal local terminal. Keep the ownership checks enabled. |
| `UNSAFE_DIRECTORY` or `UNSAFE_DATABASE` | Inspect the chosen path. The database's leaf directory must be owner-private (0700), and the database must be an owner-owned, single-link regular file (0600). Do not recursively change permissions or relocate live data as a shortcut. |
| `SCHEMA_MISMATCH` | Preserve the database and review the explicit migration/recovery workflow in the README. Startup never migrates it. |
| No qualified data | Inspect Home's source status and Evidence's audit history; sample or unlinked rows do not count as qualified observations. |

## Developer verification

Use your existing compatible test environment:

```bash
.venv312/bin/python -m pip check
.venv312/bin/python -m pytest -o addopts='' -q tests/test_local_install.py tests/test_local_setup.py tests/test_dashboard_checks.py
python -m pytest tests/test_site_readiness.py tests/test_companion_setup.py
git diff --check
```

The full suite creates isolated synthetic fixtures in temporary directories.
Run it in the ordinary host environment so ownership checks see real filesystem
owners. Keep actual local databases, reports and virtual environments untracked.

## Local entry point and Setup verification — 2026-10-01

The repository-root `Start-MEGALODON.sh` installs once and opens the local HUD.
Normal repeated launches reuse the same user-service process. `--check` is
read-only and `--update` installs this checkout explicitly.

Setup now retains visible locked Install controls, links them to the launch
authorization instructions, and shows guided installation when a fixed package
recipe is unavailable. App cards include current heartbeat observations and
direct links to the real MEGALODON configuration controls. Copied advanced
commands use the serving installation and work outside the checkout directory.
Failed availability requests report failure instead of saying the check finished.
Qwen model downloads use `127.0.0.1:11434` even when a remote `OLLAMA_HOST` is
inherited. Zeek and osquery installations remain guided; they are not falsely
presented as automatic installers.

Publisher destinations were checked, the outdated Ubuntu README fragment was
corrected, Git now links to its installation page, and Ollama opens its Linux
download page. Links: [Git](https://git-scm.com/install/),
[Ollama](https://ollama.com/download/linux),
[Wireshark](https://www.wireshark.org/download.html),
[Zeek](https://zeek.org/get-zeek/), [Suricata](https://suricata.io/download/),
[Scapy](https://scapy.readthedocs.io/en/latest/installation.html),
[nftables](https://netfilter.org/projects/nftables/index.html),
[ClamAV](https://www.clamav.net/downloads),
[osquery](https://github.com/osquery/osquery/releases/latest),
[Nmap](https://nmap.org/download), [Python](https://www.python.org/downloads/).

Verification: targeted launcher, packaging, HTTP authorization, fixed-recipe,
Setup, command quoting and DOM behavior tests passed. The running installed HUD
returned HTTP 200 for its document, script, local checks, install catalog, support
configuration and storage status. Fifteen changed installed modules matched the
source. A real repeat launch reused the same service process; the browser opener
was suppressed for this check. Settings remained byte-for-byte unchanged and the
active home storage policy remained 14 days / 20 GiB. Capture resumed after the
service restart. No companion package was installed or removed as part of these
checks. Browser-rendered acceptance is still unverified following the earlier
administrative browser denial; no alternate browser was used to bypass it.

## Verified upgrades

Run `./Start-MEGALODON.sh --update` from the reviewed checkout. The installer
builds and verifies a private release before stopping the managed user service.
Stopping flushes pending evidence. It then activates, restarts and compares the
service's `/healthz` package digest with the new release receipt. Startup failure
restores the prior selector, manifest and launchers and attempts to restart the
old service. If that restart also fails, the installer reports failure; review
the service journal before retrying.

The release receipt records package content identity and supported selected
extras. Geography support is retained; an installed Scapy capture extra carries
forward. Arbitrary packages from a user's environment are never copied. The
four newest releases plus current/previous selections remain available; older
manifest-owned releases are retired only when no observed process uses them.
Uncertain process inspection preserves the release. The release the active
selector points at is also kept, including after an owner rollback. User data,
models and settings are outside retirement. Modified service units require review before
activation; a foreground/manual HUD must be closed and relaunched separately.

Upgrade readiness checks the restarted systemd process owns the configured
IPv4 loopback listener before and after reading its package identity. A matching
public hash from an unrelated local process is insufficient. Running releases
hold a read-only directory descriptor so automatic retirement can identify code
still in use even after the active selector changes. Older ambiguous processes
keep their releases protected.

The installer copies the reviewed package and build metadata into a fresh private
build directory. It never reuses the checkout's generated `build/lib` tree.
The temporary copy is removed after pip finishes, and `release.json` retains the
original source path, package digest and selected supported extras. A failed
content comparison prevents activation.
