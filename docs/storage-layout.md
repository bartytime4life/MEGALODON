# Storage layout and data boundaries

Status: documentation only. This page adds no code, path, default, or budget;
it maps values that already exist in [`config/settings.toml`](../config/settings.toml),
[`.gitignore`](../.gitignore), [`docs/storage-failure-policy.md`](storage-failure-policy.md),
and the source owners linked below. It maps MEGALODON's repository content,
application stores and managed desktop artifacts; companion applications,
provider model downloads and operating-system logs have their own storage
policies. The specification and security review remain authoritative over any
behavior described here.

## Two kinds of storage

MEGALODON keeps exactly two kinds of storage apart, and every subsystem below
respects that split:

1. **Tracked repository storage** — checked into git, read-only at runtime,
   versioned by commit. Schemas, fixtures, pinned reference bundles, and the
   static Defense Console mirror live here.
2. **Runtime-only local storage** — created or selected on the operator's
   filesystem by an explicit command or API call. The repository `.gitignore`
   excludes only its named root-relative directories and filename patterns; it
   cannot guarantee that every arbitrary operator-selected path inside a
   checkout is ignored. The audit database, capture/log inputs, offline report
   sets, AI receipts, installed application state and any Suricata store live
   here. The core and AI ledgers are separate files but share a parent by
   default. Keep operator-selected destinations outside the checkout unless
   an exact `git check-ignore --no-index <path>` readback proves otherwise.

Cloning creates none of the second category. An explicit desktop installation
does create managed code, configuration, launchers and an empty data directory;
it does not create telemetry. Other runtime state follows its command/API or an
authorized external producer.

## Tracked repository storage

| Path | Contents | Produced by | Read by |
| --- | --- | --- | --- |
| `config/settings.toml` | Example conservative settings | Maintainers | `megalodon/config.py` only when explicitly selected with `--config`; otherwise built-in defaults apply |
| `config/rules.toml` | Fixed detection-rule reference | Maintainers | Documentation/reference only; the runtime does not load this file |
| `contracts/*/v1/` | Inert schemas, accepted/rejected fixtures, and per-contract `README.md` boundary notes | Maintainers | Contract tests; `tools/build_reference_assets.py` and related build tooling |
| `megalodon/reference/iana-v1/` (2.7 MiB) | SHA-256-pinned IANA service/port and protocol snapshot | `tools/build_reference_assets.py` | `megalodon/reference/loader.py`; the dashboard's read-only Reference Library panel |
| `megalodon/reference/corpus-v1/` (1.7 MiB) | Deterministic synthetic detector-evaluation corpus | `tools/build_reference_assets.py` | `megalodon.reference.loader.evaluate_corpus`, exposed by `python -m megalodon.evaluation corpus` |
| `site/dist/` | Static Defense Console source mirror (HTML/CSS/JS, no build step); equality with the hosted version is separately receipted and may be unverified | Maintainers; current deployment status is recorded in [`docs/site-source-alignment.md`](site-source-alignment.md) | A browser only; no MEGALODON process reads `site/` at runtime |
| `examples/` | Bounded JSONL replay fixture | Maintainers | `python -m megalodon run` examples in the README |

None of these paths grow at runtime. Updating them is a source change reviewed
like any other commit, not an operational side effect of running the tool.

## Runtime-only local storage

| Path (default) | Contents | Written by | Read by | Bound |
| --- | --- | --- | --- | --- |
| `data/megalodon.db` (+ `-wal`/`-shm`) | The audit ledger: accepted events, detections, one policy-plan action per detection, provenance links, and ingestion-run receipts | `Store` writer through `python -m megalodon run` or the bounded service API | Dashboard reader, opened `mode=ro` with `query_only` and a deny-by-default SQL authorizer | `storage.max_database_bytes` in `config/settings.toml`, default 256 MiB, operator range 1 MiB–4 GiB (see [`docs/storage-failure-policy.md`](storage-failure-policy.md)) |
| `megalodon-ai-receipts.db` beside the selected audit file (+ `-wal`/`-shm`; collision fallback below) | Separate AI state-event ledger, local hash chain and bounded report snapshots; not core telemetry or a `reports/` export | [`ReceiptStore`](../megalodon/ai_broker.py) through explicit `ai` CLI operations (including a doctor receipt when writable) or the enabled, token-gated HUD question route | Broker receipt/status readback | 8 KiB encoded event payload limit; current database + WAL/SHM occupancy is checked against 16 MiB before append, not reserved as a final-size ceiling; no automatic retention job |
| Repository-root `captures/`, `logs/`, and matching ignored filename patterns | Raw adapter inputs an operator has authority to analyze (pcap, `eve.json`, Zeek logs) | External producers (TShark, Zeek, Suricata) or the operator | The relevant offline adapter, by explicit `--input-root` plus `--input` selection only | No default retention job; operator-owned |
| Repository-root `offline-runs/`, or another explicit `--output` directory | One report set per offline analysis run | `python -m megalodon.offline --source tshark ...`, `--source zeek-json ...`, or `--source zeek-tsv ...`, each into a new mode-`0700` output directory | `python -m megalodon dashboard --offline-run <absolute-path>` (Linux analysis profile), read-only, single selected run at a time | One completed run only; the dashboard does not browse or watch the directory |
| An operator-selected Suricata consumer store (no repository default path) | Normalized, source-qualified EVE alert rows | Explicit API call to `megalodon.offline.suricata_consumer.consume_publication`; there is no CLI consumer | `python -m megalodon dashboard --suricata-db <absolute-path>`, opened `mode=ro` for one startup snapshot | 512 MiB logical store ceiling (see [`docs/suricata-evidence-projection.md`](suricata-evidence-projection.md)) |
| `reports/` (gitignored by convention) | Any exported analyst report an operator chooses to keep | Operator/offline tooling | Operator | No default retention job |

### Audit and AI path selection

[`load_settings`](../megalodon/config.py) and the actual launchers determine the
audit path; there is no automatic search for a repository or installed TOML file:

| Entry point | Configuration and audit-path basis |
| --- | --- |
| Direct `python -m megalodon ...` | An explicit `--config` selects the TOML file; without it, built-in defaults apply. `app.db_path` defaults to `data/megalodon.db`. A relative database path is relative to the process working directory, **not** the TOML file's directory. |
| [`scripts/start-local.sh`](../scripts/start-local.sh) | Changes to the checkout root before invoking `hud`. Without `--config`, the default is therefore `<checkout>/data/megalodon.db`. Relative config/database paths are interpreted from that root. |
| Installed `megalodon-hud` / desktop entry | The generated launcher supplies the installed absolute settings path with `--config`; an explicitly supplied later `--config` overrides it. Newly generated settings name `<XDG_DATA_HOME>/megalodon/data/megalodon.db` as an absolute path; existing settings are preserved. The launcher does not change directory, so a relative `app.db_path` still uses its inherited working directory. |

The CLI's [`_ai_receipt_path`](../megalodon/cli.py) derives the AI filename from
the selected audit file's parent. If the audit basename case-insensitively
matches `megalodon-ai-receipts.db` or its `-wal`, `-shm` or `-journal` name, it
uses `megalodon-ai-receipts-ledger.db` instead. `ReceiptStore` validates SQLite
sidecars and enables WAL for that separate file. Opening the ordinary HUD does
not create an AI ledger; an explicit AI receipt writer may create it and its
private parent. An API caller supplies its own receipt path. These files do
not inherit the core store's capacity or retention policy; see the
[AI receipt contract](ai-control-plane.md#receipts-and-hud).

Capture/log inputs and offline output are selected for their invocation; the
Suricata store/publication are supplied to its explicit API. There is no single
data directory shared by every subsystem. Core, AI and Suricata stores apply
their own private-path admission, including POSIX owner-private directories,
database modes, safe ancestors and file identity. Separate database names do
not imply independent filesystem failure domains.

### Installed desktop state

[`install_paths`, `_default_settings` and `_artifact_contents`](../megalodon/local_install.py)
own this layout. `XDG_DATA_HOME` defaults to `$HOME/.local/share` and
`XDG_CONFIG_HOME` to `$HOME/.config`; supplied values must be absolute. The
installer embeds its selected paths in the launchers. It does not move an
existing installation merely because a later shell changes an XDG variable.

| Managed path | Persisted content and lifecycle |
| --- | --- |
| `<XDG_DATA_HOME>/megalodon/releases/<release-id>/venv/`, `current`, `install.json`, `.install.lock` | Private installed environments, active-release symlink, installation manifest and maintenance lock file. Upgrade retains recorded releases, up to the 32-release history limit; it is not an automatic cleanup policy. |
| `<XDG_DATA_HOME>/megalodon/data/` | Private data directory created during installation; newly generated settings place the core audit file here, with CLI-derived AI receipts beside it when used. Installation creates no telemetry database. |
| `<XDG_CONFIG_HOME>/megalodon/settings.toml` | Generated mode-`0600` settings, created only when absent; existing valid settings are preserved. |
| `$HOME/.local/bin/megalodon-hud`, `$HOME/.local/bin/megalodon-manage` | Generated launchers for the selected private release; these paths do not follow `XDG_DATA_HOME`. |
| `<XDG_DATA_HOME>/applications/megalodon.desktop`, `<XDG_DATA_HOME>/icons/hicolor/scalable/apps/megalodon.svg` | Application-menu entry and icon. |

The manager's uninstall removes validated managed releases, selectors,
manifest and desktop/launcher artifacts, while preserving data and settings;
it does not recursively erase the application's parent directory or its lock
file. Installation, repair and uninstall are explicit operations, not effects
of reading this map.

The per-launch AI operator token, heartbeat cache/history, and the tool
installer's current job/status/output are process memory in
[`dashboard.py`](../megalodon/dashboard.py),
[`tool_heartbeat.py`](../megalodon/tool_heartbeat.py) and
[`tool_installer.py`](../megalodon/tool_installer.py), not SQLite ledgers.
The AI token is printed to the launch terminal and entered in the browser;
MEGALODON does not persist it. External terminal/session logging is separate.
In-memory installer status does not make any separately authorized package or
service effects temporary.

For generic TShark and Zeek inputs, the offline opener checks the selected root,
no-follow path traversal, regular single-link files, size and read stability.
It does not enforce input owner or permission bits. Keeping those raw inputs
private is an operator responsibility; private output and database checks are
separate controls.

## How an operator ties the pieces together

The stores above are independent by design, but an operator who wants one
predictable layout on disk can still choose a single parent directory and
point each command at a dedicated child underneath it, for example:

```text
~/megalodon-data/
├── audit/            -> --config pointing app.db_path = "audit/megalodon.db"
├── captures/          (TShark/Zeek/Suricata inputs the operator owns)
├── offline-runs/      (one leaf directory per `--output` run)
└── suricata/           store.sqlite3  (--suricata-db)
```

This is a convention, not a requirement enforced by any command: nothing
rejects a different layout, and nothing assumes this one exists. Keep each
leaf directory private (mode `0700`) and use the relevant writer or explicit
initializer to create each store. The Suricata consumer requires an existing
initialized store. Prefer dedicated directories to avoid mixing unrelated
state. Checks in `megalodon/storage.py` and `megalodon/suricata_store.py` verify
current ownership, permissions and filesystem identity; they do not prove a
directory's historical writers or isolate processes sharing the same OS user.

## Proposed repository directories

These directories are not tracked in git today. The exact repository-root
forms below appear in `.gitignore`, and none is created by cloning the
repository. Listing them here in one place is the "proposed layout" a fresh
checkout can grow into once an operator starts running commands. A similarly
named nested or arbitrary directory is not automatically protected; verify it
with `git check-ignore --no-index <path>` or keep it outside the checkout.

- `data/` — default checkout audit database and WAL/SHM sidecars (`app.db_path`),
  plus AI receipts when explicitly used. The core audit file is created by its
  writer, not by opening `dashboard` or `hud`; an AI receipt writer may create
  the shared parent without creating core telemetry.
- `captures/`, `logs/` — operator-supplied adapter inputs; no command creates
  these automatically, and none should be created until an operator has
  authorized capture on that host.
- `offline-runs/` — parent for `--output` report-set directories; each run
  creates its own mode-`0700` leaf under whatever parent the operator names.
- `reports/` — optional destination for anything an operator exports out of
  an offline report set; MEGALODON itself does not write here.

None of these should be added as empty tracked directories: git does not
track empty directories, `.gitignore` already excludes their contents, and a
placeholder file would only invite confusion about whether the directory
ships with the repository. The correct signal that a store exists is the
command that created it, not a directory present in a fresh clone.

## Non-goals

This page does not define a retention policy, a backup strategy, a disk-full
recovery procedure, or a migration path — those remain the separate concerns
of [`docs/storage-failure-policy.md`](storage-failure-policy.md),
[`docs/ingestion-integrity.md`](ingestion-integrity.md), and the README's
[Local dashboard and storage](../README.md#local-dashboard-and-storage)
section. It also does not change any default, budget, or command; every value
above is quoted from the source it links to.
