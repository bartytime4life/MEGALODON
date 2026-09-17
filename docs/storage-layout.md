# Storage layout and data boundaries

Status: documentation only. This page adds no code, path, default, or budget;
it maps values that already exist in [`config/settings.toml`](../config/settings.toml),
[`.gitignore`](../.gitignore), [`docs/storage-failure-policy.md`](storage-failure-policy.md),
and [`docs/suricata-evidence-projection.md`](suricata-evidence-projection.md)
so a reader can see where every persistent byte in the system lives without
re-deriving it from each contract separately. The specification and security
review remain authoritative over any behavior described here.

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
   sets, and any Suricata store live here, each under its own owner-private leaf
   directory. Keep operator-selected destinations outside the checkout unless
   an exact `git check-ignore --no-index <path>` readback proves otherwise.

Nothing in the second category is implied by cloning or installing the
repository. It exists only after an operator explicitly selects or creates it
through a command or API, or authorizes an external producer to write it.

## Tracked repository storage

| Path | Contents | Produced by | Read by |
| --- | --- | --- | --- |
| `config/settings.toml`, `config/rules.toml` | Conservative typed defaults and the fixed detection-rule reference | Maintainers | `megalodon/config.py` at startup |
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
| Repository-root `captures/`, `logs/`, and matching ignored filename patterns | Raw adapter inputs an operator has authority to analyze (pcap, `eve.json`, Zeek logs) | External producers (TShark, Zeek, Suricata) or the operator | The relevant offline adapter, by explicit `--input-root` plus `--input` selection only | No default retention job; operator-owned |
| Repository-root `offline-runs/`, or another explicit `--output` directory | One report set per offline analysis run | `python -m megalodon.offline --source tshark ...`, `--source zeek-json ...`, or `--source zeek-tsv ...`, each into a new mode-`0700` output directory | `python -m megalodon dashboard --offline-run <absolute-path>` (Linux analysis profile), read-only, single selected run at a time | One completed run only; the dashboard does not browse or watch the directory |
| An operator-selected Suricata consumer store (no repository default path) | Normalized, source-qualified EVE alert rows | Explicit API call to `megalodon.offline.suricata_consumer.consume_publication`; there is no CLI consumer | `python -m megalodon dashboard --suricata-db <absolute-path>`, opened `mode=ro` for one startup snapshot | 512 MiB logical store ceiling (see [`docs/suricata-evidence-projection.md`](suricata-evidence-projection.md)) |
| `reports/` (gitignored by convention) | Any exported analyst report an operator chooses to keep | Operator/offline tooling | Operator | No default retention job |

`config/settings.toml` only ever names `app.db_path` (default `data/megalodon.db`,
resolved relative to the working directory, not the TOML file). Every other
path in this table — captures, logs, and offline output — is supplied explicitly
on the command line for that one invocation. The Suricata store and publication
are supplied to the explicit consumer API. There is no shared "data directory"
the whole system writes into; that separation is what lets each store keep its
own POSIX ownership and mode checks (owner-private `0700` directories, `0600`
files, no symlinked or hard-linked ancestors) without one store's failure or
migration touching another's.

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
leaf directory private (mode `0700`) and let the writer/consumer create it;
do not pre-create or share it across stores, since the identity checks in
`megalodon/storage.py` and `megalodon/suricata_store.py` verify a directory
that only that store's process has ever written into.

## Proposed repository directories

These directories are not tracked in git today. The exact repository-root
forms below appear in `.gitignore`, and none is created by cloning the
repository. Listing them here in one place is the "proposed layout" a fresh
checkout can grow into once an operator starts running commands. A similarly
named nested or arbitrary directory is not automatically protected; verify it
with `git check-ignore --no-index <path>` or keep it outside the checkout.

- `data/` — audit database and WAL/SHM sidecars (`app.db_path`); created by
  the first writer command, never by `dashboard` or `hud`.
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
