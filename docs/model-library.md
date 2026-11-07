# Explicit local model staging

Setup → Local AI now has **Download & stage** and **Check staged files and
space** controls. Installed Ollama models continue to use **Refresh installed
models** and **Save model** above them. Existing Ollama files are referenced in
place; this feature does not move, delete, duplicate or import those files.
An explicitly requested new GGUF download has its own staging copy.

## Reuse an installed model without a transfer

**Use existing files · verify saved model** checks the exact saved tag and
manifest digest using the existing offline artifact verifier. Save the model
selection first, select its actual store from the four fixed locations shown,
and choose the standard (32 GiB / 120 seconds) or large-local
(96 GiB / 300 seconds) read budget. These are cooperative bounds; a blocked
kernel read cannot be interrupted by them. The operation hashes the provider
executable as a file; it never executes it or contacts the daemon.

The protected `model_library_reuse` action accepts only `store_id`, `model`,
`model_digest` and `verification_profile`. The server rechecks the identity
against its saved selection before starting. The store is one of `user`
(`~/.ollama/models`), `system` (`/usr/share/ollama/.ollama/models`), `service`
(`/var/lib/ollama/models`) or `snap` (`/var/snap/ollama/common/models`). There
is no automatic store search or environment-selected fallback. Other stores
remain accessible through the explicit offline verifier CLI. Provider discovery
uses the already configured trusted Ollama directory, or the fixed
`/usr/local/bin` and `/usr/bin` directories. An inaccessible store/provider
refuses; it never changes permissions, installs tools or downloads a replacement.

Private SQLite schema version 2 adds at most 64 `local_models` references,
keyed by store scope and exact tag. It retains manifest/provider hashes,
verified byte count (including manifest/provider), read profile, check time,
fixed failure code and latest check state. No external file path or content is
stored. A v1 database migrates additively in one transaction, preserving its
model/job rows. Unknown schemas still refuse. Each check commits `verifying`
before reading, clears previous successful evidence for that reference, and
commits `files_verified` only after the complete closure passes. A failed
commit cannot appear as a successful check. A crash leaves `verifying`; the
next explicit library action records `interrupted` without restarting a check
or transfer. Stopping an offline check records `CHECK_CANCELLED` and never
claims that an Ollama daemon transfer was stopped.

Status polling is memory-only. After restart, an explicit library check reads
historical references; the HUD projects at most the latest 16, and their labels
say **at last check**, never continuous
verification. A different saved tag/digest labels older observations as a
previous selection requiring a recheck. A changed manifest, missing file,
corrupted component or unsupported manifest cannot receive a verified result.
The UI keeps **Runtime acceptance: held (UNBOUND)** separate from both existing
file verification and staged downloads. SQLite contains no accepted-model flag.

The existing pinned GGUF transfer remains unchanged. A catalog source, revision,
size, digest or license change now clears the browser's earlier download consent.
A rejected/expired permission refresh also clears consent and never automatically
replays a download POST; the operator must review and click again.
No new Ollama pull transport is enabled. See the pinned
[Ollama transfer investigation](ollama-transfer-contract.md) for its unresolved
shared-cancellation and storage guarantees.

This is Linux, non-root host maintenance through the existing protected
`/api/support-config` action route. It requires the HUD operator session,
same-origin checks and per-launch configuration token. Viewing Setup, polling,
startup, shutdown and restarting an interrupted job never download anything.
An operator checks the displayed source, license and size, ticks the download
checkbox, and clicks **Download & stage**. Only a closed catalog ID reaches the
server; URLs, filenames, paths, commands, credentials and provider endpoints
cannot be supplied by the browser or model output.

## Initial pinned catalog

The first bounded catalog contains one small file; arbitrary model downloads
are deliberately not a runtime configuration surface. Other **installed**
Ollama models remain selectable. Adding downloadable models requires a reviewed
catalog change with exact upstream revision, size, SHA-256 and licensing.

| Field | Pin |
| --- | --- |
| Publisher repository | `Qwen/Qwen2.5-0.5B-Instruct-GGUF` on Hugging Face |
| Revision | `9217f5db79a29953eb74d5343926648285ec7e67` |
| File | `qwen2.5-0.5b-instruct-q4_k_m.gguf` |
| Exact bytes | `491400032` (468.6 MiB) |
| SHA-256 | `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db` |
| Upstream license metadata | Apache-2.0 |

Source readback on 2026-11-03:
[official model blobs API](https://huggingface.co/api/models/Qwen/Qwen2.5-0.5B-Instruct-GGUF?blobs=true),
[pinned file page](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/blob/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf),
and [pinned license](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/blob/9217f5db79a29953eb74d5343926648285ec7e67/LICENSE).
The runtime fetches the file at that commit, never `main` or `latest`.
A matching checksum proves identity against this catalog, not model safety,
publisher signing, loaded identity, quality or operational acceptance.

## Download and privacy boundary

This is explicit online maintenance. The public host receives the model-file
request, ordinary HTTP headers and the computer's public connection address.
No packet metadata, audit rows, prompts, model responses, tokens, credentials or
personal paths are sent. The downloader ignores ambient proxy and Hugging Face
token settings; it uses direct HTTPS with certificate and hostname validation.
It performs no inference and contacts no Ollama API.

The exact HTTPS hostname allowlist is in `model_library.DOWNLOAD_HOSTS`. It
contains Hugging Face and its documented file CDN/legacy download endpoints,
not arbitrary subdomains. Evidence:
[HF download/firewall documentation](https://huggingface.co/docs/hub/models-downloading#downloading-behind-a-proxy-or-firewall)
and [HF staff's legacy redirect list](https://discuss.huggingface.co/t/how-to-get-a-list-of-all-huggingface-download-redirections-to-whitelist/30486/11).
Each redirect is checked before connecting: HTTPS/443 only, no credentials or
fragment, bounded URL and at most three redirects. DNS answers must all be
global unicast addresses; one address is pinned for each connection while TLS
validates the original hostname. Infrastructure changes fail closed; the app
does not broaden the list or fall back to a shell command. Response headers
must declare exactly the pinned byte count with no compression or chunking.
Signed redirect URLs and response bodies are never logged or stored in SQLite.

One in-process operation and a lifetime cross-process file lock permit one
staging operation at a time. Preflight requires the file size plus 256 MiB
available on the staging filesystem. This is a check, not a disk reservation:
other processes can consume disk space, and disk exhaustion fails the job.
Reads/writes are at most 64 KiB; total staged bytes cannot exceed the exact
catalog size. There are no retries or automatic resume requests.

The cooperative staging deadline is 30 minutes with 10-second socket timeouts.
Cancellation is checked before network work, between reads/writes, while
hashing and before publication/success. It closes only this downloader's
connection and removes its partial file. A blocking DNS/filesystem/native call
can delay cancellation or the deadline; this is not process containment or a
hard wall-clock guarantee. No shared Ollama daemon transfer needs to be killed.

## Private files and SQLite state

Files live below `~/.local/share/megalodon/model-library`, admitted with the
existing descriptor-based trusted-ancestry and owner-private checks. The
directory is private, files are mode 0600, and symlinks, hardlinks, FIFOs and
unsafe modes are refused. Only the fixed catalog's own `.part` names can be
cleaned. Existing final files are never overwritten or silently deleted.

Downloads use exclusive partial files, exact size/SHA-256 checks, file fsync,
exclusive final publication, directory fsync and a second hash of the published
file before recording success. Valid existing staged files are rehashed and
reused without a network request. A mismatch fails and preserves the final
file for operator inspection; it never receives a verified record.

`library.sqlite3` is separate from core telemetry and the AI receipt store.
It uses descriptor-admitted SQLite, a fixed schema, parameterized SQL and a
1 MiB database ceiling. `models` records catalog ID, expected SHA-256/size,
last-check state/time. `jobs` records a random job ID, catalog ID, fixed state,
bounded byte count, fixed error code and times. It stores no weight blobs,
prompts, provider output, personal paths or redirect URLs. History is capped at
64 jobs; a full journal refuses new downloads. The HUD projects at most the
latest 16 jobs from validated in-memory snapshots; GET never writes the ledger.
No history pruning/automatic retention job is introduced.

Initial tables and schema version commit in one transaction. An interrupted
first start can recover an existing empty database, or an exact known empty
version-zero partial schema, while holding the exclusive library lock. Unknown
objects (including triggers/indexes), changed schemas, populated partial tables
and unexpected versions are refused; they are never reset or deleted.

States are `downloading`, `verifying`, `staged_verified`, `failed`, `cancelled`
or `interrupted`. File publication precedes one transaction recording both the
verified model and successful job. A database/commit failure is not displayed
as success. At the next **explicit** staging/check action, the exclusive lock
allows abandoned in-progress jobs to become `interrupted`, and safe partials
are removed. Nothing resumes online. A complete file left by a crash is
rehashable with **Check staged files and space**. A verified receipt describes
the check time; it is not continuous monitoring of later file changes.

## Remaining activation boundary

Staging does not create an Ollama model, change the saved model preference,
load a model or enable responses. The release remains `UNBOUND` under
`local_model_runtime`; closing historical issue #446 did not supply an accepted
runtime binding. Ollama import, exact loaded identity/containment and acceptance
remain separate work. This workflow makes the requested download and SQLite
staging step reviewable without claiming that later inference works.

Tests use inert fixture bytes and fake HTTP responses. Native Linux tests cover
the real private SQLite/file-lock boundary and end-to-end staged-file readback.
No test fetches upstream weights. A real publisher/CDN download on the installed
operator host remains an explicit operational acceptance check.

## Check an installed copy without starting it

The normal installer `status` command describes release/artifact health. It does
not establish that the model-library source matches a particular merged commit.
From a reviewed checkout, run this separate read-only observation on the actual
operator PC:

```bash
python3 -B tools/check_model_library_install.py
```

The checker locates exactly one package under the managed `current` release,
honoring `XDG_DATA_HOME` when configured. It refuses a selector outside the
managed releases directory or ambiguous Python package locations. For an
unmanaged copy, explicitly supply its actual package directory:

```bash
python3 -B tools/check_model_library_install.py --package-dir /absolute/installed/site-packages/megalodon
```

Managed discovery requires real directory ancestry, an absolute data home and
one direct child of the managed `releases` directory. Only the `current`
selector may be a symlink, with either an absolute target or a relative
`releases/<release-id>` target. Application, releases, release and package
directory descriptors remain pinned during source observation. Before reporting,
the checker rechecks their path identities and the selector's link identity and
target. A changed selection discards all file results and reports
`INSTALLATION_CHANGED`; it never retries against a different installation.
Discovery also retains descriptors and rechecks metadata for venv/lib and every
existing Python-version and site-packages directory it considers, including
those without a MEGALODON package. A package added below an already present
version directory, or a version directory added or removed during observation,
cannot leave an observed change labeled as a unique-package match.
The final selector check follows directory revalidation.
This detects observed replacement during the check, not changes made afterward
or an adversary able to conceal and restore changes between observations.

It reads at most 1 MiB per file for six named source files, refuses links and
nonregular files, and compares SHA-256 with the recorded source from merged
commit `ba3303eb0df043a2a6a5d6a88a89cff1970c5ba4` (#745). It checks file/directory
identity for observed replacement. Output contains fixed filenames, hashes and
states; personal paths and source contents are omitted. A later legitimate
version can differ from this historical pin and requires review; there is no
automatic update or repair.

The checker never imports installed MEGALODON code, reads the private model
catalog or weights, contacts Ollama, executes a subprocess, writes an evidence
file, or changes services. `SOURCE_FILES_MATCH` is source parity at the check
time, not a full installation check, running-process fingerprint, loaded-byte
attestation or acceptance. A blocked native filesystem call can still delay
completion. A cloud-workspace result does not establish the owner's installed
PC state.

The dedicated `tests/browser_model_library.py` rehearsal uses the real rendered
HUD with synthetic responses and intercepted library POSTs. It covers keyboard
reuse, failed-check invalidation, interrupted reload/polling, stale identities,
catalog/permission consent and 390/1440-pixel reflow. Its route handler never
passes library actions to a real backend. The main browser workflow runs it and
retains synthetic screenshots; only an actual successful run is browser evidence.
