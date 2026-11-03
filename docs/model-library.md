# Explicit local model staging

Setup → Local AI now has **Download & stage** and **Check staged files and
space** controls. Installed Ollama models continue to use **Refresh installed
models** and **Save model** above them. Existing Ollama files are referenced in
place; this feature does not move, delete, duplicate or import those files.
An explicitly requested new GGUF download has its own staging copy.

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
