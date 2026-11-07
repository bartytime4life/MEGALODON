# Ollama pull contract investigation — 2026-11-07

Disposition: **HOLD for an Ollama transfer backend**. This investigation reads
upstream source only. It does not identify, execute or accept the installed
provider, download weights, or grant a runtime binding. MEGALODON's existing
explicit pinned GGUF downloader from PR #733 remains separate; reuse of local
Ollama files uses the offline verifier from PR #731.

## Exact upstream scope

The official release API reported `v0.40.15`, published 2026-11-03T22:52:31Z.
The tag ref resolved to commit
`02480ca2a47153e1f9c31cbe1e05536da97ce1ba` during this investigation.
The following source files were read at that tag. This is a source-inspection
pin, not a supported/accepted installed build declaration.

| Question | Source observation | Consequence for MEGALODON |
| --- | --- | --- |
| Request and progress | `POST /api/pull`; `PullRequest` has model, runner, stream and legacy fields. Progress has component digest, total and completed bytes. | A tag and progress message alone do not pin the whole artifact closure or enforce a cumulative byte/disk cap. |
| Request lifetime | `PullHandler` derives a context from the incoming request and calls `PullModel`. | Closing a client request concerns that request; do not equate it with stopping all transfer work. |
| Shared download | `downloadBlob` uses a shared digest-keyed manager; new work runs with a background context. `Wait` acquires/releases references; the last release calls its cancel function. | **Inference from source:** another client holding a reference can keep shared transfer work alive after MEGALODON disconnects. Real overlapping-client tests are still required. |
| Existing bytes | An already present blob produces a completed cache-hit progress observation. | Independent post-download closure verification is still needed; progress is not an artifact-verification receipt. |
| Store mutations | `PullModel` writes a manifest, may write a downgrade anchor, and can prune unused layers unless NoPrune is configured. Digest-mismatch handling can remove a blob. | A generic pull does more than an isolated MEGALODON staging write. No daemon reconfiguration or shared-file deletion is authorized by the library feature. |
| Pin and bounds | The inspected request structure has no manifest comparison pin, total-byte ceiling, disk reservation or whole-job deadline field. | Source/tag drift, disk guarantees and cancellation cannot be delegated to this request as currently described. |

Primary sources at the resolved commit:

- [Release metadata](https://api.github.com/repos/ollama/ollama/releases/tags/v0.40.15)
- [Tag reference](https://api.github.com/repos/ollama/ollama/git/ref/tags/v0.40.15)
- [Request types, lines 857–866](https://github.com/ollama/ollama/blob/02480ca2a47153e1f9c31cbe1e05536da97ce1ba/api/types.go#L857)
- [Pull handler, lines 1486–1553](https://github.com/ollama/ollama/blob/02480ca2a47153e1f9c31cbe1e05536da97ce1ba/server/routes.go#L1486)
- [Reference counting and shared download, lines 470–550](https://github.com/ollama/ollama/blob/02480ca2a47153e1f9c31cbe1e05536da97ce1ba/server/download.go#L470)
- [Pull mutations, lines 1193–1340](https://github.com/ollama/ollama/blob/02480ca2a47153e1f9c31cbe1e05536da97ce1ba/server/images.go#L1193)
- [Official current pull documentation](https://docs.ollama.com/api/pull)

## Required evidence before enabling Ollama transfers

An approved future experiment must identify the exact daemon build and binary
hash, use a disposable store, and measure request cancellation, completion and
disk growth with and without a concurrent client. Exercise restart and partial
recovery, out-of-space behavior, manifest/tag replacement between preview and
transfer, unexpected layers, redirects and provider errors. Preserve logs
privately and expose fixed codes only. Test that an explicit protected click is
the sole transfer trigger; startup, selection, polling and recovery must remain
offline. No automatic retry or daemon restart is implied by an interrupted job.

Until those tests establish an acceptable contract, there is no Ollama pull
action in the candidate, no generic provider-method exception and no change to
`local_model_runtime.binding_failure()`. Downloads, local byte consistency,
loaded identity, independent evaluation, owner acceptance and runtime admission
remain separate evidence classes.
