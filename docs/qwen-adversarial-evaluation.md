# Qwen adversarial evaluation receipt

Status: ● **implemented offline receipt validation; no evaluation executed**  
Related gate: issue #261

`tools/qwen_evaluation_receipt.py` validates one explicit, privacy-minimized
receipt:

```bash
python tools/qwen_evaluation_receipt.py evaluation-receipt.json
```

The tool performs no model request, corpus read, provider discovery, signature
verification, process inspection, host change, or approval transition.

To check that a receipt accounts for exactly one frozen corpus manifest:

```bash
python tools/qwen_evaluation_manifest.py corpus-manifest.json
python tools/qwen_evaluation_receipt.py evaluation-receipt.json --manifest corpus-manifest.json
```

The manifest tool performs no fixture read, model request, provider discovery,
signature verification or host change. The receipt projection reports
`manifest_binding` as `MATCHED` only when `--manifest` was given and the
receipt cites that manifest's canonical-file digest, corpus, candidate
profile/comparison boundary, total and per-category denominators, and
unknown-evidence-ID count; any mismatch refuses with a fixed
`RECEIPT_MANIFEST_*` code.

## Corpus manifest

The manifest is the privacy-minimized list to freeze and sign before any run,
as required by the [#446 owner-decision packet](qwen-446-owner-decision-packet.md).
It binds the candidate binding, profile and comparison-boundary digests, the
corpus ID and corpus digest, the denominator, and an ordered list of opaque
`case-NNNN` cases. Each case records its category, fixture SHA-256, expected
`ANSWER`/`ABSTAIN`/`DENY`/`ERROR` outcome, and whether it is an
unknown-evidence-ID case. The contract is in
[`contracts/local-model-evaluation/v1`](../contracts/local-model-evaluation/v1/README.md).

`MANIFEST_VALIDATED` means the structure, coverage and canonical digest are
consistent. It does not mean the manifest was signed, the signature was
verified, the fixtures exist or match their digests, or any case was run.

## Required corpus categories

The closed category order is:

1. injection;
2. fabricated evidence IDs;
3. Unicode/control text;
4. privacy;
5. exhaustion;
6. cancellation;
7. out-of-distribution requests.

Each category records only total, passed, and failed counts. The receipt also
binds the corpus, manifest, detached signature, signer-key fingerprint, and
external verification-receipt hashes. Public receipts must not include raw
prompts, evidence, provider responses, or advisory text.

## Hard gates

An operator-observed receipt stays `EVALUATION_HOLD` when any of these are true:

- detached-signature verification is not recorded;
- any case remains incomplete;
- any case failed;
- an unknown evidence ID did not deterministically reject;
- answer, abstain, and error were not proven distinct; or
- any prohibited effect has a non-zero observation count.

The prohibited-effect vocabulary covers network access outside literal
loopback, filesystem mutation, subprocess/shell use, tool invocation, detector
authority, action authority, and persistent model-state change.

## Truth boundary

`EVALUATION_RECEIPT_VALIDATED` means the supplied accounting is internally
consistent and all named hard gates are reported complete. The validator does
not authenticate the receipt origin, cryptographically verify the signature,
prove that tests were run, establish model accuracy, prove provider containment,
select a model, close #261, or authorize release or deployment.
