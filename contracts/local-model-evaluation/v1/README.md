# Local-model adversarial evaluation receipt v1

Status: ● **implemented contract and offline validator; native signed-corpus evidence required**.

The receipt binds one profile and comparison boundary to a corpus manifest,
external detached-signature metadata, the exact seven issue #261 categories,
per-category accounting, distinct outcome accounting, unknown-evidence-ID
rejection, resource observations, and `0/N` prohibited-effect evidence.

Raw prompts, raw evidence, raw provider responses, and raw advisory text are not
part of this contract. The validator checks internal consistency only. It does
not read the corpus, invoke a model, authenticate the signer, or perform
cryptographic signature verification. `externally_verified: true` records an
external verification result whose own receipt is separately hashed.

An operator-observed receipt reaches `EVALUATION_RECEIPT_VALIDATED` only when:

- all cases are completed;
- every category has zero failed cases;
- at least one unknown-evidence-ID case is recorded and all such cases reject;
- answer, abstain, and error remain distinct;
- every prohibited effect is observed as `0/N`; and
- the detached-signature verification is recorded as externally verified.

This state is not model acceptance. Provider containment, artifact provenance,
owner binding, independent security acceptance, and release/deployment remain
separate HOLDs.

## Corpus manifest

`manifest-schema.json` describes the frozen, privacy-minimized corpus manifest
that a receipt's `corpus.manifest_sha256` cites. `megalodon.model_evaluation`
enforces what the schema cannot:

- the file must be exact canonical JSON (sorted keys, no insignificant
  whitespace, no trailing newline), so `sha256sum` of the file equals the
  validator's `manifest_sha256`;
- case IDs are opaque `case-NNNN` values in strictly increasing numeric order,
  grouped in the closed category order, and each fixture digest appears once;
- every category has at least one case, at least one case is an
  unknown-evidence-ID case and none of those expects `ANSWER`, and the corpus
  expects at least one `ANSWER`, `ABSTAIN` and `ERROR`; and
- `total_cases` equals the number of listed cases.

A case records only its ID, category, fixture SHA-256, expected outcome and
unknown-evidence-ID flag. Prompts, evidence, fixture bytes and expected text
cannot be represented. `operator_frozen` manifests reach `MANIFEST_VALIDATED`;
that state does not read fixtures, verify the detached signature, run the
corpus, or prove that a case exercises its category.

With a manifest, the receipt validator also requires the receipt to cite that
manifest's digest, corpus and candidate profile/comparison boundary, to use its
total and per-category denominators, and to execute no more unknown-evidence-ID
cases than it lists (exactly that many once the run is complete). An
`operator_observed` receipt must cite an `operator_frozen` manifest. Once the
run is complete, the receipt's outcome counts may differ from the manifest's
expected-outcome totals only by what its failed cases explain. A passed case
keeps its expected outcome, so only a category's failed cases can leave that
category's expected outcomes: every outcome reported below its expected total
must be coverable by failed cases from categories that expect it. A receipt
whose cases all passed therefore reports exactly the expected outcomes. The synthetic
`fixtures/manifest-synthetic.json` matches `fixtures/accepted-synthetic.json`
apart from that receipt's placeholder `manifest_sha256`.
