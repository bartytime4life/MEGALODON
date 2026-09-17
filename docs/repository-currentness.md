# Repository currentness v1

Issue #254, M01. This development-only tool formats and validates explicitly
captured GitHub evidence after the #253 truth repair. It imports no MEGALODON
runtime code and performs no network, subprocess, Git write, host mutation,
model invocation, or output-file write. Install the existing `.[test]` extra
to supply JSON Schema validation; the core runtime gains no dependency.

## Capture and validation

1. Read `main` before collection and record its exact commit. Read that Git
   commit and recursive tree. Do not treat a locally invented SHA as readback.
2. Capture the exact GET queries listed in
   `contracts/repository-currentness/v1/schema.json`: open issues (including
   PR entries), open PRs, exact-commit checks/workflows, releases, the ruleset
   collection and the current default-branch ruleset `22394782`.
3. Select only the schema's fields. Preserve **all** collection rows; never
   clip to fit. Version 1 refuses 100 or more rows, truncated trees, missing
   reads, another/missing ruleset, an unsupported applicability condition, or
   inconsistent counts. A larger collection or changed ruleset profile needs
   a reviewed contract extension, not silent truncation. Never replace an
   unavailable response with an empty successful response.
4. Capture only the six allowlisted tree entries. Keep their Git blob IDs;
   they identify reviewed repository source, not captured network input. Map
   each claim to its fixed sources/tests below. A successful check reference
   must exist on the same commit; no check means no test receipt, not failure.
5. Read `main` last. All reads must fit one nondecreasing 15-minute capture
   window bracketed by equal branch readbacks. This detects observed movement,
   not an intervening change-and-return or an atomic GitHub snapshot. Record
   unavailable/ambiguous reads explicitly and retain the resulting refusal.
6. In a trusted checkout with those exact source bytes, run:

   ```bash
   python tools/repository_currentness.py /absolute/path/to/capture.json
   ```

The caller may save stdout in an operator-selected private location outside
the checkout. A successful invocation exits 0 with one complete JSON object;
failure exits 3 with a closed reason and no source/caller content. Input is
limited to 128 KiB and depth 12; source files to 2 MiB each. Duplicate keys,
non-finite numbers, unknown fields, unsafe references, symlinks, special files,
and changed/mismatching source bytes refuse. Trusted checkout ancestry must not
be concurrently replaced; filesystem stalls have no hard deadline guarantee.

## Meaning and limits

`status=validated` means only that the supplied capture is structurally and
internally consistent, and the allowlisted local bytes match its selected tree
entries. The tool **does not authenticate GitHub responses**, prove tree
membership independently of the captured tree, prove a test covers a claim,
or rerun the tests. The operator/reviewer owns truthful capture and claim
classification. Do not use this tool to certify an untrusted capture.

The manifest embeds the closed capture plus SHA-256 digests of canonical JSON
for the capture and each selected excerpt: sorted keys, ASCII escaping, compact
separators, no non-finite numbers, no trailing newline. Array order is preserved.
These are digests of **selected excerpts**, not raw HTTP bodies, signatures, or
credentials. The enclosing manifest can be hashed separately by its custodian.

Claims retain `verified`, `observed`, `proposed`, `blocked`, `unknown`, or `stale`;
validation never promotes them. `verified` claims with test references require
at least one captured successful same-commit check. That link is a necessary
reference check, not independent acceptance. `basis=synthetic` remains synthetic
even if all structural checks pass. The committed fixtures are synthetic test
material, not repository receipts; their source blobs belong to a temporary
test checkout.

| Claim ID | Source | Test reference | Scope |
| --- | --- | --- | --- |
| `firewall-refusal` | `megalodon/firewall.py` | `tests/test_firewall.py` | Source refusal boundary; no live firewall test |
| `storage-documentation` | `docs/storage-layout.md` | `tests/test_documentation_currentness.py` | Documented paths, ignore limits and real entry points |
| `site-parity-unverified` | `docs/site-source-alignment.md` | `tests/test_documentation_currentness.py` | Withheld hosted parity claim; no Site deployment read |
| `control-disposition` | `SECURITY_REVIEW.md` | None | Delivered, declined and outstanding obligations |

Ruleset fields are a selected profile, not exhaustive branch administration or
proof that an actor cannot merge. Required approvals may truthfully be zero.
No protection change, review policy change, approval, release, deployment,
issue closure or installed-host acceptance follows from validation.

## CI and next gate

The existing `python -m pytest -ra` entry point discovers
`tests/test_repository_currentness.py` in both checkout and sdist CI. Tests
exercise contract fixtures, refusal behavior, local path identity, privacy,
and absence of network/process/write calls. CI does not fetch mutable GitHub
state or pretend a frozen fixture is current.

After owner review and merge, collect a **new** receipt naming the immutable
merge SHA and tree, run this tool against that checkout, and record its manifest
digest and readback time in the existing coordination record. A pre-merge
candidate cannot know its future squash SHA. Keep #254 open until that receipt
exists. Then #256's contract-only recovery slice is the next dependency step;
#255 still requires the owner's actual license selection.
