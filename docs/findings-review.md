# Visual Findings review

Open **Findings** to browse retained detector, sensor and pattern observations.
Choose **Refine view** for the time range, source and recorded severity. The
search box filters the returned page; Previous and Next browse additional pages.
Coverage labels describe the actual bounded read. An empty page is not proof of
a quiet or safe network, and recorded severity is not an AI risk score.

Select an observation to see its recorded source, destination and measurements.
The activity ribbon groups the returned observations over their occupied span;
its counts sum to that page and zero-count groups have zero height. Selecting a
group exposes each original observation. Source timestamps, byte bases, references
and missing information remain available through the evidence disclosures.
Compacted findings retain qualified original links when those links are present.
Missing measurements are not reconstructed from current settings.

## Ask for another perspective

**Ask local AI** submits the selected displayed fact packet to the saved local
model. The result separates an evidence interpretation, another possibility and
missing information. Expand each explanation for its complete text, or open the
model/citation details. No cloud inference or model download is added.

Model, settings, source, context and reference checks bind a saved review to its
evidence. Changed or expired inputs invalidate reuse. Generic answers that do not
refer to a recorded subject or measurement are rejected. These checks establish
relevance and binding, not factual correctness or proof of malicious intent.
**Cancel review** cancels this workflow rather than another operator's request.

**Expected activity**, **Investigate** and **Incorrect match** save an assessment
with the finding. They do not disable a detector, approve a restriction or declare
a fix. AI output cannot apply or approve an action.

## A temporary local response

For an eligible recorded public peer, **Preview containment** requests a fresh
server-bound preview. The confirmation names the address, five-minute effect,
observed port/service hints and unknown dependencies. Shared cloud services and
other applications may be affected. A separate unchecked acknowledgement and
explicit confirmation are required, followed by the existing OS authorization.
Private/reserved/protected addresses and guarded service targets remain refused.

Changing selection, model or context, losing the connection, or preview expiry
invalidates confirmation. An ambiguous response is checked rather than replayed.
Fresh managed Defense state keeps **Release** available if the original finding
expires. Release and kernel expiry remain distinct from unverified absence.
The [Defense contract](visual-operations-defense.md) defines the underlying action.

## Local API and bounds

`GET /api/findings` requires the explicit local-check header, admitted Host/session
and a non-root local operator. It accepts only single-valued `start`, `end`,
`source`, `severity`, `limit`, `cursor` and `selected` parameters. Reads have a
31-day range limit, up to 128 source segments and 4,096 candidates; the JSON
response is capped at 256 KiB. Partial/truncated coverage remains explicit.

`POST /api/findings` uses its own per-launch Findings nonce, exact same-origin
JSON envelope and a 2 KiB body limit. The closed actions are `analyze`, `cancel`,
`feedback`, `plan_containment`, `apply_containment` and `release_containment`.
Analyze, assessment and preview requests bind the finding ID and context digest.
Applying a preview additionally requires `acknowledge_disruption: true` and a
fresh matching plan. The backend retains the existing Defense authorization.

The [HTTP contract](dashboard-http-contract.md) describes the common session and
request protections. The [Setup guide](setup-console.md) describes the selected
model's optional keep-ready policy.
