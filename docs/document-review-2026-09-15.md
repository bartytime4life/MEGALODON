# Document review and selected engineering work

Repository basis: main `caf7e4bd441ddd33facd2b7d406e4abe5e7e72c9`.
This is a selective engineering pass across the 24 supplied documents, using
extracted text, contents and relevant sections. It is not a cover-to-cover audit,
independent authentication of the incident report, or an operational assessment.
The connected Drive coordination log was read; its leading checkpoint still
used `a9ab662a...`. Current GitHub and executable code resolve historical claims.

## Decisions against current code

The Advancement and Local Command Center blueprints correctly prioritize
trustworthy evidence and bounded reads. Many of their historical gaps are
already implemented: contained firewall apply, atomic event bundles, a separate
read-only dashboard store, bounded capture, capacity stops, and browser checks.
PR #176 is now on main. Open #177 covers hypothetical workload arithmetic; #179
covers enabled-provider denials; #178, #180 and #181 form the anomaly evidence,
Qwen-policy and triage stack. Those changes should not be duplicated here.

Two independent gaps remained open at this document's `caf7e4bd` basis:

1. **JSONL admission:** repeated keys silently replace prior values and unknown
   fields disappear during projection. Reject ambiguity before constructing
   evidence; preserve truthful prefix and failed-run receipts.
2. **Dashboard database work:** output row limits and connection busy timeouts
   do not bound SQLite execution work. Add per-read VM/deadline budgets with
   complete-result-or-unavailable behavior, retaining existing SQL authority.

The second item is a separate proposed implementation at this document's commit,
not a claim that its code is present here. Both choices strengthen the evidence
appliance without adding another integration or overlapping the AI stack.

**Resolved as of current `main`.** Both gaps are implemented and documented
separately; do not duplicate this work. JSONL admission rejects duplicate keys
and unknown fields (`megalodon/capture.py`'s `_jsonl_object`/`_jsonl_integer`
hooks; see [`docs/jsonl-admission.md`](jsonl-admission.md)). Dashboard reads
enforce a cooperative SQLite progress-handler VM/deadline budget with
complete-result-or-`503` behavior (`Store`'s dashboard read path in
`megalodon/storage.py`, raising `DASHBOARD_STORE:READ_BUDGET_EXCEEDED`; see
[`docs/dashboard-query-budget.md`](dashboard-query-budget.md)). This paragraph
is a documentation-currentness correction only; it changes no runtime,
schema, dependency, or review-control behavior.

## Supplied source disposition

PDF references use one-based PDF pages. For remaining references, the basis is
contents/search excerpts and prior selective inspection, not an adopted API or
implementation recipe. Source text and executable examples are not redistributed.

| Supplied document | Inspection and engineering disposition |
| --- | --- |
| MEGALODON Advancement Blueprint | Sections 2–5 and priorities: closed inputs, atomic receipts, bounded resource failure. Historical pins and governance proposals are not current authority. |
| MEGALODON Local Command Center Integration Blueprint | Operating contract, input boundary and native read-model proposals: strengthen stable seams before more integrations. |
| Repository Research Analysis Framework — Repository Not Yet Supplied | Architecture, state/side-effect and test-evidence method. Generic placeholders are not findings. |
| OpenAI–Hugging Face Incident Technical Report | Previously inspected pp. 4–6, 17–18, 20, 22–27: admission and supporting-service containment. Existing #179 addresses the selected provider regressions. |
| Building Secure and Reliable Systems | pp. 150–152: validation before data crosses a trusted application boundary; selected for JSONL. Availability/overload material informs bounded-read work. |
| Advanced-SQL-Concepts | pp. 54–55: query cost and early filtering. Evaluate the actual SQLite plan; do not assume a small result means little work. |
| A Practical Guide to Smarter Programming — efficient-r-programming | pp. 22–23, profiling discussion: establish the bottleneck before optimization. No R port or dependency. |
| advanced-data-analysis-from-an-elementary-point-of-view | Prior selective pp. 66–67 and calibration sections: held-out generalization remains a prerequisite to accuracy claims. No new scoring here. |
| Data Analysis Using SQL and Excel | Contents and prior sampling/bias sections: preserve denominators and selection limitations; defer a separate evaluation corpus. |
| AI Concepts Using Python | Data cleaning discussion, p. 67, and prior confusion-matrix material: improve admitted-data integrity before adding learned inference. |
| AI Foundations of Computational Agents 3rd Ed | Prior pp. 312–314: classifier denominators/error costs. Already relevant to #177; no duplicate calculator. |
| Artificial Intelligence A Modern Approach | Prior probability exercises, p. 528: base-rate assumptions belong in explicit evaluation, already addressed by #177. |
| Artificial Intelligence Third Edition Python Code — aipython | Generator/iteration and display material: retain streaming admission; no agent framework or executable book examples. |
| Artificial Neural Networks An Introduction | pp. 36–37: representative, reproducible and protected data precede training. No efficacy claim from synthetic parser tests. |
| Artificial Neural Networks In Real Life Applications | Evaluation/validation search excerpts: research lead requiring local representative labels, not justification for model deployment. |
| Artificial Neural Networks Models and Applications | Limited contents/search inspection; damaged extraction in some technical passages. No algorithm or implementation claim adopted. |
| Bayesian computational methods | Importance-sampling sections, pp. 10 and 14: computation requires an explicit inferential model; none is introduced here. |
| Bayesian Methods for Hackers | Prior pp. 22–25: uncertainty and sample size; complementary to #177 and the anomaly stack. |
| Black Hat Python | Network and exception-handling discussion: inert malformed-input fixtures only; no offensive code or capability imported. |
| Cloud Security Practical Guide to Security in the AWS Cloud | Reliability/control overview, pp. 19 and 35: supporting-service boundaries remain relevant; no cloud requirement or deployment. |
| Coding Freedom The Ethics and Aesthetics of Hacking | Cultural/ethical research context; no licensing choice, engineering permission or dependency inferred. |
| Android UI Design | Hierarchy/performance discussion, pp. 10–11: keep the existing focused command center; no mobile rewrite. |
| Create Graphical User Interfaces with Python | Contents/UI structure: no second GUI toolkit needed for this pass. Existing native browser acceptance remains the interface gate. |
| Build Your First Web App | UX discussion and contents: avoid feature growth without a demonstrated operator need. Preserve current degraded-state behavior. |

Deferred work includes the run/source inspector, representative labeled
assessment, installed sensor compatibility, actual model/provider containment,
and release evidence. The attachments do not authorize host operations, a
license decision, governance changes, publishing a release or merging a PR.
