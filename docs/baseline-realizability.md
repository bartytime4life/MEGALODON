# Baseline byte and time consistency

A structurally valid baseline can still describe impossible observations. At
main `ccc7b5a8ef7912d31fb076ccd030d7074d6bfd2c`, a twenty-record baseline
could claim every record was large while declaring only 1,280 total bytes.
The anomaly dossier then treated the large-record share as usable evidence.

The shared baseline validator now requires the total byte count to fall within
the exact range allowed by the three declared band counts:

| Band | Per-record byte range |
| --- | --- |
| small | 0–511 |
| medium | 512–4,095 |
| large, TShark packets | 4,096–262,144 |
| large, Zeek flows | 4,096–2,199,023,255,550 |

The lower total is `512 * medium + 4096 * large`. The upper total is
`511 * small + 4095 * medium + adapter_max * large`. Both endpoints are
included. These limits follow the existing adapter admission and band-generation
code; they do not change the size bands or introduce a threat threshold.
Calculations use exact Python integers, including flow totals above JavaScript's
safe integer range. Empty baselines remain valid only with zero total bytes.

Nonempty relative-minute distributions must also contain minute zero. The
existing generator measures offsets from the earliest admitted observation,
so a distribution starting later cannot have been generated as declared.
Unsorted input and gaps after zero remain valid and normalize deterministically.
This does not bind relative offsets to an absolute capture window.

All consumers of the shared validator inherit these checks: reference candidate
analysis, baseline comparison, anomaly dossiers and dashboard projections.
Refusal uses existing bounded errors and returns no partial successful receipt.
Previously accepted contradictory files must be regenerated or corrected from
source evidence; do not invent a total to pass validation.

## Source basis and limits

This follow-up reuses the 24-document review in
[the document decision record](document-review-2026-09-15.md). The Advancement
Blueprint's closed-source/unit and evidence requirements, the Command Center
Blueprint's comparable-evidence/read-model guidance, and the AI/Bayesian
references' emphasis on input quality support this fix. The generic Repository
Research Analysis Framework is methodology, not current implementation proof.
The source scan and current main supersede historical PR dispositions in those
records; #177, #178, #179 and #183 are now on this inspected main.

The check proves a necessary aggregate arithmetic condition. It cannot prove
that all distributions describe the same actual observations, authenticate a
producer, identify a malicious record, or establish detection accuracy.
Synthetic tests cover all combinations of small band counts, exact endpoints,
outside values, adapter parser ceilings, empty/gapped time distributions,
generated records and rejection by every consumer. The existing large-record
anomaly fixture is corrected to carry a possible byte total; its expected
candidate rules are unchanged. No I/O, model call, detector change, schema
migration, dependency or host action is added.
