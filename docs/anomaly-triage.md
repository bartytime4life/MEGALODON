# Run an offline anomaly review

The one-shot Linux command compares two selected metadata baselines and emits
one bounded JSON receipt to stdout. Qwen is disabled by default. The command
does not collect traffic, start a sensor, poll, schedule work, modify a database,
write a report file or change the host. Run it as a non-root, capability-free
analyst account, after the input source and collection scope are authorized.

Use an installed, reviewed MEGALODON checkout. The example working directory is
`~/Projects/MEGALODON`. Keep selected files in an operator-controlled private
local directory. Existing offline analysis produces `baseline.json`; copy the
two reviewed baselines into the selected directory with distinct names. Do not
combine TShark packet counts with Zeek flow counts or different source IDs.

Create `windows.json` to describe the real selected windows. This is a
synthetic shape example, not proof of collection time or completeness:

```json
{
  "schema": "offline-anomaly-windows-v1",
  "as_of": "2026-09-15T02:01:00Z",
  "reference": {
    "source_id": "source-0001",
    "started_at": "2026-09-15T00:00:00Z",
    "finished_at": "2026-09-15T01:00:00Z",
    "completeness": "complete"
  },
  "current": {
    "source_id": "source-0001",
    "started_at": "2026-09-15T01:00:00Z",
    "finished_at": "2026-09-15T02:00:00Z",
    "completeness": "complete"
  }
}
```

`as_of` is an explicit replay/evaluation basis. It is not replaced by the wall
clock, and the command cannot attest the operator's timestamp declarations.
Choose `unknown` or `incomplete` when appropriate; the scorer will abstain.
The [pipeline contract](anomaly-pipeline.md) defines eligibility and thresholds.

```bash
cd "$HOME/Projects/MEGALODON"
.venv/bin/python -m megalodon.offline.triage \
  --input-root "$HOME/Analysis/case001/triage" \
  --reference reference.json --current current.json --windows windows.json
```

Read `dossier.status`, supporting counts and limitations before interpreting
candidate changes. A candidate is not an infection verdict; `no_candidates`
does not mean safe, and `abstained` means eligibility was not established.

## Optional local Qwen explanation

First verify and separately operate a truly local Qwen model through Ollama.
Prepare a `qwen-anomaly-registry-v1` under the [separate anomaly policy](anomaly-advisory-contract.md)
with the actual approved model alias/artifact digest and fixed limits. Review
its canonical JSON fingerprint independently and set `MEGALODON_ANOMALY_REGISTRY_PIN`
to that approved value. Do not use the synthetic test registry as approval, and
do not silently compute a replacement pin from whatever file happens to exist.
No model installation, pull, discovery, health probe or service start is part
of this command. Provider egress and loaded model bytes remain operator gates.

```bash
cd "$HOME/Projects/MEGALODON"
.venv/bin/python -m megalodon.offline.triage \
  --input-root "$HOME/Analysis/case001/triage" \
  --reference reference.json --current current.json --windows windows.json \
  --qwen --registry qwen-anomaly-registry.json \
  --registry-sha256 "${MEGALODON_ANOMALY_REGISTRY_PIN:?Set the independently approved registry pin}" \
  --question-type explain_anomalies
```

The model receives only a recomputed, bounded aggregate evidence projection.
It cannot select tools, endpoints, commands or response actions. The deterministic
dossier remains in the same receipt if the model is denied, refuses or fails.
The new-policy receipt is not yet wired into #176's v1 dashboard display.

| Exit | Meaning |
| --- | --- |
| 0 | Evidence evaluation completed; AI was not requested, not eligible, answered or abstained. Inspect both statuses. |
| 1 | Input/platform validation failed; no evidence or provider request is claimed. |
| 2 | Invalid/duplicate arguments; no selected file was read. |
| 3 | Evidence retained, but the requested AI explanation was denied or failed. |

`provider_request_performed` is false/true from the provider accounting, or null
if an unexpected provider exception or malformed return makes completion unknown. Unknown is never
reported as a confirmed no-request. There is no retry. JSON escapes model text
for terminal safety. Baseline reads are limited to 1 MiB each, windows/registry
to 8 KiB each, and the complete emitted receipt to 32 KiB. Descriptor-relative
reads reject traversal, symlinks, devices and multi-link files; input-change
checks are not an atomic multi-file snapshot. The command does not enforce OS
isolation or the egress policy of the separately operated provider.

The [shared result validator](advisory-result-integrity.md) checks the returned
type, outcome/code, separate anomaly policy, model identity, bounded display
text and request accounting before serialization. Validation and serialization
stay inside the provider failure boundary. A malformed result produces the
fixed `PROVIDER_COMPLETION_UNKNOWN` error, exit 3 and the unchanged dossier;
its claimed request flag and arbitrary methods are not trusted. A valid
provider error, including an explicit non-normal completion reason, retains
the provider's known request flag instead of converting it to unknown.

Synthetic acceptance covers the real non-root/capability-free command plus
mocked Qwen transport. Installed model behavior, live sensor coverage, useful
triage quality, calibrated accuracy, dashboard integration and repeated
operation remain separate review and acceptance gates.
