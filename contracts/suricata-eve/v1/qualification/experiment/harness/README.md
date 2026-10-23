# Offline Suricata laboratory candidate

Status: **synthetic controls and harness tested; Suricata not executed**.

This standalone, opt-in Linux laboratory builds on merged PR #668. It is not
called by MEGALODON, its CLI, HUD, EVE consumer, installer, or CI. It accepts no
interface, arbitrary producer arguments, rule download, engine installation,
upgrade, model, service, or network option. It never creates an acceptance
receipt or changes the declared installed-producer profile.

## Inputs and controls

`inputs.json` SHA-256 binds the existing independently authored study PCAPs,
generator, original manifest/configuration/rules, this harness, all three
new controls, and separate laboratory rule sets/configuration. The original
research packet and its `not_run` receipt remain historical evidence.

| Run | Fixed input | Required observation |
| --- | --- | --- |
| TLS positive control | Unsplit ClientHello; `fragmented.example` | Exactly one SID 9900001 alert with `app_proto=tls` |
| TLS study | Existing header split across two TLS records | Same exact alert; a complete zero-alert result is an observed oracle failure |
| TLS negative control | Valid, equal-length `mismatched.example` ClientHello | Zero alerts |
| PCRE study | Existing 32/64/128 × 512-byte streams, three runs each | At least one SID 9900002 alert in every run |
| PCRE progress control | Same captures, plus a nonmatching `content:"*mcH"` rule | Same SID 9900002 requirement; SID 9900003 must never alert |
| PCRE negative control | 512 horizontal spaces | Zero alerts |

The PCRE progress control follows the mechanism described in
[upstream ticket 8684's fix](https://github.com/OISF/suricata/commit/f87b8e64a5fb80788897f7a9073c5407a2f5bc96):
a content-prefilter group advances raw-stream progress. TLS and PCRE rules
are loaded separately with `-S`, preventing the TLS rule from contaminating
the PCRE-only rule-group comparison. Chunk-size randomization is disabled in
`lab.yaml` for this synthetic laboratory only. Fixtures use documentation
addresses, fixed packet timestamps, valid checksums, and no captured traffic.

Zero alerts on a negative control are useful only together with the same
binary's positive controls. Missing files, malformed/truncated JSONL, extra
SIDs, wrong addresses/protocol, and duplicate TLS alerts cannot satisfy the
oracles. An empty, complete EVE file is allowed only for a zero-alert oracle.

## Reproduce without an engine

From the repository root, use Python 3.11+ on Linux:

```bash
python contracts/suricata-eve/v1/qualification/experiment/harness/offline.py \
  --report /tmp/suricata-input-check.json
python contracts/suricata-eve/v1/qualification/experiment/harness/offline.py \
  --preflight --report /tmp/suricata-containment-check.json
python -m pytest -q tests/test_suricata_offline_lab.py \
  tests/test_suricata_engine_fixture_oracle.py tests/test_suricata_engine_qualification.py
```

Reports are create-only. Exit 2 means not run, unavailable, or non-pass. A
preflight launches only `/usr/bin/true` inside the required sandbox. The
checked-in `verification-environment.json` records that network namespace
containment was unavailable in the verification runner and no engine was
attempted. No Suricata executable or reviewed binary identities were available.
Helper-process tests exercise timeout, file limits, CPU accounting, and cleanup;
they are not native Suricata tests or successful namespace-containment evidence.

## Native prerequisites and fixed procedure

Execution requires bubblewrap, working unprivileged user/network/PID namespaces,
and two **already built, independently qualified local binaries**. Nothing
fetches or builds them. Supply a JSON identity file for each binary, containing
exactly these fields:

```json
{
  "binary": "/absolute/path/to/reviewed/suricata",
  "sha256": "<64 lowercase hex digits>",
  "version": "8.0.7",
  "source_commit": "<40 lowercase hex digits>",
  "contains_commits": [],
  "build_record": "/absolute/path/to/independently-reviewed-build-record",
  "build_record_sha256": "<64 lowercase hex digits>",
  "review_reference": "<actual independent build review reference>"
}
```

For the candidate, use its exact reported version and put both research commit
IDs from `offline.py:COMMITS` in `contains_commits`, in that order. An independent
review must verify source ancestry, the build-to-source/binary relationship,
compiler/dependency identity, and suitability of comparing that candidate with
8.0.7. The harness verifies hashes, native version output, and the required
attestation fields. It **cannot authenticate an operator-supplied build
attestation or establish ancestry from executable bytes**. Hashes identify
content; they do not establish its trust or authorization. Do not fill unknown
fields with guesses. Absence of either reviewed identity remains a hold.

After independent input review, pin the reviewed `inputs.json` digest explicitly:

```bash
python contracts/suricata-eve/v1/qualification/experiment/harness/offline.py \
  --execute --expected-inputs-sha256 REVIEWED_INPUTS_SHA256 \
  --baseline-identity /absolute/path/baseline.json \
  --candidate-identity /absolute/path/candidate.json \
  --report /absolute/path/new-observation-report.json
```

The fixed argument vector reads one completed PCAP using `-r`, the bound
configuration, `-S` dedicated rules, and `--runmode single`. Both binaries and
all packet inputs are copied from verified bytes to a private temporary
directory before use. No caller environment, shell, credentials, home directory,
host `/etc`, or host network namespace is exposed. System executable/library
directories are mounted read-only for the existing build's loader dependencies;
their provenance must be covered by the independent environment/build review.

Every child inherits hard 512 MiB `RLIMIT_AS`, ten CPU seconds, zero core size,
64 descriptors, and affinity to one allowed CPU. Bubblewrap drops capabilities
and unshares namespaces. The packet-processing runmode is single; this does not
claim that Suricata has no ancillary internal threads. A parent outside the
producer enforces elapsed time, kills/reaps a timed-out process group, and uses
`wait4` process CPU/resource totals. Each TLS or PCRE case receives a cumulative
ten-second elapsed budget **per producer**, including its controls/repetitions.
The version probe has its own ten-second bound. Exhausted budgets create explicit
`case_budget_exhausted` records without starting the remaining runs.

Only precreated `eve.json` and `diagnostic.log` are writable in the output
directory; each has a hard 512 KiB file limit, keeping their aggregate at or
below 1 MiB. Temporary and output directories otherwise mount read-only.
Reaching either file limit is non-pass. Smaller per-file limits are deliberately
stricter than the research packet's aggregate ceiling. Fixture byte/packet
ceilings are checked before execution. Symlinks, FIFOs, identity mismatch,
unavailable isolation, nonzero exit, timeout, incomplete output, and unexpected
results are explicit non-pass states; there is no uncontained retry.

## Interpretation and evidence limits

The report records each run's status, count, EVE digest, output bytes, wall time,
whole-process CPU time, and peak RSS. The hard address-space ceiling is enforced
by the kernel; RSS is not relabeled as measured virtual address space. EVE and
diagnostic content is discarded with the temporary directory. The report is
privacy-minimized observation evidence, not retained raw-EVE acceptance evidence.
Its content hash covers canonical JSON with `report_sha256` omitted.

For each binary and rule mode, compute median CPU of three repetitions at each
size and record exact numerator/denominator ratios for both doublings. The
original packet's 3.0 bounds are recorded as smoke-test observations. Whole-process
CPU includes engine startup, configuration/rule loading, and sandbox overhead;
small ratios can therefore hide quadratic scanning. A flat ratio **never proves
the fix**. PCRE complexity qualification remains `inconclusive` until a separately
reviewed, noise-aware measurement of scan work discriminates the affected path.

Compare the two complete reports side by side: both must satisfy positive and
negative controls before interpreting a TLS difference. Baseline failure plus
candidate success supports only this synthetic continuity case. Both succeeding
does not demonstrate that the candidate introduced the fix. Any missing,
timed-out, truncated, or unexpected run prevents a complete comparison.

Even native observations retain `acceptance_authority=false` and
`producer_acceptance=not_established`. No result automatically changes the
upstream-fix claim, installed-producer acceptance, operational privacy, release
authority, or MEGALODON's completed alert-only EVE ingestion boundary.
