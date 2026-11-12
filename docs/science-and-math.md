# Science and mathematics behind the next improvements

This research connects published methods to executable MEGALODON behavior.
The implementation basis is `main@201fe4939cbfb160dccb80782455d106cdebaed4`.
Synthetic checks establish properties of supplied metadata; operational
usefulness still requires a representative, separately authorized evaluation.

## Exact rolling windows for retained burst reviews

At the source basis, twenty port-53 observations at 59.50, 59.55, ..., 60.45
seconds produce a burst alone. Adding an unrelated port-443 observation at
zero seconds moves the relative minute boundary and suppresses the burst.
The relevant port-53 observations have not changed.

For one source, sort eligible observation times as integer microseconds. For
each left endpoint, find the exclusive right endpoint satisfying

```text
W = 60,000,000 microseconds
window(i) = {j : t[i] <= t[j] < t[i] + W}
qualifies(i) iff count(window(i)) >= 20
```

Advance two monotone pointers to the earliest qualifying window. Emit its full
support, then consume that window before looking for another. This produces
deterministic, disjoint review windows rather than every overlapping interval.
Sorting costs O(n log n); the scan costs O(n), with O(n) bounded working storage.
Each supporting observation belongs to at most one burst for its source.
An observation exactly sixty seconds after the left endpoint is excluded.
The retained adapter clips the displayed end to the completed-hour horizon.

This is an exact count over a small, bounded batch, not an implementation of
the approximate exponential-histogram algorithm in Datar, Gionis, Indyk and
Motwani's [sliding-window research](https://epubs.siam.org/doi/10.1137/S0097539701398363).
That work supplies the broader stream-window model; MEGALODON's concrete
algorithm and invariants above are derived for its existing limits.

The retained analyzer explicitly requests `rolling_bursts=True` and timing
provenance. It preserves source/interface/measurement separation, connection
identity checks, the 2,048-record group limit, the 24-reference display page and
full support-segment dependencies. The pure helper refuses rolling work above
20,000 records. Dense legitimate resolver activity can still produce a review;
port 53 does not establish parsed DNS questions or malicious intent.

Version-1 offline exports retain their fixed relative-minute bins and closed
reader contract. They are a different measurement format, not rolling-window
reports. Newly processed retained hours use the new algorithm; saved reviews
and existing admission/cooldown decisions are not rewritten.

See [timing provenance](pattern-evidence-provenance.md),
[implementation](../megalodon/offline/analysis.py) and the
[independent rolling-window tests](../tests/test_rolling_bursts.py).

## Measure what the available input can distinguish

Some bundled cases intentionally supply identical analyzer input with different
scenario labels. No deterministic classifier restricted to that exact input can
assign different decisions to those cases. Changing a threshold cannot recover
authorization or intent that is absent from the observations.

The layered report now groups by the full canonical ordered analyzer input:
rows, time boundaries, comparison history and declared gaps. Case IDs, labels,
rationales and the support oracle remain outside that input. SHA-256 identifies
the groups in the report; grouping uses the full canonical value. Within each
group let `u` be useful labels and `o` ordinary labels. Then

```text
minimum binary disagreements = sum(min(u, o)) over exact input groups
maximum fixture agreement = determinate cases - minimum disagreements
```

Indeterminate labels are excluded from the binary denominator. The bound is
conditional on this finite fixture set, its labels and the stated input; it is
not an estimate of population Bayes error, operational accuracy or the best
possible detector with additional evidence. The original provenance/stability
meaning of `all_match` is unchanged.

This audit makes the semantic gap discussed by
[Sommer and Paxson](https://scispace.com/papers/outside-the-closed-world-on-using-machine-learning-for-4oj3n5uk26)
visible as a computed property of this corpus. It does not suppress an ordinary
case by reading its withheld scenario rationale. Reproduce with the
[layered evaluation](layered-evaluation.md). The authors'
[complete paper](https://www.icir.org/robin/papers/oakland10-ml.pdf) discusses
the gap between anomaly output and operational meaning.

## Research that guides the next experiments

| Method and source | Connection to MEGALODON | Evidence needed before changing operation |
| --- | --- | --- |
| Base-rate reasoning: [Axelsson, 2000](https://scispace.com/papers/the-base-rate-fallacy-and-the-difficulty-of-intrusion-4td454jjhu) | The existing [Alert Workload Lab](alert-workload-lab.md) computes exact hypothetical alert burden and positive predictive value. An unusual-pattern score is not an incident probability. | Population, decision unit, time selection, prevalence, sensitivity and false-positive rate must describe the same evaluation. Toy-case ratios cannot supply them. |
| Precision/recall: [Saito and Rehmsmeier, 2015](https://scispace.com/papers/the-precision-recall-plot-is-more-informative-than-the-roc-w78tv6wyk3) | Evaluate review workload and missed useful cases alongside class balance; an attractive aggregate accuracy can conceal a poor alert burden. | Separate chronological tuning and held-out evaluation, independent labels and explicit ordinary/useful/unknown denominators. |
| Adaptive windows: [Bifet and Gavaldà, 2007](https://scispace.com/papers/learning-from-time-changing-data-with-adaptive-windowing-1fikekz41a) | Candidate method for studying whether stale traffic baselines hide or exaggerate a real distribution change. This branch does not add ADWIN or automatic baseline replacement. | Offline abrupt/gradual drift and contamination experiments; preserve source identity, coverage gaps, baseline eligibility and explicit operator review. |
| Circular statistics for event arrivals: [Elton and Slocumb, 1996](https://scispace.com/papers/robust-parameter-estimation-for-periodic-point-process-31ox8o8jcm) | Candidate method for studying a cadence with missing observations. A trial period can be scored by phase concentration, `abs(sum(exp(2*pi*i*t/P)))/n`. This is a proposed experiment, not a shipped estimator. | Bound the period search; test aliases, jitter, duplicates, missing observations and ordinary scheduled jobs; report period ambiguity and account for multiple trial periods. |
| Proportion uncertainty: [NIST confidence intervals](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm) | A future representative validation should report uncertainty as well as a measured fraction; zero observed errors alone does not establish zero population error. | Establish the sampling unit and statistical assumptions first. The hand-built, related corpus cases are not independent random traffic samples and do not justify a binomial confidence claim. |

The ADWIN authors' [full preprint](https://www.cs.upc.edu/~gavalda/papers/adwin06.pdf)
states bounded, independent observation assumptions and explicitly adjusts for
the many candidate cuts being tested. Those guarantees cannot be transferred
to correlated network observations simply by copying the threshold formula.
The paper links above also provide bibliographic records for further reading;
neither a literature result nor its benchmark is a MEGALODON acceptance receipt.

For a concrete base-rate example, one million hypothetical source-windows with
prevalence 1,000 ppm, sensitivity 900,000 ppm and false-positive rate 10,000 ppm
yield 900 true positives and 9,990 false positives. Positive predictive value is
exactly `10/121`, about 8.26%. These are supplied assumptions, not measured
MEGALODON rates:

```bash
python -m megalodon.evaluation base-rate --population 1000000 \
  --unit source-window --prevalence-ppm 1000 --sensitivity-ppm 900000 \
  --false-positive-ppm 10000
```

The next numerical correctness investigation concerns the fixed detector's
floating-point epoch windows: translating two equally spaced timestamps can
change an exact-boundary result. It requires a separate correction and oracle;
the rolling-window work does not silently change that detector's state units.

## Reproduce the current implementation checks

Use the reviewed checkout's existing Python environment and a newly created,
owner-private temporary directory. Drop inherited/ambient capabilities as the
repository's native privilege tests require:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
setpriv --inh-caps=-all --ambient-caps=-all python -m pytest -o addopts= -ra \
  tests/test_rolling_bursts.py tests/test_pattern_provenance.py \
  tests/test_layered_evaluation.py tests/test_layered_review.py \
  tests/test_host_fanout.py tests/test_flow_identity_review.py \
  --basetemp=/absolute/owner-private/test-output
python tools/replay_pattern_provenance.py
```

The rolling tests compare the linear scan against an independently written
quadratic oracle and test time translation, input permutation, irrelevant early
traffic, exact endpoint exclusions, source separation and bounded work. The
identifiability tests compare the finite bound with exhaustive binary choices
on small toy groups and verify that changing labels cannot alter predictions.
The focused integration selection passed 441 tests, with one explicitly opt-in
installed-TShark test skipped. A separate 500-case seeded oracle experiment also
passed exact rolling support, time translation, permutation and legacy-default
equality checks. The unchanged 25-case corpus now reviews eight of ten stipulated
useful cases, versus seven at the source basis; ordinary cases with a review
remain four of ten. These finite results are not deployment recall or a
measured false-positive rate.
The [comparison record](benchmarks/rolling-review-20261111.json) preserves source
file hashes, fixed corpus/label identities and before/after synthetic counts.
Representative traffic, installed-machine behavior and native producer/model
acceptance remain separate from these synthetic checks.
