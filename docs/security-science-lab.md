# Security science in Help

Open **Help → Explore security science**. The worked examples run entirely in
the browser, even when telemetry and reference APIs are unavailable. They use
hypothetical counts; they never read traffic, save inputs, invoke a model,
change a detector, download references or apply a firewall policy.

## Try the comparison

1. Choose **Rare condition**. Of 100,000 hypothetical cases, 100 contain the
   condition. Ninety are detected and 999 ordinary cases also alert. Precision
   is `90 / 1089 = 10 / 121`, about **8.26%**, despite 90% recall and 98.99%
   overall accuracy.
2. Choose **More common condition**. Recall stays 90% and the false-positive
   rate stays 1%, but precision rises to **90.91%**. The changed base rate is
   enough to change the fraction of alerts corresponding to the condition.
3. Choose **Only one alert**. Its observed precision is 100%, but the hypothetical
   95% Wilson interval extends from about **20.65% to 100%**. One success does
   not establish reliable precision for future traffic.
4. Edit TP, FP, FN and TN to explore another hypothetical confusion matrix.
   Each count accepts canonical whole numbers from zero to one billion.
   An empty, negative, fractional or oversized entry hides prior results and
   identifies the invalid input. Zero denominators remain **Undefined**.

TP and FN describe condition-present cases. FP and TN describe condition-absent
cases. The case unit, selection period and independent label process must be
consistent across the four cells. Unknown labels cannot become true negatives.
These supplied examples are not measured MEGALODON accuracy or incident odds.

## Mathematics and assumptions

| Display | Calculation |
| --- | --- |
| Precision / positive predictive value | `TP / (TP + FP)` |
| Recall / sensitivity | `TP / (TP + FN)` |
| False-positive rate | `FP / (FP + TN)` |
| Accuracy | `(TP + TN) / (TP + FP + FN + TN)` |

The implementation admits at most four billion cases, so count additions stay
exact within JavaScript's safe integer range. Ratios and confidence intervals
use floating-point arithmetic; displayed percentages are rounded. Positive
values below 0.01% display `<0.01%`, and non-unit values above 99.99% display
`>99.99%`, rather than becoming a displayed exact zero or one.

The precision interval uses the two-sided 95% Wilson formula with
`z = 1.959963984540054`, `n = TP + FP` and `p = TP/n`:

```text
center = (p + z²/(2n)) / (1 + z²/n)
half-width = z × sqrt(p(1-p)/n + z²/(4n²)) / (1 + z²/n)
```

This assumes independent Bernoulli trials with a common success probability and
a suitable labelled sample. Correlated packets, overlapping windows, biased
labels and distribution changes can invalidate that interpretation. The interval
is not a posterior probability that a particular alert is malicious. The
hypothetical lab cannot calibrate the app or select production thresholds.

The existing [CLI Alert Workload Lab](alert-workload-lab.md) remains a separate
exact-fraction projection from supplied rates, including fractional expected
counts. The HUD companion uses integer confusion-matrix cells and an illustrative
sampling interval; it does not change the CLI's pure execution contract.

## Defensive lessons connected to the app

The expandable lessons cover service discovery, authentication attacks,
exploitation of exposed services and CIDR scope. Each distinguishes observations
from conclusions, links primary sources, and opens the existing Findings, host
checks or host-protection controls. Navigation does not approve an action.
A service exception is permission to connect, not a safety verdict or a patch.
Packet rate does not establish a failed login, successful access or AI use.

The summaries are original educational text, reviewed November 17, 2026:
[Axelsson's base-rate analysis](https://scispace.com/papers/the-base-rate-fallacy-and-the-difficulty-of-intrusion-4td454jjhu),
[NIST's Wilson interval formula](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm),
[NIST SP 800-94](https://csrc.nist.gov/pubs/sp/800/94/final),
[MITRE T1046](https://attack.mitre.org/techniques/T1046/),
[T1110](https://attack.mitre.org/techniques/T1110/),
[T1190](https://attack.mitre.org/techniques/T1190/) and
[RFC 4632](https://www.rfc-editor.org/rfc/rfc4632).
External sources are opened only when their links are selected.

## Verification

`tests/test_security_lab.py` compares 87 cases against exact Python fractions
and independently inverts the binomial score test by bisection. It covers
undefined denominators, large counts and misleading display boundaries.
`tests/browser_security_lab.py` exercises the assembled HUD, keyboard presets,
invalid/zero counts, narrow layouts, announcements and lesson navigation against
synthetic unavailable APIs. Its browser job retains screenshots. Neither these
checks nor the local browser audit establishes field detection performance or
screen-reader acceptance.
