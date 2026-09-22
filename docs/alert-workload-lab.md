# Alert Workload Lab

Status: ● implemented offline hypothetical calculator, exposed as
`megalodon-evaluate base-rate`. It helps an analyst see how prevalence and
false-positive assumptions affect the number of units needing review.
It does not measure the three MEGALODON rules, inspect traffic, train a model,
or estimate whether an actual alert is malicious.

## Try a hypothetical scenario

From the repository root in the supported Python environment:

```bash
python -m megalodon.evaluation base-rate \
  --population 100000 --unit source-window \
  --prevalence-ppm 1000 --sensitivity-ppm 900000 \
  --false-positive-ppm 10000
```

This assumes 100,000 source-window units, a condition present in 0.1% of them,
90% sensitivity, and a 1% false-positive rate. None is a MEGALODON measurement
or a recommended setting. All five inputs are required; there are no defaults.

| Expected outcome under these assumptions | Units |
| --- | ---: |
| Condition present / absent | 100 / 99,900 |
| True positive / false negative | 90 / 10 |
| False positive / true negative | 999 / 98,901 |
| Units that alert | 1,089 |
| Positive predictive value (PPV) | 10/121, approximately 8.26% |

Changing only `--prevalence-ppm` to `10000` (1%) yields 900 true positives,
990 false positives, and PPV `10/21` (approximately 47.62%). Sensitivity and
false-positive rate are identical in both scenarios. A high sensitivity alone
does not imply that most alerts correspond to the condition of interest.

## Closed assumptions and observation units

| Input | Accepted values | Meaning |
| --- | --- | --- |
| `population` | Integer 1 through 1,000,000,000 | Number of hypothetical evaluation units |
| `unit` | `event`, `flow`, `source-window` | Exactly one binary classification per declared unit |
| `prevalence_ppm` | Integer 0 through 1,000,000 | Condition-present share of all units |
| `sensitivity_ppm` | Integer 0 through 1,000,000 | Alert share of condition-present units |
| `false_positive_ppm` | Integer 0 through 1,000,000 | Alert share of condition-absent units |

PPM means parts per million: `1000` = 0.1%, `10000` = 1%, `1000000` = 100%.
CLI names use hyphens. Only canonical ASCII decimal integers are accepted;
leading zeros, signs, decimals, exponents, booleans, missing/repeated options,
abbreviations, unknown options, and oversized values fail with exit 2 and the
existing bounded `INVALID_ARGUMENTS` JSON diagnostic. Input is never echoed.
The direct Python API also rejects scalar subclasses and coercible objects
with the fixed `INVALID_BASE_RATE_INPUT` exception.

The same population, selection period, labels and unit definition must apply
to all assumptions. For a source-window study, define the window duration
outside this calculator and classify each such unit once. The tool cannot
verify these definitions or the supplied rates. An `event` here is an
evaluation unit, not a claim that a detector alerts once per packet; a `flow`
is not interchangeable with a packet or Zeek record. Cooldown, overlapping
rules, duplicated observations and aggregation can make actual alert counts
different from these binary-classification expectations.

## Exact calculation and result contract

For population `N`, prevalence `p`, sensitivity `s` and false-positive rate `f`
(each PPM value divided by 1,000,000):

```text
TP = N * p * s          FN = N * p * (1 - s)
FP = N * (1 - p) * f    TN = N * (1 - p) * (1 - f)
alerted units = TP + FP
PPV = TP / (TP + FP), when TP + FP > 0
```

The four expected counts sum exactly to `N`. Expectations can be fractional;
they are not rounded into observed counts. The output is deterministic JSON
with schema `alert-workload-projection-v1`, status `projected`, and quality
labels `hypothetical-only` and `uncalibrated`. It retains every assumption,
the seven expected counts, PPV, and fixed interpretation limits.

Every computed number is a reduced fraction represented as decimal **strings**,
for example `{"numerator": "10", "denominator": "121"}`. This preserves
exact large integers even in JSON consumers with a limited numeric precision.
When no alerts are expected, PPV is explicitly
`{"status": "undefined_no_expected_alerts", "ratio": null}`; it is never
reported as zero, perfect accuracy, or a safe-traffic claim. All admitted
outputs fit within 4 KiB. The decimal percentages above are explanatory
roundings; the command returns exact ratios.

This is conditional arithmetic on supplied point assumptions, not Bayesian
learning, a posterior distribution fitted to evidence, a confidence/credible
interval, or statistical calibration. The synthetic corpus's expected rule
counts are regression assertions, not independently verified malicious/benign
labels; they must not be fed in as measured rates.

## Execution boundary and validation

The calculation imports only the standard library and performs no file,
reference-bundle, database, configuration, network, provider/model, subprocess,
detector, service, dashboard or firewall operation. The CLI writes one JSON
result to stdout, or a fixed argument error to stderr. It does not persist the
result, choose a threshold, create an action, or expose a new HTTP route.
Shell redirection, if explicitly chosen by the operator, is outside that pure
calculation boundary. No dependency or workflow change is required.

```bash
python -m pytest tests/test_alert_workload.py tests/test_reference_data.py
```

Checks cover the hand-calculated examples, population conservation, extreme
rates, fractional rare events, integers beyond JavaScript's exact-number
range, undefined denominators, repeatability, malformed and hostile inputs,
and sentinels on file, socket/HTTP, model, SQLite, config, reference-loader,
subprocess and firewall entry points.

The [source rationale](resource-informed-advancement.md#alert-workload-lab-follow-up)
records the inspected book sections. The next empirical gate is a separately
scoped, privacy-approved and independently labeled local dataset with fixed
units/time selection and held-out evaluation. Neither this calculator nor
passing synthetic tests closes that gate.
