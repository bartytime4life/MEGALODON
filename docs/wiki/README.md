# MEGALODON Documentation Wiki

## From complex telemetry to a useful local workspace

**A portfolio of AI-assisted product direction, systems engineering, security design, and visual communication.** Built under [Andy’s project direction](https://github.com/bartytime4life), MEGALODON brings a Python metadata core, private SQLite evidence, a visual Linux HUD, and bounded local-model advice into one inspectable project.

![MEGALODON architecture: bounded inputs feed a deterministic core and local HUD; model advice and operator authority are separate.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/3c81889ba37953e997620c8bf15b3c1239bfc103/assets/wiki/evidence-architecture.png)

The design challenge is to make a complex security workspace understandable while keeping evidence, uncertainty, and authority visible. Explore the decisions and their implementation below.

## The two-minute recruiter tour

1. **[Meet the builder](builder-profile.md)** — product judgment, AI collaboration, and how to assess the work.
2. **[See the visual design](visual-tour.md)** — the atlas, workspace hierarchy, motion, status, and reports.
3. **[Inspect four engineering case studies](engineering-case-studies.md)** — concrete problems, choices, results, tradeoffs, and tests.
4. **[Follow the evidence](evidence-index.md)** — immutable source links and the limits behind each claim.

## A result you can inspect

The saved October 1 benchmark records **98.1% fewer OS-written bytes** for 10,000 synthetic packet records, with all 10,000 retained in both runs. History-query p95 increased from 4.21 ms to 27.06 ms. This is a finite workstation measurement, with its tradeoff disclosed; it is not a production-capacity or SSD-lifetime claim. Read the [storage case study](engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff) and [raw measurements](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/benchmarks/efficient-recording-comparison.json).

## What the project brings together

| Layer | Implemented scope | Evidence to inspect |
| --- | --- | --- |
| Product and graphics | Local connection atlas, resource strip, findings, source status, topology and visual reports | [Visual tour](visual-tour.md) |
| Systems engineering | Typed metadata, three fixed detection heuristics, segmented storage, bounded history, scheduled local reports and Linux installation | [Case studies](engineering-case-studies.md) |
| Security judgment | Local request controls, private storage admission, bounded collectors, explicit operator actions and expiring containment | [Security boundaries](security-boundaries.md) |
| Applied AI | Digest-pinned installed local models, bounded explanations, closed proposals and failure states | [Integrations and local AI](integrations-and-qwen.md) |
| Delivery discipline | Versioned contracts, negative tests, reproducible measurements and separate acceptance gates | [Evidence index](evidence-index.md) |

## Use or contribute

[Quick start](quick-start.md) · [Operator guide](operator-guide.md) · [Development and validation](development-and-validation.md) · [Roadmap and limits](roadmap-and-limits.md)

The supported application is the **local Linux HUD**. The former hosted Sites console is retired; it is not a recruiter demo or a connection to this PC. Source and publication history remain in [the Site record](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/site-source-alignment.md).

This showcase was checked against repository main at `4da7fae0d8df2d8cd6b3ff93964055f7e14972bb` (October 11, 2026 UTC / October 10 in America/Chicago). Case-study evidence is pinned to that revision. Guides link to current repository documentation. Code, tests, merges, host operation, release, and independent acceptance remain separate claims. Wiki source lives in `docs/wiki/`; this public projection does not replace the [specification](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/SPECIFICATION.md) or [security review](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/SECURITY_REVIEW.md).
