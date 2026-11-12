# Builder Profile

## Andy — directing complex work with AI

MEGALODON is a working portfolio for [Andy / bartytime4life](https://github.com/bartytime4life): turning an ambitious security-workspace brief into a project people can inspect, use locally, and improve. The work combines product direction with AI-assisted implementation, interface design, documentation, and validation.

The useful hiring question is **how the builder directs and evaluates complex work**. These pages connect that question to observable project artifacts. They do not assign professional credentials, employment history, solo authorship, or a security certification.

The current operator reading is merged source `418fa54474f3f77d0758e94aab5735a516d8c43b`,
November 11, 2026 (America/Chicago). Older pinned examples below keep their
historical scope; [current state](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md#november-11-source-orientation)
separates implemented source, tests and remaining acceptance gates.

## Capabilities demonstrated by the project

| Capability | Concrete project decision | Inspect it |
| --- | --- | --- |
| Product direction | Offer one evidence-derived next step, direct task routes and an optional tool disclosure; keep configuration in Setup | [Guided workspace](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/docs/dashboard-operations.md#read-the-interface-in-evidence-order) |
| Systems thinking | Separate packet observations, sensor flow summaries, model advice and action receipts rather than combine incompatible evidence | [Managed evidence](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/docs/managed-evidence.md) |
| Visual communication | Use motion for observed direction, retain a text roster, and label approximate or unavailable geography | [Atlas design](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/docs/live-connection-globe.md) |
| Engineering tradeoffs | Measure batching savings alongside retention and query latency | [Recording case study](engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff) |
| Security judgment | Treat local browser requests, file identity, model text and OS authorization as distinct trust boundaries | [Security case study](engineering-case-studies.md#3-security-at-the-point-of-use) |
| AI orchestration | Use AI for design, implementation and review support; constrain in-product AI to evidence-linked advice | [AI case study](engineering-case-studies.md#4-ai-advice-without-transferring-authority) |
| Delivery discipline | Keep candidate code, checks, publication and acceptance separately inspectable | [Evidence index](evidence-index.md) |

## The collaboration method

1. Define the operator’s task and the source of truth.
2. Translate the brief into interfaces, typed contracts, limits, and refusal behavior.
3. Use AI assistance to develop code, graphics, explanations, and focused review candidates.
4. Evaluate results against source, negative tests, measurements, and the actual interaction.
5. Keep work versioned and publish claims that a reviewer can verify.

AI-assisted development and MEGALODON’s local-model interfaces are different
roles. Development assistance helps produce the project. The application defines
bounded advice and closed proposals, but operational generation currently remains
[UNBOUND](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/docs/qwen-runtime-unbound.md).
The explicit fixed READY diagnostic has separate preparation scope. Model text
cannot authorize or execute generated commands.

## A useful technical interview

- How should a network globe behave when an address cannot be mapped or evidence becomes stale?
- What can batching lose in a power failure, and how does the interface disclose that?
- Why does a loopback address still need request and local-user checks?
- How do you keep a model explanation from becoming evidence or action authority?
- What evidence is missing before claiming a release or production accuracy?

Start with the [case studies](engineering-case-studies.md), then inspect their linked tests. For project contact or discussion, use [the public GitHub profile](https://github.com/bartytime4life). No private contact or workstation details are published here.
