# Architecture decision record index

Status: **Implemented index and template only.** The links below organize
existing dated records without changing their content, evidence scope, or
original disposition. An index entry is not an acceptance receipt.

## Numbering and use

`ADR-0001` through `ADR-0005` are stable **legacy index keys** for records that
predate this directory. They link to the original files; those files have not
been renamed or converted into newly accepted ADRs. Start the first new ADR at
`0006-short-kebab-case-title.md` in this directory, increment monotonically,
and do not reuse a number. Add its link and current decision state to this index.

Copy [the template](TEMPLATE.md) for a new decision. Set its `Status` header to
**Proposed**, **Contract only**, or **Implemented** according to what the record
actually contains, and keep the separate decision state explicit. A proposal,
contract, implementation, test result, or merged PR does not by itself provide
operator, security, host, release, or platform acceptance. Record the exact
source and review evidence before changing a decision state; retain superseded
records with a link to the replacement rather than rewriting their history.

## Indexed legacy records

| Index key | Original record | Classification at indexing | Boundary |
| --- | --- | --- | --- |
| ADR-0001 | [Repository correction review and PR delivery — 2026-09-11](../repository-review-2026-09-11.md) | Dated review and delivery readback | Historical GitHub state, not current approval |
| ADR-0002 | [Repository and document alignment — 2026-09-17](../document-alignment-2026-09-17.md) | Dated alignment receipt | Historical baseline, not a floating currentness claim |
| ADR-0003 | [License decision — 2026-09-20](../license-decision-2026-09-20.md) | Owner license decision | Repository terms, not artifact notice review or release acceptance |
| ADR-0004 | [Document and file alignment — 2026-09-20](../document-alignment-2026-09-20.md) | Dated alignment receipt | Retains its original checkpoint scope |
| ADR-0005 | [Repository, Console, and telemetry alignment — 2026-09-21](../document-alignment-2026-09-21.md) | Dated alignment receipt | Does not prove hosted parity or sensor health |

## New ADRs

None yet. The next available number is `ADR-0006`.
