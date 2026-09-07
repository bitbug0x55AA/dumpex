# Report enrichment contract

Status: **implemented** in dumpex 3.7.0 and schema v2.17.

This document records the current implementation contract behind `--report`
enrichment. User-visible behavior and wire fields are documented in
[Output and Evidence Schema](../user/OUTPUT_SCHEMA.md); schema upgrade details
belong in [Output Schema Migration](../user/OUTPUT_MIGRATION.md).

---

## Scope and boundaries

Report enrichment adds context to an existing triage card without adding a new
detection signal. It covers:

- one process-scoped identity, environment, handle-summary, and token-capability
  projection per invocation;
- exception, allocation-neighborhood, handle-correlation, and string-context
  projections scoped to one card;
- explicit evidence state, provenance, retention counts, caps, truncation, and
  limitations for each section;
- invocation-level limits for multi-card `--report-string` runs.

Enrichment must not change findings, finding details, verdict, score,
confidence, coverage status, Finding IDs, or exit-code semantics. Exception and
handle correlations are observations, not maliciousness claims.

CSV is not an output surface. JSON is the structured projection, while the
console and `--txt` are human-readable projections of the same typed records.

## Collection and projection ownership

`collect_report()` owns the invocation. It collects process enrichment, the
canonical handle inventory, the region view, and their indexes once, then reuses
them for every card. A multi-card run must not parse the same process-wide
stream independently for each card.

`_collect_triage_card()` owns card-local capture and constructs the four
card-scoped enrichment records. Renderers consume those records; they do not
repeat selection, correlation, or evidence-state decisions. JSON serialization
and console/`--txt` rendering therefore describe the same retained evidence.

The implementation reuses the established process and handle collectors and
the shared virtual-address/capture primitives. It does not introduce a second
report-only interpretation of process identity, handle parsing, or captured
memory ranges.

## Console detail-level contract

`--verbose` changes presentation only. Default and verbose reports run the same
collectors over the same captured bytes and produce the same typed records,
coverage, execution status, diagnostics, artifacts, and exit code. `--txt`
uses the requested console detail level; JSON always carries the complete
retained record set.

Default output remains self-contained while limiting routine detail. It keeps
the anchor, region, thread, string and IOC evidence, findings, verdict,
coverage, diagnostics, every incomplete enrichment state, and every identity
conflict. Process, session, handle-census, and token details are summarized;
populated collections use bounded previews, and a complete section with no
eligible entries does not repeat an empty counts row.

Verbose output expands every retained handle-type census row,
allocation-neighborhood entry, correlated handle, and nearby-string entry. It
also shows each section's scope, evidence state, counts, cap, provenance, and
each entry's selection reason. A renderer must not re-run collection or infer
new evidence at either level.

Two omission notices have distinct meanings:

- A console preview omits retained rows. The notice says they remain available
  from `--verbose` and JSON.
- A retention cap drops eligible rows before projection. The notice says the
  rows are absent from every console level and JSON.

Where the console renders a dump-derived value that reached its retained-text
cap, it must expose the truncation beside that value. Ordinary fields use a
bracketed field-specific marker; the packed handle-type census uses a trailing
ellipsis on the affected name. If an affected census row is outside the current
preview, the notice describes it as retained rather than as displayed.

The process block reports whether the process image base matched the captured
module list. `unregistered` and `unavailable` are visible at both detail levels:
the process section may otherwise be complete even when no module list was
available for that separate comparison.

## Evidence-state contract

Every enrichment section uses the same three states:

- `missing`: the required stream, page, or capture was unavailable and the
  section could not evaluate its question;
- `partial`: useful evidence was evaluated, but a parse failure, unread value,
  short read, skipped descriptor, or other stated limitation leaves the result
  incomplete;
- `complete`: the bounded evaluation reached its end. An empty retained subset
  is a completed negative only for that section and scope.

When the eligible population is known, `truncated` is exactly
`included < total`. When it cannot be determined, `total` is null rather than a
fabricated count. A section limitation describes missing evidence or incomplete
work; a captured disagreement is an observation and belongs in its typed
conflict record instead.

## Bounded selection

The retention and text limits are deliberately centralized in
`dumpex.commands.report_enrichment`:

| Projection | Retained limit |
|---|---:|
| Exception records | 4 per card |
| Allocation-neighborhood regions | 7 per card |
| Correlated handles | 12 per card |
| String-context entries | 12 per card |
| Environment variables | 7 per invocation |
| Handle types in the process census | 12 per invocation |
| Dump-derived text | 200 characters per field |

The handle and region inventories are indexed once per invocation. Per-card
selection uses those indexes and bounded retained subsets. The correlated
handle subset is deduplicated by handle value, while the region view collapses
duplicate bases deterministically; discarded or unreadable evidence is surfaced
through the owning section's limitations.

Allocation selection retains the anchor, nearby members of its allocation, and
the closest regions outside that allocation. Outside neighbors are reserved
before interchangeable same-allocation members when the cap binds. Adjacency is
layout context only and never implies a behavioral relationship.

Handle correlation compares the identifying final segment of a captured object
name with text captured by the card. Generic namespace prefixes do not establish
a correlation. String context reuses the card's existing content scan and does
not perform another region read.

## Multi-card budget and overlapping regions

A `--report-string` invocation builds at most 32 cards and applies a 256 MiB
cumulative budget to card content reads. When extraction is requested, its
second read is charged as well. The first actionable card is always built so a
direct query cannot return no card solely because its first region reaches the
byte ceiling; that deliberate first-card exception is the only case that may
take the accumulated charge past the byte budget.

String search identifies the virtual address of each hit. From that point, one
covering region is resolved and reused for every later decision:

1. image/private classification;
2. grouping hits that share a region;
3. estimating the card's read charge;
4. constructing the card and rebasing its hit offset.

This single-resolution rule matters for malformed or overlapping region tables.
Resolving again at card construction could charge the size of one region while
reading another or publish an offset relative to the wrong base.

Budget accounting happens after hits are grouped by their covering region. A
group that receives a card contributes one to `card_count`; its additional hits
contribute to `hits_sharing_a_region`. Every hit in a group rejected by the
budget contributes to `hits_skipped_for_budget`, while the group itself
contributes to `cards_skipped_for_budget`. Consequently:

```text
card_count + hits_sharing_a_region + hits_skipped_for_budget == hits_private
hits_private + hits_image == total_hits
```

Only a group that actually received a card may contribute to
`hits_sharing_a_region`. A budget stop emits `REPORT_CARD_BUDGET_REACHED` and
makes execution partial; it does not alter the evidence coverage or verdict of
cards that were built.

## Safety and compatibility invariants

- Environment output is allowlisted; a full captured environment block is not
  copied into report enrichment.
- Path redaction remains a presentation policy shared with the rest of dumpex.
- Dump-derived terminal text is escaped and bounded before rendering.
- Analysis uses captured dump evidence only and never consults live-system
  process, handle, token, environment, or memory state.
- Schema v2.16 remains frozen. Schema v2.17 is the first contract containing
  report enrichment and the multi-card accounting fields.

The focused collector and projection tests live in
`tests/unit/test_report_enrichment.py` and
`tests/integration/test_report_enrichment_output.py`; console detail-level
projection is covered by `tests/integration/test_report_verbose_detail.py`.
Schema compatibility is covered by `tests/integration/test_json_schema_v2.py`
and `tests/integration/test_report_compat_freeze.py`.
