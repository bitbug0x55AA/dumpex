# Report enrichment contract

Status: **implemented** in dumpex 3.8.0 and schema v2.18. Phase 1 (process,
exception, allocation-neighbourhood, handle, string context) landed in 3.7.0 /
v2.17; Phase 2 (PE, instruction, and IAT correlation) in 3.8.0 / v2.18. The
3.8.1 hotfix changed console/`--txt` document hierarchy, presentation caps,
and string-identity deduplication; it changed no wire field, schema, finding,
verdict, or coverage semantic.

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

### Document hierarchy

The report banner (title and file identity) is the first substantive block of
every invocation, tid/addr or string mode alike, printed exactly once
regardless of how many cards the run produces. It is followed, per anchor, by:

1. **Assessment** — the current verdict, its findings, and a concise next step
   looked up from those findings and `coverage.status` alone; it names no new
   risk category and adds no fact this run did not already collect.
2. **Coverage summary** — `coverage.status` and its reasons, printed even when
   the run is complete, so an analyst never has to infer completeness from a
   block's absence. For `--report-string`, this prints before either the
   zero-hit or the all-hits-in-known-modules early return, so neither path can
   hide a partial or not-evaluated scan behind "not found".
3. **Anchor context** — thread analysis, memory region, other threads in the
   region, and the anchor's PE placement.
4. **Key evidence** — the region's strings and IOC matches, then
   anchor-proximity string context.
5. **Correlation** — exception, instruction, IAT, and handle correlation.
6. **Additional context** — this card's allocation neighborhood, then (once
   per invocation, not once per card) process identity and the main-image PE
   header.
7. **Limitations and provenance** — verbose only; see below.

Section headers are plain names, never numbers: a conditional section this run
did not populate leaves no numbering gap to reason about.

### Default output

Default output remains self-contained while limiting routine detail. It keeps
the anchor, region, thread, string and IOC evidence, findings, verdict,
coverage, diagnostics, every incomplete enrichment state, and every identity
conflict. Process, session, handle-census, and token details are summarized;
populated collections use bounded previews, and a complete section with no
eligible entries does not repeat an empty counts row.

The console preview of retained IOC matches and of retained notable strings is
each capped independently (`CONSOLE_IOC_STRINGS` / `CONSOLE_NOTABLE_STRINGS` in
`dumpex.commands.report`). Selecting the IOC preview prioritizes
network-pattern hits — the only class carrying its own byte context — ahead of
other matches, so a routine match at a low offset cannot crowd a C2 indicator
at a higher offset out of the default view; a network-pattern hit the
preview still could not fit states so explicitly; a hit's overlapping
±128-byte context windows are coalesced into one combined byte range instead
of repeating shared bytes once per hit, whether one hit or several.

### Verbose output

Verbose output expands every retained handle-type census row,
allocation-neighborhood entry, correlated handle, IOC match, notable string,
and nearby-string entry, plus each entry's selection reason. A renderer must
not re-run collection or infer new evidence at either level.

Each section's scope, evidence state, counts, cap, and provenance no longer
print inline after that section: the full envelope appears once per anchor, in
a trailing **Limitations and provenance** table, verbose only. Each section's
own short reminder — evidence state, retained count, truncation, and
limitations — still prints inline at both detail levels; an incomplete
evidence state is never deferred to that trailing table.

### Deduplicated string identity

A retained string selected both as an IOC match (or notable string) in
STRINGS IN REGION and as anchor-proximity context is one presentation
identity. Its full text prints once — in STRINGS IN REGION, wherever that
section's own cap allows it — and STRING CONTEXT prints only its placement and
a short cross-reference in place of a second copy. The cross-reference is
built against exactly what STRINGS IN REGION renders at the current level,
never the wider retained set: a match STRINGS IN REGION's own cap left out of
its preview is, from STRING CONTEXT's perspective, still new, and prints there
in full under STRING CONTEXT's own separate cap — a cross-reference must never
point at a section that does not actually show the string.

### Omission notices

Three omission notices have distinct meanings:

- A console preview omits retained rows. The notice says they remain available
  from `--verbose` and JSON.
- A retention cap drops eligible rows before projection. The notice says the
  rows are absent from every console level and JSON.
- A retained string's full text is published under a different section at
  this same detail level. The cross-reference names that section rather than
  repeating the text.

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
| Main-image correlation conflicts | 16 per invocation |
| Decoded instructions | 48 per card |
| Resolved branch targets | 16 per card |
| Correlated IAT slots | 16 per card |
| Instruction-window bytes | 512 per card |
| Distinct module PE profiles | 8 per invocation |
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

## PE, instruction, and IAT correlation

Phase 2 adds one process-wide section and three card-scoped sections. Each
consumes a canonical collector and adds no report-only PE or IAT parser:

- `collect_pe_context` reuses `dumpex.core.pe_profile.collect_pe_image_profile`
  and `dumpex.core.pe_correlation.correlate_main_image` for the main image. It
  publishes the profile's own decoded identity and the correlation layer's
  consistent/conflict/unavailable tally, and retains the `conflict`
  observations. A conflict is a disagreement between two captured facts; it is
  never a finding, a score, or a verdict input.
- `collect_anchor_pe_context` places the card's anchor against the PE image that
  owns it. `classification` is `headers`, `code`, `data`, `import_iat`,
  `relocation`, `unmapped`, or `outside_image` inside the owning module;
  `module` when the module's profile was not available to place it finer; and
  `private` or `unresolved` when no module owns it. The section's declared
  R/W/X against the live region protection is an observation.
- `collect_instruction_context` reads a bounded window at the highest-priority
  approved anchor source and decodes it through the isolated
  `dumpex.core.disasm` seam. An anchor is admitted only when it is correlated
  with this card: an exception RIP only when its record relates to the anchor
  thread or the anchor region (never the dump's own process-wide crash record),
  a live thread RIP and a thread StartAddress only for the card's anchor thread,
  then the card's own anchor -- and when the card carries an explicit
  user-supplied address, that anchor leads and only a correlated fault outranks
  it. The window's architecture is fixed by consulting, strongest first: the
  COFF `Machine` of the module that owns the chosen anchor (`I386` is `x86`,
  `AMD64` is `x64`; a concrete non-x86 machine is `unsupported_arch`); a WOW64
  thread context; the **main image** `Machine` -- a statement of the process's
  own code width, checked before the dump SystemInfo, which reports the *host*
  (a WOW64 process on an x64 host has an `I386` main image and an `AMD64`
  SystemInfo and runs `x86`); the anchor thread's context flavour (`RIP` vs
  `EIP`); and the dump SystemInfo. Only when none of those fixes it is the
  state `arch_undetermined`. The PE32/PE32+ format width is never consulted --
  an ARM64 image is PE32+.
  `decoder_state` is `decoded`, `not_run`, `unavailable`, `unsupported_arch`,
  `arch_undetermined`, `decode_error`, or `undecoded_tail`; every value but
  `decoded` makes the section `partial`, as does a window the byte cap or the
  end of the capture cut short (`total` is then null, like the instruction
  cap). The decoder reads up to one instruction's length of lookahead past
  the byte cap: a legitimate instruction the cap cut is a byte-cap
  truncation (`decoded`), and `decode_error` is an invalid opcode that a
  full instruction's worth of bytes from the failure point still cannot
  decode (or one with a whole instruction's room inside the window). When
  the capture ends before that many lookahead bytes are available and the
  tail does not decode, the state stays `undecoded_tail`, whose limitation
  states the invalid-opcode / cut-instruction ambiguity. A direct branch
  resolves to its destination. An indirect branch through a `[rip+disp]` or
  absolute `[disp]` memory operand resolves the slot and the pointer currently
  in it -- the only mechanically provable indirect form; a sign-extended
  displacement is brought back into the unsigned address space by the operand
  width. A memory-slot branch is `iat_slot` when a parsed IAT entry names the
  slot or the module's IAT directory bounds are known and contain it; it is
  `indirect_memory` otherwise, carrying `iat_classification_uncertain: true`
  when the IAT bounds were unreadable and no import table parsed. An indirect
  branch through a register is reported unresolved. Nothing here names a
  function boundary, a call argument, or a stack.
- `collect_iat_correlation` reuses `dumpex.core.pe_utils.parse_iat` over the
  module that owns the instruction window's anchor -- the same image the window
  is in, so an instruction-correlated slot is never checked against a different
  module's table -- falling back to the card anchor's own module when there is
  no window. It retains only the slots a window branch targets
  (`instruction_correlated`) or whose live thunk target is unusual
  (`slot_out_of_bounds`, `target_unregistered`, `target_private_executable`).
  The instruction-correlated set is taken before the branch-target retention
  cap, so a slot the public `branch_targets` list dropped is still evaluated.
  A module whose import-directory array could not be read leaves the section
  `partial` with `import_directory_present: null` -- undetermined, not a
  completed "declares no imports". A module that positively declares no
  import directory is `complete` with no missed-slot limitation -- there are
  no slots to walk. Three kinds of incompleteness are kept apart. A
  *population* gap (a descriptor/thunk read failed, the table was
  unterminated or cyclic, a walk cap was hit) leaves `total` null: slots
  may be unenumerated. An unreadable *data-directory array* also leaves
  `total` null: the IAT directory bounds are then unknown, so a slot whose
  `slot_in_bounds` could not be checked might belong in the set via
  `slot_out_of_bounds`. An unread import symbol *name* -- resolved after
  the slot, thunk, and target -- makes the section `partial` with its own
  note but leaves the eligible count exact. When `total` is null the
  known-eligible set overrunning the retention cap still sets `truncated`.

The main-image profile, its correlation, and each distinct module's parsed IAT
are built once per invocation by `PeProfileCache`, which caps the number of
distinct module profiles it builds. When an anchor or a branch/thunk target
lands in a module past that cap, its section is resolved as far as the module
list allows and the section is `partial` with a limitation naming the budget --
never `complete` with a silently missing section. A `pe_context` conflict, a
redirected or private thunk target, and a declared-versus-live protection
mismatch are investigation leads: none of them touches `findings`,
`finding_details`, `verdict`, `coverage.status`, or the exit code.

The disassembler is the optional `capstone` dependency (`dumpex[disasm]`),
imported only inside `dumpex.core.disasm`. With no decoder installed the
instruction section reports `decoder_state: unavailable` and an empty
instruction list.

## Safety and compatibility invariants

- Environment output is allowlisted; a full captured environment block is not
  copied into report enrichment.
- Path redaction remains a presentation policy shared with the rest of dumpex.
- Dump-derived terminal text is escaped and bounded before rendering.
- Analysis uses captured dump evidence only and never consults live-system
  process, handle, token, environment, or memory state.
- Schema v2.17 remains frozen. Schema v2.18 is the first contract containing
  PE, instruction, and IAT correlation.

The focused collector and projection tests live in
`tests/unit/test_report_enrichment.py` (Phase 1),
`tests/unit/test_report_pe_enrichment.py` (Phase 2), and
`tests/integration/test_report_enrichment_output.py`; console detail-level
projection is covered by `tests/integration/test_report_verbose_detail.py`.
The document hierarchy, presentation caps, and string-identity deduplication
introduced in 3.8.1 are covered by `tests/integration/test_report_hierarchy.py`;
the exact byte-for-byte hierarchy of the banner, assessment, and anchor-context
blocks is frozen in `tests/integration/test_report_compat_freeze.py`.
The isolated disassembler seam and the VA-resolution join have their own tests
in `tests/unit/test_disasm.py` and `tests/unit/test_va_location.py`.
Schema compatibility is covered by `tests/integration/test_json_schema_v2.py`
and `tests/integration/test_report_compat_freeze.py`.
