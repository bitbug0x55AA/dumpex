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
2. **Coverage summary** — `coverage.status`, its reasons, and every already-
   collected enrichment section's own gap, printed even when the run is
   complete, so an analyst never has to infer completeness from a block's
   absence and never reads "No known collection limitations" while a later
   section still discloses one. `coverage.status`/`coverage.reasons` are the
   compatibility-frozen reducer's own verdict and are unread by this
   addition; the status line carries a short qualifier ("core report
   coverage — see below for optional-enrichment gaps") whenever this run's
   own sections add anything beneath it, so `COMPLETE` is never read as
   covering more than that narrower contract.

   Each enrichment section's own gap (see `_all_gap_reasons` in
   `dumpex.commands.report`) is one of two kinds, kept apart because they
   call for different follow-up: **availability** (an incomplete status, or
   a limitation sentence `_split_limitations` classifies as a gap — evidence
   not evaluated at all) prints under the main `[~]` list alongside
   `coverage.reasons`; **retention** (a retained-set cut — evidence
   evaluated but not all of it kept) prints under its own "Retention
   limits:" lead-in. A completed evaluation's settled negative is neither,
   and appears in no gap list (see **Settled negatives** below). A card's own
   gap that is already the identical fact as a `coverage.reasons` entry (a
   target-region read coming up short is both the reducer's own aggregate
   reason and String context's own limitation) is stated once, via the
   reducer's reason; the affected section still reports its own distinct
   status without repeating byte counts the reducer's sentence does not
   carry. The incomplete-coverage caveat that can follow both lists carries
   its own `[·]` marker, distinguishing advice about reading the summary
   from one more gap in it.

   One cause is one line, however many sections observed it. A single
   missing stream leaves every projection that consumed it with the
   identical reason — a dump with no `HandleDataStream` leaves both the
   process-wide handle census and each card's handle correlation unable to
   evaluate — and `_merge_shared_causes` states it once, naming every
   affected section, each keeping its own region annotation. Merging is
   keyed on the reason's own detail, so only genuinely identical causes
   merge; a reason already scoped to one specific region is left alone
   rather than widened into a whole-run line.

   For `--report-string`, this prints before either the zero-hit or the
   all-hits-in-known-modules early return, so neither path can hide a
   partial or not-evaluated scan behind "not found"; a reason every triaged
   card shares collapses to one line naming every region it covers, printed
   before any reason narrower than that, rather than once per hit or
   interleaved with per-region reasons. A label whose own per-region detail
   differs too much to merge that way (Instruction context's own limitation
   names each region's own anchor address, for one) still collapses once
   there are more than `_MAX_PER_LABEL_VARIANTS_SHOWN` such variants, into
   one line naming how many distinct detail lines it replaced -- a count of
   lines, not of affected regions, since a line already covering more than
   one region (see the previous paragraph) is not re-expanded to count
   each of those regions separately. An actionable hit region this run's
   own card/read budget left completely untriaged is named here too — the
   widest scope gap such a run can carry — and here only, carrying its own
   next step (`--report-addr` against a specific region) rather than being
   restated in full beside the hit list further down.
3. **Anchor context** — thread analysis, memory region, other threads in the
   region, and the anchor's PE placement (rendered as `ANCHOR PLACEMENT`; a
   declared-versus-live protection comparison prints only when the anchor is
   actually inside an owning PE section -- private or otherwise unmapped
   memory has a live protection but no declared bits to compare it against,
   and prints a bare `Live protection` line instead).
4. **Key evidence** — the region's strings and IOC matches, then
   anchor-proximity string context.
5. **Additional retained strings** — verbose only: routine (non-IOC) notable
   strings, kept out of Key evidence as its own sibling group (not a section
   nested under it) so a page of low-priority strings never crowds the
   evidence an analyst reads first. Default detail names only how many this
   card retained; there is no narrower default-detail preview of the
   strings themselves to cap.
6. **Correlation** — exception, instruction, IAT, and handle correlation.
7. **Additional context** — this card's allocation neighborhood, then (once
   per invocation, not once per card) process identity and the main-image PE
   header.
8. **Limitations and provenance** — verbose only; see below.

Section headers are plain names, never numbers: a conditional section this run
did not populate leaves no numbering gap to reason about.

### Default output

Default output remains self-contained while limiting routine detail. It keeps
the anchor, region, thread, string and IOC evidence, findings, verdict,
coverage, diagnostics, every incomplete enrichment state, and every identity
conflict. Process, session, handle-census, and token details are summarized;
populated collections use bounded previews, and a complete section with no
eligible entries does not repeat an empty counts row. Notable (non-IOC)
strings are the exception: default detail previews none of them at all (not
even a capped preview) and names only their retained count, since the
strings themselves are Additional retained strings' own verbose-only content.

Routine text reaches the console by two routes, and default detail holds both.
The second is String context's own proximity selection: an entry whose
`selection_reason` is `adjacent_to_anchor` was kept only because it sits near
the anchor — proximity is layout, not a finding — so it is the same class of
low-priority background, and String context renders inside Key evidence. Held
there too, default detail names how many were held and where to get them; a
`query_match` or `ioc_pattern` entry carries its own analytic claim and always
keeps its place. Without this, moving the notable-string inventory out of Key
evidence would close only one of the two routes and the same strings would
reach that block through the other.

The console preview of retained IOC matches is capped independently
(`CONSOLE_IOC_STRINGS` in `dumpex.commands.report`). Selecting the IOC
preview prioritizes network-pattern hits — the only class carrying its own
byte context — ahead of other matches, so a routine match at a low offset
cannot crowd a C2 indicator at a higher offset out of the default view; a
network-pattern hit the preview still could not fit states so explicitly; a
hit's overlapping ±128-byte context windows are coalesced into one combined
byte range instead of repeating shared bytes once per hit, whether one hit
or several.

### Verbose output

Verbose output expands every retained handle-type census row,
allocation-neighborhood entry, correlated handle, IOC match, notable string,
and nearby-string entry, plus each entry's selection reason. A renderer must
not re-run collection or infer new evidence at either level.

Each section's scope, evidence state, counts, and cap no longer print inline
after that section: that envelope appears once per anchor, in a trailing
**Limitations and provenance** table, verbose only — and only for a section
that actually has a gap (`_has_reportable_limitation` in
`dumpex.commands.report`: an incomplete status, a retained-set cut, or a
limitation sentence). A section with none of those contributes no envelope
fact the table does not already imply by leaving it out.

Provenance is a different fact from that envelope, and is not gated on having
a gap: every section this run collected still gets its own entry in the
trailer naming the streams it was built from, whether or not anything about
it went wrong — with a `built from:` line and no envelope line above it when
the section is clean. A section with neither a gap nor any provenance to name
is the only case left out of the table entirely.

Each section's own short reminder — evidence state, retained count,
truncation, and limitations — prints inline at both detail levels, but only
when that same `_has_reportable_limitation` test is true: a routine complete
result (an incomplete evidence state is never routine) states nothing beyond
the block's own sentence above it, whether that sentence reports rows or
reports nothing eligible, so an `evidence: complete   kept: N of N` line under
it is never printed. Neither surface prints `kept:`/`cap:` when a section's own
`included`/`total` are both zero (`_has_meaningful_counts`): `0 of 0` names no
retention cap this run ever approached, and would duplicate whatever a more
specific count in the section's own body already means (main-image PE
context's own "N consistent, 0 conflict, N unavailable" line, for one).

### Deduplicated string identity

A retained string can be selected into any two of three projections: STRINGS
IN REGION's own IOC-match inventory, Additional retained strings' notable-
string inventory (verbose only), and STRING CONTEXT's own anchor-proximity
selection. A string chosen for one of the first two AND for proximity context
is one presentation identity; its full text prints once, in whichever of the
two source sections actually shows it at the current level, and STRING
CONTEXT drops the row entirely rather than printing a per-row cross-reference
in its place. Every dropped row is named once, together, as a single trailing
count that also names which section(s) it was already shown under ("N
further retained entries are already shown in full under STRINGS IN REGION",
or "... under STRINGS IN REGION and ADDITIONAL RETAINED STRINGS" when a
verbose run's duplicates come from both), or, when every entry STRING
CONTEXT's own console cap would otherwise show is a duplicate, one summary
sentence replaces the row list outright, naming the same section(s).

The identity check is built against exactly what each source section renders
at the current level, never its wider retained set: a match that section's own
cap left out of its preview is, from STRING CONTEXT's perspective, still new,
and prints there in full under STRING CONTEXT's own separate cap — a
duplicate is only ever counted when it points at text genuinely on screen
elsewhere. Notable strings render at verbose only, so at normal detail none
of them are in STRING CONTEXT's dedup source at all; a notable string close
enough to the anchor to be selected as proximity context is proximity-only by
that route as well, and default detail holds it rather than printing it (see
**Default output**). STRING CONTEXT's own console cap is applied AFTER this
dedup partition and after that hold, over the remainder only: a duplicate or a
routine entry at the front of the retained order can never push a genuinely
unique one further back out of the preview, and can never make the
all-duplicate summary sentence print while entries this level has not yet
considered still exist beyond it.

### Omission notices

Three omission notices have distinct meanings:

- A console preview omits retained rows. The notice says they remain available
  from `--verbose` and JSON.
- A retention cap drops eligible rows before projection. The notice says the
  rows are absent from every console level and JSON.
- A retained string's full text is published under a different section at
  this same detail level. The row is dropped rather than repeated, and every
  dropped row in one section is named once, together, in a single trailing
  count naming the other section — never one stub row per duplicate.

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

### Settled negatives

A few `complete` sections carry a limitation sentence that is not a gap but the
answer: the collector read what it needed and the thing it was looking for is
positively absent. `iat_correlation` is the published case — a module that
declares no import directory is `complete` with "the module declares no import
directory", exactly so a consumer does not read it as an unanswered question
(see `OUTPUT_SCHEMA.md`).

`_split_limitations` in `dumpex.commands.report` is the presentation-side
classifier, and it changes no record: `limitations` stays exactly what the
collector published. A settled negative
- appears in no coverage-summary gap list, since naming it one would send an
  analyst looking for evidence this run has already established is not there;
- leaves its section out of the inline `evidence: …` envelope line and out of
  the LIMITATIONS AND PROVENANCE trailer's envelope, the same as any other
  routine complete result (`_has_reportable_limitation`);
- still prints, under the neutral `[·]` marker rather than the caveat `[~]` —
  it is that section's result, and suppressing it would lose the answer.

Only a section that is `complete`, untruncated, and found nothing eligible can
carry one at all, and only for the exact sentences the classifier lists: a
`partial` or truncated section did not finish the evaluation that would have
settled anything, and any other sentence — including a genuine gap riding in
the same section's own `limitations`, such as an unread data-directory array —
stays a gap. Classification is per sentence, not per section, and an unlisted
sentence over-reports rather than being silently reclassified.

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

The disassembler is the `capstone` dependency, imported only inside
`dumpex.core.disasm`. It is a base requirement of the Python distribution and
unconditional in the official Windows executable, so every supported
installation can decode; the `disasm` extra survives only as an empty alias for
older installation instructions. With no decoder the instruction section
reports `decoder_state: unavailable` and an empty instruction list, and that
state describes a damaged installation or a development tree.

`unavailable` covers two causes and the section limitation keeps them apart.
`module_absent` is the declared dependency not being present. `load_failure`
is a backend that imports by name and still does not work -- capstone resolves
its native library through `ctypes.CDLL()` during its own import, so a missing
or incompatible `capstone.dll` raises `ImportError`/`OSError`, never
`ModuleNotFoundError`. The limitation names the raising exception's type and
nothing more: the bounded, path-redacted reason stays in
`DecodeResult.backend` for build and release diagnostics. A packaged executable
is never told to run `pip install`; its missing decoder is reported as a
distribution defect. `decoder_state` itself, the schema, findings, verdict,
coverage, and exit codes are unchanged by any of this.

`dumpex --self-check` (`dumpex.core.selfcheck`) decodes fixed synthetic bytes
through `decode_window()` and exits non-zero when this build cannot decode. It
is the release gate the Windows workflow runs against the built executable and
against the copy extracted from the published ZIP.

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
in `tests/unit/test_disasm.py` and `tests/unit/test_va_location.py`; backend
classification and reason sanitization are covered by
`tests/unit/test_disasm_backend.py`, the build self-check by
`tests/unit/test_selfcheck.py`, and the Windows bundling contract by
`tests/unit/test_release_packaging_gates.py`.
Schema compatibility is covered by `tests/integration/test_json_schema_v2.py`
and `tests/integration/test_report_compat_freeze.py`.
