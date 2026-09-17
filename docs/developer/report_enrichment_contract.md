# Report enrichment contract

Status: **implemented** in dumpex 3.8.0 and schema v2.18. Phase 1 (process,
exception, allocation-neighbourhood, handle, string context) landed in 3.7.0 /
v2.17; Phase 2 (PE, instruction, and IAT correlation), together with the final
console/`--txt` document hierarchy, presentation caps, and string-identity
deduplication, landed in 3.8.0 / v2.18. The presentation changes added no wire
field, schema, finding, verdict, or coverage semantic.

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
context's own "N consistent, 0 conflict, N unavailable, N not applicable"
line, for one).

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
  tally -- one count per observation state -- and retains the `conflict`
  observations. A conflict is a disagreement between two captured facts; it is
  never a finding, a score, or a verdict input. `unavailable` and
  `not_applicable` are counted apart on both surfaces, because they are
  different facts: evidence this dump does not carry, and a comparison an
  established fact leaves no subject for (PE contract §8.1).
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
  states the invalid-opcode / cut-instruction ambiguity.

  Three different reasons end a decode short of the window, and each
  states itself in its own limitation sentence: an undecodable byte
  mid-window (which also says it is NOT the byte cap, and that the bytes
  after it were never offered to the decoder and so are unevaluated
  rather than invalid), an incomplete instruction at the end of the
  capture, and the byte cap cutting a real instruction. WHERE decoding
  ended is separate from all three and is carried as `bytes_decoded` and
  `decode_stop_address` (`window_base` + `bytes_decoded`, None when no
  decode ran) -- console and text-report presentation state, absent from
  the record's `to_dict` and from the published schema. The console
  summary prints the location alone; naming one of the three reasons
  there would contradict the other two. A direct branch resolves to its
  destination. An indirect branch through a `[rip+disp]` or
  absolute `[disp]` memory operand resolves the slot and the pointer currently
  in it -- the only mechanically provable indirect form; a sign-extended
  displacement is brought back into the unsigned address space by the operand
  width. A memory-slot branch is `iat_slot` when a parsed IAT entry names the
  slot or the module's IAT directory bounds are known and contain it; it is
  `indirect_memory` otherwise, carrying `iat_classification_uncertain: true`
  when the IAT bounds were unreadable and no import table parsed. An indirect
  branch through a register is reported unresolved. A target no module
  owns is still placed by the captured region table through the existing
  `region_type` / `registration` pair, which is what the console labels
  it with -- there is no separate same-region field. Nothing here names a
  function boundary, a call argument, or a stack.

  `leads` is what `_instruction_leads` names from the one proof
  `dumpex.core.insn_flow.find_transform_loop` returns for this window. It
  is console and text-report presentation state like the decode-stop
  location: no `to_dict` carries it, and the published JSON contract is
  unchanged by it. The analysis itself lives in `insn_flow` so that every
  renderer consumes one accepted semantic result rather than re-deriving
  it; `_instruction_leads` only turns a proof into a name, a signal set,
  an evidence list, and one sentence.

  The evidence list is the whole of the proof and not its endpoints.
  `TransformLoop.instruction_addresses` names the copies that carried a
  transformed value to the register the store reads, the
  `mov`/`lea`/`add` chain that carried a `call`/`pop` value to the
  address register, and the branches on the walked path from the loop's
  exit edge to a register-indirect transfer -- each of those is a step
  the claim depends on, and a reader re-checking the claim needs them.
  A fall-through run on that path is not named: it is the instruction
  rows read downwards, and what the rows do not show is which
  instruction left the run and where it went. The list is capped at
  `MAX_INSTRUCTION_LEAD_EVIDENCE`, so when a proof names more than the
  cap holds `ReportInstructionLead.evidence_truncated` says the printed
  list is a cut one.

  The rule is a two-step ladder, and each step names only what has been
  shown. `memory_transform_loop` is the base: a loop that transforms
  memory in place, in either of the two forms that prove it. An ordinary
  buffer decode loop is exactly that shape, so the name claims nothing
  about the bytes being written.

  The **direct** form is one arithmetic or logic instruction whose
  explicit memory operand is both its input and its output: a mnemonic in
  `insn_flow.TRANSFORM_MNEMONICS`, capstone's own READ *and* write access
  on that one memory operand, and a result that still derives from what
  the memory held. It carries the `memory_write_back` signal. The
  non-identity rule below is applied here too, at the memory operand's
  width rather than a register's -- `add dword ptr [rax], 0` and
  `and dword ptr [rax], -1` change nothing, and `and dword ptr [rax], 0`
  replaces the bytes with a constant, which is a scrub and not a
  transform.

  The **register-mediated** form is the same operation written across
  three instructions -- a load, a non-identity transform of the loaded
  value in a register, and a store of that surviving value back to the
  same effective address -- and it carries `register_mediated_write_back`
  instead. It is the shape a compiler and a real sample both emit far
  more often than the first, and it is proven rather than matched:

  - both accesses are normalized `DecodedInsn.memory_operands`
    (`MemoryOperand`: segment, base, index, scale, displacement, access
    width, read/write). `insn_flow.same_effective_address` requires every
    one of those to agree, so a different width at the same start, a
    segment override on one side, and the `[ebp]`/`[rbp]` address-size
    pair are all different addresses. A RIP-relative operand matches
    nothing, its own text included: `[rip + disp]` resolves against the
    NEXT instruction's address, so one displacement at two instructions
    is two addresses.

    So does an operand carrying `MemoryOperand.components_unknown`. The
    normalized record represents an absence the expression itself states
    -- no index means a scale of one, no base or segment means None, no
    displacement means zero -- but a component the binding NAMED and the
    record could not represent falls back to those same defaults, where
    it is indistinguishable from a real `[base + 0]`. The flag keeps the
    two apart, and an operand carrying it is equivalent to no operand at
    all, its own identical self included.
  - the load must not write a register its own address expression reads.
    `mov eax, dword ptr [rax]` computes its address from the `rax` it
    then destroys -- a 32-bit write clears the whole of it in 64-bit
    mode -- and `mov ecx, dword ptr [rax + rcx*4]` does the same to an
    index. A later access with identical text is then a second address,
    so such a load anchors no same-address proof.
  - agreement of the expressions is only half of equivalence. A write to
    the base or index register anywhere between the load and the store
    ends the candidate, which is what makes the two operands the same
    address under the same register versions rather than merely the same
    text. The SEGMENT register counts as one of those, named or implied:
    `insn_flow.effective_segment` resolves a 32-bit `[ebp]`/`[esp]` to SS
    and everything else to DS (in 64-bit code the CS/DS/ES/SS bases are
    forced to zero and only an explicit FS or GS can move), and moving
    that selector moves every address that resolved through it.
    `insn_flow._SEGMENT_BASE_WRITES` covers the instructions
    that move a segment BASE without touching the selector, for which
    capstone offers no group, and records WHICH base each one moves:
    `wrfsbase` FS, `wrgsbase` and `swapgs` GS, and `wrmsr` either,
    because the MSR it writes is chosen by ECX at run time and this
    module does not resolve that. A base write ends the address flow only
    when the address under analysis resolves through the segment it
    moves. A `wrfsbase` beside a `gs:` access, or beside a plain `[rbp]`
    in 64-bit code -- whose base the architecture forces to zero --
    relocates some other region and leaves this one where it was.
  - the loaded value is followed by exact register NAME, because the
    width is part of the value: a 4-byte load lands in `edx`, and a write
    to `dl` or to `rdx` leaves something that is no longer the 4 bytes
    that were read. Kills are by register FAMILY and cover
    `DecodedInsn.clobbered_registers`, the implicit writes included.
    `DecodedInsn.data_register_reads` -- the read set with the address
    registers removed -- is what separates a register that reaches a
    value from a register that is one, so `mov edx, dword ptr [rbp]`
    reads `rbp` to form an address and consumes no register's contents.
  - the transform has to be non-identity, and "not a transform" is not
    the same fact as "the value is gone". Each instruction over a tracked
    register resolves to one of three outcomes, because an analyst reads
    two different things off the two rows:

    - TRANSFORMED -- the result still derives from what was there. This
      is the outcome the proof requires exactly one of.
    - UNCHANGED -- the instruction writes back the bytes it read.
      `add edx, 0`, `shl edx, 0`, `and edx, -1`, and the `and`/`or`
      flag-test idiom between two copies of one value each set flags and
      leave the register alone. The value carries on to whatever
      transforms it below, with its origin and transform state intact;
      the instruction simply is not the transform.
    - LOST -- the instruction replaces the value with a constant, or
      leaves something this module cannot pin down. `and edx, 0`,
      `or edx, -1`, the `xor reg, reg` / `sub reg, reg` zeroing idiom,
      `sbb reg, reg` (the carry flag alone), a shift count at or past the
      operand width, and every form this module does not model. The
      register is no longer tracked.

      `adc` and `sbb` are LOST rather than UNCHANGED on two immediates,
      because they read a third input this module does not follow.
      `adc x, i` is `x + i + CF` and `sbb x, i` is `x - i - CF`, so
      either leaves x exactly when `i + CF` is zero at the destination's
      width -- and the carry being zero or one, the immediates that can
      do that are ZERO and the ALL-ONES MASK, and no others. The flag
      that decides which applies may have been set anywhere above or
      outside the window. Reading such an instruction as an identity lets
      a cancelling pair -- `stc`, `adc edx, 0`, `sub edx, 1` -- reach the
      store as a "transform" of a value it returned to exactly what was
      loaded; reading it as a transform asserts a non-identity result on
      the run where it was not one. Giving the value up instead costs a
      proof rather than the truth of one. No other immediate is affected:
      `adc edx, 5`, `adc edx, -2` and `adc edx, ecx` are transforms under
      either value of the flag. The one-instruction form asks the same
      question at the memory operand's width.

      `rcl` and `rcr` read the carry too -- they rotate an (n+1)-bit
      quantity, so a count of n+1 returns every bit to where it started,
      which x86 reaches for the narrow operands (a count is masked to
      five bits and then taken modulo 9 for a byte and modulo 17 for a
      word). They need no rule of their own: the shift range below
      already requires a count strictly between zero and the operand's
      bit width, which refuses `rcl dl, 9` and `rcl dx, 17` along with
      every other count that is not the shift its text reads as.

    `DecodedInsn.immediates` is what decides the immediate cases, at the
    destination's width -- so an `and` against all-ones reads as the
    identity it is whether the binding reports it as -1 or as the
    unsigned mask. A load and a store with only `mov`s and UNCHANGED
    operations between them is an ordinary copy and proves nothing.

    Naming one register twice is only the visible spelling of the
    same-value rule. Tracking is per VALUE as well as per register name:
    a register-to-register `mov` copies a value's identity along with its
    contents, so after `mov ecx, edx` the instruction `xor edx, ecx` is
    `xor edx, edx` written across two instructions and its result is a
    constant, while `and edx, ecx` is `and edx, edx` and its result is
    the loaded value. `add`/`adc` are in neither set: doubling a value is
    a transform of it.
  - exactly ONE transform is allowed. Two of them compose, and
    composition is where a non-identity claim stops being checkable
    without symbolic evaluation: `xor edx, eax` twice, `not` twice, and
    `add 1` then `sub 1` each write back precisely what was read, and the
    tracker's own "transformed" flag cannot see it because that flag
    never returns to False. A second transform therefore ends the
    candidate, and a genuine composite transform under-reports. After the
    transform, only an equal-width register `mov` carries the result on.
  - the walk ends without a proof on anything
    `DecodedInsn.leaves_analysis_context` marks -- a `call`, an
    interrupt, a `syscall`, a VM entry, `getsec` -- after which neither
    the tracked value nor the memory it came from is something these
    bytes still account for; on anything
    `DecodedInsn.may_write_memory` cannot rule out, on an instruction
    that does not fall through, on a CONDITIONAL branch inside the span,
    and on a direct branch from outside into
    the middle of the span, which joins a path on which the tracked
    register holds something this walk never saw.

    The conditional branch is the outside join seen from within. Both of
    its edges are real and both rejoin below, so the store then has more
    than one reaching definition and this walk established only one of
    them -- a branch over the transform delivers the value memory already
    held, which is precisely what the proof exists to rule out. Proving
    the definitions equal would need a dataflow join this module does not
    do, so a fork inside the span ends the candidate.

    `may_write_memory` is one memory-safety question asked once, at the
    decode layer, rather than a list of write forms each consumer keeps
    complete on its own. It is True for ANY explicit memory operand,
    whatever access capstone claims, because a claimed access does not
    prove a pure read: capstone reports the memory operands of `movnti`,
    `stmxcsr` and `cmpxchg16b` as read-only, and every one of those
    writes. It is True for a `call` and for an interrupt, whose pushes
    name no operand. And it is True for
    `disasm._IMPLICIT_MEMORY_WRITE_INSN_NAMES`, which carries the
    instructions that write memory while naming no memory operand at all
    -- a stack push, the `maskmov*` masked stores through `[rdi]`, and
    `clzero`, for which capstone reports no operand, no access and no
    register clobber, leaving the mnemonic as the only statement. That
    list is the enforcement point for its class and has to stay complete
    to stay safe; keeping it to the no-operand cases is what keeps it
    short. It is keyed on capstone instruction identities rather than
    rendered mnemonics. In particular, the all-register pushes are exposed
    as `pushaw`/`pushal` rather than the version-dependent `pusha`/`pushad`
    spellings, so a text-keyed rule could silently omit all eight writes.

    Under all of it sits `DecodedInsn.effects_unknown`, which is true two
    ways, because reporting SOMETHING is not the same as reporting
    everything.

    Either the report contradicts the architecture
    (`implicit_clobbers_known` False): executing the instruction must
    change the stack pointer or the accumulator and the report names
    neither, as for `enter`, a segment-register `push`/`pop`, and
    `aam`/`aad`. A report short in one place is not relied on in another.
    This is a self-consistency check rather than a list of instructions
    to distrust -- capstone models most stack instructions fully, so
    `push rbp` names `rsp` and `leave` names `rbp` and `rsp`, and the
    same instruction id therefore answers both ways depending on the
    encoding. That is what keeps a `push rbp` between a get-PC sequence
    and a loop provable, which the sanitized sample this recognizer
    exists for depends on.

    Or capstone reported no operand, no register write, no clobber and no
    group at all, and the mnemonic is not in
    `disasm._NO_EFFECT_MNEMONICS`, the allowlist of instructions that
    genuinely have no memory, general-register, or control-flow effect for
    this analysis: `nop`, `emms`/`femms`, `pause`, and
    `lfence`/`mfence`/`sfence`. Reporting
    nothing is not the same as doing nothing, and the encoding spaces the
    system instructions live in are full of the difference -- `aaa` and
    `das` change AL, `xlatb` reads through `[rbx + al]` and writes AL,
    `rdpkru` writes EAX and EDX, and every SGX and virtualisation leaf
    dispatcher (`encls`, `enclu`, `enclv`, `pconfig`) selects its
    behaviour from a register this module does not track, several of
    those leaves writing memory or entering an enclave.

    That inverts the liability deliberately. A list of dangerous
    instructions has to be complete or a proof becomes untrue; an
    ALLOWLIST of inert ones has to be complete only for the analysis to
    keep its reach. Everything unclassified now ends a candidate instead
    of passing through it.

    Two exceptions keep the rule from taking more than it has to.
    `lea` answers False, and not because its report is believed --
    capstone describes its operand exactly as it describes `movnti`'s,
    read-only -- but because the instruction is architecturally
    guaranteed never to dereference the address it computes. And
    `insn_flow._is_pure_load` lets a `mov`/`movzx`/`movsx` whose single
    memory operand is a source and whose destination is a register pass
    the walk: that is the same trust the proof already places in the
    `mov` mnemonic at both ends of it, and without it a key read from a
    table inside the body ends the candidate -- which is what the
    canonical decoder loop does.

    The remaining cost is stated rather than hidden: a read this module
    does not read as a load (`cmp dword ptr [rsi], eax`) still ends the
    walk, as does a multi-byte `nop` with a memory operand. Widening the
    load set is a trust decision per mnemonic and each one has to earn
    it; against a decoder that calls `movnti` read-only and reports
    `encls` as inert, that is the direction to be wrong in.

  A backward direct `call` does not close a loop. capstone reports a
  relative `call` in its relative-branch group as well as its call group,
  so `DecodedInsn.is_jump` is True for one; `is_call` is what separates
  them, and a backward `call` is recursion -- it pushes a return address
  every time round -- rather than the loop this analysis is about. The
  decode layer keeps `is_jump` as capstone states it, because
  `ReportDecodedInstruction.is_jump` is published and its meaning is
  fixed; the distinction is drawn here instead.

  What remains after all of this is a measured, non-zero rate at which
  the WEAK name fires on bytes that are not code. Over 10,000 512-byte
  synthetic windows of each kind: 0.32% of uniformly random ones, 0.74%
  of 30%-random-over-zeros ones, 0.17% of 10%-random ones, and none of
  pure zero padding. Every one of those is `memory_transform_loop`, whose
  own label already says an ordinary buffer decode is exactly that shape;
  `self_decoding_stub` fired on none of the 30,500 data windows measured,
  which is the ladder doing what it was built for. The withheld note is
  rarer still -- 0.13%, 0.05% and 0% of the same three -- and says only
  that a shape was there and not proven. The rate is recorded
  here rather than driven to zero, because the remaining hits are random
  bytes that happen to decode to a real read-modify-write inside a real
  backward branch, and no mechanical rule separates those from the same
  instructions written on purpose.

  A direct write-back must not write its own address. Zero bytes decode
  to `add byte ptr [rax], al` -- a read-modify-write under a transform
  mnemonic whose source register is the low byte of its own address base
  -- so padding that the anchor falls into, with a stray branch byte
  above it, otherwise reads as a transform loop. Folding an address into
  the bytes at that address is not a shape any transform loop has, and
  rejecting it costs none of the real forms (`xor [rbp], eax`,
  `xor byte ptr [rax], 0x41`, `not [rbp]`, `inc [rbp]`).

  A loop whose entry nothing reaches is not a loop. Zero padding decodes
  to `add byte ptr [rax], al` -- a transform mnemonic writing memory --
  and a data table decodes to whatever its bytes spell, so a backward
  branch decoded from data can close a "loop" around bytes no execution
  ever arrives at. `insn_flow._candidate_loops` therefore requires the
  loop entry to be reachable from the window's FIRST instruction over
  `LocalCfg`.

  That first instruction is the card's ANCHOR, not an entry point, and an
  anchor that does not fall through reaches nothing: a thread whose start
  address is a jump thunk, an explicit `--report-addr` that lands on a
  `ret` or inside an instruction, a card anchored in data. Every loop in
  such a window is then unreachable, so the gate withholds a shape it
  would otherwise have named -- and this is the ONE rejection in the
  whole ladder that says something about where the decode began rather
  than about the instructions an analyst can see in front of them. It is
  therefore the one that has to be said out loud.
  `insn_flow.transform_loop_withheld` answers whether that happened, by
  asking what the same bytes would have proven without the gate, and
  `collect_instruction_context` records the answer in
  `ReportInstructionContext.lead_limitations`. That is a presentation-only
  tuple beside `leads`, NOT an entry in `section.limitations`: the
  section's own limitations ARE published, and a sentence about what the
  lead analysis could not establish is lead analysis -- it belongs on the
  same side of the JSON contract as the lead itself. The note names no
  address either: a withheld proof is not a lead, and pointing at the
  bytes that nearly carried one would assert the thing the gate declined
  to assert. It prints beside the instruction rows, it moves no status,
  and it is absent whenever a lead was read or no shape existed at all.

  `transform_loop_withheld` reports a second reason, `WITHHELD_UNPROVEN`,
  for the same rule: a decline an analyst cannot read off the rows gets a
  note, and one they can does not. Here the load, an attempted transform
  and a same-address store are all present inside a reachable loop, and
  the value between them was not provably the same transformed value --
  a composite transform this module will not compose, a clobber of that
  value it cannot rule out, an access it cannot account for. A load and a store with no
  transform between them is NOT this: that is a copy loop, which the rows
  show plainly, and it stays silent along with a store at a different
  address.

  "An attempted transform" means one the proof's OWN non-identity rules
  accept, reading the loaded value and reaching the register the store
  writes. `insn_flow._attempted_transform_reaches_store` is
  `_prove_load_transform_store` with exactly one half removed, so the two
  cannot drift: the same `_TrackedValue` origins, the same three-outcome
  carry, the same same-value rule. A copy loop with an unrelated
  `xor eax, ecx` beside it, a `xor edx, edx` that zeroes what was read,
  an `add edx, 0` that changes nothing, an `and edx, 0` that leaves a
  constant, and a transform of one copy when a different copy reaches
  memory are each a negative the instruction rows state outright, so none
  of them gets a note.

  The ADDRESS half is not removed either, and for the same reason. A
  write to the base, the index, or the effective segment selector between
  the two accesses makes them two addresses, as does a segment-base write
  moving the base THIS address resolves through without touching the
  selector -- `_address_version_survives` is the one rule both the proof
  and this query ask. An analyst reads that instruction in the
  rows, so the two accesses are not a same-address candidate and there is
  nothing to call unproven.

  What IS removed is everything about whether a TRANSFORMED value
  survives: once an entry carries one, a clobber of it, a memory write, a
  call, a control-flow stop, a fork, a join. That is the half the proof
  declined on and the half the rows do not show, which is what the note
  is for.

  For an entry carrying no transform yet, nothing is removed. A
  `mov edx, eax` over the loaded value, a `xor edx, edx` that zeroes it,
  a narrow `mov dl, al` over part of it -- each of those says on its own
  row that what reaches a later transform is not what was loaded, so that
  transform transforms something else and there is no declined proof to
  report.

  That relaxation is decided PER TRACKED VALUE and never for the walk as
  a whole. One loaded value can sit in several registers at once, and
  what happened to one copy says nothing about another: after
  `mov ecx, edx` and `xor ecx, eax`, the copy in `ecx` carries a
  transform and the copy in `edx` does not, so a `mov edx, ebx` below
  them still ends `edx` while `ecx` carries on. A walk-wide flag would
  let the transformed sibling shelter every untransformed one, and a
  store reading a register the rows show arriving from elsewhere would
  produce a note about a proof that was never close. Both reasons are notes rather than leads, and both stay out of
  the published document.

  Code reached only through a branch this module cannot resolve -- an
  indirect one, or one from before the window -- is likewise not reached
  here, and under-reports. That is the direction this errs in, now with
  the cost visible at the point of use rather than only here.

  Lying between the branch target and the branch is NOT enough for either
  form, and `insn_flow._loop_body_holds` is the gate: the target must be
  an instruction boundary this decode produced, nothing from the target
  up to the access may end the run (the instruction AT the target
  included -- a `ret` sitting exactly there is the case this rejects),
  and nothing after it may end the run before the closing branch. What
  ends a run is `DecodedInsn.falls_through`, decided at the decode layer
  from capstone's instruction id and groups rather than from mnemonic
  text. `dumpex.core.disasm._NON_FALLTHROUGH_INSN_NAMES` is the whole
  list and says why each entry is on it: a far `ljmp` ends a run exactly
  as a near `jmp` does, `retf`/`iret` exactly as `ret` does, and an
  instruction that never reaches its successor at all -- an undefined
  opcode, `hlt`, a return to another context (`sysret`/`sysexit`/`rsm`),
  `sysenter` (which records no return address, so where control resumes
  is an OS convention rather than a fact about these bytes), a
  transactional abort -- ends it too, because assuming a handler resumes
  below it is not something a byte window shows. The list also records
  what was considered and left off, each for its own reason: `syscall`
  DOES record the address to come back to, `int`/`int3` return to their
  successor, and a VM entry falls through precisely when it fails.

  `self_decoding_stub` additionally requires one of the proven address's
  registers -- base or index, since `[rax + rbp*4]` computes its address
  from both and which one a compiler chose says nothing about the
  relationship -- to carry a value a `call`/`pop` pair in the same window
  left the code's own address in, AND no return and no unconditional
  branch between that `pop` and the loop. The `pop` has to end before the
  loop entry and before the loop's first access to that address; a pair
  inside or after the loop, or anywhere else in the 512-byte window, says
  nothing about this loop.

  The `call` itself has to be reachable from the anchor. A `call` nothing
  arrives at pushed nothing, so a `pop` below it read a value that came
  from outside this window, and crediting the code's own address to it
  would credit a write to an instruction no path executes -- a `jmp` over
  a `call`, straight onto the `pop` it targets, is exactly that shape.

  The widths have to agree, all three of them: what the `call` pushed
  (`DecodedInsn.return_address_width`, which is the instruction's own
  operand size -- a `callw` in 32-bit code pushes two bytes where a plain
  `call` pushes four), what the `pop` took (`register_width` of its
  destination, which must also be `is_full_width_register` for this
  architecture), and the architecture's own address width. `pop bp` after
  an x64 `call` recovers sixteen bits of a sixty-four-bit return address
  and leaves the rest of `rbp` holding whatever it held before, so
  `[rbp]` is not an address this code computed. Requiring one number for
  all three rejects every mismatch without enumerating them.

  That value is followed per register FAMILY, not per name:
  `dumpex.core.disasm.register_family` maps `rax`, `eax`, `ax`, `al` and
  `ah` to one register. Writing any of them ends what it held, and the
  kill covers `DecodedInsn.clobbered_registers` -- every register
  capstone says the instruction writes, the implicit ones included, so a
  `mul` that overwrites `rax` without naming it leaves nothing stale
  behind. The kill is unconditional and comes first, because a 32-bit
  write in 64-bit mode zeroes the upper half outright and an 8- or
  16-bit write leaves the rest stale; in neither case does a 64-bit
  address survive.

  Anything `DecodedInsn.leaves_analysis_context` marks ends every carry
  at once. capstone reports a `call`'s own writes as the stack and
  instruction pointers alone, so treating it as an ordinary instruction
  would leave every other register looking intact across a function whose
  body was never examined -- and a volatile address register is precisely
  the one a callee may replace. A resolver call between a get-PC sequence
  and a decode loop is an ordinary layout, not an exotic one, which is
  why this matches the value proof's own rule rather than being more
  permissive than it.

  The same holds for an instruction the decoder reported nothing about
  (`effects_unknown` above), which is not the same as an instruction that
  does nothing -- a carried address does not survive an `xlatb` or a
  `rdpkru` merely because capstone named no clobber.

  And it holds, with less of the state visible, for everything else that
  hands control to code this window does not contain: `int 0x80`,
  `int3` and `syscall` enter a handler or the kernel, and `vmcall`,
  `vmmcall`, `vmlaunch`, `vmresume`, `vmfunc`, `vmrun` and the rest of
  capstone's `vm` group enter a hypervisor. Most of them fall through to
  their successor, clobber no register capstone reports, and name no
  memory operand, so the group they are in is the only thing that says
  other code ran at all. `getsec` is in no group and is carried by name,
  as is `enclu`, whose EENTER/ERESUME/EEXIT leaves transfer into and out
  of an SGX enclave -- EAX selects which, and this module does not track
  EAX, so every `enclu` is read as the transfer.

  capstone's `privilege` group is deliberately not read for this: it is
  broader than the claim -- `mov es, ecx` is in it, and loading a segment
  register hands control to nobody -- and a group whose membership
  exceeds the fact is not a mechanical basis for stating the fact. What a
  privileged instruction can still do to an ADDRESS is handled where it
  belongs, in the address-version set and
  `insn_flow._SEGMENT_BASE_WRITES`.

  The carried address must be CONSUMED, not merely mentioned.
  `DecodedInsn.register_reads` names a memory operand's base and index
  too, so `add rcx, qword ptr [rbp]` reads `rbp` -- and what it adds to
  `rcx` is the memory AT that address, not the address. Reading the
  sources through `data_register_reads` is what stops a register that
  only supplied an address from promoting a register holding something
  fetched with it, which would otherwise call an ordinary
  pointer-out-of-a-table buffer loop a self-decoding stub. `lea` is the
  one exception and takes the wider set: its memory operand is never
  dereferenced, so there the address registers ARE the value. A
  `add`/`sub` with any memory operand is rejected outright -- that is a
  load however the mnemonic reads.

  The carried address has to arrive with a COEFFICIENT OF ONE. Every
  register in the carry set holds the value of one `pop`, so an
  instruction that consumes it more than once, or scales it, leaves a
  multiple or a difference of this code's address rather than a place in
  it: `sub rcx, rbp` between two carrying registers is zero, the same
  after `lea rcx, [rbp + 0x20]` is the constant `0x20` -- a displacement,
  which names no location -- and `add rbp, rbp`,
  `lea rbp, [rbp + rbp]`, `lea rbp, [rbp*2]` and
  `lea rcx, [rcx + rbp]` after `mov rcx, rbp` are each a multiple.

  The coefficient is summed over the instruction's inputs rather than
  read off a pair of register names, because the name is not what
  matters: a register named twice counts twice however the operand list
  spells it, an index register contributes its own scale, and two
  different names carrying one value count once each. `sub` counts its
  second input negatively, which is how a difference reaches zero. None
  of those results is a place in this code, so none of them carries, and
  a transform through such a register stays `memory_transform_loop`.
  `add` with only its second input carrying is the ordinary
  offset-plus-address form and is untouched.

  The SAME sum is taken over the memory operand the loop actually
  touches, and not only over the instructions that led to it. The
  intermediate rule and the final one are one rule
  (`insn_flow._address_carries_once`), because the address that decides
  the claim is the one the access uses: `[rax + rbp*4]` is four times
  where this code sits, and `[rbp + rcx]` after `mov rcx, rbp` is twice
  it, whether the scaling happened in an `lea` above or in the access
  itself. Each names a location computed FROM the code's address rather
  than a location IN it. `[rax + rbp]` still correlates -- one whole copy
  of the popped value plus whatever `rax` holds -- as does a scaled index
  that carries nothing, like `[rbp + rax*4]`.

  That address also has to reach the access at this architecture's full
  ADDRESS width. `register_family` is the right question for a kill and
  the wrong one for a use: a write to `ebp` does destroy what `rbp` held,
  which is why kills are asked by family -- but `[ebp]` in 64-bit code is
  an address-size override that resolves through the low 32 bits of `rbp`
  and discards the rest, `[bp]` in 32-bit code through the low 16, and
  `lea rcx, [ebp]` computes from the same truncated half. None of those
  is the address the `pop` recovered, so none of them upgrades the lead,
  however plainly the family says it is the same register.

  Only then does one destination take the value on, and only for the
  instruction forms `insn_flow._carrying_destination` models: a
  register-to-register `mov`, an `lea` address computation, and
  `add`/`sub`/`inc`/`dec` whose destination is also an input. Each needs
  exactly one written register, at this architecture's full width
  (`is_full_width_register`: `rax` on x64, `eax` on x86). Reading a
  carrying register is NOT sufficient -- `and reg, 0` and `or reg, -1`
  read one and leave a constant, `xchg` writes two destinations that are
  not interchangeable, and a load (`mov dst, [src]`) brings back what the
  memory held rather than the address used to reach it. This is a
  whitelist on purpose: a blacklist of value-destroying forms would have
  to be complete to be safe, and x86 has too many ways to reduce a
  register to a constant for that to be a claim worth making. Everything
  unmodelled -- including a value that moves through a narrower register
  and back -- under-reports, and under-reporting is the direction this
  errs in.

  `register_transfer_after_loop` is a supporting signal and never a gate.
  It is read over `insn_flow.LocalCfg`, a graph whose nodes are the
  instruction boundaries this decode produced and whose edges are the
  transfers each instruction states for itself: a fall-through (only when
  `DecodedInsn.falls_through` says so), a direct conditional branch's
  taken edge, a direct unconditional branch, and a direct call. A
  destination outside the window contributes no edge, because a path that
  leaves is a path the graph cannot follow. Every edge OUT of the loop
  body is considered, not only the closing branch's fall-through: an
  unconditional backward `jmp` has no fall-through edge at all, and the
  edge that leaves such a loop is a conditional branch inside the body.
  Because reachability is walked over the graph rather than over byte
  order, bytes below an unconditional branch that nothing targets are not
  reached and cannot supply the transfer -- which is what "bytes after a
  branch may be data" means mechanically.

  That walk also STOPS at the loop body. An edge that leaves the body's
  address span and falls straight back into it has not left the loop, and
  a transfer reached only after re-entering is inside the loop rather
  than after it. Cutting the walk at the body is what makes "after the
  loop" a statement about control flow instead of about which addresses
  happen to lie outside the span.

  Only a CONDITIONAL branch's edge is accepted as an exit, and that rule
  is applied rather than inferred afterwards. A `call` edge is not an
  exit: control comes back below the call and carries on round the loop,
  so reading one as an exit would report a transfer on a path that
  returns. An unconditional branch out of the body cannot occur in a
  proven loop at all -- `_loop_body_holds` requires uninterrupted runs
  either side of the access and would already have rejected it. What
  remains is a conditional branch's taken edge and the closing branch's
  own fall-through, both of which belong to a conditional branch. So the
  record carries no flag saying so, and the closed vocabulary spends no
  second signal name on a fact `register_transfer_after_loop` already
  implies.

  Every step is bounded: `insn_flow.MAX_PROOF_ATTEMPTS` caps the
  candidates one window evaluates, `MAX_TRACKED_VALUES` caps the values
  followed through one span, and the graph walk is bounded by the decoded
  instruction count, so a window that is one cycle terminates.

  Linear order is not an executed path, and these relationships are the
  weakest ones that still connect the instructions to each other; none
  asserts that any of it ran. The console prints a lead in the ASSESSMENT
  block beside the findings, under its own heading and its own next step,
  and the verdict line and indicator count are still computed from
  `card.findings` alone. The next step is chosen by whether the card
  carries a correlated thread: a card anchored by an explicit address or
  a string hit has none, and is told to establish which thread or control
  flow reaches the region instead.

  At most one lead is printed -- the strongest the window supports, never
  a list of every shape in it -- and the two blocks that mention it carry
  different halves. ASSESSMENT carries the lead's sentence. INSTRUCTION
  CONTEXT carries its signal names, and under `--verbose` its evidence
  addresses, which sit beside the instruction rows they are re-checked
  against, marked `(+more)` when the proof named more instructions than
  the cap holds. Neither block repeats the other's half.
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
introduced in 3.8.0 are covered by `tests/integration/test_report_hierarchy.py`;
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
