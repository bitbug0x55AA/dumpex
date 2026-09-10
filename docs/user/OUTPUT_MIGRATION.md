# Output Schema Migration

This document records dumpex's structured-output compatibility history. It is
for consumers validating archived case records or upgrading parsers. For the
current contract, see [Output and Evidence Schema](OUTPUT_SCHEMA.md).

## Compatibility rule

Select a schema from the document's own `meta.schema_version`; never rewrite an
archived result merely to make it validate against a newer schema. Historical
schema files remain packaged and frozen so old evidence can still be validated.

A new schema version is required when dumpex changes the produced wire shape in
a way an existing consumer must understand, including:

- adding a `result.kind` value;
- adding/removing a required field on a closed object;
- changing a closed enum;
- removing or reshaping a field producers emitted;
- changing a record's keying or nesting.

Clarifying documentation, console-only presentation, or adding a coverage code
to an intentionally open string vocabulary does not by itself require a bump.

## Packaged v2 schemas

| Commands | Contract | Schema file |
|---|---|---|
| `--list`, `--modules`, `--threads`, `--process`, `--sysinfo`, `--handles`, `--profile`, `--diff`, `--extract`, `--strings`, `--report`, `--hunt` | v2.18 (current) | [`dumpex-output-v2.18.schema.json`](../../dumpex/schemas/dumpex-output-v2.18.schema.json) |
| — (historical) | v2.17 | [`dumpex-output-v2.17.schema.json`](../../dumpex/schemas/dumpex-output-v2.17.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.16 | [`dumpex-output-v2.16.schema.json`](../../dumpex/schemas/dumpex-output-v2.16.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.15 | [`dumpex-output-v2.15.schema.json`](../../dumpex/schemas/dumpex-output-v2.15.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.14 | [`dumpex-output-v2.14.schema.json`](../../dumpex/schemas/dumpex-output-v2.14.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.13 | [`dumpex-output-v2.13.schema.json`](../../dumpex/schemas/dumpex-output-v2.13.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.12 | [`dumpex-output-v2.12.schema.json`](../../dumpex/schemas/dumpex-output-v2.12.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.11 | [`dumpex-output-v2.11.schema.json`](../../dumpex/schemas/dumpex-output-v2.11.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.10 | [`dumpex-output-v2.10.schema.json`](../../dumpex/schemas/dumpex-output-v2.10.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.9 | [`dumpex-output-v2.9.schema.json`](../../dumpex/schemas/dumpex-output-v2.9.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.8 | [`dumpex-output-v2.8.schema.json`](../../dumpex/schemas/dumpex-output-v2.8.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.7 | [`dumpex-output-v2.7.schema.json`](../../dumpex/schemas/dumpex-output-v2.7.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.6 | [`dumpex-output-v2.6.schema.json`](../../dumpex/schemas/dumpex-output-v2.6.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.5 | [`dumpex-output-v2.5.schema.json`](../../dumpex/schemas/dumpex-output-v2.5.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.4 | [`dumpex-output-v2.4.schema.json`](../../dumpex/schemas/dumpex-output-v2.4.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.3 | [`dumpex-output-v2.3.schema.json`](../../dumpex/schemas/dumpex-output-v2.3.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.2 | [`dumpex-output-v2.2.schema.json`](../../dumpex/schemas/dumpex-output-v2.2.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.1 | [`dumpex-output-v2.1.schema.json`](../../dumpex/schemas/dumpex-output-v2.1.schema.json) — frozen; no command emits this anymore |
| — (historical) | v2.0 | [`dumpex-output-v2.0.schema.json`](../../dumpex/schemas/dumpex-output-v2.0.schema.json) — frozen; no command emits this anymore |

## Version summary

| Version | Consumer-visible change |
|---|---|
| 2.18 | Added PE, instruction, and IAT correlation to `--report` enrichment, building on the v2.17 sections. `result.summary.pe_context` is one process-wide object per invocation: the main image's identity (machine, timestamp, `SizeOfImage`, preferred `ImageBase`, actual base, entry point, section count -- the canonical PE profile's own decoded values) and the main-image correlation layer's `consistent_count` / `conflict_count` / `unavailable_count` tally, with `observations` carrying the retained `conflict` observations. Every `triageCardRecord` additionally carries `anchor_pe_context`, `instruction_context`, and `iat_correlation` alongside the v2.17 `exception_context`, `allocation_neighborhood`, `handle_correlation`, and `string_context`. Each carries an `enrichmentSection` with the same `missing` / `partial` / `complete` semantics: `missing` means the evidence was not there and nothing was evaluated, `partial` means it was usable but incomplete, `complete` with `included` 0 means a bounded evaluation found no eligible item -- a consumer must not read an empty subset as a negative. `anchor_pe_context.classification` places the anchor as `headers`, `code`, `data`, `import_iat`, `relocation`, `unmapped`, or `outside_image` within its owning module, `module` when that module's PE profile was not available to place it finer, or `private` / `unresolved` when no module owns it; `protection_matches_declared` compares the section's declared R/W/X against the live region protection. `instruction_context` decodes a bounded window at the highest-priority approved anchor source correlated with this card -- an exception RIP only when its record relates to the anchor thread or region, a live thread RIP or StartAddress only for the anchor thread, then the card anchor, named in `anchor_source` -- through an optional isolated disassembler. `architecture` is fixed by the COFF `Machine` of the module that owns the chosen anchor (`I386` is x86, `AMD64` is x64; a concrete non-x86 machine, ARM64 included, is `unsupported_arch`), falling back -- when that module carries no `Machine` -- to a WOW64 thread context, then the main image `Machine` (checked before the dump SystemInfo, which reports the host, not the process), then the anchor thread's context flavour, then the SystemInfo. So an anchor in unbacked private code is still decoded on an x64 dump, and a WOW64 process is decoded x86. `decoder_state` is `decoded`, `not_run` (no captured bytes at the anchor), `unavailable` (no disassembler installed -- `pip install dumpex[disasm]`), `unsupported_arch`, `arch_undetermined` (no signal fixed the architecture), `decode_error` (an invalid opcode a full instruction's worth of bytes from the failure point still cannot decode), or `undecoded_tail` (the capture ends before that many lookahead bytes are available and a short trailing run did not decode -- an invalid opcode or a cut-short instruction, indistinguishable); every value but `decoded` makes the section `partial`, as does a window the byte cap or the end of the capture cut short, or a non-decoded window -- its `total` is then null. A legitimate instruction the byte cap cut is `decoded` (byte-cap truncation), not `decode_error`. When both `--report-addr` and `--report-tid` are given, the explicit address leads the anchor priority. Direct branch targets and mechanically-proven indirect memory-slot targets (`[rip+disp]` and absolute `[disp]`) are resolved to module / section / region in `branch_targets`; a memory slot is `iat_slot` when a parsed IAT entry names it or the module's IAT directory bounds contain it, `indirect_memory` otherwise -- carrying `iat_classification_uncertain: true` when the run could not confirm it is outside the IAT -- and an indirect branch through a register is `indirect_register` with no address. `iat_correlation` reuses the canonical in-memory IAT parser over the module that owns the instruction window's anchor (falling back to the card anchor's module when there is no window) and retains only slots a window branch targets or whose live thunk target is unusual -- `slot_out_of_bounds`, `target_unregistered`, `target_private_executable`, or `instruction_correlated`, named in `selection_reason`. A module whose import-directory array was unreadable reports `import_directory_present: null` and a `partial` section rather than a completed "no imports"; a module that positively declares no import directory is `complete` with no missed-slot limitation. A population gap in the walk (a failed descriptor/thunk read, an unterminated or cyclic table, a walk cap) reports `total: null`, and so does an unreadable data-directory array (the IAT directory bounds are then unknown, so an unchecked slot might qualify via `slot_out_of_bounds`); an unread import symbol name makes the section `partial` with its own note but leaves the eligible count exact. When `total` is null, a known-eligible set larger than the retention cap still sets `truncated: true`. A `pe_context` conflict observation, a redirected or private IAT thunk target, and a declared-versus-live protection mismatch are investigation leads, never verdict dimensions. Every dump-derived string in these sections obeys the same 200-character cap and carries its own truncation flag; the main-image PE profile, its correlation, and each anchor module's parsed IAT are collected once per invocation and reused by every card. Enrichment stays captured evidence only: it never appears in `findings`, `finding_details`, or `verdict`, adds no `coverage.limitations` entry, and no `coverage.status`, verdict, score, confidence, Finding identity, or exit code moves. See the v2.17 row below for the `process_enrichment`, `exception_context`, `allocation_neighborhood`, `handle_correlation`, and `string_context` projections this builds on |
| 2.17 | Added `--report` enrichment. `result.summary.process_enrichment` is one process-wide object per invocation -- process identity from the same canonical boundary `--process` uses, an allowlisted session slice of the environment block, a bounded per-type handle census, and an explicit TokenStream capability status. Every `triageCardRecord` additionally carries `exception_context`, `allocation_neighborhood`, `handle_correlation`, and `string_context`, each scoped to that one card's anchor. Each of those projections carries an `enrichmentSection` naming its `scope` (`process` or `card`), its evidence state (`missing`, `partial`, or `complete`), the eligible `total` it selected from, the `included` count it kept, its `cap`, whether the retained set was `truncated`, its `provenance`, and its `limitations`. The three states are the point: `missing` means the stream or pages were not there and nothing was evaluated, `partial` means the evidence was usable but incomplete, and `complete` with `included` 0 means a bounded evaluation ran and found no eligible item -- a consumer must not read an empty subset as a process-wide negative. `total` is `null` only where the eligible population is not determinable, and wherever it is known `truncated` is exactly `included < total`, so an eligible item is only ever dropped by the declared cap. `string_context` re-selects the strings the card's single content read already produced -- the query hit first, then IOC-pattern matches, then remaining strings by absolute distance from `distance_anchor_address` -- and performs no second region read; proximity is layout, not a claim that an adjacent string is referenced by the anchor. `handle_correlation` matches a handle object name's LAST path segment against text captured in the examined range -- a namespace prefix such as `Device` is shared by unrelated objects and never correlates on its own -- compares every collected handle, and deduplicates by `handle`. `allocation_neighborhood` walks OUTWARD past the anchor's own allocation so the regions bounding a private reservation are always candidates, reserves them ahead of the allocation's own subregions when the cap binds, and counts every considered region in `total`. `exception_context` decodes an access violation's `access_type` and `referenced_address` and resolves both that address and the faulting address to a region and module; registers and ExceptionStream-versus-thread-context comparison are deliberately not in this contract. Identity disagreements between captured sources are published in `process_enrichment.identity_conflicts` rather than in that section's `limitations`, so a fully captured conflict never reads as a collection gap: only a diagnostic reporting an unavailable preferred source keeps driving the evidence state. An absent `MemoryInfoListStream` is distinguished from one the dump declares but could not parse. Every dump-derived string in these sections -- object and type names, module owners, paths, command lines -- obeys one 200-character cap and carries its own truncation flag. The region table and the handle inventory are each collected and indexed once per invocation, so per-card work is bounded by the section caps rather than by the size of those tables, and the region view holds at most one descriptor per base address so a dump declaring the same base twice degrades the neighborhood instead of stopping the report. `--report-string` additionally carries an invocation budget -- at most 32 cards and 256 MB of cumulative content reads -- and reports what it did not triage in the new `summary.cards_skipped_for_budget`, alongside `execution_status: partial` and a `REPORT_CARD_BUDGET_REACHED` diagnostic; the hit counters keep naming every hit the search found. The region covering a hit is resolved once, up front, and drives every later decision -- image/private classification, grouping, the budget charge, and the card itself. On an overlapping region table, classifying on the search's own region while carding the covering one made `hits_private`/`hits_image`/`image_hit_modules` describe different regions than the cards did; a second lookup additionally budgeted one region's size for another's read and published a hit offset measured from the wrong base. Hits sharing one covering region yield one card. Counting happens after the budget, because a group the budget skipped covers nothing: its hits go to the new `summary.hits_skipped_for_budget` (with `cards_skipped_for_budget` counting the regions), never to `summary.hits_sharing_a_region`, which now counts only hits inside a region that actually received a card. `card_count + hits_sharing_a_region + hits_skipped_for_budget` accounts for `hits_private`, and `hits_private + hits_image` accounts for `total_hits`. It is two captures of one name in one dump, not proof of use, and the complete inventory is still `--handles`. A section is `complete` only when every body of evidence under it is: a partial handle inventory, an unread handle name, a short card read, or a region descriptor the model could not represent each make the owning section `partial` rather than letting an empty subset read as a completed check. Enrichment is captured evidence only. It never appears in `findings`, `finding_details`, or `verdict`, adds no `coverage.limitations` entry, and no `coverage.status`, verdict, score, confidence, Finding identity, or exit code moves |
| 2.16 | Added `eligible_bytes`, `unscanned_pass_bytes` and `unscanned_fraction` to `coverage.missed_bytes`: how much scanning work the run had in front of it, how much of that work did not happen, and the second as a proportion of the first. An absolute byte count ranks two runs against each other and says nothing about either on its own -- 3.2 MB unscanned is a rounding error out of 11.4 GB eligible and almost the whole hunt out of 3.4 MB -- so the proportion is what lets a pipeline apply one threshold across dumps of any size. All three measure **scanning work, per pass**, which is a different basis from `bytes`: a hunter that runs three passes over one region had three passes' worth of work to do, so that region contributes three times to `eligible_bytes`, and a region only one pass skipped contributes once to `unscanned_pass_bytes`. Gap ranges are unioned *within* a pass (one pass can name the same bytes under two codes) and summed *across* them. A pass's scope includes items a whole-scan budget left unreached, so `unscanned_pass_bytes <= eligible_bytes` always. `bytes` keeps its own memory basis -- what a re-collection would have to recover -- and is deliberately NOT the numerator: dividing it by a per-pass scope would report a region EVERY pass skipped as two-thirds scanned. The scope is per producer and reflects that producer's own filters, so two hunters over one dump legitimately report different denominators, and the number is a property of the hunter, never of the dump. `eligible_bytes` and `unscanned_fraction` are `null` when no denominator was established: a producer that measures no eligibility, a scan loop that took items into scope without measuring them, and every `coverage.status` of `not_evaluated`. `null` and `0` are different answers -- `0` says a scan measured its scope and had no capturable memory in front of it. `unscanned_fraction` is additionally `null` when `state` is `unknown` -- `0` is what a run that missed nothing looks like, and a budget that stopped a scan somewhere unmeasured must never render as `0`. Where it is non-null it is exactly `unscanned_pass_bytes / eligible_bytes` and carries `state`'s own qualifier: an exact proportion under `exact`, a floor under the real one under `lower_bound`. `--hunt`'s document-level `coverage.missed_bytes` reports both as `null`; eligibility is per hunter and there is no dump-wide scope to roll up into. Every hunter publishes a scale except `hollowing`, whose limitation codes never describe unexamined bytes, so its `bytes` is always `0` and there is nothing to scale. `coverage.status` keeps its three values and its meaning, and no verdict, score, confidence, `coverage.reasons` string, or exit code moves |
| 2.15 | Added `coverage.missed_bytes` on every result and every hunter record: how much captured in-scope memory that run's own coverage gaps add up to, so a `partial` can be told from a `partial`. `state` labels the figure -- `exact` (every gap's extent is established), `lower_bound` (some gap could not be measured, so `bytes` is a floor under the real total), or `unknown` (no gap's extent is established, and `bytes` is `null`). A consumer thresholding on `bytes` must read `state` first: `null` and a lower bound each mean something other than "this much was missed", and `0` with state `exact` is the only shape that says nothing capturable was missed. `complete` is true exactly when `unquantified_gaps` is `0`. `bytes` measures memory, not gap records: the unexamined address ranges are unioned, so one physical region named by several gaps at once (obfuscation's three scan layers skip overlapping region sets; a `--hunt all` run reaches the same region once per analyzer) is counted once and the figure can never exceed what the dump captured. `quantified_gaps` counts the gap records and `distinct_ranges` the merged ranges they cover; neither counts bytes, and neither does a limitation's own `affected_count`. Added `examined_size` and `unexamined_size` on `scanTarget` -- how many of that target's captured bytes were examined, and the remainder that was not -- both `null` when the extent was never established, which is not the same claim as `0`. The aggregate is the union of exactly those per-target ranges, so the two cannot disagree about any one target and the total never counts memory two gaps both name twice. `coverage.status` keeps its three values and its meaning, `derive_status` is unchanged, and no verdict, score, confidence, or exit code moves: this grades a `partial`, it does not redefine when one is reported |
| 2.14 | Added `huntSummary.scan_scope` in both hunt modes, and `targeted_scope` on a targeted rescan's hunter details. Added the `coverageLimitation.code` value `TARGETED_SOURCE_NOT_EVALUATED`. A targeted hunter record's `coverage.status` may be `complete` with a non-empty `coverage.limitations`: those entries name coverage sources outside what a targeted rescan evaluates, not gaps in what it did. Full-scope records keep the earlier `complete` implies no limitations relationship. `scan_scope` is cross-checked by the schema rather than merely well-formed: a `targeted` tag must agree with `summary.selected` and with that analyzer's registered source/scopes, and requires `targeted_scope` on the record; a `full` tag forbids it. A `targeted_scope` entry also carries `applicability_reason` and `measurements`, and its `coverage_status` may be `not_applicable` -- the source's own eligibility gate declined the target, which is the boundary of what that source speaks about and not a gap. A consumer must not count it as a coverage failure; `coverage.status` does not, and a rescan whose closures all decline the target reports `not_evaluated`. Added the `coverageLimitation.code` value `TARGETED_SOURCE_NOT_APPLICABLE` |
| 2.13 | Replaced retired `pid`/`peb` result kinds with `process`, `handles`, and `profile`; updated `sysinfo` records |
| 2.12 | Added target identity for read/short-read/budget gaps, capture-state fields, skip causes, and partial evidence availability |
| 2.11 | Added exact hidden-PE candidate address, region offset, and dump-file offset |
| 2.10 | Added deep-triage reason codes and bounded findings under investigation actions |
| 2.9 | Added `huntSummary.investigation_actions` |
| 2.8 | Added structured skipped scan `targets` to coverage limitations |
| 2.7 | Re-keyed Cobalt Strike config fields by field name |
| 2.6 | Removed redundant raw hex from Cobalt Strike config field values |
| 2.5 | Added normalized finding identity, severity, ATT&CK, evidence, IOC, and rule-provenance fields |
| 2.4 | Migrated `--hunt` to the shared v2 envelope |
| 2.3 | Added the `report` result kind |
| 2.2 | Added `extract` and `strings` result kinds |
| 2.1 | Added the `comparison` result kind and envelope support later used by artifacts/diagnostics |
| 2.0 | Introduced the shared `meta`/`result` envelope for structured commands |

## Producer behavior within v2.18

Not every change to what dumpex emits changes the wire shape. These narrow what
a current document contains without changing what it may contain, so
they need no schema bump and every archived document stays valid — but a
consumer that inferred a rule from earlier output should read them.

- `triageCardRecord.instruction_context` is present only when the card resolved
  an anchor address; a card with no anchor at all (an unresolved `--report-tid`)
  carries `null`. When it is present but the disassembler is not installed, the
  section is `partial` with `decoder_state: "unavailable"` and an empty
  `instructions` list — never absent, so a consumer can tell "not decoded" from
  "no branches found".
- `iat_correlation` is `null` when the anchor is in no loaded module, `missing`
  when the module's PE header or import table could not be read, and `complete`
  with an empty `entries` list when the module imports nothing or nothing about
  its imports was unusual.

- `investigation_actions[].recommended_actions` includes a
  `targeted_hunter_rescan` entry only when at least one hunter that skipped the
  target can actually run a `--hunt-addr` invocation over it, and only when this
  dump holds bytes to rescan. Its `hunters` names that subset rather than every
  skipping hunter. Consumers reading it as "who left this gap" must read
  `skipped_by` instead, which is unchanged and still names all of them; an
  action with no rescan entry still carries `recollect_dump` or
  `inspect_metadata`, and `recommended_actions` is still never empty.
- No investigation action carries a rendered command line, under any key. The
  address, size, and hunter are the structured inputs; quoting belongs to the
  shell that reads a command, so a consumer that needs one builds it. This is a
  fixed property of the contract, not a field awaiting a later release.
- A `--hunt pipe` run whose HandleDataStream dropped part of its descriptor
  array carries one `HANDLE_STREAM_TRUNCATED` limitation, sourced to
  `handle_data`. `coverage.sources` is unchanged, on that run as on any other:
  the pipe hunter publishes the same three sources whatever went wrong, so a
  consumer can compare a full-scope record and a later targeted rescan source
  by source. Note that the same limitation code appears under `--handles` with
  `source: "handles"` — one stream, named as each command has always named it,
  and `affected_count` means the same thing in both.
- The `pipe` hunter's `handle_data` source can now be `failed`, with the
  parser's own error text in `detail` and a companion `SOURCE_FAILED`
  limitation. A dump that carried a HandleDataStream which would not parse
  previously reported that source as `absent`, whose reason text said the dump
  was captured without handle data. A consumer distinguishing "re-collect with
  handle data" from "this dump's handle stream is corrupt" reads `state`,
  exactly as it already does for `--handles`. Nothing changes for a dump whose
  handle stream is absent, or readable with no recorded parse failure.
- When a HandleDataStream parse failure is recorded, `--hunt pipe` scores no
  handle from that stream, and its `details.handle_pipes` is empty even if the
  dump also carried a parsed stream object. A dump can declare the same stream
  type at more than one directory index; only one parse outcome is retained per
  stream type, so which entry a surviving object came from cannot be
  determined. A consumer must therefore not read an empty `handle_pipes` beside
  a `failed` `handle_data` as "no pipe handles were held" — the record's
  `coverage.status` is `partial` and the hunter's own `status` is
  `INCONCLUSIVE`, never a clean result. `--handles` resolves the same dump the
  same way.

## Important upgrade boundaries

### v2.12 to v2.13

Consumers must recognize `result.kind` values `process`, `handles`, and
`profile`. The older `pid` and `peb` kinds are not aliases and are not produced.
The CLI likewise uses `--process`, `--handles`, and `--profile`.

### v2.8 to v2.12

Coverage gaps became actionable rather than count-only:

- v2.8 identifies skipped targets;
- v2.9 groups them into the hunt-all investigation queue;
- v2.10 records bounded deep-triage content signals;
- v2.11 identifies hidden-PE candidates precisely;
- v2.12 distinguishes skip causes, capture completeness, and budget facts.

Consumers should use structured limitation/action fields rather than parsing
`coverage.reasons` text.

Deep-mode triage is a historical v2.10-v2.13 producer shape. Current dumpex
keeps those schemas frozen for archived output validation but emits metadata-
only investigation actions; `--triage-skipped` is temporarily unavailable.

### v2.4 to v2.7

The hunt result joined the v2 envelope in v2.4. Later versions expanded the
normalized finding shape and changed Cobalt Strike config field representation.
Parsers that ingest hunt details must validate the claimed schema version before
assuming field keys or raw-value availability.

### v2.0 to v2.3

The earliest v2 releases added comparison, extraction/string, and report result
kinds incrementally. A parser should dispatch on `result.kind` and must not
assume a record kind existed in every historical v2 file.

## Legacy v1.1

[`dumpex-output-v1.1.schema.json`](../../dumpex/schemas/dumpex-output-v1.1.schema.json)
is retained for archived hunt output created before the v2.4 migration. No
current command produces v1.1. Its root shape is different from v2 and should be
handled as a separate contract, not coerced into the current envelope.

## Upgrade checklist

1. Read `meta.schema_version` before parsing `result`.
2. Validate with the matching packaged schema.
3. Dispatch on `result.kind`.
4. Preserve unknown historical documents rather than rewriting them in place.
5. Update stored fixtures and downstream mappings deliberately for breaking
   field changes.
6. Keep the evidence hash and original JSON together during migration testing.
