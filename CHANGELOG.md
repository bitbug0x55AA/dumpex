# Changelog

User-facing changes are grouped by dumpex release. Internal refactors, test-only
changes, and field-by-field design rationale are intentionally omitted.

For the current JSON contract, see
[Output and Evidence Schema](docs/user/OUTPUT_SCHEMA.md). For compatibility history,
see [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md).

## 3.8.1 — 2026-09-11

### Changed

- `--report` console/`--txt` output is now analyst-first: the report title is
  the first line printed, followed immediately by the current assessment, its
  findings, a concise next step, and a coverage summary. Anchor context, key
  evidence, correlation, and process/PE background follow, in that order.
  Section headers are plain names rather than numbers, so a conditional
  section that this run did not populate never leaves a numbering gap.
- Default detail now also caps the console preview of retained IOC matches (5,
  prioritizing network-pattern hits) and notable strings (5), each with an
  omission notice; `--verbose` still expands to the complete retained set.
  Overlapping ±128-byte network-hit windows are coalesced into one combined
  byte range instead of repeating shared bytes once per hit.
- A retained string selected as both an IOC match (or notable string) and
  anchor-proximity context now prints its full text once, only when that
  first copy is actually rendered at the current detail level; STRING
  CONTEXT AROUND THE ANCHOR no longer repeats one cross-reference line per
  such string, naming them instead as a single trailing count (or, when
  every anchor-context entry is already shown elsewhere, one summary
  sentence in place of the row list).
- Each section's scope, cap, and provenance -- previously repeated inline
  after every verbose section -- now appear once, in a trailing LIMITATIONS
  AND PROVENANCE table, and only for a section that actually has an
  incomplete status, a retained-set cut, or a limitation to report. Each
  section's own evidence state and retained count now print inline only
  under that same condition -- a routine complete section (however many rows
  it retained) no longer prints an `evidence: complete   kept: N of N` line
  at either detail level, and neither surface prints `kept:`/`cap:` when a
  section's own retained count is meaninglessly `0 of 0`. Truncation and
  limitation lines remain inline at both detail levels whenever they apply.
- A multi-hit `--report-string` run's COVERAGE SUMMARY collapses a gap
  every triaged card shares (a whole-dump fact, such as no ExceptionStream)
  into one line naming the regions it covers, instead of repeating the
  identical sentence once per hit; a gap only one card carries keeps its own
  region prefix.
- The instruction decoder is now a base dependency. `pip install dumpex`, an
  install from a Git ref, and the official Windows executable all arrive able
  to decode `--report` instruction windows, resolve branch targets, and
  correlate the IAT; no extra has to be discovered or requested. The `disasm`
  extra remains accepted so existing instructions keep working, but it is now
  empty and installs nothing beyond the plain package. A decoder that is
  missing or will not load is reported as a broken installation or build
  rather than as an optional feature awaiting installation, and `--report`,
  `--self-check`, and the documentation say so consistently.

### Added

- `dumpex --self-check` verifies this build's instruction decoder and exits 0
  (usable) or 1 (missing or unloadable). It takes no dump file and no command:
  it decodes fixed synthetic bytes -- `90 c3`, `nop` then `ret` -- for x86 and
  x64 through the same decoder `--report` instruction context uses. A failure
  names the raising exception and a bounded reason, never a traceback or a
  filesystem path.

### Fixed

- The official Windows executable now bundles the Capstone decoder and its
  native library, so `dumpex.exe --report` decodes instruction windows,
  resolves branch targets, and correlates the IAT with no Python or `pip`
  step. Previously that headline capability could report "no disassembler is
  installed" in an executable whose users had no way to install one. The
  release workflow declares the decoder dependency explicitly, checks the
  packaged native library, and runs the decode self-check against both the
  built executable and the copy extracted from the published ZIP, so a build
  that lost the decoder fails before publication. The bundle carries
  Capstone's license with the code it now ships.
- A decoder that is installed but will not load is no longer reported as one
  that is not installed. `--report` instruction context distinguishes an
  absent dependency from a native library that failed to load, names
  the raising exception's type, and keeps the reason bounded and free of
  filesystem paths. A packaged executable is told its decoder is a
  distribution defect rather than being advised to run `pip install`, which it
  cannot act on. `decoder_state`, the JSON schema, findings, verdict,
  coverage, and exit codes are unchanged.
- `--report-string` no longer prints process-wide and main-image PE context
  before the report's own title, and no longer hides a partial or
  not-evaluated coverage state behind an early "not found" or
  "all hits are in known system modules" return.
- COVERAGE SUMMARY no longer prints "No known collection limitations" while
  this run's own already-collected enrichment sections (exception,
  instruction, and string context; PE and anchor-PE placement; process
  identity, session, handles, and token capability) are themselves partial,
  not evaluated, unavailable, or cut at a retention cap. The compatibility-
  frozen `coverage.status`/`coverage.reasons` reducer is unread and
  unchanged; the summary now also states the presentation-level gaps each
  of those sections already discloses further down, so `Status: COMPLETE`
  never reads as "nothing to report" when a later section says otherwise.
  The incomplete-coverage caveat sentence now carries its own neutral
  marker, distinct from an actual gap reason.
- STRING CONTEXT AROUND THE ANCHOR's console cap now bounds how many
  UNIQUE entries the preview renders, applied after -- not before -- the
  dedup partition against STRINGS IN REGION. Previously the cap sliced the
  raw retained order first, so a duplicate ranked ahead of a genuinely
  unique entry could push that entry out of the preview entirely and, when
  the whole capped slice happened to be duplicates, made the section falsely
  claim no unique entries existed at all.
- COVERAGE SUMMARY's `Status:` line now carries a short qualifier ("core
  report coverage — see below for optional-enrichment gaps") whenever this
  run's own enrichment sections add anything beneath it, so `COMPLETE` is
  never read as covering more than the compatibility-frozen reducer's own
  narrower contract. A retained-set cut (evaluated, but not all of it kept)
  now prints under its own "Retention limits:" lead-in, separate from an
  unavailable evidence source (not evaluated at all) -- the two call for
  different follow-up and no longer share one undifferentiated list.
- A card's own target-region read coming up short no longer states the same
  fact twice in COVERAGE SUMMARY: the reducer's own aggregate "Requested
  memory region was only partially read" and String context's own "the
  region read came up short: N of M..." limitation both derived from the
  identical read. String context's own distinct PARTIAL status still names
  that the section was affected; the specific byte counts remain available
  in that section's own inline reminder, further down.
- LIMITATIONS AND PROVENANCE no longer drops a section's `built from:`
  provenance just because the section itself was clean: every section this
  run collected still gets its own entry naming the streams it was built
  from, with no `scope:`/`evidence:` envelope line above it when there is
  nothing to report -- restoring a fact the previous 3.8.1 revision had
  dropped along with the routine envelope line.
- A `--report-string` run's COVERAGE SUMMARY now also names any actionable
  hit region this run's own card/read budget left completely untriaged --
  the widest scope gap such a run can carry, previously visible only as a
  YELLOW line printed after the coverage summary and the per-hit region
  list, easy to miss relative to the triaged cards' own minor gaps listed
  above it.
- KEY EVIDENCE no longer includes routine (non-IOC) notable strings: they
  render in their own verbose-only ADDITIONAL RETAINED STRINGS section
  instead, so the section an analyst reads first stays IOC matches and
  proximity context. Default detail now only names how many notable
  strings this card retained, with no console-only cap of its own to
  disclose.
- ANCHOR IN THE PE IMAGE is renamed ANCHOR PLACEMENT, and no longer prints
  a `declared ?  live X` comparison for private or otherwise unmapped
  memory: that memory has a live protection but no owning PE section to
  compare it against, and the comparison implied one existed with merely
  unknown bits. A bare `Live protection` line prints instead; the
  declared/live comparison (and its own mismatch caveat) now appears only
  when an owning PE section genuinely has declared bits to compare against.
- A `--report-string` run's COVERAGE SUMMARY no longer prints one line per
  triaged region for a section whose own per-region detail differs across
  more than a few regions (Instruction context's own limitation names each
  region's own anchor address, for one): beyond four such variants for one
  label, they collapse into a single line naming the count, so the summary
  no longer scales with the hit count for that case.
- A completed evaluation's settled negative is no longer reported as an
  evidence gap. A module that positively declares no import directory is a
  `complete` IAT section carrying "the module declares no import directory"
  -- the answer, not an unanswered question -- and it was being listed under
  the coverage summary's known evidence gaps and pulling its own section
  into the LIMITATIONS AND PROVENANCE envelope, blurring `complete`,
  `partial`, and positively-absent back together and sending an analyst
  looking for an import table this run had already established does not
  exist. It now prints under the neutral marker, in its own section only.
  Classification is per limitation sentence, so a genuine gap riding in the
  same section (an unread data-directory array) is unaffected, and only a
  complete, untruncated, nothing-eligible section can carry a settled
  negative at all. No collected record changes.
- Default detail no longer expands routine strings inside KEY EVIDENCE
  through STRING CONTEXT AROUND THE ANCHOR. An entry selected purely
  because it lies near the anchor is the same low-priority background that
  moved to ADDITIONAL RETAINED STRINGS, and reached KEY EVIDENCE anyway by
  that second route; default detail now names how many were held and where
  to get them. A query match or an IOC-pattern match carries its own
  analytic claim and still prints, and `--verbose` still renders every
  retained entry.
- One missing stream is now one gap in COVERAGE SUMMARY, however many
  sections observed it: a dump with no HandleDataStream left both the
  process-wide handle census and each card's handle correlation reporting
  the identical reason, so one capture gap read as two independent
  problems. The merged line names the cause once and every section it
  affects, each keeping its own region annotation; only genuinely identical
  causes merge.
- The card/read budget's untriaged-region fact is now stated once. It was
  printed in full both in COVERAGE SUMMARY and again beside the hit list,
  giving one gap two complete presentation records in one document. It now
  appears only in the summary, carrying its own `--report-addr` next step.

## 3.8.0 — 2026-09-10

### Added

- `--report` now correlates each triage card's anchor with the PE image that
  owns it: a process-wide main-image identity and structural-consistency
  summary, the anchor's placement (headers, code, data, import/IAT, relocation,
  or private memory) with the section's declared versus live protection, a
  bounded x86/x64 instruction window at the anchor with direct and proven
  indirect branch targets resolved to module/section/region, and the anchor
  module's import table reduced to the slots a nearby branch targets or whose
  live thunk target is unusual. Every section states unavailable, incomplete,
  completed-empty, or truncated evidence and changes no report finding, verdict,
  or exit code.
- The instruction window uses an optional `capstone` dependency, installed with
  `pip install dumpex[disasm]`. Without it the instruction section reports an
  explicit unavailable state rather than being omitted.
- Published output schema v2.18 for the new report correlation fields. See
  [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the structured
  compatibility details.

## 3.7.1 — 2026-09-08

### Changed

- Default `--report` console output now summarizes routine enrichment, while
  `--verbose` expands all retained process and per-card context. `--txt` follows
  the requested detail level; structured records and analysis results are
  unchanged.

### Fixed

- Report output now distinguishes console previews from retention caps and
  marks truncated dump-derived values, so omitted or shortened evidence is not
  presented as complete.
- Report process summaries now state when captured module data cannot verify
  whether the process image base is registered.

## 3.7.0 — 2026-09-06

### Added

- `--report` now includes bounded process and session context plus per-card
  exception, allocation-neighborhood, correlated-handle, and nearby-string
  context. Each section distinguishes unavailable, incomplete, completed-empty,
  and truncated evidence without changing report findings or verdicts.
- `--report-string` now limits multi-card generation to 32 cards and a 256 MB
  cumulative card-read budget. Shared-region hits are consolidated, while hits
  left untriaged by the budget are counted explicitly and make the run partial.
- Published output schema v2.17 for the new report context and accounting fields.
  See [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the structured
  compatibility details.

## 3.6.2 — 2026-09-05

### Fixed

- `--hunt all` no longer treats several scanners failing to read the same
  uncaptured memory range as corroborating evidence. Skipped-target actions now
  also prefer targets that can be investigated from the current dump over
  targets that require a new collection.
- `--hunt obfuscation --verbose` now shows bounded, terminal-safe previews of
  retained Base64 strings and their decoded content. Text is escaped for safe
  display, while binary and PE content is shown as hex with a SHA-256 when
  appropriate.
- Hunt console `Coverage` rows now distinguish completed byte scanning from
  missing contextual evidence, explain partial coverage without contradictory
  zero-gap wording, and wrap cleanly within the terminal width.

## 3.6.1 — 2026-09-03

### Added

- Coverage now says how much memory a partial hunt actually missed, not only
  that it was partial. Schema v2.15 adds `coverage.missed_bytes` to every result
  and hunter record, including the missed range count and whether the byte
  figure is exact, a lower bound, or unknown. The console reports the figure,
  and scan targets expose their examined and unexamined sizes.
- Schema v2.16 adds `eligible_bytes`, `unscanned_pass_bytes`, and
  `unscanned_fraction` to show the share of each hunter's scanning work that did
  not happen. The console reports the share alongside missed bytes without
  changing coverage status, verdicts, scores, confidence, or exit codes.

### Changed

- `--hunt pipe` now reports a truncated `HandleDataStream`. A dump whose
  descriptor array declares more handles than it delivers now carries a
  `HANDLE_STREAM_TRUNCATED` limitation with the dropped-descriptor count and
  reports partial coverage instead of silently omitting the missing tail.
- `--hunt pipe` now distinguishes a HandleDataStream that was never captured
  from one that was captured but could not be parsed. Parse failures now report
  the parser error as a failed source and prevent that stream's handles from
  being scored, matching `--handles`. See
  [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the consumer
  impact.

## 3.6.0 — 2026-09-02

### Added

- Added `--hunt-addr ADDR`, which rescans one virtual-address range with the
  selected hunter instead of the whole dump. It requires `--hunt <TTP>` and
  `--size SIZE`, supports `stomping`, `pipe`, `cs-beacon`, `yara`, and
  `obfuscation`, and reuses each hunter's own detection rules, scores, and
  coverage vocabulary. Only the selected scanner's per-region or per-segment
  size cap is bypassed; every other budget stays enforced. Conclusions apply to
  the requested range only.
- Targeted rescans distinguish a source that does not apply to the requested
  range (`not_applicable`) from one that could not evaluate it
  (`not_evaluated`). They also report per-source measurements and, with
  `--verbose`, the range's structural context.
- A targeted `obfuscation` rescan now measures entropy in bounded windows as
  well as over the whole range, reporting the highest-entropy sub-ranges and
  whether window coverage was exhaustive or sampled.
- The `--hunt all` skipped-target queue now prints the targeted rescan to run
  next for each capable hunter. Targets that require recollection or an
  unsupported hunter are labelled instead, and unsafe-to-render paths receive
  arguments rather than a misleading command line. `--redact-paths` also
  reduces paths in rendered commands to basenames.

### Changed

- `investigation_actions[].recommended_actions` now includes a
  `targeted_hunter_rescan` entry only when a hunter that skipped the target can
  actually run one over it, and only when this dump holds bytes to rescan; its
  `hunters` names that subset rather than every skipping hunter. `skipped_by`
  is unchanged and still names all of them. Schema v2.14 is unchanged: every
  archived document stays valid.
- `--size` now requires `--hunt-addr` when used with `--hunt`, and is rejected
  with a usage error otherwise. Hunt options that the selected targeted scanner
  does not use are also rejected instead of being silently ignored. `--size`
  is unchanged for `--extract` and `--strings`.
- Published schema v2.14. Every hunt summary now carries a `scan_scope` tag
  naming what the invocation covered, and targeted hunter details carry
  per-source applicability, measurements, and coverage in `targeted_scope`.
  Sources outside the targeted grant remain explicit, and schema validation
  rejects inconsistent full/targeted scope combinations. Schema v2.13 and older
  remain frozen.

### Fixed

- A targeted `pipe` rescan whose pipe-name budget ran out attributed that one
  exhaustion to both coverage closures. The gap is now reported once by its
  owning `pipe_name` closure while `c2_context` still reports partial coverage.
- Corrected the reported address of a UTF-16LE IOC token in module-stomping
  output. Matching, classification, and scoring are unchanged.

## 3.5.2 — 2026-08-27

### Changed

- Temporarily disabled `--triage-skipped` pending analyzer-aware recovery
  orchestration.
- Standardized empty memory reads as failed reads across all hunters.

### Fixed

- Made hunt coverage fail closed when eligible scan items are left unaccounted
  for, reporting `SCAN_ITEMS_UNACCOUNTED` instead of complete coverage.
- Preserved exact named-pipe rescan targets when scan budgets are exhausted.
- Prevented zero-length committed regions or captured segments from aborting
  hunt execution.
- Standardized virtual-address formatting across CS Beacon, obfuscation,
  hollowing, named-pipe, and module-stomping output. This may regenerate
  affected deterministic `Finding.id` values once after upgrading.

## 3.4.0 — 2026-08-23

### Added

- Added `--profile`, which reports the dump's stream inventory, memory-capture
  facts, and availability of six analysis capabilities without issuing a
  malicious/clean verdict.
- Added readable, object-type-aware access-right decoding to `--handles` while
  preserving the original `granted_access` integer in JSON.
- Added `--handles --verbose`; default output folds routine anonymous handles
  into exact per-type counts while keeping cross-process-relevant and unreadable
  rows visible.

### Changed

- Completed the breaking schema v2.13 cutover. `--process`, `--handles`, and
  `--profile` replace the retired `--pid`/`--peb` commands and result kinds.
- Improved verbose `--process` output with an explained IAT address pair,
  identity verification states, and safely escaped dump-derived text.

### Fixed

- Corrected dump-time extraction so `--sysinfo` no longer reports a fabricated
  1970 timestamp when time data cannot be recovered.

## 3.3.2 — 2026-08-17

### Added

- Added the first standalone `--handles` inventory over captured
  `HandleDataStream` descriptors.

### Security

- Escaped untrusted dump-derived strings in recon console renderers so captured
  text cannot forge terminal layout or dumpex labels.

## 3.3.1 — 2026-08-16

### Added

- Added consolidated `--process` identity and bounded IAT parsing.
- Moved captured environment context into `--sysinfo`.

### Fixed

- Constrained the supported `minidump` dependency range and hardened handle
  descriptor-size validation against upstream layout drift.

## 3.3.0 — 2026-08-13

### Changed

- Schema v2.11 records exact hidden-PE candidate addresses and file/region
  offsets after injection scanning expanded beyond region-base probes.
- Schema v2.12 preserves target identity, capture state, skip cause, and budget
  facts for read, short-read, and truncated hunter coverage gaps.

### Fixed

- Cobalt Strike verbose output now wraps complete binary TLV values instead of
  silently truncating them.
- Injection finding facts now render virtual addresses at a consistent width.
- Obfuscation, pipe, and cross-hunter investigation queues retain evidence and
  coverage identity correctly when budgets or partial captures intervene.

## 3.2.1 — 2026-08-09

### Added

- Added `--hunt all --triage-skipped`, an opt-in, budgeted deep-content pass
  over the skipped-target queue (schema v2.10).
- Added the metadata-only `result.summary.investigation_actions` queue for
  `--hunt all` (schema v2.9).

### Fixed

- Truncated SHA-256 values are now labelled as prefixes rather than complete
  hashes.
- Module stomping no longer reports a clean IOC scan when memory was unreadable
  or only partially scanned.

## 3.2.0 — 2026-08-08

### Added

- Coverage limitations now identify skipped memory regions/segments with
  structured `targets[]` entries (schema v2.8).

### Fixed

- Corrected obfuscation coverage counting when the same region is skipped by
  multiple scan layers.

## 3.1.3 — 2026-08-08

### Added

- Added console/`--txt` correlation of evidence from different hunters that
  resolves to the same memory region.

### Changed

- Removed `--csv`; JSON is the structured automation format and `--txt` is the
  human transcript.
- Cobalt Strike config output dropped redundant raw hex values (schema v2.6)
  and re-keyed fields by their names (schema v2.7).

## 3.1.2 — 2026-08-06

### Added

- Hunt findings gained deterministic IDs, derived severity, ATT&CK mappings,
  evidence references, IOC values, and rule provenance (schema v2.5).

### Changed

- Standardized normal/verbose hunt finding presentation across hunters.

## 3.1.1 — 2026-08-04

### Changed

- `--diff` now treats the positional dump as the target and the `--diff`
  argument as the baseline.
- CLI help is grouped by purpose; `--diff-scope` and `--strings-encoding` are
  the documented modifier names. Compatibility aliases remain available.

## 3.1.0 — 2026-08-04

### Changed

- Migrated `--hunt` to the shared v2 envelope (schema v2.4), completing one
  structured-output model across all commands available in that release.
- Migrated `--diff`, `--extract`, `--strings`, and `--report` to typed result
  records with structured coverage, diagnostics, and artifacts.

## 3.0.1 — 2026-07-31

### Fixed

- Corrected doubled CSV line endings on Windows in the then-supported CSV
  exporter.
- Failed evidence sources are no longer rendered as present.

## 3.0.0 — 2026-07-31

### Added

- Introduced the v2 structured-output envelope and first-class coverage,
  provenance, artifacts, and diagnostics for recon commands.

### Changed

- Standardized `complete`/`partial`/`not_evaluated` coverage and corresponding
  exit-code behavior across the migrated commands.

## 2.1.0 — 2026-07-29

### Changed

- Reduced false positives in YARA and injection scoring using clean-corpus
  validation.
- Split hunter implementations into focused modules without changing the public
  command names.

### Fixed

- Prevented duplicate YARA suppression output and improved optional-dependency
  test behavior.

## 2.0.0 — 2026-06-01

### Changed

- Improved console compatibility with older Windows Command Prompt and
  PowerShell terminals.

## Compatibility notes

- Current commands emit schema v2.17.
- Historical schema files remain packaged and frozen for archived evidence.
- Validate a document using its own `meta.schema_version`.
- See [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) before upgrading a
  parser across schema versions.
