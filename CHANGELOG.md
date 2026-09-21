# Changelog

User-facing changes are grouped by dumpex release. Internal refactors, test-only
changes, and field-by-field design rationale are intentionally omitted.

For the current JSON contract, see
[Output and Evidence Schema](docs/user/OUTPUT_SCHEMA.md). For compatibility history,
see [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md).

## 3.9.1 — Unreleased

### Fixed

- Module absence no longer implies private memory, across `--report`,
  `--extract`, the `hollowing` hunter, and YARA's `PE_In_Private_Memory` rule.
- `--report`'s injected-PE detection required only a bare `MZ` prefix and a
  confirmed-unregistered address, which reported a structurally valid but
  read-only, non-executable mapping (a resource-only PE mapped via
  `MapViewOfFile`) as an injected PE. It now requires a structurally valid PE
  header (full DOS/COFF/optional header and section table, not just an `MZ`
  prefix) in a region that is either `MEM_PRIVATE` or carries live
  executable protection — an MZ prefix that fails structural validation, or
  a valid but benign mapped view, no longer produces a false `injected_pe`
  finding, and no longer disappears silently from the console when it
  doesn't. A region read to completion whose header still cannot be fully
  parsed (its own declared offset falls past the region's own extent) is
  now visible as a genuine coverage gap rather than a silent `complete`.
- `--extract` applies the same correction: a bare `MZ` prefix no longer
  warns "this looks like an injected PE" on its own. The stronger claim
  now requires the same structurally-valid-header-in-confirmed-unregistered-
  private-or-executable-memory bar `--report` uses, and the weaker claim
  names the specific reason (module-backed, no covering MemoryInfo region,
  structurally invalid, a capture-length gap, or a confirmed non-private/
  non-executable mapping) instead of listing every possible cause at once.
  `ModuleListStream` being absent now lowers `coverage.status` (and can move
  the exit code from 0 to 3) instead of silently degrading the claim while
  still reporting `complete`; `MemoryInfoListStream` does the same, but only
  when module ownership does not already resolve the address (a known
  module already settles the question regardless of memory type, so its
  extraction is unaffected by `MemoryInfoListStream` being absent). A
  present `MemoryInfoListStream` that simply does not cover the extracted
  address stays diagnostic-only and does not move `coverage.status` or the
  exit code, matching `--report`'s own long-standing `REPORT_REGION_NOT_FOUND`
  precedent for the identical "no committed region found" condition.
- `--report`'s `anchor_pe_context.classification` no longer collapses every
  "no module owns this" anchor into `private`. It now distinguishes a
  confirmed `MEM_PRIVATE` region (`private`), a confirmed `MEM_MAPPED`
  region (`mapped`), a confirmed `MEM_IMAGE` region a module list confirms
  is unregistered (`unregistered_image` — a manually mapped or stomped
  module), a confirmed `MEM_IMAGE` region with no module list available to
  check registration at all (`image_registration_unavailable` — a different
  gap from confirmed-unregistered), and a region whose own type could not be
  confirmed at all (`region_type_unavailable` — never asserted as `mapped`).
- The `hollowing` hunter's structural-correlation text no longer asserts
  `MEM_PRIVATE` for an image base that is actually `MEM_MAPPED`. The check
  still fires for any non-`MEM_IMAGE` image base (a `MEM_MAPPED` image base
  is just as real an anomaly), but every rendered fact, inference, and
  verdict line now names the region's own observed type.
- YARA's `PE_In_Private_Memory` rule (`--hunt yara`) no longer confirms a
  detection from module-list absence alone. It now requires a confirmed
  `MEM_PRIVATE` region exactly — the rule's own name makes that literal
  promise — and reports `context_unverified` otherwise (still recorded, no
  longer scored). The broader `private_or_unbacked`-scoped rules
  (`Shellcode_Bootstrap_x64` and others) are unaffected: they keep their own,
  deliberately wider "not backed by a known module" bar.
- `--report-string`'s `summary.hits_private` counted every hit not attributed
  to a resolved image module — including `MEM_MAPPED`, `MEM_IMAGE`, and
  unresolvable-type hits — which read as a memory-type claim it never was.
  The new `hits_mapped`/`hits_unregistered_image`/
  `hits_image_registration_unavailable`/`hits_region_type_unavailable`
  counters break that bucket down by the covering region's own observed
  type, so a summary-only consumer no longer has to read every card to tell
  a genuinely private hit from a mapped, unregistered-image, or unresolved
  one; every hit still gets the same card it always did.
- Within that same summary breakdown, an unresolvable region type (`Type`
  parsed as `None`, which the minidump dependency can leave on an
  unrecognized value) was silently counted toward confirmed `MEM_PRIVATE`
  because it matched neither `MEM_MAPPED` nor `MEM_IMAGE`. It now has its own
  `hits_region_type_unavailable` counter, so `hits_private` minus every
  breakdown field is always genuinely confirmed `MEM_PRIVATE`.
- `hits_unregistered_image` counted a `MEM_IMAGE` hit whenever no module
  covered it — including when `ModuleListStream` was entirely absent, which
  is "never checked", not "confirmed unregistered". It now requires a
  present module list that genuinely does not cover the address; an absent
  module list counts toward the new, explicitly weaker
  `hits_image_registration_unavailable` instead, matching the distinction
  `anchor_pe_context.classification` already draws between
  `unregistered_image` and `image_registration_unavailable`.
- `--extract`'s structural-PE-validation gap (`pe_header_state ==
  "short_read"`) reported `coverage.status: complete`, even though the
  identical gap already made `--report` report `partial`. It now reports
  `partial` too, via the new `EXTRACT_PE_HEADER_VALIDATION_INCOMPLETE`
  limitation, matching `--report`'s own `REPORT_PE_HEADER_VALIDATION_INCOMPLETE`.
- `--extract` required both `ModuleListStream` and `MemoryInfoListStream`
  whenever an MZ header was detected, even when a known module already
  confirmed the address was not an unregistered injected PE — penalizing an
  already-resolved extraction for evidence its conclusion never depended on.
  `MemoryInfoListStream` is now required only when module ownership does not
  already settle the question.
- `--report`'s `REPORT_PE_HEADER_VALIDATION_INCOMPLETE` and `--extract`'s new
  `EXTRACT_PE_HEADER_VALIDATION_INCOMPLETE` no longer assert the target
  region was "read in full" — that claim was false whenever the underlying
  raw read was ALSO short (a real case: `REGION_READ_TRUNCATED` and this
  limitation can fire together, and neither's fixed text may contradict the
  other by naming a specific cause).
- A `ModuleListStream` that is present but parses to zero modules — a
  CHECKED negative — no longer reports the same `registration: "unavailable"`
  / `anchor_pe_context.classification: "image_registration_unavailable"` an
  entirely absent stream reports. It now reports the confirmed
  `"unregistered"` / `"unregistered_image"` answer, matching a non-empty
  module list that simply does not cover the address.

### Changed

- Published output schema v2.20. `anchor_pe_context.classification` widens
  from two to five values for the "no module owns this" case (see above).
  `reportRegionInfo` gains `pe_header_state` (`ok`/`pe_invalid`/`short_read`),
  bidirectionally enforced against `has_injected_pe` in both Python and the
  schema. `extractRecord` gains the same `pe_header_state`. `hollowingDetails`
  gains `region_type`, the image-base region's own observed MemoryInfo type.
  `reportSummary` gains `hits_mapped`/`hits_unregistered_image`/
  `hits_image_registration_unavailable`/`hits_region_type_unavailable` (see
  above).
  See [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the
  field-level summary. Earlier schemas stay frozen, and documents produced
  by earlier releases keep validating against their own version.
  `coverage.status` and the exit code DO move for a real, narrow set of
  documents — a `--report` card or `--extract` run whose injected-PE
  determination depended on evidence the dump could not supply now reports
  `partial`/3 where it previously reported `complete`/0 (see [Output Schema
  Migration](docs/user/OUTPUT_MIGRATION.md)'s v2.20 row for the exact
  triggers). `verdict`/`findings`/score move only in the direction this
  release corrects: no result is ever newly promoted toward malicious.

## 3.9.0 — 2026-09-18

### Added

- `--process` now reports the main image's PE profile. The console gains a
  `Main Image PE` block with the image's architecture and header format, its
  load address and the preferred base it was linked for as separate facts
  alongside whether relocation was required, its declared size and section
  count, where execution begins, how completely the header was read, and any
  structural disagreement between two captured facts. A `Scope` line states
  what the block establishes: structural checks over this one image, which do
  not establish that the process is benign.
- `--process --verbose` adds the section table (declared R/W/X, the memory each
  section is mapped over, and how much of it the dump captured), all sixteen
  data-directory descriptors, the relocation evidence (the distance from the
  preferred base, what the header declares, and how much of the
  base-relocation directory the dump holds), every consistency check with the
  evidence it rested on — including the ones the captured evidence could not
  answer — and the header acquisition's own byte provenance, which measures the
  read against the bytes parsing required rather than against the window that
  was requested.
- `--json` carries the complete profile, every section and descriptor, and every
  consistency observation in the new `pe_image` object on the process record,
  whether or not `--verbose` was given.

### Changed

- Published output schema v2.19 for the new `--process` PE evidence. See
  [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the field-level
  summary. Earlier schemas stay frozen, and documents produced by earlier
  releases keep validating against their own version.
- `--process` and `--report` now publish consistent main-image PE facts.
  `--report`'s `summary.pe_context` gains a matching `not_applicable_count`
  beside its existing correlation counts.
- PE output now distinguishes conflicts, unavailable evidence, and checks that
  do not apply, and explains why a check could not be completed. These are
  structural observations rather than maliciousness verdicts: existing
  findings, scores, confidence, coverage status, and exit codes are unchanged.
- `--hunt obfuscation` rounds structured numeric `entropy` values to at most
  twelve decimal places for stable output across supported Python runtimes.
  Detection thresholds, window ranking, classification, scores, coverage
  status, and exit codes are unchanged.

## 3.8.1 — 2026-09-16

### Fixed

- Console and `--txt` static-analysis leads now recognize the common
  register-mediated form of an in-place memory-transform loop, where a value is
  loaded, transformed in a register, and stored back to the same address.
- Static-analysis leads now use stricter control-flow, value-flow, and address
  checks. This reduces false positives from unreachable or non-code bytes,
  copy/identity or cancelling operations, changed addresses, ambiguous
  instruction effects, unrelated or truncated get-PC sequences, and transfers
  that do not actually occur after a loop.
- When a transform-loop shape is present but cannot be proven for a reason that
  is not visible in the instruction rows, console and `--txt` output now say
  that the analysis was withheld instead of implying that no shape was found.
- Verbose lead evidence now includes the supporting instructions used by the
  analysis and clearly marks a truncated evidence list.

### Changed

- Lead descriptions remain in the assessment, while supporting instruction
  addresses now appear once beside the instruction rows and only under
  `--verbose`.

Leads remain investigative context: no finding, score, confidence, verdict,
indicator count, coverage status, exit code, public JSON/CSV field, or output
schema changes.

## 3.8.0 — 2026-09-10

### Changed

- Console and `--txt` reports now put the title, assessment, next step, and
  coverage summary first, followed by anchor context, key evidence,
  correlation, and background. Section names are no longer numbered.
- Default detail keeps high-priority evidence concise: it previews up to five
  IOC matches with network-pattern hits first, keeps routine notable and
  proximity-only strings for `--verbose`, coalesces overlapping network-hit
  byte windows, and avoids printing the same retained string in more than one
  section. Omission notices point to `--verbose` and JSON where applicable.
- Evidence gaps, retention limits, and provenance are presented consistently:
  routine complete counts are suppressed, detailed scope/provenance moves to a
  trailing verbose table, and multi-card reports merge genuinely identical
  causes while preserving region-specific gaps. Every collected section still
  names its evidence sources.
- Capstone is now a base dependency and is bundled with the official Windows
  executable, so every supported installation can decode report instruction
  windows. The empty `disasm` extra remains as a compatibility alias for older
  installation commands; a missing or unloadable decoder is reported as a
  broken installation or build.

### Added

- `--report` now correlates each triage-card anchor with its owning PE image,
  including main-image identity and structural consistency, anchor placement
  and memory protection, a bounded x86/x64 instruction window with resolved
  branch targets, and relevant IAT slots. Every section distinguishes missing,
  incomplete, completed-empty, and truncated evidence without changing report
  findings, verdicts, or exit status.
- The console and `--txt` assessment adds qualified static-analysis leads for
  possible in-place memory-transform loops and position-independent
  self-decoding stubs found in the decoded instruction window. Leads are
  investigative context only: they do not change JSON, findings, verdict,
  coverage, or exit status.
- `dumpex --self-check` verifies that the installed instruction decoder works
  for both x86 and x64 and returns a failing exit status with a safe diagnostic
  when the decoder is missing or cannot load.
- Published output schema v2.18 for the new report correlation fields. See
  [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the structured
  compatibility details.

### Fixed

- Instruction output now distinguishes a byte-cap stop from an undecodable or
  cut-short tail, reports where linear decoding ended, labels captured
  unregistered branch targets and register-indirect destinations accurately,
  and makes clear that the listing is byte-order analysis rather than an
  executed path.
- `--report-string` no longer prints process-wide and main-image PE context
  before the report's own title, and no longer hides a partial or
  not-evaluated coverage state behind an early "not found" or
  "all hits are in known system modules" return.
- Coverage summaries now include optional-enrichment gaps and completely
  untriaged hit regions, distinguish unavailable evidence from retention cuts,
  merge duplicate causes and shared multi-region gaps, bound repeated
  per-region variants, and state each untriaged-region or short-read fact only
  once. A completed negative such as a module declaring no import directory is
  no longer presented as an evidence gap.
- String-context preview limits are applied after deduplication, preventing a
  duplicate from hiding a unique retained entry. Routine notable strings and
  proximity-only background no longer crowd analyst-significant evidence at
  default detail; query and IOC matches remain visible.
- Anchor placement now shows declared-versus-live protection only when an
  owning PE section provides declared permissions; private and otherwise
  unmapped memory shows only its live protection.

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
