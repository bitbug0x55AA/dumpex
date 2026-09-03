# Changelog

User-facing changes are grouped by dumpex release. Internal refactors, test-only
changes, and field-by-field design rationale are intentionally omitted.

For the current JSON contract, see
[Output and Evidence Schema](docs/user/OUTPUT_SCHEMA.md). For compatibility history,
see [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md).

## Unreleased

## 3.6.1 — 2026-09-03

### Added

- A hunt now reports how much of its own scanning work did not happen, not
  only how many bytes it missed. `coverage.missed_bytes` gains
  `eligible_bytes`, `unscanned_pass_bytes` and `unscanned_fraction`, and the
  console coverage line states the share alongside the byte figure —
  `Coverage    PARTIAL — 3.2 MB unscanned across 3 range(s) (0.03% of 11.4 GB
  eligible)`. An absolute figure ranks two runs against each other; a share is
  what lets one run be judged on its own, and lets a triage pipeline apply a
  single threshold across dumps of any size. A `complete` scan states its share
  too — `0% of 11.4 GB eligible` and `0% of 8 KB eligible` are the same two
  words for a negative worth trusting and one worth almost nothing.
  The share measures scanning work **per pass**: a hunter that runs three
  passes over one region had three passes' worth of work to do, so a region
  every pass skipped reports 100% while a region only one of two passes skipped
  reports 50%. Gap extents are unioned within a pass and summed across passes,
  and a pass's scope covers items a whole-scan budget never reached, so the
  share can never exceed 100%. The byte figure keeps its own basis — memory
  with at least one unanswered question, which is what a re-collection has to
  recover — and is deliberately not the numerator. Pass identity is declared by
  each producer rather than inferred from `limitations[].scope`, which may name
  a budget or signal instead. The scale belongs to the hunter, not the dump: two
  hunters over one dump legitimately report different denominators, and the
  `--hunt` document-level rollup states none at all. Every hunter publishes one
  except `hollowing`, whose gaps never describe unexamined bytes. Both fields are
  `null` wherever a proportion would not be supportable — a producer that
  measures no eligibility, a scan loop that took items into scope without
  measuring them, a hunter that evaluated nothing, and a run whose gaps have no
  measured extent — so a budget that stopped a scan somewhere unmeasured never
  renders as `0%` unscanned, and an exact-looking percentage never stands beside
  an unmeasured gap: a lower bound is labelled as one. The console reserves both
  saturating values for what they mean, rendering anything that would round into
  them as `<0.01%` or `>99.99%`. Schema v2.16. Nothing about when `partial` is
  reported changes, and no verdict, score, confidence value,
  `coverage.reasons` string, or exit code moves.
- Coverage now says how much memory a partial hunt actually missed, not only
  that it was partial. Every result and every hunter record carries
  `coverage.missed_bytes`, and the console coverage line gains a clause —
  `Coverage    PARTIAL — 3 MB unscanned across 4 target(s)` — that separates a
  negative result worth recollecting for from one that essentially stands. The
  figure counts what the dump actually holds for each skipped region or
  segment, never the address space it declares, so a region the capture never
  backed contributes zero rather than inflating the total; that case still
  needs a re-collection, which `capture_state` already says. It measures
  memory rather than gap records: the unexamined ranges are unioned, so one
  region that several scan layers each skipped, or that several hunters each
  skipped, is counted once and the total can never exceed what the dump holds.
  `distinct_ranges` reports how many ranges the figure spans, which is what
  separates one region skipped three times from three skipped regions.
  A gap whose extent the run cannot establish is counted, never estimated:
  `state` reads `exact`, `lower_bound` (labelled as a floor, never rendered as
  a total), or `unknown` (no figure at all, so a consumer thresholding on the
  number cannot read it as zero). `scanTarget` gains `examined_size` and
  `unexamined_size` alongside it, and the aggregate is the union of exactly
  those per-target ranges, so the per-target and total figures cannot disagree.
  Schema v2.15. Nothing about when `partial` is reported changes, and no verdict,
  score, confidence value, `coverage.reasons` string, or exit code moves.

### Changed

- `--hunt pipe` now reports a truncated `HandleDataStream`. A dump whose
  descriptor array declares more handles than it delivers carries a
  `HANDLE_STREAM_TRUNCATED` limitation with the dropped-descriptor count, makes
  the run's coverage `partial`, and says on the console that the handle
  evidence is a head rather than the whole set — a pipe handle in the missing
  tail is neither found nor ruled out. Previously such a handle simply did not
  appear, with no coverage caveat. A dump whose HandleDataStream is readable
  and untruncated produces byte-identical output, coverage, and exit code; the
  only other behavior change is the parse-failure correction below, which
  applies to a dump whose handle stream would not parse at all.
- `--hunt pipe` now distinguishes a HandleDataStream that was never captured
  from one that was captured and could not be parsed. The second previously
  reported the first's reason — that the dump needs to be re-collected with
  `MiniDumpWithHandleData` — which is not the next step for a dump whose handle
  stream is corrupt, and which that analyst cannot act on anyway. The parser's
  own error text is now reported instead, and the `handle_data` coverage source
  is `failed` rather than `absent`, matching what `--handles` already reports
  for the same dump. When a parse failure is recorded, no handle from that
  stream is scored, even if a parsed stream object is also present — a dump can
  declare the same stream twice, and which entry survived is not knowable, so
  the evidence is treated as untrustworthy rather than scored. `--handles`
  already resolved it that way. See
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
- A targeted rescan now separates "this source does not apply to the requested
  range" from "this source could not evaluate it". A closure whose own
  descriptor-eligibility gate declined the target reports `not_applicable` with
  the gate that declined it, rather than the same `not_evaluated` a missing
  capture, a read failure, or a spent budget produces. A minimum input splits
  the same way: a requested range shorter than the algorithm can be applied to
  is `not_applicable` (a larger `--size` is what changes it), while a range
  that clears the minimum but is only partly captured stays `not_evaluated`
  (a fuller collection is). Only the second is a
  coverage failure, so one inapplicable layer no longer forces the layers that
  did apply to read as `PARTIAL` / `INCONCLUSIVE`.
- A targeted closure that finished without a hit now records what it did: bytes
  evaluated, values measured, bounds reached, per-decode-sub-layer candidate and
  attempt counts, and what that layer alone spent against each of the shared
  budget's four limits. The measurements appear in `details.targeted_scope` and
  on the console card, and `--verbose` adds the structural context the range
  sits in — containing allocation, module attribution, capture file offset —
  plus every entry of a bounded ranked list. They are observations only: they
  create no finding, move no score, and make no claim about any other source's
  coverage.
- A targeted `obfuscation` rescan now measures entropy in bounded windows as
  well as over the whole range. A single Shannon value over a sparse oversized
  allocation is an average its zero-filled majority dominates, so a bounded
  encrypted payload inside it reads as low-entropy; the rescan now reports the
  highest-entropy sub-ranges with their addresses, how many windows crossed the
  threshold, and whether the windows were measured exhaustively or sampled. A
  range whose own average clears the threshold is still reported as one hit, as
  before.
- The `--hunt all` skipped-target queue now prints the targeted rescan to run
  next. Each eligible entry renders one copyable `--hunt-addr` command per
  skipping hunter that has a targeted capability, with the dump path quoted so
  the line means the same thing in a POSIX shell, PowerShell, and `cmd.exe`,
  alongside the `hunter + source + scope + base_address + size`
  key the new result is matched back by. A hunter with no targeted capability
  is named as unsupported instead; a target whose bytes this dump never
  captured is told to recollect rather than rescan; and a target larger than
  the hunter's request ceiling gets one capped command, labelled supplementary,
  that does not claim to close the original gap. Structured output carries no
  command string: the address, size, and hunters are the contract, and quoting
  belongs to the shell that reads a command line. Options come first and the
  dump path last, behind a `--` terminator, so a dump legitimately named
  `-case.dmp` still gets a command that runs. A dump path no single quoting rule
  can carry through all three shells -- one holding `%`, `$`, a backtick, `"`,
  `!`, a character a terminal acts on (C0/C1 controls, `DEL`, bidi marks,
  overrides and isolates, line and paragraph separators), a trailing backslash,
  or the doubled backslash of a UNC path -- gets the arguments without a command
  line instead, rather than a line that would expand, split, execute part of the
  filename, or misrepresent itself on screen.
  `--redact-paths` reduces the
  dump path in a rendered command to its basename, so a `--txt` transcript stays
  as shareable as the structured document.

### Changed

- `investigation_actions[].recommended_actions` now includes a
  `targeted_hunter_rescan` entry only when a hunter that skipped the target can
  actually run one over it, and only when this dump holds bytes to rescan; its
  `hunters` names that subset rather than every skipping hunter. `skipped_by`
  is unchanged and still names all of them. Schema v2.14 is unchanged: every
  archived document stays valid.
- `--size` now requires `--hunt-addr` when used with `--hunt`, and is rejected
  with a usage error otherwise. It previously had no effect there, which let a
  targeted invocation missing its address run an unbounded whole-dump hunt
  while silently discarding the option. `--size` is unchanged for `--extract`
  and `--strings`.
- Published schema v2.14. Every hunt summary now carries a `scan_scope` tag
  naming what the invocation covered, and a targeted rescan's hunter details
  carry one `targeted_scope` entry per coverage closure. A targeted record's
  coverage also names every source outside the rescan's grant explicitly, so a
  complete result for one source cannot read as complete coverage for the
  hunter. Full-scope hunt details omit `targeted_scope` entirely. Schema v2.13
  and older are frozen and unchanged.
- The current schema now cross-checks `summary.scan_scope` against the rest of
  the document instead of only validating its own shape: a `targeted` tag must
  agree with `summary.selected` and with the selected analyzer's registered
  source, must name that analyzer's scope set exactly, and requires
  `targeted_scope` on the record with one entry per closure in the analyzer's
  own fixed order; a `full` tag forbids `targeted_scope` entirely.
- A `targeted_scope` entry now carries `applicability_reason` and
  `measurements`, and its `coverage_status` may be `not_applicable`. A consumer
  must not count `not_applicable` as a coverage failure: the record's own
  `coverage.status` does not, and a rescan whose closures all decline the target
  reports `not_evaluated`. These are same-version additions to the still
  unreleased v2.14 targeted shapes; schema v2.13 and older stay frozen, and
  full-scope documents are unaffected.
- A hunt option the selected hunter's targeted rescan does not read is now a
  usage error instead of being accepted and ignored. `--hunt stomping
  --hunt-addr` rejects `--ref-dir`, which supplies reference modules for a
  content comparison no targeted rescan runs; it previously recorded that
  directory in `meta.execution.options` for a run that never read it, and let
  it change the invocation's observation identity. `--yara-dir` stays accepted
  for `--hunt yara`, whose targeted rescan does resolve rules through it.

### Fixed

- A targeted `pipe` rescan whose pipe-name budget ran out attributed that one
  exhaustion to both of its coverage closures, so it appeared twice in
  `coverage.limitations`, twice in the derived `coverage.reasons`, and twice on
  the console. The gap is now raised once, by the `pipe_name` closure that owns
  the budget; the `c2_context` closure it also constrains still reports
  `partial` and still carries the diagnostic explaining the dependency.
- Corrected the reported address of a UTF-16LE IOC token in module-stomping
  output. Its `VA` was computed from the match's character position rather than
  its byte position, placing the token at half its true distance into the
  string. ASCII and URL-run tokens are unaffected; which tokens match, the hit
  counts, the weak/strong classification, and the score are unchanged.

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

- Current commands emit schema v2.13.
- Historical schema files remain packaged and frozen for archived evidence.
- Validate a document using its own `meta.schema_version`.
- See [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) before upgrading a
  parser across schema versions.
