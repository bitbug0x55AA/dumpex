# Changelog

User-facing changes are grouped by dumpex release. Internal refactors, test-only
changes, and field-by-field design rationale are intentionally omitted.

For the current JSON contract, see
[Output and Evidence Schema](docs/user/OUTPUT_SCHEMA.md). For compatibility history,
see [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md).

## Unreleased

### Added

- Added `--hunt-addr ADDR`, which rescans one virtual-address range with the
  selected hunter instead of the whole dump. It requires `--hunt <TTP>` and
  `--size SIZE`, supports `stomping`, `pipe`, `cs-beacon`, `yara`, and
  `obfuscation`, and reuses each hunter's own detection rules, scores, and
  coverage vocabulary. Only the selected scanner's per-region or per-segment
  size cap is bypassed; every other budget stays enforced. Conclusions apply to
  the requested range only.

### Changed

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
