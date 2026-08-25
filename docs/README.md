# Documentation

Documentation is separated by audience. Start in `user/` when operating dumpex
or integrating its output. Use `developer/` for frozen design decisions,
compatibility rationale, and implementation history.

## User documentation

| Document | Use it for |
|---|---|
| [SOC / DFIR Quick Start](user/SOC_QUICKSTART.md) | End-to-end analyst workflow, recon, hunt/report pivots, disposition, and handoff |
| [CLI Reference](user/CLI_REFERENCE.md) | Current commands, options, examples, and exit codes |
| [Detection Methodology](user/DETECTION_METHODOLOGY.md) | Detection logic, evidence boundaries, scoring, and false-positive considerations |
| [Output and Evidence Schema](user/OUTPUT_SCHEMA.md) | Current JSON envelope, records, coverage, artifacts, and provenance |
| [Output Schema Migration](user/OUTPUT_MIGRATION.md) | Historical schema selection and parser upgrade notes |
| [Handle Access Rights Reference](user/HANDLE_RIGHTS_REFERENCE.md) | Object-type-specific handle-right decoding and interpretation |

User documentation describes the current released interface. Version history
belongs in the migration guide or root [Changelog](../CHANGELOG.md), not in the
workflow/reference pages.

## Developer documentation

| Document | Lifecycle | Purpose |
|---|---|---|
| [Analyzer registry contract](developer/hunt_analyzer_registry_contract.md) | Implemented | Frozen analyzer catalog/orchestration decisions |
| [Targeted rescan contract](developer/hunt_targeted_rescan_contract.md) | Planned; not in current CLI | Proposed targeted hunter range-rescan contract |
| [Recon process/sysinfo/handles contract](developer/recon_process_sysinfo_handles_contract.md) | Implemented | Normative design and acceptance history for recon redesign |
| [Recon profile contract](developer/recon_profile_contract.md) | Implemented | Frozen `--profile` record and capability-map design |
| [Hunt migration field matrix](developer/hunt_migration_field_matrix.md) | Historical | Pre-v2.4 field inventory and compatibility audit |
| [Hunt shared-model review](developer/hunt_shared_model_review.md) | Superseded | Pilot architecture review retained for history |

Developer documents intentionally contain issue sequencing, implementation
paths, acceptance gates, and historical decisions. Their lifecycle banner takes
precedence over statements describing an earlier delivery phase.

## Maintenance rules

- Keep current user behavior under `docs/user/`.
- Put implementation plans and frozen decisions under `docs/developer/`.
- Label developer documents as planned, implemented, historical, or superseded.
- Link to current user documentation from README and analyst-facing output.
- Keep release summaries concise; move field-level compatibility detail to the
  migration guide.
- After moving or renaming a document, update code comments/tests that use its
  path and run the repository link checks.
