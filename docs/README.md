# Documentation

Documentation is separated by audience. Start in `user/` when operating dumpex
or integrating its output. Use `developer/` for current architecture decisions,
behavior contracts, and final designs for work that has not shipped yet.

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
| [Hunt architecture](developer/hunt_architecture.md) | Implemented | Domain ownership, projection, and deterministic-output boundaries |
| [Analyzer registry contract](developer/hunt_analyzer_registry_contract.md) | Implemented | Built-in analyzer identity, selection, capability, and execution contract |
| [Targeted rescan contract](developer/hunt_targeted_rescan_contract.md) | Planned; not in current CLI | Final targeted hunter range-rescan design |
| [Recon process/sysinfo/handles contract](developer/recon_process_sysinfo_handles_contract.md) | Implemented | Current recon records, evidence, coverage, and compatibility contract |
| [Recon profile contract](developer/recon_profile_contract.md) | Implemented | Current `--profile` record and capability-map contract |
| [Entropy full-scope page-pass evaluation](developer/hunt_entropy_full_scope_page_pass_evaluation.md) | Decided; not implemented | Why full-scope entropy stays whole-region and localization stays targeted-only: measurements, benign-noise cost, and the coverage semantics a future page pass would need |

Live developer documents keep only current architecture decisions, current
behavior contracts, non-obvious safety and compatibility invariants, and final
designs for work that has not shipped. Superseded planning documents do not
participate in current navigation.

## Maintenance rules

- Keep current user behavior under `docs/user/`.
- Keep current implementation contracts and final unimplemented designs under
  `docs/developer/`.
- Keep issue sequencing, implementation history, review history, and acceptance
  progress in GitHub issues and pull requests; Git history is the archive for
  superseded document text.
- Let tests verify behavior and let documents explain the contract. Do not keep
  revision history merely so a test can parse it.
- Link to current user documentation from README and analyst-facing output.
- Keep release summaries concise; move field-level compatibility detail to the
  migration guide.
- After modifying, moving, or deleting a document, update every repository
  reference and run the relevant link, documentation, and behavior checks.
