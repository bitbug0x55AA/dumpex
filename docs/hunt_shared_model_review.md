# Hunt shared-model review (issue #6)

**Status: decisions recorded, follow-up extraction landed in this change.**
Planning baseline: `d9a3605` (v3.2.1), schema v2.10, after the completed
Injection (#2/#3/#4) and Encoding (#5) pilots. This is the mandatory
post-pilot review issue #1 required before migrating Stomping/Pipe/
Hollowing/CS Beacon/YARA (#8/#7/#10/#9/#11) — it records what both pilots
actually proved, not a speculative design for hunters that haven't
migrated yet.

Every claim below is checked against the current tree (`dumpex/hunt/
injection/`, `dumpex/hunt/encoding/`, `dumpex/hunt/_domain.py`,
`dumpex/hunt/_coverage.py`, `dumpex/hunt/_finding.py`,
`dumpex/hunt/_location.py`), not against the pilots' original issue text.

## Domain/projector decisions

### 1. Shared value objects/interfaces proven by both pilots

Both pilots independently converged on the same four-module split, and
each already exists in production, imported by both hunter packages:

| Module | What it owns | Consumed by |
|---|---|---|
| `dumpex.hunt._domain` | `CheckResult` (evidence-carrying check outcome) + `require_recursively_immutable`/`as_tuple` (the immutability guardrail every `*Report`/`*Evidence` type builds on) | `injection.domain.InjectionReport`, `encoding.domain.EncodingReport` |
| `dumpex.hunt._coverage` | `derive_status`/`derive_coverage_status` (the one DETECTED/INCONCLUSIVE/... and complete/partial/not_evaluated reduction), `CoverageTracker`, `region_scan_target`/`segment_scan_target` | Both pilots' `CoverageSnapshot.status`/`.evaluated`/`.complete` properties |
| `dumpex.hunt._finding` | `Finding` (the wire/console compat projection), tag/confidence/severity vocabulary, `overall_confidence`/`verdict_level`/`lead_count`/`review_priority` reducers | Both pilots' `*Report` derived properties, both `report_facts.py` |
| `dumpex.hunt._location` | `Location`/`resolve_location` (VA/region-offset/file-offset resolved once, at scan time) | Both pilots' evidence types (`RegionRef`+resolved offsets in injection; `h.location` in encoding) |

This is the full set. **No wider "universal Evidence hierarchy" is
justified** — `InjectionEvidence` and `EncodingEvidence` deliberately stay
separate, hunter-owned dataclasses with hunter-specific bucket names and
bucket-relation invariants (`_require_bucket_relations` in each
`domain.py`); the only things genuinely common across both are the four
modules above, which is exactly what's already shared. A hypothetical
`BaseEvidence`/`BaseReport` superclass was considered and rejected: the
per-hunter `_require_*` invariants (e.g. injection's correlation-map
consistency vs. encoding's pe/shellcode mutual-exclusion) have no common
shape to lift, and forcing one would either weaken the checks or leak
hunter-specific fields onto a shared base.

### 2. Canonical coverage snapshot / CheckResult contract

Confirmed minimal and already stable across both pilots:

- **`CheckResult`** (`dumpex/hunt/_domain.py`): `check, inference,
  confidence, rationale, evidence, limitations, tag, technique_ids,
  evidence_refs, iocs, rule_id, rule_version, evidence_limit`, plus the
  derived `severity` property. Both hunters use every field identically;
  neither has needed a field the other doesn't use. No change proposed.
- **`CoverageSnapshot`** is *not* a shared type, and shouldn't become one:
  injection's (`memory_info_stream`/`thread_info_stream`/... plus
  thread-context counters) and encoding's (`memory_info_stream` plus
  per-layer oversized-target tuples) share no fields except
  `memory_info_stream` and the `evaluated`/`complete`/`status` property
  triad — and that triad is exactly what `dumpex.hunt._coverage.
  derive_status`/`derive_coverage_status` already centralizes. Each
  hunter's own gap vocabulary (RIP-context-missing vs.
  oversized-per-layer) is real domain content, not incidental
  duplication — see `_coverage.CoverageTracker`'s own docstring, which
  already documents this same "generic tracker for the common shape,
  hunter-owned dict for the rest" split for stomping/pipe's non-fitting
  cases.

### 3. Projector ownership and compatibility-adapter placement

Confirmed pattern, identical file layout in both `dumpex/hunt/injection/`
and `dumpex/hunt/encoding/`:

- `domain.py` — the canonical `*Report`/`*Evidence`/`CoverageSnapshot`.
- `report_facts.py` — the ONE place the compat `Finding` (wire-shaped
  `facts`, capped at `evidence_limit`) and both coverage projections
  (`project_coverage_v1` for the v1.1 dict shape, `project_coverage_report`
  for the v2.10 `CoverageReport`) are built. Both `report_legacy.py` and
  `report_record.py` call into this module rather than re-deriving facts
  text or coverage shape themselves.
- `report_legacy.py` — pure `*Report -> v1.1 dict` projector.
- `report_record.py` — pure `*Report -> HunterRecord` (v2.10) projector.
- `report_console.py` — pure `*Report -> console lines` projector; also
  the one place each hunter's own normal/verbose `verbose_facts` POLICY
  lives (`report_facts.finding_from_check_result` deliberately never
  populates `verbose_facts` — see that module's own docstring).

This ownership split is confirmed correct and is now itself testable:
`tests/hunt/test_output_source_architecture.py` asserts the
`aggregate.build_report()` boundary (typed evidence/scalars only, no
dump/resolver/verbosity in) for both hunters. No change proposed to this
layering.

### 4. Current-schema compatibility

Confirmed: neither pilot hardcodes a schema filename. Tests and code
reference `dumpex.schemas.CURRENT_SCHEMA` / `current_schema_path()`
(`dumpex/schemas/__init__.py:18,71`, currently resolving to
`dumpex-output-v2.10.schema.json`); `report_facts.py`'s own docstrings say
"current-schema (v2.10)" while pointing at the live constant, not a pinned
literal. Future hunters should follow the same pattern: import
`CURRENT_SCHEMA`/`current_schema_path()`, never write a version string
into test or production code directly.

## Presentation decisions

### 1. Smallest shared presentation primitives — extracted

Diffing `injection/report_console.py` against `encoding/report_console.py`
before this change showed a substantial **byte-identical** block: both
pilots, written independently against the same issue #1 structure,
converged on the exact same helper functions and vocabulary tables. That
convergence is the proof issue #6 asked for — not naming similarity, but
two independent implementations landing on the same code. Extracted to
the new `dumpex/hunt/_report_console.py` in this change:

- `header_lines(title)` — the `══…` bar + `HUNT: {title}` banner.
- `wrap_block(text, width, indent)` — indented word-wrap.
- `sorted_for_display(findings, exclude_checks=frozenset())` —
  DETECTION → LEAD → CONTEXT ordering, stable within a class
  (`exclude_checks` covers injection's coverage-only-check filter;
  encoding passes none).
- `render_key_signal_compact(finding, width, titles)` — one normal-mode
  KEY SIGNALS entry (icon/label/title + wrapped inference).
- `render_why_this_verdict(driving, width)` — the normal-mode WHY THIS
  VERDICT block for the single driving finding.
- `render_coverage(coverage_status, reasons, width, impacts=())` — the
  unified COVERAGE section (`impacts` covers injection's coverage-only
  `Impact:` lines; encoding passes none).
- `with_verbose_facts(finding, verbose_facts)` — the
  `dataclasses.replace(...)`-if-nonempty pattern both `_console_finding`
  helpers repeated.
- `TAG_ICON`/`TAG_LABEL`/`TAG_RANK`/`LABEL_WIDTH`/`COVERAGE_ICON` — the
  tag/coverage-status → icon/label vocabulary, identical in both files.

**Deliberately left where it was, per hunter** (both pilots'
`report_console.py` still own these directly): verdict-block wording and
scoring thresholds (`_render_verdict_block`), check-id → title maps
(`_TITLES`), per-evidence-type `--verbose` fact renderers
(`_*_verbose_fact`), and any hunter-specific evidence section. Two data
points aren't enough to prove a third hunter needs the same *wording* —
only that it needs the same *structure*, which is what moved. This
mirrors the issue's own instruction: "keep hunter-specific verdict
wording, titles, evidence tables ... outside generic domain types."

Both hunters' full test suites (including the injection golden
byte-parity test and the encoding structural/golden tests) pass unchanged
after the extraction — confirming it was a pure refactor, not a behavior
change.

### 2. Legacy console byte parity vs. structural tests + goldens

Confirmed as issue #1 specified, and no different between the two pilots
than documented there:

- **Injection** keeps byte-for-byte parity with the pre-migration console
  (`report_console.py`'s own module docstring; enforced by
  `tests/hunt/test_injection_projectors.py::
  test_golden_scenario_console_matches_approved_fixture` against
  `tests/fixtures/hunt_cli_golden/injection_console.txt`/
  `injection_verbose_console.txt`), plus `tests/integration/
  test_hunt_cli_compat_freeze.py`'s CLI-level frozen console text. This
  is the compatibility target issue #1 named ("Process Injection and HUNT
  SUMMARY are already approved").
- **Encoding** intentionally does NOT preserve legacy byte parity
  (`report_console.py`'s own docstring: "Legacy console byte parity is
  intentionally NOT preserved"). Its `tests/hunt/
  test_encoding_projectors.py` instead pins structure (section presence,
  ordering, wrapping, purity, JSON/console independence — same test names
  as injection's own structural tests) plus reviewed goldens
  (`tests/fixtures/hunt_cli_golden/obfuscation_console.txt`/
  `obfuscation_verbose_console.txt`), consumed only within that one test
  file — i.e. a human-reviewed target, not a frozen historical artifact.

Confirmed: this is the correct, intentional difference, not drift —
Injection is the reference/compatibility target; every other hunter
(Encoding included) gets the structural-test-plus-reviewed-golden
treatment.

### 3. Progress-line policy, normal/verbose boundaries, truncation, no-duplicate coverage

- **No mid-scan progress printing.** Both `report_console.py` modules are
  pure post-hoc projectors (`render_console_lines(report, ...) ->
  list[str]`, never called during scanning). Encoding's pre-migration
  per-layer "Layer 0/1/2-4: ..." progress announcements are gone;
  replaced by a **static, verbose-only** summary
  (`_scan_layers_lines()`), never printed in normal mode and never
  reflecting live progress. Confirmed policy for future hunters: a scan
  layer's own progress chatter has no console representation at all in
  the new model — at most a static verbose-only "what layers ran" note.
- **Normal/verbose boundary**: normal mode shows icon + label + title +
  wrapped inference only (`render_key_signal_compact`); confidence,
  rationale, and full fact enumeration are verbose-only
  (`render_finding_lines`, via `Finding.print`'s own `DetailLevel`).
  Neither pilot's verbose mode recomputes score/status/coverage/ordering
  — both call the identical `report.results`/`report.evidence` verbose
  renders `render_console_lines` already builds normal-mode ordering
  from (see `test_console_verbose_and_normal_never_change_json_projections`
  in both test files).
- **Truncation indicator**: `report_facts._facts_for` appends `"... and N
  more"` when `evidence_limit` trims wire-shaped `facts`; `--verbose`
  fact lists (`verbose_facts`) are always uncapped, so the indicator only
  ever appears in the capped/wire view, never contradicts what
  `--verbose` then shows in full. Identical policy in both pilots.
- **No-duplicate coverage**: confirmed via injection's
  `_coverage_only_impacts`, which dedupes a coverage-only finding's
  limitation text against `coverage_reasons` (`seen = set(coverage_reasons)`)
  before adding an `Impact:` line — the same textual reason is never
  printed twice. Encoding has no coverage-only checks yet, so this rule
  is currently exercised by one pilot only; it is recorded here as the
  rule the next hunter with a coverage-only check (if any) must also
  satisfy, not invented fresh.

### 4. YARA path

Confirmed unchanged from issue #1's own decision, re-verified against
current code: `dumpex/hunt/yara_hunt/aggregate.py`'s own module docstring
states "yara_hunt deliberately does NOT use the Finding model ... it
keeps its own `matches`/`rules_hit` shape." YARA is out of scope for this
review's non-goals ("No ... YARA implementation") — the decision here is
routing only: when #11 migrates YARA, it gets **its own** immutable
Report/projector pair (mirroring this review's #1 finding, not
Injection's or Encoding's `*Evidence`/`CheckResult` shape), because
YARA's score/confidence/review fields are genuinely absent (not merely
zero) for `NOT_EVALUATED`, and its match model (`matches`/`rules_hit`) has
no `Finding`-shaped analogue to project onto — forcing one would fabricate
a confidence/rationale YARA never computed (see `docs/
hunt_migration_field_matrix.md`'s own "yara — the outlier" section, which
already reached this conclusion at the v1.1→v2.4 migration and is
unchanged by this review).

### 5. Remaining order

Confirmed unchanged: **#8 → #7 → #10 → #9 → #11 → #12**. Nothing in
either pilot's evidence argues for reordering — Stomping (#8) and Pipe
(#7) are the two remaining hunters closest in shape to Injection (typed
raw-object evidence, `CoverageTracker`-shaped gaps per
`docs/hunt_migration_field_matrix.md`), Hollowing (#10) needs a genuine
JSON-surface addition (no raw-detail fields exist pre-migration), CS
Beacon (#9) is schema-sensitive (bounded config presentation, v2.10
freeze), and YARA (#11) is the one hunter needing its own boundary rather
than the `CheckResult`/`Finding` shape (see §4 above) — each child issue
should re-read this document's §1–§3 before starting, but none requires a
scope change.

## Non-goals respected

- No Stomping/Pipe/Hollowing/CS Beacon/YARA implementation in this
  change — the only production code touched is the presentation-primitive
  extraction from the two *already-migrated* pilots (§1 above), which
  both hunters' existing test suites (including golden fixtures) verify
  byte-for-byte unchanged.
- No public schema change — `_report_console.py` is console-rendering
  code only; no `HunterRecord`/wire-shape field moved.

## Follow-up changes

- `dumpex/hunt/_report_console.py` (this change) — shared presentation
  primitives, consumed by `injection/report_console.py` and
  `encoding/report_console.py`.
- #8 (Stomping) and every later child issue should import from
  `dumpex.hunt._report_console` rather than re-deriving
  `header_lines`/`wrap_block`/`sorted_for_display`/
  `render_key_signal_compact`/`render_why_this_verdict`/`render_coverage`/
  `with_verbose_facts`/the tag-icon vocabulary locally — and should flag
  it here (or in a follow-up issue) if a THIRD hunter needs to change one
  of those primitives' behavior, since two data points fixed their
  current shape.
