# Output and Evidence Schema

dumpex can write JSON and plain-text output in addition to the console
display. JSON is the canonical case-record format because it contains analysis
data together with evidence identity, execution context, dependency versions,
and rule provenance.

## Formats

| Format | Option | Intended use |
|---|---|---|
| JSON | `--json FILE` | Automation, case records, reproducibility |
| Plain text | `--txt FILE` | Human-readable transcript with ANSI colours removed |

All enabled formats are derived from the same in-memory analysis result.
Existing output files are protected unless `--force` is supplied, and an
output path may never replace an input dump.

`--txt` is a human-readable console transcript (colours stripped), not a
machine interface: it carries no schema, no version, and no compatibility
promise. Automation must use `--json`, never scrape `--txt`.

## One JSON contract

Every command now shares a single JSON contract. `--hunt` was the last
holdout on the older v1.1 contract; it has since migrated onto v2, and
the whole v2 envelope has since moved onto v2.11:

| Commands | Contract | Schema file |
|---|---|---|
| `--list`, `--modules`, `--threads`, `--pid`, `--sysinfo`, `--peb`, `--diff`, `--extract`, `--strings`, `--report`, `--hunt` | v2.11 (current) | [`dumpex-output-v2.11.schema.json`](../dumpex/schemas/dumpex-output-v2.11.schema.json) |
| — (historical) | v2.10 | [`dumpex-output-v2.10.schema.json`](../dumpex/schemas/dumpex-output-v2.10.schema.json) — frozen, kept only to validate output produced before `schema_version 2.11`; no command emits this anymore |
| — (historical) | v2.9 | [`dumpex-output-v2.9.schema.json`](../dumpex/schemas/dumpex-output-v2.9.schema.json) — frozen, kept only to validate output produced before `schema_version 2.10`; no command emits this anymore |
| — (historical) | v2.8 | [`dumpex-output-v2.8.schema.json`](../dumpex/schemas/dumpex-output-v2.8.schema.json) — frozen, kept only to validate output produced before `schema_version 2.9`; no command emits this anymore |
| — (historical) | v2.7 | [`dumpex-output-v2.7.schema.json`](../dumpex/schemas/dumpex-output-v2.7.schema.json) — frozen, kept only to validate output produced before `schema_version 2.8`; no command emits this anymore |
| — (historical) | v2.6 | [`dumpex-output-v2.6.schema.json`](../dumpex/schemas/dumpex-output-v2.6.schema.json) — frozen, kept only to validate output produced before `schema_version 2.7`; no command emits this anymore |
| — (historical) | v2.5 | [`dumpex-output-v2.5.schema.json`](../dumpex/schemas/dumpex-output-v2.5.schema.json) — frozen, kept only to validate output produced before `schema_version 2.6`; no command emits this anymore |
| — (historical) | v2.4 | [`dumpex-output-v2.4.schema.json`](../dumpex/schemas/dumpex-output-v2.4.schema.json) — frozen, kept only to validate output produced before `schema_version 2.5`; no command emits this anymore |
| — (historical) | v2.3 | [`dumpex-output-v2.3.schema.json`](../dumpex/schemas/dumpex-output-v2.3.schema.json) — frozen, kept only to validate output produced before `schema_version 2.4`; no command emits this anymore |
| — (historical) | v2.2 | [`dumpex-output-v2.2.schema.json`](../dumpex/schemas/dumpex-output-v2.2.schema.json) — frozen, kept only to validate output produced before `schema_version 2.3`; no command emits this anymore |
| — (historical) | v2.1 | [`dumpex-output-v2.1.schema.json`](../dumpex/schemas/dumpex-output-v2.1.schema.json) — frozen, kept only to validate output produced before `schema_version 2.2`; no command emits this anymore |
| — (historical) | v2.0 | [`dumpex-output-v2.0.schema.json`](../dumpex/schemas/dumpex-output-v2.0.schema.json) — frozen, kept only to validate output produced before `schema_version 2.1`; no command emits this anymore |

`schema_version` moved from `"2.0"` to `"2.1"` when `result.kind` gained a
`"comparison"` value, then from `"2.1"` to `"2.2"` when it gained `"extract"`
and `"strings"` values, then from `"2.2"` to `"2.3"` when it gained `"report"`,
then from `"2.3"` to `"2.4"` when it gained `"hunt"` (a `result.kind` value
now produced by `--hunt`, the last command to switch its CLI wiring onto
the v2 envelope; see "Hunt records" below for that record shape), then from
`"2.4"` to `"2.5"` when `hunterRecord.findings[]`'s own `finding` $def
gained seven new properties (`id`/`severity`/`technique_ids`/
`evidence_refs`/`iocs`/`rule_id`/`rule_version` — see "Hunt records" below),
then from `"2.5"` to `"2.6"` when `--hunt cs-beacon`'s
`csBeaconDetails.configs[*].fields[*]` lost its `raw` field (see "Hunt
records" below — `configs[*]` items stay schema-open, `type: object`, in
both v2.5 and v2.6, so this particular change isn't visible as a schema
`$defs` diff the way the earlier ones are; it is still a real, breaking
change to the WIRE shape a consumer actually receives, which is what the
versioning policy below cares about, not merely whether the schema file's
own JSON text changed), then from `"2.6"` to `"2.7"` when `--hunt
cs-beacon`'s `csBeaconDetails.configs[*].fields` was re-keyed by field
NAME instead of numeric TLV field ID, dropping the now-redundant `name`
property from each field's own value (see "Hunt records" below — UNLIKE
the 2.6 change, this one IS visible as a `$defs` diff: `fields` itself
gained a `propertyNames` pattern and a per-field `additionalProperties:
false` shape, specifically so a document still shaped like 2.6 fails
validation against 2.7 rather than silently passing), then from `"2.7"`
to `"2.8"` when the shared `coverageLimitation` $def gained a `targets`
array (and the `scanTarget` $def it holds), so a limitation reporting
that a scan skipped something can identify WHAT it skipped rather than
only counting it (see "Coverage limitations and skipped scan targets"
below — `coverageLimitation` is `additionalProperties: false` with a
closed `required` list, so this too is a visible, validator-enforced
`$defs` diff), then from `"2.8"` to `"2.9"` when `huntSummary`
(`result.summary` for `kind == "hunt"`) gained a required
`investigation_actions` array — `--hunt all`'s automatically-derived,
metadata-only skipped-target investigation queue (see "Hunt investigation
actions" below — `huntSummary` is `additionalProperties: false` with a
closed `required` list, the same reason v2.7→v2.8's `coverageLimitation`
change forced a bump), then from `"2.9"` to `"2.10"` when the shared
`triageInfo` $def (nested inside each `investigation_actions[]` entry)
gained a required `content_reason_codes` array — the opt-in `--hunt all
--triage-skipped` budgeted deep-content triage pass's own structured
record of what it actually found in a target's examined bytes (an
IOC-pattern string match, a network-pattern string match, or an
injected-PE MZ header — see "Hunt investigation actions" below;
`triageInfo` is `additionalProperties: false` with a closed `required`
list, the same reason every prior closed-object addition on this list
forced a bump), then from `"2.10"` to `"2.11"` when `huntPeHeaderHit`
(each entry of `--hunt injection`'s `hidden_pe_validated`/
`hidden_pe_unvalidated`/`suspicious_validated_pe_hits`/
`informational_validated_pe_hits`) gained the required `va`/
`region_offset`/`file_offset` candidate location — the hidden-PE scan now
searches each eligible region for `MZ` candidates at every byte offset
instead of only probing the region base
([issue #26](https://github.com/bitbug0x55AA/dumpex/issues/26)), so a
hit's containing region no longer says where the PE actually is, and a
consumer needs the candidate's own address to carve or correlate it
(`huntPeHeaderHit` is `additionalProperties: false` with a closed
`required` list, the same reason every prior closed-object addition on
this list forced a bump)
(see "v2 structured output" below) — a
new value on an existing closed enum, a new field on an already-closed
(`additionalProperties: false`) object, or the removal of a field a
command has ever actually emitted (whether or not the schema itself
enforced that field's presence), always bumps the version per this
document's own versioning policy, even though an already-migrated
command's own output is otherwise unaffected (the `"report"`/`"hunt"`/
`finding`-extension/cs-beacon-`raw`-removal/cs-beacon-field-rekey/
coverage-`targets`/hunt-`investigation_actions`/triage-`content_reason_codes`/
hidden-PE-candidate-location changes
specifically must NOT be folded into `dumpex-output-v2.2.schema.json`/
`v2.3.schema.json`/`v2.4.schema.json`/`v2.5.schema.json`/`v2.6.schema.json`/
`v2.7.schema.json`/`v2.8.schema.json`/`v2.9.schema.json`/`v2.10.schema.json`
in place: those files were already shipped/used by earlier-migrated
commands' output before each change existed, so they stay byte-frozen —
each change gets its own new schema_version instead). `dumpex-output-
v2.0.schema.json`/`v2.1.schema.json`/`v2.2.schema.json`/`v2.3.schema.json`/
`v2.4.schema.json`/`v2.5.schema.json`/`v2.6.schema.json`/`v2.7.schema.json`/
`v2.8.schema.json`/`v2.9.schema.json`/`v2.10.schema.json`
stay installed and importable via
`dumpex.schemas.schema_path("dumpex-output-v2.0.schema.json")` (or `v2.1`/
`v2.2`/`v2.3`/`v2.4`/`v2.5`/`v2.6`/`v2.7`/`v2.8`/`v2.9`/`v2.10`) for validating output captured
before each respective
change; none is deleted or overwritten, following the same precedent
v1.0→v1.1 set. All eleven commands, including `--hunt`, now produce the
v2.11 contract.

`--extract` is the first command to populate the top-level `artifacts[]`
(the file it wrote) and `diagnostics.warnings[]` (e.g. an MZ-header-detected
warning) — both are siblings of `result`, not nested under it (see the
envelope shape above) — for real; both were part of the v2 envelope since
`schema_version 2.1` but had no producer until `--extract` migrated.
`--strings` reuses the same `requested_region`-scoped coverage shape as
`--extract` (see `extractRecord`/`stringRecord` below) but never writes an
artifact of its own. `--report` also populates `artifacts[]` (one entry per
triage card whose `--output` extract succeeded, `kind: "report_extracted_region"`
— a different `kind` string than `--extract`'s own `"extracted_region"`, so
`artifacts[].kind` still distinguishes the two) and `diagnostics.warnings[]`
(e.g. a not-found TID/region/string, or a thread's unbacked-status fact
excluded from the combined verdict because it isn't correlated with the
resolved region).

This split used to exist because v1.1's root schema requires a top-level
`hunt` object (`"required": ["meta", "hunt"]`) — the six original recon
commands never produced one, so their JSON, despite stamping
`schema_version: "1.1"`, could never actually validate against the schema
it claimed to satisfy. v2 was built as a genuinely separate,
self-consistent contract for those six commands rather than a patch to
v1.1's `hunt`-shaped root. `--hunt` was the last command still on v1.1;
it has since migrated onto v2 as well (see "Hunt records" below), so no
command produces the v1.1 contract anymore. The rest of this section
describes v1.1 for historical/reference purposes only — see "v2
structured output" below for the current contract every command,
including `--hunt`, now uses.

## JSON document (v1.1 — historical, no longer produced)

The top-level object contains `meta` followed by one or more command-specific
result sections:

```json
{
  "meta": {
    "schema_version": "1.1",
    "tool": {
      "name": "dumpex",
      "version": "<installed version>"
    },
    "execution": {
      "started_at": "2026-07-26T01:00:00Z",
      "finished_at": "2026-07-26T01:00:01Z",
      "duration_seconds": 1.234,
      "command": "hunt",
      "options": {
        "hunt": "all"
      },
      "case_id": "CASE-1234",
      "analyst": "analyst01"
    },
    "evidence": {
      "file_name": "sample.dmp",
      "path": "C:\\cases\\sample.dmp",
      "size_bytes": 1048576,
      "sha256": "<64 hexadecimal characters>"
    },
    "runtime": {
      "python_version": "3.12.0",
      "minidump_version": "<installed version>",
      "yara_version": "<installed version>",
      "pyyaml_version": "<installed version>"
    }
  },
  "hunt": {
    "...": "command-specific results"
  }
}
```

Fields that do not apply to a run may be omitted. Dependency version fields
are present only when the corresponding distribution is installed.

## Metadata fields

### `meta.schema_version`

Version of the JSON contract, independent of the dumpex application version.
Consumers should use this field when validating compatibility.

### `meta.tool`

Identifies the producer and its package version. Source-checkout runs fall
back to the package's `__version__` when installed distribution metadata is
unavailable.

### `meta.execution`

Records UTC start and finish timestamps, whole-invocation duration, selected
mode, effective options, and optional `--case-id` / `--analyst` values.

The duration starts before argument parsing and dump opening, so it covers
evidence parsing as well as the requested analysis.

### `meta.evidence`

Records the input filename, absolute path, size, and SHA-256 identity. Hash or
filesystem errors are captured in an `error` field without preventing the
analysis result from being written.

With `--redact-paths`, the absolute `path` is omitted while `file_name`,
`size_bytes`, and `sha256` remain available for evidence correlation.

### `meta.runtime`

Records the Python version and installed versions of relevant parser, YAML,
and YARA dependencies.

### `meta.rules`

Present when a hunt loads the TTP ruleset. It identifies the actual
`rules.yaml` source, SHA-256, and whether the source was explicitly supplied.
This block is omitted for commands that never load the TTP rules.

### `meta.yara_rules`

Present when YARA scanning is invoked. It records:

- the effective rules directory;
- sorted rule filenames;
- a SHA-256 for each rule file;
- an aggregate ruleset SHA-256; and
- compile success and failure counts.

It is omitted when YARA scanning was not invoked. This distinction prevents
an unused rules directory from being mistaken for the ruleset that produced a
verdict.

`--redact-paths` reduces paths in `meta.rules`, `meta.yara_rules`, and
path-bearing execution options (`ref_dir`, `yara_dir`, and `rules_file`) to
basenames.

## Hunt result semantics (v1.1 field names — historical)

Each hunter reported its findings and decision fields inside the v1.1
`hunt` object using the field names below. Under the current v2.11
contract these same concepts live on `HunterRecord` — see "Hunt records"
below for the `status`/`coverage.status`/`verdict_level`/`confidence`
mapping `--hunt` now uses. The important decision fields were:

| Field | Question answered |
|---|---|
| `status` | Was evidence detected, not detected in scanned scope, inconclusive, or not evaluated? |
| `coverage_status` | Was the evidence needed by the hunter fully available? |
| `verdict_level` | What severity did the validated evidence support? |
| `confidence` | How strongly does the available evidence support that interpretation? |
| `coverage_reason` | What was missing, unreadable, skipped, or limited? |

These fields must be interpreted together. In particular, partial coverage
does not negate a positive detection, and a scoped non-detection is not proof
of absence. See the [SOC / DFIR Quick Start](SOC_QUICKSTART.md) for the
disposition matrix and hunter-specific caveats.

`confidence`, `findings`, `lead_count`, and `review_priority` are reported by
the six Finding-model hunters (injection, hollowing, stomping, pipe,
cs-beacon, obfuscation). `yara` reports its own `matches`/`rules_hit` shape
instead and does not emit those four fields — only `status`, `score`,
`coverage_status`, and `verdict_level` are guaranteed across all seven.

## JSON Schema

The formal contract for the document above is
[`dumpex/schemas/dumpex-output-v1.1.schema.json`](../dumpex/schemas/dumpex-output-v1.1.schema.json)
(JSON Schema, draft 2020-12). It ships inside the installed package — a
consumer of `pip install dumpex` reaches it via
`importlib.resources.files("dumpex.schemas")`, the same way
`dumpex.rules_pkg` ships the bundled YARA/TTP rule defaults — not by reading
a path relative to a source checkout. `tests/integration/test_json_schema.py`
still validates each hunter's internal result dict (all seven hunters, both
typical and edge-case verdicts) against this file on every test run,
including the negative cases it must reject — this is legacy-compatibility
coverage for the v1.1 shape itself, independent of the CLI's own
`--hunt --json` output, which is now v2.11 (see "Hunt records" below).

Each entry under `hunt` is validated as one of three shapes: `findingHunterResult`
(injection, hollowing, stomping, pipe, cs-beacon — and any future/renamed
hunter, via the schema's `additionalProperties` fallback), which requires
`confidence`/`findings`/`lead_count`/`review_priority` in addition to the
fields common to all three; `obfuscationHunterResult` (the `obfuscation`
key specifically), a `findingHunterResult` that additionally formally
types its own `sleep_mask`/`entropy`/`base64`/`xor`/`compressed`/
`hidden_pe`/`hidden_shellcode` hit-list fields (schema_version 1.1 —
these were entirely unvalidated before, passing through the generic
shape's `additionalProperties: true`); or `yaraHunterResult` (the `yara`
key specifically), which only requires the fields common to all three
since yara_hunt's own `matches`/`rules_hit` model never emits
`confidence`/`findings`/`lead_count`/`review_priority`. All three compose
the same `hunterResultBase` (`status`/`score`/`coverage_status`/
`verdict_level` plus the NOT_EVALUATED/INCONCLUSIVE cross-field
invariants) via `allOf`.

The standalone Windows EXE built by `.github/workflows/build.yml` does not
read this file (or any schema file) at runtime (nothing in the running
tool validates its own output — only the test suite and external `--json`
consumers do), so none of them are collected into the frozen executable.
They are instead uploaded as separate `dumpex-output-v*.schema.json`
files alongside `dumpex.exe` in the release ZIP — every version currently
packaged (`v1.1`, `v2.0`, `v2.1`, `v2.2`, `v2.3`, `v2.4`, `v2.5`, `v2.6`, `v2.7`, `v2.8`, `v2.9`, `v2.10`, `v2.11`), the same
set `pip install dumpex` already ships (see "Reproducing a run" below for
how an installed package reaches these via `importlib.resources`) — so an
EXE-only install (no `pip install dumpex`, no source checkout) still has
a way to get the schema for whatever output it's holding. Current CLI
output (from any command, including `--hunt`) always validates against
`dumpex-output-v2.11.schema.json`, the current contract — this section's
own subject, `dumpex-output-v1.1.schema.json`, and `v2.0`–`v2.10` are
shipped only to validate output produced by an older dumpex version, not
anything a current install can produce.

### Versioning and breaking changes

`meta.schema_version` (`"1.1"`, back when this was the contract `--hunt`
produced) is the contract version, independent of the dumpex application
version. The policy for changing the schema file — retained here for
historical reference and because the schema file itself still exists for
the legacy-compatibility coverage described above:

- **A new optional object field** — no version bump. `additionalProperties`
  keeps object shapes open, so an older cached copy of the schema silently
  ignores a field it doesn't know about; nothing that already validated
  stops validating. Update the schema file and add/extend a schema test.
- **A new field on an object whose $def already sets
  `additionalProperties: false`** (e.g. `finding`, or any of the typed
  record shapes) — **always bump**, even for an optional/nullable field.
  Unlike the open-object case above, a closed object's already-shipped
  schema copy rejects ANY key it doesn't list — real output that starts
  carrying the new field would fail validation against the old schema
  the moment the field appears, not just when it's missing. This is what
  `schema_version 2.4` → `2.5` did to `finding` (see "Hunt records"
  below).
- **A new value added to an existing enum-typed field** (`status`,
  `coverage_status`, `verdict_level`, `confidence`, `review_priority`,
  `finding.tag`, …) — **always bump**, even though this feels "additive" from
  the tool's side. Unlike object properties, enums are a closed list: an
  older cached copy of the schema will reject a document carrying the new
  value, because that value simply isn't in its list. There is no
  forward-compatible way to add an enum value without either bumping
  `schema_version` or breaking whoever is still validating against the old
  one.
- **Narrowing that codifies existing behavior** (e.g. making `required` match
  fields every hunter already unconditionally emits, or narrowing a field's
  type to what the tool has only ever actually produced) — no version bump
  *if and only if* it's verified against all seven hunters' real code paths
  that no currently-produced document is rejected by the change. This is a
  bugfix to the contract file, not a change to the contract itself. Add a
  schema test proving both the still-valid real shape and the now-rejected
  broken shape.
- **Narrowing that could reject a currently-valid document**, or any
  **removal/renaming of a field or status value** — bump `schema_version`
  (the `const` in the schema, `StructuredOutput.SCHEMA_VERSION` in
  `dumpex/ui/structured.py`, and the schema filename), and call it out in
  release notes. Never silently reuse an existing `schema_version` for an
  incompatible shape change.

## v2 structured output

These eleven commands are always structured internally — even
without `--json` — and use a distinct envelope from v1.1's old
`hunt`-shaped root. `--diff` is the one two-dump exception (`kind:
"comparison"`, a two-entry `meta.evidence`) — see "`result.kind ==
"comparison"`" below; everything in this section otherwise applies to it
too:

```json
{
  "meta": {
    "schema_version": "2.11",
    "tool": { "name": "dumpex", "version": "<installed version>" },
    "execution": { "...": "same shape as v1.1" },
    "evidence": [
      { "id": "primary", "role": "primary", "file_name": "sample.dmp",
        "path": "C:\\cases\\sample.dmp", "size_bytes": 1048576,
        "sha256": "<64 hex chars>" }
    ],
    "runtime": { "...": "same shape as v1.1" }
  },
  "result": {
    "kind": "modules",
    "execution_status": "completed",
    "coverage": {
      "status": "complete", "reasons": [],
      "sources": { "modules": { "state": "present", "record_count": 42, "detail": null } },
      "limitations": []
    },
    "summary": { "count": 42 },
    "data": { "records": [ "...": "one canonical record per item" ] }
  },
  "artifacts": [],
  "diagnostics": { "warnings": [], "errors": [] }
}
```

`meta.evidence` is an **array**, not a single object (v1.1's shape) — a
single-dump recon command emits exactly one entry, `role: "primary"`;
`--diff` emits exactly two, `role: "baseline"`/`role: "target"` (see
"`result.kind == "comparison"`" below), without a breaking change to this
array's own shape.

`result` deliberately keeps three concepts separate, and none of them is
a verdict:

- **`execution_status`** — did the *command* run to completion
  (`"completed"` / `"partial"` / `"failed"`)? Ten of these eleven commands
  have no internal scan-budget/timeout, so this is `"completed"` in every
  case that doesn't crash. `--report` is the exception: its own per-region
  string scan is capped at a fixed byte ceiling
  (`MAX_REGION_READ`), and a per-card `--output` extract can itself fail
  to write — either one sets `execution_status: "partial"`, independent of
  `coverage.status` (a self-imposed scan-budget clamp or a write failure is
  not an evidence-completeness gap, see `coverage.status` below). `--hunt`
  is not a second exception here: its `execution_status` is always
  `"completed"`, even when individual hunters hit their own scan budgets
  (`scan_complete`/`budget_exhausted` on `PipeDetails`/`YaraDetails`/
  `ObfuscationDetails`) — that is folded into `coverage.status` below
  instead, the same way any other per-hunter evidence gap is.
- **`coverage.status`** — was the *evidence* it looked at complete
  (`"complete"` / `"partial"` / `"not_evaluated"`), reusing the same
  vocabulary `--hunt`'s own hunter-level coverage derivation uses
  (`dumpex.hunt._coverage.derive_coverage_status`)? For example,
  `--threads` reports `"partial"` when a dump lacks
  `ThreadInfoListStream`; `--pid` reports `"partial"` when it had to fall
  back past `MINIDUMP_MISC_INFO` to a thread-list/exception-stream
  heuristic; `--hunt`'s document-level `coverage.status` (built by
  `dumpex.hunt._hunt_coverage_report()` from `result.summary`) is
  `"not_evaluated"` when every selected hunter is, `"partial"` when any
  hunter is INCONCLUSIVE or NOT_EVALUATED, and `"complete"` otherwise —
  independent of each individual `HunterRecord`'s own, more detailed
  `coverage`. `coverage.reasons` explains why.
- **verdict/confidence** — not a top-level `result` concept for any of
  these eleven commands. Two carry it per-record instead: `--report`'s
  `triageCardRecord.verdict` (one triage card's own MECE score),
  independent of and orthogonal to that card's `execution_status`/
  `coverage.status` — a card can be `"CLEAN"` with `coverage.status:
  "partial"` (evidence was incomplete but what was seen showed nothing),
  or vice versa — and `--hunt`'s `hunterRecord.verdict_level`/
  `confidence`, one judgment per selected hunter; `result.summary`'s own
  `overall_status`/`highest_verdict_level` roll those per-hunter values up
  across the whole `--hunt` invocation without introducing a second,
  competing top-level verdict field.

`coverage.reasons` is a flat, human-readable text array — fine for
printing, not for programmatic filtering. `coverage.sources` and
`coverage.limitations` expose the same facts structurally, for a
consumer that wants to act on them without string-matching:

- **`coverage.sources`** — one entry per underlying minidump stream this
  command consulted, keyed by source name (`"memory_info"`, `"threads"`,
  `"misc_info"`, ...). Each value is `{"state", "record_count", "detail"}`
  — `state` is one of `"absent"` / `"present_empty"` / `"present"` /
  `"failed"`. Eight of the nine single-dump recon/extract/report commands
  never produce `"failed"` (a read failure crashes the whole command
  instead) — `--diff` is one exception: reading one side's stream can
  genuinely raise without the other side's dump being at fault, so that
  side is reported as `"failed"` (with `detail` carrying the underlying
  error text) and that entity's diff is skipped, rather than the whole
  comparison crashing or the failed side being silently treated as empty.
  `--report` is the other exception, for a different reason: a triage
  card's own target-region content read failing has evidence elsewhere in
  the same card (thread, other-region, verdict) worth still reporting, so
  a synthetic `"requested_region"` source aggregates "at least one card's
  region read failed" as `"failed"` rather than aborting the whole
  command. This is exactly `dumpex.output.coverage.SourceObservation`, one
  per source. `--hunt` is a different shape entirely: its document-level
  `coverage` (built by `dumpex.hunt._hunt_coverage_report()`) carries only
  a `status`, with empty `sources`/`limitations` — per-source coverage
  detail lives one level down, on each selected hunter's own
  `HunterRecord.coverage`, not on the whole-command `result.coverage`.
- **`coverage.limitations`** — an array of structured, machine-readable
  gaps; `coverage.reasons` is rendered from this list, one string per
  entry, in the same order. Each entry always has `code` and `source`;
  every other field (`scope`, `affected_count`, `unavailable_fields`,
  `available_fields`, `counterpart_source`, `related_sources`,
  `related_tids`, `thread_id`, `detail`) is populated only when that
  particular `code` uses it, `null`/`[]` otherwise. `code` is
  intentionally a plain string, not a
  fixed enum in the schema — the underlying vocabulary
  (`dumpex.output.coverage.LimitationCode`) grows as more commands
  migrate, and this schema doesn't need a version bump every time a new
  code is added.

Both fields are optional (a producer that doesn't populate them is still
a schema-valid document) and were additive to `schema_version: "2.1"` — no
version bump, per the versioning rule above.

`result.data.records` is always an array of one canonical record type per
`kind` (`memory_regions` → `MemoryRegionRecord`, `modules` →
`ModuleRecord`, `threads` → `ThreadRecord`, `sysinfo` → `SysInfoRecord`,
`pid` → `PidRecord`, `peb` → `PebRecord`, `hunt` → `HunterRecord`) — a
single-record result (`sysinfo`/`pid`/`peb`) is still a one-element array,
not a bare object,
so a consumer never needs to special-case array-vs-object by `kind`. Each
record type is fully typed per `kind` in the JSON Schema itself
(`additionalProperties: false`, every field's exact type, hex-address
format) via an `if`/`then` dispatch on `result.kind` — a dropped, renamed,
or mistyped field fails schema validation, not just "records is an
array." See [`dumpex/output/records.py`](../dumpex/output/records.py) for
the exact field lists.

Two type conventions apply uniformly across every v2 record: a field is a
normalized, fixed-width (16 hex digit), lowercase `"0x..."` string only
when it is a real memory address/pointer/handle; every other numeric
field (`pid`, `tid`, `size`, `checksum`, durations, counts, `exit_status`,
...) is a plain JSON integer. Missing values are always `null`, never
`""`. The v2 serializer
([`dumpex/output/serializer.py`](../dumpex/output/serializer.py)) enforces
the second rule structurally: it raises rather than silently
stringifying any value that isn't already a plain JSON scalar/list/dict
by the time it's serialized.

An exit code mirrors `coverage.status` one-for-one for these eleven
commands, independent of whether `--json` was even requested: `0`
for `"complete"`, `3` for `"partial"`, `4` for `"not_evaluated"` (the
primary stream a command needed was entirely absent from the dump — e.g.
`--modules` when `ModuleListStream` itself isn't present, as opposed to
being present with zero entries, which is `"complete"`) — a SOC script
checking `$?` on a bare `dumpex sample.dmp --threads` can distinguish "no
data at all" from "some data, degraded" without parsing JSON at all.
`--hunt` follows the same mapping from its own document-level
`coverage.status` (`4` when every selected hunter is NOT_EVALUATED, `3`
when any hunter is INCONCLUSIVE or NOT_EVALUATED, `0` otherwise) — the
same three-way split `dumpex/hunt/__init__.py`'s `_hunt_coverage_report()`
derives from `result.summary`, replacing the unconditional `0` `--hunt`
used to exit with under the v1.1 contract. This convention is scoped to
these eleven commands only; every other command's exit-code behavior (`0`
on completion, an uncaught exception's default nonzero on a fatal error)
is unchanged. `--extract`/`--strings`/`--report`
also use `"partial"` for a short read (`REGION_READ_TRUNCATED` —
`read_region()` returned fewer bytes than requested, e.g. because the
requested range extends past what's actually backed in the dump): the
requested region itself stays `"present"` in `coverage.sources` (there IS
real data), but the read didn't fully succeed either. `--report` reuses
this exact code/source pair (`source: "requested_region"`) for an
aggregate, whole-run fact spanning every triage card's own target-region
read — not one entry per card, since the source name is not namespaced per
card (every card reads the same underlying dump). `--report-string`'s own
memory-wide search additionally distinguishes a *different* gap —
`REPORT_STRING_SCAN_INCOMPLETE`, source `"string_search"` — for regions the
search itself skipped because it could not read them while looking for the
needle, independent of whether the regions it DID find are then read
completely or short.

`artifacts` (top-level, a sibling of `result`) is an output file the tool
itself produced — e.g. an extracted memory region — distinct from
`meta.evidence`, which describes the *input* dump(s). Each entry is
`{"id", "kind", "path", "size_bytes", "sha256", "description"}`
(`dumpex.output.records.Artifact`), field naming mirroring
`meta.evidence`'s own `id`/`path`/`size_bytes`/`sha256` shape.
`--extract` is the first command to populate it — one entry per
`--output` file written (`kind: "extracted_region"`); `--report` also
populates it — one entry per triage card whose own `--output` extract
succeeded (`kind: "report_extracted_region"`, a different string so
`artifacts[].kind` still distinguishes the two producers). `--redact-paths`
reduces each entry's `path` to its basename the same way it does
`meta.execution.options`' path-typed fields — `size_bytes`/`sha256`/
`description` are left untouched.

### Comparison records

`schema_version 2.1` adds a `"comparison"` value to `result.kind` and
three new tagged-union record types for it, grounded in `--diff`'s own
`diff_modules`/`diff_threads`/`diff_memory` console business logic (see
[`dumpex/commands/comparison.py`](../dumpex/commands/comparison.py) for
the ported `collect_module_diff`/`collect_thread_diff`/
`collect_memory_diff`/`collect_comparison()` functions, and
[`dumpex/commands/diff.py`](../dumpex/commands/diff.py) for the
`collect_diff`/`render_diff_console`/`cmd_diff` CLI-facing trio):
`moduleDiffRecord`, `threadDiffRecord`, `memoryDiffRecord` --
`entity_type` (`"module"` / `"thread"` / `"memory_region"`) is the
discriminator a mixed `result.data.records` array uses to tell them apart.
Each carries `change_type` (`"added"`/`"removed"`/`"rebased"` for modules,
`"added"`/`"removed"` for threads, `"added"`/`"removed"`/
`"protection_changed"` for memory regions) plus before/after field pairs --
only the pair a given `change_type` actually produces is non-null (e.g. an
`"added"` module has no `full_path_before`, since there is no
baseline-side module to report one from). `--diff-scope
modules|threads|memory|all` (default `all`) selects which entity types
appear in `result.data.records`; only the corresponding sources appear in
`coverage.sources` too. See
[`dumpex/output/records.py`](../dumpex/output/records.py)'s
`ModuleDiffRecord`/`ThreadDiffRecord`/`MemoryDiffRecord` for the exact
field lists.

`--diff REFERENCE`'s `meta.evidence` has exactly two entries --
`{"id": "baseline", "role": "baseline", ...}` for the `--diff` reference
dump and `{"id": "target", "role": "target", ...}` for the primary dump
argument --
built via `V2Output.from_evidence()` instead of the single-`dump_path`
constructor the other ten commands use. `coverage.sources` uses dotted,
entity-namespaced source names (e.g. `"baseline.modules"`/
`"target.modules"`, `"baseline.thread_info"`/`"target.thread_info"`,
`"baseline.memory_info"`/`"target.memory_info"`) rather than the bare
names the nine single-dump commands use, so a comparison's baseline and
target sides never collide as coverage facts about the same-named source.
`coverage.status` is combined across whichever entities `--diff-scope`
selected (`dumpex.output.coverage.combine_coverage_reports`): unanimous
`"not_evaluated"` only if every selected entity is (e.g. `--diff-scope all`
against two dumps that both lack every one of ModuleListStream/
ThreadInfoListStream/MemoryInfoListStream); a single weak entity among
otherwise-complete ones is `"partial"`, not `"not_evaluated"`. This is
also the one place `coverage.sources`' `"failed"` state appears in
practice (see above) -- a side's stream raising on read (as opposed to
merely being absent) marks that side `"failed"` and skips that entity's
diff, without aborting the other selected entities.

### Extract and strings records

`schema_version 2.2` adds `"extract"`/`"strings"` values to `result.kind`
and their own record types, `extractRecord`/`stringRecord` (see
[`dumpex/commands/extract.py`](../dumpex/commands/extract.py)'s
`collect_extract`/`collect_strings` and
[`dumpex/output/records.py`](../dumpex/output/records.py)'s
`ExtractRecord`/`StringRecord` for the exact field lists).

`--extract` always returns a single-element `records` array —
`{"requested_address", "requested_size", "auto_sized", "bytes_read",
"mz_header_detected"}` — the READ-side facts only; the WRITE-side facts
(the `--output` path, its size, its sha256) live on the matching
`artifacts[]` entry instead, not duplicated onto the record, since the
two describe conceptually distinct things (what was read from the dump
vs. what was written to disk) that happen to usually agree in size.
`mz_header_detected` also drives a `diagnostics.warnings[]` entry
(`code: "EXTRACT_MZ_HEADER_DETECTED"`) when set.

`--strings` returns one `stringRecord` per extracted string —
`{"offset", "address", "encoding", "text", "matched_grep"}` — regardless
of `--grep`: `matched_grep` is a flag, not a filter, so `result.data.
records` (JSON) always contains every extracted string (`null` when
`--grep` wasn't given at all; `true`/`false` per record when it was). The
console rendering is narrower and does NOT match this one-for-one: it
skips any record with `matched_grep == false` entirely (only ever
highlighting the `true` matches). Console skips records whose
`matched_grep` is false, so it may show fewer records than JSON when
non-matching strings exist — if every extracted string happens to match
`--grep`, console and JSON show the same count for that run.
`result.summary` additionally carries `requested_address`/
`requested_size`/`bytes_read`/`auto_sized`/`shown` (`--strings`-only
scan-context fields exposed directly in JSON's `result.summary`).

Both commands share the same `requested_region`-scoped
`coverage.sources` shape as every other v2 command — a bad `--extract`/
`--strings` address or size is a usage error (`sys.exit(1)`, printed
before any structured output is written), not something either command
models as a coverage gap; a short read (fewer bytes actually read than
requested) is the one genuine evidence-completeness gap either command
can hit, and is what `coverage.status: "partial"` /
`REGION_READ_TRUNCATED` (see above) exists for.

### Report records

`schema_version 2.3` adds a `"report"` value to `result.kind` and its own
record type, `triageCardRecord` (see
[`dumpex/commands/report.py`](../dumpex/commands/report.py)'s
`collect_report`/`_collect_triage_card` and
[`dumpex/output/records.py`](../dumpex/output/records.py)'s
`TriageCardRecord`/`ReportThreadInfo`/`ReportRegionInfo`/`ReportIocString`
for the exact field lists). `"report"` gets its own new `schema_version`
rather than being folded into `dumpex-output-v2.2.schema.json` in place:
that file was already shipped/used by `--extract`/`--strings` output
before `"report"` existed, and a closed enum's already-shipped copy must
never start silently accepting a value it didn't originally define.

`result.data.records` holds one `triageCardRecord` per **triage card** —
deliberately NOT a tagged union of independent thread/region/string
entities the way `"comparison"` is: a card's thread/region/strings/verdict
form one coherent, MECE-scored narrative about a single anchor, not
things a consumer would reasonably count or filter separately.
`--report-tid`/`--report-addr` (used alone or together) always produce
exactly one card; `--report-string` searches every committed region for
the needle, then produces one card per hit in an unregistered/private
region (a hit inside a known module is treated as expected noise and
never becomes a card at all — see `result.summary` below for the
skipped/noise counts). `anchor_source` (`"tid"` / `"address"` /
`"string_hit"`) says which trigger produced a given card; `anchor_tid`/
`anchor_address` are the resolved TID/target address regardless of
source. `verdict` (`"CLEAN"` / `"SUSPICIOUS"` / `"LIKELY_MALICIOUS"` /
`"HIGH_CONFIDENCE_MALICIOUS"`) is `dumpex.core.memory.verdict_for(dims)`'s
own four-tier output — provably the same rule the console's own colored
verdict text is derived from, not a second, independently maintained
copy. `findings` lists which of the four MECE dimensions
(`unbacked_thread`/`rwx_private`/`injected_pe`/`ioc_strings`) fired, in
the order they were detected; `finding_details` maps each to its human
detail string. `thread_region_correlation_excluded` is `true` exactly
when the anchor thread's own unbacked-thread fact was excluded from the
combined verdict because it isn't actually correlated with the resolved
region (two unrelated facts about two unrelated locations must never
combine into one confidence score).

`reportRegionInfo.module_context`/`mz_header_detected`/`has_injected_pe`
are a tri-state triple, not a single boolean: `module_context`
(`"resolved"`/`"unregistered"`/`"unavailable"`, reusing `threadRecord`'s
own vocabulary) is never null once a region is resolved at all;
`mz_header_detected` is `null` when the region's own content read either
fails outright or returns fewer than 2 bytes — either way there isn't
enough data to confirm OR rule out an `"MZ"` signature, so it must not
collapse to `false` the way a bare `data[:2] == b"MZ"` comparison would
(a 1-byte read's own `b"M"[:2]` is unequal to `b"MZ"`, but that is
"unknown", not "confirmed absent"). `mz_header_detected` is derived from
the SAME read Section 4 performs for its own string scan, not a second,
independent small peek read — reusing one read for both closes a gap
where a header-only read failing on its own while a larger read of the
identical starting address succeeded right after would otherwise leave
`mz_header_detected` stuck at `null` even though the bytes needed were
available; a failure (or short read) of that one shared read now means
`mz_header_detected` is `null` AND `string_scan.truncated`/
`string_scan_error` reflect the same gap, both correctly tied to the SAME
read rather than two independently-tracked facts that could disagree.
`has_injected_pe` is `null` whenever the
evidence needed to decide either way is itself missing (an unread header,
or an MZ header found but `module_context` is `"unavailable"` — found
something suspicious-shaped but can't confirm it's actually unregistered).
`findings` may only ever contain `"injected_pe"` when `has_injected_pe`
is `true` — never on a `null` (unconfirmed) or `false` value; this closes
a false-positive the tri-state model replaced, where a missing
`ModuleListStream` (so no module could be confirmed either way) was
previously indistinguishable from a *confirmed* unregistered region, and
silently produced the same `"injected_pe"` finding either way.
`ioc_strings[]` entries (`reportIocString`) additionally carry a bounded
(≤256 byte) `context_hex`/`context_base_address`/`context_hit_offset`
hexdump-context window, populated only when `is_network_pattern` is
`true` and computed once at collect time — the console renderer decodes
this window rather than ever re-reading the dump to reproduce it, so
console output stays fully determined by the JSON `CommandResult` even
across a second, later read failure.

Not-found and non-correlation facts a query can hit against otherwise
fully-read evidence (an unknown TID, no region at the target address, the
needle not found anywhere, the exclusion above, `--report-tid` given
alongside `--report-string` and therefore not carried into the per-region
triage) become `diagnostics.warnings[]` entries with `REPORT_*`-prefixed
codes — not `LimitationCode`s, since they are facts about *this query*
against evidence that was itself fully evaluated, not gaps in the
evidence itself. Genuine evidence gaps DO reach `result.coverage`,
though: the three admin sources every card's own thread/region
resolution depends on (`thread_info`/`modules`/`memory_info`,
`REPORT_MODULE_CONTEXT_UNAVAILABLE` when `modules` itself is absent — a
dedicated code, not `threadRecord`'s own thread-specific
`MODULE_CLASSIFICATION_UNAVAILABLE`, since its fixed wording is
thread-specific and would misdescribe a region-only card with no thread
evidence); a card's own target-region content read coming up short or
failing outright (`REGION_READ_TRUNCATED`/`SOURCE_FAILED`, aggregated
across however many cards under one synthetic `"requested_region"`
source rather than one entry per card, since every card reads the same
underlying dump — a card's optional `--output` extract coming up short
folds into this SAME aggregate fact too, via `extract_read_truncated`
below, since it's the identical underlying gap whether observed via
Section 4's scan or the extract step); and, string-search mode only, two
distinct facts about the memory-wide search itself, source
`"string_search"` for both: regions it could not read AT ALL
(`REPORT_STRING_SCAN_INCOMPLETE`) and regions it read but only
PARTIALLY (`REPORT_STRING_SCAN_TRUNCATED`, `bytes_read < requested`) —
kept as two separate codes rather than one, since "skipped" and
"partially read" are different facts with different wording, and a
needle sitting past a partial read is exactly as much a false negative
as one in a fully-skipped region. All of the above combine across
however many cards a `--report-string` run produced via
`dumpex.output.coverage.combine_coverage_reports()`, the same reducer
`--diff-scope all` uses to merge its own three entities' coverage into
one.

`execution_status` is `"partial"` (independent of `coverage.status`)
when `MAX_REGION_READ` clamped a card's own scan below the region's real
size, the memory-wide `--report-string` search itself had to clamp any
region bigger than that same cap, or a per-card `--output` extract
itself failed to write — a self-imposed scan-budget policy or a write
failure, neither of which is an evidence-completeness gap. A search-wide
clamp is deliberately NOT a coverage fact (unlike the two
`REPORT_STRING_SCAN_*` codes above): asking for less than a region's own
size is this command's own policy choice, not evidence going missing —
the two stay separate exactly the way `string_scan.clamped` (policy) and
`string_scan.truncated` (evidence gap) already do for a single card's own
scan.

`result.summary` carries call-level context no single card's own fields
capture: `mode` (`"tid"` / `"addr"` / `"tid_addr"` / `"string"`),
`card_count`, the raw `query_tid`/`query_addr`/`query_string` CLI strings
as given (`null` for whichever anchor wasn't used), and — string-search
mode only — `total_hits`/`hits_private`/`hits_image`/`image_hit_modules`/
`skipped_unreadable_regions`/`truncated_regions`/`clamped_regions` (the
three region counters mirror `dumpex.core.memory.StringSearchStats`
one-for-one; `skipped_unreadable_regions`/`truncated_regions` also drive
the two `REPORT_STRING_SCAN_*` coverage limitations above when nonzero,
`clamped_regions` drives `execution_status` instead, per the split above
— none of the three is purely informational).

`--report`'s optional `--output` extract (available in every trigger
mode) populates `artifacts[]` exactly like `--extract` does, under a
different `kind` string (`"report_extracted_region"` vs. `--extract`'s
own `"extracted_region"`) so `artifacts[].kind` still distinguishes the
two producers. A `--report-string` run with multiple hit regions
and `--output` given disambiguates each card's own extract path (e.g.
`out_0x7ffe1000.bin`, `out_0x7ffe2000.bin`) rather than letting later
writes silently clobber earlier ones.

### Hunt records

`schema_version 2.4` adds a `"hunt"` value to `result.kind` and its own
record type, `hunterRecord` (one entry per hunter — `injection`/
`hollowing`/`stomping`/`pipe`/`cs-beacon`/`yara`/`obfuscation` — not one
per raw hunter hit; see
[`dumpex/output/records.py`](../dumpex/output/records.py)'s
`HunterRecord` and its seven `*Details` types for the exact field lists,
and [`docs/hunt_migration_field_matrix.md`](hunt_migration_field_matrix.md)
for the full per-hunter field-by-field migration rationale). `"hunt"`
gets its own new `schema_version` for the same reason `"report"` did:
`dumpex-output-v2.3.schema.json` was already shipped/used by `--report`
output before `"hunt"` existed, so it stays byte-frozen.

`--hunt` now emits this contract: it is routed through the v2 envelope
like the other ten commands, `result.kind` is `"hunt"`, and the process
exit code is coverage-based (`0`/`3`/`4`) instead of always `0`. The CLI
wiring lives in `dumpex/cli.py` (`--hunt` is included in
`_V2_STRUCTURED_MODES`) and `dumpex/hunt/__init__.py`'s `cmd_hunt()`,
which takes a `collect_records=True` flag to return `(results, records)`
for the CLI's v2 path; `cmd_hunt()` still returns its original bare dict
when `collect_records` is left at its default, so other, non-CLI callers
of the v1.1-era dict shape are unaffected. Console output (the per-hunter
detail and the `--hunt all` summary card) is unchanged — only the
`--json` output and the exit code changed.

`schema_version 2.5` extends `hunterRecord.findings[]`'s own `finding`
$def (unchanged since it was introduced in `2.4`) with seven fields that
let one finding stand alone as a normalized SIEM alert, without a
consumer having to hand-map this shape onto a generic one first — see
[`dumpex/hunt/_finding.py`](../dumpex/hunt/_finding.py)'s `Finding`
dataclass for the authoritative field semantics, and "Reading a Finding"
in [`docs/SOC_QUICKSTART.md`](SOC_QUICKSTART.md) for the analyst-facing
explanation:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Deterministic: a 128-bit (32 hex char) SHA-256 prefix of an unambiguous, sort_keys=True JSON encoding of every field that makes one finding materially different from another — `check`/`rule_id`/`rule_version`/`tag`/`confidence`/`technique_ids`(sorted)/`evidence_refs`(sorted)/`iocs`(sorted)/`facts` — never a bare delimiter-joined string (which would let two DIFFERENT fact lists collide onto the same id) and never based on facts alone (which would let a finding re-tagged from a lead to a detection, or reissued after a rules.yaml content update, silently keep the SAME id as the finding it superseded). Stable across repeated `--hunt` runs against the same dump. Content-only, NOT evidence-scoped: two different dumps producing byte-identical hashed fields get the same `id` by design. Safe as a re-scan dedup key for one dump; combine with `meta.evidence[].sha256` for a key unique across dumps/cases. |
| `severity` | `"info"` \| `"low"` \| `"medium"` \| `"high"` \| `"critical"` | Always derived from `tag` + `confidence` (Python: `init=False` on the `Finding` dataclass, so a caller cannot pass a contradictory value; wire: pinned by the `finding.allOf` block in the schema itself, so any producer must follow it too) — see `severity_for()`. |
| `technique_ids` | array of string | MITRE ATT&CK technique/sub-technique IDs, format-validated (`^T[0-9]{4}(\.[0-9]{3})?$`) and deduplicated. Empty unless the hunter that built this finding has a real mapping to attach (today: `pipe`'s own `rules.yaml`-driven framework matches) — never invented per check. |
| `evidence_refs` | array of string | Structured pointers into this hunter's own `details` object, distinct from free-text `facts`. |
| `iocs` | array of string | Indicator-of-compromise values this finding's facts embed, when a hunter has extracted one. |
| `rule_id` | string | Defaults to `check` when a hunter doesn't set one explicitly — `check` is already this codebase's own stable detection-logic identifier. |
| `rule_version` | string or null | `null` unless a real versioned rule source produced this finding. For a `rules.yaml`-driven finding (today: `pipe`'s framework matches) this is that ruleset's own *content* SHA-256 (`dumpex.rules_pkg.loader.get_rules_source_info()["sha256"]`, the same value as `meta.rules.sha256`) — never `rules.yaml`'s own top-level `version:` field, which is a FORMAT/schema version ("bump when schema changes") that stays unchanged when a pattern or MITRE mapping is edited. |

This is the first `schema_version` bump that is NOT a new `result.kind`
enum value — every prior bump (`2.1`→`"comparison"`, `2.2`→`"extract"`/
`"strings"`, `2.3`→`"report"`, `2.4`→`"hunt"`) added a root-level kind;
`2.5` instead adds required properties to an already-`additionalProperties:
false` nested object (`finding`), which the versioning policy above
already covers under "narrowing/closed-object changes always bump" — see
that section's own closed-object bullet. `dumpex-output-v2.4.schema.json`
stays byte-frozen (its own `finding` $def still rejects these seven
properties), the same precedent every earlier frozen schema file follows.

`schema_version 2.6` removes the `raw` field from `--hunt cs-beacon`'s
`csBeaconDetails.configs[*].fields[*]` — each parsed TLV field in a
recovered Cobalt Strike config now carries only `name`, `type`, and
`value`. PublicKey, Malleable C2, and inject-transform fields could embed
very long raw-hex strings under the old `raw` field, degrading JSON
and any downstream tool's display for no benefit once `value` already
carries that same field's decoded (or hex-rendered, for non-printable
`bytes` fields) content. This is a field REMOVAL, not an addition —
`configs[*]` items are schema-open (`type: object`) in both `v2.5` and
`v2.6`, so the schema file's own `$defs` did not need a structural edit,
but the actual wire shape every `--hunt cs-beacon`/`--hunt all` JSON
run produces changed incompatibly, which is what the versioning policy
above's "removal of a field a command has ever actually emitted" clause
covers. Nothing else about `csBeaconDetails` or any other hunter's
`details` shape changed. The change is confined to
[`dumpex/hunt/cs_beacon/collect.py`](../dumpex/hunt/cs_beacon/collect.py)'s
`_field_dict()` (the function that reshapes one parsed TLV field into its
public v2 dict) — CS Beacon config identification, the sanity check, DER
public-key validation, Malleable C2 instruction decoding, scoring,
status/verdict/confidence, findings, and both normal and verbose console
output are all unaffected: the parser
([`dumpex/hunt/cs_beacon/parser.py`](../dumpex/hunt/cs_beacon/parser.py))
still returns `raw` as `bytes` on its own internal field dicts, and both
DER validation (`fields[0x0007]["raw"]`) and instruction decoding still
consume it directly, before `_field_dict()` ever reshapes anything for
JSON. `dumpex-output-v2.5.schema.json` stays byte-frozen and remains
shipped/installable for validating output produced before this change,
the same precedent every earlier frozen schema file follows.

`schema_version 2.7` re-keys `--hunt cs-beacon`'s
`csBeaconDetails.configs[*].fields` by field NAME (e.g. `"BeaconType"`,
or `"field_0xNNNN"` for an unrecognized field ID) instead of the raw TLV
field ID string (`"1"`), and drops the now-redundant `name` property from
each field's own value — a consumer no longer has to already know that
field ID 1 means `BeaconType` before it can look anything up
(`fields["BeaconType"]["value"]` instead of `fields["1"]["value"]`);
each field's value now carries only `type`/`value`. Unlike the 2.6
`raw`-removal, this constraint IS expressed structurally in the schema
file itself: `csBeaconDetails.configs[*].fields` gained a `propertyNames`
pattern (`^(field_0x[0-9a-f]{4}|[A-Za-z][A-Za-z0-9_]*)$`, rejecting a
purely-numeric-string key) and a per-field `additionalProperties: false`
shape requiring exactly `type` (integer, `1`/`2`/`3`) and `value` — a
document still shaped like `v2.6` (numeric-string keys, a `name`
property) now fails validation against `v2.7`, which is deliberate:
`schema_version` 2.7 is meant to be mechanically distinguishable from
2.6 by a validator, not merely documented as different.
[`dumpex/hunt/cs_beacon/collect.py`](../dumpex/hunt/cs_beacon/collect.py)'s
`_config_dict()` additionally raises `ValueError` at collect time if two
different field IDs ever resolve to the same name (`CS_FIELD_NAMES` in
[`dumpex/hunt/cs_beacon/schema.py`](../dumpex/hunt/cs_beacon/schema.py)
has no such collision today, but a future edit that introduced one would
otherwise silently drop a field from the output rather than fail loudly)
— this guard is Python-only, not itself expressible in JSON Schema.
`configs[*]` items otherwise stay schema-open (`type: object`) — every
property besides `fields` is unconstrained, same as `v2.5`/`v2.6`. CS
Beacon config identification, the sanity check, DER public-key
validation, Malleable C2 instruction decoding, scoring, status/verdict/
confidence, and findings are all unaffected — internal field-ID keying
(`fields[0x0007]["raw"]`) is untouched, the reshape happens only at the
`_config_dict()`/`_field_dict()` public-output boundary. The console's
`--hunt cs-beacon --verbose` field table also dropped its hex field-ID
column and stopped showing a separate near-duplicate raw-hex preview
alongside `value` for binary fields, in the same change — that part is
presentation-only and carries no schema impact of its own.
`dumpex-output-v2.6.schema.json` stays byte-frozen and remains
shipped/installable for validating output produced before this change,
the same precedent every earlier frozen schema file follows.

`schema_version 2.11` adds the candidate's own location to
`huntPeHeaderHit` — every entry of `--hunt injection`'s
`hidden_pe_validated`, `hidden_pe_unvalidated`,
`suspicious_validated_pe_hits`, and `informational_validated_pe_hits`:

| Field | Type | Notes |
|---|---|---|
| `va` | hexAddress | The process address the candidate's `MZ` header was actually found at. Equals `region.base_address` for a PE at its region's base, and does not otherwise. |
| `region_offset` | integer ≥ 0 | How far into `region` that address is. `0` for a PE at the region base. |
| `file_offset` | hexAddress or null | Where those bytes sit in the `.dmp`, for carving. `null` means the VA is not covered by any captured memory segment — **not** the same claim as offset zero. |

The hidden-PE scan previously read two bytes at each region's own base
address and stopped there, so a structurally valid PE mapped at a nonzero
offset inside a private or unbacked allocation was invisible to it
([issue #26](https://github.com/bitbug0x55AA/dumpex/issues/26)). It now
searches each eligible region end to end for `MZ` candidates at every
byte offset, which means `region` alone no longer answers "where is the
PE": one region can host several candidates, and a consumer needs the
candidate's own address to carve it, correlate it, or tell two hits
apart. `region` still describes the CONTAINING region and is still what
allocation correlation (`rwx_and_pe_alloc_bases`, `rip_hits`,
`rip_full_correlation`) is keyed on.

That search reads far more of the dump than the old base-address probe,
and a dump is untrusted input, so it runs under explicit budgets (bytes
read, structural validations, retained evidence — see
[`dumpex/hunt/injection/config.py`](../dumpex/hunt/injection/config.py)).
Anything a budget cut short is reported rather than silently dropped: a
region whose search stopped early raises the `PE_HEADER_SCAN_TRUNCATED`
coverage limitation, and validated hits found but not retained raise
`PE_HEADER_EVIDENCE_CAPPED` (see "Coverage limitations and skipped scan
targets" below). `dumpex-output-v2.10.schema.json` stays byte-frozen (its
own `huntPeHeaderHit` rejects these three properties) and remains
shipped/installable for validating output produced before this change.

### Coverage limitations and skipped scan targets

`result.coverage.limitations[]` is the structured, machine-readable form
of `result.coverage.reasons[]` — one entry per specific way coverage fell
short, with its human text rendered from a hardcoded per-`code` template
rather than composed at the call site (see
[`dumpex/output/coverage.py`](../dumpex/output/coverage.py)).

`schema_version 2.8` adds a `targets` array to every limitation (and the
`scanTarget` `$def` its items follow). Before it, a hunt that skipped
oversized memory could only say *how many* things it skipped:

```json
{ "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "pipe_name_scan", "affected_count": 2 }
```

That tells an investigator the result is incomplete but not which
addresses to go after, so the gap could not be dispositioned without
re-running the hunt. `targets` names them:

```json
{
  "code": "SCAN_REGION_OVERSIZED_SKIPPED",
  "source": "pipe_name_scan",
  "scope": null,
  "affected_count": 1,
  "targets": [
    {
      "kind": "memory_region",
      "base_address": "0x00007ff000001000",
      "size": 16777216,
      "size_limit": 8388608,
      "file_offset": 4096,
      "allocation_base": "0x00007ff000000000",
      "state": "MEM_COMMIT",
      "type": "MEM_PRIVATE",
      "protection": "PAGE_EXECUTE_READWRITE"
    }
  ]
}
```

- `kind` is `"memory_region"` (a MemoryInfoListStream region — `--hunt
  pipe`, `--hunt obfuscation`, `--hunt stomping`) or `"memory_segment"` (a
  Memory64List/MemoryList segment — `--hunt cs-beacon`, `--hunt yara`).
  A segment carries no MemoryInfo, so `allocation_base`/`state`/`type`/
  `protection` are always `null` for one.
- Addresses use the same fixed-width hex convention as every other
  address in this contract (`hexAddress`). `file_offset` is a byte offset
  inside the `.dmp`, not an address, and stays a plain integer; it is
  `null` when those bytes were never captured — which is itself the
  answer to "can I extract this from the dump I already have, or do I
  need to recollect?".
- `size_limit` is the configured cap that caused the skip, recorded per
  target rather than once per limitation.
- `affected_count` equals `targets`' length exactly, so the count and the
  identified targets can never disagree. Every other limitation code
  emits `targets: []`; a consumer that ignores the key sees the v2.7
  shape unchanged.

Console output shows a bounded preview (the first few targets, then
`+N more (see coverage.limitations[].targets in --json output)`); the
JSON list is never truncated.

`scope`, on this code, names the **scan layer** whose own cap did the
skipping. `--hunt obfuscation` runs three region scans with three
different caps (sleep-mask 10 MB, entropy 10 MB, decode 2 MB) over
overlapping candidate sets, and previously summed their three counters
into one `N oversized region(s) skipped`. A single 12 MB private region
exceeds all three caps, so that sum reported **three regions** where
there was one — sending an analyst looking for two allocations that never
existed. It now emits one limitation per layer:

```json
[
  { "code": "SCAN_REGION_OVERSIZED_SKIPPED", "scope": "sleep_mask", "affected_count": 1, "targets": [ ... ] },
  { "code": "SCAN_REGION_OVERSIZED_SKIPPED", "scope": "entropy",    "affected_count": 1, "targets": [ ... ] },
  { "code": "SCAN_REGION_OVERSIZED_SKIPPED", "scope": "decode",     "affected_count": 1, "targets": [ ... ] }
]
```

Three region × layer skips over one physical region, each naming its own
threshold — which also answers the question the sum destroyed: whether a
region was missed by every layer or only by the strictest one. Deduplicate
on `targets[*].base_address` to count distinct physical regions.

`source` names the scan the gap belongs to, and one hunter can have more
than one: `--hunt stomping` reports `section_content_diff` gaps (its
scored, `--ref-dir` content comparison) and `ioc_string_scan` gaps (its
unscored IOC-string region scan, capped at 5 MB per executable
`MEM_IMAGE` region) separately. An `ioc_string_scan` limitation means
part of the executable module memory was never examined for IOC strings —
so that check reports `INCOMPLETE` rather than `CLEAN`, `coverage.status`
is `"partial"`, and a score-0 run is `INCONCLUSIVE` rather than
`NOT_DETECTED_IN_SCANNED_SCOPE`. It never changes `score`, and a real
detection stays `DETECTED` with `coverage.status: "partial"`.

`dumpex-output-v2.7.schema.json` stays byte-frozen and remains
shipped/installable for validating output produced before this change.

### Hunt investigation actions

`schema_version 2.9` adds `investigation_actions` to `huntSummary`
(`result.summary` when `kind == "hunt"`) — `--hunt all`'s automatically
built, deduplicated, priority-ordered skipped-target investigation queue.
`schema_version 2.10` (issue #19 Phase 2) then adds `content_reason_codes`
to each entry's own `triage` sub-object — the opt-in `--triage-skipped`
budgeted deep-content triage pass's structured record of what it actually
found; see the `triage` bullet below.
It is derived entirely from data every hunter already collected (each
`SCAN_REGION_OVERSIZED_SKIPPED` limitation's own `targets`, see "Coverage
limitations and skipped scan targets" above, plus the cross-hunter region
correlation `--hunt all`'s console `CORRELATED REGIONS` section already
computes) — building it reads **no additional bytes from the dump**.
Always present and populated only for `selected == "all"`; a
single-hunter run (`--hunt pipe`, ...) always has `investigation_actions:
[]`.

One physical region/segment can be skipped by several different hunters,
or by several scan layers of the same hunter (obfuscation's own
sleep_mask/entropy/decode — see above), each contributing its own
`CoverageLimitation`/`targets` entry. Previously there was no single
place that merged these into one actionable item; `investigation_actions`
deduplicates on the physical target's own `(kind, base_address, size)`:

```json
{
  "investigation_actions": [
    {
      "target": {
        "kind": "memory_region", "base_address": "0x00007ff000001000",
        "size": 16777216, "size_limit": 8388608, "file_offset": 4096,
        "allocation_base": "0x00007ff000000000", "state": "MEM_COMMIT",
        "type": "MEM_PRIVATE", "protection": "PAGE_EXECUTE_READWRITE"
      },
      "skipped_by": [
        { "hunter": "pipe", "source": "pipe_name_scan", "scope": null, "size_limit": 8388608 },
        { "hunter": "obfuscation", "source": "encoding_scan", "scope": "entropy", "size_limit": 10485760 }
      ],
      "priority": "high",
      "priority_reason_codes": ["PRIVATE_EXECUTABLE_MEMORY", "RWX_PROTECTION", "MULTIPLE_SCOPES_SKIPPED"],
      "evidence_availability": "captured",
      "triage": { "mode": "metadata", "status": "completed", "bytes_examined": 0,
                  "region_fully_examined": false, "content_reason_codes": [], "findings": [],
                  "finding_count": 0, "findings_truncated": false },
      "recommended_actions": [
        { "type": "inspect_metadata" },
        { "type": "extract_captured_range" },
        { "type": "targeted_hunter_rescan", "hunters": ["pipe", "obfuscation"] },
        { "type": "preserve_artifact" }
      ],
      "coverage_effect": "original_hunter_gap_not_resolved"
    }
  ]
}
```

With `--triage-skipped` (schema_version 2.10 or later), the same entry's
`triage` reflects a real, budgeted content read instead:

```jsonc
"triage": {
  "mode": "deep", "status": "clamped", "bytes_examined": 4194304,
  "region_fully_examined": false,
  "content_reason_codes": ["IOC_PATTERN_STRING_MATCH", "NETWORK_PATTERN_STRING_MATCH"],
  "findings": [
    { "type": "ioc_string", "address": "0x00007ff000001230", "offset": 560,
      "encoding": "ASCII", "value": "http://evil.example/beacon",
      "is_network_pattern": true, "module_context": null }
    /* ... up to 20 total ... */
  ],
  "finding_count": 37, "findings_truncated": true
},
"recommended_actions": [
  { "type": "inspect_metadata" },
  { "type": "extract_captured_range" },
  { "type": "targeted_hunter_rescan", "hunters": ["pipe", "obfuscation"] },
  { "type": "preserve_artifact" },
  { "type": "chunked_analysis" }
]
```

- `target` is the same `scanTarget` `$def` `coverageLimitation.targets[]`
  items already use (one representative instance out of the deduplicated
  group). `skipped_by` lists every distinct `(hunter, source, scope)`
  that skipped this exact physical target, each with that relationship's
  own `size_limit` (the same target can legitimately exceed different
  caps under different hunters/scopes).
- `priority` (`"low"`/`"medium"`/`"high"`) and `priority_reason_codes`
  are two deterministic, centrally-derived facts, never a single
  combined score: `PRIVATE_EXECUTABLE_MEMORY`/`RWX_PROTECTION` come
  straight from the target's own MemoryInfo facts; `MULTIPLE_SCOPES_
  SKIPPED` (more than one `skipped_by` entry) and `CORRELATED_REGION_
  EVIDENCE` (this target's region coincides with an existing multi-hunter
  `CORRELATED REGIONS` entry) are cross-hunter correlation facts. Neither
  reason present → `"low"`; exactly one → `"medium"`; both → `"high"`.
- `evidence_availability` (`"captured"`/`"not_captured"`) is a
  **separate** axis from `priority`, derived only from `target.
  file_offset`: whether the bytes are already in this dump file. A
  `not_captured` target is not thereby more suspicious — it means
  extraction won't work and recollection is the next step, never that the
  target is more malicious (an explicit design goal: this queue must
  never conflate "we don't have the bytes" with "this looks worse").
- `triage` records what analysis actually produced this entry.
  **Without `--triage-skipped`**, `--hunt all` always emits `{"mode":
  "metadata", "status": "completed", "bytes_examined": 0,
  "region_fully_examined": false, "content_reason_codes": [], "findings":
  [], "finding_count": 0, "findings_truncated": false}` — the
  schema-enforced witness that the default pass performs no region-content
  read whose cost scales with a skipped target's size.
  **With `--triage-skipped`** (issue #19 Phase 2, see
  `dumpex.hunt._deep_triage.run_deep_triage()`), `mode` is `"deep"` and
  `status` reflects the real outcome of a budgeted content read reusing
  `--report`'s own low-level content-scan primitive
  (`dumpex.commands.report._scan_content_range()`), reading from the
  target's own recorded address regardless of its `kind` (correctly
  handling a `memory_segment` target with no MemoryInfoListStream entry,
  and a `memory_region` target that only covers part of a larger
  MemoryInfo region): `"completed"` (the whole target was examined —
  `region_fully_examined: true`, `bytes_examined >= 1`), `"partial"` (the
  dump had fewer bytes than requested — a real evidence gap,
  checked BEFORE the clamp check below so a genuine short read is never
  misreported as a mere budget choice), `"clamped"` (deep triage's own
  per-target/whole-run/target-count budget intentionally capped the read
  before reaching the whole target, and the dump had at least that much),
  `"unreadable"` (the read itself failed), or `"not_captured"` (same
  meaning as the metadata pass — the bytes were never captured, so
  nothing was attempted). `bytes_examined` is real for a deep-triage
  entry (`>= 1` for completed/partial/clamped, always `0` otherwise), and
  `region_fully_examined` is `true` if and only if `status ==
  "completed"`.

  `content_reason_codes` is a closed, structured SUMMARY of what the deep
  read itself found in the examined bytes — `IOC_PATTERN_STRING_MATCH`,
  `NETWORK_PATTERN_STRING_MATCH`, `MZ_HEADER_DETECTED` (an MZ header at
  the read's own start), and/or `INJECTED_PE_HEADER` (that MZ header
  CONFIRMED to sit in unregistered memory — a strictly stronger fact than
  `MZ_HEADER_DETECTED`; when module classification itself is unavailable,
  e.g. no `ModuleListStream`, only the weaker `MZ_HEADER_DETECTED` is
  reachable, and it is never silently dropped just because confirmation
  wasn't possible) — always `[]` for the metadata pass, and always `[]`
  for any deep-triage outcome that never completed a read
  (`not_captured`/`budget_deferred`/`unreadable`); `findings`/
  `finding_count`/`findings_truncated` are `[]`/`0`/`false` in exactly
  those same cases.

  `findings` is the bounded, structured EVIDENCE behind that summary — at
  most 20 entries (`ioc_string` or `mz_header`, see the `contentFinding`
  $def), sharing the exact same "only populated for a real-read status"
  rule as `content_reason_codes`. An `ioc_string` finding carries
  `offset`/`encoding`/`value` (truncated to 256 characters — a bounded
  lead, not the full match) /`is_network_pattern`; an `mz_header` finding
  carries only `module_context`. An analyst who needs the complete string
  text, hexdump context, or an extractable artifact still runs `--report
  --report-addr <target.base_address>` directly — `findings` is a lead,
  never a substitute for that.

  When more than 20 findings exist, the array is filled
  REPRESENTATIVE-FIRST rather than by a bare offset-order cutoff: an
  `mz_header` finding (if any) always appears first, then one
  network-pattern `ioc_string` finding (if any), then one plain
  `ioc_string` finding (if any), and only then the remaining `ioc_string`
  findings in offset order up to the cap — so a reason code in
  `content_reason_codes` is never left with zero backing evidence purely
  because 20+ plain IOC hits filled every slot first. `finding_count` is
  the TOTAL number of findings the read actually produced, before that
  cap; `findings_truncated` is `true` exactly when `finding_count` exceeds
  `findings.length`, so a consumer can tell "3 findings, all shown" apart
  from "47 findings, a bounded sample of 20 shown."

  **A deep-triage result is never a verdict**: a `"completed"` read with
  `[]` `content_reason_codes`/`findings` means "no generic indicators in
  examined bytes," never "clean" — the generic content scan cannot
  substitute for the specific hunter logic that originally skipped the
  target, and `coverage_effect` (below) stays unresolved regardless of
  what the deep read found.
- `recommended_actions` are structured action objects (`type`, plus
  `hunters` on `targeted_hunter_rescan` only) — never free prose or a raw
  shell command string — from a closed vocabulary: `inspect_metadata`,
  `extract_captured_range` (only when `evidence_availability ==
  "captured"`), `targeted_hunter_rescan` (always; `hunters` is every
  hunter in `skipped_by`, `HUNTERS`' own fixed order), `recollect_dump`
  (only when `evidence_availability == "not_captured"`), `preserve_artifact`
  (only when `priority == "high"` AND `evidence_availability ==
  "captured"` — there is nothing local to preserve for bytes that were
  never captured in this dump; the schema itself rejects a
  `preserve_artifact` entry on any `investigation_actions[]` item whose
  `evidence_availability` is `"not_captured"`), and `chunked_analysis`
  (only ever emitted by a `--triage-skipped` run, appended whenever that
  entry's own deep-triage `status` is `"partial"`/`"clamped"`/
  `"budget_deferred"`/`"unreadable"` — i.e. the target could not be fully
  examined within budget).
- `coverage_effect` is always `"original_hunter_gap_not_resolved"` in
  this schema version: this queue is advisory only. It never changes any
  hunter's own `score`/`verdict_level`/`coverage.status`, the document-
  level `result.coverage.status`, or the process exit code — only a real,
  successful rerun of the specific hunter/scope that skipped a target
  (not automated by this change) could ever resolve that hunter's own
  coverage gap.

The console mirrors this as a `SKIPPED TARGET ACTIONS` section in
`--hunt all`'s `HUNT SUMMARY` card (priority-ordered, bounded with an
omission notice pointing at `--json` for the rest — the same convention
`CORRELATED REGIONS` and the oversized-`targets` preview above both use).
With `--triage-skipped`, each entry also gets a `Deep triage: ...` line
(status, bytes examined, and either the translated `content_reason_codes`
or the literal wording "No generic indicators in examined bytes" — never
"clean"), and a bounded `DEEP TRIAGE NOTES` block follows the section
with the same budget-exhausted/read-failed/summary messages that also
appear in `diagnostics.warnings[]`. When `content_reason_codes` is
non-empty, the entry also renders a bounded preview straight from
`triage.findings` itself (the actual IOC `value`/`address`/`encoding`, or
an `mz_header` finding's own `module_context`) — up to 3 entries by
default, every retained entry (still at most 20) with `--verbose`; a
`Showing 20 of 47 deep-triage findings.` line appears whenever
`triage.findings_truncated` is `true`, regardless of `--verbose`, since
that reflects a data-level cap (`MAX_FINDINGS_PER_TARGET`), not a
console-only one. `MZ_HEADER_DETECTED` and `INJECTED_PE_HEADER` each
render under their own distinct label — the console never prints a raw
enum name for either. `--verbose` only changes how much of each
already-computed entry's own `skipped_by`/reason/action/findings lists —
and how many entries — the console shows; it never changes
`investigation_actions` itself, its order, or any other structured
field, preserving the existing rule that console verbosity can never
change structured output (see "CORRELATED REGIONS" in
[SOC_QUICKSTART.md](SOC_QUICKSTART.md#correlated-regions-console-and-txt-output-only)
for the precedent this follows).

`dumpex-output-v2.8.schema.json` and `dumpex-output-v2.9.schema.json`
stay byte-frozen and remain shipped/installable for validating output
produced before, respectively, the `investigation_actions` and
`content_reason_codes` additions.

## Reproducing a run

Retain the following together:

1. the JSON result;
2. the source dump identified by `meta.evidence[0].sha256`;
3. any explicit rules or reference modules;
4. the dumpex version and runtime versions in `meta`; and
5. the exact options recorded under `meta.execution.options`.

For reports shared outside the investigation environment, use
`--redact-paths` but preserve hashes and basenames. Redaction protects local
directory layout — including `--extract`'s/`--report`'s own `artifacts[].path`
— it does not anonymize evidence content, strings, module names, host data,
or findings.
