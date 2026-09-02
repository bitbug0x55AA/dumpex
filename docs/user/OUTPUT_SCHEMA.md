# Output and Evidence Schema

This document describes the JSON contract dumpex currently produces. JSON is
the canonical case-record and automation format because it carries analysis
data together with evidence identity, execution context, coverage, diagnostics,
artifacts, and rule provenance.

For historical schema files and upgrade notes, see
[Output Schema Migration](OUTPUT_MIGRATION.md). For analyst disposition, use
the [SOC / DFIR Quick Start](SOC_QUICKSTART.md).

## Formats

| Format | Option | Intended use |
|---|---|---|
| JSON | `--json FILE` | Automation, case records, validation, and reproducibility |
| Plain text | `--txt FILE` | Human-readable, ANSI-free console transcript |

`--txt` has no schema or compatibility promise. Never scrape it for automation.
Output files are protected unless `--force` is supplied, and an output path may
never replace an input dump.

## Current contract

All twelve commands emit the same v2.14 envelope. The authoritative schema is
[`dumpex-output-v2.14.schema.json`](../../dumpex/schemas/dumpex-output-v2.14.schema.json).
The schema uses JSON Schema Draft 2020-12 and closes record objects with
`additionalProperties: false` where their field sets are fixed.

| Commands | Contract | Schema file |
|---|---|---|
| `--list`, `--modules`, `--threads`, `--process`, `--sysinfo`, `--handles`, `--profile`, `--diff`, `--extract`, `--strings`, `--report`, `--hunt` | v2.14 (current) | [`dumpex-output-v2.14.schema.json`](../../dumpex/schemas/dumpex-output-v2.14.schema.json) |

Use the document's own `meta.schema_version` to select a validator. Do not
validate archived output against whichever schema happens to be current today.

## Document envelope

Every produced document follows this shape:

```jsonc
{
  "meta": {
    "schema_version": "2.14",
    "tool": { "name": "dumpex", "version": "<installed version>" },
    "execution": { "...": "command, options, timestamps, case metadata" },
    "evidence": [ { "...": "input identity and SHA-256" } ],
    "runtime": { "...": "dependency versions" }
  },
  "result": {
    "kind": "modules",
    "execution_status": "completed",
    "coverage": { "status": "complete", "reasons": [], "sources": {}, "limitations": [] },
    "summary": { "...": "kind-specific counts or rollup" },
    "data": { "records": [] }
  },
  "artifacts": [],
  "diagnostics": { "warnings": [], "errors": [] }
}
```

The envelope deliberately separates four concepts:

- `meta`: what ran, against which evidence, with which rules and runtime.
- `result`: the command result and its evidence coverage.
- `artifacts`: files dumpex produced, distinct from input evidence.
- `diagnostics`: warnings and errors that should not be inferred from prose.

## Metadata fields

### `meta.schema_version`

Selects the exact schema contract. The current producer value is `"2.14"`.

### `meta.tool`

Contains the tool name and installed dumpex version.

### `meta.execution`

Records UTC start/finish timestamps, duration, normalized command name, relevant
options, and optional `case_id`/`analyst` values. Path-typed options reflect
`--redact-paths` when requested.

### `meta.evidence`

Always an array:

- single-dump commands emit one `role: "primary"` entry;
- `--diff` emits `role: "target"` and `role: "baseline"` entries.

Each entry identifies the evidence with its role, filename/path, size, and
content SHA-256. The hash is the stable evidence identity; a path is not.

### `meta.runtime`

Records Python and relevant dependency versions so behavior can be reproduced.

### `meta.rules` and `meta.yara_rules`

Record the rules source, content hash, and override provenance when the command
uses TTP or YARA rules. Absence means that rule source was not used during the
run; it does not mean a default path should be guessed later.

## Result semantics

### `result.execution_status`

Values are `completed`, `partial`, or `failed`. This answers whether the
command itself completed its intended work. It is not a verdict and is not the
same as evidence coverage.

### `result.coverage`

`coverage.status` answers whether required evidence was available and fully
examined:

| Status | Meaning |
|---|---|
| `complete` | Required evidence for the selected operation was examined |
| `partial` | Some useful evidence was examined, but one or more gaps remain |
| `not_evaluated` | The operation could not evaluate its required evidence |

The supporting fields are:

- `reasons`: ordered human-readable explanations.
- `sources`: source name to `{state, record_count, detail}` observations.
- `limitations`: structured, machine-readable gaps.

Source states are `absent`, `present_empty`, `present`, or `failed`.
`present_empty` is positive evidence that a captured source contained zero
records; it is not interchangeable with `absent`.

Exit codes mirror document-level coverage for the current commands: `0` for
`complete`, `3` for `partial`, and `4` for `not_evaluated`. Exit code does not
encode whether a hunter detected something.

### `result.summary`

Contains command-specific counts and rollups. Consumers should not infer fields
shared by every kind: the schema's `if`/`then` dispatch defines the exact shape
for each `result.kind`.

### `result.data.records`

Always an array, including commands that produce one logical record. Missing
values are JSON `null`, never empty strings. Addresses, pointers, and handles
use normalized lowercase `0x` strings; ordinary counts, IDs, sizes, and
durations use JSON integers.

## v2 structured output

| Command | `result.kind` | Record purpose |
|---|---|---|
| `--list` | `memory_regions` | Captured memory-region descriptors |
| `--modules` | `modules` | Loaded module records |
| `--threads` | `threads` | Thread identity, context, and region/module correlation |
| `--sysinfo` | `sysinfo` | Dump, OS, host, CPU, and environment identity |
| `--process` | `process` | Consolidated process identity, IAT, and verification evidence |
| `--handles` | `handles` | Captured handle descriptors and raw granted-access masks |
| `--profile` | `profile` | Stream inventory, capture facts, and capability map |
| `--diff` | `comparison` | Baseline-to-target module/thread/memory changes |
| `--extract` | `extract` | Extracted-range metadata and artifact reference |
| `--strings` | `strings` | Strings found in a requested captured range |
| `--report` | `report` | Triage cards anchored to a TID, address, or string hit |
| `--hunt` | `hunt` | One hunter record per selected analyzer |

The schema file is the field-level reference for each record type. The sections
below document the semantic boundaries most likely to affect consumers.

### Comparison records

`--diff` is the only two-input command. The positional dump is the target and
the `--diff` argument is the baseline. Its records describe module, thread, and
memory changes in the target relative to the baseline.

Coverage sources are side-qualified where necessary, such as
`baseline.modules` and `target.modules`. A failed source on one side is reported
as a gap; it is not silently converted into an empty list of records.

### Extract and strings records

`--extract` and `--strings` describe the requested address/range, resolved
region, bytes requested/read, and completion. A short read produces partial
coverage even when a useful prefix was recovered.

`--extract` also emits a top-level artifact for the written file. `--strings`
records the matched strings and encoding metadata but does not create a binary
artifact unless a different command explicitly writes one.

### Report records

`--report` emits one `triageCardRecord` for a TID/address anchor or one card per
actionable private-memory hit in string mode. Each card keeps its anchor,
thread, region, module backing, content indicators, evidence dimensions,
verdict, coverage, and optional extraction artifact together.

The command-level fields remain independent:

- `execution_status` reports whether report collection/output completed;
- `coverage.status` reports evidence completeness;
- each card's `verdict` reports its own evidence interpretation.

A string not found during an incomplete search is not a clean conclusion.
Unreadable, truncated, or clamped search regions remain coverage limitations.

### Hunt records

`--hunt all` produces seven `hunterRecord` entries in fixed order:
`injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, and
`obfuscation`. A focused hunt produces one matching record.

Shared hunter fields include:

| Field | Meaning |
|---|---|
| `hunter` | Analyzer identity |
| `score` / `max_score` | Hunter-specific evidence score and ceiling |
| `status` | `DETECTED`, `NOT_DETECTED_IN_SCANNED_SCOPE`, `INCONCLUSIVE`, or `NOT_EVALUATED` |
| `verdict_level` | Hunter-level interpretation |
| `confidence` | Strongest detection confidence; `null` for YARA |
| `lead_count` / `review_priority` | Review support fields; `null` for YARA |
| `coverage` | Coverage for this hunter |
| `findings` | Structured findings; YARA uses its own match model |
| `details` | Hunter-specific typed evidence |

A structured finding carries direct facts, inference, rationale, limitations,
confidence, evidence tag, deterministic ID, derived severity, ATT&CK mappings,
evidence references, IOCs, and rule provenance. Consumers must treat
`observation`, `lead`, and `detection` as distinct evidence roles.

YARA is intentionally different: its matches and rules hit live in
`details.matches`/`details.rules_hit`, and the shared finding/confidence fields
are null or empty according to the schema.

### Hunt scan scope and targeted rescans (v2.14)

`result.summary.scan_scope` names what a hunt invocation covered. It is a
closed tagged shape present in both modes:

```json
{"kind": "full"}
```

```json
{
  "kind": "targeted",
  "hunter": "obfuscation",
  "source": "encoding_scan",
  "scopes": ["decode", "entropy", "sleep_mask"],
  "base_address": "0x0000000010000000",
  "size": 1048576
}
```

A targeted invocation (`--hunt <hunter> --hunt-addr ADDR --size SIZE`) always
names exactly one analyzer, produces exactly one hunter record, and keeps
`investigation_actions` empty.

`scopes` is the sorted set of scopes the invocation's own coverage closures
were attributed under, so it always agrees with that result's
`details.targeted_scope`. It is not the analyzer's granted scope set: `pipe`'s
grant is unscoped, yet one pipe rescan closes `pipe_name` and `c2_context`
independently and `scopes` names both.

That record's `details` additionally carries `targeted_scope`, one entry per
coverage closure in the analyzer's own fixed closure order — one for
`stomping`, `yara`, and `cs-beacon`, two for `pipe` (`pipe_name` and
`c2_context`), and three for `obfuscation` (`sleep_mask`, `entropy`, `decode`):

```json
{
  "source": "encoding_scan",
  "scope": "entropy",
  "base_address": "0x0000000010000000",
  "size": 1048576,
  "captured_size": 524288,
  "capture_state": "partial",
  "coverage_status": "partial",
  "applicability_reason": null,
  "measurements": [
    {"name": "whole_range_entropy", "value": 0.45, "unit": "bits_per_byte",
     "base_address": null, "size": null},
    {"name": "entropy_top_window", "value": 8.0, "unit": "bits_per_byte",
     "base_address": "0x0000000010140000", "size": 65536}
  ]
}
```

`base_address` and `size` are always the range you requested, never the
containing region or the captured prefix, so a closure's identity is
`(hunter, source, scope, base_address, size)` whatever the capture outcome was.
Capture and evaluation are separate facts: `captured_size`/`capture_state`
describe byte availability in the dump, `coverage_status` describes how far
that source's algorithm got. A complete capture can still evaluate partially
(a retained budget), and a partial capture can be `not_evaluated` when the
bytes never reached the algorithm's minimum input — in which case
`captured_size` still reports the real captured prefix, which is what a
re-collection or a chunked rescan is sized from. `captured_size` is `null`
only when availability was genuinely never measured.

`coverage_status` has a fourth value that is **not** a coverage failure.
`not_applicable` means the source does not apply to the range you asked for:
the sleep-mask layer examines read-write private memory, so it says nothing
about an executable range, and nothing there was missed.
`applicability_reason` names what declined it — `region_not_committed`,
`region_type_ineligible`, `region_protection_ineligible`,
`region_module_backed`, `region_system_module`, or
`range_below_source_minimum` — and is `null` for every other status.

The last of those is about the range you asked for, not about the dump: a
request shorter than the algorithm can be applied to would produce no result
however completely it were captured, so a larger `--size` is what changes it. A
request that IS long enough but that the dump only partly backs is the other
case entirely — `not_evaluated`, with `captured_size` reporting the prefix a
re-collection has to beat.

That distinction reaches the record. `coverage.status` reduces over the
closures that apply, so one inapplicable layer does not turn the layers that
did apply into a partial result; a rescan whose closures all decline the target
evaluated no bytes and reports `not_evaluated`. Do not count `not_applicable`
as a gap.

`measurements` is what the closure retained about the work it did, kept whether
or not it found anything — a negative that records nothing is indistinguishable
from a scan that never ran. Each entry is `{name, value, unit, base_address,
size}`. `unit` is one of `bytes`, `count`, `bits_per_byte`, `seconds`, `text`,
or `flag`, and `value`'s type follows from it; `value` is `null` only when the
quantity was not measured, never as a stand-in for zero. `base_address` and
`size` locate a measurement inside the requested range when it has a location,
such as an entropy window. A name may repeat: a bounded top-N list is N entries
sharing one name, in the order the closure ranked them, so its first entry is
that ranking's maximum.

Measurements are observations. They never create a finding, change a score, or
say anything about a source other than the closure carrying them — including
the structural context entries (`containing_region`, `containing_module`,
`capture_file_offset`, and their siblings), which say where the requested range
sits, not that any hunter evaluated the module or allocation named.

For a targeted `obfuscation` rescan the entropy layer measures the range in
bounded windows as well as end to end, because one Shannon value over a sparse
oversized allocation is an average its zero-filled majority dominates: a
bounded encrypted payload inside it reads as low-entropy. `whole_range_entropy`
is that average, `entropy_top_window` entries carry the highest-entropy
sub-ranges with their addresses, `entropy_windows_above_threshold` counts how
many crossed the threshold, and `entropy_window_coverage` is `exhaustive` or
`sampled`. A `sampled` pass leaves the closure `partial`, since a window
between two measured ones could hold something nobody looked at.

A full-scope result omits `targeted_scope` entirely rather than emitting
`null`, so existing full-scope consumers see no change.

A targeted record's `coverage.sources` carries `targeted_scan` plus the
analyzer's whole published source vocabulary — the same roster a full-scope
record has — so scope is never inferred from a missing key. The granted source
the closures ran for is `present`; every source outside that grant is `absent`
and carries its own `TARGETED_SOURCE_NOT_EVALUATED` sourced to that source
name.

That matters most on a clean result. A completed targeted `stomping` rescan
reports `coverage.status: "complete"` and exit `0`, because the requested range
was fully evaluated for `ioc_string_scan` — but `module_headers`,
`reference_files`, `section_content_diff`, `modules`, and `memory_info` are all
listed absent with a limitation each, so `hunter: "stomping"` plus
`coverage.status: "complete"` cannot be read as "stomping is completely
covered". A targeted record is therefore the one place `coverage.status` can be
`complete` while `limitations` is non-empty: those entries are not gaps in the
scan, they are the boundary of what the result is about.

`TARGETED_SOURCE_NOT_EVALUATED` sourced to `targeted_scan` (optionally scoped
to a closure) is the other shape: a granted closure that would have applied and
did not run. The prerequisite limitations explaining it stay alongside it.

`TARGETED_SOURCE_NOT_APPLICABLE`, also sourced to `targeted_scan`, is the
closure whose eligibility gate declined the target, with that gate in `detail`.
The two never appear together for one closure: a source that never applied to
the target did not fail to evaluate it.

### Process, handle, and profile records (v2.13)

`processRecord` consolidates process identity from captured sources and keeps
the selected values separate from `identity_evidence`, IAT data, diagnostics,
and optional verbose `peb_extended` fields.

`handleRecord` preserves the raw `granted_access` integer and captured
descriptor facts. Human-readable access-right names are a console projection,
not a replacement or schema mutation of the mask.

`profileRecord` reports the dump directory/stream inventory, header capture
flags, actual captured-memory facts, and the fixed capability registry. A
capability status (`available`, `limited`, or `unavailable`) is an evidence
boundary, never a malicious/clean verdict.

## Coverage limitations and skipped scan targets

Each `coverage.limitations[]` entry has a stable `code`, `source`, and
human-readable `detail`, plus fields used only by that limitation type. Common
structured fields include:

- `scope`: scan layer or narrower operation;
- `affected_count`: number of affected items;
- `targets`: concrete skipped memory regions/segments;
- `budget_kind`, `budget_limit`, and `budget_consumed`;
- source/field/thread relationships relevant to the gap.

A `scanTarget` identifies a physical range with normalized base address, size,
capture state, captured size/file offset, and MemoryInfo context when available.
`file_offset: null` means the bytes are not present in the dump; it is not
offset zero.

`SCAN_ITEMS_UNACCOUNTED` is the one scan-coverage code that reports a count with
no `targets`. It means that many regions or segments failed to reconcile against
the scan's own eligibility ledger, in either direction: taken into scope with no
outcome recorded, or an outcome recorded by a scan that never took its items into
scope. Either way their identity was never captured, so treat it as coverage that
cannot be confirmed rather than as a located gap to revisit.

Do not parse `reasons` text to automate follow-up. Use limitation codes and
structured target/budget fields.

### Hunt investigation actions

For `--hunt all`, `result.summary.investigation_actions` is a deduplicated,
priority-ordered queue derived from skipped-target limitations. Focused
single-hunter runs keep this array empty.

Each action contains:

- `target`: the representative physical range;
- `skipped_by`: every hunter/source/scope/cause relationship;
- `priority` and deterministic `priority_reason_codes`;
- `evidence_availability`: `captured`, `partial`, or `not_captured`;
- `triage`: metadata-only results from the current producer; historical schemas
  also permit retired deep-mode results;
- `recommended_actions`: structured next steps;
- `coverage_effect`.

The current queue is metadata-only: `triage.mode` is `metadata`, no skipped-
region content is read, and `coverage_effect` remains
`original_hunter_gap_not_resolved`. The reserved `--triage-skipped` option is
temporarily unavailable and is rejected before analysis. Historical v2.10-
v2.13 documents may contain `mode="deep"`, content reason codes, and bounded
findings; validate those documents against the schema version they declare.

A targeted rescan does not populate this queue and does not resolve an entry in
one: it is supplementary evidence about the range you asked for, matched back
to an originating gap by `hunter + source + scope + base_address + size`.
Deep-mode historical evidence did not close an originating hunter's coverage
gap, and current gaps likewise require that hunter's successful targeted rescan.

#### The `targeted_hunter_rescan` recommendation

A `recommended_actions` entry of type `targeted_hunter_rescan` carries
`hunters`: the hunters that skipped this target **and** can run a `--hunt-addr`
invocation over it. It is the only action type that carries `hunters`, and the
list is a subset of `skipped_by`, in the fixed hunter order — a hunter without a
targeted capability never appears in it, and the entry itself is absent when no
skipping hunter has one. It is also absent when
`evidence_availability` is `not_captured`: a local rescan of a range this dump
holds no bytes for would read nothing, so `recollect_dump` is the recommendation
that stands. Read `skipped_by`, not `hunters`, for who left the gap.

Everything needed to run one is already in the action: `target.base_address`,
`target.size`, and the hunter. The document deliberately carries no command
string — quoting is a property of the shell that reads a command line, not of a
result — so build the invocation yourself, capping `--size` at the hunter's own
request ceiling (256 MiB, or 32 MiB for `obfuscation`) and treating a capped
request as covering that piece only. The console renders the same command for
the dump path it was given, and shows the arguments without a command line when
that path holds characters no quoting carries through every shell unchanged.

Reconcile a rescan against the relationship it was meant to answer, and close
that relationship only when its own scope came back `complete`. One target may
carry several relationships from the same hunter — a pipe region whose
`pipe_name` and `c2_context` budgets both ran out is one range and one rescan —
and that rescan's per-scope closures decide which of them it actually closed.

## Artifacts and diagnostics

`artifacts[]` describes files dumpex produced, including their kind, path,
size, SHA-256, and description. It must not be confused with
`meta.evidence[]`, which identifies input dumps.

`diagnostics.warnings[]` and `diagnostics.errors[]` carry structured entries
with severity, code, and message. Consumers should display or retain them even
when `result.execution_status` is `completed`.

## Path redaction

`--redact-paths` reduces evidence, rules, YARA, reference, and artifact paths to
basenames in structured output. It does not sanitize strings, IOCs, command
lines, environment values, or other sensitive content recovered from memory.

## Reproducing a run

Preserve together:

1. the original dump and its `meta.evidence[].sha256`;
2. the JSON output and `meta.schema_version`;
3. `meta.execution`, including command options and case metadata;
4. `meta.rules`/`meta.yara_rules` and referenced rule content;
5. any `artifacts[]` files and hashes;
6. the dumpex/runtime versions under `meta.tool` and `meta.runtime`.

Validate the JSON against the schema named by `meta.schema_version`. Historical
schemas remain packaged so archived case records can be validated without
rewriting them into a newer shape.

## Consumer checklist

- Select behavior by `result.kind`; do not assume every record has hunt fields.
- Treat `execution_status`, coverage, and verdicts as separate axes.
- Use structured limitations rather than parsing coverage prose.
- Preserve raw addresses, integers, hashes, and null values without coercion.
- Expect YARA's hunter details to differ from structured findings.
- Use `artifacts[]` for outputs and `meta.evidence[]` for inputs.
- Pin validation to `meta.schema_version`.
