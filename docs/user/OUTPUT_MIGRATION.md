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
| `--list`, `--modules`, `--threads`, `--process`, `--sysinfo`, `--handles`, `--profile`, `--diff`, `--extract`, `--strings`, `--report`, `--hunt` | v2.15 (current) | [`dumpex-output-v2.15.schema.json`](../../dumpex/schemas/dumpex-output-v2.15.schema.json) |
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

## Producer behavior within v2.15

Not every change to what dumpex emits changes the wire shape. These narrow what
a v2.15 document contains without changing what a v2.15 document may contain, so
they need no schema bump and every archived document stays valid — but a
consumer that inferred a rule from earlier output should read them.

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
