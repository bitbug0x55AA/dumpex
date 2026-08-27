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
| `--list`, `--modules`, `--threads`, `--process`, `--sysinfo`, `--handles`, `--profile`, `--diff`, `--extract`, `--strings`, `--report`, `--hunt` | v2.13 (current) | [`dumpex-output-v2.13.schema.json`](../../dumpex/schemas/dumpex-output-v2.13.schema.json) |
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
