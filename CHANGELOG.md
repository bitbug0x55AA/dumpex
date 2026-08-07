# Changelog

User-facing changes only. For the full field-by-field migration rationale
and JSON Schema details, see [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md);
for how to read the new fields as a triage analyst, see
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md).

## CSV output removed

The `--csv` option has been removed. Structured results are now exported
only through `--json`; human-readable output remains available in the
console and through `--txt`. This also removes the CSV conversion layer,
whose nested values were JSON-encoded inside cells and whose single-file
mode concatenated multiple table shapes into one non-standard CSV file.

## `--hunt cs-beacon` structured fields keyed by name (schema v2.7)

`--hunt cs-beacon`/`--hunt all --json`/`--csv` output re-keys each parsed
Cobalt Strike beacon config's `details.configs[*].fields` by field NAME
(e.g. `"BeaconType"`) instead of the raw TLV field ID string (`"1"`), and
drops the now-redundant `name` property from each field's own value — a
consumer no longer needs to already know that field ID 1 means
BeaconType before it can look anything up:

```jsonc
// before (schema v2.6)
"fields": { "1": { "name": "BeaconType", "type": 1, "value": 0 } }
// after (schema v2.7)
"fields": { "BeaconType": { "type": 1, "value": 0 } }
```

An unrecognized field ID still renders as `"field_0xNNNN"`, unchanged.

This is a public-output-only change:

- **Internal parsing, detection, and scoring are unchanged** (console
  DISPLAY changed in two spots — see "Console-only" below). CS Beacon
  config identification, the sanity check, DER public-key validation,
  Malleable C2 instruction decoding, scoring, and status/verdict/
  confidence/findings are all unaffected — the internal parser
  ([`dumpex/hunt/cs_beacon/parser.py`](dumpex/hunt/cs_beacon/parser.py))
  still keys its own field dict by integer field ID
  (`fields[0x0007]["raw"]`); only the value reshaped into the public v2
  record
  ([`dumpex/hunt/cs_beacon/collect.py`](dumpex/hunt/cs_beacon/collect.py)'s
  `_config_dict()`/`_field_dict()`) changed.
- **A name collision fails loudly, not silently.** If a future edit to
  `CS_FIELD_NAMES` ever mapped two different field IDs to the same name,
  `_config_dict()` raises `ValueError` at collect time instead of letting
  the second field silently overwrite the first in the output.
- **`meta.schema_version` moves from `"2.6"` to `"2.7"`** — every
  producer now stamps `"2.7"`. `dumpex-output-v2.6.schema.json` remains
  shipped and installable for validating output produced before this
  change. Unlike the prior (`raw`-removal) bump, this one IS visible as a
  schema `$defs` diff: `configs[*].fields` now structurally rejects the
  old numeric-key/`name`-carrying shape, not just the new shape's own
  documentation.

**Console-only, no schema impact** (two spots share the same new
`_field_display_value()` rendering rule — see
[`dumpex/hunt/cs_beacon/presentation.py`](dumpex/hunt/cs_beacon/presentation.py)):

1. `--hunt cs-beacon --verbose`'s "Full Config Field Table" no longer
   shows the hex field-ID column (redundant once the table is
   name-keyed) and no longer prints a near-duplicate raw-hex preview
   alongside `value` for binary fields (e.g. PublicKey used to show
   almost the same hex string twice, in two different formats).
2. The "Process Injection" inline section (`ProcInject_Transform_x86`/
   `ProcInject_Transform_x64`, and any other type-3 field in that group)
   now uses the SAME rendering rule, replacing its own, slightly
   different prior logic — this is a real, visible change to that
   section specifically, not merely a side effect of the field-table
   cleanup:
   - a printable value now prints as `repr(value)` (quoted, escape
     sequences visible) instead of the bare decoded string — deliberate:
     tab/CR/LF count as "printable" for a type-3 field, and an
     unescaped embedded newline previously broke the one-field-per-line
     layout;
   - a binary value now always shows a truncated hex encoding of the
     field's FULL raw bytes (64 hex chars, `...` if longer) instead of
     the previous `raw.hex()[:60]` fallback (only reached when the
     decoded/stripped text was empty, no truncation marker, 60 not 64
     chars) — trailing NUL bytes, previously stripped from what small
     amount was shown, are now included in that hex (truncation-permitting).

Both spots show `value`/`raw` exactly once, never a value alongside a
separate raw-hex preview that says the same thing. Console output was
never part of any `schema_version` contract, so none of this needed a
version bump.

See [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md#hunt-records) for the
full versioning rationale.

## `--hunt cs-beacon` structured fields drop raw hex bytes (schema v2.6)

`--hunt cs-beacon`/`--hunt all --json`/`--csv` output no longer includes a
`raw` field on `details.configs[*].fields[*]` for each parsed Cobalt
Strike beacon config TLV field. PublicKey, Malleable C2, and
inject-transform fields could carry very long hex strings there,
degrading JSON, CSV, and any downstream tool's display for no benefit —
`value` already carries the same field's decoded (or hex-rendered, for
non-printable `bytes` fields) content. Each field entry now carries only
`name`, `type`, and `value`.

This is a public-output-only change:

- **Internal parsing and console behavior are unchanged.** CS Beacon
  config identification, the sanity check, DER public-key validation,
  Malleable C2 instruction decoding, scoring, status/verdict/confidence,
  findings, and both normal and verbose console output are all
  unaffected — the internal parser
  ([`dumpex/hunt/cs_beacon/parser.py`](dumpex/hunt/cs_beacon/parser.py))
  still returns `raw` as `bytes` on its own internal field dicts, and DER
  validation / instruction decoding still consume it directly.
- **`meta.schema_version` moves from `"2.5"` to `"2.6"`** — every producer
  now stamps `"2.6"`. `dumpex-output-v2.5.schema.json` remains shipped and
  installable for validating output produced before this change; it still
  describes `configs[*].fields[*]` as carrying `raw`.

See [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md#hunt-records) for the
full versioning rationale.

## `--hunt` findings now carry a normalized-SIEM-alert shape (schema v2.5)

Every entry in a hunter's `findings[]` array (`--hunt --json`/`--csv`)
now carries seven additional fields, so one finding can be consumed
directly as a SIEM alert instead of first being hand-mapped onto one:

- `id` — deterministic, stable across repeated `--hunt` runs against the
  same dump (a 128-bit hash covering check/rule id/rule version/tag/
  confidence/technique ids/evidence refs/iocs/facts, unambiguously
  encoded) — a re-scan dedup key for that dump; combine with
  `meta.evidence[].sha256` for a key unique across dumps.
- `severity` — `info`/`low`/`medium`/`high`/`critical`, always derived
  from `tag`+`confidence` — a producer cannot set it independently, and
  the schema itself pins the exact mapping.
- `technique_ids` — MITRE ATT&CK IDs, populated where a hunter has a real
  mapping (today: `pipe`'s own `rules.yaml`-driven framework matches).
- `evidence_refs` — structured pointers into that hunter's own `details`.
- `iocs` — indicator-of-compromise values extracted from this finding.
- `rule_id` / `rule_version` — detection-logic provenance.

`meta.schema_version` moves from `"2.4"` to `"2.5"` — every producer now
stamps `"2.5"`. `dumpex-output-v2.4.schema.json` remains shipped and
installable for validating output produced before this change; it does
NOT accept these seven new `finding` properties (a closed `finding` $def
must never silently start accepting fields it didn't originally define).
See [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md#hunt-records) for the
full field table and versioning rationale, and
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#reading-a-finding) for
the analyst-facing explanation.

## `--diff` now treats the positional dump as the analysis target

For `dumpex suspect.dmp --diff clean-reference.dmp`, `suspect.dmp` is now
the target and `clean-reference.dmp` is the baseline. Console additions,
new threads, and protection changes therefore describe the suspicious
dump relative to the reference. Structured output follows the same rule:
`meta.evidence[target]` points to the positional dump and
`meta.evidence[baseline]` points to the `--diff` argument.

The comparison filter is now shown in help as `--diff-scope` to make clear
that it is an optional modifier, not a second comparison command. The old
`--diff-mode` spelling remains available as a hidden compatibility alias.

CLI help is now grouped by purpose (commands, memory/extraction, string
scanning, diff, display, hunt, report, and output/case metadata) instead of
placing every flag in one undifferentiated list. The string encoding filter
is now shown as `--strings-encoding`; the older `--encoding` spelling remains
available as a hidden compatibility alias.

## `--hunt` output migrated to the v2.4 contract

`--hunt` was the last command still writing the older v1.1 JSON contract.
It has now moved onto the same v2.4 envelope every other command
(`--list`, `--modules`, `--threads`, `--pid`, `--sysinfo`, `--peb`,
`--diff`, `--extract`, `--strings`, `--report`) already uses. **`--hunt`
no longer produces v1.1 output at all** — every `--json`/`--csv` result it
writes now stamps `schema_version: "2.4"`.

If you have automation (a SIEM/SOAR integration, a parsing script, a case
management hook) that reads `dumpex --hunt ... --json`, it needs to be
updated for this release. The `dumpex-output-v1.1.schema.json` file is
still shipped (wheel, sdist, and the Windows EXE bundle) so existing
archived v1.1 results can still be validated, but no command produces
that shape anymore.

### JSON: root structure change

**v1.1** (old): a bare top-level `hunt` object, keyed by hunter name:

```json
{ "meta": { "schema_version": "1.1", ... },
  "hunt": { "pipe": { "score": 3, "status": "DETECTED", "coverage_status": "complete", ... },
            "stomping": { "score": 0, "status": "INCONCLUSIVE", "coverage_status": "partial", ... } } }
```

**v2.4** (current): the same shared envelope every other command uses —
`result.kind == "hunt"`, and each hunter is now one entry in
`result.data.records[]`, discriminated by its own `hunter` field. The
former bare `coverage_status`/`coverage_reasons` strings are now a
structured `coverage` object (`coverage.status`/`coverage.reasons`, plus
new `coverage.sources`/`coverage.limitations` detail) on each record,
*and* rolled up across every selected hunter into `result.coverage.status`
(see [Exit codes](#exit-codes-for---hunt-are-no-longer-always-0) below).
A new `result.summary` object (`selected`, `hunter_count`,
`detected_count`, `inconclusive_count`, `not_evaluated_count`,
`overall_status`, `highest_verdict_level`, `lead_count`) replaces the
console-only summary table as a machine-readable cross-hunter rollup:

```json
{ "meta": { "schema_version": "2.4", ... },
  "result": {
    "kind": "hunt",
    "coverage": { "status": "partial", "reasons": [...] },
    "summary": { "selected": "all", "hunter_count": 7, "detected_count": 1, ... },
    "data": { "records": [
      { "hunter": "pipe", "score": 3, "status": "DETECTED",
        "coverage": { "status": "complete", "reasons": [] }, "findings": [...], "details": {...} },
      { "hunter": "stomping", "score": 0, "status": "INCONCLUSIVE",
        "coverage": { "status": "partial", "reasons": [...] }, "findings": [], "details": {...} }
    ] }
  } }
```

`meta.evidence` also changed shape: it's now an array (`role: "primary"`
for `--hunt`'s single dump) rather than a bare object, matching every
other command — see docs/OUTPUT_SCHEMA.md for the full `meta` shape.

### CSV: table changes

`--csv` for `--hunt` now writes the same table-per-shape convention every
other v2 command uses, instead of its old bespoke layout:

- `summary` — one row: `kind`/`execution_status`/`coverage`/record count.
- `hunters` — one row per hunter (`status`/`score`/`coverage_status`/
  `verdict_level`/`confidence`/... — the judgment fields every hunter
  carries).
- `findings` — one row per structured `Finding`, across every hunter
  (empty for `yara`, which has none).
- Per-hunter evidence tables, populated only for hunters that produce
  that kind of evidence: `injection_evidence`, `stomping_changes`,
  `pipe_evidence`, `beacon_configs`, `yara_matches`, `obfuscation_hits`.

A CSV consumer keyed on the old single-table `--hunt` layout will need
updating to read from these tables instead.

### Exit codes for `--hunt` are no longer always `0`

`--hunt` previously always exited `0` regardless of what it found or
whether it could fully evaluate the dump. It now uses the same
coverage-based exit code every other v2-routed command uses, derived from
`result.coverage.status`:

| Exit code | `result.coverage.status` | Meaning |
|---|---|---|
| `0` | `complete` | Every selected hunter's evidence was fully covered |
| `3` | `partial` | At least one selected hunter had a coverage gap (unreadable stream, missing `--ref-dir`, a scan budget hit, ...) |
| `4` | `not_evaluated` | No selected hunter could evaluate at all |

This is independent of `--json`/`--csv` being requested at all — a bare
`dumpex sample.dmp --hunt all` now exits `0`/`3`/`4` accordingly, so a
script checking `$?` can detect incomplete coverage without parsing JSON.
It's also independent of whether anything was *detected* — exit code
tracks coverage completeness, not verdict severity.

### Windows EXE release bundle now ships the current schema

The downloadable Windows EXE release bundle (`dumpex-vX.Y.Z-windows-x64.zip`)
previously only included `dumpex-output-v1.1.schema.json` — stale from
before this migration, and not the contract `--hunt` (or any other
command) actually produces. The bundle now includes every packaged
`dumpex-output-v*.schema.json` file (current v2.4 plus the frozen
historical v1.1/v2.0/v2.1/v2.2/v2.3 files), matching what `pip install
dumpex` already ships.
