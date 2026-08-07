# Changelog

User-facing changes only. For the full field-by-field migration rationale
and JSON Schema details, see [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md);
for how to read the new fields as a triage analyst, see
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md).

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
