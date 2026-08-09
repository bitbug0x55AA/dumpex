# Changelog

User-facing changes only. For the full field-by-field migration rationale
and JSON Schema details, see [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md);
for how to read the new fields as a triage analyst, see
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md).

## `--hunt all` automatically triages skipped targets (schema v2.9)

Issues #16/#17/#18 made partial coverage from oversized skipped
regions/segments *visible* (`targets[]` on `SCAN_REGION_OVERSIZED_SKIPPED`),
but an analyst still had to manually copy each address into `--report
--report-addr`, dedupe overlapping skips across hunters by hand, and
reconstruct priority/next-steps themselves.

`--hunt all` now builds that investigation queue automatically, from data
already collected during the scan — **no additional bytes are read from
the dump.** `result.summary.investigation_actions` is a new array,
deduplicated on the physical region/segment (one entry even when several
hunters or scan layers skipped the same target) and sorted by priority:

```jsonc
{
  "investigation_actions": [
    {
      "target": { "kind": "memory_region", "base_address": "0x00007ff000001000",
                  "size": 16777216, "size_limit": 8388608, "file_offset": 4096,
                  "allocation_base": "0x00007ff000000000", "state": "MEM_COMMIT",
                  "type": "MEM_PRIVATE", "protection": "PAGE_EXECUTE_READWRITE" },
      "skipped_by": [
        { "hunter": "pipe", "source": "pipe_name_scan", "scope": null, "size_limit": 8388608 },
        { "hunter": "obfuscation", "source": "encoding_scan", "scope": "entropy", "size_limit": 10485760 }
      ],
      "priority": "high",
      "priority_reason_codes": ["PRIVATE_EXECUTABLE_MEMORY", "RWX_PROTECTION", "MULTIPLE_SCOPES_SKIPPED"],
      "evidence_availability": "captured",
      "triage": { "mode": "metadata", "status": "completed", "bytes_examined": 0,
                  "region_fully_examined": false },
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

- **Two independent priority/evidence axes**, never collapsed into one
  score: `priority` (`low`/`medium`/`high`) comes from deterministic
  MemoryInfo facts (private/executable memory) and cross-hunter
  correlation signals (multiple scopes skipped it, or it coincides with
  an existing `CORRELATED REGIONS` entry); `evidence_availability`
  (`captured`/`not_captured`) only says whether the bytes are already in
  this dump file — a missing capture means "recollect," never "more
  malicious."
- **`recommended_actions` are structured, not prose** — a renderer may
  turn `targeted_hunter_rescan.hunters` plus the target's own
  `base_address`/`size` into a safe command suggestion.
- **Advisory only.** `coverage_effect` is always
  `"original_hunter_gap_not_resolved"`: no score, verdict, coverage
  status, or exit code is ever upgraded because this queue was built.
  Only a real rerun of the specific hunter that skipped a target closes
  its own gap.
- **`--hunt all` only.** A single-hunter run (`--hunt pipe`, ...) always
  reports `investigation_actions: []` — this feature does not change
  single-hunter output.
- **Console**: a new bounded `SKIPPED TARGET ACTIONS` section in the
  `HUNT SUMMARY` card, printed after `CORRELATED REGIONS`. `--verbose`
  only expands how much of each already-computed entry is shown (full
  `skipped_by`/reason/action lists, more entries) — it never changes
  which entries exist, their order, or `--json`, preserving the existing
  rule that console verbosity cannot change structured output.

This is a `--triage-skipped`-free, metadata-only pass by design — a
budgeted, opt-in deep-content triage (reusing `--report`'s own triage
collector under an explicit byte/read budget) is tracked as a follow-up
and is not part of this change.

See [docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#skipped-target-investigation-queue-hunt-all)
for the full field-by-field reading guide.

## Fixed: truncated hash prefixes were mislabeled `sha256=` in console/fact text

Several console displays truncated a SHA-256 digest to its first 16 hex
characters and appended an ellipsis, but still labeled the value
`sha256=`/`disk_sha256=`/`mem_sha256=` — indistinguishable, at a glance,
from a complete digest suitable for exact verification or copy/paste into
another forensic tool. A 16-hex-character value is only a 64-bit prefix.

Every such display is now labeled with an explicit `_prefix` suffix
instead:

- `--hunt pipe --verbose`'s C2-context lines: `sha256=<16 hex>…` →
  `sha256_prefix=<16 hex>…`.
- Rules-loader announcements (`Rules loaded from ... (sha256=...)`, both
  `--rules-file` and packaged/auto-discovered rules): → `sha256_prefix=`.
- The `stomping.verified_content_change` Finding's `facts` entry:
  `disk_sha256=<16 hex>… mem_sha256=<16 hex>…` →
  `disk_sha256_prefix=<16 hex>… mem_sha256_prefix=<16 hex>…`.

**This is a one-time, expected `Finding.id` change for
`stomping.verified_content_change` findings.** `Finding.id` is a hash of
the Finding's own content, including `facts`, so relabeling that fact
string changes the id of every `stomping.verified_content_change` Finding
this version produces, even against an unchanged dump. No other hunter's
Finding IDs are affected — no other hunter embeds a truncated hash in
`facts`. A downstream consumer that treats Finding IDs as a re-scan
dedup/idempotency key (see `Finding.id`'s own docstring in
`dumpex/hunt/_finding.py`) will see this version's
`stomping.verified_content_change` findings as "new" even for a
previously-seen dump; this is expected, not a regression, and does not
indicate a change in what was detected — re-running affected pipelines'
dedup baselines is the only action needed.

**Schema stays at v2.8** — this is a text/labeling fix, not a field
addition, removal, or shape change. **The complete, untruncated SHA-256
values already exist in structured output and are unchanged**:
`meta.evidence[].sha256`, rule/YARA provenance hashes, and the full
`disk_sha256`/`mem_sha256`/pipe `sha256` fields in each hunter's
structured `details` all remain full 64-hex digests with no truncation —
only the free-text display strings above were mislabeled and are fixed
here.

## Fixed: `--hunt stomping` no longer reports a clean IOC scan over memory it never read

The stomping hunter's IOC-string scan skips executable `MEM_IMAGE` regions
larger than 5 MB — string extraction over a huge mapping is expensive and
can never contribute to the score. Those skips were dropped silently: no
count, no addresses, no coverage record, and the check still printed

```text
[✓] IOC strings in module code regions
    Status : CLEAN — no IOC patterns in executable module memory
```

even when a 40 MB executable mapping had never been looked at. Large
executable regions are exactly where planted strings can hide, so this
read as evidence of absence where there was no evidence at all.

Every otherwise-eligible region skipped for size is now recorded before it
is skipped, with the same `targets` identity every other hunter's
oversized skips carry (VA, size, the 5 MB cap it exceeded, dump-file
offset, allocation base, state/type/protection) under a new
`ioc_string_scan` coverage source:

```jsonc
{
  "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "ioc_string_scan",
  "affected_count": 1,
  "targets": [{ "kind": "memory_region", "base_address": "0x00007ff600100000",
                "size": 6291456, "size_limit": 5242880, "file_offset": null,
                "allocation_base": "0x00007ff600000000", "state": "MEM_COMMIT",
                "type": "MEM_IMAGE", "protection": "PAGE_EXECUTE_READWRITE" }]
}
```

- **The check reports `INCOMPLETE`, never `CLEAN`,** when an eligible
  region was skipped or failed to read, and the console names the
  region(s) to follow up on with `--extract`/`--strings` or an external
  scanner.
- **`coverage_status` is `"partial"`** with the skipped regions in
  `coverage.reasons`, and a score-0 run is therefore `INCONCLUSIVE`
  instead of `NOT_DETECTED_IN_SCANNED_SCOPE` — the status/coverage pair
  the output contract requires, and a scan that examined part of its own
  scope is not a clean bill of health. IOC-scan **read failures** were
  already counted on the console but likewise left coverage reading
  `"complete"`; they now downgrade it too.
- **Scores, verdicts, and findings are unchanged.** A verified content
  change still scores and still reports `DETECTED` (with
  `coverage_status: "partial"`), so an oversized region can neither invent
  nor hide a detection; when the IOC lead does fire, its `limitations` now
  say how much of the scope the hit list came from.

## Skipped oversized scan targets are identified, not just counted (schema v2.8)

A hunt that skipped memory for exceeding a scan's size cap used to report
only a tally, which told an investigator the result was incomplete but not
which addresses to act on:

```jsonc
// before (schema v2.7)
{ "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "pipe_name_scan", "affected_count": 2 }
```

Every such limitation now carries a `targets` array naming exactly what
was skipped — kind (memory region vs. memory segment), virtual address,
size, dump-file offset, allocation base/state/type/protection where
MemoryInfo is available, and the configured cap the target exceeded:

```jsonc
// after (schema v2.8)
{
  "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "pipe_name_scan",
  "affected_count": 1,
  "targets": [{ "kind": "memory_region", "base_address": "0x00007ff000001000",
                "size": 16777216, "size_limit": 8388608, "file_offset": 4096,
                "allocation_base": "0x00007ff000000000", "state": "MEM_COMMIT",
                "type": "MEM_PRIVATE", "protection": "PAGE_EXECUTE_READWRITE" }]
}
```

The gap can now be dispositioned directly: check whether it covers
executable private memory or an ordinary large mapping, run `--extract`/
`--strings` against the address, rescan it with another tool, or decide a
broader recollection is needed. Applies to `--hunt pipe` (regions over
8 MB), `--hunt cs-beacon` and `--hunt yara` (segments over 50 MB), and
`--hunt obfuscation` (sleep-mask/entropy regions over 10 MB, decode
regions over 2 MB).

- **`affected_count` now has one unambiguous meaning** — it equals
  `targets`' length exactly.
- **Console and `--txt`** show a bounded preview (address, size, and the
  limit it exceeded) with `+N more (see coverage.limitations[].targets in
  --json output)` when the list is abbreviated; `--json` always carries
  the complete list.
- **Every other limitation code emits `targets: []`.** A consumer that
  ignores the new key sees the v2.7 shape unchanged.
- **The rendered noun matches what was actually skipped.** `--hunt
  cs-beacon` and `--hunt yara` attach this code to Memory64List/MemoryList
  *segments*, not MemoryInfo regions — the rendered text (both
  `coverage.reasons` and the console verdict line) now says `segment(s)`
  there, not `region(s)`.

### Fixed: `--hunt obfuscation` no longer double-counts skipped regions

Obfuscation runs three region scans with three different size caps
(sleep-mask 10 MB, entropy 10 MB, decode 2 MB) over overlapping candidate
sets, and used to sum their counters into a single `N oversized region(s)
skipped`. One 12 MB private region exceeds all three caps, so that sum
reported **three regions** where there was one. It now emits one
limitation per scan layer, each carrying `scope`
(`sleep_mask`/`entropy`/`decode`), its own targets, and its own
threshold — three region × layer skips over one physical region, which is
what actually happened. Deduplicate on `targets[*].base_address` to count
distinct regions. Coverage status, scores, verdicts, and findings are
unchanged.

`dumpex-output-v2.7.schema.json` stays frozen and installable for
validating output produced before this change; see
[docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) for the full `scanTarget`
shape.

## CSV output removed

The `--csv` option has been removed. Structured results are now exported
only through `--json`; human-readable output remains available in the
console and through `--txt`. This also removes the CSV conversion layer,
whose nested values were JSON-encoded inside cells and whose single-file
mode concatenated multiple table shapes into one non-standard CSV file.

## `--hunt all` console/`--txt` gains a `CORRELATED REGIONS` section

`--hunt all`'s printed `HUNT SUMMARY` card (and its `--txt` copy) can now
end with a `CORRELATED REGIONS` section, shown after `OTHER HUNTERS` and
before `NEXT INVESTIGATION`: whenever two or more *different* hunters
each produced real, structured evidence that resolves to the exact same
normalized MemoryInfo region (`BaseAddress`/`RegionSize`, half-open
containment), that region's evidence is listed together, region base and
allocation base in dumpex's usual fixed-width hex, hunter verdict badges,
and a short evidence line per hunter. See
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#correlated-regions-console-and-txt-output-only)
for the full read on what this section does and does not mean.

- **Console/`--txt` presentation only.** `--json`,
  `schema_version`, and every finding id are unchanged; no hunter's own
  `score`/`confidence`/`verdict_level`/`coverage` is recomputed or
  affected in any way — co-location is never treated as a scoring
  signal.
- **No re-scan.** The correlation is built entirely from the same
  `HunterRecord`s and the same already-parsed MemoryInfo list `--hunt
  all` already had in hand for this run
  ([`dumpex/hunt/region_correlation.py`](dumpex/hunt/region_correlation.py)).
- **Same allocation is not the same region.** Two MemoryInfo sub-regions
  that only share an `AllocationBase` (routine after a `VirtualProtect`
  split) are never merged into one entry.
- **Omitted when nothing correlates.** A run with no cross-hunter
  overlap prints exactly what it always did — no empty section, no other
  change to `HUNT SUMMARY`.

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
