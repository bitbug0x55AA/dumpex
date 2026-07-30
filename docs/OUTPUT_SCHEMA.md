# Output and Evidence Schema

dumpex can write JSON, CSV, and plain-text output in addition to the console
display. JSON is the canonical case-record format because it contains analysis
data together with evidence identity, execution context, dependency versions,
and rule provenance.

## Formats

| Format | Option | Intended use |
|---|---|---|
| JSON | `--json FILE` | Automation, case records, reproducibility |
| CSV | `--csv FILE.csv` | One combined flat export |
| CSV directory | `--csv DIR` | One file per result table |
| Plain text | `--txt FILE` | Human-readable transcript with ANSI colours removed |

All enabled formats are derived from the same in-memory analysis result.
Existing output files are protected unless `--force` is supplied, and an
output path may never replace an input dump.

`--txt` is a human-readable console transcript (colours stripped), not a
machine interface: it carries no schema, no version, and no compatibility
promise. Automation must use `--json`, never scrape `--txt`.

## Two JSON contracts

dumpex currently has two coexisting JSON contracts, not one:

| Commands | Contract | Schema file |
|---|---|---|
| `--hunt` | v1.1 | [`dumpex-output-v1.1.schema.json`](../dumpex/schemas/dumpex-output-v1.1.schema.json) |
| `--list`, `--modules`, `--threads`, `--pid`, `--sysinfo`, `--peb` | v2.0 | [`dumpex-output-v2.0.schema.json`](../dumpex/schemas/dumpex-output-v2.0.schema.json) |
| `--diff`, `--report`, `--extract`, `--strings` | none yet | — `--json`/`--csv` are rejected up front (before the dump is opened) for these modes |

This split exists because v1.1's root schema requires a top-level `hunt`
object (`"required": ["meta", "hunt"]`) — the six recon commands never
produced one, so their JSON, despite stamping `schema_version: "1.1"`,
could never actually validate against the schema it claimed to satisfy.
v2 is a genuinely separate, self-consistent contract for those six
commands rather than a patch to v1.1's `hunt`-shaped root. `--hunt` keeps
using v1.1 unchanged. The rest of this document describes v1.1
(`--hunt`); see "v2 structured output" below for the recon contract.

## JSON document (v1.1 — `--hunt`)

The top-level object contains `meta` followed by one or more command-specific
result sections:

```json
{
  "meta": {
    "schema_version": "1.1",
    "tool": {
      "name": "dumpex",
      "version": "3.0.0"
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

## Hunt result semantics

Each hunter reports its findings and decision fields inside the command result.
The important decision fields are:

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
validates real hunter output (all seven hunters, both typical and edge-case
verdicts) against this file on every test run, including the negative cases
it must reject.

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
read this file at runtime (nothing in the running tool validates its own
output — only the test suite and external `--json` consumers do), so it is
not collected into the frozen executable. It is instead uploaded as a
separate `dumpex-output-v1.1.schema.json` file alongside `dumpex.exe` on
each GitHub release, so an EXE-only install (no `pip install dumpex`, no
source checkout) still has a way to get the canonical schema for that
release.

### Versioning and breaking changes

`meta.schema_version` (currently `"1.1"`) is the contract version, independent
of the dumpex application version. The policy for changing the schema file:

- **A new optional object field** — no version bump. `additionalProperties`
  keeps object shapes open, so an older cached copy of the schema silently
  ignores a field it doesn't know about; nothing that already validated
  stops validating. Update the schema file and add/extend a schema test.
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

## v2 structured output (`--list` / `--modules` / `--threads` / `--pid` / `--sysinfo` / `--peb`)

These six recon commands are always structured internally — even without
`--json`/`--csv` — and use a distinct envelope from v1.1's `hunt`-shaped
root:

```json
{
  "meta": {
    "schema_version": "2.0",
    "tool": { "name": "dumpex", "version": "3.0.0" },
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
    "coverage": { "status": "complete", "reasons": [] },
    "summary": { "count": 42 },
    "data": { "records": [ "...": "one canonical record per item" ] }
  },
  "artifacts": [],
  "diagnostics": { "warnings": [], "errors": [] }
}
```

`meta.evidence` is an **array**, not a single object (v1.1's shape) — a
future comparison command (baseline + target dumps) can add a second
entry without a breaking change to this array's own shape. A single-dump
recon command always emits exactly one entry, `role: "primary"`.

`result` deliberately keeps three concepts separate, and none of them is
a verdict:

- **`execution_status`** — did the *command* run to completion
  (`"completed"` / `"partial"` / `"failed"`)? None of these six commands
  has an internal scan-budget/timeout, so this is `"completed"` in every
  case that doesn't crash.
- **`coverage.status`** — was the *evidence* it looked at complete
  (`"complete"` / `"partial"` / `"not_evaluated"`), reusing the same
  vocabulary `--hunt`'s `coverage_status` uses
  (`dumpex.hunt._coverage.derive_coverage_status`)? For example,
  `--threads` reports `"partial"` when a dump lacks
  `ThreadInfoListStream`; `--pid` reports `"partial"` when it had to fall
  back past `MINIDUMP_MISC_INFO` to a thread-list/exception-stream
  heuristic. `coverage.reasons` explains why.
- **verdict/confidence** — not applicable to these six commands at all;
  that concept stays scoped to `--report`/`--hunt`, which reason about
  evidence, not just list it.

`result.data.records` is always an array of one canonical record type per
`kind` (`memory_regions` → `MemoryRegionRecord`, `modules` →
`ModuleRecord`, `threads` → `ThreadRecord`, `sysinfo` → `SysInfoRecord`,
`pid` → `PidRecord`, `peb` → `PebRecord`) — a single-record result
(`sysinfo`/`pid`/`peb`) is still a one-element array, not a bare object,
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

An exit code mirrors `coverage.status` one-for-one for these six commands,
independent of whether `--json`/`--csv` was even requested: `0` for
`"complete"`, `3` for `"partial"`, `4` for `"not_evaluated"` (the primary
stream a command needed was entirely absent from the dump — e.g.
`--modules` when `ModuleListStream` itself isn't present, as opposed to
being present with zero entries, which is `"complete"`) — a SOC script
checking `$?` on a bare `dumpex sample.dmp --threads` can distinguish "no
data at all" from "some data, degraded" without parsing JSON at all. This
convention is scoped to these six commands only; every other command's
exit-code behavior (`0` on completion, an uncaught exception's default
nonzero on a fatal error) is unchanged.

`--diff`/`--report`/`--extract`/`--strings` do not produce structured
output yet. Passing `--json`/`--csv` with one of them is rejected before
the dump is opened (`parser.error`, exit code `2`), not after a full run
completes with nothing to write.

## Reproducing a run

Retain the following together:

1. the JSON result;
2. the source dump identified by `meta.evidence[0].sha256` (v2) or
   `meta.evidence.sha256` (v1.1 `--hunt`);
3. any explicit rules or reference modules;
4. the dumpex version and runtime versions in `meta`; and
5. the exact options recorded under `meta.execution.options`.

For reports shared outside the investigation environment, use
`--redact-paths` but preserve hashes and basenames. Redaction protects local
directory layout; it does not anonymize evidence content, strings, module
names, host data, or findings.

