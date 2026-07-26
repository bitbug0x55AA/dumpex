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

## JSON document

The top-level object contains `meta` followed by one or more command-specific
result sections:

```json
{
  "meta": {
    "schema_version": "1.0",
    "tool": {
      "name": "dumpex",
      "version": "2.0.0"
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

## Reproducing a run

Retain the following together:

1. the JSON result;
2. the source dump identified by `meta.evidence.sha256`;
3. any explicit rules or reference modules;
4. the dumpex version and runtime versions in `meta`; and
5. the exact options recorded under `meta.execution.options`.

For reports shared outside the investigation environment, use
`--redact-paths` but preserve hashes and basenames. Redaction protects local
directory layout; it does not anonymize evidence content, strings, module
names, host data, or findings.

