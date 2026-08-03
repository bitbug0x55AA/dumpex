# CLI Reference

This page is the complete command reference for `dumpex`. For a first
investigation, start with the [README quick start](../README.md#quick-start).
For help interpreting hunt results, use the
[SOC / DFIR Quick Start](SOC_QUICKSTART.md).

## Command shape

```text
dumpex DUMPFILE MODE [OPTIONS]
python -m dumpex DUMPFILE MODE [OPTIONS]
```

Exactly one mode is required. Addresses, sizes, and thread IDs accept the
formats documented for their individual options.

## Analysis modes

| Mode | Purpose |
|---|---|
| `--list` | List captured memory regions |
| `--modules` | List loaded modules |
| `--threads` | List threads with analysis |
| `--extract ADDR` | Extract raw bytes from the region containing `ADDR` |
| `--strings ADDR` | Extract strings from the region containing `ADDR` |
| `--peb` | Show Process Environment Block information |
| `--pid` | Show the process ID recorded in the dump |
| `--sysinfo` | Show OS, host, process, and CPU summary |
| `--diff DUMP2` | Compare the primary dump with a second dump |
| `--report` | Generate a focused triage report |
| `--hunt TTP` | Run `injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, `obfuscation`, or `all` |

## Shared and mode-specific options

| Option | Applies to | Description |
|---|---|---|
| `-s SIZE`, `--size SIZE` | extraction, strings | Region size in hexadecimal |
| `-o FILE`, `--output FILE` | extraction | Raw output file |
| `--filter PROT` | list | Filter by protection name, such as `PAGE_EXECUTE_READWRITE` |
| `--grep REGEX` | strings | Keep strings matching a regular expression |
| `--min-len N` | strings | Minimum string length; default `6` |
| `--encoding ascii\|unicode\|both` | strings | String encoding to scan; default `both` |
| `--diff-mode modules\|threads\|memory\|all` | diff | Objects to compare; default `all` |
| `--verbose` | multiple modes | Include routine regions or additional detail |
| `--yara-dir DIR` | YARA hunt | Use an explicit directory of `.yar`/`.yara` files instead of packaged rules |
| `--ref-dir DIR` | stomping hunt | Directory of analyst-supplied reference modules, matched by basename |
| `--rules-file FILE` | rule-driven hunts | Use an explicit `rules.yaml`, `.yml`, or `.json` file instead of packaged defaults |
| `--report-tid TID` | report | Anchor a report to a thread ID in hexadecimal or decimal |
| `--report-addr ADDR` | report | Anchor a report to a memory address |
| `--report-string STRING` | report | Search memory and report on each matching region |

`--ref-dir` enables the optional on-disk-versus-memory content comparison for
module stomping. The structural section-protection check still runs without
it. See [Detection Methodology](DETECTION_METHODOLOGY.md#module-stomping).

`--rules-file` fails closed: if the file is missing, unreadable, fails to
parse, or does not satisfy the rules schema, dumpex exits non-zero rather
than silently falling back to the packaged or built-in rule defaults. A run
that asked for a specific ruleset never produces a verdict from a different
one.

## Output and evidence options

| Option | Description |
|---|---|
| `--json FILE` | Write structured JSON results |
| `--csv PATH` | Write one combined `.csv` file, or one file per table when `PATH` is a directory |
| `--txt FILE` | Write an ANSI-free copy of console output |
| `--force` | Allow replacement of an existing output file; never permits replacing an input dump |
| `--case-id ID` | Record a case or ticket identifier in JSON metadata |
| `--analyst NAME` | Record the analyst name or handle in JSON metadata |
| `--redact-paths` | Reduce absolute evidence, rules, YARA, reference, and (for `--extract`) output/artifact paths to basenames in JSON metadata |

Output files are not overwritten unless `--force` is present. dumpex also
refuses any output path that resolves to an input dump path, and refuses to
run at all if two of `--output`/`--json`/`--csv`/`--txt` (or `--extract`'s own
auto-generated default filename) would resolve to the same file — a later
write silently clobbering an earlier one's output is never allowed, even
with `--force`.

`--json`/`--csv` currently route to one of two contracts depending on the
mode: `--hunt` uses the v1.1 contract unchanged; `--list`/`--modules`/
`--threads`/`--pid`/`--sysinfo`/`--peb`/`--diff`/`--extract`/`--strings`/
`--report` use the v2 contract (canonical records, `null` for missing
values, normalized hex addresses — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#v2-structured-output)). All
ten of these support `--json`/`--csv` — `--hunt` is the only command left
on the v1.1 contract.
`--diff` produces a `kind: "comparison"` result with a two-entry
`meta.evidence` array (`baseline`/`target`) instead of the single-dump
`meta` shape the other nine use — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#comparison-records).
`--extract` is the first command to populate the top-level `artifacts[]`
(the `--output` file it wrote) and `diagnostics.warnings[]` (e.g. an
MZ-header-detected warning) — both are siblings of `result`, not nested
under it — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#extract-and-strings-records).
`--report` produces a `kind: "report"` result, one `triageCardRecord` per
triage card (see [Output and Evidence Schema](OUTPUT_SCHEMA.md#report-records)),
and also populates `artifacts[]` for its own optional `--output` extract.
For the v2-routed modes, the process exit code also
reports coverage independent of `--json`/`--csv`: `0` for complete coverage,
`3` for partial (e.g. `--threads` on a dump missing `ThreadInfoListStream`
while the base thread list is still present, or `--extract`/`--strings`
reading fewer bytes than requested), `4` when the one stream the command
needed is entirely absent (e.g. `--modules` when `ModuleListStream`
itself isn't in the dump at all).

See [Output and Evidence Schema](OUTPUT_SCHEMA.md) for formats and metadata.

## Examples

### Recon

```bash
dumpex sample.dmp --sysinfo
dumpex sample.dmp --pid
dumpex sample.dmp --peb
dumpex sample.dmp --modules
dumpex sample.dmp --threads
dumpex sample.dmp --list
dumpex sample.dmp --list --filter PAGE_EXECUTE_READWRITE
```

When running from a source checkout without an installed console entry point,
replace `dumpex` with `python -m dumpex`.

### TTP hunting

```bash
# Run every hunter
dumpex sample.dmp --hunt all

# Run a single hunter
dumpex sample.dmp --hunt injection
dumpex sample.dmp --hunt hollowing
dumpex sample.dmp --hunt stomping --ref-dir C:\Windows\System32
dumpex sample.dmp --hunt pipe
dumpex sample.dmp --hunt cs-beacon
dumpex sample.dmp --hunt yara
dumpex sample.dmp --hunt obfuscation

# Use explicit analyst-controlled rules
dumpex sample.dmp --hunt all --rules-file case-rules.yaml
dumpex sample.dmp --hunt yara --yara-dir case-yara
```

### Focused report

Use exactly one report anchor:

```bash
dumpex sample.dmp --report --report-tid 0x1234
dumpex sample.dmp --report --report-addr 0x7ff600001000
dumpex sample.dmp --report --report-string "powershell"
```

### Diff

```bash
dumpex before.dmp --diff after.dmp
dumpex before.dmp --diff after.dmp --diff-mode memory
```

### Extraction and strings

```bash
dumpex sample.dmp --extract 0x7ff600001000 --size 0x1000 --output region.bin
dumpex sample.dmp --strings 0x7ff600001000 --min-len 8
dumpex sample.dmp --strings 0x7ff600001000 --encoding unicode --grep "(?i)https?://"
```

### Case-ready output

```bash
dumpex sample.dmp --hunt all \
  --json result.json \
  --csv tables/ \
  --txt transcript.txt \
  --case-id CASE-1234 \
  --analyst analyst01
```

Add `--redact-paths` when the JSON will leave the analyst workstation.

