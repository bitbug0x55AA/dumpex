# CLI Reference

This page is the complete command reference for `dumpex`. For a first
investigation, start with the [README quick start](../README.md#quick-start).
For help interpreting hunt results, use the
[SOC / DFIR Quick Start](SOC_QUICKSTART.md).

## Command shape

```text
dumpex DUMPFILE COMMAND [OPTIONS]
python -m dumpex DUMPFILE COMMAND [OPTIONS]
```

Exactly one command is required. Addresses, sizes, and thread IDs accept the
formats documented for their individual options.

## Commands

| Mode | Purpose |
|---|---|
| `--list` | List captured memory regions |
| `--modules` | List loaded modules |
| `--threads` | List threads with analysis |
| `--extract ADDR` | Extract raw bytes from the region containing `ADDR` |
| `--strings ADDR` | Extract strings from the region containing `ADDR` |
| `--process` | Show consolidated process identity (PID, path, command line, start time, image base, IAT) — replaces `--pid`/`--peb` (removed in v2.13, no alias) |
| `--handles` | List captured handle descriptors from `HandleDataStream` |
| `--profile` | Describe dump evidence and the analysis-capability map (an evidence boundary, not a verdict) |
| `--sysinfo` | Show dump identity (size/SHA-256/dump time), OS, host, CPU, and environment |
| `--diff REFERENCE` | Compare the primary target dump against a reference dump |
| `--report` | Generate a focused triage report |
| `--hunt TTP` | Run `injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, `obfuscation`, or `all` |

## Command-specific options

These sections mirror the groups shown by `dumpex --help`. They are modifiers
for the named commands, not additional command entry points.

### Memory and extraction options

| Option | Applies to | Description |
|---|---|---|
| `-s SIZE`, `--size SIZE` | extraction, strings | Region size in hexadecimal |
| `-o FILE`, `--output FILE` | extraction, report | Write extracted region bytes |
| `--filter PROT` | list | Filter by protection name, such as `PAGE_EXECUTE_READWRITE` |

### String scan options

| Option | Applies to | Description |
|---|---|---|
| `--grep REGEX` | strings | Keep strings matching a regular expression |
| `--min-len N` | strings | Minimum string length; default `6` |
| `--strings-encoding ascii\|unicode\|both` | strings | String encoding to scan; default `both` |

### Diff and display options

| Option | Applies to | Description |
|---|---|---|
| `--diff-scope modules\|threads\|memory\|all` | diff | Optional evidence-type filter for `--diff`; default `all` |
| `--verbose` | process, handles, sysinfo, diff, hunt | Include routine regions or additional detail. Console only — `--json` always carries every record (see [Verbose recon output](#verbose-recon-output)) |

### Hunt options

| Option | Applies to | Description |
|---|---|---|
| `--yara-dir DIR` | YARA hunt | Use an explicit directory of `.yar`/`.yara` files instead of packaged rules |
| `--ref-dir DIR` | stomping hunt | Directory of analyst-supplied reference modules, matched by basename |
| `--rules-file FILE` | rule-driven hunts | Use an explicit `rules.yaml`, `.yml`, or `.json` file instead of packaged defaults |
| `--triage-skipped` | `--hunt all` | Opt-in budgeted deep-content triage of the skipped-target investigation queue (see below) |

### Report options

| Option | Applies to | Description |
|---|---|---|
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

`--triage-skipped` performs a REAL, budgeted content read of each target in
`--hunt all`'s own skipped-target investigation queue (see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#skipped-target-investigation-queue)),
reusing `--report`'s own triage collector directly — never spawning a second
`dumpex` process, and never the unbounded, up-to-256-MiB-per-region read
`--report` itself allows. Three fixed limits bound the whole pass (a
per-target byte cap, a whole-run byte cap, and a maximum target count); once
either is exhausted, remaining targets are marked `budget_deferred` rather
than read past the intended budget. This is genuinely more expensive than
the default metadata-only pass — expect real, if bounded, additional I/O
and CPU time proportional to the queue's size — which is why it is opt-in
rather than automatic. It has no effect on a single-hunter `--hunt <name>`
run (there is no investigation queue to triage), and it never changes a
hunt's detection verdicts, coverage status, or exit code — only the
advisory `investigation_actions[].triage`/`.recommended_actions` fields and
the console's SKIPPED TARGET ACTIONS section.

## Output and evidence options

| Option | Description |
|---|---|
| `--json FILE` | Write structured JSON results |
| `--txt FILE` | Write an ANSI-free copy of console output |
| `--force` | Allow replacement of an existing output file; never permits replacing an input dump |
| `--case-id ID` | Record a case or ticket identifier in JSON metadata |
| `--analyst NAME` | Record the analyst name or handle in JSON metadata |
| `--redact-paths` | Reduce absolute evidence, rules, YARA, reference, and (for `--extract`) output/artifact paths to basenames in JSON metadata |

Output files are not overwritten unless `--force` is present. dumpex also
refuses any output path that resolves to an input dump path, and refuses to
run at all if two of `--output`/`--json`/`--txt` (or `--extract`'s own
auto-generated default filename) would resolve to the same file — a later
write silently clobbering an earlier one's output is never allowed, even
with `--force`.

`--json` routes through a single contract for every mode:
`--list`/`--modules`/`--threads`/`--process`/`--sysinfo`/`--handles`/
`--profile`/`--diff`/`--extract`/`--strings`/`--report`/`--hunt` all use
the v2 contract (canonical records, `null` for missing values, normalized
hex addresses — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#v2-structured-output)).
All twelve commands support `--json` on this same v2.13 contract, the
single atomic cutover that replaced `--pid`/`--peb` (result kinds
`"pid"`/`"peb"`) with `--process`/`--handles`/`--profile` (result kinds
`"process"`/`"handles"`/`"profile"`) with no hidden alias between the
old and new flags;
`--hunt` was the last to migrate — its `result.kind` is `"hunt"` and
`result.data.records` holds one `hunterRecord` per hunter.
`--diff` produces a `kind: "comparison"` result with a two-entry
`meta.evidence` array (`baseline`/`target`) instead of the single-dump
`meta` shape the other ten use — see
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
reports coverage independent of `--json`: `0` for complete coverage,
`3` for partial (e.g. `--threads` on a dump missing `ThreadInfoListStream`
while the base thread list is still present, or `--extract`/`--strings`
reading fewer bytes than requested), `4` when the one stream the command
needed is entirely absent (e.g. `--modules` when `ModuleListStream`
itself isn't in the dump at all). `--hunt` follows the same convention now
too — `0`/`3`/`4` based on whether every selected hunter, any hunter, or
none reached a conclusive result — instead of its old unconditional `0`.

See [Output and Evidence Schema](OUTPUT_SCHEMA.md) for formats and metadata.

## Verbose recon output

`--verbose` changes what `--process` and `--handles` **print**. It never
changes what they collect: the records, coverage, limitations, summary
counts and exit code are identical with and without it, so `--json` is
always the complete, lossless evidence surface.

### `--handles`

The default console folds **anonymous** handle rows — rows whose object
name the descriptor positively records as absent — into per-type counts:

```text
  13 anonymous handle(s) not shown (no object name recorded): Event 9, Semaphore 3, Key 1
  These rows are captured evidence and are complete in structured output -- use --verbose to show all.
```

Those rows are still captured, still counted in the headline and the
`By type:` line, and still in `--json`. `--verbose` prints all of them.

Anonymous `Process`, `Thread`, `Token`, `Section` and `Job` handles are
**never** folded — those are the ones a cross-process access question
turns on — and neither is any row whose name could not be read. Every
other anonymous type folds, and the fold line always names the type and
its exact count, so nothing disappears unnamed.
The two states are different facts and the console keeps them apart:

- `(unnamed)` — the descriptor records no name. Nothing was lost.
- `(unreadable)` — a name should have been there and the bounded read
  or decode failed. Evidence was lost, and the run reports it as a
  coverage limitation.

Common NT Object Manager names are explained under `Object name notes`.
For example, `\KnownDlls` is an Object Manager **directory**, not a
filesystem path and not a list of DLLs; the handle descriptor records
its name only, and the objects inside it are not captured by it. dumpex
never expands such a directory from the machine running the analysis.

### `--process`

`--verbose` adds three blocks:

- **The import table**, with headers and a legend for its address pair.
  Each row reads `IAT Slot VA -> Resolved Target VA`: the slot is the
  address where the import pointer is stored, and the target is the
  address stored in that slot in the captured process memory. A slot
  outside the recorded import directory bounds is flagged with `*` — an
  observation about the dump's directory framing, not a verdict about
  the import.
- **`Identity Verification`**, which shows the selected path and name,
  the source they came from, and one line per independent check with an
  explicit state: `[OK]`, `[!!]` (conflict), or `[--]` (could not be
  evaluated). The checks are ModuleList registration of the PEB image
  base, PEB/ModuleList process-name agreement, PE-header validity at the
  image base, and whether another module competes for the same name. The
  raw per-source claims follow underneath. A conflict is an
  **observation**: it never becomes a maliciousness verdict, a command
  failure, or a change to the exit code.
- **`Extended PEB`**, the fields the retired `--peb` command used to
  print, also published as `peb_extended` in `--json`.

Every string in these blocks that came out of the dump — paths, names,
DLL and API names, window title — is escaped before it reaches the
terminal, so a hostile name cannot forge dumpex's own output. `--json`
keeps the exact decoded bytes.

## Examples

### Recon

```bash
dumpex sample.dmp --sysinfo
dumpex sample.dmp --process
dumpex sample.dmp --process --verbose
dumpex sample.dmp --handles
dumpex sample.dmp --handles --verbose
dumpex sample.dmp --profile
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

# Deep-triage the skipped-target queue under an explicit budget
dumpex sample.dmp --hunt all --triage-skipped
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
dumpex suspect.dmp --diff clean-reference.dmp
dumpex suspect.dmp --diff clean-reference.dmp --diff-scope memory
```

The positional dump is always the analysis target; the dump passed to
`--diff` is the baseline/reference. Thus "added", "new", and "changed to"
records describe the positional dump relative to the reference.
`--diff-scope` is not a standalone command; it only narrows an existing
`--diff` comparison. The older `--diff-mode` spelling remains accepted as
a hidden compatibility alias for existing scripts.

### Extraction and strings

```bash
dumpex sample.dmp --extract 0x7ff600001000 --size 0x1000 --output region.bin
dumpex sample.dmp --strings 0x7ff600001000 --min-len 8
dumpex sample.dmp --strings 0x7ff600001000 --strings-encoding unicode --grep "(?i)https?://"
```

### Case-ready output

```bash
dumpex sample.dmp --hunt all \
  --json result.json \
  --txt transcript.txt \
  --case-id CASE-1234 \
  --analyst analyst01
```

Add `--redact-paths` when the JSON will leave the analyst workstation.
