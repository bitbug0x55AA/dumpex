# CLI Reference

This page is the current command and option reference for dumpex. For an
investigation workflow and disposition rules, use the
[SOC / DFIR Quick Start](SOC_QUICKSTART.md). For JSON fields, use
[Output and Evidence Schema](OUTPUT_SCHEMA.md).

## Command shape

```text
dumpex DUMPFILE COMMAND [OPTIONS]
python -m dumpex DUMPFILE COMMAND [OPTIONS]
```

Exactly one command is required. The positional `DUMPFILE` is always the
primary analysis target. Addresses and thread IDs accept hexadecimal or decimal
forms where documented by the option.

## Commands

| Mode | Purpose |
|---|---|
| `--list` | List captured memory regions |
| `--modules` | List loaded modules |
| `--threads` | List threads with captured analysis context |
| `--extract ADDR` | Extract raw bytes from the region containing `ADDR` |
| `--strings ADDR` | Extract ASCII/Unicode strings from a captured range |
| `--process` | Show consolidated process identity, IAT, and verification evidence |
| `--handles` | List captured `HandleDataStream` descriptors |
| `--profile` | Describe dump streams, capture facts, and analysis capabilities |
| `--sysinfo` | Show dump identity, OS, host, CPU, and environment evidence |
| `--diff REFERENCE` | Compare the target dump against a baseline dump |
| `--report` | Generate triage cards anchored to a TID, address, or string |
| `--hunt TTP` | Run `injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, `obfuscation`, or `all` |

## Memory and extraction options

| Option | Applies to | Description |
|---|---|---|
| `--filter PROT` | `--list` | Keep regions whose protection matches `PROT` |
| `-s SIZE`, `--size SIZE` | `--extract`, `--strings` | Requested range size in hexadecimal |
| `-o FILE`, `--output FILE` | `--extract`, `--report` | Write extracted region bytes |

Without `--output`, `--extract` creates `region_0x<address>.bin` in the current
directory. A short captured range is still written when possible and reported
as partial coverage.

## String options

| Option | Description |
|---|---|
| `--grep REGEX` | Keep strings matching a regular expression |
| `--min-len N` | Minimum string length; default `6` |
| `--strings-encoding ascii\|unicode\|both` | Encoding to scan; default `both` |

These options modify `--strings`; `--min-len` also controls report string
collection. The older hidden `--encoding` alias remains accepted for existing
scripts.

## Diff options

| Option | Description |
|---|---|
| `--diff-scope modules\|threads\|memory\|all` | Evidence type to compare; default `all` |

The positional dump is the target and `--diff REFERENCE` is the baseline.
“Added,” “new,” and “changed to” records describe the target relative to the
baseline. The older hidden `--diff-mode` alias remains accepted.

## Display options

| Option | Applies to | Description |
|---|---|---|
| `--verbose` | `--process`, `--handles`, `--sysinfo`, `--diff`, `--hunt` | Print additional console detail |

`--verbose` does not change JSON records, coverage, limitations, summary, or
exit code. `--profile` accepts and records it but its own output is already
complete and does not change.

## Hunt options

| Option | Description |
|---|---|
| `--hunt-addr ADDR` | Rescan one virtual-address range with the selected hunter instead of the whole dump; requires `--hunt <TTP>` and `--size SIZE` |
| `--yara-dir DIR` | Use an explicit directory of `.yar`/`.yara` rules for YARA hunting |
| `--ref-dir DIR` | Supply reference DLL/EXE files for module-stomping comparison |
| `--rules-file FILE` | Use an explicit TTP rules YAML/JSON file |
| `--triage-skipped` | Temporarily unavailable; name reserved for future analyzer-aware recovery orchestration |

An explicit `--rules-file` fails closed if missing, unreadable, malformed, or
unsupported; dumpex does not silently fall back to another ruleset. The
`--ref-dir` path is validated before analysis and should contain trusted,
same-build reference modules.

`--triage-skipped` currently fails with argparse usage exit code `2` before the
dump is opened, rules are loaded, scans begin, or output artifacts are created.
It is never a silent no-op. Without the flag, `--hunt all` continues to build
the metadata-only skipped-target investigation queue without additional content
reads. Only a successful targeted rescan by the originating hunter can close
that hunter's coverage gap.

### Targeted rescans (`--hunt-addr`)

```bash
dumpex suspect.dmp --hunt <hunter> --hunt-addr <address> --size <size>
```

`--hunt-addr` is a modifier, not a command. It asks one hunter to evaluate the
half-open range `[address, address + size)` instead of the whole dump, reusing
that hunter's own detection rules, scores, evidence types, and coverage
vocabulary. It exists to revisit a range a full-scope scan skipped for size —
it bypasses only the selected scanner's per-region or per-segment size cap.
Every other budget (time, total bytes, candidates, matches, decode output,
retained evidence) stays enforced.

Supported hunters: `stomping`, `pipe`, `cs-beacon`, `yara`, `obfuscation`.
`injection`, `hollowing`, and `--hunt all` are rejected — `all` is a selection
mode, not an analyzer, and the other two have no targeted-scan capability.

| Rule | Behavior |
|---|---|
| `--hunt-addr` without `--hunt` or `--size` | Usage error, exit `2` |
| Unparsable address or size, non-positive size, an end past the 64-bit address space, or a size over the hunter's request ceiling | Usage error, exit `2` |
| Unknown, `all`, or targeted-unsupported hunter | Hunt error, exit `1` |
| `--size` with `--hunt` but no `--hunt-addr` | Usage error, exit `2` — a targeted invocation missing its address, never a silently unbounded whole-dump hunt |
| A hunt option the selected hunter's targeted rescan does not read (`--ref-dir` for any hunter, `--yara-dir` for any hunter but `yara`) | Usage error, exit `2` — refused rather than recorded in the result and ignored |

Request ceilings are 256 MiB for `stomping`, `pipe`, `cs-beacon`, and `yara`,
and 32 MiB for `obfuscation`. Both address and size accept `0x`-prefixed
hexadecimal or plain decimal. Nothing is wrapped, clamped, or inferred: a range
larger than a ceiling is refused rather than truncated, and a short capture is
reported as a short read against the range you asked for.

A rescan closes its own granted coverage source and nothing else. The console
names the hunter's other sources under `NOT COVERED BY THIS RESCAN`, and
structured output lists each of them as an absent source with its own
limitation — so a `complete` targeted result for one source is never readable
as complete coverage for the hunter.

For the same reason, a hunt option that only feeds one of those other sources
is refused instead of accepted and ignored: `--ref-dir` supplies reference
modules for stomping's content comparison, which a targeted rescan does not
run, so `--hunt stomping --hunt-addr` rejects it rather than record a
directory in the result that nothing read. `--yara-dir` is accepted for
`--hunt yara`, whose targeted rescan really does resolve rules through it, and
rejected for every other hunter.

Every conclusion applies to the requested range only. An address the dump holds
no bytes for is valid input and produces a not-evaluated result, never a clean
one, and a rescan never closes a coverage gap recorded by an earlier run. The
console prints the normalized range, one row per coverage closure with capture
and evaluation reported separately, and a closing statement naming the exact
scope of the result. Structured output carries the same facts as
`summary.scan_scope` and `details.targeted_scope` (see
[Output and Evidence Schema](OUTPUT_SCHEMA.md)); exit codes follow the usual
coverage mapping — `0` complete, `3` partial, `4` not evaluated.

### Rescan commands in the skipped-target queue

`--hunt all` ends with a `SKIPPED TARGET ACTIONS` section listing the ranges a
hunter left unexamined. Each eligible entry prints the exact command to run
next — one per skipping hunter that has a targeted capability, quoted for the
dump path you passed:

```text
  [HIGH] 0x00000000007ff000  64 MB  captured
       Skipped by: pipe/pipe_name_scan:pipe_name (scan budget exhausted),
       pipe/pipe_name_scan:c2_context (scan budget exhausted),
       obfuscation/encoding_scan:entropy (scan truncated)
       Rescan (match the new result back by hunter + source + scope + base_address + size):
         dumpex "C:\cases\case 7.dmp" --hunt pipe --hunt-addr 0x7ff000 --size 0x4000000
         dumpex "C:\cases\case 7.dmp" --hunt obfuscation --hunt-addr 0x7ff000 --size 0x2000000
```

The rules behind that block:

| Situation | What is offered |
|---|---|
| One target, several relationships from the same hunter | One command for that hunter. A pipe region that exhausted the budget for both `pipe_name` and `c2_context` is one range and one rescan; its result is reconciled against both relationships |
| A skipping hunter with no targeted capability (`injection`, `hollowing`) | No command. The hunters are named under `No targeted rescan for:` — their coverage gap on that target stays open |
| A target whose bytes this dump never captured | No command. The entry says so and recommends recollection: a local scan of a range the dump does not hold reads nothing |
| A target larger than the hunter's request ceiling | One capped command covering the first ceiling-sized piece, labelled supplementary. Rescanning the remaining pieces is a separate decision, and chunked rescans never add up to coverage of the whole range |
| A budget limitation that names a reason but no target | No queue entry, and therefore no command. A range is never invented to make one |

A rescan produces a separate result document. Nothing merges it back into the
run that recommended it: the queue entry keeps
`coverage_effect: original_hunter_gap_not_resolved`, and you reconcile the two
yourself on `hunter + source + scope + base_address + size` — the key
`summary.scan_scope` carries in the new document. A relationship is closed only
when the scope that actually failed comes back `complete` in the rescan; a pipe
rescan that closes `pipe_name` and only partly evaluates `c2_context` closes
one of its two originating relationships, not both.

Evaluation stops at the end of the descriptor holding the requested base
address, so a command that crosses a region or segment boundary comes back
`partial` with `SCAN_REGION_EVALUATION_TRUNCATED` rather than silently claiming
the whole range. Everything a rescan reports is scoped to the bytes it
evaluated: a `NOT_DETECTED_IN_SCANNED_SCOPE` result for one range is not a
statement about the rest of the target, about the hunter's other sources, or
about the dump.

With `--redact-paths`, the rendered command names the dump by basename, the
same reduction the flag applies to paths in structured output. The command still
runs, from the directory holding the dump.

Structured output carries no command string. `--json` gives you the target's
`base_address` and `size` plus the hunters a rescan can name, in
`summary.investigation_actions[].recommended_actions`; build the invocation
from those under your own shell's quoting rules.

## Report options

| Option | Description |
|---|---|
| `--report-tid TID` | Anchor a report to a thread ID |
| `--report-addr ADDR` | Anchor a report to a memory address |
| `--report-string STRING` | Search memory and report each actionable matching region |

`--report` requires at least one anchor. For clear provenance, prefer one anchor
per invocation. Address/TID mode produces one triage card; string mode searches
captured memory and produces a card for each actionable private-memory hit.
`--output` extracts each card's surrounding captured region, disambiguating
filenames when string mode produces several cards.

## Output and case metadata

| Option | Description |
|---|---|
| `--json FILE` | Write canonical structured output |
| `--txt FILE` | Write an ANSI-free console transcript |
| `--force` | Allow replacement of existing output files, never input dumps |
| `--case-id ID` | Record a case/ticket identifier in JSON metadata |
| `--analyst NAME` | Record the analyst name/handle in JSON metadata |
| `--redact-paths` | Reduce filesystem paths to basenames in JSON metadata and in the rescan commands the skipped-target queue renders |

Dumpex rejects an output path that resolves to an input dump. It also rejects
collisions among `--output`, `--json`, `--txt`, and `--extract`'s generated
filename, even with `--force`.

`--redact-paths` protects local directory layout only. It does not sanitize
environment values, command lines, strings, IOCs, or other memory content.

## Command details

### `--profile`

Use `--profile` to establish what the dump can support before interpreting
absence as negative evidence. It reports:

- the raw minidump stream directory and parser state for every entry;
- header flags separately from actual captured-memory segments/bytes;
- six fixed capabilities: memory-region, module, injection-artifact, thread,
  handle, and injector-handle assessment;
- `available`, `limited`, or `unavailable` status with structured limitations.

Capability availability is an evidence boundary, not a hunt verdict.
`--profile` command coverage can be complete even when downstream capabilities
are unavailable because their source streams were never captured.

### `--sysinfo`

Reports dump filename/size/SHA-256/time, OS and architecture, host and CPU, and
captured environment facts. `--verbose` prints environment values, which may
contain credentials, tokens, usernames, and internal paths. JSON should be
handled at the same sensitivity as the dump.

### `--process`

Consolidates PID, path/name, command line, start time, image base, source claims,
IAT entries, and identity diagnostics. `--verbose` adds:

- `IAT Slot VA -> Resolved Target VA` entries;
- identity verification states (`[OK]`, `[!!]`, `[--]`);
- extended PEB fields.

An identity conflict is an observation requiring corroboration, not a command
failure or maliciousness verdict.

### `--handles`

Requires captured `HandleDataStream`; otherwise coverage is `not_evaluated`.
Default console output folds routine anonymous rows but JSON retains every
descriptor. `--verbose` prints the complete inventory.

`(unnamed)` and `(unreadable)` are different evidence states. Access masks are
decoded against each row's object type while the JSON `granted_access` integer
remains unchanged. See [Handle Access Rights Reference](HANDLE_RIGHTS_REFERENCE.md)
for type-specific rights, aliases, provenance markers, and Windows-version
differences.

### `--list`, `--modules`, and `--threads`

These commands provide the primary region/module/thread inventories used to
correlate hunter and report output. An empty captured stream is different from
a missing stream; consult `coverage.sources` before interpreting an empty
record list.

`--threads` uses available thread and thread-info evidence and reports partial
coverage when context/timing sources are missing. `--list --filter` is a fast
projection, not a detection verdict.

### `--hunt`

`--hunt all` runs the seven hunters in the fixed order shown in the command
table and prints a summary plus per-hunter details. A focused `--hunt <name>`
runs only that analyzer.

Each hunter reports status, coverage, and verdict semantics. `DETECTED` with
partial coverage remains a positive finding; `INCONCLUSIVE` and
`NOT_EVALUATED` are not clean outcomes. See the
[SOC disposition matrix](SOC_QUICKSTART.md#disposition-matrix) and
[Detection Methodology](DETECTION_METHODOLOGY.md).

### `--report`

Builds a focused triage card around an alert or hunt pivot. It correlates the
anchor with thread, region, module backing, protection, strings, PE/header
context, verdict dimensions, and coverage. A string not found during an
incomplete scan is not a clean result.

### `--extract` and `--strings`

Both resolve the region containing the requested address and operate only on
captured bytes. `--extract` preserves raw bytes for other tools; `--strings`
extracts ASCII/Unicode content with optional regex filtering. Neither command
can recover bytes that were never written into the dump.

### `--diff`

Compares module, thread, and/or memory evidence between the target and baseline.
A change is an observation; its meaning depends on capture comparability and
case context. Coverage is reported independently for each side/source.

## Structured output and exit codes

All commands use the current shared JSON envelope. See
[Output and Evidence Schema](OUTPUT_SCHEMA.md) for the result-kind mapping and
field semantics.

| Exit code | Coverage | Meaning |
|---|---|---|
| `0` | `complete` | Selected analysis completed; findings may still exist |
| `3` | `partial` | Useful analysis completed with one or more evidence gaps |
| `4` | `not_evaluated` | Required evidence was unavailable |

Fatal CLI/argument errors use other nonzero exits. Never use exit code `0` as a
“no detection” test.

## Examples

### Recon

```bash
dumpex sample.dmp --profile --json profile.json
dumpex sample.dmp --sysinfo
dumpex sample.dmp --process --verbose
dumpex sample.dmp --handles --verbose
dumpex sample.dmp --list --filter PAGE_EXECUTE_READWRITE
dumpex sample.dmp --modules
dumpex sample.dmp --threads
```

### Hunting and focused reporting

```bash
dumpex sample.dmp --hunt all --json hunt.json
dumpex sample.dmp --hunt stomping --ref-dir trusted-modules
dumpex sample.dmp --hunt yara --yara-dir case-yara
dumpex sample.dmp --hunt obfuscation --hunt-addr 0x7ff600001000 --size 0x400000

dumpex sample.dmp --report --report-tid 0x1234
dumpex sample.dmp --report --report-addr 0x7ff600001000 --output region.bin
dumpex sample.dmp --report --report-string "powershell" --json report.json
```

### Extraction, strings, and comparison

```bash
dumpex sample.dmp --extract 0x7ff600001000 --size 0x1000 --output region.bin
dumpex sample.dmp --strings 0x7ff600001000 --min-len 8 \
  --strings-encoding unicode --grep "(?i)https?://"
dumpex suspect.dmp --diff clean-reference.dmp --diff-scope all
```

### Case-ready output

```bash
dumpex sample.dmp --hunt all \
  --json result.json --txt transcript.txt \
  --case-id CASE-1234 --analyst analyst01
```
