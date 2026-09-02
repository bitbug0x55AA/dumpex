# SOC / DFIR Quick Start

This guide is for analysts triaging a Windows process minidump with dumpex. It
connects the recon, hunt, report, comparison, and extraction commands into one
workflow and explains how to disposition their output.

It is not a flag or schema reference. Use the [CLI Reference](CLI_REFERENCE.md)
for every option, [Detection Methodology](DETECTION_METHODOLOGY.md) for detection
logic, and [Output and Evidence Schema](OUTPUT_SCHEMA.md) for the complete JSON
contract.

## Command map

Every command has a role in the investigation; the sequence is a guide, not a
requirement.

| Stage | Command | Analyst question |
|---|---|---|
| Evidence boundary | `--profile` | What streams were captured, and which analysis capabilities are available, limited, or unavailable? |
| Evidence identity | `--sysinfo` | Which dump, host, OS, architecture, environment, and capture time am I examining? |
| Process recon | `--process` | What identity, command line, image base, imports, and PEB/module consistency were recorded? |
| Object recon | `--handles` | Which captured objects could this process access, with what rights? |
| Memory recon | `--list` | Which regions, types, states, and protections were recorded? |
| Module recon | `--modules` | Which images were loaded and where? |
| Thread recon | `--threads` | Where were threads executing, and what context was captured? |
| TTP triage | `--hunt TTP` | Which implemented TTP indicators are supported by the captured evidence? |
| Focused investigation | `--report` | What thread, region, module, strings, and suspicious properties surround a known TID, address, or string? |
| Evidence recovery | `--extract ADDR` | Can I preserve captured bytes from a target region for other tools? |
| Content review | `--strings ADDR` | Which ASCII/Unicode strings are present around a target address? |
| Change analysis | `--diff REFERENCE` | What changed in this dump relative to a baseline dump? |

## 1. Establish the evidence boundary

Start with `--profile`; it prevents a small or incomplete dump from being
mistaken for negative evidence:

```bash
dumpex sample.dmp --profile --json profile.json \
  --case-id CASE-1234 --analyst analyst01
dumpex sample.dmp --sysinfo --json sysinfo.json \
  --case-id CASE-1234 --analyst analyst01
```

`--profile` is an evidence-capability map, not a verdict. An `unavailable`
capability means the dump lacks evidence required for that analysis; it does
not mean the corresponding behavior was absent. `--profile` itself can have
complete command coverage while some downstream capabilities are unavailable.

Use `--sysinfo --verbose` cautiously: environment variable values may contain
secrets. JSON is always complete, so protect it as case evidence.

## 2. Build process context with recon

Run the recon views before or alongside hunting:

```bash
dumpex sample.dmp --process --verbose --json process.json
dumpex sample.dmp --handles --verbose --json handles.json
dumpex sample.dmp --list --json memory.json
dumpex sample.dmp --modules --json modules.json
dumpex sample.dmp --threads --json threads.json
```

Use `--list --filter PAGE_EXECUTE_READWRITE` for a fast RWX review, but do not
treat RWX memory alone as injection. Correlate regions with modules, thread
instruction pointers, hunter findings, and the focused report.

Recon describes what the dump recorded at capture time; it never queries the
live analysis host. Keep these reading rules in mind:

- `--verbose` changes console presentation only. JSON retains the complete
  inventory and the same coverage and limitations.
- `(unnamed)` means the descriptor recorded no name. `(unreadable)` means a
  name was expected but could not be recovered, which is a coverage gap.
- Handle rights are object-type-specific. Interpret the access mask using that
  row's `Type`; a decoded right shows capability, not use or malicious intent.
- A PEB/ModuleList identity conflict is a lead, not a verdict. Corroborate it
  with hollowing/injection evidence and other telemetry.

See [Verbose recon output](CLI_REFERENCE.md#verbose-recon-output) for the full
console conventions.

## 3. Run and preserve hunts

Run all hunters for broad triage:

```bash
dumpex sample.dmp --hunt all --json hunt.json --txt hunt.txt \
  --case-id CASE-1234 --analyst analyst01
```

Use a focused hunter to answer a narrower question or rerun with better inputs:

```bash
dumpex sample.dmp --hunt injection --json injection.json
dumpex sample.dmp --hunt stomping --ref-dir trusted-modules --json stomping.json
dumpex sample.dmp --hunt yara --yara-dir case-yara --json yara.json
```

Without `--ref-dir`, module stomping's scored content comparison cannot run and
the hunter is `INCONCLUSIVE`; score `0` is not clean. References must be trusted
DLL/EXE files from the same architecture, build, and patch level. A same-named
file from an unrelated host is not ground truth.

An explicit `--rules-file` or `--yara-dir` should be preserved with the case.
The JSON records the evidence, execution options, and rules provenance needed
to reproduce the run.

## 4. Read hunt results in the right order

Read structured output from the outside in:

1. Confirm `result.execution_status` and review `diagnostics`.
2. Read run-wide `result.coverage.status`.
3. Read `result.summary`, then each entry in `result.data.records[]`.
4. Interpret each hunter's `status` together with its `coverage.status`.
5. Review findings, limitations, and skipped-target actions before disposition.

| Field | Analyst question |
|---|---|
| `status` | Did this hunter detect evidence, complete without a detection, stop inconclusively, or not run? |
| `coverage.status` | Did the dump and scan limits allow all required evidence to be examined? |
| `verdict_level` | How strongly does the hunter classify its overall result? |
| `confidence` | How much weight does it place on its strongest detection finding? |

`status` and `coverage.status` are separate axes. `DETECTED` with `partial`
coverage remains a positive finding; the gap means other evidence may still be
unexamined. `NOT_DETECTED_IN_SCANNED_SCOPE` with complete coverage is a scoped
non-detection, not proof that the process or host is clean.

### Disposition matrix

| `status` | Typical coverage | Interpretation | Action |
|---|---|---|---|
| `DETECTED` | `complete` | Corroborated evidence was found and eligible scope was examined | Escalate by TTP and validate against endpoint, timeline, network, and binary evidence |
| `DETECTED` | `partial` | The positive finding stands, but other evidence was skipped or unavailable | Escalate the finding and separately close or document the gap |
| `NOT_DETECTED_IN_SCANNED_SCOPE` | `complete` | No indicator was found in the evidence this hunter examines | Record only as a scoped non-detection |
| `INCONCLUSIVE` | `partial` | The hunter examined something but could not support a detection or clean scoped result | Resolve its reasons/limitations and rerun when practical |
| `NOT_EVALUATED` | `not_evaluated` | Required evidence was absent or unusable | Record the TTP as not checked; recollect if the question matters |

Never translate `INCONCLUSIVE` or `NOT_EVALUATED` into “clean.” Treat
`possible` as a review priority, not attribution or confirmation.

### Read findings as evidence, not labels

For structured `findings`, combine `facts`, `inference`, `confidence`,
`rationale`, and `limitations`. The `tag` tells you whether an entry is a raw
`observation`, an unverified `lead`, or a corroborated `detection` that can
drive score. Write the case note from those fields, not from score alone.

YARA uses its own model: read `details.matches`, `details.rules_hit`, and
`coverage`. It does not emit the other hunters' structured
`findings`/`confidence` shape. Complete downstream fields are documented under
[Hunt records](OUTPUT_SCHEMA.md#hunt-records).

## 5. Turn leads into focused reports

`--report` is the bridge from a recon/hunter/EDR clue to a reviewable triage
card. Anchor it to one known TID, address, or string:

```bash
dumpex sample.dmp --report --report-tid 0x1234 --json report-thread.json
dumpex sample.dmp --report --report-addr 0x7ff600001000 --json report-region.json
dumpex sample.dmp --report --report-string "powershell" --json report-string.json
```

The report correlates the anchor with its thread, memory region, module
backing, protection, strings, PE/header context, and coverage. String mode
searches captured memory and produces a card for each actionable private-memory
hit; module-backed hits remain summary context. A “not found” result is not
clean when the string scan reports unreadable, truncated, or clamped regions.

Use `--output region.bin` with `--report` when the surrounding captured region
must be handed to YARA, a disassembler, or malware analysis. For a known
address, direct extraction and targeted strings are also useful:

```bash
dumpex sample.dmp --extract 0x7ff600001000 --size 0x1000 --output region.bin
dumpex sample.dmp --strings 0x7ff600001000 --min-len 8 \
  --strings-encoding both --grep "(?i)https?://"
```

Preserve the source virtual address, requested size, output hash, and the report
JSON with every extracted artifact.

## 6. Close coverage gaps

Use `coverage.reasons` for the explanation and `coverage.limitations[]` for
structured targets. Common causes are missing streams, unreadable/short data,
oversized regions, scan budgets, YARA compile/runtime failures, and missing
stomping references.

For `SCAN_REGION_OVERSIZED_SKIPPED`, inspect `targets[]`:

- Prioritize executable `MEM_PRIVATE` or RWX memory, without treating priority
  as proof of maliciousness.
- A present `file_offset` means the captured range can be extracted or reported.
- `file_offset: null` means the bytes are not in this dump; recollection is the
  only way to recover them.

On `--hunt all`, `result.summary.investigation_actions` deduplicates skipped
regions and orders follow-up. The queue remains metadata-only and performs no
additional skipped-region content reads. `--triage-skipped` is temporarily
unavailable and fails before analysis instead of running or being ignored.
Historical v2.10-v2.13 JSON may contain retired deep-mode IOC/header leads;
those leads never upgraded the original verdict or coverage. Only the
originating hunter's successful targeted rescan can close its coverage gap.

The console/`--txt` `SKIPPED TARGET ACTIONS` section prints the rescan to run
for each eligible entry — one `--hunt-addr` command per skipping hunter that has
a targeted capability, with the dump path quoted so the line means the same
thing in a POSIX shell, PowerShell, and `cmd.exe`. Work it top down:
the queue is already ordered by priority.

- Run the command as printed. It names the range the queue named, capped at the
  hunter's request ceiling; a capped command is labelled supplementary and
  covers that piece only.
- Match the new result back on `hunter + source + scope + base_address + size`,
  which the rescan's own `summary.scan_scope` carries. Nothing merges
  automatically, and the original entry keeps
  `coverage_effect: original_hunter_gap_not_resolved`.
- Close a relationship only when its own scope came back `complete`. One target
  can carry two relationships from the same hunter — a pipe region that ran out
  of budget for both `pipe_name` and `c2_context` — and one rescan may close one
  of them and not the other.
- `No targeted rescan for: ...` means those hunters have no `--hunt-addr`
  capability. Their gap stays open; document it rather than reading the
  remaining commands as full closure.
- `Rescan: unavailable` means the bytes are not in this dump. Recollect;
  a local scan would read nothing and must not be recorded as a negative.
- An entry that prints arguments without a command means this dump's own path
  holds characters a shell would expand or execute, so no command line could
  carry it unchanged. Run those arguments against the dump yourself, quoting the
  path your shell's way; do not reconstruct the line by pasting the path in.

Everything a rescan reports applies to the bytes it evaluated. A
`NOT_DETECTED_IN_SCANNED_SCOPE` rescan is not a clean verdict for the rest of the
target, for the hunter's other sources, or for the dump.

The console/`--txt` `CORRELATED REGIONS` section means different hunters placed
evidence in the same normalized memory region. It is a location correlation,
not a new verdict, and changes no score, confidence, or coverage.

## 7. Compare when a baseline exists

Use `--diff` when a known earlier or reference dump is available:

```bash
dumpex suspect.dmp --diff clean-reference.dmp --diff-scope all \
  --json diff.json
```

The positional dump is the target; the dump passed to `--diff` is the baseline.
“Added,” “new,” and “changed to” describe the target relative to that baseline.
A difference is an observation requiring context, not automatically malicious.

## Hunter-specific boundaries

| Hunter | What deserves attention | Important boundary |
|---|---|---|
| `injection` | Validated hidden PE structure plus executable private/RWX memory and thread context | RWX or MZ alone can be produced by JITs, debuggers, or packers |
| `hollowing` | Correlated image-base, mapping, header, and protection anomalies | One anomaly is a lead; unreadable image evidence creates a gap |
| `stomping` | Relocation-normalized code differences, especially with execution in changed bytes | Scored comparison needs an identity-matched `--ref-dir`; hotpatches and security hooks can modify code legitimately |
| `pipe` | An OS-recorded pipe handle corroborated by C2 context or execution | A pipe-like memory string is an unscored lead; handle proof needs `HandleDataStream` |
| `cs-beacon` | A structurally valid decoded Beacon config with memory/thread context | Config presence does not prove active network callbacks |
| `yara` | Matches with verified memory context and complete compile/read/time coverage | Only captured bytes and successfully loaded rules are scanned |
| `obfuscation` | Confirmed Sleep Mask decode or structurally validated PE payload | Entropy, Base64-like data, and GZIP magic alone are benign-compatible observations |

See [Detection Methodology](DETECTION_METHODOLOGY.md) for scoring thresholds,
relocation handling, rule selection, false positives, and ATT&CK mapping.

## Exit codes and automation

Exit codes summarize coverage, not detections:

| Exit code | Coverage | Meaning |
|---|---|---|
| `0` | `complete` | The selected analysis completed; findings may still exist |
| `3` | `partial` | At least one selected analysis had a coverage gap |
| `4` | `not_evaluated` | The selected analysis could not evaluate required evidence |

Never use exit code `0` as a “no detection” test. Read `status` and
`verdict_level` for disposition.

## Evidence and handoff checklist

- Preserve the original dump and JSON; verify `meta.evidence` hashes.
- Record `meta.execution`, `meta.rules`, and `meta.yara_rules` for reproducibility.
- Separate positive findings from coverage gaps in case notes.
- State which capabilities and hunters were unavailable, `INCONCLUSIVE`, or
  `NOT_EVALUATED`.
- Preserve focused reports and extracted artifacts with their source addresses.
- Add `--redact-paths` before sharing JSON outside the collection environment;
  separately sanitize sensitive strings and findings.
- Corroborate high-impact claims with endpoint telemetry, process ancestry,
  binaries, network evidence, timelines, or a broader memory capture.

## Scope statement

“Dumpex found nothing” is not the same as “this host is clean.” dumpex analyzes
one process at one capture time, using only streams and bytes in that minidump
and the selected hunters/rules. A fully covered
`NOT_DETECTED_IN_SCANNED_SCOPE` result means no indicators were found in that
defined scope. It says nothing about uncaptured memory, other processes, or
activity before or after collection.

## Related documentation

- [CLI Reference](CLI_REFERENCE.md): complete commands, options, and examples.
- [Detection Methodology](DETECTION_METHODOLOGY.md): validation and scoring.
- [Output and Evidence Schema](OUTPUT_SCHEMA.md): JSON, coverage, and provenance.
- [Changelog](../../CHANGELOG.md): release and output-contract history.
