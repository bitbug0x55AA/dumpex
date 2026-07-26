# Detection Methodology and Coverage

dumpex is a triage engine, not a malware classifier. Its hunters combine
captured-memory characteristics, structural validation, execution context,
and rule matches to produce findings with explicit coverage and confidence.
A finding should be corroborated with process ancestry, endpoint telemetry,
full-memory analysis, binaries, and timeline evidence whenever those sources
are available.

For operational disposition guidance, see the
[SOC / DFIR Quick Start](SOC_QUICKSTART.md).

## Rules and source selection

The canonical TTP and YARA defaults are package resources:

```text
dumpex/rules_pkg/data/rules.yaml
dumpex/rules_pkg/data/yara/*.yar
```

They are declared as package data in `pyproject.toml`, so installed wheels and
PyInstaller builds retain the same resource layout. dumpex does not
automatically trust a `rules.yaml` or YARA directory in the current working
directory.

Source priority is:

1. An explicit analyst override supplied with `--rules-file` or `--yara-dir`.
2. A legacy `sys._MEIPASS/rules` compatibility path, but only when present in
   an older frozen executable.
3. The packaged defaults.
4. Built-in TTP defaults only if the packaged `rules.yaml` cannot be read.

An explicit `--rules-file` fails closed on missing, unreadable, malformed, or
unsupported content; dumpex will not silently replace it with another
ruleset. JSON metadata records the rules source and content hashes used for a
run. See [Output and Evidence Schema](OUTPUT_SCHEMA.md).

The TTP rules file controls:

- suspicious memory protections;
- common C2 named-pipe patterns;
- offensive-framework pipe patterns;
- PowerShell and shellcode indicators; and
- LOLBin keywords.

## Evidence model

Hunters distinguish three things that are easy to conflate:

- `status`: whether the hunter detected evidence, did not detect it in the
  scanned scope, could not reach a conclusion, or was not evaluated;
- `coverage_status`: whether the dump supplied all evidence required by that
  hunter; and
- `verdict_level` / `confidence`: how strongly the validated evidence supports
  the interpretation.

`DETECTED` with partial coverage is still a positive finding. Conversely,
`NOT_DETECTED_IN_SCANNED_SCOPE` is not proof that the behavior was absent from
the process or host. Exact disposition rules and per-hunter limits are in the
[SOC guide](SOC_QUICKSTART.md#the-four-fields-that-matter).

## Process injection

The injection hunter correlates suspicious page protection, PE structure,
thread instruction pointers, and page context. Executable private memory is a
useful lead but is not sufficient by itself for a high-confidence verdict;
JIT runtimes, packers, security products, and other legitimate software can
produce similar layouts.

High-confidence interpretations require stronger structural or execution
evidence, such as a validated in-memory PE or a thread executing in the
suspicious region. Missing thread context reduces coverage and confidence
rather than being interpreted as negative evidence.

## Process hollowing

The hollowing hunter compares the image mapping and process metadata available
in the dump for inconsistencies associated with image replacement. Its reach
depends on the dump containing the required PEB, module, and memory data.
Incomplete or unreadable structures result in partial or inconclusive
coverage, not a clean bill of health.

## Module stomping

Two complementary checks are used:

1. A structural check for executable module sections whose observed memory
   protections conflict with their PE section characteristics.
2. An optional content check that compares captured executable bytes with an
   analyst-supplied reference module from `--ref-dir`.

Only a verified, relocation-normalized difference between a captured module
and its matching reference contributes the content-modification score.
Malformed files, identity mismatches, unavailable bytes, or unsupported
relocations are coverage limitations rather than evidence of stomping.

### Reference requirements

Reference files are matched by basename and must represent the same module
build. dumpex validates PE identity fields including:

- architecture / `Machine`;
- `SizeOfImage`; and
- `TimeDateStamp`.

Reference provenance is an investigator responsibility. Prefer binaries from
the affected host or an authoritative image with the same OS and patch level.
A same-named DLL from another machine or patch level is not reliable ground
truth.

### Relocation-aware comparison

Windows normally rebases images. dumpex normalizes supported base relocations
before comparing executable section bytes:

- `IMAGE_REL_BASED_HIGHLOW` for PE32/x86; and
- `IMAGE_REL_BASED_DIR64` for PE32+/x64.

The module is treated as unverifiable when relocation information is required
but missing, malformed, truncated, or inconsistent. Unsupported relocation
types and short captured reads are likewise surfaced as coverage limitations.

Some legitimate runtime changes may remain after relocation normalization,
including import-address-table updates, loader bookkeeping, and sanctioned
hotpatching. For this reason, a verified code difference alone is a triage
finding, not final proof of malicious stomping.

### Scoring interpretation

- A verified module-code modification produces a modification finding.
- A thread instruction pointer inside the modified executable range increases
  the severity because it supplies execution context.
- Missing thread context does not erase verified modification evidence; it
  limits the execution-context portion of coverage.

## Named-pipe C2

The pipe hunter searches captured strings for named-pipe syntax and configured
framework patterns. A generic pipe name is contextual evidence; a
framework-specific pattern is stronger but can still be copied, spoofed, or
present in benign tooling. Attribution should therefore be corroborated.

## Cobalt Strike Beacon

The Beacon hunter searches captured memory for parseable Cobalt Strike
configuration blocks and related execution evidence.

- No valid configuration produces no Beacon-config score.
- A validated configuration is a positive artifact.
- A thread instruction pointer in the containing region strengthens the
  finding.

Multiple valid configurations are retained as separate findings but do not
multiply the core score. This prevents duplicate or decoy blocks from
artificially inflating severity.

Configuration extraction establishes that a valid Beacon configuration was
present in captured memory. It does not, by itself, prove that the Beacon was
active at capture time, that the process contacted C2, or that every parsed
endpoint was used. Version estimation is heuristic and should be reported as
an estimate.

`MemoryInfoListStream` coverage materially improves page-protection and
allocation context. When it is absent, the artifact can still be detected,
but coverage and some confidence claims are reduced.

## YARA and obfuscation

YARA scans only memory bytes present in the dump and only rules that compiled
successfully. JSON provenance records the exact rule files, per-file hashes,
aggregate hash, and compile counts used in the run.

The obfuscation hunter looks for encoded payload characteristics and known
sleep-mask-related patterns. Entropy or encoding indicators are leads rather
than standalone malware proof; compressed, encrypted, and application data
may look similar.

## MITRE ATT&CK mapping

| Hunter | Primary ATT&CK techniques |
|---|---|
| Process injection | T1055 |
| Process hollowing | T1055.012 |
| Module stomping | T1055.013 |
| Named-pipe C2 | T1090, T1071 |
| Cobalt Strike Beacon | T1071, T1219 |
| YARA memory scan | Depends on matched rule |
| Encoded / obfuscated payloads | T1027 |

These mappings describe the behavior each hunter is designed to surface. They
do not turn a finding into proof that an ATT&CK technique occurred.

## Attribution

Some Beacon parsing and memory signatures build on public defensive research.
The complete source, license, and nature-of-use record is maintained in
[`CREDITS`](../CREDITS).
