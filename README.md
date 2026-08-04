# dumpex

**dumpex** is a command-line DFIR and CTF triage tool for Windows process
minidumps (`.dmp`). It exposes captured system, module, thread, and memory
state, and hunts for evidence of injection, hollowing, module stomping,
named-pipe C2, Cobalt Strike Beacon artifacts, YARA matches, and
encoded/obfuscated payloads.

> Start with the [SOC / DFIR Quick Start](docs/SOC_QUICKSTART.md) when
> interpreting hunt output. `DETECTED` with partial coverage, `INCONCLUSIVE`,
> `NOT_EVALUATED`, and a scoped non-detection require different dispositions.

## What it does

- **Recon** — inspect system information, PID, PEB, modules, threads, and
  captured memory regions.
- **TTP hunting** — run focused or complete hunts with explicit evidence,
  confidence, verdict, and coverage semantics.
- **Alert triage** — build a report around a thread ID, address, or string.
- **Dump comparison** — identify module, thread, memory-region, and protection
  changes between two dumps.
- **Extraction** — recover raw bytes or ASCII/Unicode strings from a region.
- **Rule-driven detection** — use packaged defaults or explicit analyst
  overrides without editing Python.
- **Case-ready output** — export JSON, CSV, and plain-text results with
  evidence and rule provenance.

## Investigative role

dumpex answers questions about one process at capture time. It complements,
rather than replaces, broader sources:

| Evidence | Typical tool | Question |
|---|---|---|
| Full RAM image | Volatility 3 / MemProcFS | What was running across the system? |
| Event and EDR telemetry | Splunk / Sysmon / EDR | What happened over time? |
| **Process minidump** | **dumpex** | **What was captured inside this process?** |

Minidumps may come from EDR collection, Windows Error Reporting, crash
handling, or `MiniDumpWriteDump`. Their streams are selective, so absence from
a dump is not necessarily absence from the process.

For an end-to-end investigation workflow, see
[Minidump Analysis Workflow](https://github.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/blob/main/03_DFIR_Analysis/3.2_Investigation_Workflow/3.2.06_Minidump_Analysis.md).

## Installation

Python 3.10 or newer is required.

```bash
git clone https://github.com/bitbug0x55AA/dumpex.git
cd dumpex
python -m pip install -e .
```

The base install can already read the packaged `rules.yaml` TTP defaults
(`pyyaml` is a required dependency, not optional). Install YARA support for
the complete hunt set:

```bash
python -m pip install -e ".[full]"
```

The install exposes both `dumpex` and `python -m dumpex` entry points.

## Quick start

```bash
# Identify the process and capture environment
dumpex sample.dmp --sysinfo

# Review memory, modules, and threads
dumpex sample.dmp --list
dumpex sample.dmp --modules
dumpex sample.dmp --threads

# Run all hunters and preserve a case-ready result
dumpex sample.dmp --hunt all \
  --json result.json \
  --case-id CASE-1234 \
  --analyst analyst01
```

Useful focused operations:

```bash
# Compare captured module code with trusted same-build references
dumpex sample.dmp --hunt stomping --ref-dir C:\Windows\System32

# Scan with an analyst-controlled YARA directory
dumpex sample.dmp --hunt yara --yara-dir case-yara

# Build a report around a suspicious instruction pointer
dumpex sample.dmp --report --report-addr 0x7ff600001000

# Extract a memory region
dumpex sample.dmp --extract 0x7ff600001000 --size 0x1000 --output region.bin

# Compare a suspicious capture against a known reference
dumpex suspect.dmp --diff clean-reference.dmp --diff-scope all
```

See the [CLI Reference](docs/CLI_REFERENCE.md) for every mode, option, and
example.

## Hunt overview

| Hunt | Primary signal | Important limit |
|---|---|---|
| `injection` | Executable private memory, validated PE structure, thread context | Legitimate JIT and packed code can resemble injection |
| `hollowing` | Image, PEB, module, and memory inconsistencies | Required structures may be absent from a small dump |
| `stomping` | Section/protection mismatch and optional normalized code diff | Content comparison needs a trusted same-build `--ref-dir` |
| `pipe` | Named-pipe syntax and framework patterns | Names are contextual and can be spoofed |
| `cs-beacon` | Valid Beacon configuration and execution context | Config presence does not prove active C2 |
| `yara` | Matches from successfully compiled rules over captured bytes | Only captured memory and loaded rules are scanned |
| `obfuscation` | Encoding, entropy, and sleep-mask-related indicators | Compressed or encrypted benign data may look similar |

The detailed validation, relocation, scoring, rule-selection, and ATT&CK
mapping rationale is in
[Detection Methodology and Coverage](docs/DETECTION_METHODOLOGY.md).

## Reading results

Do not interpret a single field in isolation:

| Field | Meaning |
|---|---|
| `status` | Whether evidence was detected, not detected in scanned scope, inconclusive, or not evaluated |
| `coverage.status` (`result.data.records[].coverage.status` in `--json` output) | Whether the dump supplied the evidence required by that hunter |
| `verdict_level` | Severity supported by validated evidence |
| `confidence` | Strength of the interpretation given the available evidence |

Two rules matter most:

1. `DETECTED` with `coverage.status: partial` remains a positive finding.
2. `NOT_DETECTED_IN_SCANNED_SCOPE` does not prove the behavior was absent from
   the process or host.

Use the [SOC disposition guide](docs/SOC_QUICKSTART.md) for the decision matrix,
recommended pivots, and per-hunter evidence requirements.

## Rules and reproducibility

Canonical defaults are packaged under:

```text
dumpex/rules_pkg/data/rules.yaml
dumpex/rules_pkg/data/yara/*.yar
```

Use `--rules-file` and `--yara-dir` for explicit case-specific overrides.
dumpex does not automatically load a rules file from the current working
directory. JSON output records evidence identity, execution options,
dependency versions, and the hashes of rules actually used.

See [Output and Evidence Schema](docs/OUTPUT_SCHEMA.md) before building an
integration or archiving a result.

## Documentation

| Document | Use it for |
|---|---|
| [SOC / DFIR Quick Start](docs/SOC_QUICKSTART.md) | Triage, disposition, evidence requirements, and next actions |
| [CLI Reference](docs/CLI_REFERENCE.md) | Complete modes, options, and examples |
| [Detection Methodology](docs/DETECTION_METHODOLOGY.md) | Validation logic, limitations, scoring, and ATT&CK mapping |
| [Output and Evidence Schema](docs/OUTPUT_SCHEMA.md) | JSON metadata, provenance, formats, and reproducibility |
| [Changelog](CHANGELOG.md) | User-facing changes between releases, including output-contract migrations |
| [Contributing](CONTRIBUTING.md) | Development setup, tests, CI, and contribution expectations |
| [CREDITS](CREDITS) | Research attribution, licenses, and nature of use |

## Scope and limitations

- dumpex analyzes only bytes and streams present in the supplied process dump.
- It is a triage aid, not a substitute for full-memory, endpoint, timeline, or
  malware analysis.
- Heuristic findings require investigator validation and corroboration.
- Reference modules must match the captured build; a same-named file is not
  sufficient.
- Path redaction protects local directory layout, not sensitive content inside
  findings.

## Development

```bash
python -m pip install -e ".[full,dev]"
pytest
pytest --cov=dumpex --cov-report=term-missing
```

The default suite builds synthetic minidump and PE object graphs and does not
require a malware corpus or network access. See [Contributing](CONTRIBUTING.md)
for the test layout and optional private-corpus workflow.

## Acknowledgements

dumpex incorporates and references public defensive research by Didier
Stevens, Elastic Security, NVISO Labs, and Stephen Fewer. Full provenance is
maintained in [`CREDITS`](CREDITS), with required license text in
[`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES).

## Disclaimer

This tool is intended for education, authorized digital forensics, and
incident response. The author is not responsible for misuse or resulting
damage.

## Author and license

Developed by Juana (Tao Fan), a cyber security analyst specializing in DFIR,
threat hunting, operational malware analysis, and detection engineering.
Connect on [LinkedIn](https://www.linkedin.com/in/tao-f-272929229).

Licensed under the [Mozilla Public License 2.0](LICENSE). Modifications to
MPL-covered files must remain available under MPL-2.0 when distributed; those
files may still be combined with separate proprietary files in a larger work.
See [`NOTICE`](NOTICE) for the source-code offer and license-transition note.
