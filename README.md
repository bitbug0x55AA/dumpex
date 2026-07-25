# dumpex

**dumpex** is a command-line DFIR/CTF triage tool for analyzing Windows minidump (`.DMP`) files. It parses minidump structures to surface system information, memory layout, loaded modules, and thread state — and includes a TTP detection engine to hunt for signs of process injection, module stomping, C2 named pipes, Cobalt Strike beacons, and encoded/obfuscated payloads.

---

## Features

- **Recon** — Extract system info, PID, PEB, loaded modules, threads, and memory regions from a dump
- **TTP Hunting** — Detect process injection, process hollowing, module stomping, named pipe C2, Cobalt Strike beacon artifacts, and encoded/obfuscated payloads
- **Alert Triage** — Generate focused reports anchored to a thread ID, memory address, or string match
- **Diff** — Compare two dumps to identify new/removed modules, threads, and memory regions (including RWX changes)
- **Extraction** — Dump raw bytes or extract strings from a specific memory region, with regex filtering
- **Rule-driven** — Detection patterns are externalized in `rules.yaml`; extend coverage without modifying code
- **Structured Output** — Export results as JSON, CSV, or plain-text for downstream tooling and reporting

---

## Investigative Context

dumpex is the **minidump analysis layer** in a broader DFIR investigation stack. It fills a specific gap that full-memory tools (Volatility, MemProcFS) and log-based platforms (Splunk, Sysmon) do not cover:

| Evidence Source | Tool | What It Answers |
|---|---|---|
| Full RAM image | Volatility 3 / MemProcFS | What was running across the entire system |
| Windows Event Logs | Splunk + Sysmon | What happened, when, and from where |
| **Process .DMP file** | **dumpex** | **What was in a specific process's memory at capture time** |

Minidumps are produced in a wider range of scenarios than full memory images — EDR-triggered captures, Windows Error Reporting (WER), crash dumps, and attacker-generated dumps via `MiniDumpWriteDump`. When a full RAM image is not available, a process `.DMP` is often the only memory artifact.

For a complete investigation workflow showing how dumpex integrates with Volatility, Sysmon, and Splunk across the full incident response lifecycle:

→ **[Blue Team Hunting Field Notes](https://github.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/tree/main)**  
   See: [`3.2.06 Minidump Analysis Workflow`](https://github.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/blob/main/03_DFIR_Analysis/3.2_Investigation_Workflow/3.2.06_Minidump_Analysis.md) — when to use dumpex, how it connects to Sysmon alerts, and how to pivot from memory findings back to log-based investigation.

---

## Requirements

- Python 3.10+
- [`minidump`](https://github.com/skelsec/minidump) library

```bash
pip install minidump
```

Optional (for YAML rule files and YARA scanning):

```bash
pip install pyyaml yara-python
```

---

## Installation

```bash
git clone https://github.com/bitbug0x55AA/dumpex.git
cd dumpex
pip install -e .
```

For full functionality including YAML rules and YARA scanning:

```bash
pip install -e ".[full]"
```

---

## Usage

### Recon

```bash
# OS, host, process and CPU summary
python -m dumpex dump.DMP --sysinfo

# Process ID recorded in the dump
python -m dumpex dump.DMP --pid

# PEB (Process Environment Block) information
python -m dumpex dump.DMP --peb

# List loaded modules
python -m dumpex dump.DMP --modules

# List threads with analysis
python -m dumpex dump.DMP --threads

# List all memory regions, optionally filtered by protection
python -m dumpex dump.DMP --list
python -m dumpex dump.DMP --list --filter PAGE_EXECUTE
```

### TTP Hunting

```bash
# Detect process injection (RWX regions, unbacked executable memory)
python -m dumpex dump.DMP --hunt injection

# Detect process hollowing indicators
python -m dumpex dump.DMP --hunt hollowing

# Detect module stomping (verified on-disk-vs-memory section content diff;
# --ref-dir is required for a score — see "Module Stomping Detection" below)
python -m dumpex dump.DMP --hunt stomping
python -m dumpex dump.DMP --hunt stomping --ref-dir ./known-good-dlls/

# Detect suspicious named pipes (C2 frameworks, lateral movement tools)
python -m dumpex dump.DMP --hunt pipe

# Detect Cobalt Strike beacon artifacts
python -m dumpex dump.DMP --hunt cs-beacon --verbose

# Detect encoded or obfuscated payloads (Base64, XOR, GZIP, high entropy)
python -m dumpex dump.DMP --hunt obfuscation
python -m dumpex dump.DMP --hunt obfuscation --verbose

# Run YARA rules against dump memory
python -m dumpex dump.DMP --hunt yara --yara-dir ./rules/yara/

# Run all TTP checks
python -m dumpex dump.DMP --hunt all --verbose
```

### Alert Triage

```bash
# Report anchored to a thread ID
python -m dumpex dump.DMP --report --report-tid 0x3a8

# Report anchored to a memory address
python -m dumpex dump.DMP --report --report-addr 0xb120870000

# Search all memory for a string and report on each hit region
python -m dumpex dump.DMP --report --report-string "192.168.1.1"
```

### Diff (Two Dumps)

```bash
# Full diff (modules, threads, memory)
python -m dumpex before.DMP --diff after.DMP

# Diff specific categories
python -m dumpex before.DMP --diff after.DMP --diff-mode modules
python -m dumpex before.DMP --diff after.DMP --diff-mode threads
python -m dumpex before.DMP --diff after.DMP --diff-mode memory
```

### Extraction

```bash
# Extract raw bytes from a memory region to a file
python -m dumpex dump.DMP --extract 0x3a0000 --size 0x4e000 -o out.bin

# Extract strings from a region with optional regex filter
python -m dumpex dump.DMP --strings 0x3a0000 --size 0x4e000 --grep "http|cmd"

# Extract Unicode strings with minimum length of 4
python -m dumpex dump.DMP --strings 0x3a0000 --encoding unicode --min-len 4
```

### Structured Output

```bash
# Export results as JSON
python -m dumpex dump.DMP --hunt all --json results.json

# Export results as CSV (single file or directory)
python -m dumpex dump.DMP --modules --csv modules.csv
python -m dumpex dump.DMP --hunt all --csv ./output/

# Save a plain-text copy of all console output
python -m dumpex dump.DMP --hunt all --txt report.txt

# Combine output formats
python -m dumpex dump.DMP --hunt all --json results.json --csv ./output/ --txt report.txt
```

---

## Detection Rules (`rules.yaml`)

TTP detection is driven by `rules.yaml`, bundled inside the package at `dumpex/rules_pkg/data/rules.yaml` — this is what `pip install dumpex` ships, so the tool works standalone with no extra files. Pass `--rules-file PATH` for an explicit, deliberate override without touching the installed package. There is **no** automatic scan of the current working directory or the directory the script lives in — a DFIR working directory routinely contains untrusted case files, so a `rules.yaml` sitting there is never picked up implicitly. Built-in defaults are used only when **no** `--rules-file` was given and the packaged copy can't be loaded; if you *do* pass `--rules-file`, a missing/unreadable/unparseable/schema-invalid file is a hard error (non-zero exit) rather than a silent fallback — you never get a verdict produced by a different ruleset than the one you asked for. The rules source actually used (path + SHA-256) is printed to the console (and captured in `--txt` output) and recorded under `hunt._rules_source` in `--json` output.

The rule file controls:

| Section | Description |
|---|---|
| `suspicious_protections` | Memory protection flags flagged as suspicious (e.g. `PAGE_EXECUTE_READWRITE`) |
| `stomping_whitelist` | DLLs excluded from net-IOC checks to reduce false positives |
| `stomping_ioc_patterns` | Always-suspicious strings checked in all modules |
| `stomping_net_ioc_patterns` | Network IOC patterns (URLs, IPs, API names) flagged outside whitelisted DLLs |
| `pipe_c2_context_patterns` | Patterns matched in memory near a suspicious pipe name |
| `framework_pipes` | Named pipe patterns mapped to C2 frameworks and MITRE ATT&CK technique IDs |

To add new detection coverage, edit `rules.yaml` — no code changes required.

---

## Module Stomping Detection

`--hunt stomping` no longer scores on IOC strings or on an unusual page
protection alone — both are still reported (as an unscored, low/medium-
confidence **lead**), but the only signal that can produce a nonzero score
is a **verified, relocation-normalized on-disk-vs-memory content diff**:

1. Each loaded module's own PE header is parsed out of process memory.
2. For every section the header declares executable-but-not-writable, its
   live memory protection is compared against the normal, unmodified-
   mapping set. `PAGE_EXECUTE_WRITECOPY` is explicitly **not** flagged —
   Windows routinely maps executable sections copy-on-write even when
   nothing was ever written, so treating it as suspicious made every
   ordinary, untouched DLL look "stomped". A deviation from that (most
   notably `PAGE_EXECUTE_READWRITE`) is reported as a lead only:
   protection state alone proves nothing about content, since an attacker
   can reprotect a section back to RX after stomping it and before a dump
   is captured.
3. **`--ref-dir DIR`** points at a directory of analyst-supplied reference
   copies of modules (matched by filename), used to perform the actual
   content verification. Without it, the verified-content check — the
   only scored signal this hunter has — cannot run at all.

### Reference file requirements

A candidate reference file is only used if its **own** PE header identity
(Machine, SizeOfImage, TimeDateStamp) matches the in-memory module's
header. A same-named file that is actually a different build/version/patch
level is skipped rather than diffed — comparing against the wrong build
would report ordinary compiler-output differences as "stomped". Before
comparing, the reference file's bytes are **relocation-normalized**: if
the module loaded at a different address than its preferred `ImageBase`
(ASLR, or a base collision), the same delta the Windows loader applied at
load time is applied to the on-disk copy, so an unmodified-but-relocated
section reads as identical rather than "changed". Only `IMAGE_REL_BASED_
HIGHLOW`/`DIR64` fixups on **x86/x64** (`I386`/`AMD64`) modules are
applied — the two types real x86/x64 linkers emit. On any other machine
type (ARM/ARM64/…), if the relocation table itself is missing/malformed,
if an entry uses a fixup type other than `ABSOLUTE`/`HIGHLOW`/`DIR64`
(unrecognized/unsupported), or if an entry's target RVA falls in a
section's virtual-only tail — `VirtualSize` extending past
`SizeOfRawData`, e.g. a zero-padded region the loader fills at load time
with no corresponding on-disk bytes — normalization is explicitly
reported as **unavailable/malformed** rather than silently skipped or
partially applied: when a nonzero relocation delta is actually needed and
normalization can't be completed *in full*, the comparison is aborted for
that section (counted under `coverage_counts.relocation_failed`) instead
of diffing raw, un-normalized bytes — doing so would misreport every
relocation-touched instruction as "modified". Similarly, a live-memory
read shorter than the section's declared `SizeOfRawData` is never
silently compared over just the bytes that happened to be readable — it's
counted under `coverage_counts.short_reads`, a coverage gap, not a clean
result. IAT/delay-import ranges and hotpatch trampolines are **not**
specifically excluded from the diff itself; see the
`stomping.verified_content_change` finding's `limitations` for that
residual caveat.

A verified diff with **no** corroborating live execution in the changed
range (score 1) is reported as a neutral **"VERIFIED MODULE CODE
MODIFICATION"**, not "stomping" — that same signature is also what a
legitimate hotpatch or EDR inline hook produces, and attributing it to
malicious stomping from a content diff alone would overstate what's
actually known. The "stomping" framing (and `verdict_level: high`) is
reserved for score 2, where a thread's own current RIP/EIP is executing
inside one of the changed byte ranges.

### Coverage semantics: `DETECTED` with `coverage_status: partial`

Every hunt result carries `status` (`DETECTED` / `NOT_DETECTED_IN_SCANNED_SCOPE`
/ `INCONCLUSIVE` / `NOT_EVALUATED`) **and**, independently, `coverage_status`
(`complete` / `partial` / `not_evaluated`) plus a `coverage_reasons` list.
These are deliberately not collapsed into one field: a hunter can find a
genuine, verified stomped section (`status: DETECTED`) while *other*
modules in the same dump couldn't be checked (unreadable header, no
matching reference file, identity mismatch) — that's still `DETECTED`,
with `coverage_status: partial` reported alongside so an investigator
knows there could be more they haven't seen. Without `--ref-dir` at all,
`score` is always `0` and `status` is `INCONCLUSIVE` (never a bare
"clean") — the one scored signal in this hunter simply never ran.

Every finding also carries a `verdict_level` (`clean` / `possible` /
`likely` / `high`, plus `inconclusive` / `not_evaluated` mirroring
`status`) that the hunter itself computes from its own score and status;
this is the single value console output, `--json`, and `--csv` all read
directly (uppercased) — none of them re-derive a verdict from `score` or
`confidence` independently, so the same finding can't show different
tiers in different output formats. `verdict_level` is never `clean` when
`status` is `INCONCLUSIVE` or `NOT_EVALUATED` — a scanner that didn't run,
or ran over incomplete coverage, hasn't earned "clean", and reporting it
as such would tell an analyst a scope was verified benign when it was
actually never (or only partly) checked.

YARA rules are bundled inside the package at `dumpex/rules_pkg/data/yara/`. Pass `--yara-dir PATH` for an explicit directory of `.yar` files to extend scanning coverage without touching the installed package — same as `--rules-file`, there is no automatic cwd/script-dir scan.

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection |
|---|---|---|
| Process Injection | T1055 | RWX memory regions, unbacked executable memory, hidden PE headers |
| Process Hollowing | T1055.012 | Image base memory type, MZ header, module list mismatch |
| Inter-Process Communication: Named Pipes | T1559.001 | Cobalt Strike postex, msagent, status, beacon pipes |
| Proxy: Internal Proxy | T1090.001 | CS SMB Beacon peer-to-peer pipe |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec, PAExec, RemCom, svcctl pipes |
| Exploitation for Privilege Escalation | T1068 | PrintNightmare / Spooler pipe (DserNamePipe) |
| Obfuscated Files or Information | T1027 | CS beacon XOR-encoded config; single-byte XOR payload detection |
| Obfuscated Files or Information: HTML Smuggling | T1027.006 | Base64-encoded payloads in memory |
| Encrypted Channel: Asymmetric Cryptography | T1573.002 | CS beacon RSA public key ASN.1 header |
| Impair Defenses: Execution Guardrails | T1622 | CS 64-bit sleep mask deobfuscation routine |
| Deobfuscate/Decode Files or Information | T1140 | Shannon entropy scan; GZIP/ZLIB compressed payload detection |

---

## Options Reference

| Flag | Description |
|---|---|
| `--list` | List all memory regions |
| `--modules` | List loaded modules |
| `--threads` | List threads with analysis |
| `--peb` | Show PEB info |
| `--pid` | Show recorded process ID |
| `--sysinfo` | Show OS, host, process, and CPU summary |
| `--hunt TTP` | TTP detection: `injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, `obfuscation`, `all` |
| `--report` | Generate triage report (requires `--report-tid`, `--report-addr`, or `--report-string`) |
| `--diff DUMP2` | Diff against a second dump file |
| `--diff-mode` | Scope of diff: `modules`, `threads`, `memory`, `all` (default: `all`) |
| `--extract ADDR` | Extract raw bytes at address |
| `--strings ADDR` | Extract strings at address |
| `--size SIZE` | Region size in hex |
| `-o FILE` | Output file for `--extract` |
| `--filter PROT` | Filter `--list` by protection name |
| `--grep REGEX` | Regex filter for `--strings` |
| `--min-len N` | Minimum string length for `--strings` (default: 6) |
| `--encoding` | String encoding: `ascii`, `unicode`, `both` (default: `both`) |
| `--verbose` | Show all regions including routine ones |
| `--yara-dir DIR` | Directory of `.yar` rule files for `--hunt yara` (explicit override; no automatic cwd scan) |
| `--rules-file FILE` | Explicit `rules.yaml`/`.yml`/`.json` for TTP detection (no automatic cwd scan) |
| `--ref-dir DIR` | Directory of reference module files for `--hunt stomping`'s verified content diff (required for a nonzero score; see "Module Stomping Detection") |
| `--json FILE` | Write structured results to FILE as JSON |
| `--csv PATH` | Write CSV output: `FILE.csv` → single combined file, `DIR\` → one file per table |
| `--txt FILE` | Write plain-text copy of console output (ANSI colours stripped) |

---

## Development

The regression suite requires no real `.dmp`/PE sample files — every test
builds its own synthetic PE header and minidump object graph via
`tests/fixtures/fakes.py`:

```bash
pip install -e ".[dev]"     # pytest, pytest-cov
pytest                       # run the full suite
pytest --cov=dumpex --cov-report=term-missing   # with coverage
```

Layout:

| Path | Scope |
|---|---|
| `tests/unit/` | Pure function-level tests (PE parsing, relocation normalization) — no hunter or minidump object graph involved |
| `tests/hunt/` | Per-hunter tests (`dumpex.hunt.*`) driven through synthetic `FakeMF` minidump objects |
| `tests/integration/` | Cross-module output-path tests (CSV/JSON summary rows faithfully reflecting a hunter's own `verdict_level`/`confidence`/`coverage_status`) |
| `tests/fixtures/` | Shared synthetic-PE/minidump builders (`fakes.py`) used by all of the above |

`tests/conftest.py` also resets `stomping.get_thread_contexts`/
`pipemod.get_thread_contexts` before and after every test — both hold a
plain module-level monkeypatch point so a test can inject a synthetic
RIP, and without a reset a patched value would otherwise leak into
whichever test happens to run next.

CI (`.github/workflows/tests.yml`) runs the suite on the package's
minimum supported Python version (`requires-python` in `pyproject.toml`)
and one current version, on every push/PR.

---

## Acknowledgements

Dumpex builds on the work of several researchers and organizations in the public security community. Their contributions are gratefully acknowledged below.

---

### Didier Stevens — 1768.py and cs-analyze-processdump.py

The Cobalt Strike beacon configuration scanner in [`dumpex/hunt/cs_beacon.py`](dumpex/hunt/cs_beacon.py) is an adaptation of **1768.py** by [Didier Stevens](https://blog.didierstevens.com/). While [`dumpex/hunt/encoding.py (Layer 0 — _scan_sleep_mask and helpers)`](dumpex/hunt/encoding.py) is from his **cs-analyze-processdump.py**.

Specifically derived from 1768.py:

- XOR-encoded config block detection algorithm (`AnalyzeEmbeddedPEFileSub`)
- TLV config field parser (`AnalyzeEmbeddedPEFileSub2`)
- Malleable C2 instruction stream decoder (`DecodeInstructions`)
- Config field identifier table (`dConfigIdentifiers`)
- Beacon type and proxy type lookup tables (`LookupConfigValue`)
- CS version estimation from max field ID (`DetermineCSVersionFromConfig`)
- Config sanity check logic (`SanityCheckExtractedConfig`)

The YARA signatures `CS_Beacon_Config_XOR69` and `CS_Beacon_Config_XOR2E` in [`dumpex/rules_pkg/data/yara/cs_indicators.yar`](dumpex/rules_pkg/data/yara/cs_indicators.yar) are also derived from the same work.

> Didier Stevens, *1768.py and cs-analyze-processdump.py — Analyse Cobalt Strike beacons*  
> <https://blog.didierstevens.com/programs/cobalt-strike-tools/>  
> Source code placed in the **public domain** by the author.

---

### Elastic Security

The YARA rules `CS_SleepMask_64bit` and `CS_SleepMask_32bit` in [`dumpex/rules_pkg/data/yara/cs_indicators.yar`](dumpex/rules_pkg/data/yara/cs_indicators.yar) are based on byte signatures published by **Elastic Security**.

> Elastic Security, *Detecting Cobalt Strike with Memory Signatures*  
> <https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures>  
> Published as public security research.

---

### NVISO Labs

The contextual understanding of Cobalt Strike beacon memory layout and config extraction that informed the design of `cs_beacon.py` draws on the public research series published by **NVISO Labs**.

> NVISO Labs, *Cobalt Strike: Memory Dumps* blog series  
> <https://blog.nviso.eu/>  
> Published as public security research.

---

### Stephen Fewer — ReflectiveDLLInjection

The hash constants used in the `Reflective_Loader_Signature` YARA rule in [`dumpex/rules_pkg/data/yara/suspicious_memory.yar`](dumpex/rules_pkg/data/yara/suspicious_memory.yar) are derived from the **ReflectiveDLLInjection** project by Stephen Fewer.

> Stephen Fewer, *ReflectiveDLLInjection*  
> <https://github.com/stephenfewer/ReflectiveDLLInjection>  
> Source code placed in the **public domain** by the author.

---

*All referenced works are used for defensive, educational, and incident response
purposes, consistent with the intent of their original authors.*

---

## Disclaimer

This tool is designed strictly for educational purposes, authorized digital forensics, and incident response operations. The author is not responsible for any misuse or damage caused by the application of this tool.

---

## Author

Developed by Juana (Tao Fan)  
Cyber Security Analyst specializing in DFIR, Threat Hunting, Operational Malware Analysis, and Detection Engineering.  
Connect on [LinkedIn](https://www.linkedin.com/in/tao-f-272929229)

---

## License

This project is licensed under the MIT License.
