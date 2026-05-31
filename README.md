# dumpex

**dumpex** is a command-line DFIR/CTF triage tool for analyzing Windows minidump (`.DMP`) files. It parses minidump structures to surface system information, memory layout, loaded modules, and thread state — and includes a TTP detection engine to hunt for signs of process injection, module stomping, C2 named pipes, and Cobalt Strike beacons.

---

## Features

- **Recon** — Extract system info, PID, PEB, loaded modules, threads, and memory regions from a dump
- **TTP Hunting** — Detect process injection, process hollowing, module stomping, named pipe C2, and Cobalt Strike beacon artifacts
- **Alert Triage** — Generate focused reports anchored to a thread ID, memory address, or string match
- **Diff** — Compare two dumps to identify new/removed modules, threads, and memory regions (including RWX changes)
- **Extraction** — Dump raw bytes or extract strings from a specific memory region, with regex filtering
- **Rule-driven** — Detection patterns are externalized in `rules.yaml`; extend coverage without modifying code
- **Structured Output** — Export results as JSON, CSV, or plain-text for downstream tooling and reporting

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

# Detect module stomping (IOC strings inside legitimate DLL memory)
python -m dumpex dump.DMP --hunt stomping

# Detect suspicious named pipes (C2 frameworks, lateral movement tools)
python -m dumpex dump.DMP --hunt pipe

# Detect Cobalt Strike beacon artifacts
python -m dumpex dump.DMP --hunt cs-beacon --verbose

# Run all TTP checks
python -m dumpex dump.DMP --hunt all --verbose

# Run YARA rules against dump memory
python -m dumpex dump.DMP --hunt yara --yara-dir ./rules/yara/
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

TTP detection is driven by `rules.yaml`, loaded from `rules/rules.yaml` relative to the package directory (or the current working directory as fallback). Built-in defaults are used if the file is not found, so the tool always runs standalone.

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

YARA rules are loaded from `rules/yara/`. Drop any `.yar` file into that directory to extend scanning coverage.

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
| Obfuscated Files or Information | T1027 | CS beacon XOR-encoded config (keys 0x69 / 0x2E) |
| Encrypted Channel: Asymmetric Cryptography | T1573.002 | CS beacon RSA public key ASN.1 header |
| Impair Defenses: Execution Guardrails | T1622 | CS 64-bit sleep mask deobfuscation routine |

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
| `--hunt TTP` | TTP detection: `injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, `all` |
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
| `--yara-dir DIR` | Directory of `.yar` rule files for `--hunt yara` |
| `--json FILE` | Write structured results to FILE as JSON |
| `--csv PATH` | Write CSV output: `FILE.csv` → single combined file, `DIR\` → one file per table |
| `--txt FILE` | Write plain-text copy of console output (ANSI colours stripped) |

---

## Disclaimer

This tool is designed strictly for educational purposes, authorized digital forensics, and incident response operations. The author is not responsible for any misuse or damage caused by the application of this tool.

---

## Author

Developed by Juana (Tao Fan)
- Cyber Security Analyst specializing in DFIR, Threat Hunting, Operational Malware Analysis, and Detection Engineering.
- Connect on [LinkedIn](https://www.linkedin.com/in/tao-f-272929229)

---

## License

This project is licensed under the MIT License.
