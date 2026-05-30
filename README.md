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

---

## Requirements

- Python 3.8+
- [`minidump`](https://github.com/skelsec/minidump) library

```bash
pip install minidump
```

Optional (for YARA scanning):

```bash
pip install yara-python
```

---

## Installation

```bash
git clone https://github.com/bitbug0x55AA/dumpex.git
cd dumpex
pip install minidump
```

No build step required. Run directly with `python dumpex.py`.

---

## Usage

### Recon

```bash
# OS, host, process and CPU summary
python dumpex.py dump.DMP --sysinfo

# Process ID recorded in the dump
python dumpex.py dump.DMP --pid

# PEB (Process Environment Block) information
python dumpex.py dump.DMP --peb

# List loaded modules
python dumpex.py dump.DMP --modules

# List threads with analysis
python dumpex.py dump.DMP --threads

# List all memory regions, optionally filtered by protection
python dumpex.py dump.DMP --list
python dumpex.py dump.DMP --list --filter PAGE_EXECUTE
```

### TTP Hunting

```bash
# Detect process injection (RWX regions, unbacked executable memory)
python dumpex.py dump.DMP --hunt injection

# Detect process hollowing indicators
python dumpex.py dump.DMP --hunt hollowing

# Detect module stomping (IOC strings inside legitimate DLL memory)
python dumpex.py dump.DMP --hunt stomping

# Detect suspicious named pipes (C2 frameworks, lateral movement tools)
python dumpex.py dump.DMP --hunt pipe

# Detect Cobalt Strike beacon artifacts
python dumpex.py dump.DMP --hunt cs-beacon --verbose

# Run all TTP checks
python dumpex.py dump.DMP --hunt all --verbose

# Run YARA rules against dump memory
python dumpex.py dump.DMP --hunt yara --yara-dir ./rules/yara/
```

### Alert Triage

```bash
# Report anchored to a thread ID
python dumpex.py dump.DMP --report --report-tid 0x3a8

# Report anchored to a memory address
python dumpex.py dump.DMP --report --report-addr 0xb120870000

# Search all memory for a string and report on each hit region
python dumpex.py dump.DMP --report --report-string "192.168.1.1"
```

### Diff (Two Dumps)

```bash
# Full diff (modules, threads, memory)
python dumpex.py before.DMP --diff after.DMP

# Diff specific categories
python dumpex.py before.DMP --diff after.DMP --diff-mode modules
python dumpex.py before.DMP --diff after.DMP --diff-mode threads
python dumpex.py before.DMP --diff after.DMP --diff-mode memory
```

### Extraction

```bash
# Extract raw bytes from a memory region to a file
python dumpex.py dump.DMP --extract 0x3a0000 --size 0x4e000 -o out.bin

# Extract strings from a region with optional regex filter
python dumpex.py dump.DMP --strings 0x3a0000 --size 0x4e000 --grep "http|cmd"

# Extract Unicode strings with minimum length of 4
python dumpex.py dump.DMP --strings 0x3a0000 --encoding unicode --min-len 4
```

---

## Detection Rules (`rules.yaml`)

TTP detection is driven by `rules.yaml`, loaded from the same directory as `dumpex.py` (or the current working directory as fallback). Built-in defaults are used if the file is not found, so the tool always runs standalone.

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

## MITRE ATT&CK Coverage

| Technique | ID | Detection |
|---|---|---|
| Inter-Process Communication: Named Pipes | T1559.001 | Cobalt Strike postex, msagent, status, beacon pipes |
| Proxy: Internal Proxy | T1090.001 | CS SMB Beacon peer-to-peer pipe |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec, PAExec, RemCom, svcctl pipes |
| Exploitation for Privilege Escalation | T1068 | PrintNightmare / Spooler pipe (DserNamePipe) |
| Process Injection | T1055 | RWX memory regions, unbacked executable memory |
| Process Hollowing | T1055.012 | Hollowing indicators in module/memory layout |

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

## Disclaimer
This tool is designed strictly for educational purposes, authorized digital forensics, and incident response operations. The author is not responsible for any misuse or damage caused by the application of this tool.

## Author
Developed by Juana (Tao Fan) 
* Cyber Security Analyst specializing in DFIR, Threat Hunting, Operational Malware Analysis, and Detection Engineering.
* Connect on [LinkedIn](https://www.linkedin.com/in/tao-f-272929229)

## License
This project is licensed under the MIT License.