"""Structured output: JSON / CSV / TXT (tee)."""
import io
import re
import os
import sys
import json
import csv
import datetime
from pathlib import Path
from dumpex.ui.colors import DIM
from dumpex.core.memory import va_to_file_offset, prot_str

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

class _TeeWriter:
    """
    Transparent stdout wrapper that tees to a plain-text file.

    - Terminal stream: unchanged (colours preserved)
    - File stream:     ANSI escape codes stripped, UTF-8 encoded

    Activated by setting sys.stdout = _TeeWriter(file_handle, original_stdout).
    Deactivated by restoring sys.stdout = original_stdout.
    """

    def __init__(self, fh: io.TextIOWrapper, original):
        self._fh       = fh          # plain-text file
        self._original = original    # real terminal stdout

    def write(self, text: str) -> int:
        self._original.write(text)
        self._fh.write(_ANSI_RE.sub('', text))
        return len(text)

    def flush(self):
        self._original.flush()
        self._fh.flush()

    # Delegate everything else (isatty, fileno, etc.) to the real stdout
    def __getattr__(self, name):
        return getattr(self._original, name)


def _json_safe(obj):
    """
    Recursively convert an object into a JSON-serializable form.
      bytes         → lowercase hex string
      set/frozenset → sorted list
      re.Pattern    → pattern string
      enum-like     → .name
      dict/list/tuple → recurse
      str/int/float/bool/None → passed through unchanged
      everything else → str(obj)   ← explicit fallback, never crashes
    """
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (set, frozenset)):
        return sorted(str(x) for x in obj)
    if isinstance(obj, re.Pattern):
        return obj.pattern
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(i) for i in obj]
    # Enum-like objects (minidump protection/state flags, etc.)
    if not isinstance(obj, (str, int, float, bool, type(None))) and hasattr(obj, 'name'):
        try:
            return obj.name
        except Exception:
            pass
    # Primitive JSON types pass through unchanged
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    # Catch-all: minidump objects (MinidumpMemoryInfo, MinidumpModule, etc.),
    # ctypes structs, and any other non-serializable type → string representation
    return str(obj)


class StructuredOutput:
    """
    Accumulates structured results from command functions and serialises
    them to JSON or CSV on demand.

    Usage
    -----
    out = StructuredOutput(dump_path)
    out.add("modules",  cmd_modules(mf))
    out.add("hunt",     cmd_hunt(mf, ...))
    out.write_json("results.json")
    out.write_csv("output/")
    """

    TOOL    = "dumpex"

    def __init__(self, dump_path: str, mf=None):
        self._meta = {
            "tool":       self.TOOL,
            "dump_file":  os.path.basename(dump_path),
            "dump_path":  os.path.abspath(dump_path),
            "timestamp":  datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self._sections: dict = {}
        self._mf = mf   # MinidumpFile reference for VA → file-offset lookups

    def add(self, key: str, data):
        """Store a section (overwrites if key already exists)."""
        self._sections[key] = data

    # ── JSON ─────────────────────────────────────────────────────────────

    def to_json(self) -> str:
        doc = {"meta": self._meta}
        doc.update(_json_safe(self._sections))
        return json.dumps(doc, indent=2, ensure_ascii=False)

    def write_json(self, path: str, cmd_label: str = ""):
        p = Path(path)
        if str(path).endswith(('/', '\\')) or p.is_dir():
            ts    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
            label = f"_{cmd_label}" if cmd_label else ""
            p     = p / f"dumpex_{ts}{label}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        print(DIM(f"  [·] JSON written → {p}"))

    # ── CSV ──────────────────────────────────────────────────────────────

    def write_csv(self, path: str, cmd_label: str = ""):
        """
        Write structured output as CSV.

        Two modes, auto-detected from the path argument:

        Directory mode  (path has no .csv extension, e.g. "output/")
            One file per logical table:
            dumpex_<cmd_label>_<section>_<table>.csv

        Single-file mode  (path ends with .csv, e.g. "result.csv")
            All tables written into a single CSV file, separated by a blank
            row and a "## section / table" header line.
        """
        p     = Path(path)
        label = f"{cmd_label}_" if cmd_label else ""

        # ── Single-file mode ─────────────────────────────────────────────
        if p.suffix.lower() == ".csv":
            p.parent.mkdir(parents=True, exist_ok=True)
            total_rows = 0
            with open(p, "w", newline="", encoding="utf-8") as fh:
                for section, data in self._sections.items():
                    tables = self._section_to_tables(section, data)
                    for table_name, rows in tables.items():
                        if not rows:
                            continue
                        fh.write(f"## {section} / {table_name}\n")
                        writer = csv.DictWriter(fh, fieldnames=rows[0].keys(),
                                               extrasaction="ignore")
                        writer.writeheader()
                        writer.writerows(rows)
                        fh.write("\n")
                        total_rows += len(rows)
            print(DIM(f"  [·] CSV  written → {p}  ({total_rows} row(s) across all tables)"))
            return

        # ── Directory mode ───────────────────────────────────────────────
        p.mkdir(parents=True, exist_ok=True)
        for section, data in self._sections.items():
            tables = self._section_to_tables(section, data)
            for table_name, rows in tables.items():
                if not rows:
                    continue
                fname = p / f"dumpex_{label}{section}_{table_name}.csv"
                with open(fname, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=rows[0].keys(),
                                           extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(rows)
                print(DIM(f"  [·] CSV  written → {fname}  ({len(rows)} row(s))"))

    def _section_to_tables(self, section: str, data) -> dict:
        """
        Convert a section's data into {table_name: [row_dict, ...]} for CSV.
        Each section type has its own flattening logic.
        """
        if section == "modules" and isinstance(data, list):
            return {"modules": data}

        if section == "threads" and isinstance(data, list):
            return {"threads": data}

        if section in ("sysinfo", "pid") and isinstance(data, dict):
            rows = [{"field": k, "value": v} for k, v in data.items()
                    if not isinstance(v, (dict, list))]
            return {section: rows}

        if section == "hunt" and isinstance(data, dict):
            summary_rows  = []
            findings_rows = []

            for ttp, findings in data.items():
                if not isinstance(findings, dict):
                    continue
                score     = findings.get("score", 0)
                max_score = {"injection": 3, "hollowing": 4, "stomping": 2,
                             "pipe": 4, "cs-beacon": 1, "yara": 3}.get(ttp, "?")
                verdict   = ("CLEAN"           if score == 0 else
                             "HIGH CONFIDENCE" if isinstance(max_score, int) and score >= max_score - 1
                             else "POSSIBLE")
                summary_rows.append({
                    "ttp": ttp, "score": score,
                    "max_score": max_score, "verdict": verdict,
                })

                # CS beacon configs
                for cfg in findings.get("configs", []):
                    fields = cfg.get("fields", {})
                    c2_raw = ""
                    if "8" in fields:
                        c2_raw = fields["8"].get("value", "") or ""
                    c2_host, c2_uri = (c2_raw.split(",", 1) if "," in c2_raw
                                       else (c2_raw, ""))
                    findings_rows.append({
                        "ttp":            ttp,
                        "finding_type":   "cs_beacon_config",
                        "va_process":     f"0x{cfg.get('va', 0):016x}",
                        "file_offset":    f"0x{cfg.get('file_offset', 0):x}",
                        "cs_version":     cfg.get("cs_version", ""),
                        "xor_key":        f"0x{cfg.get('xor_key', 0):02x}",
                        "beacon_type":    fields.get("1", {}).get("value", ""),
                        "c2_host":        c2_host.strip(),
                        "c2_uri":         c2_uri.strip(),
                        "port":           fields.get("2", {}).get("value", ""),
                        "useragent":      (fields.get("9", {}).get("value") or "").strip("\x00"),
                        "pipename":       (fields.get("15", {}).get("value") or "").strip("\x00"),
                        "license_id":     fields.get("37", {}).get("value", ""),
                        "sleep_ms":       fields.get("3", {}).get("value", ""),
                        "jitter_pct":     fields.get("5", {}).get("value", ""),
                        "details":        "",
                    })

                # YARA matches
                for match in findings.get("matches", []):
                    rule   = match.get("rule", "")
                    rfile  = match.get("file", "")
                    mitre  = (match.get("meta") or {}).get("mitre", "")
                    n_str  = len(match.get("strings", []))
                    seg_va = match.get("seg_va", 0)
                    seg_fo = match.get("seg_fo", 0)
                    findings_rows.append({
                        "ttp":          ttp,
                        "finding_type": "yara_match",
                        "va_process":   f"0x{seg_va:016x}",
                        "file_offset":  f"0x{seg_fo:x}",
                        "cs_version":   "",
                        "xor_key":      "",
                        "beacon_type":  "",
                        "c2_host":      "",
                        "c2_uri":       "",
                        "port":         "",
                        "useragent":    "",
                        "pipename":     "",
                        "license_id":   "",
                        "sleep_ms":     "",
                        "jitter_pct":   "",
                        "details":      f"rule={rule};file={rfile};mitre={mitre};strings={n_str}",
                    })

                # Pipe findings
                for r, off, name in findings.get("private_pipes", []):
                    abs_va = r.BaseAddress + off
                    fo     = (va_to_file_offset(self._mf, abs_va) or 0) if self._mf else 0
                    findings_rows.append({
                        "ttp":          ttp,
                        "finding_type": "suspicious_pipe",
                        "va_process":   f"0x{abs_va:016x}",
                        "file_offset":  f"0x{fo:x}" if fo else "",
                        "cs_version":   "", "xor_key":   "", "beacon_type": "",
                        "c2_host":      "", "c2_uri":     "", "port":        "",
                        "useragent":    "", "pipename":   name.strip(),
                        "license_id":   "", "sleep_ms":   "", "jitter_pct":  "",
                        "details":      prot_str(r.Protect),
                    })

            tables = {"summary": summary_rows}
            if findings_rows:
                tables["findings"] = findings_rows
            return tables

        # Fallback: try list-of-dicts as-is
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return {section: data}

        return {}

