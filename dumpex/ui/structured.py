"""Structured output: JSON / CSV. Plain-text tee lives in core/safe_io.py
(AtomicTextTee) — kept there because it shares atomic-write plumbing with
the rest of the output-safety helpers."""
import io
import re
import os
import sys
import json
import csv
import platform
import datetime
import importlib.metadata
from pathlib import Path
from dumpex.ui.colors import DIM
from dumpex.core.memory import va_to_file_offset, prot_str
from dumpex.core.safe_io import write_text_to_target, write_text_to_directory, summarize_file
from dumpex.core.evidence import sha256_file

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# CLI options whose VALUE is a filesystem path — redacted (basename only)
# under --redact-paths, same as evidence.path, so a case JSON meant for
# sharing outside the analyst's own machine doesn't leak local usernames/
# directory layout embedded in an absolute path.
_PATH_OPTION_KEYS = frozenset({"ref_dir", "yara_dir", "rules_file"})


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
    out = StructuredOutput(dump_path, mf, command="hunt_all",
                            options={"hunt": "all", "verbose": False})
    out.add("modules",  cmd_modules(mf))
    out.add("hunt",     cmd_hunt(mf, ...))
    out.write_json("results.json")
    out.write_csv("output/")
    """

    TOOL           = "dumpex"
    SCHEMA_VERSION = "1.1"   # meta document shape — bumped independently of
                              # the tool's own version (dumpex.__version__ /
                              # importlib.metadata), which changes far more
                              # often than the shape a consumer parses.
                              # 1.0 -> 1.1: obfuscation's sleep_mask/entropy/
                              # base64/xor/compressed/hidden_pe/hidden_shellcode
                              # hit shape changed incompatibly (sleep_mask's
                              # `offset` used to BE the XOR key rotation value;
                              # it is now always 0, with rotation moved to a
                              # new `key_offset` field) and is formally defined
                              # in the schema for the first time -- see
                              # dumpex/schemas/dumpex-output-v1.1.schema.json
                              # and docs/OUTPUT_SCHEMA.md's versioning policy.

    def __init__(self, dump_path: str, mf=None, *, command: str = None,
                 options: dict = None, case_id: str = None, analyst: str = None,
                 redact_paths: bool = False, started_at: "datetime.datetime" = None):
        self._dump_path_abs  = os.path.abspath(dump_path)
        self._dump_file_name = os.path.basename(dump_path)
        self._command        = command
        self._options        = dict(options) if options else {}
        self._case_id        = case_id
        self._analyst        = analyst
        self._redact_paths   = redact_paths
        # Defaults to "now" (construction time) for any caller that
        # doesn't pass one explicitly — but cli.py passes the timestamp
        # captured at the CLI entry point, BEFORE open_dump()/
        # MinidumpFile.parse() runs, so execution.duration_seconds
        # reflects the run's actual total wall-clock time (dump parsing
        # included) rather than starting the clock only once analysis
        # itself began.
        self._started_at = started_at or datetime.datetime.now(datetime.timezone.utc)
        self._sections: dict = {}
        self._mf = mf   # MinidumpFile reference for VA → file-offset lookups
        # Evidence hash is computed at most once per process (a multi-GB
        # dump is expensive to re-hash) and cached here — a failure is
        # remembered too, as a message, rather than retried on every
        # to_json() call or allowed to raise.
        self._evidence_sha256 = None
        self._evidence_hash_error = None

    def add(self, key: str, data):
        """Store a section (overwrites if key already exists)."""
        self._sections[key] = data

    # ── Evidence metadata (--json meta block) ───────────────────────────
    # Every _*_meta() helper below is independently exception-safe — a
    # failure computing ONE piece (e.g. sha256 on a locked/huge/deleted
    # file) must not prevent the rest of meta, and must never prevent the
    # actual analysis results from being written. Each records an
    # "error" string in its own sub-object instead of raising.

    def _redact(self, options: dict) -> dict:
        out = {}
        for k, v in options.items():
            if k in _PATH_OPTION_KEYS and isinstance(v, str) and v:
                out[k] = os.path.basename(v.rstrip("/\\"))
            else:
                out[k] = v
        return out

    def _tool_meta(self) -> dict:
        try:
            version = importlib.metadata.version("dumpex")
        except importlib.metadata.PackageNotFoundError:
            # A source checkout run without `pip install -e .` (or any
            # other layout where the package isn't registered with
            # importlib.metadata) previously reported version: null here
            # — falling back to the package's own __version__ constant
            # means --json output still carries a real version string
            # from the most common "not actually installed" case, rather
            # than silently going null.
            import dumpex
            version = getattr(dumpex, "__version__", None)
        return {"name": self.TOOL, "version": version}

    def _execution_meta(self, finished_at: "datetime.datetime") -> dict:
        options = self._redact(self._options) if self._redact_paths else dict(self._options)
        return {
            "started_at":       self._started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at":      finished_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round((finished_at - self._started_at).total_seconds(), 3),
            "command":          self._command,
            "options":          options,
            "case_id":          self._case_id,
            "analyst":          self._analyst,
        }

    def _evidence_meta(self) -> dict:
        out = {"file_name": self._dump_file_name}
        if not self._redact_paths:
            out["path"] = self._dump_path_abs
        try:
            out["size_bytes"] = os.path.getsize(self._dump_path_abs)
        except OSError as e:
            out["size_bytes"] = None
            out["error"] = f"could not stat evidence file: {e}"
            return out
        if self._evidence_sha256 is None and self._evidence_hash_error is None:
            try:
                self._evidence_sha256 = sha256_file(self._dump_path_abs)
            except Exception as e:
                self._evidence_hash_error = str(e)
        if self._evidence_sha256 is not None:
            out["sha256"] = self._evidence_sha256
        elif self._evidence_hash_error is not None:
            out["error"] = f"sha256 computation failed: {self._evidence_hash_error}"
        return out

    def _runtime_meta(self) -> dict:
        info = {"python_version": platform.python_version()}
        for dist_name, key in (("minidump", "minidump_version"),
                                ("yara-python", "yara_version"),
                                ("pyyaml", "pyyaml_version")):
            try:
                info[key] = importlib.metadata.version(dist_name)
            except importlib.metadata.PackageNotFoundError:
                pass
        return info

    def _rules_meta(self):
        """
        Rules provenance (which rules.yaml, its sha256, whether it was
        explicitly supplied via --rules-file) — the single copy of this
        information; hunt/__init__.py no longer duplicates it inside the
        "hunt" section's own data as "_rules_source". None if get_rules()
        was never called this run (e.g. --hunt injection alone, which
        doesn't read rules.yaml) — omitted from meta entirely in that case
        rather than printed as a misleading empty object.

        `path` can be a real absolute filesystem path (--rules-file, or a
        PyInstaller _MEIPASS extraction dir) — same leak `_redact()`
        exists to prevent for CLI path options, so the identical
        basename-only redaction is applied here under --redact-paths
        rather than shipping this one field unredacted.
        """
        try:
            from dumpex.rules_pkg.loader import get_rules_source_info
            info = get_rules_source_info()
            if info is None:
                return None
            info = dict(info)
            if self._redact_paths and info.get("path"):
                info["path"] = os.path.basename(info["path"].rstrip("/\\"))
            return info
        except Exception as e:
            return {"error": str(e)}

    def _yara_meta(self):
        """
        YARA rule provenance (sorted rule filenames, per-file sha256,
        aggregate sha256, compile success/fail counts) for the rule files
        actually used by the most recent --hunt yara/all run — the same
        reproducibility guarantee meta.rules already gives rules.yaml.
        None if YARA scanning was never invoked this run (e.g. --hunt
        injection alone, which never loads any .yar/.yara file) —
        omitted from meta entirely in that case rather than printed as a
        misleading empty object.
        """
        try:
            from dumpex.hunt.yara_hunt import get_yara_provenance
            info = get_yara_provenance()
            if info is None:
                return None
            info = dict(info)
            if self._redact_paths and info.get("rules_dir"):
                info["rules_dir"] = os.path.basename(info["rules_dir"].rstrip("/\\"))
            return info
        except Exception as e:
            return {"error": str(e)}

    def _build_meta(self) -> dict:
        finished_at = datetime.datetime.now(datetime.timezone.utc)
        try:
            meta = {
                "schema_version": self.SCHEMA_VERSION,
                "tool":           self._tool_meta(),
                "execution":      self._execution_meta(finished_at),
                "evidence":       self._evidence_meta(),
                "runtime":        self._runtime_meta(),
            }
            rules = self._rules_meta()
            if rules is not None:
                meta["rules"] = rules
            yara_meta = self._yara_meta()
            if yara_meta is not None:
                meta["yara_rules"] = yara_meta
            return meta
        except Exception as e:
            # Last-resort net: meta construction itself must never take
            # down an otherwise-complete analysis's JSON output.
            return {"schema_version": self.SCHEMA_VERSION, "error": f"metadata construction failed: {e}"}

    # ── JSON ─────────────────────────────────────────────────────────────

    def to_json(self) -> str:
        doc = {"meta": self._build_meta()}
        doc.update(_json_safe(self._sections))
        return json.dumps(doc, indent=2, ensure_ascii=False)

    def write_json(self, path: str, cmd_label: str = "", force: bool = False):
        p = write_text_to_target(path, self.to_json(), ".json", cmd_label,
                                  self._dump_path_abs, force, "--json output")
        print(DIM(f"  [·] JSON written → {p}  ({summarize_file(p)})"))

    # ── CSV ──────────────────────────────────────────────────────────────

    def write_csv(self, path: str, cmd_label: str = "", force: bool = False):
        """
        Write structured output as CSV.

        Two modes, auto-detected from the path argument:

        Directory mode  (path has no .csv extension, e.g. "output/")
            One file per logical table:
            dumpex_<cmd_label>_<section>_<table>.csv

        Single-file mode  (path ends with .csv, e.g. "result.csv")
            All tables written into a single CSV file, separated by a blank
            row and a "## section / table" header line.

        Both modes write to a scratch temp file first, then commit; nothing
        is ever created at/near the final path(s) until content is ready.
        Single-file mode refuses to clobber an existing file unless
        force=True; directory mode instead auto-picks a fresh,
        collision-free filename per table (dumpex_..._001.csv, _002.csv,
        ...) so a same-second re-run can never silently overwrite a prior
        table — see write_text_to_directory / commit_to_directory. Every
        candidate filename — in both modes, regardless of force — is
        checked against the input dump path immediately before it is
        committed.
        """
        p_in  = Path(path)
        label = f"{cmd_label}_" if cmd_label else ""

        # ── Single-file mode ─────────────────────────────────────────────
        if p_in.suffix.lower() == ".csv":
            buf = io.StringIO()
            total_rows = 0
            for section, data in self._sections.items():
                tables = self._section_to_tables(section, data)
                for table_name, rows in tables.items():
                    if not rows:
                        continue
                    buf.write(f"## {section} / {table_name}\n")
                    writer = csv.DictWriter(buf, fieldnames=rows[0].keys(),
                                           extrasaction="ignore",
                                           lineterminator="\n")
                    writer.writeheader()
                    writer.writerows(rows)
                    buf.write("\n")
                    total_rows += len(rows)
            p = write_text_to_target(path, buf.getvalue(), ".csv", cmd_label,
                                      self._dump_path_abs, force, "--csv output",
                                      newline="")
            print(DIM(f"  [·] CSV  written → {p}  ({total_rows} row(s) across all tables, {summarize_file(p)})"))
            return

        # ── Directory mode ───────────────────────────────────────────────
        for section, data in self._sections.items():
            tables = self._section_to_tables(section, data)
            for table_name, rows in tables.items():
                if not rows:
                    continue
                stem = f"dumpex_{label}{section}_{table_name}"
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=rows[0].keys(),
                                       extrasaction="ignore",
                                       lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
                fname = write_text_to_directory(p_in, buf.getvalue(), stem, ".csv",
                                                 self._dump_path_abs, force,
                                                 f"CSV table output ({stem}.csv)",
                                                 newline="")
                print(DIM(f"  [·] CSV  written → {fname}  ({len(rows)} row(s), {summarize_file(fname)})"))

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
            finding_detail_rows = []   # facts/inference/confidence/rationale/limitations
                                        # — one row per dumpex.hunt._finding.Finding,
                                        # populated from findings["findings"] wherever a
                                        # hunt module reports it (injection/stomping/pipe/
                                        # obfuscation/cs-beacon as of phase three)

            for ttp, findings in data.items():
                if ttp.startswith("_"):
                    continue   # metadata (e.g. "_rules_source"), not a TTP's findings
                if not isinstance(findings, dict):
                    continue
                score     = findings.get("score", 0)
                status    = findings.get("status", "")
                max_score = findings.get("max_score") or {
                             "injection": 3, "hollowing": 2, "stomping": 2,
                             "pipe": 3, "cs-beacon": 2, "yara": 3,
                             "obfuscation": 2}.get(ttp, "?")

                # Phase-two/three/four hunters (injection/stomping/pipe/
                # obfuscation/cs-beacon/hollowing) report their own
                # "verdict_level" (clean/possible/likely/high), "confidence"
                # (none/low/medium/high), and "coverage_status" (complete/
                # partial/not_evaluated), all computed independently of
                # score — yara_hunt is still on the legacy model and
                # falls back to the score/max_score heuristic below.
                hunter_verdict_level   = findings.get("verdict_level")
                hunter_confidence      = findings.get("confidence")
                hunter_coverage_status = findings.get("coverage_status")

                # Verdict must be driven by status, not score alone: a
                # NOT_EVALUATED scanner (dependency/stream missing) or an
                # INCONCLUSIVE one (partial coverage — segments skipped,
                # unreadable, timed out) both report score=0, and score==0
                # alone reading as "CLEAN" is exactly the false-negative
                # this status model exists to prevent — a downstream SIEM/
                # SOAR consuming this CSV has no other signal to catch it.
                if status == "NOT_EVALUATED":
                    verdict           = "NOT_EVALUATED"
                    coverage_complete = False
                elif status == "INCONCLUSIVE":
                    verdict           = "INCONCLUSIVE"
                    coverage_complete = False
                else:
                    # status is DETECTED or NOT_DETECTED_IN_SCANNED_SCOPE
                    # here — but a phase-two hunter's OWN coverage_status
                    # can still be "partial" even when it found something
                    # (DETECTED): a nonzero score must not silently imply
                    # complete coverage just because status won the race
                    # against a coverage gap (see dumpex.hunt.stomping/
                    # dumpex.hunt.pipe/dumpex.hunt.encoding/dumpex.hunt.injection
                    # "DETECTED but partial" handling).
                    coverage_complete = (hunter_coverage_status != "partial"
                                          if hunter_coverage_status is not None else True)
                    if hunter_verdict_level is not None:
                        # The hunter's OWN verdict_level, printed as-is —
                        # NEVER re-derived here from score/confidence.
                        # Different hunters have different max scores and
                        # different evidentiary weight per point (stomping's
                        # max is 2, injection's is 3), so a single
                        # generic formula produced console text and CSV
                        # text that disagreed with each other for the same
                        # finding (e.g. stomping 1/2 showing LIKELY on the
                        # console but POSSIBLE in the CSV). Each hunter
                        # owns its own score->level table; this is purely
                        # a display transform (upper-casing) of that.
                        verdict = hunter_verdict_level.upper()
                    elif hunter_confidence is not None:
                        verdict = ("CLEAN" if score == 0 else
                                   "HIGH CONFIDENCE" if hunter_confidence == "high" else
                                   "POSSIBLE")
                    else:
                        verdict = ("CLEAN"           if score == 0 else
                                   "HIGH CONFIDENCE" if isinstance(max_score, int) and score >= max_score - 1
                                   else "POSSIBLE")

                coverage = findings.get("coverage") or {}
                coverage_reasons_list = findings.get("coverage_reasons")
                if not coverage_complete:
                    if coverage_reasons_list:
                        coverage_reason = "; ".join(coverage_reasons_list)
                    else:
                        missing = [k for k, v in coverage.items() if not v]
                        coverage_reason = (f"missing: {', '.join(missing)}" if missing else
                                            "not evaluated" if status == "NOT_EVALUATED" else
                                            "partial coverage")
                else:
                    coverage_reason = ""

                summary_rows.append({
                    "ttp": ttp, "score": score, "max_score": max_score,
                    "status": status, "verdict": verdict,
                    "verdict_level": hunter_verdict_level or "",
                    "confidence": hunter_confidence or "",
                    "coverage_complete": coverage_complete,
                    "coverage_reason": coverage_reason,
                    # Only populated for hunters on the shared Finding model
                    # (see dumpex.hunt._finding.lead_count/.review_priority)
                    # — "" for legacy hunters (yara_hunt) rather than 0/
                    # "none", so a consumer can't mistake "field not
                    # computed" for "computed as zero/none".
                    "lead_count": findings.get("lead_count", ""),
                    "review_priority": findings.get("review_priority", ""),
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

                # Shared blank row template — every finding_type below only
                # fills in the columns relevant to it; "details" carries
                # whatever doesn't have a dedicated column.
                def _blank_row(finding_type, va=0, fo=None, details=""):
                    return {
                        "ttp": ttp, "finding_type": finding_type,
                        "va_process":  f"0x{va:016x}" if va else "",
                        "file_offset": f"0x{fo:x}" if fo else "",
                        "cs_version": "", "xor_key": "", "beacon_type": "",
                        "c2_host": "", "c2_uri": "", "port": "",
                        "useragent": "", "pipename": "", "license_id": "",
                        "sleep_ms": "", "jitter_pct": "", "details": details,
                    }

                # Injection findings. Guarded by ttp (not just dict-key
                # presence): "hidden_pe_validated" is injection-specific —
                # obfuscation's "hidden_pe" key holds a differently-shaped
                # dict (dumpex.hunt.encoding.models.Hit.to_dict(): layer/
                # region/offset/decoded/cls/..., not region/pe like this
                # one), so keying off ttp avoids reading the wrong shape
                # from the wrong TTP.
                if ttp == "injection":
                    for r in findings.get("rwx", []):
                        fo = (va_to_file_offset(self._mf, r.BaseAddress) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "injection_rwx_region", r.BaseAddress, fo,
                            f"AllocationBase=0x{r.AllocationBase:x}; RegionSize=0x{r.RegionSize:x}; "
                            f"Protect={prot_str(r.Protect)}"))
                    for h in findings.get("hidden_pe_validated", []):
                        r, pe = h["region"], h["pe"]
                        fo = (va_to_file_offset(self._mf, r.BaseAddress) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "injection_hidden_pe_validated", r.BaseAddress, fo,
                            f"AllocationBase=0x{r.AllocationBase:x}; machine={pe['machine_name']}; "
                            f"sections={pe['number_of_sections']}"))
                    for h in findings.get("hidden_pe_unvalidated", []):
                        r, pe = h["region"], h["pe"]
                        fo = (va_to_file_offset(self._mf, r.BaseAddress) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "injection_mz_prefix_unvalidated", r.BaseAddress, fo,
                            f"reason={pe['reason']}"))
                    for ti in findings.get("threads", []):
                        sa = ti.StartAddress or 0
                        fo = (va_to_file_offset(self._mf, sa) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "injection_unbacked_thread_startaddr", sa, fo,
                            f"TID=0x{ti.ThreadId:x}"))
                    for tc, r in findings.get("rip_hits", []):
                        fo = (va_to_file_offset(self._mf, tc["ip"]) if self._mf else None)
                        full = r.AllocationBase in set(findings.get("rwx_and_pe_alloc_bases", []))
                        findings_rows.append(_blank_row(
                            "injection_rip_in_suspicious_allocation", tc["ip"], fo,
                            f"TID=0x{tc['ThreadId']:x}; {tc['ip_reg']}; "
                            f"AllocationBase=0x{r.AllocationBase:x}; full_correlation={full}"))

                # Hollowing: no per-item collection exists on the findings
                # dict (score-only checks) — summary_rows already carries
                # the score/verdict, nothing further to flatten per-item.

                # Stomping findings
                if ttp == "stomping":
                    for m in findings.get("section_mismatches", []):
                        module, sec, r = m["module"], m["section"], m["region"]
                        fo = (va_to_file_offset(self._mf, r.BaseAddress) if self._mf else None)
                        modname = os.path.basename(module.name) if module.name else "(unnamed module)"
                        disk_diff = m.get("disk_diff")
                        findings_rows.append(_blank_row(
                            "stomping_section_protection_mismatch", r.BaseAddress, fo,
                            f"module={modname}; section={sec['name']!r}; "
                            f"declared={m['expected']}; actual={m['actual']}; "
                            f"live_rip={'yes' if m.get('rip_hit') else 'no'}; "
                            f"disk_diff_match={disk_diff['match'] if disk_diff else 'n/a'}"))

                # Obfuscation (dumpex/hunt/encoding/ package) findings.
                # sleep_mask/entropy/hidden_pe/hidden_shellcode hold plain
                # dicts -- the output of dumpex.hunt.encoding.models.Hit/
                # EntropyHit.to_dict(), NOT the Hit/EntropyHit objects
                # themselves. aggregate.py deliberately converts before
                # returning `findings`, because _json_safe below has no
                # dataclass case and would otherwise fall back to
                # str(obj) for the raw object -- embedding a live memory
                # address and the full undecoded `decoded` bytes into the
                # JSON output. `region` is itself a nested dict
                # (BaseAddress/RegionSize/State/Protect/Type) for the same
                # reason -- see models._region_to_dict.
                if ttp == "obfuscation":
                    for hit in findings.get("sleep_mask", []):
                        r  = hit.get("region")
                        va = r["BaseAddress"] if r else 0
                        fo = (va_to_file_offset(self._mf, va) if self._mf and va else None)
                        key = hit.get("key")
                        key_str = key.hex() if isinstance(key, (bytes, bytearray)) else str(key)
                        findings_rows.append(_blank_row(
                            "obfuscation_sleep_mask_confirmed", va, fo, f"key=0x{key_str}"))
                    for hit in findings.get("entropy", []):
                        va = hit["region"]["BaseAddress"]
                        fo = (va_to_file_offset(self._mf, va) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "obfuscation_entropy_observation", va, fo,
                            f"entropy={hit['entropy']:.3f}; threshold={hit['threshold']}"))
                    for hit in findings.get("hidden_pe", []):
                        abs_va = hit["region"]["BaseAddress"] + hit["offset"]
                        fo = (va_to_file_offset(self._mf, abs_va) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "obfuscation_structural_pe_payload", abs_va, fo,
                            f"encoding={hit['layer']}; decoded_len={len(hit['decoded'])}"))
                    for hit in findings.get("hidden_shellcode", []):
                        abs_va = hit["region"]["BaseAddress"] + hit["offset"]
                        fo = (va_to_file_offset(self._mf, abs_va) if self._mf else None)
                        findings_rows.append(_blank_row(
                            "obfuscation_structural_shellcode_payload", abs_va, fo,
                            f"encoding={hit['layer']}; decoded_len={len(hit['decoded'])}"))

                # Pipe findings
                for hc in findings.get("handle_pipes", []):
                    h = hc["handle"]
                    fm = hc.get("framework_match")
                    findings_rows.append({
                        "ttp":          ttp,
                        "finding_type": "pipe_open_handle",
                        "va_process":   "", "file_offset": "",
                        "cs_version":   "", "xor_key":   "", "beacon_type": "",
                        "c2_host":      "", "c2_uri":     "", "port":        "",
                        "useragent":    "", "pipename":   h.ObjectName,
                        "license_id":   "", "sleep_ms":   "", "jitter_pct":  "",
                        "details":      f"Handle=0x{h.Handle:x}" + (f"; framework={fm[0]}" if fm else ""),
                    })
                for hit in findings.get("private_pipes", []):
                    r, off, name = hit["region"], hit["offset"], hit["name"]
                    abs_va = r.BaseAddress + off
                    fo     = (va_to_file_offset(self._mf, abs_va) or 0) if self._mf else 0
                    pipename = name.strip()
                    if hit.get("truncated"):
                        pipename += f" [truncated, sha256={hit['sha256'][:16]}…]"
                    findings_rows.append({
                        "ttp":          ttp,
                        "finding_type": "pipe_string_scan_lead",
                        "va_process":   f"0x{abs_va:016x}",
                        "file_offset":  f"0x{fo:x}" if fo else "",
                        "cs_version":   "", "xor_key":   "", "beacon_type": "",
                        "c2_host":      "", "c2_uri":     "", "port":        "",
                        "useragent":    "", "pipename":   pipename,
                        "license_id":   "", "sleep_ms":   "", "jitter_pct":  "",
                        "details":      prot_str(r.Protect),
                    })

                # Phase-two Finding schema (facts/inference/confidence/
                # rationale/limitations) — populated by injection/stomping/
                # pipe/obfuscation via findings["findings"]. One row per
                # Finding, independent of the legacy per-item rows above.
                for f in findings.get("findings", []):
                    finding_detail_rows.append({
                        "ttp":         ttp,
                        "check":       f.get("check", ""),
                        "tag":         f.get("tag", ""),
                        "confidence":  f.get("confidence", ""),
                        "inference":   f.get("inference", ""),
                        "rationale":   f.get("rationale", ""),
                        "facts":       " | ".join(f.get("facts", [])),
                        "limitations": " | ".join(f.get("limitations", [])),
                    })

            tables = {"summary": summary_rows}
            if findings_rows:
                tables["findings"] = findings_rows
            if finding_detail_rows:
                tables["finding_details"] = finding_detail_rows
            return tables

        # Fallback: try list-of-dicts as-is
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return {section: data}

        return {}

