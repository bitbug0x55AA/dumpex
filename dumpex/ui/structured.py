"""Structured JSON output. Plain-text tee lives in core/safe_io.py
(AtomicTextTee) — kept there because it shares atomic-write plumbing with
the rest of the output-safety helpers."""
import re
import os
import json
import platform
import datetime
import importlib.metadata
from dumpex.ui.colors import DIM
from dumpex.core.safe_io import write_text_to_target, summarize_file
from dumpex.core.evidence import cached_sha256_file

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
    them to JSON on demand.

    Usage
    -----
    out = StructuredOutput(dump_path, mf, command="hunt_all",
                            options={"hunt": "all", "verbose": False})
    out.add("modules",  cmd_modules(mf))
    out.add("hunt",     cmd_hunt(mf, ...))
    out.write_json("results.json")
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
                self._evidence_sha256 = cached_sha256_file(self._dump_path_abs)
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
