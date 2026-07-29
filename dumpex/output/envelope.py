"""v2 meta/result/envelope construction.

Mirrors dumpex/ui/structured.py's StructuredOutput._tool_meta/
_execution_meta/_runtime_meta/_evidence_meta (same failure-isolation
style: a failure computing one piece of meta must never take down the
rest, or the actual result), but meta.evidence is a LIST here, not a
single object -- so a future comparison command (baseline + target
dumps) doesn't force a second breaking meta change. This PR always
emits a single-element evidence array.

execution_status ("completed"/"partial"/"failed") and coverage.status
("complete"/"partial"/"not_evaluated") are kept as two independent axes
-- a command can finish (execution_status="completed") while still
reporting incomplete evidence (coverage.status="partial"). coverage's
vocabulary is imported from dumpex.hunt._coverage, not redefined, so the
two output contracts never drift on what "partial"/"complete" mean.
"""
import os
import platform
import datetime
import importlib.metadata
from dataclasses import dataclass, field

from dumpex.core.evidence import sha256_file
from dumpex.hunt._coverage import derive_coverage_status   # re-exported below

__all__ = [
    "SCHEMA_VERSION", "EXECUTION_COMPLETED", "EXECUTION_PARTIAL", "EXECUTION_FAILED",
    "derive_coverage_status", "build_meta_v2", "Result", "Envelope",
]

SCHEMA_VERSION = "2.0"

EXECUTION_COMPLETED = "completed"
EXECUTION_PARTIAL   = "partial"
EXECUTION_FAILED    = "failed"

# CLI options whose VALUE is a filesystem path -- same redaction concern
# as dumpex.ui.structured's _PATH_OPTION_KEYS, kept as its own copy here
# rather than importing that module's private name, so v2 never depends
# on v1's internals.
_PATH_OPTION_KEYS = frozenset({"ref_dir", "yara_dir", "rules_file"})


def _redact_options(options: dict) -> dict:
    out = {}
    for k, v in options.items():
        if k in _PATH_OPTION_KEYS and isinstance(v, str) and v:
            out[k] = os.path.basename(v.rstrip("/\\"))
        else:
            out[k] = v
    return out


def _tool_meta() -> dict:
    try:
        version = importlib.metadata.version("dumpex")
    except importlib.metadata.PackageNotFoundError:
        import dumpex
        version = getattr(dumpex, "__version__", None)
    return {"name": "dumpex", "version": version}


def _runtime_meta() -> dict:
    info = {"python_version": platform.python_version()}
    for dist_name, key in (("minidump", "minidump_version"),
                            ("yara-python", "yara_version"),
                            ("pyyaml", "pyyaml_version")):
        try:
            info[key] = importlib.metadata.version(dist_name)
        except importlib.metadata.PackageNotFoundError:
            pass
    return info


def _evidence_entry(dump_path_abs: str, dump_file_name: str, id_: str, role: str,
                     redact_paths: bool) -> dict:
    entry = {"id": id_, "role": role, "file_name": dump_file_name}
    if not redact_paths:
        entry["path"] = dump_path_abs
    try:
        entry["size_bytes"] = os.path.getsize(dump_path_abs)
    except OSError as e:
        entry["size_bytes"] = None
        entry["error"] = f"could not stat evidence file: {e}"
        return entry
    try:
        entry["sha256"] = sha256_file(dump_path_abs)
    except Exception as e:
        entry["error"] = f"sha256 computation failed: {e}"
    return entry


def build_meta_v2(*, dump_path_abs: str, dump_file_name: str, command: "str | None",
                   options: dict, case_id: "str | None", analyst: "str | None",
                   redact_paths: bool, started_at: "datetime.datetime",
                   finished_at: "datetime.datetime") -> dict:
    try:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": _tool_meta(),
            "execution": {
                "started_at":       started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "finished_at":      finished_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
                "command":          command,
                "options":          _redact_options(options) if redact_paths else dict(options),
                "case_id":          case_id,
                "analyst":          analyst,
            },
            "evidence": [_evidence_entry(dump_path_abs, dump_file_name, "primary", "primary",
                                          redact_paths)],
            "runtime": _runtime_meta(),
        }
    except Exception as e:
        # Last-resort net, matching StructuredOutput._build_meta: meta
        # construction must never take down an otherwise-complete result.
        return {"schema_version": SCHEMA_VERSION, "error": f"metadata construction failed: {e}"}


@dataclass
class Result:
    """result.* -- already-serializable pieces only (records must be
    plain dicts by construction time; see collector.V2Output.set_result,
    which calls each record's own to_dict() before building this)."""
    kind:              str
    execution_status:  str
    coverage_status:   str
    coverage_reasons:  list = field(default_factory=list)
    summary:           dict = field(default_factory=dict)
    records:           list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind":             self.kind,
            "execution_status": self.execution_status,
            "coverage": {
                "status":  self.coverage_status,
                "reasons": list(self.coverage_reasons),
            },
            "summary": dict(self.summary),
            "data":    {"records": list(self.records)},
        }


@dataclass
class Envelope:
    """The whole v2 document. diagnostics entries must already be plain
    dicts (Diagnostic.to_dict()) by construction time, same rule as
    Result.records."""
    meta:                dict
    result:              Result
    artifacts:           list = field(default_factory=list)
    diagnostics_warnings: list = field(default_factory=list)
    diagnostics_errors:   list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "meta":   self.meta,
            "result": self.result.to_dict(),
            "artifacts": list(self.artifacts),
            "diagnostics": {
                "warnings": list(self.diagnostics_warnings),
                "errors":   list(self.diagnostics_errors),
            },
        }
