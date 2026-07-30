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
reporting incomplete evidence (coverage.status="partial").
EXECUTION_COMPLETED/PARTIAL/FAILED are imported from
dumpex.output.coverage (the neutral command/domain-layer vocabulary
module), not defined here, so this wire-format layer depends on the
domain model rather than the other way around.
"""
import os
import platform
import datetime
import importlib.metadata
from dataclasses import dataclass, field

from dumpex.core.evidence import sha256_file
from dumpex.output.coverage import EXECUTION_COMPLETED, EXECUTION_PARTIAL, EXECUTION_FAILED

__all__ = [
    "SCHEMA_VERSION", "EXECUTION_COMPLETED", "EXECUTION_PARTIAL", "EXECUTION_FAILED",
    "build_meta_v2", "Result", "Envelope",
]

SCHEMA_VERSION = "2.0"

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
    """
    Each of tool/execution/evidence/runtime is isolated in its OWN
    try/except rather than one try wrapping the whole document: the v2
    schema requires meta.tool/meta.execution/meta.evidence (only
    meta.runtime is optional) with their own required sub-fields, so a
    single all-or-nothing except that replaced the entire meta object
    with just {"schema_version", "error"} (as a prior version of this
    function did) would itself be schema-invalid -- silently producing a
    document that claims "schema_version: 2.0" but cannot pass the very
    schema it names. Each fallback below still satisfies every field
    dumpex-output-v2.0.schema.json's $defs/meta requires, with an "error"
    key added alongside (additionalProperties is not restricted on these
    objects) so the failure is visible rather than merely papered over.
    """
    meta = {"schema_version": SCHEMA_VERSION}

    try:
        meta["tool"] = _tool_meta()
    except Exception as e:
        meta["tool"] = {"name": "dumpex", "version": None,
                         "error": f"tool metadata failed: {e}"}

    try:
        meta["execution"] = {
            "started_at":       started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at":      finished_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "command":          command,
            "options":          _redact_options(options) if redact_paths else dict(options),
            "case_id":          case_id,
            "analyst":          analyst,
        }
    except Exception as e:
        meta["execution"] = {
            "started_at": str(started_at), "finished_at": str(finished_at),
            "duration_seconds": 0.0, "command": command, "options": {},
            "case_id": case_id, "analyst": analyst,
            "error": f"execution metadata failed: {e}",
        }

    try:
        meta["evidence"] = [_evidence_entry(dump_path_abs, dump_file_name, "primary", "primary",
                                             redact_paths)]
    except Exception as e:
        meta["evidence"] = [{"id": "primary", "role": "primary",
                              "error": f"evidence metadata failed: {e}"}]

    try:
        meta["runtime"] = _runtime_meta()
    except Exception:
        pass   # optional field -- omitted entirely on failure, not required by the schema

    return meta


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
