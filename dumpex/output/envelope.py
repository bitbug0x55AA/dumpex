"""v2 meta/result/envelope construction.

Mirrors dumpex/ui/structured.py's StructuredOutput._tool_meta/
_execution_meta/_runtime_meta/_evidence_meta (same failure-isolation
style: a failure computing one piece of meta must never take down the
rest, or the actual result), but meta.evidence is a LIST here, not a
single object -- so a comparison command (baseline + target dumps)
doesn't force a second breaking meta change. Every one of the six
original recon commands still emits a single-element evidence array
(build_meta_v2's dump_path_abs/dump_file_name form); build_meta_v2's
evidence= parameter is the multi-entry form Phase C adds for that
future comparison command -- see EvidenceInput below.

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
    "EvidenceInput", "build_meta_v2", "Result", "Envelope",
]

SCHEMA_VERSION = "2.10"

# CLI options whose VALUE is a filesystem path -- same redaction concern
# as dumpex.ui.structured's _PATH_OPTION_KEYS, kept as its own copy here
# rather than importing that module's private name, so v2 never depends
# on v1's internals. "output" (--extract's own --output path) joined
# ref_dir/yara_dir/rules_file here -- it was missing entirely, so
# meta.execution.options.output kept leaking the full absolute path even
# with --redact-paths set.
_PATH_OPTION_KEYS = frozenset({"ref_dir", "yara_dir", "rules_file", "output"})


def _redact_options(options: dict) -> dict:
    out = {}
    for k, v in options.items():
        if k in _PATH_OPTION_KEYS and isinstance(v, str) and v:
            out[k] = os.path.basename(v.rstrip("/\\"))
        else:
            out[k] = v
    return out


def _redact_artifacts(artifacts: list) -> list:
    """Non-destructive: returns NEW dicts with `path` reduced to its
    basename, same redaction rule as _redact_options -- size_bytes/
    sha256/description are left untouched (only the filesystem location
    is sensitive, not the file's own facts). The caller's own artifact
    dicts (also used by V2Output's already-written-output protection --
    see collector.py) are never mutated;
    this always returns a fresh list of fresh dicts."""
    out = []
    for a in artifacts:
        a2 = dict(a)
        path = a2.get("path")
        if isinstance(path, str) and path:
            a2["path"] = os.path.basename(path.rstrip("/\\"))
        out.append(a2)
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


def _rules_meta(redact_paths: bool) -> "dict | None":
    """v2 counterpart to dumpex.ui.structured.StructuredOutput._rules_meta
    -- same provenance (which rules.yaml, its sha256, whether it was
    explicitly supplied via --rules-file), same basename-only redaction
    under --redact-paths, same "None if get_rules() was never called this
    run" contract (omitted from meta entirely rather than a misleading
    empty object)."""
    try:
        from dumpex.rules_pkg.loader import get_rules_source_info
        info = get_rules_source_info()
        if info is None:
            return None
        info = dict(info)
        if redact_paths and info.get("path"):
            info["path"] = os.path.basename(info["path"].rstrip("/\\"))
        return info
    except Exception as e:
        return {"error": str(e)}


def _yara_rules_meta(redact_paths: bool) -> "dict | None":
    """v2 counterpart to dumpex.ui.structured.StructuredOutput._yara_meta
    -- same provenance (sorted rule filenames, per-file sha256, aggregate
    sha256, compile success/fail counts) for the rule files actually used
    by the most recent --hunt yara/all run, same basename-only redaction
    under --redact-paths, same "None if YARA scanning was never invoked
    this run" contract."""
    try:
        from dumpex.hunt.yara_hunt import get_yara_provenance
        info = get_yara_provenance()
        if info is None:
            return None
        info = dict(info)
        if redact_paths and info.get("rules_dir"):
            info["rules_dir"] = os.path.basename(info["rules_dir"].rstrip("/\\"))
        return info
    except Exception as e:
        return {"error": str(e)}


@dataclass(frozen=True)
class EvidenceInput:
    """One dump file for meta.evidence -- the multi-entry counterpart to
    build_meta_v2's dump_path_abs/dump_file_name single-entry form. A
    comparison command builds two of these (e.g. id="baseline",
    role="baseline" / id="target", role="target") and passes them as
    build_meta_v2's evidence= list; a single-dump recon command keeps
    using dump_path_abs/dump_file_name unchanged and never constructs
    one of these at all. id/role are deliberately separate fields (not
    collapsed into one) for the same reason the six existing commands'
    hardcoded "primary"/"primary" pair keeps them separate: id is a
    stable identifier a future record could reference, role is the
    human-facing label -- they happen to coincide in every case that
    exists today, but nothing requires that."""
    id:   str
    role: str
    path: str

    def __post_init__(self):
        for field_name in ("id", "role", "path"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"EvidenceInput.{field_name} must be a non-empty string")


def _normalize_evidence_inputs(evidence) -> "list[EvidenceInput]":
    """The single place an `evidence=` argument is validated and
    normalized -- shared by build_meta_v2() and V2Output so the two can
    never drift apart on what counts as valid (a review round found
    build_meta_v2(), a public __all__ export, silently accepting
    everything V2Output's own constructor already rejected: duplicate
    ids, bare dicts, dump_path_abs+evidence together).

    Restricted to list/tuple specifically -- like coverage.py's own
    _normalize_tuple, for the same reason: a generator would otherwise
    be silently exhausted by the first of several validation passes this
    function makes over it (non-empty check, per-entry type check,
    id-uniqueness check, path normalization), leaving every later pass
    operating on an already-empty sequence. That exact bug previously
    produced meta.evidence=[] (violating the schema's minItems: 1) AND
    an empty _protected_paths (silently disabling the overwrite guard)
    from a single generator argument -- rejecting non-list/tuple up
    front closes both at once rather than requiring three separate
    "did I consume this already" fixes downstream.

    Each returned EvidenceInput has its `path` already resolved to an
    absolute path, exactly once, here -- the same normalized objects are
    what both meta construction (_safe_evidence_entry) and overwrite
    protection (V2Output._protected_paths) read from, so the two can
    never disagree about which on-disk file a given entry refers to even
    if the process's current working directory changes between
    construction and serialization time (os.path.abspath is cwd-relative
    and was previously being called fresh, a second time, at
    serialization -- a caller-visible identity drift, not just a
    cosmetic difference, if cwd changed in between).
    """
    if not isinstance(evidence, (list, tuple)):
        raise TypeError(
            f"evidence must be a list or tuple of EvidenceInput, got {type(evidence).__name__}")
    if not evidence:
        raise ValueError(
            "evidence requires at least one EvidenceInput -- an empty list would produce "
            "meta.evidence=[], which violates the v2 schema's minItems: 1")
    normalized = []
    for ei in evidence:
        if not isinstance(ei, EvidenceInput):
            raise TypeError(
                f"evidence entries must be EvidenceInput instances, got {type(ei).__name__} -- "
                f"a bare dict would otherwise reach build_meta_v2 and fail with an unrelated "
                f"AttributeError instead of a clear message at the actual point of misuse")
        normalized.append(EvidenceInput(id=ei.id, role=ei.role, path=os.path.abspath(ei.path)))
    ids = [ei.id for ei in normalized]
    if len(set(ids)) != len(ids):
        raise ValueError(
            f"evidence entries must have unique id values (role may repeat), got ids={ids!r} "
            f"-- id is a stable identifier a future comparison record could reference, so a "
            f"duplicate would make that reference ambiguous")
    return normalized


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


def _safe_evidence_entry(ei: EvidenceInput, redact_paths: bool) -> dict:
    """Wraps _evidence_entry in its OWN try/except, isolated per entry --
    unlike the single-entry case (where one try/except around the whole
    call is enough because there's only one entry to lose), a multi-
    entry evidence list must not let one side's unexpected failure (not
    just the OSError/hash-Exception _evidence_entry already handles
    internally, but anything else, e.g. a bad path type slipping past
    EvidenceInput's own validation) blank out an already-successful
    sibling entry -- see SourceState.FAILED's own docstring in
    coverage.py for the same "one side failing shouldn't abort the
    other" principle applied to comparison/diff source reads."""
    try:
        return _evidence_entry(os.path.abspath(ei.path), os.path.basename(ei.path),
                                ei.id, ei.role, redact_paths)
    except Exception as e:
        return {"id": ei.id, "role": ei.role, "error": f"evidence metadata failed: {e}"}


def build_meta_v2(*, dump_path_abs: "str | None" = None, dump_file_name: "str | None" = None,
                   evidence: "list[EvidenceInput] | None" = None,
                   command: "str | None",
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
    document that claims "schema_version: 2.2" but cannot pass the very
    schema it names. Each fallback below still satisfies every field
    dumpex-output-v2.2.schema.json's $defs/meta requires, with an "error"
    key added alongside (additionalProperties is not restricted on these
    objects) so the failure is visible rather than merely papered over.
    """
    if (dump_path_abs is None) == (evidence is None):
        # Both None -> nothing to build meta.evidence from. Both given ->
        # genuinely ambiguous (a review round found this silently picking
        # evidence and dropping dump_path_abs entirely, rather than
        # raising) -- exactly one is required, always, for the same
        # reason V2Output's own constructor enforces this (see there).
        raise TypeError(
            "build_meta_v2() requires exactly one of dump_path_abs (single-dump commands) or "
            "evidence (multi-dump commands), got "
            + ("neither" if dump_path_abs is None else "both"))
    if dump_path_abs is not None and not dump_file_name:
        raise TypeError(
            "build_meta_v2(dump_path_abs=...) also requires a non-empty dump_file_name")
    if evidence is not None:
        # _normalize_evidence_inputs is the single place this validation
        # (non-empty, real EvidenceInput instances, unique ids, absolute
        # paths) lives -- shared with V2Output so the two constructors
        # can never accept a shape the other would reject.
        evidence = _normalize_evidence_inputs(evidence)

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

    if evidence is not None:
        # Each entry is isolated in _safe_evidence_entry itself (not one
        # try/except wrapping the whole list) -- see that function's own
        # docstring for why: a comparison's baseline/target sides must
        # not let one side's failure blank out the other's already-
        # successful entry.
        meta["evidence"] = [_safe_evidence_entry(ei, redact_paths) for ei in evidence]
    else:
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

    # rules/yara_rules are both optional, omitted entirely (not even as an
    # error placeholder) when the corresponding loader was never invoked
    # this run -- see each helper's own docstring. This mirrors
    # dumpex.ui.structured.StructuredOutput._build_meta's identical
    # if-not-None-then-attach pattern, so v1.1 and v2 report the exact
    # same provenance for the exact same run.
    rules = _rules_meta(redact_paths)
    if rules is not None:
        meta["rules"] = rules
    yara_rules = _yara_rules_meta(redact_paths)
    if yara_rules is not None:
        meta["yara_rules"] = yara_rules

    return meta


@dataclass
class Result:
    """result.* -- already-serializable pieces only (records must be
    plain dicts by construction time; see collector.V2Output.
    set_command_result, which calls each record's own to_dict() before
    building this). coverage_sources/coverage_limitations are likewise
    pre-dict-ified by the caller (dumpex.output.coverage's
    SourceObservation.to_dict()/CoverageLimitation.to_dict()) -- this
    dataclass never imports dumpex.output.coverage itself, matching the
    existing rule that this wire-format layer depends on the domain
    model, not the reverse."""
    kind:                str
    execution_status:    str
    coverage_status:     str
    coverage_reasons:    list = field(default_factory=list)
    coverage_sources:    dict = field(default_factory=dict)
    coverage_limitations: list = field(default_factory=list)
    summary:             dict = field(default_factory=dict)
    records:             list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind":             self.kind,
            "execution_status": self.execution_status,
            "coverage": {
                "status":       self.coverage_status,
                "reasons":      list(self.coverage_reasons),
                "sources":      dict(self.coverage_sources),
                "limitations":  list(self.coverage_limitations),
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
