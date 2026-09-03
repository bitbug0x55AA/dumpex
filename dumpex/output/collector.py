"""Collect one command run into the versioned v2 output envelope."""
import os
import datetime

from dumpex.ui.colors import DIM
from dumpex.core.safe_io import write_text_to_target, summarize_file
from dumpex.output.envelope import build_meta_v2, Result, Envelope, EvidenceInput, \
    _normalize_evidence_inputs, _redact_artifacts
from dumpex.output.serializer import to_json as _serialize_envelope
from dumpex.output.records import Diagnostic, SEVERITY_ERROR


class V2Output:
    def __init__(self, dump_path: "str | None" = None, mf=None, *, command: str = None,
                 options: dict = None, case_id: str = None, analyst: str = None,
                 redact_paths: bool = False, started_at: "datetime.datetime" = None,
                 evidence: "list[EvidenceInput] | None" = None):
        if (dump_path is None) == (evidence is None):
            # Both None -> nothing to build meta from. Both given ->
            # genuinely ambiguous (which one wins?) and, worse, silently
            # dropping dump_path here would ALSO silently drop it from
            # self._protected_paths below -- disabling write_json's
            # overwrite guard for a path the caller clearly
            # considered real input. Exactly one is required, always.
            raise TypeError(
                "V2Output requires exactly one of dump_path (single-dump commands) or "
                "evidence (multi-dump commands), got "
                + ("neither" if dump_path is None else "both"))
        if evidence is not None:
            # _normalize_evidence_inputs (shared with build_meta_v2, see
            # envelope.py) rejects a non-list/tuple outright rather than
            # risking a generator getting silently exhausted by one of
            # ITS OWN validation passes -- and resolves every entry's
            # path to absolute exactly once, so the object stored below
            # and self._protected_paths always agree on which on-disk
            # file a given entry refers to, even if the process's cwd
            # changes between construction and to_json()/write_json().
            evidence = _normalize_evidence_inputs(evidence)
            # A multi-evidence collector has no single canonical dump path.
            self._dump_path_abs  = None
            self._dump_file_name = None
            self._evidence        = evidence
            self._protected_paths = [ei.path for ei in evidence]
        else:
            self._dump_path_abs  = os.path.abspath(dump_path)
            self._dump_file_name = os.path.basename(dump_path)
            self._evidence        = None
            self._protected_paths = [self._dump_path_abs]
        self._command        = command
        self._options        = dict(options) if options else {}
        self._case_id        = case_id
        self._analyst        = analyst
        self._redact_paths   = redact_paths
        self._started_at     = started_at or datetime.datetime.now(datetime.timezone.utc)
        self._mf              = mf   # kept for parity with StructuredOutput; unused so far
        self._result             = None
        self._diagnostics_warnings = []
        self._diagnostics_errors   = []
        self._artifacts            = []
        self._yara_provenance     = None   # see set_yara_provenance() -- this command's OWN
                                             # YaraReport provenance, never a shared global

    @classmethod
    def from_evidence(cls, evidence: "list[EvidenceInput]", *, command: str = None,
                       options: dict = None, case_id: str = None, analyst: str = None,
                       redact_paths: bool = False,
                       started_at: "datetime.datetime" = None) -> "V2Output":
        """Construct a collector for commands with multiple evidence inputs,
        such as ``--diff``."""
        return cls(evidence=evidence, command=command, options=options, case_id=case_id,
                    analyst=analyst, redact_paths=redact_paths, started_at=started_at)

    def set_command_result(self, result) -> None:
        """The single way a command populates this collector's result --
        consumes every dumpex.output.command_result.CommandResult field
        (execution_status, structured coverage, diagnostics, artifacts),
        converting each nested value's own to_dict() before storing it, so
            every consumer downstream of this call (notably the serializer)
        only ever sees plain JSON-safe data. `result` is duck-typed (not
        type-hinted as CommandResult) to avoid this module importing
        command_result.py, which itself imports this module's sibling
        envelope.py -- without a hard import dependency between the two."""
        record_dicts = [r.to_dict() for r in result.records]
        self._result = Result(
            kind=result.kind,
            execution_status=result.execution_status,
            coverage_status=result.coverage.status,
            coverage_reasons=list(result.coverage.reasons),
            coverage_sources={name: obs.to_dict()
                               for name, obs in result.coverage.sources.items()},
            coverage_limitations=[lim.to_dict() for lim in result.coverage.limitations],
            coverage_missed_bytes=result.coverage.missed_bytes.to_dict(),
            summary=dict(result.summary) if result.summary else {"count": len(record_dicts)},
            records=record_dicts,
        )
        for d in result.diagnostics:
            # No dict-passthrough fallback: CommandResult.__post_init__
            # already rejects anything that isn't a real Diagnostic
            # instance, so .to_dict() is always safe to call directly --
            # a bare dict here would have bypassed Diagnostic's own
            # validation and could reach the wire in a schema-invalid
            # shape (e.g. missing `severity`).
            d_dict = d.to_dict()
            if d_dict.get("severity") == SEVERITY_ERROR:
                self._diagnostics_errors.append(d_dict)
            else:
                self._diagnostics_warnings.append(d_dict)
        self._artifacts.extend(a.to_dict() for a in result.artifacts)
        # Second line of defense behind cli.py's own up-front
        # --output/--json/--txt collision check (see
        # safe_io.check_no_output_collisions): an artifact this run
        # already wrote (e.g. --extract's own --output file) is now also
        # a protected path for write_json below, so a later
        # structured-output write to that same path is refused instead of
        # silently overwriting it -- check_not_dump_path accepts a
        # (path, description) tuple precisely for this case, so the
        # printed refusal correctly names the artifact instead of always
        # claiming it's the input dump.
        for a in result.artifacts:
            self._protected_paths.append(
                (a.path, f"the '{a.kind}' artifact this run already wrote"))

    def set_yara_provenance(self, provenance: "dict | None") -> None:
        """Attach THIS command's own YARA rule provenance (a plain dict,
        e.g. `domain.RulesProvenance.to_dict()` off the exact `YaraReport`
        `dumpex.hunt.cmd_hunt()` built for this invocation) so
        `meta.yara_rules` reflects it explicitly -- `build_meta_v2()`
        never reads `dumpex.hunt.yara_hunt.get_yara_provenance()`'s own
        process-wide "last build" global itself (see that function's own
        docstring on why: a caller building more than one `YaraReport` in
        one process could otherwise have a LATER build's provenance
        silently attributed to an EARLIER command's own JSON output).
        `None` (the default if this is never called) omits meta.yara_rules
        entirely, same as "YARA scanning was never invoked this run"."""
        self._yara_provenance = provenance

    def add_diagnostic(self, severity: str, message: str, code: str = None) -> None:
        d = Diagnostic(severity=severity, message=message, code=code).to_dict()
        if severity == SEVERITY_ERROR:
            self._diagnostics_errors.append(d)
        else:
            self._diagnostics_warnings.append(d)

    @property
    def has_result(self) -> bool:
        return self._result is not None

    @property
    def coverage_status(self) -> "str | None":
        return self._result.coverage_status if self._result else None

    def _build_envelope(self) -> Envelope:
        finished_at = datetime.datetime.now(datetime.timezone.utc)
        if self._evidence is not None:
            meta = build_meta_v2(
                evidence=self._evidence,
                command=self._command, options=self._options, case_id=self._case_id,
                analyst=self._analyst, redact_paths=self._redact_paths,
                started_at=self._started_at, finished_at=finished_at,
                yara_provenance=self._yara_provenance,
            )
        else:
            meta = build_meta_v2(
                dump_path_abs=self._dump_path_abs, dump_file_name=self._dump_file_name,
                command=self._command, options=self._options, case_id=self._case_id,
                analyst=self._analyst, redact_paths=self._redact_paths,
                started_at=self._started_at, finished_at=finished_at,
                yara_provenance=self._yara_provenance,
            )
        artifacts = _redact_artifacts(self._artifacts) if self._redact_paths else list(self._artifacts)
        return Envelope(meta=meta, result=self._result, artifacts=artifacts,
                         diagnostics_warnings=list(self._diagnostics_warnings),
                         diagnostics_errors=list(self._diagnostics_errors))

    def to_json(self) -> str:
        return _serialize_envelope(self._build_envelope())

    def write_json(self, path: str, cmd_label: str = "", force: bool = False) -> None:
        # self._protected_paths covers every real input -- a single dump
        # path for the six existing commands, or every evidence entry's
        # path for an evidence=-constructed (e.g. comparison) instance,
        # so check_not_dump_path (inside write_text_to_target) refuses to
        # overwrite any of them, baseline or target. The input-protection
        # guard cannot be lifted by --force.
        p = write_text_to_target(path, self.to_json(), ".json", cmd_label,
                                  self._protected_paths, force, "--json output")
        print(DIM(f"  [·] JSON written → {p}  ({summarize_file(p)})"))
