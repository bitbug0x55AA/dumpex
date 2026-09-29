"""Top-level diagnostics and artifact records every command can emit."""
from dataclasses import dataclass


SEVERITY_WARNING = "warning"
SEVERITY_ERROR   = "error"


@dataclass(frozen=True)
class Diagnostic:
    """One entry in the top-level diagnostics.warnings/.errors (a sibling
    of `result`, not nested under it) -- structured,
    not a bare string, so a consumer can filter/triage without parsing
    free text. Frozen: a plain (mutable) dataclass would let a caller
    construct a valid instance, then mutate a field past __post_init__'s
    own validation (e.g. `d.severity = "critical"`) before it reaches
    collector.py's set_command_result() -- CommandResult's isinstance
    check only confirms the TYPE at construction time, not that the
    fields are still valid by the time .to_dict() is actually called."""
    severity: str            # SEVERITY_WARNING / SEVERITY_ERROR
    message:  str
    code:     "str | None" = None

    def __post_init__(self):
        if self.severity not in (SEVERITY_WARNING, SEVERITY_ERROR):
            raise ValueError(
                f"Diagnostic.severity must be {SEVERITY_WARNING!r} or {SEVERITY_ERROR!r}, "
                f"got {self.severity!r}")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("Diagnostic.message must be a non-empty string")
        if self.code is not None and (not isinstance(self.code, str) or not self.code):
            raise ValueError("Diagnostic.code must be None or a non-empty string")

    def to_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "code": self.code}


@dataclass(frozen=True)
class Artifact:
    """One entry in the top-level `artifacts` array -- an output file the
    tool itself produced (e.g. an extracted memory region), distinct from
    meta.evidence (which describes the INPUT dump(s)). Field naming
    mirrors meta.evidence's own id/path/size_bytes/sha256 shape. Populated
    by --extract and by --report's own optional extract-to-file side
    effect (both via dumpex.commands.extract.build_extract_artifact(),
    which calls dumpex.core.safe_io.compute_bytes_summary() for the
    size_bytes/sha256 fields directly rather than parsing them back out
    of summarize_bytes()'s formatted string) -- report.py calls this
    helper directly rather than going through collect_extract()/
    cmd_extract(), passing kind="report_extracted_region" so
    artifacts[].kind still distinguishes the two producers. Constructing
    one is the ONLY
    way an entry reaches `artifacts` on the wire -- dumpex.output.collector.
    V2Output.set_command_result() calls .to_dict() unconditionally (no
    duck-typed dict passthrough), so a caller can't smuggle a shape this
    class doesn't validate. Frozen for the same reason as Diagnostic --
    otherwise a valid instance could be mutated past its own
    __post_init__ checks after CommandResult's isinstance check already
    passed."""
    id:          str
    kind:        str            # open vocabulary (e.g. "extracted_region") -- mirrors
                                  # dumpex.output.coverage's `source` staying open too
    path:        str
    size_bytes:  "int | None" = None
    sha256:      "str | None" = None
    description: "str | None" = None

    def __post_init__(self):
        for field_name in ("id", "kind", "path"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"Artifact.{field_name} must be a non-empty string")
        if self.size_bytes is not None and (
                not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool)
                or self.size_bytes < 0):
            raise ValueError(
                f"Artifact.size_bytes must be None or a non-negative int, got {self.size_bytes!r}")
        if self.sha256 is not None and (not isinstance(self.sha256, str) or not self.sha256):
            raise ValueError("Artifact.sha256 must be None or a non-empty string")
        if self.description is not None and not isinstance(self.description, str):
            raise ValueError("Artifact.description must be None or a string")

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "path": self.path,
                "size_bytes": self.size_bytes, "sha256": self.sha256,
                "description": self.description}
