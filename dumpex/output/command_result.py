"""Immutable command result passed from collection to output adapters.

Records, coverage, execution state, diagnostics, artifacts, and summaries remain
separate so rendering cannot infer evidence semantics from presentation text.
Mutable caller containers are defensively copied.
"""
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from dumpex.output.coverage import CoverageReport, EXECUTION_COMPLETED, ExecutionStatus
from dumpex.output.records import Diagnostic, Artifact

T = TypeVar("T")


@dataclass
class CommandResult(Generic[T]):
    kind: str
    records: "list[T]"                         # record dataclass instances, not yet .to_dict()'d
    coverage: CoverageReport
    execution_status: str = EXECUTION_COMPLETED
    summary: dict = field(default_factory=dict)
    diagnostics: list = field(default_factory=list)   # list[Diagnostic] -- populated by
                                                         # --extract (Phase E) for its MZ-
                                                         # header-detected warning
    artifacts: list = field(default_factory=list)      # list[Artifact] -- populated by
                                                         # --extract (Phase E) for its
                                                         # written-file record

    def __post_init__(self):
        try:
            self.execution_status = ExecutionStatus(self.execution_status)
        except ValueError:
            raise ValueError(f"unknown execution status: {self.execution_status!r}") from None
        # Only a real Diagnostic/Artifact instance is accepted here -- a
        # bare dict would bypass those classes' own __post_init__
        # validation (required fields, type checks) and could reach the
        # wire in a shape the JSON Schema rejects (e.g. an artifact
        # missing `kind`). collector.py's set_command_result() calls
        # .to_dict() unconditionally, so anything that isn't one of these
        # two types fails loudly here, at construction time, rather than
        # producing a schema-invalid document much later.
        for d in self.diagnostics:
            if not isinstance(d, Diagnostic):
                raise TypeError(
                    f"CommandResult.diagnostics entries must be Diagnostic instances, "
                    f"got {type(d).__name__}")
        for a in self.artifacts:
            if not isinstance(a, Artifact):
                raise TypeError(
                    f"CommandResult.artifacts entries must be Artifact instances, "
                    f"got {type(a).__name__}")
