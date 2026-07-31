"""
CommandResult[T] -- what a migrated command's collect_*() function
returns, replacing the ad hoc 3-to-6-element positional tuple every
recon command used to return (see dumpex/commands/list_cmd.py,
modules.py, threads.py, peb.py, sysinfo.py -- the last one holds both
--sysinfo and --pid). All six of dumpex's original recon commands
return this type now.

Deliberately separate from dumpex.output.envelope's Result/Envelope
(the wire-format dataclasses the serializer/schema actually consume):
CommandResult is a pre-serialization, richer intermediate a command
builds and cli.py hands to dumpex.output.collector.V2Output.
set_command_result(), which consumes every field here (including
execution_status/diagnostics/artifacts -- see that method's docstring
for why a narrower adapter used to silently drop them) before it becomes
wire-format JSON/CSV.

Imports EXECUTION_COMPLETED from dumpex.output.coverage, not
dumpex.output.envelope, on purpose: this is a command/domain-layer type,
and the dependency direction is command/domain model -> output adapter
(collector.py) -> envelope/serializer, never the reverse.
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
    diagnostics: list = field(default_factory=list)   # list[Diagnostic], unused by any
                                                         # migrated command yet -- plumbing
                                                         # for a future one that needs it
    artifacts: list = field(default_factory=list)      # list[Artifact], likewise unused today

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
