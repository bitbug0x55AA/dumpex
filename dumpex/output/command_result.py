"""
CommandResult[T] -- what a migrated command's collect_*() function
returns, replacing the ad hoc 3-to-6-element positional tuple every
recon command currently returns (see dumpex/commands/list_cmd.py,
modules.py, threads.py, sysinfo.py, peb.py -- the last three are not yet
migrated onto this).

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
    artifacts: list = field(default_factory=list)

    def __post_init__(self):
        try:
            self.execution_status = ExecutionStatus(self.execution_status)
        except ValueError:
            raise ValueError(f"unknown execution status: {self.execution_status!r}") from None
