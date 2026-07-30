"""
CommandResult[T] -- what a migrated command's collect_*() function
returns, replacing the ad hoc 3-to-6-element positional tuple every
recon command currently returns (see dumpex/commands/list_cmd.py,
modules.py, threads.py, sysinfo.py, peb.py -- the last three are not yet
migrated onto this).

Deliberately separate from dumpex.output.envelope's Result/Envelope
(the wire-format dataclasses the serializer/schema actually consume):
CommandResult is a pre-serialization, richer intermediate a command
builds and cli.py unpacks via attribute access (`result.records`,
`result.coverage.status`, `result.coverage.reasons`) into the SAME,
unchanged V2Output.set_result() call every migrated command already
used -- so introducing this type changes nothing about the JSON/CSV wire
format it eventually feeds.
"""
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from dumpex.output.coverage import CoverageReport
from dumpex.output.envelope import EXECUTION_COMPLETED

T = TypeVar("T")


@dataclass
class CommandResult(Generic[T]):
    kind: str
    records: list                              # list[T] -- record dataclass instances,
                                                 # not yet .to_dict()'d
    coverage: CoverageReport
    execution_status: str = EXECUTION_COMPLETED
    summary: dict = field(default_factory=dict)
    diagnostics: list = field(default_factory=list)   # list[Diagnostic], unused by any
                                                         # migrated command yet -- plumbing
                                                         # for a future one that needs it
    artifacts: list = field(default_factory=list)
