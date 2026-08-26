"""Build a pipe report and project it into a ``HunterRecord``."""
from dumpex.hunt.pipe import _build_pipe_report
from dumpex.hunt.pipe.report_record import project_hunter_record
from dumpex.output.records import HunterRecord


# `_record_from_pipe_report` is the ONE place both `collect_pipe_record()`
# (below) and `collect_hunt()` (dumpex/hunt/__init__.py's orchestrator)
# build the typed record from an ALREADY-BUILT Report, so a single
# `_build_pipe_report()` call can feed both the console renderer and this
# conversion without scanning twice.
_record_from_pipe_report = project_hunter_record


def collect_pipe_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="pipe"`) for `mf` -- sharing the
    exact same underlying `PipeReport` `_hunt_pipe()` would build for the
    same `mf`. Thin compat wrapper: builds a fresh Report and converts it
    -- `collect_hunt()` calls `_build_pipe_report()` and
    `_record_from_pipe_report()` directly instead, so it never scans twice
    just to also get console output from the same run."""
    return _record_from_pipe_report(_build_pipe_report(mf))
