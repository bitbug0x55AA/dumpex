"""
`collect_pipe_record()` -- the `HunterRecord`-producing entry point for
the pipe hunter, alongside the console-oriented `_hunt_pipe()` in
`dumpex/hunt/pipe/__init__.py`. Both call the exact same
`_build_pipe_report()` pipeline, so this module only RESHAPES the
resulting canonical `PipeReport` into a `HunterRecord` -- via
`dumpex.hunt.pipe.report_record.project_hunter_record`, the same pure
projector `report_console.py`/`report_legacy.py` build their own
projections from. That is what guarantees the console path and this typed-
record path can never silently disagree about the same input. Mirrors
`dumpex.hunt.stomping.collect`/`dumpex.hunt.encoding.collect`/
`dumpex.hunt.injection.collect` (the three completed reference pilots).

The pre-migration version of this module owned the whole dict-building
projection itself: it converted raw `Handle`/`MinidumpMemoryInfo`/
`ThreadInfo` objects (embedded in the legacy `findings` dict's own
`handle_pipes`/`private_pipes`/`c2_context`/`framework_pipes`/
`unbacked_in_rgn` entries) into JSON-safe dicts here, re-deriving
`prot_str()` a second time. All of that now lives in report_record.py,
reading typed evidence whose identity was resolved once at scan time
(dumpex.hunt.pipe.models), and this module no longer reads the legacy dict
at all.

This module is read by `dumpex/hunt/__init__.py`'s `collect_hunt()`
orchestrator, which `cli.py`'s `--hunt` branch calls for `--json` output.
"""
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
