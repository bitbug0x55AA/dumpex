"""
`collect_hollowing_record()` -- the `HunterRecord`-producing entry point for
the hollowing hunter, alongside the console-oriented `_hunt_hollowing()` in
`dumpex/hunt/hollowing/__init__.py`. Both call the exact same
`_build_hollowing_report()` pipeline, so this module only RESHAPES the
resulting canonical `HollowingReport` into a `HunterRecord` -- via
`dumpex.hunt.hollowing.report_record.project_hunter_record`, the same pure
projector `report_console.py`/`report_legacy.py` build their own
projections from. That is what guarantees the console path and this typed-
record path can never silently disagree about the same input. Mirrors
`dumpex.hunt.stomping.collect`/`dumpex.hunt.pipe.collect`/
`dumpex.hunt.encoding.collect`/`dumpex.hunt.injection.collect` (the four
completed reference pilots).

The pre-migration equivalent of this module lived as two module-level
functions inside the single-file `dumpex/hunt/hollowing.py`, next to the
scan and the renderer; the conversion itself had to re-derive each of
`HollowingDetails`' tri-state fields from loose booleans on the mutable
Report, several of which restated what a live `MinidumpMemoryInfo`/`Module`
the same Report carried already said. All of that now lives in
report_record.py, reading a `ImageBaseContext` whose identity was resolved
once at scan time (dumpex.hunt.hollowing.models).

This module is read by `dumpex/hunt/__init__.py`'s `collect_hunt()`
orchestrator, which `cli.py`'s `--hunt` branch calls for `--json` output.
"""
from dumpex.hunt.hollowing import _build_hollowing_report
from dumpex.hunt.hollowing.report_record import project_hunter_record
from dumpex.output.records import HunterRecord


# `_record_from_hollowing_report` is the ONE place both
# `collect_hollowing_record()` (below) and `collect_hunt()`
# (dumpex/hunt/__init__.py's orchestrator) build the typed record from an
# ALREADY-BUILT Report, so a single `_build_hollowing_report()` call can
# feed both the console renderer and this conversion without scanning
# twice.
_record_from_hollowing_report = project_hunter_record


def collect_hollowing_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="hollowing"`) for `mf` -- sharing
    the exact same underlying `HollowingReport` `_hunt_hollowing()` would
    build for the same `mf`. Thin compat wrapper: builds a fresh Report and
    converts it -- `collect_hunt()` calls `_build_hollowing_report()` and
    `_record_from_hollowing_report()` directly instead, so it never scans
    twice just to also get console output from the same run."""
    return _record_from_hollowing_report(_build_hollowing_report(mf))
