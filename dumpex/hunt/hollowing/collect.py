"""Build a hollowing report and project it into a ``HunterRecord``."""
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
