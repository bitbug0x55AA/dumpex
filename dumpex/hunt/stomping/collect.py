"""Build a stomping report and project it into a ``HunterRecord``."""
from dumpex.hunt.stomping import _build_stomping_report
from dumpex.hunt.stomping.report_record import project_hunter_record
from dumpex.output.records import HunterRecord


# `_record_from_stomping_report` is the ONE place both
# `collect_stomping_record()` (below) and `collect_hunt()`
# (dumpex/hunt/__init__.py's orchestrator) build the typed record from an
# ALREADY-BUILT Report, so a single `_build_stomping_report()` call can
# feed both the console renderer and this conversion without scanning
# twice.
_record_from_stomping_report = project_hunter_record


def collect_stomping_record(mf, ref_dir: str = None) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="stomping"`) for `mf` -- sharing
    the exact same underlying `StompingReport` `_hunt_stomping()` would
    build for the same `mf`/`ref_dir`. Thin compat wrapper: builds a fresh
    Report and converts it -- `collect_hunt()` calls
    `_build_stomping_report()` and `_record_from_stomping_report()`
    directly instead, so it never scans twice just to also get console
    output from the same run."""
    return _record_from_stomping_report(_build_stomping_report(mf, ref_dir=ref_dir))
