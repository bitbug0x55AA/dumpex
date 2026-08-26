"""Build an injection report and project it into a ``HunterRecord``."""
from dumpex.hunt.injection import _build_injection_report
from dumpex.hunt.injection.report_record import project_hunter_record
from dumpex.output.records import HunterRecord


# `_record_from_injection_report` is the ONE place both
# `collect_injection_record()` (below) and `collect_hunt()`
# (dumpex/hunt/__init__.py's orchestrator) build the typed record from an
# ALREADY-BUILT Report, so a single `_build_injection_report()` call can
# feed both the console renderer and this conversion without scanning
# twice. Kept as a name distinct from `project_hunter_record` (rather than
# re-exporting that name directly) only because both call sites already
# import it under this name.
_record_from_injection_report = project_hunter_record


def collect_injection_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="injection"`) for `mf`, sharing
    the exact same underlying `InjectionReport` `_hunt_injection()` would
    build for the same `mf`. Thin compat wrapper: builds a fresh Report and
    converts it -- `collect_hunt()` calls `_build_injection_report()` and
    `_record_from_injection_report()` directly instead, so it never scans
    twice just to also get console output from the same run."""
    return _record_from_injection_report(_build_injection_report(mf))
