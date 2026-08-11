"""
`collect_stomping_record()` -- the `HunterRecord`-producing entry point
for the stomping hunter, alongside the console-oriented `_hunt_stomping()`
in `dumpex/hunt/stomping/__init__.py`. Both call the exact same
`_build_stomping_report()` pipeline, so this module only RESHAPES the
resulting canonical `StompingReport` into a `HunterRecord` -- via
`dumpex.hunt.stomping.report_record.project_hunter_record`, the same pure
projector `report_console.py`/`report_legacy.py` build their own
projections from. That is what guarantees the console path and this typed-
record path can never silently disagree about the same input. Mirrors
`dumpex.hunt.encoding.collect`/`dumpex.hunt.injection.collect` (the
completed reference pilots).

The pre-migration version of this module had to convert raw `Module`/
`MinidumpMemoryInfo` objects (embedded in the legacy `findings` dict's own
`protection_leads`/`verified_changes` entries) into JSON-safe dicts here,
re-deriving `prot_str()`/basenames a second time. Both are now resolved
once, at scan time (dumpex.hunt.stomping.models), and this module no
longer reads the legacy dict at all.

This module is read by `dumpex/hunt/__init__.py`'s `collect_hunt()`
orchestrator, which `cli.py`'s `--hunt` branch calls for `--json` output.
"""
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
