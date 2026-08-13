"""
`collect_cs_beacon_record()` -- the `HunterRecord`-producing entry point for
the cs-beacon hunter, alongside the console-oriented `_hunt_cs_beacon()` in
`dumpex/hunt/cs_beacon/__init__.py`. Both call the exact same
`_build_cs_beacon_report()` pipeline and project the SAME immutable
`domain.CSBeaconReport`, via `report_record.project_hunter_record()` -- this
module only re-exports that projection under the name the dispatcher/other
callers already import, and provides the thin `collect_cs_beacon_record()`
compat wrapper.
"""
from dumpex.hunt.cs_beacon import _build_cs_beacon_report
from dumpex.hunt.cs_beacon.report_record import project_hunter_record as _record_from_cs_beacon_report
from dumpex.output.records import HunterRecord


def collect_cs_beacon_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="cs-beacon"`) for `mf` -- sharing
    the exact same underlying Report `_hunt_cs_beacon()` builds. Thin compat
    wrapper: builds a fresh Report and converts it -- `collect_hunt()` calls
    `_build_cs_beacon_report()` and `_record_from_cs_beacon_report()`
    directly instead, so it never scans twice just to also get console
    output from the same run."""
    return _record_from_cs_beacon_report(_build_cs_beacon_report(mf))
