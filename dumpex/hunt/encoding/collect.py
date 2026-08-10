"""
`collect_obfuscation_record()` -- the `HunterRecord`-producing entry point
for the obfuscation hunter, alongside the console-oriented
`_hunt_encoding()` in `dumpex/hunt/encoding/__init__.py`. Both call the
exact same `_build_encoding_report()` pipeline, so this module only
RESHAPES the resulting canonical `EncodingReport` into a `HunterRecord` --
via `dumpex.hunt.encoding.report_record.project_hunter_record`, the same
pure projector `report_console.py`/`report_legacy.py` build their own
projections from. That is what guarantees the console path and this
v2.4+ path can never silently disagree about the same input. Mirrors
`dumpex.hunt.injection.collect` (the completed reference pilot).

This module is read by `dumpex/hunt/__init__.py`'s `collect_hunt()`
orchestrator, which `cli.py`'s `--hunt` branch calls for `--json` output.
"""
from dumpex.hunt.encoding import _build_encoding_report
from dumpex.hunt.encoding.report_record import project_hunter_record
from dumpex.output.records import HunterRecord


# `_record_from_encoding_report` is the ONE place both
# `collect_obfuscation_record()` (below) and `collect_hunt()`
# (dumpex/hunt/__init__.py's orchestrator) build the typed record from an
# ALREADY-BUILT Report, so a single `_build_encoding_report()` call can
# feed both the console renderer and this conversion without scanning
# twice.
_record_from_encoding_report = project_hunter_record


def collect_obfuscation_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="obfuscation"`) for `mf` --
    sharing the exact same underlying `EncodingReport` `_hunt_encoding()`
    would build for the same `mf`. Thin compat wrapper: builds a fresh
    Report and converts it -- `collect_hunt()` calls
    `_build_encoding_report()` and `_record_from_encoding_report()`
    directly instead, so it never scans twice just to also get console
    output from the same run."""
    return _record_from_encoding_report(_build_encoding_report(mf))
