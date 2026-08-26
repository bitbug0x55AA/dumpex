"""Build an encoding report and project it into a ``HunterRecord``."""
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
