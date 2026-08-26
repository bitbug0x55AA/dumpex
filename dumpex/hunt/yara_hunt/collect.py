"""Build a YARA report and project it into a ``HunterRecord``."""
from dumpex.hunt.yara_hunt import _build_yara_report
from dumpex.hunt.yara_hunt.report_record import project_hunter_record as _record_from_yara_report
from dumpex.output.records import HunterRecord


def collect_yara_record(mf, rules_dir: str = None) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="yara"`) for `mf` -- shares the
    exact same underlying `domain.YaraReport` construction as `_hunt_yara()`.
    Thin compat wrapper: builds a fresh Report and converts it --
    `collect_hunt()` calls `_build_yara_report()` and
    `project_hunter_record()` directly instead, so it never scans twice
    just to also get console output from the same run."""
    return _record_from_yara_report(_build_yara_report(mf, rules_dir=rules_dir))
