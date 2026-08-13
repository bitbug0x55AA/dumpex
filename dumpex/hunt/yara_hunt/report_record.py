"""`domain.YaraReport` -> `HunterRecord` (the current typed record) -- a
pure projection, independent of `report_legacy.py`/`report_console.py`.
Mirrors `dumpex.hunt.cs_beacon.report_record` (and, through it, the other
completed reference pilots): builds the SAME `YaraDetails` shape the
pre-migration `_record_from_yara_report()` built -- no public schema/wire-
shape change.

`findings=[]`, `max_score=confidence=lead_count=review_priority=None` are
fixed for every YaraReport, per `HunterRecord`'s own yara-only-null
invariant (dumpex/output/records.py) -- YARA stays off the shared Finding
model (see domain.py's own docstring).
"""
from dumpex.hunt.yara_hunt.domain import YaraReport
from dumpex.hunt.yara_hunt.report_facts import match_dict, project_coverage_report
from dumpex.output.records import HunterRecord, YaraDetails


def project_hunter_record(report: YaraReport) -> HunterRecord:
    """Pure `YaraReport` -> `HunterRecord` conversion -- no scanning, no
    printing."""
    details = YaraDetails(
        matches=[match_dict(m, hex_va=True) for m in report.evidence.matches],
        rules_hit=list(report.triggered_rules),
    )
    return HunterRecord(
        hunter="yara", status=report.status, score=report.score, max_score=None,
        verdict_level=report.verdict_level, confidence=None, lead_count=None,
        review_priority=None, coverage=project_coverage_report(report), findings=[],
        details=details)
