"""Project a ``YaraReport`` into the current ``HunterRecord``.

YARA does not use the shared Finding model, so ``findings`` is empty and
unsupported score-adjacent fields remain ``None`` by contract.
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
