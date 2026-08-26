"""Project a ``HollowingReport`` into its ten-key legacy v1.1 shape.

Not-evaluated and evaluated reports use the same public key set; typed
evidence is exposed separately through ``HollowingDetails``.
"""
from dumpex.hunt.hollowing.domain import HollowingReport
from dumpex.hunt.hollowing.report_facts import finding_from_check_result, project_coverage_v1


def project_legacy_dict(report: HollowingReport) -> dict:
    """The v1.1 findings dict -- the same shape `_hunt_hollowing()` has
    always returned, built purely from `report.results`/`report.coverage`/
    derived properties."""
    coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    return {
        "score": report.score,
        "max_score": report.max_score,
        "status": report.status,
        "coverage_status": coverage_status,
        "coverage_reasons": coverage_reasons,
        "confidence": report.confidence,
        "verdict_level": report.verdict_level,
        "findings": [f.to_dict() for f in findings_list],
        "lead_count": report.lead_count,
        "review_priority": report.review_priority,
    }
