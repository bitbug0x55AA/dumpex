"""`HollowingReport` -> the v1.1 legacy `findings` dict -- a pure
projection, independent of `report_record.py`/`report_console.py`. Mirrors
`dumpex.hunt.stomping.report_legacy`/`dumpex.hunt.pipe.report_legacy` (the
completed reference pilots).

The dict's KEY SET is unchanged by this migration (issue #10: "no public
schema change") -- the same ten keys `_hunt_hollowing()` has always
returned, frozen by tests/integration/test_hunt_compat_freeze.py's own
`_HOLLOWING_KEYS`.

One structural simplification: the pre-migration renderer built this dict
TWICE, from two different places -- an early-return literal inside
`_render_hollowing_console()` for the PEB-missing case (with `score`/
`max_score`/`coverage_status`/`coverage_reasons`/`lead_count` hand-written
as `0`/`2`/`"not_evaluated"`/`["PEB stream missing from this dump"]`/`0`
rather than read off the Report that already carried them), and a second
literal at the end of the same function for every other case. Both are this
one function now, so a NOT_EVALUATED run and a DETECTED run can no longer
disagree about the shape of their own output. This hunter carries no
evidence arrays in its v1.1 dict at all (unlike stomping's
`protection_leads`/`verified_changes`), so there is nothing here to rebuild
by value -- the typed evidence reaches --json solely through
`findings[].facts` and, since v2.4, `report_record.py`'s `HollowingDetails`.
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
