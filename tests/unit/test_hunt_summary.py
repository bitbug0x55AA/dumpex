"""
Unit tests for dumpex.hunt.summary.build_hunt_summary() -- the single
cross-hunter result.summary reducer JSON/CSV/console must all share (see
that module's own docstring). Built directly from
tests/fixtures/hunt_records.py's synthetic HunterRecord fixtures.
"""
import dataclasses

import pytest

from dumpex.hunt.summary import build_hunt_summary
from dumpex.output.coverage import CoverageReport, CoverageStatus
from tests.fixtures.hunt_records import (
    injection_detected, hollowing_detected, hollowing_not_evaluated, stomping_inconclusive,
    pipe_clean, cs_beacon_detected, yara_detected, yara_not_evaluated, obfuscation_detected,
    all_seven_detected_variety, all_seven_not_evaluated,
)


def test_all_detected_variety_matches_hand_computed_counts():
    records = all_seven_detected_variety()
    # injection_detected, cs_beacon_detected, yara_detected, obfuscation_detected -> DETECTED (4)
    # hollowing_not_evaluated -> NOT_EVALUATED (1); stomping_inconclusive -> INCONCLUSIVE (1);
    # pipe_clean -> NOT_DETECTED_IN_SCANNED_SCOPE (1)
    summary = build_hunt_summary(records, selected="all")
    assert summary == {
        "selected": "all", "hunter_count": 7, "detected_count": 4, "inconclusive_count": 1,
        "not_evaluated_count": 1, "overall_status": "DETECTED",
        "highest_verdict_level": "high", "lead_count": sum(r.lead_count or 0 for r in records),
    }


def test_all_not_evaluated_is_not_evaluated_overall():
    records = all_seven_not_evaluated()
    summary = build_hunt_summary(records, selected="all")
    assert summary["overall_status"] == "NOT_EVALUATED"
    assert summary["highest_verdict_level"] == "not_evaluated"
    assert summary["not_evaluated_count"] == 7
    assert summary["detected_count"] == 0


def test_partial_not_evaluated_among_seven_is_inconclusive_not_clean():
    # 3 of 7 hunters never got a data source (NOT_EVALUATED), the other 4
    # ran to completion and found nothing (NOT_DETECTED_IN_SCANNED_SCOPE)
    # -- no hunter is individually DETECTED or INCONCLUSIVE. A scope only
    # PARTLY looked at has not earned "clean" -- must be INCONCLUSIVE.
    base = [dataclasses.replace(
        r, status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0, verdict_level="clean",
        confidence=None if r.hunter == "yara" else "none",
        lead_count=None if r.hunter == "yara" else 0,
        review_priority=None if r.hunter == "yara" else "none",
        coverage=CoverageReport(status=CoverageStatus.COMPLETE), findings=[],
    ) for r in all_seven_detected_variety()]
    records = list(base)
    for idx in (1, 3, 5):   # hollowing, pipe, yara -> NOT_EVALUATED
        r = records[idx]
        records[idx] = dataclasses.replace(
            r, status="NOT_EVALUATED", verdict_level="not_evaluated",
            confidence=None if r.hunter == "yara" else "none",
            lead_count=None if r.hunter == "yara" else 0,
            review_priority=None if r.hunter == "yara" else "none",
            coverage=CoverageReport(status=CoverageStatus.NOT_EVALUATED), findings=[],
        )
    summary = build_hunt_summary(records, selected="all")
    assert summary["detected_count"] == 0
    assert summary["inconclusive_count"] == 0
    assert summary["not_evaluated_count"] == 3
    assert summary["overall_status"] == "INCONCLUSIVE"
    assert summary["highest_verdict_level"] == "inconclusive"


def test_any_inconclusive_hunter_makes_overall_inconclusive():
    records = list(all_seven_detected_variety())
    # Force every hunter except stomping (already INCONCLUSIVE in the
    # base fixture) to NOT_DETECTED_IN_SCANNED_SCOPE, so INCONCLUSIVE
    # alone -- not a DETECTED hunter -- drives the overall status.
    only_inconclusive_and_clean = [
        dataclasses.replace(r, status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
                             verdict_level="clean",
                             confidence=None if r.hunter == "yara" else "none",
                             lead_count=None if r.hunter == "yara" else 0,
                             review_priority=None if r.hunter == "yara" else "none",
                             coverage=CoverageReport(status=CoverageStatus.COMPLETE), findings=[])
        if r.hunter != "stomping" else r
        for r in records
    ]
    summary = build_hunt_summary(only_inconclusive_and_clean, selected="all")
    assert summary["detected_count"] == 0
    assert summary["inconclusive_count"] == 1
    assert summary["overall_status"] == "INCONCLUSIVE"
    assert summary["highest_verdict_level"] == "inconclusive"


def test_all_clean_is_not_detected_in_scanned_scope():
    records = [
        dataclasses.replace(r, status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
                             verdict_level="clean",
                             confidence=None if r.hunter == "yara" else "none",
                             lead_count=None if r.hunter == "yara" else 0,
                             review_priority=None if r.hunter == "yara" else "none",
                             coverage=CoverageReport(status=CoverageStatus.COMPLETE), findings=[])
        for r in all_seven_detected_variety()
    ]
    summary = build_hunt_summary(records, selected="all")
    assert summary["overall_status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert summary["highest_verdict_level"] == "clean"
    assert summary["detected_count"] == 0
    assert summary["inconclusive_count"] == 0
    assert summary["not_evaluated_count"] == 0


def test_single_hunter_detected():
    summary = build_hunt_summary([injection_detected()], selected="injection")
    assert summary["hunter_count"] == 1
    assert summary["detected_count"] == 1
    assert summary["overall_status"] == "DETECTED"


def test_single_hunter_not_evaluated():
    summary = build_hunt_summary([hollowing_not_evaluated()], selected="hollowing")
    assert summary["overall_status"] == "NOT_EVALUATED"
    assert summary["highest_verdict_level"] == "not_evaluated"


def test_highest_verdict_level_picks_the_strongest_detected_tier():
    # injection_detected has verdict "high"; hollowing_detected has
    # "possible" -- selected="all" requires all 7 in fixed order, so the
    # picking logic itself is exercised via the single-hunter path twice.
    s1 = build_hunt_summary([hollowing_detected()], selected="hollowing")
    s2 = build_hunt_summary([injection_detected()], selected="injection")
    assert s1["highest_verdict_level"] == "possible"
    assert s2["highest_verdict_level"] == "high"


# ── shape validation: fail loudly on a caller mistake ───────────────────────

def test_rejects_unknown_selected_value():
    with pytest.raises(ValueError, match="banana"):
        build_hunt_summary([injection_detected()], selected="banana")


def test_rejects_non_hunter_record_list():
    with pytest.raises(TypeError):
        build_hunt_summary([{"hunter": "injection"}], selected="injection")


def test_all_rejects_fewer_than_seven_records():
    with pytest.raises(ValueError, match="injection.*hollowing"):
        build_hunt_summary([injection_detected()], selected="all")


def test_all_rejects_records_out_of_fixed_order():
    records = list(reversed(all_seven_detected_variety()))
    with pytest.raises(ValueError):
        build_hunt_summary(records, selected="all")


def test_single_hunter_rejects_more_than_one_record():
    records = [injection_detected(), hollowing_detected()]
    with pytest.raises(ValueError):
        build_hunt_summary(records, selected="injection")


def test_single_hunter_rejects_mismatched_hunter():
    with pytest.raises(ValueError):
        build_hunt_summary([hollowing_detected()], selected="injection")
