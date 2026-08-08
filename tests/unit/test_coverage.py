"""
Unit tests for the shared coverage/status reduction rule
(dumpex.hunt._coverage) that all four phase-two hunters now call instead
of each hand-rolling the same if/elif chain.
"""
import pytest

from dumpex.hunt._coverage import derive_status, derive_coverage_status, CoverageTracker
from dumpex.output.coverage import ScanTarget, ScanTargetKind
from dumpex.hunt._ui import DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE


def test_derive_status_truth_table():
    # not evaluated always wins, regardless of detected/complete
    assert derive_status(evaluated=False, detected=True, complete=True) == NOT_EVALUATED
    assert derive_status(evaluated=False, detected=False, complete=False) == NOT_EVALUATED

    # detected wins over an incomplete scan -- a real hit in what WAS
    # scanned must not be downgraded just because coverage elsewhere fell short
    assert derive_status(evaluated=True, detected=True, complete=False) == DETECTED
    assert derive_status(evaluated=True, detected=True, complete=True) == DETECTED

    # score == 0 and incomplete coverage -> can't trust a negative result
    assert derive_status(evaluated=True, detected=False, complete=False) == INCONCLUSIVE

    # score == 0 and complete coverage -> genuinely clean
    assert derive_status(evaluated=True, detected=False, complete=True) == NOT_DETECTED_IN_SCANNED_SCOPE


def test_derive_coverage_status_truth_table():
    assert derive_coverage_status(evaluated=False, complete=True) == "not_evaluated"
    assert derive_coverage_status(evaluated=False, complete=False) == "not_evaluated"
    assert derive_coverage_status(evaluated=True, complete=True) == "complete"
    assert derive_coverage_status(evaluated=True, complete=False) == "partial"


def test_coverage_tracker_complete_property():
    t = CoverageTracker(total=10)
    assert t.complete is True

    t.note_read_failed()
    assert t.complete is False


def _oversize_target(base=0x1000, size=32 * 1024, limit=16 * 1024):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=size, size_limit=limit)


def test_coverage_tracker_each_note_method_breaks_complete():
    for method in ("note_read_failed", "note_short_read", "note_timed_out"):
        t = CoverageTracker()
        getattr(t, method)()
        assert t.complete is False, method

    t = CoverageTracker()
    t.note_skipped_oversize(_oversize_target())
    assert t.complete is False

    t = CoverageTracker(budget_exhausted=True)
    assert t.complete is False


def test_note_skipped_oversize_requires_a_scan_target():
    # An oversized skip that can't name what it skipped is the
    # unactionable bare-count shape the tracker moved away from -- a
    # bare call (or a look-alike object) must fail loudly, not silently
    # record a gap with no identity.
    t = CoverageTracker()
    with pytest.raises(TypeError):
        t.note_skipped_oversize()
    with pytest.raises(TypeError):
        t.note_skipped_oversize("0x1000")


def test_skipped_oversize_count_is_derived_from_the_retained_targets():
    t = CoverageTracker()
    assert t.skipped_oversize == 0
    t.note_skipped_oversize(_oversize_target(base=0x1000))
    t.note_skipped_oversize(_oversize_target(base=0x9000))
    assert t.skipped_oversize == 2 == len(t.skipped_oversize_targets)
    assert [x.base_address for x in t.skipped_oversize_targets] == [0x1000, 0x9000]


def test_coverage_tracker_build_reasons():
    t = CoverageTracker()
    t.note_skipped_oversize(_oversize_target(base=0x1000))
    t.note_skipped_oversize(_oversize_target(base=0x9000))
    t.note_read_failed()
    t.reasons.append("a hunter-specific extra reason")
    reasons = t.build_reasons()
    assert reasons == [
        "2 oversized item(s) skipped: 0x0000000000001000 (32 KB > 16 KB limit), "
        "0x0000000000009000 (32 KB > 16 KB limit)",
        "1 item(s) failed to read",
        "a hunter-specific extra reason",
    ]


def test_build_reasons_oversize_preview_is_bounded_and_points_at_json():
    # The rendered text stops after a few targets; the full list stays in
    # skipped_oversize_targets (and, from there, in the JSON limitation).
    t = CoverageTracker()
    for i in range(5):
        t.note_skipped_oversize(_oversize_target(base=0x1000 * (i + 1)))
    reason = t.build_reasons()[0]
    assert reason.startswith("5 oversized item(s) skipped: 0x0000000000001000")
    assert "+2 more (see coverage.limitations[].targets in --json output)" in reason
    assert len(t.skipped_oversize_targets) == 5


def test_coverage_tracker_no_gaps_builds_no_reasons():
    t = CoverageTracker(total=5, scanned=5)
    assert t.build_reasons() == []
    assert t.complete is True


def test_coverage_tracker_note_scanned_increments_and_does_not_affect_complete():
    t = CoverageTracker()
    t.note_scanned()
    t.note_scanned()
    assert t.scanned == 2
    assert t.complete is True   # a successful scan is not itself a coverage gap
