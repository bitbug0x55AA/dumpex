"""
Unit tests for the shared coverage/status reduction rule
(dumpex.hunt._coverage) that all four phase-two hunters now call instead
of each hand-rolling the same if/elif chain.
"""
from dumpex.hunt._coverage import derive_status, derive_coverage_status, CoverageTracker
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


def test_coverage_tracker_each_note_method_breaks_complete():
    for method in ("note_skipped_oversize", "note_read_failed", "note_short_read", "note_timed_out"):
        t = CoverageTracker()
        getattr(t, method)()
        assert t.complete is False, method

    t = CoverageTracker(budget_exhausted=True)
    assert t.complete is False


def test_coverage_tracker_build_reasons():
    t = CoverageTracker()
    t.note_skipped_oversize()
    t.note_skipped_oversize()
    t.note_read_failed()
    t.reasons.append("a hunter-specific extra reason")
    reasons = t.build_reasons()
    assert reasons == [
        "2 oversized item(s) skipped",
        "1 item(s) failed to read",
        "a hunter-specific extra reason",
    ]


def test_coverage_tracker_no_gaps_builds_no_reasons():
    t = CoverageTracker(total=5, scanned=5)
    assert t.build_reasons() == []
    assert t.complete is True
