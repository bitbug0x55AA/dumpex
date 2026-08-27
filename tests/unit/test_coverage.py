"""Tests for the shared hunter coverage/status reducer."""
import pytest

from dumpex.hunt._coverage import derive_status, derive_coverage_status, CoverageTracker
from dumpex.output.coverage import ScanTarget, ScanTargetKind, format_scan_target_preview
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
    t = CoverageTracker()
    assert t.complete is True

    t.note_eligible()
    t.note_read_failed()
    assert t.complete is False


def _oversize_target(base=0x1000, size=32 * 1024, limit=16 * 1024):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=size, size_limit=limit)


def test_coverage_tracker_each_note_method_breaks_complete():
    for method in ("note_read_failed", "note_short_read"):
        t = CoverageTracker()
        t.note_eligible()
        getattr(t, method)()
        if method == "note_short_read":
            # An annotation, not a disposition -- the item still needs
            # one, and here it got scanned despite the short read.
            t.note_scanned()
        assert t.complete is False, method

    t = CoverageTracker()
    t.note_eligible()
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
    t.note_eligible()
    t.note_skipped_oversize(_oversize_target(base=0x1000))
    t.note_eligible()
    t.note_skipped_oversize(_oversize_target(base=0x9000))
    assert t.skipped_oversize == 2 == len(t.skipped_oversize_targets)
    assert [x.base_address for x in t.skipped_oversize_targets] == [0x1000, 0x9000]


def test_the_tracker_accumulates_facts_and_renders_none_of_them():
    """Reason text belongs to each hunter, rendered from its own frozen
    coverage snapshot -- the tracker exposes counters and targets, with no
    second renderer a hunter's wording could drift from."""
    tracker = CoverageTracker()
    assert not hasattr(tracker, "build_reasons")
    assert not hasattr(tracker, "reasons")


def test_oversize_preview_is_bounded_and_points_at_json():
    # A rendered preview stops after a few targets; the full list stays on
    # the tracker (and, from there, in the JSON limitation).
    t = CoverageTracker()
    for i in range(5):
        t.note_eligible()
        t.note_skipped_oversize(_oversize_target(base=0x1000 * (i + 1)))
    preview = format_scan_target_preview(t.skipped_oversize_targets)
    assert preview.startswith("0x0000000000001000")
    assert "+2 more (see coverage.limitations[].targets in --json output)" in preview
    assert len(t.skipped_oversize_targets) == 5


def test_coverage_tracker_no_gaps_is_complete():
    t = CoverageTracker()
    for _ in range(5):
        t.note_eligible()
        t.note_scanned()
    assert t.complete is True
    assert t.reconciled is True


def test_coverage_tracker_note_scanned_increments_and_does_not_affect_complete():
    t = CoverageTracker()
    for _ in range(2):
        t.note_eligible()
        t.note_scanned()
    assert t.scanned == 2
    assert t.complete is True


def _failure_target(base=0x2000, size=4096):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                      size=size, size_limit=None)


def test_note_read_failed_without_a_target_still_works_unchanged():
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_read_failed()
    assert tracker.read_failed == 1
    assert tracker.read_failed_targets == []


@pytest.mark.parametrize(
    "method,count_attr,targets_attr,base",
    [
        ("note_read_failed", "read_failed", "read_failed_targets", 0x2000),
        ("note_short_read", "short_reads", "short_read_targets", 0x3000),
    ],
    ids=["read-failed", "short-read"],
)
def test_failure_notes_retain_their_scan_target(method, count_attr, targets_attr, base):
    tracker = CoverageTracker()
    tracker.note_eligible()
    target = _failure_target(base=base)
    getattr(tracker, method)(target)
    assert getattr(tracker, count_attr) == 1
    assert getattr(tracker, targets_attr) == [target]


@pytest.mark.parametrize("method", ["note_read_failed", "note_short_read"])
def test_failure_notes_reject_non_scan_targets(method):
    tracker = CoverageTracker()
    with pytest.raises(TypeError):
        getattr(tracker, method)("0x2000")


def test_a_failure_note_retains_a_target_only_when_one_is_supplied():
    """A caller that cannot resolve the item's identity at the failure
    site still records the gap -- it just leaves the target list empty,
    and a renderer appends no preview for it."""
    bare = CoverageTracker()
    bare.note_eligible()
    bare.note_read_failed()
    assert (bare.read_failed, bare.read_failed_targets) == (1, [])

    with_target = CoverageTracker()
    with_target.note_eligible()
    with_target.note_read_failed(_failure_target())
    assert with_target.read_failed == 1
    assert (format_scan_target_preview(with_target.read_failed_targets)
            == "0x0000000000002000 (4 KB)")


# ── The reconciliation ledger ─────────────────────────────────────────────
# `complete` is a POSITIVE assertion that every eligible item reached a
# recorded outcome -- not merely that no gap happened to be reported. A
# scan loop that `continue`s out of an iteration without calling any
# note_* method must therefore be distinguishable from full coverage.

def test_a_walked_item_with_no_disposition_fails_closed():
    tracker = CoverageTracker()
    for _ in range(9):
        tracker.note_eligible()
        tracker.note_scanned()
    tracker.note_eligible()      # the tenth item hit a `continue`
                                  # that recorded nothing

    assert tracker.total == 10
    assert tracker.accounted == 9
    assert tracker.unaccounted == 1
    assert tracker.reconciled is False
    assert tracker.complete is False


def test_an_unreconciled_tracker_reduces_to_inconclusive_not_a_clean_negative():
    """A missed disposition must not turn "we could not rule this out"
    into "we checked and it is not there"."""
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_scanned()
    tracker.note_eligible()      # walked, no outcome recorded

    assert derive_coverage_status(evaluated=True, complete=tracker.complete) == "partial"
    assert derive_status(evaluated=True, detected=False,
                          complete=tracker.complete) == INCONCLUSIVE
    # ...and a real hit still wins over incomplete coverage.
    assert derive_status(evaluated=True, detected=True, complete=tracker.complete) == DETECTED


def test_a_fully_reconciled_scan_is_still_complete():
    """`complete` stays reachable: every disposition, including the two
    that are outcomes rather than gaps, reconciles."""
    tracker = CoverageTracker()
    for _ in range(2):
        tracker.note_eligible()
        tracker.note_scanned()
    for _ in range(2):
        tracker.note_eligible()
        tracker.note_not_applicable()

    assert tracker.accounted == tracker.total == 4
    assert tracker.reconciled is True
    assert tracker.complete is True
    assert derive_status(evaluated=True, detected=False,
                          complete=tracker.complete) == NOT_DETECTED_IN_SCANNED_SCOPE


def test_not_applicable_is_an_outcome_not_a_gap():
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_not_applicable()
    assert tracker.not_applicable == 1
    assert tracker.complete is True
    assert tracker.reconciled is True


def _record(tracker, disposition):
    if disposition == "note_skipped_oversize":
        tracker.note_skipped_oversize(_oversize_target())
    else:
        getattr(tracker, disposition)()


DISPOSITIONS = ["note_scanned", "note_not_applicable", "note_read_failed",
                "note_skipped_oversize"]


@pytest.mark.parametrize("second", DISPOSITIONS)
def test_a_second_disposition_for_one_item_is_never_absorbed(second):
    """Dispositions are mutually exclusive: a second one against a single
    note_eligible() belongs to no item, so it is counted as over-accounted
    rather than consuming some OTHER item's missing disposition -- which
    would cancel the two errors into a false "complete"."""
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_scanned()
    _record(tracker, second)

    assert tracker.over_accounted == 1
    assert tracker.reconciled is False
    assert tracker.complete is False


@pytest.mark.parametrize("second", DISPOSITIONS)
def test_strict_mode_rejects_a_second_disposition_outright(second):
    """A hunt delivers what it can, so the shipped scans record the error
    and carry on. `strict` is the same contract stated as a rejection, for
    a caller that wants the bug to stop the loop."""
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible()
    tracker.note_scanned()
    with pytest.raises(RuntimeError, match="no eligible item open"):
        _record(tracker, second)


def test_a_ledger_error_never_terminates_a_shipped_scan():
    """Every construction site in dumpex/hunt leaves `strict` off: an
    accounting bug degrades that hunter's coverage to partial instead of
    taking the whole run's output with it."""
    assert CoverageTracker().strict is False


def test_a_short_read_is_an_annotation_that_co_occurs_with_scanned():
    """A non-empty short read is BOTH facts at once -- the readable prefix
    was scanned, and the region was not read in full -- so it takes the
    `scanned` disposition plus a short_reads annotation, and must not be
    counted against `total` twice."""
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_short_read(_failure_target())
    tracker.note_scanned()

    assert (tracker.short_reads, tracker.scanned) == (1, 1)
    assert tracker.accounted == tracker.total == 1
    assert tracker.reconciled is True
    assert tracker.complete is False        # the unread remainder is still a gap
    assert tracker.short_read_targets == [_failure_target()]


def test_dispositions_recorded_without_note_eligible_fail_closed_too():
    """A scan loop that reports coverage from a tracker it never called
    note_eligible() on. The ledger's other direction catches it, so a
    construction site that skips the eligibility hook cannot report a
    clean scan."""
    tracker = CoverageTracker()
    tracker.note_scanned()
    tracker.note_scanned()

    assert (tracker.total, tracker.accounted) == (0, 2)
    assert tracker.over_accounted == 2
    assert tracker.complete is False


def test_note_eligible_accumulates_bytes_alongside_the_item_count():
    """`eligible_bytes` accumulates at the same call as `total`, so
    expressing partial coverage as a fraction of eligible memory needs no
    second pass over the scan loops."""
    tracker = CoverageTracker()
    tracker.note_eligible(4096)
    tracker.note_scanned()
    tracker.note_eligible(64 * 1024)
    tracker.note_skipped_oversize(_oversize_target())

    assert tracker.total == 2
    assert tracker.eligible_bytes == 4096 + 64 * 1024
    # Default 0 for a caller that has no size to report -- an item count
    # is still a complete ledger on its own.
    bare = CoverageTracker()
    bare.note_eligible()
    assert (bare.total, bare.eligible_bytes) == (1, 0)


def test_the_tracker_has_no_per_item_timeout_surface():
    """Every scan loop that abandons work on a deadline does so with a
    whole-scan `break`, which leaves the remaining items un-walked and
    therefore never eligible -- there is no per-item timeout to record,
    and no `complete` branch may exist for one."""
    assert not hasattr(CoverageTracker(), "timed_out")
    assert not hasattr(CoverageTracker(), "note_timed_out")


def test_a_missed_disposition_and_a_later_double_one_cannot_cancel():
    """In real loop order: item 1 leaves its iteration recording nothing,
    then item 2 records two dispositions. A ledger that only compared
    totals would net these out to `accounted == total` and report a clean
    scan. Each is charged where it happens instead: item 1's miss the
    moment item 2 opens, item 2's extra to over-accounting."""
    tracker = CoverageTracker()
    tracker.note_eligible()          # item 1 -- falls through recording nothing
    tracker.note_eligible()          # item 2
    tracker.note_scanned()
    tracker.note_scanned()           # a second one for item 2

    assert (tracker.unaccounted, tracker.over_accounted) == (1, 1)
    assert tracker.accounted == tracker.total == 2   # the totals DO net out
    assert tracker.reconciled is False               # the ledger still does not
    assert tracker.complete is False


def test_the_two_ledger_directions_are_reported_separately():
    walked_past = CoverageTracker()
    walked_past.note_eligible()
    walked_past.note_eligible()
    walked_past.note_scanned()
    assert (walked_past.unaccounted, walked_past.over_accounted) == (1, 0)
    assert walked_past.reconciled is False

    never_in_scope = CoverageTracker()
    never_in_scope.note_scanned()
    never_in_scope.note_scanned()
    assert (never_in_scope.unaccounted, never_in_scope.over_accounted) == (0, 2)
    assert never_in_scope.reconciled is False


def test_reconciled_also_catches_a_counter_bumped_around_the_note_methods():
    """The arithmetic half of `reconciled`: a disposition counter raised
    directly, without going through the note_* method that maintains the
    per-item bookkeeping, still leaves the ledger out of balance."""
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_scanned()
    assert tracker.reconciled is True

    tracker.scanned += 1
    assert tracker.reconciled is False
    assert tracker.complete is False
