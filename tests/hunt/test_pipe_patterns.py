"""Unit tests for dumpex.hunt.pipe.patterns -- the proximity classification
predicate and budget-driven match streaming that back the pipe hunter's C2
retention policy (issue #24, and its own follow-up: a fixed per-region
"matches examined" ceiling reintroduces the same scan-order false negative
at a different threshold, invisibly to c2_budget/coverage)."""
import re
import time

from dumpex.hunt._budget import ScanBudget
from dumpex.hunt.pipe.patterns import is_proximity_match, _iter_c2_matches

_HTTP_PAT = re.compile(r"https?://")   # matched against DECODED text, not raw bytes -- see
                                        # patterns._iter_printable_runs


def _budget(**overrides):
    kwargs = dict(max_bytes_read=10**9, max_attempts=10**9,
                  max_retained_bytes=10**9, max_hits=10**9, deadline=None)
    kwargs.update(overrides)
    return ScanBudget(**kwargs)


# ── is_proximity_match ──────────────────────────────────────────────────

def test_within_distance_of_a_pipe_offset_is_proximity():
    assert is_proximity_match(5050, pipe_offsets=[5000], context_distance=100) is True


def test_beyond_distance_of_every_pipe_offset_is_context_only():
    assert is_proximity_match(6000, pipe_offsets=[5000], context_distance=100) is False


def test_within_distance_of_any_one_of_several_pipe_offsets_is_proximity():
    assert is_proximity_match(5000, pipe_offsets=[100, 5050, 999_999],
                               context_distance=100) is True


def test_no_pipe_offsets_is_never_proximity():
    assert is_proximity_match(5000, pipe_offsets=[], context_distance=100) is False


# ── _iter_c2_matches: no fixed per-region examine cap ───────────────────
# (the direct fix for the P1 follow-up: match #201+ must still be yielded)

def test_iter_c2_matches_yields_far_more_than_the_old_200_cap():
    # 250 isolated "http://" runs -- well past the removed
    # PIPE_C2_MAX_SCAN_PER_REGION=200 ceiling this replaces.
    data = b"".join(b"http://x" + str(i).encode() + b"\x00" for i in range(250))
    matches = list(_iter_c2_matches(data, _HTTP_PAT, _budget()))
    assert len(matches) == 250


def test_iter_c2_matches_stops_on_exhausted_budget_not_silently():
    budget = _budget(max_hits=0)   # already exhausted before the first take_hit
    budget.take_hit(0)             # exhausts max_hits=0 immediately
    assert budget.exhausted()
    data = b"http://a\x00http://b\x00http://c\x00"
    matches = list(_iter_c2_matches(data, _HTTP_PAT, budget))
    assert matches == []
    assert budget.exhausted_reason   # the stop is attributable, not silent


def test_iter_c2_matches_stops_on_expired_deadline_and_reports_why():
    budget = _budget(deadline=time.monotonic() - 1)   # already past
    data = b"http://a\x00http://b\x00http://c\x00"
    matches = list(_iter_c2_matches(data, _HTTP_PAT, budget))
    assert matches == []
    assert budget.exhausted_reason == "deadline"


class _CountdownBudget:
    """Duck-typed ScanBudget substitute: poll() returns True `allowed`
    times, then False forever -- lets us assert _iter_c2_matches actually
    stops consuming/yielding once told to, mid-scan, without needing a
    real clock."""
    def __init__(self, allowed):
        self.allowed = allowed
        self.calls = 0

    def poll(self):
        self.calls += 1
        return self.calls <= self.allowed


def test_iter_c2_matches_stops_promptly_once_polled_out_mid_scan():
    # 200 isolated single-match runs; a budget that only tolerates 3 polls
    # must cut the scan off within a handful of matches, not run to
    # completion first.
    data = b"".join(b"http://x" + str(i).encode() + b"\x00" for i in range(200))
    budget = _CountdownBudget(allowed=3)
    matches = list(_iter_c2_matches(data, _HTTP_PAT, budget))
    assert len(matches) == 3
