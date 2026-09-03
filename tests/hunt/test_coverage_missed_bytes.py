"""How much captured memory a partial hunt actually missed.

`coverage.status` grades a run complete/partial/not_evaluated. On its own
`partial` cannot separate one unreadable 4 KB region from forty oversized
ones adding up to gigabytes, and those two decide opposite things about
whether the dump is worth recollecting. `coverage.missed_bytes` grades a
`partial` by bytes; these tests pin what it may and may not claim.

Two rules run through all of it:

  * the basis is what the .dmp actually holds for a target
    (`ScanTarget.captured_size`), never a declared `RegionSize` that can
    claim more address space than was ever written;
  * a gap whose byte extent is not established is COUNTED, never
    estimated. Zero is reserved for "nothing capturable was missed".
"""
import ast
import pathlib

import pytest

from dumpex.hunt._coverage import (
    CoverageTracker, budget_stop_targets, derive_status, region_scan_target,
    segment_scan_target,
)
from dumpex.hunt._ui import DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE
from dumpex.output.coverage import (
    CoverageLimitation, LimitationCode, MemoryGapKind, MissedBytes, MissedBytesState,
    ScanTarget, ScanTargetKind, format_missed_bytes_clause, summarize_missed_bytes,
)

from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment

_MB = 1 << 20
_BASE = 0x10000000


_UNSET = object()


def _target(*, size=4096, captured=_UNSET, examined=None, limit=None,
             kind=ScanTargetKind.MEMORY_REGION, base=_BASE):
    captured = size if captured is _UNSET else captured
    return ScanTarget(kind=kind, base_address=base, size=size, size_limit=limit,
                       file_offset=0x1000 if captured else None,
                       captured_size=captured, examined_size=examined)


def _limitation(code, targets=(), *, source="pipe_name_scan", affected_count=None, **kw):
    return CoverageLimitation(
        code=code, source=source, targets=tuple(targets),
        affected_count=(len(targets) if affected_count is None and targets
                         else affected_count),
        **kw)


# ── per-target extents ──────────────────────────────────────────────────

def test_an_unexamined_target_reports_its_whole_capture_as_the_gap():
    assert _target(size=8192, captured=8192, examined=0).unexamined_bytes == 8192


def test_a_partly_examined_target_reports_only_the_remainder():
    assert _target(size=8192, captured=8192, examined=3000).unexamined_bytes == 5192


def test_an_unestablished_extent_is_none_rather_than_the_whole_target():
    # The distinction the whole feature turns on: nobody recorded how much
    # of this was looked at, which is not the same claim as "none of it".
    assert _target(size=8192, captured=8192).unexamined_bytes is None


def test_a_target_the_dump_captured_nothing_for_misses_nothing():
    # There were no bytes here to miss. What this target needs is a
    # re-collection, which `capture_state` already says -- counting it as a
    # gap of unknown size would put an unanswerable question beside a
    # status word that has a perfectly good answer.
    target = _target(size=8192, captured=0)
    assert target.capture_state == "none"
    assert target.unexamined_bytes == 0


def test_capture_that_was_never_computed_leaves_the_extent_unknown():
    assert _target(size=8192, captured=None).unexamined_bytes is None


def test_a_scan_cannot_have_examined_bytes_the_dump_does_not_hold():
    with pytest.raises(ValueError, match="must not exceed captured_size"):
        _target(size=8192, captured=4096, examined=4097)


def test_an_examined_extent_needs_a_capture_to_measure_it_against():
    with pytest.raises(ValueError, match="requires captured_size"):
        ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=_BASE, size=8192,
                    examined_size=0)


def test_the_wire_carries_the_derived_remainder_beside_the_examined_extent():
    d = _target(size=8192, captured=8192, examined=3000).to_dict()
    assert d["examined_size"] == 3000
    assert d["unexamined_size"] == 5192


# ── the aggregate ───────────────────────────────────────────────────────

def test_a_run_with_no_gaps_reports_an_exact_zero():
    missed = summarize_missed_bytes([])
    assert missed.state is MissedBytesState.EXACT
    assert missed.known_bytes == 0 and missed.gap_count == 0
    assert missed.to_dict()["bytes"] == 0


def test_a_gap_that_costs_no_capturable_bytes_invents_none():
    # A stream present but incomplete, an absent counterpart source: real
    # reasons for `partial`, and not one capturable byte between them.
    missed = summarize_missed_bytes([
        CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="handle_data"),
        CoverageLimitation(code=LimitationCode.THREAD_CONTEXT_PARTIAL,
                            source="thread_context", affected_count=3),
    ])
    assert missed == MissedBytes()


def test_an_oversized_skip_contributes_its_exact_capture():
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                    [_target(size=16 * _MB, captured=16 * _MB, examined=0, limit=8 * _MB)])])
    assert missed.known_bytes == 16 * _MB
    assert missed.state is MissedBytesState.EXACT


def test_a_read_failure_contributes_its_exact_capture():
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096, examined=0)])])
    assert missed.known_bytes == 4096 and missed.state is MissedBytesState.EXACT


def test_a_short_read_contributes_only_the_bytes_that_never_came_back():
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_SHORT_READ,
                    [_target(size=4096, captured=4096, examined=1024)])])
    assert missed.known_bytes == 3072


def test_a_short_read_with_no_returned_length_is_counted_not_charged_whole():
    # The readable prefix WAS scanned. Without the returned length there is
    # no way to say how much of the region is left, and claiming the whole
    # 4 KB would be a number the evidence does not support.
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_SHORT_READ,
                    [_target(size=4096, captured=4096)])])
    assert missed.state is MissedBytesState.UNKNOWN
    assert missed.known_bytes == 0 and missed.unquantified_gaps == 1


def test_a_gap_with_no_target_vocabulary_is_counted_as_unmeasured():
    missed = summarize_missed_bytes([
        CoverageLimitation(code=LimitationCode.SCAN_ITEMS_UNACCOUNTED,
                            source="pipe_name_scan", affected_count=3)])
    assert missed.state is MissedBytesState.UNKNOWN
    assert missed.unquantified_gaps == 3


def test_an_unrecorded_extent_is_unquantified_whatever_the_code_establishes():
    """A read that raised establishes that nothing was examined -- but the
    aggregate reads the TARGET, not the code name, so a producer that did
    not record it publishes an unknown rather than an exact figure the
    target beside it contradicts."""
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096)])])
    assert missed.state is MissedBytesState.UNKNOWN


def test_a_target_bearing_code_that_names_none_falls_back_to_its_count():
    # `targets` is optional on this code -- a caller that cannot resolve
    # the region's identity at the failure site still reports the gap, and
    # a gap with no target has no capture to measure against.
    missed = summarize_missed_bytes([
        CoverageLimitation(code=LimitationCode.SCAN_REGION_READ_FAILED,
                            source="pipe_name_scan", affected_count=2)])
    assert missed.state is MissedBytesState.UNKNOWN
    assert missed.unquantified_gaps == 2


def test_measured_and_unmeasured_gaps_together_make_a_lower_bound():
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096, examined=0)]),
        CoverageLimitation(code=LimitationCode.SCAN_ITEMS_UNACCOUNTED,
                            source="pipe_name_scan", affected_count=3)])
    assert missed.known_bytes == 4096
    assert missed.quantified_gaps == 1 and missed.unquantified_gaps == 3
    assert missed.state is MissedBytesState.LOWER_BOUND


def test_affected_count_is_never_added_to_the_byte_total():
    """`affected_count` counts targets and relationships; a count that
    leaked into the byte sum would read as an absurdly small miss."""
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                    [_target(size=16 * _MB, captured=16 * _MB, examined=0, limit=8 * _MB)]),
        CoverageLimitation(code=LimitationCode.SCAN_ITEMS_UNACCOUNTED,
                            source="pipe_name_scan", affected_count=9),
    ])
    assert missed.known_bytes == 16 * _MB


def test_a_result_cap_is_not_a_memory_gap():
    # The search DID examine this memory; what was capped is how many
    # findings were retained. Counting it here would grow the missed-byte
    # figure for a run that missed no bytes at all.
    missed = summarize_missed_bytes([
        CoverageLimitation(code=LimitationCode.PE_HEADER_EVIDENCE_CAPPED,
                            source="hidden_pe_scan", affected_count=5)])
    assert missed == MissedBytes()


def test_a_search_that_read_its_bytes_without_applying_everything_is_counted():
    """The scan reached these bytes and could not search them
    exhaustively. What went unexamined is real; a match quota and a window
    stride are not byte ranges, so it is counted and left unmeasured
    rather than either estimated or ignored."""
    missed = summarize_missed_bytes([
        CoverageLimitation(code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE,
                            source="pipe_name_scan", scope=None,
                            detail="match_cap_reached", affected_count=2)])
    assert missed.state is MissedBytesState.UNKNOWN
    assert missed.unquantified_gaps == 2


def test_the_aggregate_equals_the_sum_of_the_per_target_extents_on_the_wire():
    """The one structural guarantee behind "exact aggregate bytes and
    itemized per-target extents cannot disagree": both are the same
    numbers, summed, not two independently maintained ones."""
    targets = [_target(size=4096, captured=4096, examined=0, base=_BASE),
               _target(size=8192, captured=8192, examined=1024, base=_BASE + 0x10000)]
    limitation = _limitation(LimitationCode.SCAN_REGION_SHORT_READ, targets)
    missed = summarize_missed_bytes([limitation])
    assert missed.known_bytes == sum(t.to_dict()["unexamined_size"] for t in targets)


# ── how the aggregate labels itself ─────────────────────────────────────

def test_an_aggregate_with_an_unmeasured_gap_is_a_lower_bound_not_a_total():
    missed = MissedBytes(known_bytes=4096, quantified_gaps=1, unquantified_gaps=1,
                          distinct_ranges=1)
    assert missed.state is MissedBytesState.LOWER_BOUND
    assert missed.complete is False
    assert "at least" in format_missed_bytes_clause(missed)


def test_an_unknown_aggregate_reports_no_byte_figure_at_all():
    """`bytes: 0` would read as "nothing was missed" to a consumer
    thresholding on it, which is the opposite of what is known here."""
    d = MissedBytes(unquantified_gaps=2).to_dict()
    assert d["state"] == "unknown" and d["bytes"] is None and d["complete"] is False


def test_an_exact_aggregate_states_a_total():
    clause = format_missed_bytes_clause(
        MissedBytes(known_bytes=3 * _MB, quantified_gaps=4, distinct_ranges=4))
    assert clause == "3 MB unscanned across 4 range(s)"
    assert "at least" not in clause


def test_an_aggregate_is_rendered_scaled_even_when_it_is_not_a_round_unit():
    """A total is round only by accident. The exact-unit formatter the cap
    text uses would print nine digits here, which is not a figure anyone
    reads a recollect decision off."""
    clause = format_missed_bytes_clause(
        MissedBytes(known_bytes=3355443, quantified_gaps=4, distinct_ranges=4))
    assert clause.startswith("3.2 MB unscanned")


def test_nothing_measurable_missed_adds_no_clause_at_all():
    # The status word is the whole story; a rendered "0 bytes unscanned"
    # beside it is noise.
    assert format_missed_bytes_clause(MissedBytes(quantified_gaps=1)) is None


def test_bytes_belonging_to_no_gap_are_refused():
    with pytest.raises(ValueError, match="requires at least one"):
        MissedBytes(known_bytes=4096)


def test_more_ranges_than_the_gaps_they_came_from_are_refused():
    """Merging gap records can only ever reduce how many ranges they
    cover, so the reverse is an arithmetic impossibility, not a shape to
    render."""
    with pytest.raises(ValueError, match="cannot exceed quantified_gaps"):
        MissedBytes(known_bytes=4096, quantified_gaps=1, distinct_ranges=2)


# ── the figure measures memory, not gap records ─────────────────────────

def test_one_region_skipped_by_several_scan_layers_is_counted_once():
    """Obfuscation runs three layers with different size caps over
    overlapping region sets, so one oversized region is skipped by two or
    three of them and appears in one limitation per layer. Summing those
    would report two or three times the memory a re-collection has to
    recover -- and could report more than the dump captured."""
    def _layer(scope):
        return CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="encoding_scan",
            scope=scope, affected_count=1,
            targets=(_target(size=12 * _MB, captured=12 * _MB, examined=0, limit=2 * _MB),))

    missed = summarize_missed_bytes([_layer("entropy"), _layer("decode"),
                                      _layer("sleep_mask")])
    assert missed.known_bytes == 12 * _MB
    assert missed.quantified_gaps == 3 and missed.distinct_ranges == 1
    assert missed.state is MissedBytesState.EXACT


def test_a_region_short_read_and_then_stopped_inside_is_counted_once():
    """The unreturned tail belongs to both gaps. Added up it would be
    charged twice and the examined middle once."""
    base, size = _BASE, 8192
    short_read = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_SHORT_READ, source="segment_scan", affected_count=1,
        targets=(_target(size=size, captured=size, examined=2048, base=base),))
    budget = CoverageLimitation(
        code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="segment_scan", detail="deadline",
        affected_count=1,
        targets=(_target(size=size, captured=size, examined=1024, base=base),))
    missed = summarize_missed_bytes([short_read, budget])
    assert missed.known_bytes == size - 1024
    assert missed.quantified_gaps == 2 and missed.distinct_ranges == 1


def test_gaps_in_different_regions_stay_separate_ranges():
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096, examined=0, base=_BASE)]),
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096, examined=0, base=_BASE + 0x100000)],
                    source="ioc_string_scan")])
    assert missed.known_bytes == 8192 and missed.distinct_ranges == 2


def test_adjacent_gaps_merge_into_one_range():
    """Two halves of one allocation reported by two gaps are one range a
    single targeted rescan covers, not two."""
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096, examined=0, base=_BASE)]),
        _limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                    [_target(size=4096, captured=4096, examined=0, base=_BASE + 4096)],
                    source="ioc_string_scan")])
    assert missed.known_bytes == 8192 and missed.distinct_ranges == 1


def test_a_zero_byte_gap_is_measured_but_spans_no_range():
    """A target the dump captured nothing for missed exactly nothing: a
    quantified gap that adds no range and no bytes."""
    missed = summarize_missed_bytes([
        _limitation(LimitationCode.SCAN_REGION_SHORT_READ,
                    [_target(size=4096, captured=0)])])
    assert missed.state is MissedBytesState.EXACT
    assert missed.quantified_gaps == 1 and missed.distinct_ranges == 0
    assert missed.known_bytes == 0


# ── what each disposition proves ────────────────────────────────────────

class _Region:
    def __init__(self, base, size):
        self.BaseAddress, self.RegionSize = base, size
        self.AllocationBase = base
        self.State, self.Protect, self.Type = 0x1000, 0x04, 0x20000


def _mf(base=_BASE, size=8192, captured=None):
    mf = FakeMF()
    mf.memory_info = FakeStream([Region(base, base, size, "MEM_COMMIT",
                                         "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf.memory_segments_64 = FakeStream(
        [Segment(base, 0x1000, size if captured is None else captured)], "memory_segments")
    mf.modules = FakeStream([], "modules")
    return mf


def test_an_oversized_skip_records_that_nothing_was_examined():
    mf = _mf()
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(8192)
    tracker.note_skipped_oversize(region_scan_target(mf, mf.memory_info.infos[0], 4096))
    target = tracker.skipped_oversize_targets[0]
    assert target.examined_size == 0 and target.unexamined_bytes == 8192


def test_a_read_failure_records_that_nothing_was_examined():
    mf = _mf()
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(8192)
    tracker.note_read_failed(region_scan_target(mf, mf.memory_info.infos[0]))
    assert tracker.read_failed_targets[0].unexamined_bytes == 8192


def test_a_short_read_retains_the_bytes_that_actually_came_back():
    mf = _mf()
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(8192)
    tracker.note_short_read(region_scan_target(mf, mf.memory_info.infos[0]), got=2048)
    tracker.note_scanned()
    assert tracker.short_read_targets[0].examined_size == 2048
    assert tracker.short_read_targets[0].unexamined_bytes == 6144


def test_a_short_read_without_a_returned_length_stays_unmeasured():
    mf = _mf()
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(8192)
    tracker.note_short_read(region_scan_target(mf, mf.memory_info.infos[0]))
    tracker.note_scanned()
    assert tracker.short_read_targets[0].examined_size is None


def test_a_read_that_over_serves_the_capture_is_clamped_not_discarded():
    # The two numbers count different things -- bytes a reader handed back,
    # bytes the dump's own table claims -- and the quantity being derived,
    # captured bytes left unexamined, is zero either way.
    mf = _mf(size=8192, captured=4096)
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(4096)
    tracker.note_short_read(region_scan_target(mf, mf.memory_info.infos[0]), got=8192)
    tracker.note_scanned()
    assert tracker.short_read_targets[0].examined_size == 4096
    assert tracker.short_read_targets[0].unexamined_bytes == 0


def test_a_short_read_annotation_still_costs_the_scan_no_disposition():
    """The returned length rides along on an ANNOTATION -- it must not
    turn one into a disposition and unbalance the ledger."""
    mf = _mf()
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(8192)
    tracker.note_short_read(region_scan_target(mf, mf.memory_info.infos[0]), got=2048)
    tracker.note_scanned()
    assert tracker.reconciled and tracker.total == 1 and tracker.scanned == 1


# ── a budget stop ───────────────────────────────────────────────────────

def _segments(*sizes, base=_BASE):
    out, va, fo = [], base, 0x1000
    for size in sizes:
        out.append(Segment(va, fo, size))
        va, fo = va + size, fo + size
    return out


def test_segments_a_budget_never_reached_contribute_their_whole_capture():
    targets = budget_stop_targets(_segments(4096, 8192), first_started=False)
    assert [t.unexamined_bytes for t in targets] == [4096, 8192]


def test_the_segment_a_budget_stopped_inside_is_not_charged_whole():
    """Only the run BEHIND the stop is provably untouched. Charging the
    segment the scan was working on would claim bytes it did examine."""
    targets = budget_stop_targets(_segments(4096, 8192), first_started=True)
    assert targets[0].unexamined_bytes is None
    assert targets[1].unexamined_bytes == 8192


def test_a_stop_cursor_makes_the_interrupted_segment_measurable_too():
    targets = budget_stop_targets(_segments(4096, 8192), first_started=True,
                                   first_examined=1000)
    assert targets[0].unexamined_bytes == 3096


def test_a_mid_target_stop_with_no_cursor_reports_an_explicit_lower_bound():
    limitation = _limitation(
        LimitationCode.SCAN_BUDGET_EXHAUSTED,
        budget_stop_targets(_segments(4096, 8192), first_started=True),
        detail="deadline")
    missed = summarize_missed_bytes([limitation])
    assert missed.state is MissedBytesState.LOWER_BOUND
    assert missed.known_bytes == 8192 and missed.unquantified_gaps == 1


# ── every short-read call site supplies the returned length ─────────────

def _short_read_calls():
    root = pathlib.Path(__file__).resolve().parent.parent.parent / "dumpex"
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "note_short_read"):
                yield path, node


def test_every_short_read_call_site_records_the_returned_length():
    """A short read is the one gap whose extent is NOT the whole captured
    item, so a call site that drops the returned length silently turns a
    measurable gap into an unmeasurable one -- invisible in output, since
    the gap is still reported either way."""
    missing = [f"{path.name}:{node.lineno}" for path, node in _short_read_calls()
               if not any(kw.arg == "got" for kw in node.keywords)]
    assert missing == [], (
        f"note_short_read() call site(s) with no got=: {missing}")


# ── end to end: two dumps differing only in how much was skipped ────────

def _pipe_report(region_size):
    import dumpex.hunt.pipe as pipemod
    return pipemod._build_pipe_report(_mf(size=region_size))


def _coverage_line(report):
    from dumpex.hunt.pipe.report_console import render_console_lines
    return next(line for line in render_console_lines(report) if "Coverage" in line)


def _pipe_coverage(report):
    from dumpex.hunt.pipe.report_facts import project_coverage_report
    return project_coverage_report(report.coverage)


def test_two_runs_differing_only_in_skipped_memory_read_differently():
    small, large = _pipe_report(12 * _MB), _pipe_report(64 * _MB)

    assert _pipe_coverage(small).missed_bytes.known_bytes == 12 * _MB
    assert _pipe_coverage(large).missed_bytes.known_bytes == 64 * _MB
    assert "12 MB unscanned across 1 range(s)" in _coverage_line(small)
    assert "64 MB unscanned across 1 range(s)" in _coverage_line(large)


def test_grading_a_partial_moves_no_verdict_and_no_status():
    small, large = _pipe_report(12 * _MB), _pipe_report(64 * _MB)
    for report in (small, large):
        assert report.status == INCONCLUSIVE
        assert report.score == 0
        assert _pipe_coverage(report).status.value == "partial"


def test_grading_a_partial_leaves_the_reason_text_alone():
    """`coverage.reasons` is rendered from the limitations themselves and
    says nothing about byte totals -- the quantification is a structured
    field beside it, never a new sentence inside it."""
    reasons = _pipe_coverage(_pipe_report(12 * _MB)).reasons
    assert reasons == ["handle_data not present in this dump",
                       "1 oversized region(s) skipped: "
                       "0x0000000010000000 (12 MB > 8 MB limit)"]
    assert not any("unscanned" in reason for reason in reasons)


def test_a_partial_that_missed_no_capturable_bytes_invents_none(monkeypatch):
    """This run is `partial` because the dump carries no HandleDataStream
    -- a real gap that costs not one capturable byte. The status word must
    not acquire a byte figure to justify itself."""
    import dumpex.hunt.pipe as pipemod
    from tests.fixtures.fakes import mem_reader

    mf = _mf(size=4096)
    monkeypatch.setattr(pipemod, "read_region", mem_reader({_BASE: b"\x00" * 4096}))
    report = pipemod._build_pipe_report(mf)
    coverage = _pipe_coverage(report)

    assert coverage.status.value == "partial"
    # The scale IS established -- the region walk took 4 KB into scope --
    # and 0% of it went unscanned. That is an answer, and a different one
    # from "no gap was measured": this run is partial for a missing
    # stream, and the line says so without inventing a byte figure.
    assert coverage.missed_bytes == MissedBytes(eligible_bytes=4096)
    assert coverage.missed_bytes.unscanned_fraction == 0.0
    assert (_coverage_line(report).strip()
            == "Coverage    PARTIAL — 0 bytes unscanned (0% of 4 KB eligible)")


def test_derive_status_is_untouched_by_any_of_this():
    assert derive_status(True, True, False) == DETECTED
    assert derive_status(True, False, False) == INCONCLUSIVE
    assert derive_status(True, False, True) == NOT_DETECTED_IN_SCANNED_SCOPE


def test_the_aggregate_reads_no_dump_bytes():
    """Arithmetic over targets already retained for reporting -- a
    summation that re-read the dump would make coverage reporting cost
    real I/O on exactly the runs already struggling for budget."""
    reads = []
    mf = _mf(size=16 * _MB)
    tracker = CoverageTracker(strict=True)
    tracker.note_eligible(16 * _MB)
    tracker.note_skipped_oversize(
        region_scan_target(mf, mf.memory_info.infos[0], 8 * _MB))
    limitation = _limitation(LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                              tracker.skipped_oversize_targets)
    mf._reader = None
    mf.read = lambda *a, **kw: reads.append(a) or b""
    assert summarize_missed_bytes([limitation]).known_bytes == 16 * _MB
    assert reads == []


def test_a_segment_target_carries_its_extent_the_same_way_a_region_does():
    segment = Segment(_BASE, 0x1000, 4096)
    assert segment_scan_target(segment, examined_size=1024).unexamined_bytes == 3072


# ── a whole-scan budget that never reaches its segments ─────────────────

def test_a_deadline_before_the_first_segment_charges_both_segments_exactly(monkeypatch):
    """The two whole-scan checks at the top of cs-beacon's segment loop run
    BEFORE the segment is read, so every segment the stop names is provably
    untouched -- including the one the loop was about to start on."""
    from tests.fixtures.fakes import FakeReader
    import dumpex.hunt.cs_beacon as cs_beacon
    from dumpex.hunt.cs_beacon.collect import collect_cs_beacon_record

    seg_size = 0x1000
    segments, reads = [], {}
    for index in range(2):
        va = 0x73000000 + index * 0x100000
        segments.append(Segment(va, va, seg_size))
        reads[va] = b"\x00" * seg_size

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segments, "memory_segments")
        memory_info = FakeStream([], "infos")
        _reader = FakeReader(reads)

    ticks = {"n": 0}

    def _expired_clock():
        ticks["n"] += 1
        return ticks["n"] * (cs_beacon.CS_SCAN_DEADLINE_SECONDS * 2)

    monkeypatch.setattr(cs_beacon.time, "monotonic", _expired_clock)
    record = collect_cs_beacon_record(MF())

    limitation = next(l for l in record.coverage.limitations
                       if l.code is LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED)
    assert [t.unexamined_bytes for t in limitation.targets] == [seg_size, seg_size]
    missed = record.coverage.missed_bytes
    assert missed.state is MissedBytesState.EXACT
    assert missed.known_bytes == 2 * seg_size


# ── the document-level rollup measures its records ──────────────────────

def test_the_hunt_document_rollup_measures_what_its_hunters_missed():
    """`--hunt`'s document coverage holds no limitations of its own (every
    gap lives on the record that owns it), so an aggregate derived from
    them alone would be an exact zero however much was missed -- the one
    shape that means "nothing capturable was missed" to a pipeline
    thresholding on it."""
    from dumpex.hunt import collect_hunt

    result = collect_hunt(_mf(size=64 * _MB), selected="all")
    assert result.coverage.status.value == "partial"
    assert result.coverage.limitations == []
    assert result.coverage.missed_bytes.known_bytes == 64 * _MB


def test_the_document_rollup_counts_shared_memory_once():
    """Several analyzers each skip the same oversized region. That is one
    region a re-collection has to recover, however many of them reported
    it -- which is also why the byte figure does not depend on how many
    hunters this build can actually run."""
    from dumpex.hunt import collect_hunt

    result = collect_hunt(_mf(size=64 * _MB), selected="all")
    missed = result.coverage.missed_bytes
    assert missed.distinct_ranges == 1
    assert missed.quantified_gaps >= missed.distinct_ranges
    assert missed.known_bytes == 64 * _MB


def test_a_rollup_is_only_for_a_report_with_no_limitations_of_its_own():
    """Two independent sources of truth for one number is exactly what
    this feature exists to avoid."""
    from dumpex.output.coverage import CoverageReport

    with pytest.raises(ValueError, match="must not also be given one"):
        CoverageReport(
            status="partial",
            limitations=[_limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                                      [_target(size=4096, captured=4096, examined=0)])],
            missed_bytes_rollup=MissedBytes())


# ── every limitation code has a reviewed classification ─────────────────
#
# `memory_gap` defaults to None, and None means "makes no claim about
# unexamined dump bytes" -- indistinguishable, to the aggregation, from
# "nobody classified this code". A new code would inherit it, contribute
# nothing, and keep the aggregate reading `exact`. The map below is what
# forces the decision to be made once, explicitly, per code.

_MEMORY_GAP_CLASSIFICATION = {
    # The gap's extent is whatever its own targets record as unexamined.
    # Some of these establish "none of it was examined" by their very name
    # (an oversized skip, a read that raised, a target a budget never
    # reached) and some do not (a short read, a mid-target stop) -- the
    # difference is which value the PRODUCER records, never a second rule
    # applied here. A target with no extent recorded is unquantified
    # either way.
    MemoryGapKind.TARGET_EXTENT: {
        "SCAN_REGION_OVERSIZED_SKIPPED", "SCAN_REGION_READ_FAILED",
        "PE_HEADER_READ_FAILED", "PE_HEADER_SCAN_NOT_STARTED",
        "SCAN_REGION_SHORT_READ", "SCAN_REGION_EVALUATION_TRUNCATED",
        "SCAN_BUDGET_EXHAUSTED", "CS_BEACON_SCAN_BUDGET_EXHAUSTED",
        "YARA_HIT_CAP_REACHED", "YARA_SCAN_BUDGET_EXHAUSTED",
        "PE_HEADER_SHORT_READ", "PE_HEADER_SCAN_TRUNCATED",
    },
    # Real unexamined memory with no byte extent the run can express.
    MemoryGapKind.UNMEASURED: {
        "SCAN_ITEMS_UNACCOUNTED", "SCAN_REGION_SEARCH_INCOMPLETE",
        "YARA_MATCH_FAILED", "YARA_MATCH_TIMED_OUT",
        "STOMPING_SECTION_MEMORY_READ_FAILED", "STOMPING_SHORT_READ",
        "MODULE_HEADER_READ_FAILED",
        "REPORT_STRING_SCAN_INCOMPLETE", "REPORT_STRING_SCAN_TRUNCATED",
    },
}


def test_every_limitation_code_carries_a_reviewed_gap_classification():
    from dumpex.output.coverage import _CODE_SPECS

    classified = {name: kind
                  for kind, names in _MEMORY_GAP_CLASSIFICATION.items()
                  for name in names}
    actual = {code.value: _CODE_SPECS[code].memory_gap for code in LimitationCode}

    unexpected = {name: kind.value for name, kind in actual.items()
                  if kind is not None and classified.get(name) is not kind}
    assert unexpected == {}, (
        f"code(s) classified as a memory gap that this map does not agree with: {unexpected} "
        f"-- update _MEMORY_GAP_CLASSIFICATION deliberately, not to make the test pass")

    missing = {name for name in classified if actual.get(name) is None}
    assert missing == set(), (
        f"code(s) this map classifies as a memory gap but the registry does not: {missing}")


# The other side of the same decision, written out rather than derived.
# Deriving it from the registry ("every code whose memory_gap is None")
# would make the partition a tautology: a new code inherits None, joins
# this side on its own, and every assertion below stays true. Spelled out,
# a new code belongs to neither set and the test says so.
#
# A code is here because it makes no claim about dump bytes going
# unexamined: an absent or unparseable stream, a reference file that was
# not supplied, a cap on how many RESULTS were kept from memory the search
# did cover, or bytes the dump never captured in the first place (a
# request past the capture, a header whose capture ends early) -- which
# the zero-capture rule already scores as an honest zero rather than an
# unknown. Several recon codes here sit closer to the line than that
# (ENVIRONMENT_BLOCK_TRUNCATED's byte/entry budget scopes,
# HANDLE_STREAM_TRUNCATED's descriptor cap, the IAT walk budgets): those
# are captured-but-unwalked, and quantifying them is a per-command
# decision this list is the record of NOT having made yet.
_NO_MEMORY_CLAIM = frozenset({
    "ENCODING_ALL_REGIONS_FILTERED", "ENVIRONMENT_ARCHITECTURE_UNSUPPORTED",
    "ENVIRONMENT_BLOCK_TRUNCATED", "ENVIRONMENT_BLOCK_UNPARSEABLE",
    "ENVIRONMENT_BLOCK_UNREADABLE", "ENVIRONMENT_PRECONDITION_INCONSISTENT",
    "HANDLES_ALL_DESCRIPTORS_INVALID", "HANDLES_PARSE_FAILED", "HANDLES_UNAVAILABLE",
    "HANDLE_DESCRIPTOR_INVALID", "HANDLE_STREAM_TRUNCATED",
    "HANDLE_STRING_READ_FAILED", "IAT_BOUNDS_EXCEEDED", "IAT_CYCLE_DETECTED",
    "IAT_DESCRIPTOR_READ_FAILED", "IAT_DESCRIPTOR_SHORT_READ",
    "IAT_DIRECTORY_READ_FAILED", "IAT_DIRECTORY_SHORT_READ",
    "IAT_DIRECTORY_TABLE_INCOMPLETE", "IAT_ENTRIES_TRUNCATED", "IAT_NAME_READ_FAILED",
    "IAT_THUNK_READ_FAILED", "IAT_THUNK_SHORT_READ", "IAT_UNTERMINATED_TABLE",
    "MODULE_CLASSIFICATION_UNAVAILABLE", "MODULE_HEADER_PARSE_FAILED",
    "PEB_UNAVAILABLE", "PE_HEADER_EVIDENCE_CAPPED", "PID_EXCEPTION_TID_FALLBACK",
    "PID_NO_USABLE_FALLBACK", "PID_SOURCES_ABSENT", "PID_THREAD_LIST_FALLBACK",
    "PROCESS_COMMAND_LINE_UNAVAILABLE", "PROCESS_IMAGE_BASE_INVALID",
    "PROCESS_IMAGE_BASE_UNAVAILABLE", "PROCESS_MAIN_IMAGE_PE_INVALID",
    "PROCESS_MAIN_IMAGE_READ_FAILED", "PROCESS_MAIN_IMAGE_SHORT_READ",
    "PROCESS_MISC_INFO_UNAVAILABLE", "PROCESS_MODULE_FALLBACK_UNAVAILABLE",
    "PROCESS_PATH_UNAVAILABLE", "PROCESS_PEB_UNAVAILABLE", "PROCESS_PID_UNAVAILABLE",
    "PROCESS_SOURCES_ABSENT", "PROCESS_START_TIME_INVALID", "PROCESS_START_TIME_UNSET",
    "PROFILE_ARCHITECTURE_UNAVAILABLE", "PROFILE_DIRECTORY_TRUNCATED",
    "PROFILE_DIRECTORY_UNAVAILABLE", "PROFILE_FLAGS_UNAVAILABLE",
    "PROFILE_MEMORY_CONTENT_FALLBACK", "PROFILE_STREAM_STATE_AMBIGUOUS",
    "REGION_READ_TRUNCATED", "REPORT_MODULE_CONTEXT_UNAVAILABLE", "SOURCE_ABSENT",
    "SOURCE_FAILED", "SOURCE_GROUP_ABSENT", "SOURCE_KEY_MISMATCH",
    "STOMPING_REFERENCE_MISMATCH", "STOMPING_REFERENCE_MISSING",
    "STOMPING_REFERENCE_NOT_SUPPLIED", "STOMPING_REFERENCE_READ_FAILED",
    "STOMPING_RELOCATION_FAILED", "SYSINFO_DUMP_FILE_UNREADABLE",
    "SYSINFO_MISC_INFO_UNAVAILABLE", "SYSINFO_MODULES_UNAVAILABLE",
    "SYSINFO_PEB_UNAVAILABLE", "SYSINFO_SYSTEM_INFO_UNAVAILABLE",
    "SYSINFO_THREADS_UNAVAILABLE", "TARGETED_SOURCE_NOT_APPLICABLE",
    "TARGETED_SOURCE_NOT_EVALUATED", "THREAD_CONTEXT_PARTIAL",
    "THREAD_CONTEXT_UNAVAILABLE", "YARA_MATCH_CONTEXT_UNVERIFIED",
    "YARA_RULE_COMPILE_FAILED",
})


def test_the_two_sides_of_the_classification_cover_every_code_exactly_once():
    """Every code is on one side or the other, deliberately. A code added
    without a decision is on neither, and fails here."""
    classified = {name for names in _MEMORY_GAP_CLASSIFICATION.values() for name in names}
    every_code = {code.value for code in LimitationCode}

    undecided = every_code - classified - _NO_MEMORY_CLAIM
    assert undecided == set(), (
        f"LimitationCode(s) with no reviewed missed-byte classification: {sorted(undecided)} "
        f"-- add each to _MEMORY_GAP_CLASSIFICATION (with a matching _CodeSpec.memory_gap) "
        f"or to _NO_MEMORY_CLAIM, whichever the code actually is")

    stale = (classified | _NO_MEMORY_CLAIM) - every_code
    assert stale == set(), f"classified name(s) that are not LimitationCodes: {sorted(stale)}"
    assert not (classified & _NO_MEMORY_CLAIM)


def test_the_no_claim_side_matches_what_the_registry_actually_does():
    """The list above is a claim about the registry, so it is checked
    against it -- a code quietly reclassified in `_CODE_SPECS` shows up
    here rather than silently changing what every partial reports."""
    from dumpex.output.coverage import _CODE_SPECS

    registry_says = {code.value for code in LimitationCode
                     if _CODE_SPECS[code].memory_gap is None}
    assert registry_says == _NO_MEMORY_CLAIM


# ── the two aggregations that must not silently mis-measure ─────────────

def test_merging_reports_across_evidence_files_refuses_addressed_gaps():
    """`combine_coverage_reports` merges reports that can come from two
    different dumps. Unioning their virtual addresses as one space would
    merge the same VA skipped in both into a single range and report half
    the miss -- the direction this metric must never be wrong in."""
    from dumpex.output.coverage import CoverageReport, combine_coverage_reports

    gapped = CoverageReport(
        status="partial",
        limitations=[_limitation(LimitationCode.SCAN_REGION_READ_FAILED,
                                  [_target(size=4096, captured=4096, examined=0)])])
    with pytest.raises(ValueError, match="different evidence files"):
        combine_coverage_reports([gapped, CoverageReport(status="complete")])


def test_merging_reports_still_accepts_a_gap_that_names_no_address():
    """A count-only memory gap has no VA to mis-merge, so the same-dump
    combine `--report` relies on keeps working."""
    from dumpex.output.coverage import CoverageReport, combine_coverage_reports

    counted = CoverageReport(
        status="partial",
        limitations=[CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED,
                                         source="string_search", affected_count=2)])
    merged = combine_coverage_reports([counted, CoverageReport(status="complete")])
    assert merged.missed_bytes.unquantified_gaps == 2


def test_combining_rollups_instead_of_the_reports_that_own_the_gaps_is_refused():
    """A rollup has no limitations to read, so it would contribute zero
    and silently erase whatever it stands for."""
    from dumpex.output.coverage import CoverageReport, combine_missed_bytes

    rollup = CoverageReport(status="partial",
                             missed_bytes_rollup=MissedBytes(known_bytes=4096,
                                                              quantified_gaps=1,
                                                              distinct_ranges=1))
    with pytest.raises(ValueError, match="carrying a rollup"):
        combine_missed_bytes([rollup])


# ── the aggregate and the wire are one number ───────────────────────────

def test_every_contributing_target_publishes_the_extent_the_total_counted():
    """The core promise: a consumer that sums `unexamined_size` across a
    limitation's targets must land on the same figure the aggregate
    reports for it. A code-level shortcut that inferred an extent the
    target itself does not publish is exactly how those two drift."""
    limitation = _limitation(
        LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
        [_target(size=4096, captured=4096, examined=0, limit=2048, base=_BASE),
         _target(size=8192, captured=8192, examined=0, limit=2048, base=_BASE + 0x10000)])
    missed = summarize_missed_bytes([limitation])
    assert missed.known_bytes == sum(t.to_dict()["unexamined_size"]
                                      for t in limitation.targets)


# One legal construction per target-bearing memory-gap code: the `source`
# each one pins (or an open one), whether its targets carry the cap they
# exceeded, and any field its own validator requires.
_TARGET_BEARING_SHAPES = {
    "SCAN_REGION_OVERSIZED_SKIPPED":   ("pipe_name_scan", True, {}),
    "SCAN_REGION_READ_FAILED":         ("pipe_name_scan", False, {}),
    "SCAN_REGION_SHORT_READ":          ("pipe_name_scan", False, {}),
    "SCAN_REGION_EVALUATION_TRUNCATED": ("pipe_name_scan", False, {}),
    "SCAN_BUDGET_EXHAUSTED":           ("pipe_name_scan", False, {"detail": "deadline"}),
    "CS_BEACON_SCAN_BUDGET_EXHAUSTED": ("segment_scan", False,
                                         {"detail": "1 candidate(s) examined"}),
    "YARA_HIT_CAP_REACHED":            ("segment_scan", False, {}),
    "YARA_SCAN_BUDGET_EXHAUSTED":      ("segment_scan", False, {}),
    "PE_HEADER_READ_FAILED":           ("hidden_pe_scan", False, {}),
    "PE_HEADER_SHORT_READ":            ("hidden_pe_scan", False, {}),
    "PE_HEADER_SCAN_TRUNCATED":        ("hidden_pe_scan", False, {}),
    "PE_HEADER_SCAN_NOT_STARTED":      ("hidden_pe_scan", False, {}),
}


def test_the_shape_table_covers_every_target_bearing_code():
    assert (set(_TARGET_BEARING_SHAPES)
            == _MEMORY_GAP_CLASSIFICATION[MemoryGapKind.TARGET_EXTENT])


@pytest.mark.parametrize("code", sorted(_TARGET_BEARING_SHAPES))
def test_an_exact_total_never_stands_beside_a_target_with_no_extent(code):
    """The inconsistency this invariant exists to forbid: an aggregate
    claiming `exact` while the target it counted publishes
    `unexamined_size: null`. Checked for every target-bearing code,
    because the old per-code shortcut applied to only some of them and
    that is precisely where the two drifted apart."""
    source, needs_limit, extra = _TARGET_BEARING_SHAPES[code]
    target = _target(size=4096, captured=4096, limit=2048 if needs_limit else None)
    limitation = _limitation(LimitationCode(code), [target], source=source, **extra)

    assert limitation.targets[0].to_dict()["unexamined_size"] is None
    assert summarize_missed_bytes([limitation]).state is MissedBytesState.UNKNOWN


@pytest.mark.parametrize("code", sorted(_TARGET_BEARING_SHAPES))
def test_a_recorded_extent_reaches_the_total_and_the_wire_as_one_number(code):
    source, needs_limit, extra = _TARGET_BEARING_SHAPES[code]
    target = _target(size=4096, captured=4096, examined=1024,
                      limit=2048 if needs_limit else None)
    limitation = _limitation(LimitationCode(code), [target], source=source, **extra)

    missed = summarize_missed_bytes([limitation])
    assert missed.state is MissedBytesState.EXACT
    assert missed.known_bytes == limitation.targets[0].to_dict()["unexamined_size"] == 3072


def test_the_hidden_pe_scans_whole_region_gaps_record_their_extent():
    """Injection builds these targets by hand rather than through the
    tracker, so nothing else would make them measurable."""
    from dumpex.hunt.injection.memory_scan import region_scan_target as build

    mf = _mf(size=8192)
    assert build(mf, mf.memory_info.infos[0], examined_size=0).unexamined_bytes == 8192


# ── the targeted rescan's own residual targets ──────────────────────────
#
# A `--hunt-addr` rescan exists to give an exact answer about one range, so
# `missed_bytes` is the whole of its quantified output. Every residual
# target it builds is by construction the part no byte of which was looked
# at, and each records that -- otherwise the exact figure sits in scope,
# already computed, while the document reports "unmeasured".

def _read_slice(*, requested_size, read_bytes, base=_BASE, captured=None):
    from dumpex.core.va_range import CapturedSegment, VirtualRange, slice_captured

    captured = requested_size if captured is None else captured
    requested = VirtualRange(base, requested_size)
    segment = CapturedSegment(range=VirtualRange(base, captured), file_offset=0x1000)
    return slice_captured(requested, (segment,)).read_input(read_bytes)


def test_the_unread_suffix_of_a_targeted_range_records_that_none_of_it_was_read():
    from dumpex.hunt._targeted import unexamined_suffix_target

    target = unexamined_suffix_target(_read_slice(requested_size=8192, read_bytes=2048))
    assert target.examined_size == 0
    assert target.unexamined_bytes == 6144


def _segment_boundary():
    """CS Beacon's and YARA's descriptor: a captured segment."""
    from dumpex.core.va_range import CapturedSegment, VirtualRange
    from dumpex.hunt._targeted import resolve_segment_boundary

    segment = CapturedSegment(range=VirtualRange(_BASE, 4096), file_offset=0x1000)
    return resolve_segment_boundary(VirtualRange(_BASE, 12288), segment,
                                     captured_bytes=12288)


def _region_boundary():
    """Obfuscation's, pipe's and stomping's: a MemoryInfo region."""
    from dumpex.core.va_range import CapturedRegion, VirtualRange
    from dumpex.hunt._targeted import resolve_region_boundary

    mf = _mf(size=12288)
    region = CapturedRegion(range=VirtualRange(_BASE, 4096), allocation_base=_BASE,
                            state="MEM_COMMIT", type="MEM_PRIVATE",
                            protection="PAGE_READWRITE")
    return resolve_region_boundary(mf, VirtualRange(_BASE, 12288), region)


@pytest.mark.parametrize("build", [_segment_boundary, _region_boundary],
                          ids=["segment", "region"])
def test_a_targeted_evaluation_cut_at_a_descriptor_boundary_is_measured(build):
    """The evaluated part is the request clipped to its descriptor, so the
    gap past the boundary is exact without consulting the scan.

    Both descriptor kinds, because five adapters split across the two and
    this function reads only the fields they share."""
    from dumpex.hunt._targeted import evaluation_truncated_limitation

    boundary = build()
    assert boundary.truncated

    limitation = evaluation_truncated_limitation("targeted_scan", None, boundary)
    missed = summarize_missed_bytes([limitation])
    assert missed.state is MissedBytesState.EXACT
    assert missed.known_bytes == 12288 - 4096
    assert limitation.targets[0].to_dict()["unexamined_size"] == missed.known_bytes


def test_a_targeted_budget_residual_after_a_stop_cursor_is_measured():
    from dumpex.hunt.cs_beacon.targeted import _budget_residual_targets

    class _Diag:
        budget_stop_offset = 1024

    read_slice = _read_slice(requested_size=8192, read_bytes=8192)
    targets = _budget_residual_targets(_Diag(), read_slice, None, None)
    assert [t.examined_size for t in targets] == [0]
    assert [t.unexamined_bytes for t in targets] == [8192 - 1024]


def test_a_region_neither_pipe_budget_could_start_on_is_measured():
    """Recorded before any read is issued, so it is the same "budget spent
    before the target started" case injection's own not-started gap is --
    and reports the same exact whole capture."""
    mf = _mf(size=8192)
    assert region_scan_target(mf, mf.memory_info.infos[0],
                               examined_size=0).unexamined_bytes == 8192
