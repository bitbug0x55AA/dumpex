"""Unit tests for dumpex.core.va_range's neutral range and capture primitives."""
import pytest

from dumpex.core.va_range import (
    RangeError, VirtualRange, CaptureState, CapturedRegion, CapturedSegment,
    CapturedSlice, ReadSlice, CapturedEnumeration, slice_captured, capture_of,
    captured_segments, captured_regions, enumerate_captured_segments,
    enumerate_captured_regions, region_containing, segment_containing,
)
from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment


_ADDRESS_SPACE = 1 << 64


# ── VirtualRange construction ────────────────────────────────────────────

def test_virtual_range_reports_half_open_bounds():
    r = VirtualRange(0x1000, 0x400)
    assert r.base_address == 0x1000
    assert r.size == 0x400
    assert r.end_address == 0x1400
    assert r.contains_address(0x1000)
    assert r.contains_address(0x13ff)
    assert not r.contains_address(0x1400)


def test_virtual_range_accepts_a_32_bit_address():
    r = VirtualRange(0x00400000, 0x2000)
    assert r.end_address == 0x00402000


def test_virtual_range_end_may_sit_exactly_at_the_top_of_the_address_space():
    r = VirtualRange(_ADDRESS_SPACE - 0x1000, 0x1000)
    assert r.end_address == _ADDRESS_SPACE


def test_virtual_range_rejects_non_positive_size():
    with pytest.raises(RangeError):
        VirtualRange(0x1000, 0)
    with pytest.raises(RangeError):
        VirtualRange(0x1000, -1)


def test_virtual_range_rejects_negative_base():
    with pytest.raises(RangeError):
        VirtualRange(-1, 0x1000)


def test_virtual_range_rejects_base_at_or_past_the_address_space():
    with pytest.raises(RangeError):
        VirtualRange(_ADDRESS_SPACE, 0x1000)


def test_virtual_range_rejects_end_past_the_address_space():
    with pytest.raises(RangeError):
        VirtualRange(_ADDRESS_SPACE - 0x100, 0x200)


def test_virtual_range_rejects_bool_bounds():
    # bool is an int subclass; a stray True/False must not silently become 1/0.
    with pytest.raises(RangeError):
        VirtualRange(True, 0x1000)
    with pytest.raises(RangeError):
        VirtualRange(0x1000, True)


def test_virtual_range_from_endpoints_round_trips():
    r = VirtualRange.from_endpoints(0x1000, 0x1400)
    assert r == VirtualRange(0x1000, 0x400)


def test_virtual_range_from_endpoints_allows_top_of_space_end():
    r = VirtualRange.from_endpoints(_ADDRESS_SPACE - 0x1000, _ADDRESS_SPACE)
    assert r.size == 0x1000


def test_virtual_range_from_endpoints_rejects_empty_or_inverted():
    with pytest.raises(RangeError):
        VirtualRange.from_endpoints(0x1000, 0x1000)
    with pytest.raises(RangeError):
        VirtualRange.from_endpoints(0x1400, 0x1000)


def test_virtual_range_from_endpoints_rejects_an_end_past_the_address_space():
    with pytest.raises(RangeError):
        VirtualRange.from_endpoints(0x1000, _ADDRESS_SPACE + 0x1000)


# ── VirtualRange relations ───────────────────────────────────────────────

def test_contains_range_is_inclusive_of_coincident_bounds():
    outer = VirtualRange(0x1000, 0x1000)
    assert outer.contains_range(VirtualRange(0x1000, 0x1000))
    assert outer.contains_range(VirtualRange(0x1400, 0x400))
    assert not outer.contains_range(VirtualRange(0x1c00, 0x800))
    assert not outer.contains_range(VirtualRange(0x0c00, 0x800))


def test_overlaps_excludes_endpoint_touch():
    a = VirtualRange(0x1000, 0x400)
    assert a.overlaps(VirtualRange(0x1200, 0x400))
    assert not a.overlaps(VirtualRange(0x1400, 0x400))


def test_intersection_returns_the_overlap_or_none():
    a = VirtualRange(0x1000, 0x800)
    assert a.intersection(VirtualRange(0x1400, 0x800)) == VirtualRange(0x1400, 0x400)
    assert a.intersection(VirtualRange(0x1800, 0x400)) is None


def test_clip_to_is_intersection_under_the_boundary_name():
    r = VirtualRange(0x1000, 0x2000)
    assert r.clip_to(VirtualRange(0x1800, 0x400)) == VirtualRange(0x1800, 0x400)
    assert r.clip_to(VirtualRange(0x9000, 0x400)) is None


def test_suffix_after_names_the_unexamined_tail():
    r = VirtualRange(0x1000, 0x1000)
    assert r.suffix_after(0) == r
    assert r.suffix_after(0x400) == VirtualRange(0x1400, 0xc00)
    assert r.suffix_after(0x1000) is None


def test_suffix_after_rejects_a_prefix_outside_the_range():
    r = VirtualRange(0x1000, 0x1000)
    with pytest.raises(RangeError):
        r.suffix_after(-1)
    with pytest.raises(RangeError):
        r.suffix_after(0x1001)


def test_virtual_ranges_sort_deterministically_by_base_then_size():
    unsorted = [
        VirtualRange(0x2000, 0x100),
        VirtualRange(0x1000, 0x400),
        VirtualRange(0x1000, 0x100),
    ]
    assert sorted(unsorted) == [
        VirtualRange(0x1000, 0x100),
        VirtualRange(0x1000, 0x400),
        VirtualRange(0x2000, 0x100),
    ]


# ── CapturedRegion ───────────────────────────────────────────────────────

def test_captured_region_inherits_metadata_without_touching_the_parser_object():
    region = Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                    "MEM_PRIVATE")
    view = CapturedRegion.from_memory_info(region)

    assert view.range == VirtualRange(0x1000, 0x2000)
    assert (view.base_address, view.size, view.end_address) == (0x1000, 0x2000, 0x3000)
    assert view.allocation_base == 0x1000
    assert view.state == "MEM_COMMIT"
    assert view.type == "MEM_PRIVATE"
    assert view.protection == "PAGE_EXECUTE_READWRITE"

    # The raw object is not mutated and not retained anywhere on the view.
    assert region.BaseAddress == 0x1000 and region.RegionSize == 0x2000
    assert region not in vars(view).values()


def test_captured_region_tolerates_a_missing_allocation_base():
    class Bare:
        BaseAddress = 0x1000
        RegionSize = 0x1000
        State = None
        Type = None
        Protect = None

    view = CapturedRegion.from_memory_info(Bare())
    assert view.allocation_base is None
    assert view.state is None and view.type is None and view.protection is None


def test_captured_region_clip_keeps_allocation_wide_metadata():
    region = Region(0x1000, 0x1000, 0x4000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
    view = CapturedRegion.from_memory_info(region)

    clipped = view.clip_to(VirtualRange(0x2000, 0x1000))
    assert clipped.range == VirtualRange(0x2000, 0x1000)
    assert clipped.allocation_base == 0x1000
    assert clipped.state == "MEM_COMMIT"
    assert clipped.type == "MEM_PRIVATE"
    assert clipped.protection == "PAGE_READWRITE"

    assert view.clip_to(VirtualRange(0x9000, 0x1000)) is None


# ── CapturedSegment ──────────────────────────────────────────────────────

def test_captured_segment_from_segment_reads_the_library_shape():
    seg = CapturedSegment.from_segment(Segment(0x1000, 0x5000, 0x800))
    assert seg.range == VirtualRange(0x1000, 0x800)
    assert (seg.base_address, seg.size, seg.end_address) == (0x1000, 0x800, 0x1800)
    assert seg.file_offset == 0x5000


def test_captured_segment_file_offset_at_translates_within_the_segment():
    seg = CapturedSegment(VirtualRange(0x1000, 0x800), file_offset=0x5000)
    assert seg.file_offset_at(0x1000) == 0x5000
    assert seg.file_offset_at(0x1400) == 0x5400
    with pytest.raises(RangeError):
        seg.file_offset_at(0x1800)


def test_captured_segment_clip_adjusts_the_file_offset():
    seg = CapturedSegment(VirtualRange(0x1000, 0x1000), file_offset=0x5000)

    clipped = seg.clip_to(VirtualRange(0x1400, 0x400))
    assert clipped.range == VirtualRange(0x1400, 0x400)
    assert clipped.file_offset == 0x5400

    assert seg.clip_to(VirtualRange(0x9000, 0x400)) is None


def test_captured_segment_rejects_a_negative_file_offset():
    with pytest.raises(RangeError):
        CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=-1)


def test_captured_segment_from_segment_falls_back_to_end_virtual_address():
    class NoSizeSegment:
        start_virtual_address = 0x1000
        end_virtual_address = 0x1800
        start_file_address = 0x5000

    seg = CapturedSegment.from_segment(NoSizeSegment())
    assert seg.range == VirtualRange(0x1000, 0x800)
    assert seg.file_offset == 0x5000


def test_captured_segment_from_segment_fallback_accepts_an_end_at_the_top_of_the_space():
    # end_virtual_address is a half-open endpoint, not an address, so
    # exactly 1 << 64 is legal -- the same bound VirtualRange.from_endpoints
    # accepts. The size-less fallback path must not reject it.
    class TopSegment:
        start_virtual_address = _ADDRESS_SPACE - 0x1000
        end_virtual_address = _ADDRESS_SPACE
        start_file_address = 0x5000

    seg = CapturedSegment.from_segment(TopSegment())
    assert seg.range == VirtualRange(_ADDRESS_SPACE - 0x1000, 0x1000)
    assert seg.end_address == _ADDRESS_SPACE


def test_from_segment_propagates_shape_drift_rather_than_masking_it():
    # An object with no `size` AND no `end_virtual_address` is not a
    # malformed descriptor -- it is the wrong object shape. Both the strict
    # and the try_ path let that surface instead of silently vanishing.
    class Broken:
        start_virtual_address = 0x1000
        start_file_address = 0x5000

    with pytest.raises(AttributeError):
        CapturedSegment.from_segment(Broken())
    with pytest.raises(AttributeError):
        CapturedSegment.try_from_segment(Broken())


def test_from_memory_info_propagates_a_missing_field_rather_than_masking_it():
    class NoBase:
        RegionSize = 0x1000

    with pytest.raises(AttributeError):
        CapturedRegion.from_memory_info(NoBase())
    with pytest.raises(AttributeError):
        CapturedRegion.try_from_memory_info(NoBase())


# ── slice_captured: the four distinct capture outcomes ───────────────────

def _segs(*triples):
    return [CapturedSegment(VirtualRange(base, size), file_offset=fo)
            for base, fo, size in triples]


def test_slice_captured_none_when_the_base_is_not_covered():
    result = slice_captured(VirtualRange(0x1000, 0x1000), _segs((0x2000, 0x2000, 0x1000)))
    assert result.state is CaptureState.NONE
    assert result.captured is None
    assert result.captured_bytes == 0
    assert result.file_offset is None
    assert result.uncaptured_suffix == VirtualRange(0x1000, 0x1000)
    assert result.segments == ()


def test_slice_captured_complete_from_one_segment():
    result = slice_captured(VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x2000)))
    assert result.state is CaptureState.COMPLETE
    assert result.captured == VirtualRange(0x1000, 0x1000)
    assert result.captured_bytes == 0x1000
    assert result.file_offset == 0x9000
    assert result.uncaptured_suffix is None
    assert result.segments == (CapturedSegment(VirtualRange(0x1000, 0x1000), file_offset=0x9000),)


def test_slice_captured_complete_across_contiguous_segments_keeps_adjusted_offsets():
    result = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1000, 0x9000, 0x800), (0x1800, 0xf000, 0x800)),
    )
    assert result.state is CaptureState.COMPLETE
    assert result.file_offset == 0x9000
    assert result.segments == (
        CapturedSegment(VirtualRange(0x1000, 0x800), file_offset=0x9000),
        CapturedSegment(VirtualRange(0x1800, 0x800), file_offset=0xf000),
    )


def test_slice_captured_partial_when_capture_stops_partway():
    result = slice_captured(VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x600)))
    assert result.state is CaptureState.PARTIAL
    assert result.captured == VirtualRange(0x1000, 0x600)
    assert result.captured_bytes == 0x600
    assert result.file_offset == 0x9000
    assert result.uncaptured_suffix == VirtualRange(0x1600, 0xa00)


def test_slice_captured_stops_at_a_gap_and_ignores_a_tail_only_segment():
    result = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1000, 0x9000, 0x400), (0x1800, 0xf000, 0x800)),
    )
    assert result.state is CaptureState.PARTIAL
    assert result.captured == VirtualRange(0x1000, 0x400)
    assert result.uncaptured_suffix == VirtualRange(0x1400, 0xc00)
    assert result.segments == (
        CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000),
    )


def test_slice_captured_is_boundary_exact_at_the_requested_end():
    result = slice_captured(VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x1000)))
    assert result.state is CaptureState.COMPLETE
    assert result.segments == (
        CapturedSegment(VirtualRange(0x1000, 0x1000), file_offset=0x9000),
    )


def test_slice_captured_clips_an_oversized_segment_to_the_request():
    result = slice_captured(VirtualRange(0x1200, 0x400), _segs((0x1000, 0x9000, 0x4000)))
    assert result.state is CaptureState.COMPLETE
    assert result.file_offset == 0x9200
    assert result.segments == (
        CapturedSegment(VirtualRange(0x1200, 0x400), file_offset=0x9200),
    )


def test_slice_captured_reads_an_unsorted_table_in_address_order():
    ordered = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1000, 0x9000, 0x800), (0x1800, 0xf000, 0x800)),
    )
    shuffled = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1800, 0xf000, 0x800), (0x1000, 0x9000, 0x800)),
    )
    assert shuffled == ordered
    assert shuffled.state is CaptureState.COMPLETE
    assert shuffled.overlapping is False


def test_slice_captured_clean_adjacent_segments_are_not_flagged_overlapping():
    result = slice_captured(
        VirtualRange(0x1000, 0x1800),
        _segs((0x1000, 0x9000, 0x800), (0x1800, 0xf000, 0x800), (0x2000, 0x3000, 0x800)),
    )
    assert result.state is CaptureState.COMPLETE
    assert result.overlapping is False


def test_slice_captured_a_segment_ending_before_the_request_is_not_an_overlap():
    result = slice_captured(
        VirtualRange(0x1000, 0x800),
        _segs((0x0400, 0x1000, 0x400),    # [0x0400, 0x0800) -- wholly before the request
              (0x1000, 0x9000, 0x800)),
    )
    assert result.state is CaptureState.COMPLETE
    assert result.file_offset == 0x9000
    assert result.overlapping is False


def test_slice_captured_starts_mid_segment_and_offsets_from_the_cursor():
    result = slice_captured(
        VirtualRange(0x4000, 0x800),
        _segs((0x1000, 0x1000, 0x5000), (0x2000, 0x9000, 0x100), (0x3000, 0x9100, 0x100)),
    )
    assert result.state is CaptureState.COMPLETE
    # File offset of the requested base, which sits 0x3000 into the first
    # (address-sorted) segment.
    assert result.file_offset == 0x1000 + 0x3000
    assert result.segments == (
        CapturedSegment(VirtualRange(0x4000, 0x800), file_offset=0x1000 + 0x3000),
    )
    # The other two entries are nested inside the first but nowhere near
    # the request, so this slice's provenance is unambiguous.
    assert result.overlapping is False


def test_slice_captured_flags_nested_overlap_after_request_is_already_complete():
    # Segment A alone covers the whole request, so the walk breaks before
    # ever visiting B -- but A and B still place [0x1100, 0x1200) in two
    # different .dmp locations. Detection is by length, not by the walk.
    result = slice_captured(
        VirtualRange(0x1000, 0x800),
        _segs((0x1000, 0xa000, 0x1000),   # [0x1000, 0x2000)
              (0x1100, 0xb000, 0x100)),   # [0x1100, 0x1200) -- never walked
    )
    assert result.state is CaptureState.COMPLETE
    assert result.file_offset == 0xa000
    assert result.overlapping is True


def test_slice_captured_flags_overlap_within_a_partial_capture():
    result = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1000, 0xa000, 0x400),    # [0x1000, 0x1400)
              (0x1200, 0xb000, 0x100)),   # [0x1200, 0x1300) -- inside A, no run past 0x1400
    )
    assert result.state is CaptureState.PARTIAL
    assert result.captured == VirtualRange(0x1000, 0x400)
    assert result.overlapping is True


def test_slice_captured_ignores_an_overlap_entirely_outside_the_captured_prefix():
    # A short prefix is captured; the contradictory pair sits past the gap.
    result = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1000, 0xa000, 0x200),    # [0x1000, 0x1200) -- the only captured run
              (0x1800, 0xb000, 0x400),    # [0x1800, 0x1c00)
              (0x1900, 0xc000, 0x100)),   # [0x1900, 0x1a00) -- overlaps the above, but past the gap
    )
    assert result.state is CaptureState.PARTIAL
    assert result.captured == VirtualRange(0x1000, 0x200)
    assert result.overlapping is False


def test_slice_captured_flags_a_contradictory_nested_segment_table():
    # The short middle entry [0x1100, 0x1200) sits inside [0x1000, 0x1400)
    # at a different file offset -- the table places one VA in two file
    # locations. The run still advances deterministically past it (the
    # nested entry is skipped, its bytes taken from the first covering
    # entry), and `overlapping` records that the provenance is unreliable.
    result = slice_captured(
        VirtualRange(0x1000, 0x1000),
        _segs((0x1000, 0xa000, 0x400),   # [0x1000, 0x1400)
              (0x1100, 0xb000, 0x100),   # [0x1100, 0x1200)  -- contradictory
              (0x1200, 0xc000, 0xe00)),  # [0x1200, 0x2000)
    )
    assert result.state is CaptureState.COMPLETE
    assert result.captured_bytes == 0x1000
    assert result.overlapping is True
    assert result.segments == (
        CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0xa000),
        CapturedSegment(VirtualRange(0x1400, 0xc00), file_offset=0xc000 + 0x200),
    )


_OVERLAP = (
    (0x1000, 0xa000, 0x400),    # [0x1000, 0x1400) @ 0xa000  -- shorter end
    (0x1000, 0xb000, 0x1000),   # [0x1000, 0x2000) @ 0xb000
)
_OVERLAP_EXPECTED = (
    CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0xa000),
    CapturedSegment(VirtualRange(0x1400, 0xc00), file_offset=0xb000 + 0x400),
)


def test_slice_captured_overlap_tie_break_is_ascending_base_then_end():
    # A malformed table with two entries over the same VA at different file
    # offsets. The (base, end)-order-first entry (shorter end) supplies the
    # offset for the shared prefix; the run then advances monotonically,
    # and the contradiction is flagged.
    result = slice_captured(VirtualRange(0x1000, 0x1000), _segs(*_OVERLAP))
    assert result.state is CaptureState.COMPLETE
    assert result.overlapping is True
    assert result.segments == _OVERLAP_EXPECTED


def test_slice_captured_overlap_result_is_independent_of_caller_order():
    forward = slice_captured(VirtualRange(0x1000, 0x1000), _segs(*_OVERLAP))
    reversed_ = slice_captured(VirtualRange(0x1000, 0x1000), _segs(*_OVERLAP[::-1]))
    assert forward == reversed_
    assert forward.overlapping is True
    assert forward.segments == _OVERLAP_EXPECTED


def test_slice_captured_flags_overlap_when_offset_diverges_from_va_to_file_offset():
    # On a malformed overlapping table capture_of() and va_to_file_offset()
    # can resolve the same VA to different .dmp offsets. That divergence is
    # never silent -- the slice carries overlapping=True. Real tables never
    # overlap, so the two always agree in practice.
    from dumpex.core.memory import va_to_file_offset

    raw = [Segment(0x1000, 0xb000, 0x1000), Segment(0x1000, 0xa000, 0x400)]
    mf = _mf_with_segments(raw)
    sliced = capture_of(mf, VirtualRange(0x1000, 0x1000))

    assert va_to_file_offset(mf, 0x1000) == 0xb000   # raw-table-order first
    assert sliced.file_offset == 0xa000              # (base, end)-order first
    assert sliced.overlapping is True                # ... and the conflict is flagged


def test_slice_captured_empty_table_leaves_the_whole_request_uncaptured():
    result = slice_captured(VirtualRange(0x1000, 0x1000), [])
    assert result.state is CaptureState.NONE
    assert result.uncaptured_suffix == VirtualRange(0x1000, 0x1000)


def test_slice_captured_matches_va_range_captured_bytes_on_gapped_and_unsorted_tables():
    from dumpex.core.memory import va_range_captured_bytes

    cases = [
        [Segment(0x1000, 0x9000, 0x800), Segment(0x1800, 0xf000, 0x400)],   # short prefix
        [Segment(0x1800, 0xf000, 0x800), Segment(0x1000, 0x9000, 0x800)],   # unsorted, contiguous
        [Segment(0x1000, 0x9000, 0x400), Segment(0x1800, 0xf000, 0x800)],   # gap at 0x1400
    ]
    for segs in cases:
        mf = _mf_with_segments(segs)
        got = slice_captured(VirtualRange(0x1000, 0x1000),
                             [CapturedSegment.from_segment(s) for s in segs])
        assert got.captured_bytes == va_range_captured_bytes(mf, 0x1000, 0x1000)


def test_capture_state_values_match_the_coverage_wire_strings():
    assert CaptureState.NONE == "none"
    assert CaptureState.PARTIAL == "partial"
    assert CaptureState.COMPLETE == "complete"


# ── CapturedSlice normalization: no inconsistent value can be built ──────

def _complete_slice():
    return slice_captured(VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x1000)))


def test_captured_slice_coerces_a_mutable_segment_list_to_a_tuple():
    result = CapturedSlice(
        requested=VirtualRange(0x1000, 0x400),
        captured=VirtualRange(0x1000, 0x400),
        uncaptured_suffix=None,
        file_offset=0x9000,
        segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
    )
    assert isinstance(result.segments, tuple)
    assert result.overlapping is False   # defaults off


def test_captured_slice_rejects_a_non_bool_overlapping():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
            overlapping=1,
        )


def test_a_clean_slice_is_never_flagged_overlapping():
    assert _complete_slice().overlapping is False
    assert capture_of(_mf_with_segments([Segment(0x1000, 0x9000, 0x1000)]),
                      VirtualRange(0x1000, 0x1000)).overlapping is False


def test_captured_slice_rejects_a_captured_range_disjoint_from_the_request():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x100),
            captured=VirtualRange(0x2000, 0x100),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[CapturedSegment(VirtualRange(0x2000, 0x100), file_offset=0x9000)],
        )


def test_captured_slice_rejects_a_captured_range_larger_than_the_request():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x100),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
        )


def test_captured_slice_rejects_a_wrong_uncaptured_suffix():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x1000),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=VirtualRange(0x1400, 0x800),   # should be 0xc00
            file_offset=0x9000,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
        )


def test_captured_slice_rejects_captured_without_a_file_offset():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=None,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
        )


def test_captured_slice_rejects_nothing_captured_but_segments_present():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=None,
            uncaptured_suffix=VirtualRange(0x1000, 0x400),
            file_offset=None,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
        )


def test_captured_slice_rejects_segments_that_do_not_tile_the_prefix():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x1000),
            captured=VirtualRange(0x1000, 0x1000),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[
                CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000),
                CapturedSegment(VirtualRange(0x1800, 0x800), file_offset=0xf000),
            ],
        )


def test_captured_slice_rejects_a_first_segment_offset_that_disagrees():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x1234)],
        )


def test_captured_slice_rejects_nothing_captured_but_a_file_offset_present():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=None,
            uncaptured_suffix=VirtualRange(0x1000, 0x400),
            file_offset=0x9000,
            segments=(),
        )


def test_captured_slice_rejects_nothing_captured_with_a_wrong_uncaptured_suffix():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=None,
            uncaptured_suffix=VirtualRange(0x1000, 0x100),   # must be the whole request
            file_offset=None,
            segments=(),
        )


def test_captured_slice_rejects_a_negative_file_offset_when_captured():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=-1,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0)],
        )


def test_captured_slice_rejects_an_empty_segments_tuple_when_captured():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=(),
        )


def test_captured_slice_rejects_a_non_captured_segment_element():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x400),
            captured=VirtualRange(0x1000, 0x400),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[VirtualRange(0x1000, 0x400)],   # a range, not a CapturedSegment
        )


def test_captured_slice_rejects_segments_that_stop_short_of_the_captured_end():
    with pytest.raises(RangeError):
        CapturedSlice(
            requested=VirtualRange(0x1000, 0x1000),
            captured=VirtualRange(0x1000, 0x1000),
            uncaptured_suffix=None,
            file_offset=0x9000,
            segments=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0x9000)],
        )


def test_frozen_slice_cannot_be_mutated_through_its_segment_tuple():
    result = _complete_slice()
    with pytest.raises((AttributeError, TypeError)):
        result.segments.append(
            CapturedSegment(VirtualRange(0x2000, 0x100), file_offset=0x0))


# ── read_input / ReadSlice: contiguous read is a distinct layer ─────────

def test_read_input_full_read_leaves_no_unread_suffix():
    rs = _complete_slice().read_input(0x1000)
    assert rs.read == VirtualRange(0x1000, 0x1000)
    assert rs.unread_suffix is None
    assert rs.is_short is False
    assert rs.is_io_short is False


def test_read_input_zero_read_leaves_the_whole_request_unread():
    rs = _complete_slice().read_input(0)
    assert rs.read is None
    assert rs.unread_suffix == VirtualRange(0x1000, 0x1000)


def test_read_input_cannot_exceed_the_captured_prefix():
    partial = slice_captured(VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x400)))
    assert partial.captured_bytes == 0x400
    partial.read_input(0x400)
    with pytest.raises(RangeError):
        partial.read_input(0x401)
    with pytest.raises(RangeError):
        partial.read_input(-1)


def test_partial_read_is_short_against_the_request_whatever_the_cause():
    # Every partial read of a 0x1000 request is is_short, whether 0x400 is
    # all the dump held or an I/O failure cut a fully-captured range off.
    io_cut = _complete_slice().read_input(0x400)
    assert io_cut.capture.state is CaptureState.COMPLETE
    assert io_cut.is_short is True
    assert io_cut.unread_suffix == VirtualRange(0x1400, 0xc00)

    partial_capture = slice_captured(
        VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x400))
    ).read_input(0x400)
    assert partial_capture.capture.state is CaptureState.PARTIAL
    assert partial_capture.is_short is True
    assert partial_capture.unread_suffix == VirtualRange(0x1400, 0xc00)


def test_io_short_separates_a_cut_read_from_a_structural_gap():
    # is_io_short fires only when the read came back shorter than the dump
    # actually holds -- not for a full read of a short capture.
    io_cut = _complete_slice().read_input(0x400)
    assert io_cut.is_io_short is True
    assert io_cut.capture.uncaptured_suffix is None

    partial_capture = slice_captured(
        VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x400))
    ).read_input(0x400)
    assert partial_capture.is_io_short is False
    assert partial_capture.capture.uncaptured_suffix == VirtualRange(0x1400, 0xc00)


def test_read_slices_for_cut_read_and_structural_gap_are_distinguishable():
    # Same requested range, same read_bytes, same unread_suffix, and now
    # the same is_short -- but the stored value still tells the two
    # evidence states apart via is_io_short / the retained CapturedSlice.
    cut_read = _complete_slice().read_input(0x400)
    structural_gap = slice_captured(
        VirtualRange(0x1000, 0x1000), _segs((0x1000, 0x9000, 0x400))
    ).read_input(0x400)
    assert cut_read.read == structural_gap.read
    assert cut_read.unread_suffix == structural_gap.unread_suffix
    assert cut_read.is_short == structural_gap.is_short is True
    assert cut_read != structural_gap
    assert (cut_read.is_io_short, cut_read.capture.uncaptured_suffix) != \
           (structural_gap.is_io_short, structural_gap.capture.uncaptured_suffix)


def test_read_slice_models_neither_algorithm_reach_nor_completion():
    # A consumer that read every byte but whose analyzer then timed out
    # still passes the full read count -- this layer is about bytes read,
    # not about how far a candidate/window/deadline-bounded scan examined.
    # No attribute may imply algorithm completion or a byte-precise
    # "examined through here" offset.
    rs = _complete_slice().read_input(0x1000)
    for attr in ("examined", "examined_bytes", "unexamined_suffix",
                 "rescan_suffix", "recollect_suffix", "fully_examined",
                 "complete", "coverage_status"):
        assert not hasattr(rs, attr)


def test_read_slice_rejects_a_read_past_the_capture():
    with pytest.raises(RangeError):
        ReadSlice(capture=_complete_slice(), read_bytes=0x2000)


def test_read_slice_keeps_full_capture_provenance():
    rs = _complete_slice().read_input(0x400)
    assert rs.requested == VirtualRange(0x1000, 0x1000)
    assert rs.capture.file_offset == 0x9000
    assert rs.capture.segments[0].file_offset == 0x9000


# ── mf-backed convenience helpers ────────────────────────────────────────

def _mf_with_segments(segments):
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream(segments, "memory_segments")
    return mf


def _mf_with_regions(regions):
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    return mf


def test_captured_segments_returns_an_address_ordered_immutable_tuple():
    mf = _mf_with_segments([Segment(0x2000, 0xf000, 0x800), Segment(0x1000, 0x9000, 0x800)])
    views = captured_segments(mf)
    assert isinstance(views, tuple)
    assert [v.base_address for v in views] == [0x1000, 0x2000]


def test_captured_segments_empty_for_a_dump_with_no_segment_table():
    assert captured_segments(FakeMF()) == ()


def test_captured_regions_returns_address_ordered_views():
    mf = _mf_with_regions([
        Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
        Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ])
    views = captured_regions(mf)
    assert [v.base_address for v in views] == [0x1000, 0x2000]
    assert views[0].type == "MEM_PRIVATE"


def test_capture_of_slices_against_the_dumps_own_segment_table():
    mf = _mf_with_segments([Segment(0x1000, 0x9000, 0x600)])
    result = capture_of(mf, VirtualRange(0x1000, 0x1000))
    assert isinstance(result, CapturedSlice)
    assert result.state is CaptureState.PARTIAL
    assert result.captured == VirtualRange(0x1000, 0x600)
    assert result.file_offset == 0x9000


def test_region_and_segment_containing_find_the_covering_view():
    regions = captured_regions(_mf_with_regions([
        Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]))
    segments = captured_segments(_mf_with_segments([Segment(0x1000, 0x9000, 0x1000)]))

    assert region_containing(0x1400, regions).base_address == 0x1000
    assert region_containing(0x9999, regions) is None
    assert segment_containing(0x1400, segments).file_offset == 0x9000
    assert segment_containing(0x9999, segments) is None


def test_enumerate_captured_segments_skips_and_counts_unrepresentable_descriptors():
    mf = _mf_with_segments([
        Segment(0x2000, 0xf000, 0x800),                 # valid
        Segment(0x3000, 0x1000, 0),                      # zero-length -- skipped
        Segment((1 << 64) - 0x100, 0x5000, 0x200),       # base + size overflow -- skipped
        Segment(0x1000, 0x9000, 0x800),                  # valid
    ])
    result = enumerate_captured_segments(mf)
    assert isinstance(result, CapturedEnumeration)
    assert [v.base_address for v in result.views] == [0x1000, 0x2000]
    assert result.skipped == 2
    assert captured_segments(mf) == result.views   # thin wrapper


def test_enumerate_captured_regions_skips_and_counts_unrepresentable_descriptors():
    mf = _mf_with_regions([
        Region(0x3000, 0x3000, 0, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),          # zero
        Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),        # valid
        Region((1 << 64) - 0x100, 0, 0x200, "MEM_COMMIT", "PAGE_NOACCESS", "MEM_PRIVATE"), # overflow
        Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),     # valid
    ])
    result = enumerate_captured_regions(mf)
    assert [v.base_address for v in result.views] == [0x1000, 0x2000]
    assert result.skipped == 2
    assert captured_regions(mf) == result.views


def test_enumerate_captured_reports_zero_skips_for_a_clean_table():
    mf = _mf_with_segments([Segment(0x1000, 0x9000, 0x800)])
    assert enumerate_captured_segments(mf).skipped == 0


def test_captured_enumeration_coerces_views_and_rejects_a_negative_skip():
    e = CapturedEnumeration(
        views=[CapturedSegment(VirtualRange(0x1000, 0x400), file_offset=0)], skipped=0)
    assert isinstance(e.views, tuple)
    with pytest.raises(RangeError):
        CapturedEnumeration(views=(), skipped=-1)


def test_capture_of_still_slices_the_valid_segments_when_the_table_has_a_bad_entry():
    mf = _mf_with_segments([
        Segment(0x1000, 0x9000, 0),        # zero-length -- skipped
        Segment(0x1000, 0x9000, 0x1000),   # valid, backs the whole request
    ])
    result = capture_of(mf, VirtualRange(0x1000, 0x1000))
    assert isinstance(result, CapturedSlice)
    assert result.state is CaptureState.COMPLETE
    assert result.file_offset == 0x9000


def test_capture_state_matches_scan_target_capture_state_wire_values():
    from dumpex.output.coverage import ScanTarget, ScanTargetKind

    for captured, expected in ((0, CaptureState.NONE),
                                (0x400, CaptureState.PARTIAL),
                                (0x1000, CaptureState.COMPLETE)):
        target = ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=0x1000,
                            size=0x1000, file_offset=0x9000, captured_size=captured)
        assert target.capture_state == expected.value
