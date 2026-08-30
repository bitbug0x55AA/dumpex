"""Direct tests for dumpex.hunt._targeted -- the descriptor-boundary rule the
targeted-rescan contract mandates identically for every analyzer, in both of
its native scan units (MemoryInfo region and captured segment). Exercised here
without any analyzer in the loop."""
import pytest

from dumpex.core.va_range import (
    CapturedRegion, CapturedSegment, RangeError, VirtualRange, slice_captured,
)
from dumpex.output.coverage import LimitationCode, ScanTargetKind
from dumpex.hunt import _targeted


class _MF:
    memory_segments_64 = None
    memory_segments = None


def _region(base=0x10000, size=0x40000, *, state="MEM_COMMIT", mtype="MEM_PRIVATE",
            protect="PAGE_READWRITE", alloc=None):
    return CapturedRegion(range=VirtualRange(base, size), allocation_base=alloc,
                          state=state, type=mtype, protection=protect)


def _segment(base=0x10000, size=0x40000, file_offset=0x2000):
    return CapturedSegment(range=VirtualRange(base, size), file_offset=file_offset)


# ── SyntheticRegion ─────────────────────────────────────────────────────

def test_synthetic_region_wears_the_descriptor_metadata():
    region = _region(base=0x10000, size=0x40000, state="MEM_COMMIT",
                     mtype="MEM_IMAGE", protect="PAGE_EXECUTE_READ", alloc=0x10000)
    syn = _targeted.SyntheticRegion.from_captured_region(0x12000, 0x1000, region)
    assert syn.BaseAddress == 0x12000
    assert syn.RegionSize == 0x1000
    assert syn.State == "MEM_COMMIT"
    assert syn.Type == "MEM_IMAGE"
    assert syn.Protect == "PAGE_EXECUTE_READ"
    assert syn.AllocationBase == 0x10000


# ── resolve_region_boundary ─────────────────────────────────────────────

def test_boundary_request_equal_to_the_region_is_neither_truncated_nor_sub_region():
    region = _region(base=0x10000, size=0x2000)
    b = _targeted.resolve_region_boundary(_MF(), VirtualRange(0x10000, 0x2000), region)
    assert b.eval_range == VirtualRange(0x10000, 0x2000)
    assert b.truncated is False
    assert b.sub_region is False


def test_boundary_request_inside_and_smaller_is_a_sub_region():
    region = _region(base=0x10000, size=0x40000)
    b = _targeted.resolve_region_boundary(_MF(), VirtualRange(0x11000, 0x1000), region)
    assert b.eval_range == VirtualRange(0x11000, 0x1000)
    assert b.truncated is False
    assert b.sub_region is True


def test_boundary_request_ending_exactly_at_the_region_end_is_a_sub_region():
    region = _region(base=0x10000, size=0x40000)
    b = _targeted.resolve_region_boundary(
        _MF(), VirtualRange(0x10000 + 0x3F000, 0x1000), region)
    assert b.truncated is False
    assert b.sub_region is True


def test_boundary_request_starting_at_base_and_running_past_the_end_is_truncated():
    region = _region(base=0x10000, size=0x1000)
    b = _targeted.resolve_region_boundary(_MF(), VirtualRange(0x10000, 0x4000), region)
    assert b.eval_range == VirtualRange(0x10000, 0x1000)
    assert b.truncated is True
    assert b.sub_region is False


def test_boundary_request_starting_inside_and_running_past_the_end_is_truncated():
    region = _region(base=0x10000, size=0x2000)
    b = _targeted.resolve_region_boundary(_MF(), VirtualRange(0x11000, 0x4000), region)
    assert b.eval_range == VirtualRange(0x11000, 0x1000)
    assert b.truncated is True
    assert b.sub_region is False


def test_boundary_targets_name_the_whole_request_and_the_whole_allocation():
    region = _region(base=0x10000, size=0x40000)
    b = _targeted.resolve_region_boundary(_MF(), VirtualRange(0x11000, 0x1000), region)
    assert b.requested_target.base_address == 0x11000
    assert b.requested_target.size == 0x1000
    assert b.containing_target.base_address == 0x10000
    assert b.containing_target.size == 0x40000


# ── limitation + diagnostics ───────────────────────────────────────────

def test_evaluation_truncated_limitation_shape():
    region = _region()
    b = _targeted.resolve_region_boundary(_MF(), VirtualRange(0x10000, 0x100000), region)
    lim = _targeted.evaluation_truncated_limitation("encoding_scan", "entropy",
                                                    b.requested_target)
    assert lim.code == LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED
    assert lim.source == "encoding_scan"
    assert lim.scope == "entropy"
    assert lim.affected_count == 1
    assert lim.targets == (b.requested_target,)


def test_diagnostics_mention_both_boundaries_where_relevant():
    rr = VirtualRange(0x10000, 0x40000)
    trunc = _targeted.truncation_diagnostic(rr, VirtualRange(0x10000, 0x80000),
                                            VirtualRange(0x10000, 0x40000))
    assert "past the boundary were not evaluated" in trunc

    sub = _targeted.sub_region_diagnostic(rr, VirtualRange(0x11000, 0x1000))
    assert "either requested boundary" in sub
    assert "surrounding bytes of the allocation" in sub


# ── SyntheticSegment ────────────────────────────────────────────────────

def test_synthetic_segment_displaces_the_file_offset_by_the_slice_distance():
    segment = _segment(base=0x10000, size=0x40000, file_offset=0x2000)
    syn = _targeted.SyntheticSegment.from_captured_segment(
        VirtualRange(0x11000, 0x1000), segment)
    assert syn.start_virtual_address == 0x11000
    assert syn.size == 0x1000
    assert syn.end_virtual_address == 0x12000
    assert syn.start_file_address == 0x2000 + 0x1000


def test_synthetic_segment_refuses_a_slice_outside_the_segment():
    segment = _segment(base=0x10000, size=0x1000)
    with pytest.raises(RangeError):
        _targeted.SyntheticSegment.from_captured_segment(
            VirtualRange(0x20000, 0x1000), segment)


# ── resolve_segment_boundary ────────────────────────────────────────────

def test_segment_boundary_request_equal_to_the_segment_is_neither_flag():
    segment = _segment(base=0x10000, size=0x2000)
    b = _targeted.resolve_segment_boundary(
        VirtualRange(0x10000, 0x2000), segment, captured_bytes=0x2000)
    assert b.eval_range == VirtualRange(0x10000, 0x2000)
    assert b.truncated is False
    assert b.sub_segment is False


def test_segment_boundary_request_inside_and_smaller_is_a_sub_segment():
    segment = _segment(base=0x10000, size=0x40000, file_offset=0x2000)
    b = _targeted.resolve_segment_boundary(
        VirtualRange(0x11000, 0x1000), segment, captured_bytes=0x1000)
    assert b.truncated is False
    assert b.sub_segment is True
    assert b.slice_segment.start_virtual_address == 0x11000
    assert b.slice_segment.start_file_address == 0x3000
    assert b.slice_segment.size == 0x1000


def test_segment_boundary_request_past_the_segment_end_clips_evaluation():
    segment = _segment(base=0x10000, size=0x1000, file_offset=0x2000)
    b = _targeted.resolve_segment_boundary(
        VirtualRange(0x10800, 0x4000), segment, captured_bytes=0x4000)
    assert b.eval_range == VirtualRange(0x10800, 0x800)
    assert b.truncated is True
    assert b.sub_segment is False
    assert b.slice_segment.size == 0x800
    assert b.slice_segment.start_file_address == 0x2800


def test_segment_boundary_requested_target_carries_the_captured_prefix_not_the_request():
    # Capture continues past the descriptor the evaluation stopped at, so the
    # requested target's captured_size and size are legitimately different.
    segment = _segment(base=0x10000, size=0x1000, file_offset=0x2000)
    b = _targeted.resolve_segment_boundary(
        VirtualRange(0x10000, 0x4000), segment, captured_bytes=0x3000)
    assert b.requested_target.kind is ScanTargetKind.MEMORY_SEGMENT
    assert b.requested_target.size == 0x4000
    assert b.requested_target.captured_size == 0x3000
    assert b.requested_target.file_offset == 0x2000
    assert b.containing_target.base_address == 0x10000
    assert b.containing_target.size == 0x1000
    assert b.containing_target.captured_size == 0x1000


# ── unexamined_suffix_target ────────────────────────────────────────────

def _read_slice(requested, segments, read_bytes):
    return slice_captured(requested, segments).read_input(read_bytes)


def test_unexamined_suffix_is_none_when_the_whole_request_was_read():
    segment = _segment(base=0x10000, size=0x2000, file_offset=0x2000)
    rs = _read_slice(VirtualRange(0x10000, 0x2000), [segment], 0x2000)
    assert _targeted.unexamined_suffix_target(rs) is None


def test_unexamined_suffix_names_the_exact_remaining_bytes_and_their_offset():
    segment = _segment(base=0x10000, size=0x2000, file_offset=0x2000)
    rs = _read_slice(VirtualRange(0x10000, 0x2000), [segment], 0x800)
    target = _targeted.unexamined_suffix_target(rs)
    assert target.base_address == 0x10800
    assert target.size == 0x1800
    assert target.file_offset == 0x2800
    assert target.captured_size == 0x1800


def test_unexamined_suffix_of_a_budget_stop_before_the_read_is_the_whole_request():
    segment = _segment(base=0x10000, size=0x2000, file_offset=0x2000)
    rs = _read_slice(VirtualRange(0x10000, 0x2000), [segment], 0)
    target = _targeted.unexamined_suffix_target(rs)
    assert (target.base_address, target.size) == (0x10000, 0x2000)
    assert target.captured_size == 0x2000


def test_unexamined_suffix_in_an_adjacent_segment_keeps_that_segments_offset():
    # Evaluation stopped at one segment's end while capture continued into the
    # next; the suffix is still extractable, from the next segment's offset.
    segments = [_segment(base=0x10000, size=0x1000, file_offset=0x2000),
                _segment(base=0x11000, size=0x1000, file_offset=0x9000)]
    rs = _read_slice(VirtualRange(0x10000, 0x2000), segments, 0x1000)
    target = _targeted.unexamined_suffix_target(rs)
    assert target.base_address == 0x11000
    assert target.size == 0x1000
    assert target.file_offset == 0x9000
    assert target.captured_size == 0x1000


def test_unexamined_suffix_the_dump_never_captured_carries_no_file_offset():
    segment = _segment(base=0x10000, size=0x1000, file_offset=0x2000)
    rs = _read_slice(VirtualRange(0x10000, 0x2000), [segment], 0x1000)
    target = _targeted.unexamined_suffix_target(rs)
    assert target.base_address == 0x11000
    assert target.size == 0x1000
    assert target.file_offset is None
    assert target.captured_size == 0


def test_segment_truncation_diagnostic_names_the_segment_boundary():
    trunc = _targeted.truncation_diagnostic(
        VirtualRange(0x10000, 0x1000), VirtualRange(0x10000, 0x4000),
        VirtualRange(0x10000, 0x1000), unit="segment")
    assert "containing segment end" in trunc

    sub = _targeted.sub_segment_diagnostic(
        VirtualRange(0x10000, 0x40000), VirtualRange(0x11000, 0x1000))
    assert "containing captured segment" in sub
    assert "surrounding bytes of the segment" in sub
