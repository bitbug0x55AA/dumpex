"""Direct tests for dumpex.hunt._targeted -- the descriptor-boundary rule the
targeted-rescan contract mandates identically for every region-scanning
analyzer. Exercised here without any analyzer in the loop."""
from dumpex.core.va_range import CapturedRegion, VirtualRange
from dumpex.output.coverage import LimitationCode
from dumpex.hunt import _targeted


class _MF:
    memory_segments_64 = None
    memory_segments = None


def _region(base=0x10000, size=0x40000, *, state="MEM_COMMIT", mtype="MEM_PRIVATE",
            protect="PAGE_READWRITE", alloc=None):
    return CapturedRegion(range=VirtualRange(base, size), allocation_base=alloc,
                          state=state, type=mtype, protection=protect)


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
