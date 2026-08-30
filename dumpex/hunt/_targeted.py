"""Shared primitives for targeted (``--hunt-addr``) single-range rescans.

The targeted-rescan contract (``docs/developer/hunt_targeted_rescan_contract.md``
§"Range and descriptor boundaries") fixes one descriptor-boundary rule for every
analyzer: the requested bytes are captured once across the whole request, but
source eligibility and evaluation are anchored to the descriptor containing the
requested base address, so evaluation stops at that descriptor's end and the
closure is ``partial`` with ``SCAN_REGION_EVALUATION_TRUNCATED`` when the request
runs past it. A request that lies wholly inside a larger descriptor carries a
caveat naming that descriptor.

The rule is the same for both native scan units, so this module owns both
shapes: a ``MemoryInfoListStream`` region (pipe, stomping, obfuscation --
:class:`SyntheticRegion` / :func:`resolve_region_boundary`) and a
``Memory64List``/``MemoryList`` captured segment (YARA, CS Beacon --
:class:`SyntheticSegment` / :func:`resolve_segment_boundary`). A segment slice
additionally carries a dump-file offset: the slice's own offset is the
containing segment's, displaced by the slice's distance from that segment's
base, so a scanner deriving a hit's file offset from ``slice_base + match
offset`` lands on the same .dmp byte the full-scope scan would have.

Analyzer-specific coverage reduction (which ``LayerCoverage`` /
``ScanDiagnostics`` state maps to which status) and payload shapes stay in each
analyzer's own targeted module.
"""
from dataclasses import dataclass

from dumpex.core.va_range import (
    CapturedRegion, CapturedSegment, ReadSlice, VirtualRange, segment_containing,
)
from dumpex.hunt._coverage import region_scan_target, segment_scan_target
from dumpex.output.coverage import (
    CoverageLimitation, LimitationCode, ScanTarget, ScanTargetKind,
)

__all__ = [
    "SyntheticRegion",
    "SyntheticSegment",
    "TargetedRegionBoundary",
    "TargetedSegmentBoundary",
    "resolve_region_boundary",
    "resolve_segment_boundary",
    "unexamined_suffix_target",
    "evaluation_truncated_limitation",
    "truncation_diagnostic",
    "sub_region_diagnostic",
    "sub_segment_diagnostic",
]


class SyntheticRegion:
    """A raw-``MemoryInfo``-shaped view of one clipped requested range wearing a
    real descriptor's allocation/state/type/protection, for handing to a region
    scanner that expects ``BaseAddress`` / ``RegionSize`` / ``State`` / ``Type``
    / ``Protect`` / ``AllocationBase``. ``prot_str`` passes a plain string
    through unchanged, so the strings a :class:`CapturedRegion` already carries
    are accepted directly."""

    __slots__ = ("BaseAddress", "RegionSize", "State", "Type", "Protect", "AllocationBase")

    def __init__(self, base, size, *, state, mtype, protect, allocation_base):
        self.BaseAddress = base
        self.RegionSize = size
        self.State = state
        self.Type = mtype
        self.Protect = protect
        self.AllocationBase = allocation_base

    @classmethod
    def from_captured_region(cls, base, size, region: CapturedRegion) -> "SyntheticRegion":
        return cls(base, size, state=region.state, mtype=region.type,
                   protect=region.protection, allocation_base=region.allocation_base)


@dataclass(frozen=True)
class TargetedRegionBoundary:
    """How one requested range relates to its containing descriptor.

    ``region_range`` -- the containing descriptor's own span.
    ``eval_range`` -- ``requested`` clipped to ``region_range`` (what a scanner
    actually evaluates).
    ``truncated`` -- ``eval_range`` is shorter than ``requested`` (the request
    crossed the descriptor's end).
    ``sub_region`` -- ``requested`` lies wholly inside ``region_range`` and is
    strictly smaller (a transformation spanning the requested end is evaluated
    by neither this rescan nor the bytes past it).
    ``requested_target`` / ``containing_target`` -- ScanTargets for the whole
    requested range and for the containing allocation, for a limitation or a
    result payload.
    """
    region_range: VirtualRange
    eval_range: VirtualRange
    truncated: bool
    sub_region: bool
    requested_target: object
    containing_target: object


def resolve_region_boundary(mf, requested: VirtualRange,
                            containing: CapturedRegion) -> TargetedRegionBoundary:
    """Clip ``requested`` to ``containing`` and describe the relationship.

    ``containing`` must be a :class:`CapturedRegion` whose range contains
    ``requested.base_address`` (the caller resolves it, e.g. through
    ``dumpex.core.va_range.region_containing``)."""
    region_range = containing.range
    clipped = requested.clip_to(region_range)
    eval_range = clipped if clipped is not None else requested
    return TargetedRegionBoundary(
        region_range=region_range,
        eval_range=eval_range,
        truncated=eval_range.size < requested.size,
        sub_region=eval_range.size == requested.size and requested != region_range,
        requested_target=region_scan_target(
            mf, SyntheticRegion.from_captured_region(
                requested.base_address, requested.size, containing)),
        containing_target=region_scan_target(
            mf, SyntheticRegion.from_captured_region(
                region_range.base_address, region_range.size, containing)),
    )


class SyntheticSegment:
    """A raw-``Memory64List``-shaped view of one requested slice of a real
    captured segment, for handing to a segment scanner that expects
    ``start_virtual_address`` / ``start_file_address`` / ``size`` /
    ``end_virtual_address``.

    The slice's virtual base is the requested address, its size is the
    requested (clipped) extent, and its file offset is the containing
    segment's offset displaced by the slice's distance from that segment's
    base -- so ``start_virtual_address + match_offset`` and
    ``start_file_address + match_offset`` both stay absolute and correct."""

    __slots__ = ("start_virtual_address", "start_file_address", "size",
                 "end_virtual_address")

    def __init__(self, base, size, file_offset):
        self.start_virtual_address = base
        self.start_file_address = file_offset
        self.size = size
        self.end_virtual_address = base + size

    @classmethod
    def from_captured_segment(cls, sliced: VirtualRange,
                              segment: CapturedSegment) -> "SyntheticSegment":
        """The slice ``sliced`` of ``segment``. ``sliced`` must lie wholly
        inside ``segment`` -- :meth:`CapturedSegment.file_offset_at` raises
        otherwise, so a displacement is never computed for bytes belonging to
        another segment or to none at all."""
        return cls(sliced.base_address, sliced.size,
                   segment.file_offset_at(sliced.base_address))


@dataclass(frozen=True)
class TargetedSegmentBoundary:
    """How one requested range relates to its containing captured segment --
    the segment-unit counterpart of :class:`TargetedRegionBoundary`.

    ``segment_range`` -- the containing segment's own span.
    ``eval_range`` -- ``requested`` clipped to ``segment_range`` (what a
    scanner actually evaluates).
    ``slice_segment`` -- ``eval_range`` as a :class:`SyntheticSegment`, ready
    to hand to a segment scanner.
    ``truncated`` -- ``eval_range`` is shorter than ``requested`` (the request
    crossed the segment's end).
    ``sub_segment`` -- ``requested`` lies wholly inside ``segment_range`` and is
    strictly smaller (a signature spanning the requested end is evaluated by
    neither this rescan nor the bytes past it).
    ``requested_target`` -- a ScanTarget for the WHOLE requested range, whose
    ``captured_size`` is the contiguous captured prefix rather than the
    requested extent, so a truncated request never reads as fully captured.
    ``containing_target`` -- a ScanTarget for the containing segment.
    """
    segment_range: VirtualRange
    eval_range: VirtualRange
    slice_segment: SyntheticSegment
    truncated: bool
    sub_segment: bool
    requested_target: ScanTarget
    containing_target: ScanTarget


def resolve_segment_boundary(requested: VirtualRange, containing: CapturedSegment,
                             *, captured_bytes: int) -> TargetedSegmentBoundary:
    """Clip ``requested`` to ``containing`` and describe the relationship.

    ``containing`` must be a :class:`CapturedSegment` whose range contains
    ``requested.base_address`` (the caller resolves it, e.g. through
    ``dumpex.core.va_range.segment_containing``). ``captured_bytes`` is the
    contiguous captured prefix of ``requested`` -- byte availability across the
    whole request, which can run past ``containing``'s end into an adjacent
    segment and is therefore a different number from ``eval_range.size``."""
    segment_range = containing.range
    clipped = requested.clip_to(segment_range)
    eval_range = clipped if clipped is not None else requested
    return TargetedSegmentBoundary(
        segment_range=segment_range,
        eval_range=eval_range,
        slice_segment=SyntheticSegment.from_captured_segment(eval_range, containing),
        truncated=eval_range.size < requested.size,
        sub_segment=eval_range.size == requested.size and requested != segment_range,
        requested_target=ScanTarget(
            kind=ScanTargetKind.MEMORY_SEGMENT,
            base_address=requested.base_address, size=requested.size,
            file_offset=containing.file_offset_at(requested.base_address),
            captured_size=captured_bytes),
        containing_target=segment_scan_target(
            SyntheticSegment(segment_range.base_address, segment_range.size,
                             containing.file_offset)),
    )


def unexamined_suffix_target(read_slice: ReadSlice) -> "ScanTarget | None":
    """The exact tail of the requested range no byte of which reached the
    scanner, or ``None`` when the whole request was read.

    This is the honest remaining target when a retained budget, a deadline, or
    a short read stops the scan part-way: it is measured from the bytes the
    read actually returned, never from the descriptor the scan was pointed at,
    so a stop before the read names the whole request and a stop after a
    partial read names only what is left.

    ``file_offset`` and ``captured_size`` come from the capture the read ran
    against, so a suffix the dump still backs -- including one past the
    evaluated descriptor's end, in an adjacent segment -- keeps the .dmp
    location an investigator would extract it from. Both describe an
    uncaptured suffix as exactly that: no offset, nothing captured."""
    suffix = read_slice.unread_suffix
    if suffix is None:
        return None
    capture = read_slice.capture
    backing = segment_containing(suffix.base_address, capture.segments)
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_SEGMENT,
        base_address=suffix.base_address, size=suffix.size,
        file_offset=(backing.file_offset_at(suffix.base_address)
                     if backing is not None else None),
        captured_size=max(0, capture.captured_bytes - read_slice.read_bytes),
    )


def evaluation_truncated_limitation(source: str, scope: "str | None",
                                    requested_target) -> CoverageLimitation:
    """The ``SCAN_REGION_EVALUATION_TRUNCATED`` limitation for one closure whose
    evaluation stopped at the containing descriptor's end while capture
    continued across the whole requested range."""
    return CoverageLimitation(
        code=LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED, source=source,
        scope=scope, affected_count=1, targets=(requested_target,))


def truncation_diagnostic(region_range: VirtualRange, requested: VirtualRange,
                          eval_range: VirtualRange, *, unit: str = "region") -> str:
    """``unit`` names the descriptor the clip was made against -- ``"region"``
    for a ``MemoryInfo`` descriptor, ``"segment"`` for a captured-segment
    one."""
    return (f"requested range clipped to containing {unit} end "
            f"{region_range.end_address:#018x}; "
            f"{requested.size - eval_range.size} byte(s) past the boundary were not "
            f"evaluated")


def sub_region_diagnostic(region_range: VirtualRange, requested: VirtualRange) -> str:
    return (f"requested range is a {requested.size:#x}-byte sub-range of the "
            f"containing allocation {region_range}; a transformation spanning either "
            f"requested boundary is evaluated by neither this rescan nor the surrounding "
            f"bytes of the allocation")


def sub_segment_diagnostic(segment_range: VirtualRange, requested: VirtualRange) -> str:
    return (f"requested range is a {requested.size:#x}-byte sub-range of the "
            f"containing captured segment {segment_range}; a signature spanning either "
            f"requested boundary is evaluated by neither this rescan nor the surrounding "
            f"bytes of the segment")
