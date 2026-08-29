"""Shared primitives for targeted (``--hunt-addr``) single-range rescans.

The targeted-rescan contract (``docs/developer/hunt_targeted_rescan_contract.md``
§"Range and descriptor boundaries") fixes one descriptor-boundary rule for every
region-scanning analyzer: the requested bytes are captured once across the whole
request, but source eligibility and evaluation are anchored to the descriptor
containing the requested base address, so evaluation stops at that descriptor's
end and the closure is ``partial`` with ``SCAN_REGION_EVALUATION_TRUNCATED`` when
the request runs past it. A request that lies wholly inside a larger allocation
carries a caveat naming that allocation.

This module owns that rule so pipe, stomping, and obfuscation share one
implementation. Analyzer-specific coverage reduction (which ``LayerCoverage`` /
``CoverageSnapshot`` state maps to which status) and payload shapes stay in each
analyzer's own targeted module.
"""
from dataclasses import dataclass

from dumpex.core.va_range import CapturedRegion, VirtualRange
from dumpex.hunt._coverage import region_scan_target
from dumpex.output.coverage import CoverageLimitation, LimitationCode

__all__ = [
    "SyntheticRegion",
    "TargetedRegionBoundary",
    "resolve_region_boundary",
    "evaluation_truncated_limitation",
    "truncation_diagnostic",
    "sub_region_diagnostic",
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


def evaluation_truncated_limitation(source: str, scope: "str | None",
                                    requested_target) -> CoverageLimitation:
    """The ``SCAN_REGION_EVALUATION_TRUNCATED`` limitation for one closure whose
    evaluation stopped at the containing descriptor's end while capture
    continued across the whole requested range."""
    return CoverageLimitation(
        code=LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED, source=source,
        scope=scope, affected_count=1, targets=(requested_target,))


def truncation_diagnostic(region_range: VirtualRange, requested: VirtualRange,
                          eval_range: VirtualRange) -> str:
    return (f"requested range clipped to containing region end "
            f"{region_range.end_address:#018x}; "
            f"{requested.size - eval_range.size} byte(s) past the boundary were not "
            f"evaluated")


def sub_region_diagnostic(region_range: VirtualRange, requested: VirtualRange) -> str:
    return (f"requested range is a {requested.size:#x}-byte sub-range of the "
            f"containing allocation {region_range}; a transformation spanning either "
            f"requested boundary is evaluated by neither this rescan nor the surrounding "
            f"bytes of the allocation")
