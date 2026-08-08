"""
Shared coverage/status reduction for hunt modules.

Every phase-two hunter (injection/stomping/pipe/obfuscation) needs to
answer the same two questions at the end of a scan:

  1. coverage_status — did this hunter have what it needed to run, and
     did it get through everything it was supposed to look at?
     ("not_evaluated" / "partial" / "complete")
  2. status — the top-level DETECTED / NOT_DETECTED_IN_SCANNED_SCOPE /
     INCONCLUSIVE / NOT_EVALUATED a console/JSON consumer reads.

Before this module existed, each hunter hand-rolled the same two
if/elif chains separately (stomping.py, pipe.py, encoding.py each wrote
an near-identical copy; injection.py used a similarly-shaped but
differently-named helper — this history predates the injection.py ->
dumpex/hunt/injection/, stomping.py -> dumpex/hunt/stomping/, and
pipe.py -> dumpex/hunt/pipe/ package splits). That duplication is exactly how the four
hunters' coverage semantics could quietly drift apart from each other —
`derive_coverage_status()` and `derive_status()` are the single place
this reduction happens now; every hunter calls these two functions
rather than re-deriving the rule locally.

The reduction rule (the same for every hunter):

    no necessary data source / never actually ran  -> NOT_EVALUATED
    score > 0                                       -> DETECTED
                                                        (coverage_status
                                                        can still be
                                                        "partial")
    score == 0 and coverage incomplete              -> INCONCLUSIVE
    score == 0 and coverage complete                -> NOT_DETECTED_IN_SCANNED_SCOPE
"""
from dataclasses import dataclass, field

from dumpex.hunt._ui import (
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE,
)
from dumpex.core.memory import prot_str, va_to_file_offset
from dumpex.output.coverage import (
    ScanTarget, ScanTargetKind, format_scan_target_preview,
)


def region_scan_target(mf, region, size_limit: int) -> ScanTarget:
    """A ScanTarget for one MemoryInfoListStream region a scan skipped for
    exceeding `size_limit`. The ONE place a raw minidump region becomes a
    skipped-target reference -- pipe's memory scan, stomping's unscored
    IOC-string scan, and all three of obfuscation's layer scans go through
    this rather than each re-deriving the same seven fields (and each
    getting a slightly different answer for, say, whether
    `AllocationBase` is present).

    `file_offset` is looked up per skipped region rather than for every
    region walked: this only runs on the skip path, which is rare by
    construction (a region has to be over the layer's cap to get here)."""
    base = region.BaseAddress
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_REGION,
        base_address=base,
        size=region.RegionSize,
        size_limit=size_limit,
        # None when the region's bytes were never written to the .dmp at
        # all -- an important distinction for an investigator deciding
        # between "extract it from this dump" and "recollect".
        file_offset=va_to_file_offset(mf, base),
        allocation_base=getattr(region, "AllocationBase", None),
        state=prot_str(region.State),
        type=prot_str(region.Type),
        protection=prot_str(region.Protect),
    )


def segment_scan_target(segment, size_limit: int) -> ScanTarget:
    """A ScanTarget for one memory-segment-table entry (CS Beacon/YARA
    scan over Memory64List/MemoryList) skipped for exceeding
    `size_limit`. A segment carries no MemoryInfo, so state/type/
    protection stay unset -- but its own `start_file_address` IS the file
    offset, no VA translation needed."""
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_SEGMENT,
        base_address=segment.start_virtual_address,
        size=segment.size,
        size_limit=size_limit,
        file_offset=segment.start_file_address,
    )


def derive_coverage_status(evaluated: bool, complete: bool) -> str:
    """
    "not_evaluated"  — the hunter had none of the data sources it needed
                        (e.g. every required stream was missing) and
                        never actually ran its scan loop at all.
    "partial"        — it ran, but hit at least one coverage gap along
                        the way (a skipped/oversized region, a failed
                        read, an exhausted budget, a stream that was
                        present but incomplete, ...).
    "complete"        — it ran and got through everything in scope.
    """
    if not evaluated:
        return "not_evaluated"
    return "complete" if complete else "partial"


def derive_status(evaluated: bool, detected: bool, complete: bool = True) -> str:
    """
    Reduce (did this hunter actually get to scan, did coverage come out
    complete, did it find something) into the four top-level statuses.

    `detected` (score > 0) always wins over `complete` — a hunter that
    found something in what it DID manage to scan is DETECTED regardless
    of whether other parts of the dump were unreachable; that gap is
    still visible separately via coverage_status/coverage_reasons, not
    lost by downgrading a real hit to INCONCLUSIVE.
    """
    if not evaluated:
        return NOT_EVALUATED
    if detected:
        return DETECTED
    return INCONCLUSIVE if not complete else NOT_DETECTED_IN_SCANNED_SCOPE


@dataclass
class CoverageTracker:
    """
    Reusable accumulator for the generic shape a "scan every region/item,
    skip/fail on some of them" loop keeps running into across hunters:
    how many items existed, how many were actually scanned, and how many
    were skipped/failed for each of a handful of common reasons. The
    oversized-skip reason additionally retains the items themselves (see
    skipped_oversize_targets) -- the only gap here a caller can act on
    directly, and only if it knows which addresses were missed.

    Not every hunter's coverage gaps fit this generic shape exactly —
    the verified-content-diff loop in dumpex.hunt.stomping has several
    genuinely domain-specific gap reasons (reference file missing,
    reference identity mismatch, relocation normalization failure, ...)
    that don't map cleanly onto skipped_oversize/read_failed/short_reads,
    so it keeps its own richer coverage_counts dict rather than forcing
    those into this shape. Use CoverageTracker where the gaps genuinely
    ARE just "region too big / read failed / short read / ran out of
    time-or-budget" (the per-layer region scans in dumpex.hunt.encoding,
    the region scan in dumpex.hunt.pipe.memory_scan, and — in the same
    hunter whose content-diff loop does NOT fit — the unscored IOC-string
    region scan in dumpex.hunt.stomping.memory_scan, whose only two gaps
    are exactly "over the size cap" and "read raised") — for everything
    else, track whatever the hunter's own reasons array needs and call
    derive_status()/derive_coverage_status()
    directly with an explicit `complete` boolean.
    """
    total:            int = 0   # eligible items found (before any skip/fail)
    scanned:          int = 0   # items actually read and analyzed
    read_failed:      int = 0   # read raised/returned nothing usable
    short_reads:      int = 0   # read succeeded but returned less than expected
    timed_out:        int = 0   # abandoned once a deadline was hit
    budget_exhausted: bool = False
    reasons: list = field(default_factory=list)
    # One ScanTarget per eligible item skipped ONLY for exceeding a size
    # cap. Unlike the other gap reasons, this one keeps the item itself,
    # not just a tally: "coverage is partial" is not actionable unless an
    # investigator can see WHICH virtual addresses to go extract, rescan,
    # or recollect (see dumpex.output.coverage.ScanTarget).
    skipped_oversize_targets: list = field(default_factory=list)

    @property
    def skipped_oversize(self) -> int:
        """Derived, never stored: the count and the retained targets are
        the same fact, so there is nothing for them to drift apart on."""
        return len(self.skipped_oversize_targets)

    def note_skipped_oversize(self, target: ScanTarget):
        """`target` is required -- a skip that can't name what it skipped
        is exactly the unactionable shape this tracker moved away from."""
        if type(target) is not ScanTarget:
            raise TypeError(
                f"note_skipped_oversize() requires a ScanTarget identifying the skipped "
                f"region/segment, got {type(target).__name__}")
        self.skipped_oversize_targets.append(target)

    def note_read_failed(self):
        self.read_failed += 1

    def note_short_read(self):
        self.short_reads += 1

    def note_timed_out(self):
        self.timed_out += 1

    def note_scanned(self):
        self.scanned += 1

    @property
    def complete(self) -> bool:
        """True iff nothing here forced a gap in what was actually scanned."""
        return not (self.skipped_oversize or self.read_failed
                    or self.short_reads or self.timed_out or self.budget_exhausted)

    def build_reasons(self, *, oversize_label="oversized item(s) skipped",
                       read_failed_label="item(s) failed to read",
                       short_read_label="item(s) had a short/incomplete read",
                       timed_out_label="item(s) abandoned after the scan deadline") -> list:
        """
        Render the accumulated counters into human-readable
        coverage_reasons strings, in a stable order. Any reasons already
        added via `reasons.append(...)` directly (e.g. a hunter-specific
        message) are kept and appended after the generic ones.
        """
        out = []
        if self.skipped_oversize:
            # Same bounded VA/size preview the structured limitation
            # renders (dumpex.output.coverage.format_scan_target_preview),
            # so the console reason and --json's own coverage.reasons
            # describe the identical skips identically.
            out.append(f"{self.skipped_oversize} {oversize_label}: "
                        f"{format_scan_target_preview(self.skipped_oversize_targets)}")
        if self.read_failed:
            out.append(f"{self.read_failed} {read_failed_label}")
        if self.short_reads:
            out.append(f"{self.short_reads} {short_read_label}")
        if self.timed_out:
            out.append(f"{self.timed_out} {timed_out_label}")
        if self.budget_exhausted:
            out.append("scan budget exhausted")
        out.extend(self.reasons)
        return out
