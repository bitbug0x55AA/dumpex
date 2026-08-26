"""Coverage primitives shared by hunt analyzers.

Trackers record source presence and scan gaps without conflating absent,
present-empty, failed, short, or truncated states. Status reduction preserves the
rule that incomplete observation cannot produce a clean negative verdict.
"""
from dataclasses import dataclass, field

from dumpex.hunt._ui import (
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE,
)
from dumpex.core.memory import prot_str, va_to_file_offset, va_range_captured_bytes
from dumpex.output.coverage import (
    ScanTarget, ScanTargetKind, format_scan_target_preview,
)


def region_scan_target(mf, region, size_limit: "int | None" = None) -> ScanTarget:
    """A ScanTarget for one MemoryInfoListStream region. The ONE place a
    raw minidump region becomes a target reference -- pipe's memory scan,
    stomping's unscored IOC-string scan, all three of obfuscation's layer
    scans, and (issue #28) any hunter's own read-failed/short-read/scan-
    truncated gap all go through this rather than each re-deriving the
    same seven fields (and each getting a slightly different answer for,
    say, whether `AllocationBase` is present).

    `size_limit` is the cap `region` exceeded when it was skipped for
    being oversized -- pass it explicitly for that case (see ScanTarget's
    own docstring). Leave it at its default `None` for a region a scan
    actually attempted and failed to read, read short, or ran out of scan
    budget on: there is no cap being exceeded there, just an I/O failure
    or a budget exhaustion.

    `file_offset` is looked up per target rather than for every region
    walked: this only runs on the skip/failure path, which is rare by
    construction."""
    base = region.BaseAddress
    size = region.RegionSize
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_REGION,
        base_address=base,
        size=size,
        size_limit=size_limit,
        # None when the region's bytes were never written to the .dmp at
        # all -- an important distinction for an investigator deciding
        # between "extract it from this dump" and "recollect".
        file_offset=va_to_file_offset(mf, base),
        allocation_base=getattr(region, "AllocationBase", None),
        state=prot_str(region.State),
        type=prot_str(region.Type),
        protection=prot_str(region.Protect),
        # How much of `size` the dump's own segment table actually backs
        # (issue #28 P1 follow-up) -- a STRUCTURAL fact, independent of
        # whether this call is on the oversized-skip path (never read at
        # all) or a read-failed/short-read one (partially read); either
        # way it answers "how much of this region can actually be
        # extracted from the dump already in hand".
        captured_size=va_range_captured_bytes(mf, base, size),
    )


def segment_scan_target(segment, size_limit: "int | None" = None) -> ScanTarget:
    """A ScanTarget for one memory-segment-table entry (CS Beacon/YARA
    scan over Memory64List/MemoryList). A segment carries no MemoryInfo,
    so state/type/protection stay unset -- but its own
    `start_file_address` IS the file offset, no VA translation needed.
    `size_limit` follows region_scan_target()'s own convention: pass it
    explicitly for an oversized-skip target, leave it `None` for a read-
    failed/short-read/scan-truncated one.

    `captured_size` is always the segment's own full `size` (issue #28 P1
    follow-up) -- unlike a MemoryInfo region (which can span more address
    space than any Memory64List/MemoryList segment actually backs), a
    segment-table entry IS, by definition, a claim from the dump's own
    segment table that exactly this many bytes are captured at this file
    offset. A live read attempt failing or coming back short for a
    segment target is a fact about THIS scan's own read, not about
    whether the bytes exist in the file -- `va_range_captured_bytes()`
    would trivially confirm the same "fully captured" answer by re-
    walking the very table this segment came from, so it is set directly
    here instead."""
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_SEGMENT,
        base_address=segment.start_virtual_address,
        size=segment.size,
        size_limit=size_limit,
        file_offset=segment.start_file_address,
        captured_size=segment.size,
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
    # Companions to skipped_oversize_targets (issue #28): a ScanTarget per
    # item that was actually ATTEMPTED but failed to read / read short --
    # OPTIONAL, unlike skipped_oversize_targets, since note_read_failed()/
    # note_short_read() may legitimately be called with no target (a
    # caller that cannot resolve the item's own identity at the failure
    # site keeps working exactly as before this field existed). When a
    # caller DOES supply targets consistently, len() equals the matching
    # counter; a caller must not supply a target on some calls and not
    # others for the same reason, or the two numbers drift apart.
    read_failed_targets: list = field(default_factory=list)
    short_read_targets: list = field(default_factory=list)

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

    def _note_target(self, target: "ScanTarget | None", targets: list, caller: str):
        if target is None:
            return
        if type(target) is not ScanTarget:
            raise TypeError(
                f"{caller}() target, when given, must be a ScanTarget identifying the "
                f"region/segment, got {type(target).__name__}")
        targets.append(target)

    def note_read_failed(self, target: "ScanTarget | None" = None):
        self.read_failed += 1
        self._note_target(target, self.read_failed_targets, "note_read_failed")

    def note_short_read(self, target: "ScanTarget | None" = None):
        self.short_reads += 1
        self._note_target(target, self.short_read_targets, "note_short_read")

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
            # Preview appended only when the caller supplied targets (see
            # read_failed_targets' own docstring) -- a caller that never
            # calls note_read_failed(target=...) sees the exact same bare
            # count text as before this field existed.
            preview = (f": {format_scan_target_preview(self.read_failed_targets)}"
                       if self.read_failed_targets else "")
            out.append(f"{self.read_failed} {read_failed_label}{preview}")
        if self.short_reads:
            preview = (f": {format_scan_target_preview(self.short_read_targets)}"
                       if self.short_read_targets else "")
            out.append(f"{self.short_reads} {short_read_label}{preview}")
        if self.timed_out:
            out.append(f"{self.timed_out} {timed_out_label}")
        if self.budget_exhausted:
            out.append("scan budget exhausted")
        out.extend(self.reasons)
        return out
