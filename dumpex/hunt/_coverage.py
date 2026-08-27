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
from dumpex.output.coverage import ScanTarget, ScanTargetKind


# The ONE canonical wording for a reconciliation shortfall, shared by
# every hunter that builds its own gap reasons from a frozen coverage
# snapshot (pipe/stomping/cs_beacon/obfuscation), so the same accounting
# failure is never described four slightly different ways. The noun varies
# per hunter ("region(s)"/"segment(s)"/"item(s)"); the rest does not.
UNACCOUNTED_LABEL = "unaccounted for: walked by the scan, but no outcome was recorded"
OVER_ACCOUNTED_LABEL = "recorded an outcome that no eligible item can account for"
UNBALANCED_LABEL = ("unaccounted for: the scan's recorded outcomes do not add up "
                     "to the items it took into scope")


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
    else, track whatever the hunter's own coverage reasons need and call
    derive_status()/derive_coverage_status()
    directly with an explicit `complete` boolean.

    This accumulates FACTS and renders none of them: every hunter turns
    its own frozen coverage snapshot into reason text (see
    dumpex.hunt.pipe.domain.CoverageSnapshot.region_gap_reasons and its
    equivalents), with the shared wording constants above keeping those
    four renderings in step.

    ── The ledger ────────────────────────────────────────────────────────
    `complete` is a POSITIVE assertion that every eligible item reached a
    recorded outcome, not merely the absence of a recorded gap. Two
    categories, deliberately kept apart:

      dispositions -- EXACTLY ONE per eligible item, and mutually
        exclusive: `scanned` / `not_applicable` / `budget_skipped` /
        `read_failed` / `skipped_oversize`. A loop calls `note_eligible()` once per item
        that passes its own filters, then exactly one `note_*`
        disposition on every path out of that iteration.

      annotations -- orthogonal, may co-occur with any disposition:
        `short_reads` (the item WAS scanned, just not in full) and
        `budget_exhausted`.

    `accounted` (every disposition) is reconciled against `total`
    (the `note_eligible()` count), so a scan loop that `continue`s out of
    an iteration without recording anything fails CLOSED: the item is
    unaccounted for, `complete` is False, `unaccounted`/`over_accounted`
    say how badly, and the hunter's verdict is INCONCLUSIVE rather than
    NOT_DETECTED_IN_SCANNED_SCOPE. Without that reconciliation an
    unexamined item is indistinguishable from full coverage in every
    output surface.

    `budget_exhausted` is OPTIONAL and outside the ledger's contract: a
    whole-scan budget that trips ends the loop BEFORE the remaining items
    are ever walked, so they never became eligible and there is nothing
    for the ledger to reconcile. Hunters that carry their own richer
    budget state (dumpex.hunt.encoding's decode budget, pipe's two
    independent ScanBudgets, cs_beacon's five whole-scan budgets) report
    exhaustion through that state instead and never set this flag; it
    exists for a scan whose only budget signal IS the tracker
    (dumpex.hunt.encoding.sleep_mask).
    """
    # The disposition counters, named once so `accounted` below and every
    # frozen projection of this tracker sum the same set -- adding a
    # disposition means adding it here, and every snapshot that does not
    # carry it fails tests/hunt/test_coverage_ledger.py's parity check.
    # `skipped_oversize` is derived from its retained targets rather than
    # counted, so it is summed alongside these rather than listed here.
    DISPOSITION_COUNTERS = ("scanned", "not_applicable", "budget_skipped", "read_failed")

    total:            int = 0   # eligible items found (before any skip/fail)
    # Captured bytes those eligible items add up to, accumulated at the
    # same call as `total` -- what expressing partial coverage as a
    # FRACTION of eligible memory needs, rather than as a bare item count.
    # Callers pass what the DUMP actually holds for the item
    # (`va_range_captured_bytes()` for a MemoryInfo region, a segment's own
    # size for a segment-table entry), never a declared `RegionSize` that
    # can claim more address space than was ever written to the .dmp.
    eligible_bytes:   int = 0
    scanned:          int = 0   # disposition: items actually read and analyzed
    # disposition: read fine, but nothing about the ITEM was analyzable
    # (e.g. too few bytes to compute a meaningful entropy over) -- an
    # outcome, NOT a coverage gap. A rescan would find the same nothing.
    not_applicable:   int = 0
    # disposition: read fine and analyzable, but this SCAN had no budget
    # left to examine it. Also not a gap -- the budget's own exhausted
    # flag is what makes coverage partial -- but kept apart from
    # `not_applicable` because the two answer opposite questions about a
    # rescan: a bigger budget reaches these items, and reaches nothing
    # extra in the other bucket.
    budget_skipped:   int = 0
    read_failed:      int = 0   # disposition: read raised/returned nothing usable
    short_reads:      int = 0   # ANNOTATION: read short, readable prefix still scanned
    budget_exhausted: bool = False   # ANNOTATION (optional -- see class docstring)
    # Reject a ledger error instead of recording it. OFF for every shipped
    # scan: a hunt that cannot account for a region still has six other
    # hunters' worth of findings to deliver, and `dumpex.hunt.
    # _execute_full_scope` runs each builder unguarded, so raising here
    # would trade one region's coverage caveat for the whole run's output.
    # Tests turn it on to assert the contract directly.
    strict:           bool = False
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
    # Ledger bookkeeping, never part of the constructor.
    #
    # `_open_item` is whether the item most recently taken into scope still
    # owes a disposition. Tracking ONE item at a time, rather than a count
    # of outstanding ones, is what makes two opposite errors unable to
    # cancel: a missed disposition is charged to `_unaccounted` the moment
    # the NEXT note_eligible() arrives, so a later item recording two
    # dispositions finds no open item and raises instead of consuming the
    # earlier item's slot.
    #
    # `_stray_dispositions` counts dispositions that no eligible item can
    # account for: a loop that never called note_eligible(), or a second
    # disposition for an item already closed. Both surface through
    # `over_accounted`.
    _open_item:          bool = field(default=False, init=False, repr=False, compare=False)
    _unaccounted:        int = field(default=0, init=False, repr=False, compare=False)
    _stray_dispositions: int = field(default=0, init=False, repr=False, compare=False)

    @property
    def skipped_oversize(self) -> int:
        """Derived, never stored: the count and the retained targets are
        the same fact, so there is nothing for them to drift apart on."""
        return len(self.skipped_oversize_targets)

    def note_eligible(self, size_bytes: int = 0):
        """One item passed this scan's own filters and is now IN SCOPE:
        the loop owes it exactly one disposition before the iteration
        ends. Call this ONCE per item, after the filter block and before
        any disposition -- an item filtered out before this call was never
        in scope and is not a coverage gap.

        `size_bytes` is that item's captured size, accumulated into
        `eligible_bytes`."""
        if self._open_item:
            # The previous item's iteration ended without a disposition.
            # Charged here, to that item, rather than inferred later from
            # a total-vs-accounted subtraction that a second error in the
            # opposite direction would cancel out.
            self._unaccounted += 1
        self.total += 1
        self.eligible_bytes += int(size_bytes)
        self._open_item = True

    def _note_disposition(self, caller: str):
        """Close the open eligible item, or -- when none is open -- record
        that this outcome belongs to no eligible item at all."""
        if self._open_item:
            self._open_item = False
            return
        # No open item: either this loop never takes items into scope at
        # all, or it is recording a second disposition for the item it
        # just closed. Both belong to no eligible item, so both land in
        # `over_accounted` -- and neither can cancel out a MISSED
        # disposition, which `note_eligible()` has already charged to the
        # item it happened to.
        if self.strict:
            raise RuntimeError(
                f"{caller}() recorded a disposition with no eligible item open "
                f"(after {self.total} note_eligible() call(s)): dispositions "
                f"(scanned/not_applicable/budget_skipped/read_failed/skipped_oversize) are mutually "
                f"exclusive, exactly one per note_eligible(). A short read is an "
                f"ANNOTATION, not a disposition -- note_short_read() alongside "
                f"note_scanned() is the supported way to record one.")
        self._stray_dispositions += 1

    def note_skipped_oversize(self, target: ScanTarget):
        """`target` is required -- a skip that can't name what it skipped
        is exactly the unactionable shape this tracker moved away from."""
        if type(target) is not ScanTarget:
            raise TypeError(
                f"note_skipped_oversize() requires a ScanTarget identifying the skipped "
                f"region/segment, got {type(target).__name__}")
        self._note_disposition("note_skipped_oversize")
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
        """Disposition: the read raised, or came back with nothing usable
        at all. A read that came back SHORT but non-empty is not this --
        its readable prefix is still scanned, so it is note_scanned() plus
        a note_short_read() annotation."""
        self._note_disposition("note_read_failed")
        self.read_failed += 1
        self._note_target(target, self.read_failed_targets, "note_read_failed")

    def note_short_read(self, target: "ScanTarget | None" = None):
        """ANNOTATION, not a disposition: fewer bytes came back than the
        item declared, and the readable prefix IS being scanned. The same
        item therefore also takes a note_scanned() disposition -- this
        call deliberately does not close it, and must not be counted
        against `total` a second time."""
        self.short_reads += 1
        self._note_target(target, self.short_read_targets, "note_short_read")

    def note_not_applicable(self):
        """Disposition: read fine, but there was nothing analyzable to do
        with it (too few bytes to score, wrong shape for this layer, ...).
        NOT a coverage gap -- it does not make `complete` False -- but it
        IS an outcome, so the item still reconciles rather than reading as
        an unrecorded loss."""
        self._note_disposition("note_not_applicable")
        self.not_applicable += 1

    def note_budget_skipped(self):
        """Disposition: in scope and analyzable, but a whole-scan budget
        was already spent, so nothing examined it. NOT a coverage gap on
        its own -- the budget's own exhausted flag carries that -- and
        deliberately not `scanned`, which claims the item WAS examined."""
        self._note_disposition("note_budget_skipped")
        self.budget_skipped += 1

    def note_scanned(self):
        self._note_disposition("note_scanned")
        self.scanned += 1

    @property
    def accounted(self) -> int:
        """Eligible items that reached a disposition."""
        return (sum(getattr(self, name) for name in self.DISPOSITION_COUNTERS)
                + self.skipped_oversize)

    @property
    def unaccounted(self) -> int:
        """Eligible items that reached NO disposition -- a scan loop that
        walked past an item without recording what happened to it. Counted
        per item as it happens, including the item still open when the
        loop ends."""
        return self._unaccounted + (1 if self._open_item else 0)

    @property
    def over_accounted(self) -> int:
        """The other direction: outcomes that belong to no eligible item --
        a loop that never took its items into scope, or one that recorded
        a second disposition for an item it had already closed."""
        return self._stray_dispositions

    @property
    def ledger_imbalance(self) -> int:
        """Items with no trustworthy outcome BEYOND the two direction
        counts:

            accounted + unaccounted == total + over_accounted

        Redundant with those counts while the note_* methods are the only
        thing touching the counters, and kept deliberately: it is what
        catches one incremented directly, around them."""
        return abs(self.accounted + self.unaccounted - self.total - self.over_accounted)

    @property
    def reconciled(self) -> bool:
        """Every eligible item accounted for exactly once, nothing
        accounted for that was never eligible, and the books balancing --
        see `ledger_imbalance`."""
        return (not self.unaccounted and not self.over_accounted
                and not self.ledger_imbalance)

    @property
    def complete(self) -> bool:
        """A POSITIVE assertion: every eligible item reached a recorded
        outcome AND none of those outcomes was a gap. "No gap was
        reported" is not enough on its own -- an item the loop never
        recorded anything for reports no gap either."""
        return self.reconciled and not (self.skipped_oversize or self.read_failed
                                        or self.short_reads or self.budget_exhausted)
