"""RWX region and hidden-PE-header memory scans. Only collects facts —
never scores, never prints.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import (
    get_modules, get_memory_regions, addr_to_module, prot_str,
    va_to_file_offset, va_range_captured_bytes,
)
from dumpex.core.pe_utils import parse_pe_header
from dumpex.hunt._coverage import region_scan_target
from dumpex.hunt._location import resolve_location
from dumpex.hunt.injection.config import (
    PE_SCAN_DEGRADED_READ, PE_SCAN_MAX_READS_PER_REGION, PE_SCAN_MAX_UNVALIDATED_EVIDENCE,
    PE_SCAN_MAX_VALIDATED_EVIDENCE, PE_SCAN_MAX_VALIDATIONS_PER_REGION,
    PE_SCAN_MAX_VALIDATIONS_TOTAL, PE_SCAN_TOTAL_BYTES_MAX, PE_SCAN_WINDOW,
    PE_VALIDATE_READ_MAX,
)
from dumpex.hunt.injection.models import (
    HiddenPeScan, RegionRef, PeHeaderInfo, RwxRegionEvidence, HiddenPeEvidence, BudgetTargetGroup,
)
from dumpex.output.coverage import ScanTarget, ScanTargetKind

# Read outcomes shared by every read the candidate search makes (discovery
# read, degraded re-read, last-resort marker probe, validation read) -- the
# ONE vocabulary `_scan_region_for_pe` maps onto the coverage facts a
# HiddenPeScan carries (read_failed / short_reads / scan_truncated).
_READ_OK       = "ok"        # every requested byte came back
_READ_SHORT    = "short"     # fewer bytes than requested, no exception
_READ_FAILED   = "failed"    # the read itself raised
_READ_BUDGET   = "budget"    # not attempted: a read/byte budget is spent

# The candidate marker, searched for at EVERY byte offset -- not at page
# (or any other) stride. Consecutive discovery reads therefore overlap by
# len(_MZ) - 1 bytes, so a marker straddling the boundary between two
# reads is still whole inside exactly one of them (never both -- see
# `_scan_region_for_pe`, which relies on that to report each candidate
# once).
_MZ = b'MZ'
_MZ_OVERLAP = len(_MZ) - 1


def region_ref(r) -> RegionRef:
    """Convert a raw minidump Region into an immutable RegionRef -- the
    ONE place this hunter reads a region's raw Type/Protect enum values
    and formats them via prot_str(), so every Evidence type that carries
    "a region" (RWX/hidden-PE/RIP-hit/StartAddress-hit) does so with the
    SAME already-formatted strings, never a second prot_str() call at a
    different layer. Used by this module and by
    dumpex.hunt.injection.correlation (the only other place a raw Region
    is ever converted)."""
    return RegionRef(base_address=r.BaseAddress, allocation_base=r.AllocationBase,
                      size=r.RegionSize, type=prot_str(r.Type), protect=prot_str(r.Protect))


def _pe_header_info(pe: dict) -> PeHeaderInfo:
    """Project dumpex.core.pe_utils.parse_pe_header()'s dict down to the
    lean, immutable PeHeaderInfo this hunter actually consumes -- see that
    type's own docstring for which fields (and why only those)."""
    return PeHeaderInfo(
        valid=pe['valid'], machine_name=pe['machine_name'], is_pe32_plus=pe['is_pe32_plus'],
        number_of_sections=pe['number_of_sections'], address_of_entry_point=pe['address_of_entry_point'],
        image_base=pe['image_base'], reason=pe['reason'])


def _is_suspicious_rwx(protect: str, mtype: str) -> bool:
    """
    PAGE_EXECUTE_READWRITE is always suspicious — no legitimate loader
    grants direct, non-copy-on-write write access to executable memory.

    PAGE_EXECUTE_WRITECOPY is different: on a MEM_IMAGE-backed region it
    is Windows' NORMAL, unmodified-mapping copy-on-write protection for
    executable sections (see core.pe_utils.NORMAL_IMAGE_PROTECTIONS) —
    flagging it there makes every ordinary, untouched DLL "suspicious".
    On anything NOT image-backed (MEM_PRIVATE/MEM_MAPPED), WRITECOPY has
    no such benign explanation and is still worth flagging.
    """
    if protect == "PAGE_EXECUTE_READWRITE":
        return True
    if protect == "PAGE_EXECUTE_WRITECOPY":
        return mtype != "MEM_IMAGE"
    return False


def _hunt_rwx(mf: MinidumpFile) -> tuple:
    """Return tuple of RwxRegionEvidence -- each built here, at the scan
    boundary, WITH its file offset already resolved (see
    dumpex.hunt._location.resolve_location) -- so aggregate.py never
    needs `mf` or a separate region-BaseAddress -> Location lookup table."""
    regions = get_memory_regions(mf)
    hits = []
    for r in regions:
        if r.RegionSize <= 0:
            # A zero-length region spans no address a hit could sit at:
            # `resolve_location` places a VA INSIDE its region, which a
            # region of no extent has nowhere to do.
            continue
        if _is_suspicious_rwx(prot_str(r.Protect), prot_str(r.Type)):
            hits.append(RwxRegionEvidence(
                region=region_ref(r),
                location=resolve_location(mf, r.BaseAddress, r.BaseAddress, region_size=r.RegionSize)))
    return tuple(hits)


def _or_default(value, default):
    """`value` unless it is None -- `0` is a legitimate (and useful, in a
    test) budget meaning "nothing at all", so `value or default` would be
    wrong here."""
    return default if value is None else value


class _ScanBudget:
    """Every bound the hidden-PE candidate search runs under, in ONE
    place, shared by every region of a single `_hunt_hidden_pe` call.

    The search reads eligible memory end to end and looks for 'MZ' at any
    byte offset, so the dump -- attacker-supplied input -- decides how much
    work it asks for. Four independent things have to stay bounded, and
    each has its own counter because they fail for different reasons and
    mean different things in a report:

      reads / bytes  -- how much gets READ. Per-region read count bounds a
                        malformed RegionSize or a region whose reads keep
                        failing; whole-hunt bytes bound the total I/O.
      validations    -- how many parse_pe_header calls happen (one per
                        'MZ' found). A region carrying 'MZ' every other
                        byte would otherwise be ~500k parses per MB.
      evidence       -- how many hits are RETAINED, and therefore how
                        large the reported finding list and the JSON
                        document built from it can grow.

    Read/byte/validation exhaustion means memory was left UNSEARCHED, so
    it raises `scan_truncated` on the affected region and shows up as
    partial coverage. Evidence exhaustion is different: those candidates
    were searched and examined, only not all kept, so it is reported as an
    explicit count on the corresponding check (see aggregate.py) rather
    than as a coverage gap. Validated PE headers are retained in
    preference to unvalidated 'MZ' prefixes -- the first drive score and
    correlation, the second are informational, and incidental 'MZ' bytes
    are common enough in ordinary memory (~16 per MB) that keeping every
    one would bury the hits that matter.
    """

    def __init__(self, *, total_bytes: "int | None" = None,
                  reads_per_region: "int | None" = None,
                  validations_per_region: "int | None" = None,
                  validations_total: "int | None" = None,
                  validated_evidence: "int | None" = None,
                  unvalidated_evidence: "int | None" = None):
        # `None` means "whatever this module's own global says right now",
        # resolved HERE rather than as a default argument value: a default
        # is bound once, at import, so a test (or a future config object)
        # setting memory_scan.PE_SCAN_* would be silently ignored -- the
        # same call-time-lookup rule the facade applies to `read_region`
        # (see dumpex/hunt/_runtime.py).
        self.bytes_left = _or_default(total_bytes, PE_SCAN_TOTAL_BYTES_MAX)
        self.validations_left = _or_default(validations_total, PE_SCAN_MAX_VALIDATIONS_TOTAL)
        self.validated_slots_left = _or_default(validated_evidence, PE_SCAN_MAX_VALIDATED_EVIDENCE)
        self.unvalidated_slots_left = _or_default(unvalidated_evidence,
                                                    PE_SCAN_MAX_UNVALIDATED_EVIDENCE)
        self._reads_per_region = _or_default(reads_per_region, PE_SCAN_MAX_READS_PER_REGION)
        self._validations_per_region = _or_default(validations_per_region,
                                                     PE_SCAN_MAX_VALIDATIONS_PER_REGION)
        self.reads_left = self._reads_per_region
        self.region_validations_left = self._validations_per_region
        self.validated_dropped = 0
        self.unvalidated_dropped = 0
        # The ORIGINAL whole-hunt limits, kept alongside the two "_left"
        # counters that count down from them -- needed so a later
        # `exhausted_budget_info()` call can report "limit=N" after
        # `bytes_left`/`validations_left` have already been spent down
        # past it (issue #28 P4 follow-up).
        self._total_bytes_limit = self.bytes_left
        self._validations_total_limit = self.validations_left
        # Which of the four independent budgets (see this class's own
        # docstring) most recently stopped a `take_read()`/
        # `take_validation()` call, and that budget's own limit -- set
        # only on a failing call, read by the caller immediately after
        # (see `_stop_on_budget`/`_scan_region_for_pe`'s own `_on_bytes`),
        # so it always reflects the SPECIFIC exhaustion that just
        # happened, never a stale one from an earlier, different stop.
        self.last_exhausted_kind = None

    def start_region(self) -> None:
        """Reset the per-region allowances. The whole-hunt ones (bytes,
        validations, evidence slots) deliberately carry over -- a dump
        must not be able to multiply its total cost simply by declaring
        its pathological memory as many small regions instead of one big
        one."""
        self.reads_left = self._reads_per_region
        self.region_validations_left = self._validations_per_region

    def take_read(self) -> bool:
        """Checked in the same order the returned bool always implied
        (issue #28 P4 follow-up makes it explicit): the per-region read
        allowance first, then the whole-hunt byte budget -- `reads_left`
        is checked, and always decremented, before `bytes_left` is even
        looked at, so a call that fails BOTH is attributed to
        `reads_per_region`, matching this method's own prior (implicit,
        via Python's `and` short-circuit over the same two comparisons in
        the same order) behavior exactly."""
        self.reads_left -= 1
        if self.reads_left < 0:
            self.last_exhausted_kind = "reads_per_region"
            return False
        if self.bytes_left <= 0:
            self.last_exhausted_kind = "total_bytes"
            return False
        return True

    def cap_to_remaining_bytes(self, want: int) -> int:
        """Clamp a requested read size to what remains of the whole-hunt
        byte budget, so the byte cap is actually a HARD ceiling on bytes
        requested -- not just a counter that goes negative after the fact.
        Without this, a single `want=PE_SCAN_WINDOW` read issued with only
        a few bytes of budget left still asks the real I/O layer for the
        full window, and `bytes_left` merely records the overshoot instead
        of preventing it -- on production `read_region`, that is a real
        extra read of up to one window's worth of bytes past the budget
        the caller configured."""
        return max(0, min(want, self.bytes_left))

    def spend_bytes(self, count: int) -> None:
        self.bytes_left -= count

    def take_validation(self) -> bool:
        """Same "checked (and attributed) in the same order the return
        value always implied" rule as `take_read()`: the whole-hunt
        validation budget first, then the per-region one."""
        self.validations_left -= 1
        self.region_validations_left -= 1
        if self.validations_left < 0:
            self.last_exhausted_kind = "validations_total"
            return False
        if self.region_validations_left < 0:
            self.last_exhausted_kind = "validations_per_region"
            return False
        return True

    def limit_for_kind(self, kind: str) -> int:
        """The configured limit for one of the four budget-kind strings
        (issue #28 P5 follow-up) -- fixed for this `_ScanBudget`'s whole
        lifetime, so every region attributed to the same `kind` within one
        `_hunt_hidden_pe` call shares the identical limit value. Used both
        by `exhausted_budget_info()` (below) and, directly, by
        `_hunt_hidden_pe`'s own per-kind `BudgetTargetGroup` construction,
        which already has the kind (from `gaps.budget_kind`) but not a
        fresh `exhausted_budget_info()` call reflecting it (that reflects
        only the MOST RECENT stop, which may be a different region's)."""
        return {
            "reads_per_region":        self._reads_per_region,
            "total_bytes":             self._total_bytes_limit,
            "validations_per_region":  self._validations_per_region,
            "validations_total":       self._validations_total_limit,
        }[kind]

    def exhausted_budget_info(self) -> "tuple | None":
        """(kind, limit, consumed) for whichever budget `last_exhausted_
        kind` names, or `None` before any `take_read()`/`take_validation()`
        call has ever failed. `consumed` always equals `limit` here: by
        definition, a budget is only ever attributed as the exhaustion
        reason once its own configured allowance has been fully used --
        this is not a running/partial consumption figure, just the
        confirmation of how much WAS available before the scan stopped
        (issue #28 P4 follow-up: "which budget, and its own limit/
        consumed" -- see dumpex.output.coverage's PE_HEADER_SCAN_TRUNCATED/
        _SCAN_NOT_STARTED `scope`/`detail` wiring for where this surfaces
        on the wire)."""
        kind = self.last_exhausted_kind
        if kind is None:
            return None
        limit = self.limit_for_kind(kind)
        return kind, limit, limit

    def take_evidence_slot(self, valid: bool) -> bool:
        """Reserve a slot for one hit, counting the drop when there is
        none left. Valid and invalid hits draw on separate pools rather
        than one shared pool, so a flood of unvalidated 'MZ' can never
        crowd out the validated PE headers that actually drive a verdict
        -- whichever order the scan happens to encounter them in."""
        if valid:
            if self.validated_slots_left > 0:
                self.validated_slots_left -= 1
                return True
            self.validated_dropped += 1
            return False
        if self.unvalidated_slots_left > 0:
            self.unvalidated_slots_left -= 1
            return True
        self.unvalidated_dropped += 1
        return False


class _BudgetedReader:
    """`read_region` plus the read/byte budget, and the ONE place a raise,
    a short return, or an exhausted budget is turned into the `_READ_*`
    vocabulary above.

    `read_region` is the caller's own (still monkeypatchable) callable,
    threaded in exactly as `_hunt_hidden_pe` receives it -- this class
    never imports one of its own (see dumpex/hunt/_runtime.py).
    """

    def __init__(self, read_region, mf, budget: _ScanBudget):
        self._read_region = read_region
        self._mf = mf
        self._budget = budget

    def read(self, va: int, want: int) -> tuple:
        """Return (data, status). `data` is always bytes -- never None --
        so callers can slice it without a separate None check; the status
        is what tells them whether those bytes are the whole story.

        `want` is capped to the remaining byte budget BEFORE the
        underlying `read_region` is ever called -- the byte budget bounds
        what gets ASKED for, not just what gets counted afterward (see
        `_ScanBudget.cap_to_remaining_bytes`). A read capped this way
        returns `_READ_BUDGET` even when bytes DID come back: the caller
        must still scan whatever was returned (real data, not a dump-side
        short read) before it stops -- see `_scan_span`'s own handling of
        that status."""
        if not self._budget.take_read():
            return b'', _READ_BUDGET
        capped = self._budget.cap_to_remaining_bytes(want)
        if capped <= 0:
            return b'', _READ_BUDGET
        try:
            data = self._read_region(self._mf, va, capped)
        except Exception:
            return b'', _READ_FAILED
        data = data or b''
        self._budget.spend_bytes(len(data))
        if capped < want:
            return data, _READ_BUDGET
        return data, (_READ_OK if len(data) >= want else _READ_SHORT)


class _ScanGaps:
    """Per-region facts describing unexamined search bytes.

    read_failed, short_read, truncated, and not_started count regions, not read
    calls. examined_until marks the first unexamined byte; validation-budget
    exhaustion stops it at the unvalidated candidate rather than the buffer end.

    Budget attribution is present only for truncated or not-started gaps and
    records which independent resource stopped that region.
    """

    def __init__(self):
        self.read_failed = False
        self.short_read = False
        self.truncated = False
        self.not_started = False
        self.examined_until = 0
        self.budget_kind = None
        self.budget_limit = None
        self.budget_consumed = None

    def note(self, status: str) -> None:
        """Record one non-OK read status. `_READ_OK` is deliberately
        accepted and ignored, so callers can hand every status here
        without first testing for the successful one."""
        if status == _READ_FAILED:
            self.read_failed = True
        elif status == _READ_SHORT:
            self.short_read = True
        elif status == _READ_BUDGET:
            self.truncated = True

    def set_budget_info(self, budget: "_ScanBudget") -> None:
        """Attribute the CURRENT budget stop to this region -- called
        exactly once per region, at the single point (`_stop_on_budget`,
        or `_on_bytes`'s own validation-budget branch) that actually
        stops that region's scan on a budget, so `budget.
        exhausted_budget_info()` still reflects the failure that just
        happened."""
        info = budget.exhausted_budget_info()
        if info is not None:
            self.budget_kind, self.budget_limit, self.budget_consumed = info


def _mz_offsets(data: bytes):
    """Yield the offset of every 'MZ' in `data`, at ANY byte position --
    the whole point of the byte-wise search (issue #26): an image whose
    header is not page- (or otherwise) aligned is found like any other.
    `bytes.find` does the scanning in C, ~0.5 ms per MB, so the cost of
    looking everywhere is the read, not the search."""
    idx = data.find(_MZ)
    while idx != -1:
        yield idx
        idx = data.find(_MZ, idx + 1)


def _pe_validation_bytes(reader: _BudgetedReader, region_base: int, region_size: int,
                          offset: int, have: bytes, validate_max: int) -> tuple:
    """Return (bytes, status): the bytes to hand parse_pe_header for the
    candidate at region `offset`, and how completely they were obtained.

    `have` is whatever this candidate's discovery already returned (at
    minimum its 2-byte 'MZ' marker). When the discovery read already
    covers the full validation span, that IS the validation read -- no
    second read is issued for it, which is what keeps a candidate found
    mid-window free of extra I/O. Otherwise the validation read happens at
    the CANDIDATE's own address, not the region base.

    Never returns fewer bytes than `have`: a failed or short validation
    read falls back to the bytes already in hand, so the candidate is
    still reported (parse_pe_header supplies its own truncation reason)
    rather than dropped -- the caller records the corresponding coverage
    fact instead."""
    want = min(validate_max, region_size - offset)
    if len(have) >= want:
        return have[:want], _READ_OK
    data, status = reader.read(region_base + offset, want)
    return (data if len(data) > len(have) else have), status


def _stop_on_budget(budget: _ScanBudget, pos: int, data: bytes, gaps: _ScanGaps, on_bytes) -> bool:
    """The one place a `_READ_BUDGET` status is turned into "stop
    scanning". `data` may be non-empty -- the byte budget caps how many
    bytes are ASKED for (see `_BudgetedReader.read`), so a capped read
    still returns whatever real bytes it got back before running out.
    Those bytes were actually read from the dump and must still be
    examined -- scanning them first, and marking the gap only after,
    is what keeps a budget cap from silently discarding data it already
    paid for. Always returns False: a budget stop is never something the
    caller can continue past.

    `not_started` (issue #28) fires only when `pos == 0` and `data` is
    empty: the FIRST read this region's own search ever attempted was
    itself refused by an already-exhausted whole-hunt budget (bytes/
    validations carry over between regions -- see `_ScanBudget.
    start_region()` -- so a LATER region can start already out of
    budget), meaning nothing about this region was examined at all. Any
    other stop -- `pos > 0` (this region's own search already read some
    of it before running out), or `data` non-empty at `pos == 0` (a
    capped-but-nonempty first read) -- is a genuine unfinished remainder,
    not an unstarted region, and stays plain `truncated`.

    `gaps.set_budget_info(budget)` (issue #28 P4 follow-up) is called
    right here, at the exact point `take_read()` (the only way this
    status is ever reached) just failed -- `budget.last_exhausted_kind`
    still names THAT failure, not a later or earlier one."""
    if data:
        on_bytes(pos, data)
    gaps.truncated = True
    gaps.set_budget_info(budget)
    if pos == 0 and not data:
        gaps.not_started = True
    return False


def _scan_span(reader: _BudgetedReader, budget: _ScanBudget, region_base: int, region_size: int,
                start: int, span: int, read_sizes: tuple, gaps: _ScanGaps, on_bytes) -> bool:
    """
    Read [start, start+span) of a region and hand every piece that comes
    back to `on_bytes(offset, data)`. Returns True when the whole span was
    covered, False when scanning must stop -- the reason having already
    been recorded on `gaps` (or, for a budget `on_bytes` itself owns, by
    `on_bytes`).

    Consecutive reads advance by `size - _MZ_OVERLAP`, so each piece
    overlaps the previous one by exactly the marker length minus one byte.
    That is what makes the byte-wise search whole-region rather than
    per-read: a marker straddling two pieces is complete in the LATER of
    them and in only that one, so no candidate is missed and none is
    reported twice.

    `read_sizes` is a descending ladder of read sizes to try, e.g.
    (PE_SCAN_WINDOW, PE_SCAN_DEGRADED_READ). A read that RAISES is not
    treated as "this span is unreadable" -- a minidump's buffered reader
    raises for a span crossing the end of a captured segment while still
    serving smaller reads inside it -- so the failing piece is retried at
    the next size down. Below the last size the only thing left worth
    trying is the marker itself: one exact-length probe at that offset,
    which is precisely the region-base check this scan performed before it
    searched whole regions, and which keeps this search a strict superset
    of that one even in a dump that can barely be read. Its failure ends
    the region (`read_failed`): past the point the dump stops supplying
    bytes there is nothing to find, only the same failure once per read.
    """
    size = read_sizes[0]
    pos = start
    end = start + span
    while pos < end:
        # Bounded by `end - pos`, not just `region_size - pos`: a
        # RECURSIVE call (the degraded-read fallback below) is scanning
        # only its OWN slice of the region, `[start, start+span)`, which
        # can be narrower than the whole region. Without this bound, a
        # read near the recursive slice's own end could still ask for (and
        # scan) bytes past it -- into the span the calling frame has
        # already covered, or will cover next -- so the same candidate
        # offset gets found, and reported, twice.
        want = min(size, end - pos, region_size - pos)
        data, status = reader.read(region_base + pos, want)

        if status == _READ_BUDGET:
            return _stop_on_budget(budget, pos, data, gaps, on_bytes)

        if status == _READ_FAILED:
            if len(read_sizes) > 1:
                if not _scan_span(reader, budget, region_base, region_size, pos,
                                   min(size, end - pos), read_sizes[1:], gaps, on_bytes):
                    return False
                pos += max(1, size - _MZ_OVERLAP)
                continue
            marker, marker_status = reader.read(region_base + pos, min(len(_MZ), region_size - pos))
            if marker_status == _READ_BUDGET:
                return _stop_on_budget(budget, pos, marker, gaps, on_bytes)
            if marker_status == _READ_OK:
                if not on_bytes(pos, marker):
                    return False
                # Even a SUCCESSFUL marker probe leaves this piece
                # unexamined past its first two bytes -- the smallest read
                # available already failed, so the gap is real whether or
                # not those two bytes happened to be 'MZ'.
                gaps.read_failed = True
            else:
                gaps.note(marker_status)
            return False

        # Never scan more bytes than were asked for: a reader handing back
        # a longer buffer than requested must not be able to push this
        # search past the region's own end, into evidence about memory
        # that is not this region's at all.
        returned = min(len(data), want)
        if not on_bytes(pos, data[:returned]):
            return False

        if status == _READ_SHORT:
            # The bytes past what came back were never returned, so the
            # rest of the region went unexamined -- but only count that as
            # a gap when a marker could still START there. A region whose
            # final read came back a few bytes short of the region end
            # still had every byte a candidate could begin at examined.
            gaps.short_read = gaps.short_read or (pos + returned < region_size)
            return False
        pos += max(1, size - _MZ_OVERLAP)
    return True


def _scan_region_for_pe(reader: _BudgetedReader, budget: _ScanBudget, region_base: int,
                         region_size: int, on_candidate, *, window: int = PE_SCAN_WINDOW,
                         degraded_read: int = PE_SCAN_DEGRADED_READ,
                         validate_max: int = PE_VALIDATE_READ_MAX) -> _ScanGaps:
    """
    Search ONE eligible region for hidden-PE candidates, calling
    `on_candidate(region_offset, bytes)` for every 'MZ' found -- with the
    bytes its structural validation should parse -- and return the
    `_ScanGaps` describing anything the search could not examine.

    Candidates are handed over as they are found rather than collected
    into a list: a dump can carry an unbounded number of them, and the
    caller (`_hunt_hidden_pe`) validates and applies its evidence cap
    immediately, so nothing proportional to the CANDIDATE count is ever
    held in memory -- only what is actually retained as evidence.
    """
    def _on_bytes(offset: int, data: bytes) -> bool:
        # `examined_until` only advances past a byte once this window's
        # search of it is actually DONE (issue #28 P3 follow-up). Reads
        # being real is not the same as those bytes being examined: the
        # for-loop below can still stop partway through `data` (a
        # validation-budget exhaustion), and everything from that
        # candidate's own offset onward was never checked, whether or not
        # the bytes happened to already be sitting in `data`. Advancing to
        # `offset + len(data)` unconditionally here (a prior version of
        # this function did exactly that) claimed the WHOLE window --
        # up to PE_SCAN_WINDOW bytes -- was examined even when the budget
        # died on the very first candidate, silently excluding most of an
        # unfinished window from the reported truncated target.
        for hit in _mz_offsets(data):
            if not budget.take_validation():
                gaps.examined_until = max(gaps.examined_until, offset + hit)
                gaps.truncated = True
                gaps.set_budget_info(budget)
                return False
            candidate = offset + hit
            deep, status = _pe_validation_bytes(
                reader, region_base, region_size, candidate,
                data[hit:hit + validate_max], validate_max)
            gaps.note(status)
            if status == _READ_BUDGET:
                # A candidate's OWN validation read (not the discovery
                # window read `_stop_on_budget` handles) can hit the
                # read/byte budget too -- `note()` above already marks
                # `gaps.truncated`, so attribute it right here rather
                # than leaving `budget_kind` unset until (if ever) a
                # LATER top-level read also hits `_stop_on_budget`.
                gaps.set_budget_info(budget)
            on_candidate(candidate, deep)
        # Every candidate in this window was processed (the loop above
        # never returned early), so the whole window was genuinely
        # byte-searched for 'MZ' -- NOW it is safe to advance past it.
        gaps.examined_until = max(gaps.examined_until, offset + len(data))
        return True

    gaps = _ScanGaps()
    _scan_span(reader, budget, region_base, region_size, 0, region_size,
                (window, degraded_read), gaps, _on_bytes)
    return gaps


def _remainder_scan_target(mf: MinidumpFile, region, examined_until: int) -> ScanTarget:
    """A ScanTarget for the UNEXAMINED remainder of one region (issue #28
    P2 follow-up) -- `[region.BaseAddress + examined_until,
    region.BaseAddress + region.RegionSize)`, not the whole region.

    A `PE_HEADER_SCAN_TRUNCATED` region's own search may already have
    fully examined a real PREFIX of it before a scan-budget stop (see
    `_ScanGaps.examined_until`'s own docstring) -- reporting the WHOLE
    region as the gap would be inaccurate (part of it genuinely was
    searched and came up clean) and would send a targeted rescan back
    over bytes that don't need it. This is a DIFFERENT target from what
    `region_scan_target(mf, region)` would build for the same region: the
    address, size, file offset, and captured-bytes count all describe
    only the remaining, still-unsearched sub-range, even though
    `allocation_base`/`state`/`type`/`protection` still describe the
    SAME underlying allocation (those MemoryInfo facts are properties of
    the allocation as a whole, not of any particular byte sub-range
    within it).

    Falls back to the WHOLE region (mirroring `region_scan_target(mf,
    region)`) if `examined_until` somehow covers the entire region --
    defensive only: every real `PE_HEADER_SCAN_TRUNCATED` call site stops
    strictly before the region's own end (see `_stop_on_budget`'s own
    docstring), so there is always a genuine, positive-size remainder in
    practice."""
    remainder_base = region.BaseAddress + examined_until
    remainder_size = region.RegionSize - examined_until
    if remainder_size <= 0:
        remainder_base, remainder_size = region.BaseAddress, region.RegionSize
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_REGION,
        base_address=remainder_base,
        size=remainder_size,
        file_offset=va_to_file_offset(mf, remainder_base),
        allocation_base=getattr(region, "AllocationBase", None),
        state=prot_str(region.State),
        type=prot_str(region.Type),
        protection=prot_str(region.Protect),
        captured_size=va_range_captured_bytes(mf, remainder_base, remainder_size),
        # The target IS the remainder, so nothing inside it was searched:
        # the prefix that was is deliberately not part of this range.
        examined_size=0,
    )


def _hunt_hidden_pe(mf: MinidumpFile, read_region, module_list_available: bool = True,
                     budget: "_ScanBudget | None" = None) -> HiddenPeScan:
    """Search eligible regions for hidden-PE candidates under one hunt budget.

    Without ModuleListStream, return no hits because an empty module view cannot
    distinguish legitimate images from hidden ones. Search every byte offset,
    retain each candidate's own VA and dump offset, and return validated and
    MZ-only evidence separately.

    Read exceptions, short reads, partly scanned regions, and regions never
    started are distinct coverage facts. Read, byte, validation, and evidence
    limits apply across the whole call so splitting attacker-controlled memory
    into regions cannot multiply work. Examined-but-dropped candidates are
    counted as evidence caps rather than unread coverage.
    """
    if not module_list_available:
        return HiddenPeScan(hits=(), read_failed=0, short_reads=0, scan_truncated=0)
    modules = get_modules(mf)
    budget = budget if budget is not None else _ScanBudget()
    reader = _BudgetedReader(read_region, mf, budget)
    hits = []
    read_failed = 0
    read_failed_targets = []
    short_reads = 0
    short_read_targets = []
    scan_truncated = 0
    scan_truncated_by_kind = {}    # budget_kind -> list[ScanTarget] -- issue #28 P5 follow-up
    scan_not_started = 0
    scan_not_started_by_kind = {}  # budget_kind -> list[ScanTarget] -- issue #28 P5 follow-up
    # Captured bytes this search had in front of it: accumulated as each
    # region clears the filters below, which is where it enters this
    # pass's scope. A region the whole-hunt budget then abandoned is
    # counted here too, because it entered the scope before the budget
    # ended the search and it is reported as a gap on the way out.
    eligible_bytes = 0
    for r in get_memory_regions(mf):
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.RegionSize <= 0:
            # A zero-length region holds no candidate header, and a
            # ScanTarget cannot name it -- a target has an extent by
            # definition, which every gap recorded below relies on.
            continue
        # Membership is a RANGE check (addr_to_module), not "does this
        # region's BaseAddress exactly equal a module's base" — a prior
        # version used `r.BaseAddress in {m.baseaddress for m in modules}`,
        # which only matches a module's very first page. Any OTHER region
        # belonging to that same module (e.g. a resource section carrying
        # an embedded PE/icon/update payload, or any sub-region a
        # VirtualProtect call split off) has a BaseAddress that is never
        # any module's baseaddress, so it was always misclassified as
        # "unregistered" regardless of being entirely inside a known,
        # legitimately loaded module.
        owner = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == "MEM_IMAGE" and owner is not None:
            continue   # inside a known module — not a hidden-PE candidate at all
        # Past every filter: this region is IN SCOPE for the search. What
        # the DUMP holds for it, never the declared RegionSize, so the
        # scale matches the basis its own gaps are measured on.
        eligible_bytes += va_range_captured_bytes(mf, r.BaseAddress, r.RegionSize)
        def _keep(offset: int, data: bytes, region=r, owner=owner) -> None:
            """Validate ONE candidate and keep it if there is an evidence
            slot for it. Done here, as each candidate is found, rather than
            over a collected list: a dump can carry an unbounded number of
            candidates, so nothing proportional to that count may ever be
            held -- only what is retained. `region`/`owner` are bound as
            defaults so this closure describes the region it was built for
            even though the loop rebinds those names."""
            pe = _pe_header_info(parse_pe_header(data))
            if not budget.take_evidence_slot(pe.valid):
                return
            # owner is already known from the range check above for MEM_IMAGE
            # regions; a non-image region can still fall inside a module's
            # declared [baseaddress, endaddress) span in principle, so the
            # same range check is used uniformly rather than re-deriving it.
            hits.append(HiddenPeEvidence(
                region=region_ref(region), pe=pe, in_module_list=owner is not None,
                location=resolve_location(mf, region.BaseAddress + offset, region.BaseAddress,
                                           region_size=region.RegionSize)))

        # Every tunable is looked up HERE, once per region, from this
        # module's own globals -- the same call-time-lookup rule the facade
        # applies to `read_region` (see dumpex/hunt/_runtime.py). Passing
        # them explicitly rather than letting `_scan_region_for_pe`'s
        # defaults supply them keeps a test (or a future config object)
        # able to change one by setting it on this module, which a default
        # argument -- bound once, at import -- would silently ignore.
        budget.start_region()
        gaps = _scan_region_for_pe(
            reader, budget, r.BaseAddress, r.RegionSize, _keep,
            window=PE_SCAN_WINDOW, degraded_read=PE_SCAN_DEGRADED_READ,
            validate_max=PE_VALIDATE_READ_MAX)
        # Counted once per REGION, not once per failed read: these are the
        # same "N region(s) could not be fully examined" coverage counts
        # this scan has always reported (see report_facts.project_coverage_v1
        # / LimitationCode.PE_HEADER_READ_FAILED), and a single region whose
        # search needed many reads must not inflate them into N. `r` is
        # still the raw MemoryInfo region right here, so a ScanTarget for
        # each affected gap is built now (issue #28) rather than reduced to
        # a bare count before it ever reaches HiddenPeScan/CoverageLimitation.
        if gaps.read_failed:
            read_failed += 1
            # Nothing usable came back from this region, so none of its
            # captured bytes were examined -- the exact basis, recorded on
            # the target rather than left for a reader to infer.
            read_failed_targets.append(region_scan_target(mf, r, examined_size=0))
        if gaps.short_read:
            short_reads += 1
            # No examined extent. A CANDIDATE's own validation read can
            # come back short while the window search carries on to the
            # next candidate, and the window then closes by advancing
            # `examined_until` past bytes that read never got -- so it is
            # a high-water mark with holes below it, not a count of bytes
            # examined. (A discovery read that comes back short ends the
            # region instead, and leaves the mark exact.) Passing it here
            # would claim the holes were searched and UNDERSTATE the miss,
            # the one direction this metric must never be wrong in, so the
            # gap is reported as unmeasured instead.
            short_read_targets.append(region_scan_target(mf, r))
        # `not_started` further splits `truncated` into two distinct
        # facts an investigator needs to tell apart (issue #28): a region
        # this search got PART of before running out of budget (an
        # unfinished remainder, still `scan_truncated`) versus a LATER
        # region the whole-hunt budget was already exhausted before its
        # own scan ever read a single byte of (`scan_not_started` --
        # nothing here was examined at all).
        if gaps.truncated:
            # `gaps.budget_kind` is always set here (see `_stop_on_budget`/
            # `_on_bytes`'s own `set_budget_info` calls -- every path that
            # sets `gaps.truncated` also attributes a budget), so grouping
            # by it never needs a "no kind" bucket.
            if gaps.not_started:
                scan_not_started += 1
                # The budget was already spent when this region's turn came
                # up, so its search never issued a read: the whole capture
                # is unexamined, exactly.
                scan_not_started_by_kind.setdefault(gaps.budget_kind, []).append(
                    region_scan_target(mf, r, examined_size=0))
            else:
                scan_truncated += 1
                # The UNEXAMINED REMAINDER, not the whole region (issue
                # #28 P2 follow-up) -- see _remainder_scan_target's own
                # docstring for why that is a different, more precise
                # target than region_scan_target(mf, r) would build here.
                scan_truncated_by_kind.setdefault(gaps.budget_kind, []).append(
                    _remainder_scan_target(mf, r, gaps.examined_until))

    def _groups(by_kind: dict) -> tuple:
        # One BudgetTargetGroup per DISTINCT budget kind that stopped at
        # least one region (issue #28 P5 follow-up) -- see that class's
        # own docstring for why a single first-occurrence attribution for
        # the whole scan was wrong once different regions can stop on
        # different budgets within the same call.
        return tuple(
            BudgetTargetGroup(budget_kind=kind, budget_limit=budget.limit_for_kind(kind),
                               budget_consumed=budget.limit_for_kind(kind), targets=tuple(targets))
            for kind, targets in by_kind.items())

    return HiddenPeScan(hits=tuple(hits), eligible_bytes=eligible_bytes,
                         read_failed=read_failed,
                         read_failed_targets=tuple(read_failed_targets),
                         short_reads=short_reads,
                         short_read_targets=tuple(short_read_targets),
                         scan_truncated=scan_truncated,
                         scan_truncated_groups=_groups(scan_truncated_by_kind),
                         scan_not_started=scan_not_started,
                         scan_not_started_groups=_groups(scan_not_started_by_kind),
                         validated_dropped=budget.validated_dropped,
                         unvalidated_dropped=budget.unvalidated_dropped)


def split_hidden_pe_hits(scan: HiddenPeScan) -> "tuple[tuple, tuple]":
    """
    Split a HiddenPeScan's hits into (validated, mz_only). Only
    STRUCTURALLY VALID hidden PEs count toward correlation/score; an
    MZ candidate that fails header validation is a much weaker
    observation (could be a decoy, a truncated read, or coincidental
    bytes) — see dumpex/hunt/injection/__init__.py's module docstring.
    Computed once here so correlation.py and aggregate.py agree on the
    same split instead of each re-deriving it.
    """
    validated = tuple(h for h in scan.hits if not h.in_module_list and h.pe.valid)
    mz_only   = tuple(h for h in scan.hits if not h.in_module_list and not h.pe.valid)
    return validated, mz_only


def _has_executable_protection(protect: str) -> bool:
    """
    True if `protect` (a prot_str()-rendered Protect name) grants execute
    access. Checked via substring rather than an exact-match set because
    Protect can carry a combined flag name (e.g. "PAGE_EXECUTE_READ|
    PAGE_GUARD") from the underlying enum — every executable PAGE_*
    constant contains "EXECUTE" and no non-executable one does, so this is
    a safe, simpler test than enumerating every combination.
    """
    return "EXECUTE" in protect


def pe_hit_is_context_scoreable(hit) -> bool:
    """
    Classify one validated hidden-PE hit's (a HiddenPeEvidence) OWN memory
    context (before any correlation) as scoreable-by-default or
    context-only/informational. This is a FACT derivation from page type +
    protection — like the rest of this module, it never scores anything
    itself; aggregate.py is still the ONE place score gets computed. A
    context-only classification here can still be PROMOTED to scoreable by
    aggregate.py if correlation.py finds the same AllocationBase carrying
    an RWX region or live thread execution (RIP/EIP or StartAddress) — see
    aggregate.py's `_split_scoreable_pe_hits`.

    Scoreable on its own:
      - MEM_PRIVATE — no legitimate loader maps an unregistered PE image
        into private memory; this needs no further corroboration.
      - non-module-backed (already guaranteed by split_hidden_pe_hits,
        which only keeps hits with in_module_list=False) AND executable
        protection — an executable, unbacked mapping is just as
        suspicious as MEM_PRIVATE regardless of whether the underlying
        page type happens to be MEM_IMAGE or MEM_MAPPED.

    Context-only otherwise: e.g. a read-only/non-executable MEM_MAPPED
    region, or a MEM_IMAGE region absent from the module list but
    carrying no execute permission (a resource-only view, a decoy
    header, ...) — a structurally-valid PE header alone, with no execute
    permission and no correlated RWX/live-execution signal, occurs often
    enough in ordinary file-mapping/DLL-preview scenarios that it must
    not by itself drive a verdict.
    """
    r = hit.region
    if r.type == "MEM_PRIVATE":
        return True
    return _has_executable_protection(r.protect)
