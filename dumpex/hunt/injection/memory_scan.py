"""RWX region and hidden-PE-header memory scans. Only collects facts —
never scores, never prints.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_modules, get_memory_regions, addr_to_module, prot_str
from dumpex.core.pe_utils import parse_pe_header
from dumpex.hunt._location import resolve_location
from dumpex.hunt.injection.config import (
    PE_SCAN_DEGRADED_READ, PE_SCAN_MAX_READS_PER_REGION, PE_SCAN_MAX_UNVALIDATED_EVIDENCE,
    PE_SCAN_MAX_VALIDATED_EVIDENCE, PE_SCAN_MAX_VALIDATIONS_PER_REGION,
    PE_SCAN_MAX_VALIDATIONS_TOTAL, PE_SCAN_TOTAL_BYTES_MAX, PE_SCAN_WINDOW,
    PE_VALIDATE_READ_MAX,
)
from dumpex.hunt.injection.models import (
    HiddenPeScan, RegionRef, PeHeaderInfo, RwxRegionEvidence, HiddenPeEvidence,
)

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

    def start_region(self) -> None:
        """Reset the per-region allowances. The whole-hunt ones (bytes,
        validations, evidence slots) deliberately carry over -- a dump
        must not be able to multiply its total cost simply by declaring
        its pathological memory as many small regions instead of one big
        one."""
        self.reads_left = self._reads_per_region
        self.region_validations_left = self._validations_per_region

    def take_read(self) -> bool:
        self.reads_left -= 1
        return self.reads_left >= 0 and self.bytes_left > 0

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
        self.validations_left -= 1
        self.region_validations_left -= 1
        return self.validations_left >= 0 and self.region_validations_left >= 0

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
    """The three ways one region's search can leave part of that region
    unexamined, each recorded as a fact about the REGION (not about the
    individual read that hit it) -- `_hunt_hidden_pe` counts regions, so a
    single region whose search needed many reads contributes at most one
    to each count."""

    def __init__(self):
        self.read_failed = False
        self.short_read = False
        self.truncated = False

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


def _stop_on_budget(pos: int, data: bytes, gaps: _ScanGaps, on_bytes) -> bool:
    """The one place a `_READ_BUDGET` status is turned into "stop
    scanning". `data` may be non-empty -- the byte budget caps how many
    bytes are ASKED for (see `_BudgetedReader.read`), so a capped read
    still returns whatever real bytes it got back before running out.
    Those bytes were actually read from the dump and must still be
    examined -- scanning them first, and marking the gap only after,
    is what keeps a budget cap from silently discarding data it already
    paid for. Always returns False: a budget stop is never something the
    caller can continue past."""
    if data:
        on_bytes(pos, data)
    gaps.truncated = True
    return False


def _scan_span(reader: _BudgetedReader, region_base: int, region_size: int,
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
            return _stop_on_budget(pos, data, gaps, on_bytes)

        if status == _READ_FAILED:
            if len(read_sizes) > 1:
                if not _scan_span(reader, region_base, region_size, pos,
                                   min(size, end - pos), read_sizes[1:], gaps, on_bytes):
                    return False
                pos += max(1, size - _MZ_OVERLAP)
                continue
            marker, marker_status = reader.read(region_base + pos, min(len(_MZ), region_size - pos))
            if marker_status == _READ_BUDGET:
                return _stop_on_budget(pos, marker, gaps, on_bytes)
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
        for hit in _mz_offsets(data):
            if not budget.take_validation():
                gaps.truncated = True
                return False
            candidate = offset + hit
            deep, status = _pe_validation_bytes(
                reader, region_base, region_size, candidate,
                data[hit:hit + validate_max], validate_max)
            gaps.note(status)
            on_candidate(candidate, deep)
        return True

    gaps = _ScanGaps()
    _scan_span(reader, region_base, region_size, 0, region_size,
                (window, degraded_read), gaps, _on_bytes)
    return gaps

def _hunt_hidden_pe(mf: MinidumpFile, read_region, module_list_available: bool = True,
                     budget: "_ScanBudget | None" = None) -> HiddenPeScan:
    """
    Return a HiddenPeScan(hits, read_failed, short_reads, scan_truncated).

    If ModuleListStream isn't present, module_list_available is False and
    this returns an empty scan rather than flagging every MZ header as
    "hidden": an empty modules list doesn't mean "nothing here is a known
    module" — it means we have no way to tell. Producing a hit for every
    legitimate loaded PE header would be pure false-positive noise, not a
    finding.

    Every eligible region is SEARCHED for 'MZ' at EVERY byte offset (see
    `_scan_region_for_pe`), not just probed at its own BaseAddress. A
    structurally valid PE mapped at a nonzero offset inside a private or
    unbacked allocation — loader metadata ahead of the image, several
    objects in one allocation, a manual map aligned to nothing in
    particular — used to be invisible to this hunter no matter how
    obviously injected it was (issue #26), because a clean 2 bytes at the
    region base ended the check for the whole region.

    A region whose reads fail (raise) is not the same as a region that was
    read and doesn't contain 'MZ' — those bytes were never actually looked
    at, so they're tracked separately (read_failed) rather than silently
    dropped. A read that SUCCEEDS but returns fewer bytes than requested (a
    short read — the capture ends inside the region, or a candidate's
    validation read returns only its 'MZ' marker instead of up to
    PE_VALIDATE_READ_MAX bytes) is likewise not "read fine, nothing here" /
    "read fine, structurally invalid", so it's tracked separately too
    (short_reads), distinct from an exception. A region whose search stops
    on one of the `_ScanBudget` bounds — reads, bytes, or validations — is
    tracked as scan_truncated: the remainder is unsearched, not clean.

    `budget` is that `_ScanBudget`, ONE instance for the whole call rather
    than one per region, so a dump cannot multiply its total cost by
    declaring its pathological memory as many small regions. Callers
    normally let this function build it; tests pass a small one. Evidence
    it refuses to retain (see `_ScanBudget.take_evidence_slot`) is counted
    on the returned scan (validated_dropped/unvalidated_dropped) — those
    candidates WERE examined, so they are reported as an evidence cap, not
    as a coverage gap.

    `read_region` is threaded explicitly (not imported directly from
    dumpex.core.memory in this module) so a caller/test can substitute a
    fake reader without needing the facade's own `read_region` name to be
    monkeypatched and separately re-imported here — see
    dumpex/hunt/_runtime.py.

    Each hit is a HiddenPeEvidence(region, pe, in_module_list, location) --
    callers decide what "valid" means for their purposes (see
    split_hidden_pe_hits) rather than this function silently only
    returning validated hits. `location` is the CANDIDATE's own address
    (`location.va`, with `location.region_offset` telling you where inside
    the region it sits and `location.file_offset` where in the .dmp), not
    the region's base address; `region` stays the containing MemoryInfo
    region, which is what allocation correlation is keyed on. File offset
    is resolved here too, at scan time, same reasoning as `_hunt_rwx`.
    """
    if not module_list_available:
        return HiddenPeScan(hits=(), read_failed=0, short_reads=0, scan_truncated=0)
    modules = get_modules(mf)
    budget = budget if budget is not None else _ScanBudget()
    reader = _BudgetedReader(read_region, mf, budget)
    hits = []
    read_failed = 0
    short_reads = 0
    scan_truncated = 0
    for r in get_memory_regions(mf):
        if prot_str(r.State) != "MEM_COMMIT":
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
        # search needed many reads must not inflate them into N.
        read_failed    += 1 if gaps.read_failed else 0
        short_reads    += 1 if gaps.short_read else 0
        scan_truncated += 1 if gaps.truncated else 0
    return HiddenPeScan(hits=tuple(hits), read_failed=read_failed, short_reads=short_reads,
                         scan_truncated=scan_truncated,
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
