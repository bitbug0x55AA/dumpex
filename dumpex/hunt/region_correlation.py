"""Cross-hunter region correlation for `--hunt all`'s `HUNT SUMMARY` card --
console/`--txt`-only, presentation-layer aggregation. Never touches JSON,
never changes a `HunterRecord`'s own score/verdict/confidence/coverage/
finding IDs, and never rescans the dump: every fact this module reads
already lives on the already-built `HunterRecord`s (`--hunt all`'s own
`records`) and the already-parsed `MemoryInfoListStream` entries
(`dumpex.core.memory.get_memory_regions()`).

A "region" here is always a normalized MemoryInfo region -- the
`(BaseAddress, RegionSize)` pair, half-open `[BaseAddress, BaseAddress +
RegionSize)` containment, exactly `dumpex.core.memory._get_region_at()`'s
own semantics (see `_RegionIndex.containing()` below). `AllocationBase` is
carried along purely as supplementary display context -- it is NEVER part
of the correlation key, so two MemoryInfo sub-regions of the same
allocation (a routine VirtualProtect split) stay two distinct regions here,
never silently merged.

Two tiers of evidence-to-region resolution, per hunter, matching each
hunter's own `HunterRecord.details` shape (see
`docs/hunt_migration_field_matrix.md` and each hunter's own `collect.py`):

  - "Embedded" evidence already carries a complete region reference
    (`HuntRegionRef`, or an equivalent dict with base_address/size/
    allocation_base) captured AT SCAN TIME from a real MinidumpMemoryInfo
    entry -- injection's rwx/hidden_pe/rip_hits/start_hits, stomping's
    protection_leads, pipe's private_pipes/c2_context/unbacked_in_rgn,
    obfuscation's seven decode-layer hits, and (as a MemoryInfo-absent
    fallback only) cs-beacon's configs. Even though this reference was
    already a real MemoryInfo region AT SCAN TIME, it is always
    re-confirmed against the CURRENT MemoryInfo list via
    `_canonicalize()` before use -- an embedded (base, size) that no
    longer has a unique EXACT match in the current list (stale, or the
    dump's own MemoryInfo list has since changed shape) never produces a
    correlation. Only when the current MemoryInfo list is itself absent
    is the embedded reference trusted as-is (nothing to confirm it
    against).
  - "VA-only" evidence carries nothing but a virtual address (or a byte
    range) -- hollowing's `image_base`, stomping's `verified_changes[*]`
    diff-range changed bytes, yara's `matches[*].strings[*].va` -- and MUST
    be resolved against the CURRENT MemoryInfoListStream. When that stream
    is absent (empty `memory_regions`) or an address/range maps
    ambiguously, the evidence is silently skipped (never guessed, never a
    fatal error).

`_RegionIndex` exposes exactly three lookups, deliberately kept separate
so point, span-permitted range, and single-region range semantics never
blur into one another:

  - `containing(address)` -- one POINT. Ambiguous (two overlapping regions
    claim it) or unmatched: `None`.
  - `unambiguous_overlaps(start, end)` -- a byte RANGE that MAY legitimately
    span several ADJACENT regions (a stomping diff range crossing a
    VirtualProtect split), returning every region it truly touches; `[]`
    when the touched regions overlap EACH OTHER, since no byte may belong
    to two rival regions.
  - `uniquely_contains_range(start, end)` -- a byte RANGE that must belong
    ENTIRELY to ONE region, with no second region intersecting it anywhere
    (yara's own segment-level fallback); `None` otherwise.

Only hunters worth investigating contribute signals at all: `status ==
"DETECTED"` or `(lead_count or 0) > 0` (see `build_region_correlations()`).
A region only becomes a `RegionCorrelation` when at least two DIFFERENT
hunters contributed a signal there -- one hunter with many signals in one
region is not a correlation.

Every address-like value that reaches this module (hex strings on
`HunterRecord.details`, real ints on `MinidumpMemoryInfo`) goes through
`_safe_hex_int()`/`_safe_nonneg_int()` first -- both reject `None`, `bool`,
and malformed input by returning `None` rather than raising, so one
malformed record degrades to "this piece of evidence contributes no
signal", never an exception that would take down the rest of `--hunt all`.

`RegionSignal.address` is always the REAL, most-specific address this
piece of evidence actually names -- a live RIP, a thread start address, a
pipe string's own offset-resolved VA, a verified-change's own changed-byte
address -- never silently collapsed to the region's own base address
unless the evidence genuinely IS region-scoped (an RWX-protection
observation, a whole-region entropy score, a yara per-region rule
roll-up). This keeps the `(hunter, region_base, kind, address)`
de-duplication key honest: two different real hits in the same region, of
the same kind, are two signals, not one.

`address` is additionally guaranteed to fall INSIDE its own signal's
`[region_base, region_base + region_size)` -- for evidence describing a
byte range that spans a region boundary, each region's signal carries that
range's own intersection start with THAT region (see `_collect_stomping()`),
never the range's overall start, which lies outside every region after the
first.
"""
from dataclasses import dataclass

from dumpex.output.records import HUNTERS, HunterRecord

# Relative severity used only to ORDER `RegionCorrelation`s by "how urgent
# is the most severe hunter in this group" -- mirrors
# dumpex.hunt.summary._DETECTED_VERDICT_ORDER's high/likely/possible
# ranking, extended with the three non-DETECTED verdict_level values a
# lead-only (status != DETECTED but lead_count > 0) or otherwise-eligible
# record can still carry. Purely a sort key -- never surfaced as a score.
_VERDICT_SEVERITY_RANK = {
    "high": 3, "likely": 2, "possible": 1,
    "clean": 0, "inconclusive": 0, "not_evaluated": 0,
}


@dataclass(frozen=True)
class RegionSignal:
    """One piece of structured evidence, already resolved to a normalized
    MemoryInfo region -- display-only, never written to JSON. `address`
    is the literal, most-specific evidence address this signal names (see
    this module's own docstring) and is part of the
    `(hunter, region_base, kind, address)` de-duplication key -- it is not
    itself rendered."""
    hunter:          str
    kind:            str
    label:           str
    address:         "int | None"
    region_base:     int
    region_size:     int
    allocation_base: "int | None"


@dataclass(frozen=True)
class RegionCorrelation:
    """Two or more different hunters' `RegionSignal`s that share one
    normalized MemoryInfo region -- `hunters` is the subset of `HUNTERS`
    (that fixed order preserved) present in `signals`. Co-location only:
    this never implies causation or a single actor, and never changes any
    `HunterRecord`'s own score/verdict/confidence (see this module's own
    top docstring)."""
    region_base:     int
    region_size:     int
    allocation_base: "int | None"
    signals:         tuple
    hunters:         tuple


# ── Safe, explicit int coercion ──────────────────────────────────────────

def _safe_hex_int(value) -> "int | None":
    """`value` must be a real `"0x" + hex digits` string (the
    `dumpex.output.records.hex_address()` shape, or any similarly-prefixed
    hex string) to become an int here -- `None`, `bool` (a `bool` is a
    Python `int` subclass and must never silently pass as an address), a
    non-string, or a malformed string all return `None` rather than
    raising, so one bad field degrades to 'no signal from this item', not
    a crash (see this module's own docstring)."""
    if value is None or isinstance(value, bool) or not isinstance(value, str):
        return None
    v = value.strip().lower()
    if not v.startswith("0x") or len(v) == 2:
        return None
    try:
        return int(v, 16)
    except ValueError:
        return None


def _safe_nonneg_int(value) -> "int | None":
    if value is None or isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _safe_pos_int(value) -> "int | None":
    v = _safe_nonneg_int(value)
    return v if v else None


# ── MemoryInfo containment/overlap index ─────────────────────────────────

class _RegionIndex:
    """Wraps the real, already-parsed `MinidumpMemoryInfo` list
    (`dumpex.core.memory.get_memory_regions()`'s own return value) --
    reading already-parsed data, never re-scanning the dump.
    `containing()`/`unambiguous_overlaps()`/`uniquely_contains_range()` are
    the ONLY ways evidence resolves to a region in this module -- one per
    lookup SHAPE (point, span-permitted range, single-region range), each
    with its own ambiguity rule; see this module's own docstring for when
    each applies, and never widen one to serve another's shape. `exact()` is
    the separate embedded-reference re-confirmation used by
    `_canonicalize()`. `has_regions` distinguishes "no MemoryInfoListStream
    at all" (embedded evidence may be trusted as-is) from
    "MemoryInfoListStream present, but this particular address isn't in it /
    is ambiguous" (always a skip, never a fallback) -- see `_canonicalize()`
    and `_collect_cs_beacon()`, which both depend on that distinction."""

    def __init__(self, memory_regions: list):
        self._regions = []
        for r in memory_regions or []:
            base = getattr(r, "BaseAddress", None)
            size = getattr(r, "RegionSize", None)
            if not isinstance(base, int) or isinstance(base, bool):
                continue
            if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                continue
            alloc = getattr(r, "AllocationBase", None)
            if not isinstance(alloc, int) or isinstance(alloc, bool):
                alloc = None
            self._regions.append((base, size, alloc))

    @property
    def has_regions(self) -> bool:
        return bool(self._regions)

    def containing(self, address: "int | None") -> "tuple | None":
        """Half-open `BaseAddress <= address < BaseAddress + RegionSize`
        containment -- the same semantics as
        `dumpex.core.memory._get_region_at()`. Returns the single matching
        `(base, size, allocation_base)` tuple, or `None` if none or more
        than one region claims this address -- an overlapping/malformed
        MemoryInfo list must never produce an unreliable point match."""
        if address is None:
            return None
        hits = [reg for reg in self._regions if reg[0] <= address < reg[0] + reg[1]]
        if len(hits) != 1:
            return None
        return hits[0]

    def exact(self, base: "int | None", size: "int | None") -> "tuple | None":
        """The single region whose OWN `(BaseAddress, RegionSize)` exactly
        equals `(base, size)` -- used to re-confirm an embedded region
        reference against the CURRENT MemoryInfo list (see
        `_canonicalize()`). `None` when there is no such region, or (an
        MemoryInfo list that itself contains a duplicate base/size pair)
        more than one -- never an unreliable guess."""
        if base is None or size is None:
            return None
        hits = [reg for reg in self._regions if reg[0] == base and reg[1] == size]
        if len(hits) != 1:
            return None
        return hits[0]

    def _intersecting(self, start: int, end: int) -> list:
        """Every region whose own extent `[base, base+size)` intersects the
        half-open byte range `[start, end)`, in MemoryInfo list order. Raw
        intersection only -- says nothing about whether that mapping is
        AMBIGUOUS; both public range methods below add their own, different
        ambiguity rule on top."""
        return [reg for reg in self._regions if reg[0] < end and start < reg[0] + reg[1]]

    @staticmethod
    def _mutually_overlapping(regions: list) -> bool:
        """True when any two of `regions` overlap EACH OTHER -- the range
        equivalent of `containing()`'s own "more than one region claims this
        address" test. Two regions that merely abut (A ends exactly where B
        begins) do NOT overlap, thanks to the same half-open rule used
        everywhere else in this module."""
        for i, a in enumerate(regions):
            for b in regions[i + 1:]:
                if a[0] < b[0] + b[1] and b[0] < a[0] + a[1]:
                    return True
        return False

    def unambiguous_overlaps(self, start: "int | None", end: "int | None") -> list:
        """Every region the half-open byte range `[start, end)` genuinely
        touches -- but ONLY when each touched byte belongs to at most one
        region. A range legitimately spanning several ADJACENT regions (a
        stomping diff range crossing a VirtualProtect split) is a real
        one-to-many relationship and returns all of them; a range touching
        regions that OVERLAP EACH OTHER is ambiguous -- exactly the case
        `containing()` refuses for a single address -- and returns `[]`
        rather than asserting the same evidence sits in two rival regions.
        Empty for a missing/degenerate range."""
        if start is None or end is None or end <= start:
            return []
        hits = self._intersecting(start, end)
        if self._mutually_overlapping(hits):
            return []
        return hits

    def uniquely_contains_range(self, start: "int | None", end: "int | None") -> "tuple | None":
        """The single region that ENTIRELY contains the half-open byte range
        `[start, end)`, when no other region intersects that range at all --
        the strictest of this class's three lookups, for evidence that is
        only usable if the WHOLE range provably belongs to one region (yara's
        own segment-level fallback). `None` when the range crosses a region
        boundary, when a second (nested or overlapping) region also
        intersects it, or when it isn't fully covered by the one region that
        does. Unlike `unambiguous_overlaps()` above, spanning several
        adjacent regions is NOT acceptable here."""
        if start is None or end is None or end <= start:
            return None
        hits = self._intersecting(start, end)
        if len(hits) != 1:
            return None
        base, size, _ = hits[0]
        if start < base or end > base + size:
            return None
        return hits[0]


# ── Embedded-region extraction + current-MemoryInfo re-confirmation ─────

def _embedded_region(ref) -> "tuple | None":
    """`ref` is either a `dumpex.output.records.HuntRegionRef` instance
    (injection) or an equivalent plain dict with base_address/size/
    allocation_base keys (stomping/pipe/obfuscation's own region dicts --
    see each hunter's own `collect.py`). Returns `(base, size,
    allocation_base)` or `None` when the reference itself is missing or its
    base_address/size don't parse to real values. This is the RAW
    extraction only -- callers must still run the result through
    `_canonicalize()` before treating it as a correlation-worthy region."""
    if ref is None:
        return None
    if hasattr(ref, "base_address"):
        base = _safe_hex_int(ref.base_address)
        size = _safe_nonneg_int(getattr(ref, "size", None))
        alloc = _safe_hex_int(getattr(ref, "allocation_base", None))
    elif isinstance(ref, dict):
        base = _safe_hex_int(ref.get("base_address"))
        size = _safe_nonneg_int(ref.get("size"))
        alloc = _safe_hex_int(ref.get("allocation_base"))
    else:
        return None
    if base is None or size is None or size <= 0:
        return None
    return (base, size, alloc)


def _embedded_region_from_base_size(base_hex, size_val) -> "tuple | None":
    """cs-beacon's own `configs[*]` shape: `region_base`/`region_size` are
    two separate top-level keys, not a nested region dict -- see
    `_collect_cs_beacon()`. Same "raw extraction only" contract as
    `_embedded_region()` above."""
    base = _safe_hex_int(base_hex)
    size = _safe_nonneg_int(size_val)
    if base is None or size is None or size <= 0:
        return None
    return (base, size, None)


def _canonicalize(index: _RegionIndex, embedded: "tuple | None") -> "tuple | None":
    """Re-confirm an embedded `(base, size, allocation_base)` reference
    against the CURRENT MemoryInfo list before it may contribute a signal.

    When the current MemoryInfo list is absent (`not index.has_regions`),
    there is nothing to confirm it against -- the embedded reference
    (captured from a real MinidumpMemoryInfo entry when this hunter's own
    scan ran) is trusted as-is.

    When the current MemoryInfo list IS present, the embedded reference is
    NOT trusted blindly: `_RegionIndex.exact()` must find that exact
    `(base, size)` pair as a real, unambiguous entry in the CURRENT list.
    A collector bug, a hand-built record, or a MemoryInfo list that has
    since changed shape must never silently produce a correlation from a
    region reference that no longer exists -- this is what lets every
    embedded-evidence hunter (injection/pipe/stomping's protection leads/
    obfuscation) share one reliability guarantee instead of each trusting
    its own `details` blindly. The CURRENT list's own `allocation_base` is
    returned (not the embedded reference's own, possibly stale, copy)."""
    if embedded is None:
        return None
    if not index.has_regions:
        return embedded
    base, size, _ = embedded
    return index.exact(base, size)


def _va_region(index: _RegionIndex, va: "int | None") -> "tuple | None":
    return index.containing(va)


# ── Signal bucket + de-duplication ───────────────────────────────────────

def _add_signal(bucket: dict, seen: dict, hunter: str, kind: str, label: str,
                 address: "int | None", region: "tuple | None") -> None:
    if region is None:
        return
    base, size, alloc = region
    region_key = (base, size)
    dedup_key = (hunter, base, kind, address)
    seen_for_region = seen.setdefault(region_key, set())
    if dedup_key in seen_for_region:
        return
    seen_for_region.add(dedup_key)
    entry = bucket.get(region_key)
    if entry is None:
        entry = {"meta": (base, size, alloc), "signals": [], "inconsistent": False}
        bucket[region_key] = entry
    elif alloc is not None and entry["meta"][2] is not None and entry["meta"][2] != alloc:
        # Two different pieces of evidence both resolved to this exact
        # (base, size) region but disagree about its AllocationBase -- in
        # a normal run every real MemoryInfo entry has exactly one
        # AllocationBase, so this can only mean the evidence itself is
        # inconsistent (a stale/hand-built region reference, or a
        # MemoryInfo list that changed between two evidence items). Never
        # silently keep the first-seen value and present it as reliable --
        # mark the whole region inconsistent so build_region_correlations()
        # drops it entirely rather than showing a made-up allocation base.
        entry["inconsistent"] = True
    elif entry["meta"][2] is None and alloc is not None:
        entry["meta"] = (base, size, alloc)
    entry["signals"].append(RegionSignal(
        hunter=hunter, kind=kind, label=label, address=address,
        region_base=base, region_size=size, allocation_base=alloc))


# ── Per-hunter signal extraction ─────────────────────────────────────────

def _collect_injection(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    for ref in d.rwx:
        region = _canonicalize(index, _embedded_region(ref))
        addr = region[0] if region else None
        _add_signal(bucket, seen, "injection", "rwx", "RWX region", addr, region)
    for hit in d.hidden_pe_validated:
        region = _canonicalize(index, _embedded_region(hit.region))
        addr = region[0] if region else None
        _add_signal(bucket, seen, "injection", "hidden_pe_validated",
                     "validated hidden PE", addr, region)
    for hit in d.hidden_pe_unvalidated:
        region = _canonicalize(index, _embedded_region(hit.region))
        addr = region[0] if region else None
        _add_signal(bucket, seen, "injection", "hidden_pe_unvalidated",
                     "unvalidated MZ/PE lead", addr, region)
    for hit in d.rip_hits:
        region = _canonicalize(index, _embedded_region(hit.region))
        # The real, live instruction pointer -- NOT the region base -- so
        # two different threads' RIPs inside the same region stay two
        # distinct signals.
        addr = _safe_hex_int(hit.thread.ip) if region else None
        _add_signal(bucket, seen, "injection", "rip_hit",
                     "live RIP/EIP in suspicious region", addr, region)
    for hit in d.start_hits:
        region = _canonicalize(index, _embedded_region(hit.region))
        addr = _safe_hex_int(hit.thread.start_address) if region else None
        _add_signal(bucket, seen, "injection", "start_hit",
                     "thread start in suspicious region", addr, region)


def _collect_hollowing(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    va = _safe_hex_int(d.image_base)
    if va is None:
        return
    region = _va_region(index, va)
    if region is None:
        return
    for active, kind, label in (
            (d.mem_private_at_base is True, "mem_private", "private memory at image base"),
            (d.mz_header_present is False, "no_mz_header", "no MZ header at image base"),
            (d.is_rwx_at_base is True, "rwx_at_base", "RWX protection at image base"),
            (d.name_mismatch is True, "name_mismatch", "module name mismatch")):
        if active:
            _add_signal(bucket, seen, "hollowing", kind, label, va, region)


def _collect_stomping(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    for lead in d.protection_leads:
        if not isinstance(lead, dict):
            continue
        region = _canonicalize(index, _embedded_region(lead.get("region")))
        # va_start (the actual mismatched section's own start) is more
        # specific than the region base when the two differ.
        addr = _safe_hex_int(lead.get("va_start"))
        if addr is None and region:
            addr = region[0]
        _add_signal(bucket, seen, "stomping", "protection_lead",
                     "section protection mismatch", addr, region)

    for vc in d.verified_changes:
        if not isinstance(vc, dict):
            continue
        va_start = _safe_hex_int(vc.get("va_start"))
        if va_start is None:
            continue
        diff_ranges = vc.get("diff_ranges")
        if not isinstance(diff_ranges, list):
            continue
        # One signal per (verified_change, region actually touched by its
        # changed bytes) -- a single verified_change's diff_ranges can span
        # a MemoryInfo region boundary, and must surface in EVERY region it
        # actually overlaps, not just whichever region va_start (the
        # section's own start, not necessarily where the bytes changed)
        # happens to fall in. `unambiguous_overlaps()` still refuses the
        # whole range when the regions it touches overlap EACH OTHER -- the
        # same "don't assert one piece of evidence sits in two rival
        # regions" rule `containing()` applies to a single address.
        regions_hit = {}   # region_key -> (region, lowest changed address IN that region)
        for r in diff_ranges:
            if not (isinstance(r, (list, tuple)) and len(r) == 2):
                continue
            offset, length = r
            if (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0
                    or not isinstance(length, int) or isinstance(length, bool) or length <= 0):
                continue
            changed_start = va_start + offset
            changed_end = changed_start + length
            for region in index.unambiguous_overlaps(changed_start, changed_end):
                region_key = (region[0], region[1])
                # The first CHANGED byte that actually falls inside THIS
                # region -- clamped to the region's own base, never the
                # range's own start, which for a boundary-spanning range
                # lies outside every region after the first one it touches.
                # RegionSignal.address must always be an address within its
                # own region (see this module's docstring), and it is part
                # of the de-duplication key.
                intersection_start = max(changed_start, region[0])
                previous = regions_hit.get(region_key)
                if previous is None or intersection_start < previous[1]:
                    regions_hit[region_key] = (region, intersection_start)
        for region, changed_address in sorted(regions_hit.values(), key=lambda x: x[0][0]):
            _add_signal(bucket, seen, "stomping", "verified_change",
                         "verified relocation-normalized byte changes",
                         changed_address, region)


def _collect_pipe(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    for hit in d.private_pipes:
        if not isinstance(hit, dict):
            continue
        region = _canonicalize(index, _embedded_region(hit.get("region")))
        offset = _safe_nonneg_int(hit.get("offset"))
        addr = (region[0] + offset) if (region and offset is not None) else (
            region[0] if region else None)
        _add_signal(bucket, seen, "pipe", "private_pipe",
                     "pipe string in private memory", addr, region)
    for hit in d.c2_context:
        if not isinstance(hit, dict):
            continue
        region = _canonicalize(index, _embedded_region(hit.get("region")))
        if region is None:
            continue
        records_list = hit.get("records")
        vas = []
        if isinstance(records_list, list):
            for rec in records_list:
                if isinstance(rec, dict):
                    va = _safe_hex_int(rec.get("va"))
                    if va is not None:
                        vas.append(va)
        if not vas:
            vas = [region[0]]
        for va in vas:
            _add_signal(bucket, seen, "pipe", "c2_context",
                         "pipe/C2 context in memory", va, region)
    for pair in d.unbacked_in_rgn:
        if not isinstance(pair, dict):
            continue
        region = _canonicalize(index, _embedded_region(pair.get("region")))
        thread = pair.get("thread")
        addr = None
        if isinstance(thread, dict):
            addr = _safe_hex_int(thread.get("start_address"))
        if addr is None and region:
            addr = region[0]
        _add_signal(bucket, seen, "pipe", "unbacked_in_rgn",
                     "unbacked thread in pipe-bearing region", addr, region)


def _collect_cs_beacon(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    for cfg in d.configs:
        if not isinstance(cfg, dict):
            continue
        va = _safe_hex_int(cfg.get("va"))
        if index.has_regions:
            # The CURRENT MemoryInfo list is authoritative once present --
            # `containing()` itself returns None for "not in any region"
            # AND for "ambiguous, in more than one" alike, and NEITHER case
            # may fall back to the config's own embedded region_base/
            # region_size: falling back here would let a stale or
            # ambiguous VA still produce a correlation via the config's own
            # (possibly outdated) embedded copy.
            region = _va_region(index, va) if va is not None else None
        else:
            region = _embedded_region_from_base_size(cfg.get("region_base"), cfg.get("region_size"))
        if region is None:
            continue
        addr = va if va is not None else region[0]
        _add_signal(bucket, seen, "cs-beacon", "valid_config",
                     "structurally valid Beacon config", addr, region)
        if cfg.get("context_corroborated") is True:
            _add_signal(bucket, seen, "cs-beacon", "context_corroborated",
                         "context corroborated", addr, region)


def _collect_yara(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    by_region = {}   # region_key -> {"region": tuple, "rules": [str, ...]}

    def _note(region, rule):
        region_key = (region[0], region[1])
        entry = by_region.setdefault(region_key, {"region": region, "rules": []})
        if rule not in entry["rules"]:
            entry["rules"].append(rule)

    for hit in d.matches:
        if not isinstance(hit, dict):
            continue
        rule = hit.get("rule")
        if not isinstance(rule, str) or not rule:
            continue

        # Primary: each ACTUAL string hit's own absolute VA
        # (matches[*].strings[*].va) -- `seg_va` is only the enclosing scan
        # SEGMENT's own start, which can span multiple MemoryInfo regions;
        # resolving from the real hit location is what a "same region"
        # correlation claim actually requires.
        resolved_any = False
        strings = hit.get("strings")
        if isinstance(strings, list):
            for sv in strings:
                if not isinstance(sv, dict):
                    continue
                va = _safe_hex_int(sv.get("va"))
                if va is None:
                    continue
                region = _va_region(index, va)
                if region is None:
                    continue
                resolved_any = True
                _note(region, rule)

        if resolved_any:
            continue

        # Fallback: no string-level VA survived (empty/absent `strings`,
        # e.g. a segment-level-only match). Only usable when the WHOLE
        # scanned segment `[seg_va, seg_va + seg_size)` -- not just its
        # start point, and not merely "doesn't run past the end of the
        # region its start landed in" -- provably belongs to exactly one
        # region. `uniquely_contains_range()` enforces all of that at once:
        # a segment crossing a boundary, or one that also intersects a
        # nested/overlapping second region somewhere in its middle, resolves
        # to nothing rather than being pinned to whichever region happens to
        # contain its first byte.
        seg_va = _safe_hex_int(hit.get("seg_va"))
        seg_size = _safe_pos_int(hit.get("seg_size"))
        if seg_va is None or seg_size is None:
            continue
        region = index.uniquely_contains_range(seg_va, seg_va + seg_size)
        if region is None:
            continue
        _note(region, rule)

    for entry in by_region.values():
        rules = entry["rules"]
        shown = ", ".join(rules[:3])
        overflow = f" (+{len(rules) - 3} more)" if len(rules) > 3 else ""
        region = entry["region"]
        _add_signal(bucket, seen, "yara", "rule_hit", f"{shown}{overflow}",
                     region[0], region)


_OBFUSCATION_LABELS = {
    "sleep_mask":       "sleep-mask candidate",
    "entropy":          "high-entropy observation",
    "base64":           "base64-decoded content",
    "xor":              "XOR-decoded content",
    "compressed":       "compressed payload",
    "hidden_pe":        "decoded PE",
    "hidden_shellcode": "decoded shellcode",
}
# entropy hits (region + entropy score) carry no sub-region offset -- a
# whole-region observation, not a point in it (see _entropy_hit_dict()) --
# every other category's hit dict has its own byte `offset` (see
# _hit_dict()), used below to compute a real, most-specific address.
_OBFUSCATION_REGION_LEVEL = frozenset({"entropy"})


def _collect_obfuscation(record: HunterRecord, index: _RegionIndex, bucket: dict, seen: dict) -> None:
    d = record.details
    for category, label in _OBFUSCATION_LABELS.items():
        for hit in getattr(d, category):
            if not isinstance(hit, dict):
                continue
            region = _canonicalize(index, _embedded_region(hit.get("region")))
            if region is None:
                continue
            if category in _OBFUSCATION_REGION_LEVEL:
                addr = region[0]
            else:
                offset = _safe_nonneg_int(hit.get("offset"))
                addr = region[0] + offset if offset is not None else region[0]
            _add_signal(bucket, seen, "obfuscation", category, label, addr, region)


_COLLECTORS = {
    "injection":   _collect_injection,
    "hollowing":   _collect_hollowing,
    "stomping":    _collect_stomping,
    "pipe":        _collect_pipe,
    "cs-beacon":   _collect_cs_beacon,
    "yara":        _collect_yara,
    "obfuscation": _collect_obfuscation,
}


def _correlation_sort_key(corr: RegionCorrelation, record_by_hunter: dict):
    severities = [_VERDICT_SEVERITY_RANK.get(record_by_hunter[h].verdict_level, 0)
                  for h in corr.hunters]
    return (-len(corr.hunters), -max(severities, default=0), -len(corr.signals), corr.region_base)


def build_region_correlations(records: list, memory_regions: list) -> list:
    """Build the display-only `RegionCorrelation` list for `--hunt all`'s
    `CORRELATED REGIONS` section. `records` is the same `list[HunterRecord]`
    `--hunt all` already built (any subset/order is accepted here -- this
    function does not enforce `build_hunt_summary()`'s own fixed-order/
    complete-set contract, since it degrades gracefully either way);
    `memory_regions` is `dumpex.core.memory.get_memory_regions(mf)`'s own
    return value -- already-parsed MemoryInfo entries, read here, never
    re-scanned.

    Only hunters worth investigating contribute signals (`status ==
    "DETECTED"` or `lead_count > 0`); a region only becomes a
    `RegionCorrelation` when at least two DIFFERENT hunters' signals
    resolved there, and only when every signal that resolved there agreed
    on that region's own AllocationBase (see `_add_signal()`'s own
    inconsistency guard). Returns a deterministically-ordered list -- see
    `_correlation_sort_key()` -- empty when nothing correlates. Any cap on
    how many entries are actually PRINTED is a presentation-layer decision
    (see `dumpex.hunt.summary_presentation`), not made here -- this
    function always returns the full, real result."""
    if not isinstance(records, list) or any(not isinstance(r, HunterRecord) for r in records):
        raise TypeError("build_region_correlations() records must be a list of HunterRecord")

    index = _RegionIndex(memory_regions)
    record_by_hunter = {r.hunter: r for r in records}
    bucket: dict = {}
    seen: dict = {}

    for record in records:
        if not (record.status == "DETECTED" or (record.lead_count or 0) > 0):
            continue
        collector = _COLLECTORS.get(record.hunter)
        if collector is None:
            continue
        collector(record, index, bucket, seen)

    correlations = []
    for region_key, entry in bucket.items():
        if entry["inconsistent"]:
            continue
        signals = entry["signals"]
        hunters_present = tuple(h for h in HUNTERS if any(s.hunter == h for s in signals))
        if len(hunters_present) < 2:
            continue
        ordered_signals = tuple(sorted(
            signals, key=lambda s: (HUNTERS.index(s.hunter), s.kind, s.address or 0)))
        base, size, alloc = entry["meta"]
        correlations.append(RegionCorrelation(
            region_base=base, region_size=size, allocation_base=alloc,
            signals=ordered_signals, hunters=hunters_present))

    correlations.sort(key=lambda corr: _correlation_sort_key(corr, record_by_hunter))
    return correlations
