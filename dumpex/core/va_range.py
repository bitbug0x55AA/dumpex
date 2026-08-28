"""Neutral virtual-address range and captured-range primitives.

Side-effect-free value types for describing an attacker-controlled
virtual-address range, deciding how much of it a dump actually captured,
clipping work to a region or segment boundary, and naming the suffix that
still needs recollection or scanning. Nothing here scores, matches a rule,
reads process memory, prints, or retains a parser object: a caller
converts its raw ``minidump`` region/segment objects at the boundary and
the raw objects never enter this module.

The module depends only on the standard library so that report and PEB
consumers can reuse it without importing ``dumpex.hunt``.

The value types (``VirtualRange``, ``CapturedRegion``, ``CapturedSegment``,
``CapturedSlice``, ``ReadSlice``) are strict: constructing one from a
non-representable value raises ``RangeError``. The bulk ``mf``-backed
entry points (``captured_regions``, ``captured_segments``, ``capture_of``)
are resilient: a descriptor whose values the model cannot represent is
skipped, never raised on, so one bad entry never costs the rest of a
dump's table. ``enumerate_captured_regions`` / ``enumerate_captured_
segments`` return the skipped count alongside the views so the loss is an
observable fact. A descriptor OBJECT missing an expected field is a
different thing -- library-shape drift -- and still propagates.

Vocabulary
----------
Virtual range
    A half-open ``[base_address, end_address)`` span of the target
    process's address space. Never a dump-file offset.

MemoryInfo region
    One ``MemoryInfoListStream`` entry: an address span plus the
    allocation/state/type/protection metadata VirtualQuery recorded. A
    region can describe more address space than the dump actually wrote.

Captured segment
    One ``Memory64List``/``MemoryList`` entry: the dump's own claim that
    exactly ``size`` bytes at this virtual address were written to
    ``[file_offset, file_offset + size)`` in the .dmp.

Capture state
    Whether a requested range is wholly, partly, or not at all backed by
    contiguous captured segments. Structural evidence from the segment
    table, never proof that a later read of those bytes succeeded.

Three independent layers
    ``CapturedSlice`` is purely structural: its ``captured`` prefix and
    ``uncaptured_suffix`` come from the segment table alone -- byte
    availability, nothing more.

    ``ReadSlice`` is the contiguous run of bytes a consumer's read
    actually returned and handed to its algorithm. It can fall short of
    the captured prefix on a truncated file, a parser error, or an I/O
    failure past some point; it can never exceed it. This is an honest
    byte fact about the read, not a claim about the algorithm.

    Coverage status -- ``not_evaluated`` / ``partial`` / ``complete``,
    whether the algorithm ran to completion over the bytes it was given --
    is a third layer this module deliberately does not model. Candidate-,
    window-, hit-, and deadline-bounded scanners carry it as a status, not
    as a byte-precise "examined through here" offset, and it depends on
    source eligibility gates and multi-closure budget accounting that are
    hunt policy. Nothing here decides it, and no type here exposes a flag
    that could be mistaken for it.
"""
from dataclasses import dataclass
from enum import Enum

_ADDRESS_SPACE = 1 << 64   # exclusive upper bound of the 64-bit VA space

__all__ = [
    "RangeError",
    "VirtualRange",
    "CaptureState",
    "CapturedRegion",
    "CapturedSegment",
    "CapturedSlice",
    "ReadSlice",
    "CapturedEnumeration",
    "slice_captured",
    "capture_of",
    "captured_segments",
    "captured_regions",
    "enumerate_captured_segments",
    "enumerate_captured_regions",
    "region_containing",
    "segment_containing",
]


class RangeError(ValueError):
    """A range or captured view could not be constructed from the values
    given: a non-integer bound, a non-positive size, a negative base or
    file offset, or an end past the 64-bit address space. Distinct from a
    range that is merely disjoint from another, which is an ordinary
    ``None`` result rather than an error."""


def _check_int(value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RangeError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _check_address(value, name: str) -> int:
    _check_int(value, name)
    if not 0 <= value < _ADDRESS_SPACE:
        raise RangeError(f"{name} (0x{value:x}) is outside the 64-bit address space")
    return value


def _flag_name(value) -> "str | None":
    """The enum name of a raw ``minidump`` flag value, or ``str()`` of it
    when it carries no ``name``, or ``None`` when the value itself is
    ``None`` -- the same rendering ``dumpex.core.memory.prot_str`` applies,
    duplicated here so this module stays free of that import."""
    if value is None:
        return None
    name = getattr(value, "name", None)
    return name if name is not None else str(value)


@dataclass(frozen=True, order=True)
class VirtualRange:
    """An immutable half-open ``[base_address, base_address + size)`` span
    of target-process virtual address space.

    Every instance is checked at construction: ``size`` is strictly
    positive, ``base_address`` is a 64-bit address, and
    ``base_address + size`` does not run past the end of the 64-bit
    address space. An end landing exactly on ``1 << 64`` is allowed as the
    exclusive bound of the whole space; anything beyond raises RangeError.

    Ordering is by ``(base_address, size)``, so any collection of ranges
    has one deterministic sort independent of how it was assembled.
    """
    base_address: int
    size: int

    def __post_init__(self):
        _check_address(self.base_address, "base_address")
        _check_int(self.size, "size")
        if self.size <= 0:
            raise RangeError(f"size ({self.size}) must be positive -- a range has a real extent")
        if self.base_address + self.size > _ADDRESS_SPACE:
            raise RangeError(
                f"[0x{self.base_address:x}, +0x{self.size:x}) runs past the end of the "
                f"64-bit address space")

    @classmethod
    def from_endpoints(cls, base_address: int, end_address: int) -> "VirtualRange":
        """Build the range ``[base_address, end_address)``. ``end_address``
        may be ``1 << 64``; an end at or below the base is a non-positive
        size and raises RangeError."""
        _check_address(base_address, "base_address")
        _check_int(end_address, "end_address")
        if end_address > _ADDRESS_SPACE:
            raise RangeError(
                f"end_address (0x{end_address:x}) runs past the end of the 64-bit "
                f"address space")
        if end_address <= base_address:
            raise RangeError(
                f"end_address (0x{end_address:x}) must be above base_address "
                f"(0x{base_address:x})")
        return cls(base_address, end_address - base_address)

    @property
    def end_address(self) -> int:
        return self.base_address + self.size

    def contains_address(self, address: int) -> bool:
        return self.base_address <= address < self.end_address

    def contains_range(self, other: "VirtualRange") -> bool:
        return (self.base_address <= other.base_address
                and other.end_address <= self.end_address)

    def overlaps(self, other: "VirtualRange") -> bool:
        return (self.base_address < other.end_address
                and other.base_address < self.end_address)

    def intersection(self, other: "VirtualRange") -> "VirtualRange | None":
        """The overlap of the two ranges, or ``None`` when they are
        disjoint or touch only at an endpoint."""
        base = max(self.base_address, other.base_address)
        end = min(self.end_address, other.end_address)
        if base >= end:
            return None
        return VirtualRange(base, end - base)

    def clip_to(self, boundary: "VirtualRange") -> "VirtualRange | None":
        """This range restricted to ``boundary`` -- the same value as
        ``intersection``, named for the call site whose intent is
        "confine this work to a region or segment boundary". ``None`` when
        nothing of this range falls inside ``boundary``."""
        return self.intersection(boundary)

    def suffix_after(self, prefix_len: int) -> "VirtualRange | None":
        """The part of this range beyond its first ``prefix_len`` bytes, or
        ``None`` when ``prefix_len`` covers the whole range. ``prefix_len``
        must lie in ``[0, size]``."""
        _check_int(prefix_len, "prefix_len")
        if not 0 <= prefix_len <= self.size:
            raise RangeError(
                f"prefix_len ({prefix_len}) must be within [0, {self.size}]")
        if prefix_len == self.size:
            return None
        return VirtualRange(self.base_address + prefix_len, self.size - prefix_len)

    def __str__(self) -> str:
        return f"[0x{self.base_address:016x}, 0x{self.end_address:016x})"


class CaptureState(str, Enum):
    """How much of a requested range the dump's segment table backs. The
    string values match ``dumpex.output.coverage.ScanTarget.capture_state``
    so a consumer can carry one through to the other unchanged."""
    NONE = "none"          # the requested base itself is not captured
    PARTIAL = "partial"    # a contiguous prefix is captured, not the whole range
    COMPLETE = "complete"  # every byte of the requested range is captured


@dataclass(frozen=True)
class CapturedRegion:
    """An immutable view of one ``MemoryInfoListStream`` region: its
    address span plus the metadata inherited from the parser object at
    conversion time. The raw region is neither retained nor mutated.

    ``state``/``type``/``protection`` are the enum names (e.g.
    ``"MEM_COMMIT"``, ``"MEM_PRIVATE"``, ``"PAGE_EXECUTE_READWRITE"``), or
    ``str()`` of the raw value when it carries no name, or ``None`` when
    the parser object does not carry that field at all. ``allocation_base``
    is the address one reservation call originally returned, or ``None``.
    Those four facts describe the allocation as a whole, so a range clipped
    out of this region keeps them unchanged.
    """
    range: VirtualRange
    allocation_base: "int | None" = None
    state: "str | None" = None
    type: "str | None" = None
    protection: "str | None" = None

    @classmethod
    def from_memory_info(cls, region) -> "CapturedRegion":
        """Convert one raw ``MinidumpMemoryInfo``.

        Raises ``RangeError`` for a region whose values the model cannot
        represent: a non-positive ``RegionSize``, a ``None`` size/address
        from a truncated stream, a base or allocation base outside the
        64-bit space, or ``base + size`` past it. Propagates
        ``AttributeError``/``TypeError`` when ``region`` is missing an
        expected field entirely -- genuine parser-shape drift, deliberately
        not masked. Bulk enumeration uses :meth:`try_from_memory_info`."""
        base = _check_address(region.BaseAddress, "region.BaseAddress")
        size = _check_int(region.RegionSize, "region.RegionSize")
        allocation_base = getattr(region, "AllocationBase", None)
        if allocation_base is not None:
            _check_address(allocation_base, "region.AllocationBase")
        return cls(
            range=VirtualRange(base, size),
            allocation_base=allocation_base,
            state=_flag_name(getattr(region, "State", None)),
            type=_flag_name(getattr(region, "Type", None)),
            protection=_flag_name(getattr(region, "Protect", None)),
        )

    @classmethod
    def try_from_memory_info(cls, region) -> "CapturedRegion | None":
        """:meth:`from_memory_info`, returning ``None`` for a region whose
        VALUES the model cannot represent (a zero or negative
        ``RegionSize``, a ``None`` field, an address outside the 64-bit
        space, an overflowing ``base + size``) -- the same skip every
        hunter's own scan loop applies to ``RegionSize <= 0``, so one
        malformed descriptor never costs the whole table.

        Only ``RangeError`` is swallowed. A region OBJECT missing an
        expected attribute still raises ``AttributeError``/``TypeError`` --
        that is library-shape drift, not a malformed descriptor, and must
        stay loud."""
        try:
            return cls.from_memory_info(region)
        except RangeError:
            return None

    @property
    def base_address(self) -> int:
        return self.range.base_address

    @property
    def end_address(self) -> int:
        return self.range.end_address

    @property
    def size(self) -> int:
        return self.range.size

    def contains_address(self, address: int) -> bool:
        return self.range.contains_address(address)

    def clip_to(self, boundary: VirtualRange) -> "CapturedRegion | None":
        """This region narrowed to ``boundary``, carrying the same
        allocation/state/type/protection metadata (those are properties of
        the whole allocation, not of any sub-range). ``None`` when the
        region does not overlap ``boundary``."""
        clipped = self.range.intersection(boundary)
        if clipped is None:
            return None
        return CapturedRegion(
            range=clipped,
            allocation_base=self.allocation_base,
            state=self.state,
            type=self.type,
            protection=self.protection,
        )


@dataclass(frozen=True)
class CapturedSegment:
    """An immutable view of one ``Memory64List``/``MemoryList`` segment:
    the virtual range the dump captured and the byte ``file_offset`` in
    the .dmp where those bytes begin. A segment entry is itself the dump's
    claim that every byte of ``range`` is present at
    ``[file_offset, file_offset + range.size)`` in the file.
    """
    range: VirtualRange
    file_offset: int

    def __post_init__(self):
        _check_int(self.file_offset, "file_offset")
        if self.file_offset < 0:
            raise RangeError(f"file_offset ({self.file_offset}) must be non-negative")

    @classmethod
    def from_segment(cls, segment) -> "CapturedSegment":
        """Convert one raw ``Memory64List``/``MemoryList`` segment.

        Raises ``RangeError`` for a segment whose values the model cannot
        represent: a zero ``size``/``DataSize``, a start outside the
        64-bit space, an end past it, or a negative ``start_file_address``.
        ``size`` is read from the entry directly; when it is absent the
        range is built from ``[start_virtual_address, end_virtual_address)``
        as a half-open span, so an ``end_virtual_address`` of exactly
        ``1 << 64`` (the legal exclusive top of the space) is accepted the
        same way :meth:`VirtualRange.from_endpoints` accepts it. An object
        carrying neither ``size`` nor ``end_virtual_address`` raises
        ``AttributeError`` -- genuine parser-shape drift, deliberately not
        masked. Bulk enumeration uses :meth:`try_from_segment`."""
        base = _check_address(segment.start_virtual_address, "segment.start_virtual_address")
        size = getattr(segment, "size", None)
        vrange = (VirtualRange(base, size) if size is not None
                  else VirtualRange.from_endpoints(base, segment.end_virtual_address))
        return cls(range=vrange, file_offset=segment.start_file_address)

    @classmethod
    def try_from_segment(cls, segment) -> "CapturedSegment | None":
        """:meth:`from_segment`, returning ``None`` for a segment whose
        VALUES the model cannot represent -- a zero-length descriptor, an
        address outside the 64-bit space, an overflowing end, a ``None``
        field. Bulk enumeration uses this so one malformed descriptor
        never costs the whole table (the same skip
        ``dumpex.core.memory.va_range_captured_bytes`` already gives a
        zero-length segment).

        Only ``RangeError`` is swallowed. A segment OBJECT missing every
        size field still raises ``AttributeError`` -- library-shape drift,
        not a malformed descriptor."""
        try:
            return cls.from_segment(segment)
        except RangeError:
            return None

    @property
    def base_address(self) -> int:
        return self.range.base_address

    @property
    def end_address(self) -> int:
        return self.range.end_address

    @property
    def size(self) -> int:
        return self.range.size

    def contains_address(self, address: int) -> bool:
        return self.range.contains_address(address)

    def file_offset_at(self, address: int) -> int:
        """The .dmp byte offset of ``address``. Raises RangeError when
        ``address`` is outside this segment -- the offset would otherwise
        point at bytes belonging to another segment or to none at all."""
        if not self.range.contains_address(address):
            raise RangeError(f"0x{address:x} is outside segment {self.range}")
        return self.file_offset + (address - self.base_address)

    def clip_to(self, boundary: VirtualRange) -> "CapturedSegment | None":
        """This segment narrowed to ``boundary``, with ``file_offset``
        shifted to stay pointed at the clipped base. ``None`` when the
        segment does not overlap ``boundary``."""
        clipped = self.range.intersection(boundary)
        if clipped is None:
            return None
        return CapturedSegment(
            range=clipped,
            file_offset=self.file_offset + (clipped.base_address - self.base_address),
        )


@dataclass(frozen=True)
class CapturedSlice:
    """How a requested virtual range relates to the dump's captured
    evidence -- a purely structural fact from the segment table.

    ``requested``
        the range asked for, unchanged.
    ``captured``
        the contiguous prefix of ``requested`` the segment table backs,
        starting at ``requested.base_address``; ``None`` when the base
        itself is not captured. Never longer than ``requested``.
    ``uncaptured_suffix``
        the tail of ``requested`` past ``captured`` that the dump does not
        contain -- bytes that only a fuller recollection can supply;
        ``None`` when the whole request is captured. Always exactly
        ``requested.suffix_after(captured_bytes)``.
    ``file_offset``
        the .dmp byte offset of ``captured.base_address``; ``None`` iff
        ``captured`` is ``None``.
    ``segments``
        the captured segments clipped to ``captured``, tiling it in
        ascending address order with no gap or overlap, each carrying its
        own already-adjusted file offset. Empty iff ``captured`` is
        ``None``.
    ``overlapping``
        ``True`` when two or more source entries cover one virtual address
        inside the captured prefix -- a contradictory table, since a
        captured byte has exactly one place in the .dmp. Detected by
        length (the entries' intersections with ``captured`` sum to more
        than ``captured_bytes``), so it holds even for an entry the run
        completed before reaching. ``file_offset`` and ``segments`` are
        still resolved deterministically (each byte's offset from the
        first entry in ``(base_address, end_address)`` order that reaches
        it), but a consumer must treat that provenance as one arbitrary
        choice among conflicting claims and surface the anomaly rather
        than trust the offset. ``captured_bytes`` / ``state`` are
        unaffected. Always ``False`` for a well-formed table, and for an
        overlap that lies entirely outside the captured prefix.

    Every invariant above is enforced at construction, so a
    ``CapturedSlice`` -- however built -- is a normalized value.
    ``captured_bytes`` and ``state`` are derived, never stored.

    This type says nothing about whether a later read of ``captured``
    succeeds, nor whether a consumer's algorithm ran to completion. Call
    :meth:`read_input` with the byte count a read actually returned to get
    the requested / read / unread-suffix breakdown as a :class:`ReadSlice`.
    """
    requested: VirtualRange
    captured: "VirtualRange | None"
    uncaptured_suffix: "VirtualRange | None"
    file_offset: "int | None"
    segments: "tuple[CapturedSegment, ...]" = ()
    overlapping: bool = False

    def __post_init__(self):
        object.__setattr__(self, "segments", tuple(self.segments))
        if not isinstance(self.overlapping, bool):
            raise RangeError("CapturedSlice.overlapping must be a bool")
        cap = self.captured
        if cap is None:
            if self.file_offset is not None:
                raise RangeError(
                    "CapturedSlice.file_offset must be None when nothing is captured")
            if self.segments:
                raise RangeError(
                    "CapturedSlice.segments must be empty when nothing is captured")
            if self.uncaptured_suffix != self.requested:
                raise RangeError(
                    "CapturedSlice.uncaptured_suffix must be the whole request when "
                    "nothing is captured")
            return
        if cap.base_address != self.requested.base_address:
            raise RangeError(
                "CapturedSlice.captured must start at requested.base_address")
        if cap.size > self.requested.size:
            raise RangeError(
                "CapturedSlice.captured cannot extend past the requested range")
        _check_int(self.file_offset, "CapturedSlice.file_offset")
        if self.file_offset < 0:
            raise RangeError("CapturedSlice.file_offset must be non-negative")
        if self.uncaptured_suffix != self.requested.suffix_after(cap.size):
            raise RangeError(
                "CapturedSlice.uncaptured_suffix must be "
                "requested.suffix_after(captured_bytes)")
        self._validate_segments(cap)

    def _validate_segments(self, captured: VirtualRange) -> None:
        if not self.segments:
            raise RangeError(
                "CapturedSlice.segments must tile a non-empty captured prefix")
        cursor = captured.base_address
        for seg in self.segments:
            if not isinstance(seg, CapturedSegment):
                raise RangeError(
                    "CapturedSlice.segments must all be CapturedSegment instances")
            if seg.base_address != cursor:
                raise RangeError(
                    "CapturedSlice.segments must tile the captured prefix in ascending "
                    "order with no gap or overlap")
            cursor = seg.end_address
        if cursor != captured.end_address:
            raise RangeError(
                "CapturedSlice.segments must cover exactly the captured prefix")
        if self.segments[0].file_offset != self.file_offset:
            raise RangeError(
                "CapturedSlice.segments[0].file_offset must equal "
                "CapturedSlice.file_offset")

    @property
    def captured_bytes(self) -> int:
        return 0 if self.captured is None else self.captured.size

    @property
    def state(self) -> CaptureState:
        if self.captured is None:
            return CaptureState.NONE
        if self.captured.size == self.requested.size:
            return CaptureState.COMPLETE
        return CaptureState.PARTIAL

    def read_input(self, read_bytes: int) -> "ReadSlice":
        """The contiguous input a consumer's read returned, as a
        :class:`ReadSlice`.

        ``read_bytes`` is the byte count the reader actually handed back,
        counting from ``requested.base_address`` -- normally
        ``captured_bytes``, fewer on a truncated file or a failed read
        past some point, and never more (a read cannot return bytes past
        the captured contiguous prefix). It must lie in
        ``[0, captured_bytes]``.

        This records only what was READ and passed to the algorithm.
        Whether the algorithm then ran to completion over those bytes --
        candidate-, window-, hit-, or deadline-bounded scanners often
        cannot -- is coverage status, which this module does not model.
        """
        _check_int(read_bytes, "read_bytes")
        if not 0 <= read_bytes <= self.captured_bytes:
            raise RangeError(
                f"read_bytes ({read_bytes}) must be within [0, {self.captured_bytes}] "
                f"-- a read cannot return bytes the dump never captured")
        return ReadSlice(capture=self, read_bytes=read_bytes)


@dataclass(frozen=True)
class ReadSlice:
    """The contiguous run of bytes a consumer's read returned from a
    requested range and handed to its algorithm, and the tail it did not
    read.

    ``capture``
        the structural :class:`CapturedSlice` the read ran against;
        ``requested`` / ``captured`` / ``uncaptured_suffix`` /
        ``file_offset`` / ``segments`` are all recoverable from it, so an
        observation cache that stores only a ``ReadSlice`` keeps full
        provenance.
    ``read_bytes``
        the byte count the reader returned, counting from the requested
        base; in ``[0, capture.captured_bytes]``.

    Everything else is derived. ``is_short`` is measured against the
    REQUESTED range (any shortfall the investigator asked for and did not
    get); ``is_io_short`` against the captured prefix (a read that came
    back shorter than the dump actually holds) -- the two are independent.

    This type does NOT prescribe a remediation for ``unread_suffix``:
    re-issuing a scan over a sub-range is a fresh request with its own
    ``(base_address, size)`` identity, a signature straddling ``read``'s
    end is evaluated by neither the original pass nor that sub-range, and
    whether the algorithm completed over ``read`` is coverage status.
    Those judgements belong to the consumer.
    """
    capture: CapturedSlice
    read_bytes: int

    def __post_init__(self):
        _check_int(self.read_bytes, "read_bytes")
        if not 0 <= self.read_bytes <= self.capture.captured_bytes:
            raise RangeError(
                f"ReadSlice.read_bytes ({self.read_bytes}) must be within "
                f"[0, {self.capture.captured_bytes}] -- a read cannot return bytes "
                f"the dump never captured")

    @property
    def requested(self) -> VirtualRange:
        return self.capture.requested

    @property
    def read(self) -> "VirtualRange | None":
        """The contiguous prefix of ``requested`` the read returned, or
        ``None`` when it returned nothing."""
        if not self.read_bytes:
            return None
        return VirtualRange(self.requested.base_address, self.read_bytes)

    @property
    def unread_suffix(self) -> "VirtualRange | None":
        """Everything past ``read`` -- the bytes the read did not return;
        ``None`` only when the read covered the whole request. Its
        uncaptured part is ``capture.uncaptured_suffix`` (needs a fuller
        dump); the rest is captured but was not returned by this read."""
        return self.requested.suffix_after(self.read_bytes)

    @property
    def is_short(self) -> bool:
        """The read did not return every byte of ``requested`` -- a short
        read against the requested range, whatever the cause (a structural
        gap, an I/O failure, or both). Equivalent to
        ``unread_suffix is not None``. A short capture the investigator
        asked past is a short read here even when the read got everything
        the dump holds."""
        return self.read_bytes < self.requested.size

    @property
    def is_io_short(self) -> bool:
        """The read returned fewer bytes than the segment table says are
        captured at the requested base -- a truncated file, a parser
        error, or an I/O failure past some point, as distinct from (or on
        top of) a structural gap. ``False`` when the read got everything
        the dump actually holds, even if that is less than ``requested``."""
        return self.read_bytes < self.capture.captured_bytes


def slice_captured(requested: VirtualRange, segments) -> CapturedSlice:
    """Accumulate the contiguous run of captured bytes starting at
    ``requested.base_address``.

    ``segments`` is any iterable of :class:`CapturedSegment`; it is sorted
    here (by ``(base_address, end_address)``), so the caller's order does
    not matter. The walk advances a cursor from the requested base through
    each segment that continues the run without a hole. A gap -- the next
    segment in address order starts past where the run currently reaches
    -- stops the walk: a segment further along that covers only the tail,
    with unwritten space in between, is not part of one extractable prefix
    and does not count. Segments that end at or before the cursor (short
    entries nested inside a longer one already walked) are skipped without
    ending the run.

    A real ``Memory64List``/``MemoryList`` table holds no two entries that
    cover the same virtual address, so ``captured_bytes`` and every file
    offset agree with ``dumpex.core.memory.va_to_file_offset`` /
    ``va_range_captured_bytes`` on any table those primitives accept.
    Should the input violate that -- two entries covering one VA inside
    the captured prefix -- the returned :class:`CapturedSlice` has
    ``overlapping`` set, so the contradiction is never silent.
    ``captured_bytes`` is still exact; ``file_offset``/``segments`` are
    still deterministic and caller-order-independent (each byte's offset
    from the first entry in ``(base_address, end_address)`` order that
    reaches it), but on such a table that choice CAN differ from
    ``va_to_file_offset`` (raw table order) and ``va_range_captured_bytes``
    (``base_address``-only order) -- a consumer must treat the provenance
    of an ``overlapping`` slice as unreliable.

    Never raises for a disjoint, overlapping, or empty ``segments`` -- an
    empty run is a :class:`CapturedSlice` with ``state`` ``NONE`` and the
    whole request as ``uncaptured_suffix``.
    """
    ordered = sorted(segments, key=lambda s: (s.base_address, s.end_address))
    base = requested.base_address
    end = requested.end_address
    cursor = base
    file_offset = None
    covering = []
    for seg in ordered:
        if seg.end_address <= cursor:
            continue
        if seg.base_address > cursor:
            break
        if file_offset is None:
            file_offset = seg.file_offset + (cursor - seg.base_address)
        run_end = min(seg.end_address, end)
        # The guards above hold seg.base_address <= cursor < run_end <=
        # seg.end_address, so this clip is always a non-empty sub-range.
        covering.append(seg.clip_to(VirtualRange.from_endpoints(cursor, run_end)))
        cursor = run_end
        if cursor >= end:
            break
    captured_bytes = cursor - base
    captured = VirtualRange(base, captured_bytes) if captured_bytes > 0 else None
    return CapturedSlice(
        requested=requested,
        captured=captured,
        uncaptured_suffix=requested.suffix_after(captured_bytes),
        file_offset=file_offset,
        segments=tuple(covering),
        overlapping=_segments_overlap(ordered, captured),
    )


def _segments_overlap(ordered_segments, captured: "VirtualRange | None") -> bool:
    """Whether the segments jointly cover any byte of ``captured`` more
    than once -- checked by length, independent of the walk above: for a
    non-overlapping table each segment's intersection with ``captured``
    sums to exactly ``captured.size``; anything more means two entries
    place one virtual address in two file locations. Catches an
    overlapping entry the walk never visited because an earlier segment
    had already completed the run. ``ordered_segments`` is ascending by
    ``base_address``, so the scan stops at the first segment starting at
    or past ``captured``'s end."""
    if captured is None:
        return False
    covered = 0
    for seg in ordered_segments:
        if seg.base_address >= captured.end_address:
            break
        piece = seg.range.intersection(captured)
        if piece is not None:
            covered += piece.size
    return covered > captured.size


@dataclass(frozen=True)
class CapturedEnumeration:
    """The result of enumerating a dump's region or segment table into
    value views: ``views`` in ascending address order, and ``skipped`` --
    how many raw descriptors the value model could not represent (a
    zero-length or overflowing entry, a ``None`` size/address from a
    truncated stream). ``skipped`` is what makes the descriptor loss an
    observable coverage fact rather than a silent shortening, for a
    diagnostic or ``--profile`` consumer.

    A descriptor MISSING an expected field entirely (not merely holding a
    bad value) is genuine parser-shape drift and is NOT counted here -- it
    propagates out as ``AttributeError``/``TypeError``, the same way
    ``dumpex.core.memory``'s own ``HandleDescriptorLayoutError`` refuses to
    paper over library drift."""
    views: tuple = ()
    skipped: int = 0

    def __post_init__(self):
        object.__setattr__(self, "views", tuple(self.views))
        _check_int(self.skipped, "CapturedEnumeration.skipped")
        if self.skipped < 0:
            raise RangeError("CapturedEnumeration.skipped must be non-negative")


def enumerate_captured_segments(mf) -> CapturedEnumeration:
    """Every ``Memory64List``/``MemoryList`` segment of ``mf`` as a
    :class:`CapturedEnumeration` -- the same
    ``Memory64List``-preferred-over-``MemoryList`` table
    ``dumpex.core.memory`` resolves virtual addresses against. A
    non-representable descriptor is counted in ``skipped``, not raised on;
    its bytes then read as uncaptured against the result, the conservative
    direction. The ``dumpex.core.memory`` import is deferred so this
    module stays import-light for a caller that only needs the value
    types."""
    from dumpex.core.memory import get_memory_segments
    views, skipped = [], 0
    for raw in get_memory_segments(mf):
        view = CapturedSegment.try_from_segment(raw)
        if view is None:
            skipped += 1
        else:
            views.append(view)
    views.sort(key=lambda s: (s.base_address, s.end_address))
    return CapturedEnumeration(tuple(views), skipped)


def enumerate_captured_regions(mf) -> CapturedEnumeration:
    """Every ``MemoryInfoListStream`` region of ``mf`` as a
    :class:`CapturedEnumeration`, with the same skip-not-raise contract as
    :func:`enumerate_captured_segments`. A dropped region silently removes
    its allocation/protection metadata for that span, so ``skipped`` is
    the signal a consumer needs to know the region view is incomplete."""
    from dumpex.core.memory import get_memory_regions
    views, skipped = [], 0
    for raw in get_memory_regions(mf):
        view = CapturedRegion.try_from_memory_info(raw)
        if view is None:
            skipped += 1
        else:
            views.append(view)
    views.sort(key=lambda r: (r.base_address, r.end_address))
    return CapturedEnumeration(tuple(views), skipped)


def captured_segments(mf) -> "tuple[CapturedSegment, ...]":
    """The ``views`` of :func:`enumerate_captured_segments` -- an
    ascending-address tuple of :class:`CapturedSegment`. Never raises for
    a malformed segment table; use :func:`enumerate_captured_segments`
    when the count of skipped descriptors matters."""
    return enumerate_captured_segments(mf).views


def captured_regions(mf) -> "tuple[CapturedRegion, ...]":
    """The ``views`` of :func:`enumerate_captured_regions` -- an
    ascending-address tuple of :class:`CapturedRegion`. Never raises for a
    malformed region list; use :func:`enumerate_captured_regions` when the
    count of skipped descriptors matters."""
    return enumerate_captured_regions(mf).views


def capture_of(mf, requested: VirtualRange) -> CapturedSlice:
    """:func:`slice_captured` for ``requested`` against ``mf``'s own
    captured-segment table. Never raises for a malformed segment table --
    :func:`captured_segments` skips any descriptor it cannot represent."""
    return slice_captured(requested, captured_segments(mf))


def region_containing(address: int, regions) -> "CapturedRegion | None":
    """The first region whose range contains ``address``, or ``None``.
    ``regions`` is any iterable of :class:`CapturedRegion`."""
    for region in regions:
        if region.contains_address(address):
            return region
    return None


def segment_containing(address: int, segments) -> "CapturedSegment | None":
    """The first segment whose range contains ``address``, or ``None``.
    ``segments`` is any iterable of :class:`CapturedSegment`."""
    for segment in segments:
        if segment.contains_address(address):
            return segment
    return None
