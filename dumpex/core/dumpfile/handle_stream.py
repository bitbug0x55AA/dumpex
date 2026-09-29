"""HandleDataStream parsing: bounded descriptor and name reads, the
descriptor-layout validation that selects a parser stride, and the
declared-versus-delivered descriptor counts every handle consumer reports.

The one bound entry point is `dumpex.core.memory.parse_handle_stream`,
which supplies the descriptor classes, the process-lifetime layout cache
and the descriptor cap from the legacy module's namespace.
"""
import io

from minidump.streams.HandleDataStream import MINIDUMP_HANDLE_DATA_STREAM


# ── Handle stream: a dumpex-owned bounded parse (issue #37 §5.1) ───────────
# Registered in dumpex.core.memory's _STREAM_DISPATCH IN PLACE OF the library's own
# MinidumpHandleDataStream.parse, for three reasons, each grounded in the
# installed library's code (.venv/Lib/site-packages/minidump/streams/
# HandleDataStream.py):
#   1. MinidumpHandleDescriptor.parse() walks a v2 descriptor's
#      ObjectInfoRva -> NextInfoRva chain with NO cycle detection -- a
#      self-referential chain from a crafted dump hangs forever, which no
#      try/except can isolate. dumpex never needs that data (see §5.3 --
#      ObjectInfos is out of scope for every dumpex mode), so it is never
#      walked here: ObjectInfos always stays [].
#   2. MINIDUMP_STRING.parse() reads a dump-controlled UINT32 Length and
#      immediately does buff.read(ms.Length) -- an unbounded read of up to
#      4 GiB. Every string read here is bounded at MAX_HANDLE_STRING_BYTES.
#   3. MINIDUMP_STRING.get_from_rva() returns the literal placeholder
#      '<STRING_DECODE_FAILED>' on a decode error. That string must never
#      reach a record; a failed read/decode becomes None here instead.

MAX_HANDLE_DESCRIPTORS   = 65536   # descriptors parsed from HandleDataStream
MAX_HANDLE_STRING_BYTES  = 4096    # bytes read for one TypeName/ObjectName
_DESCRIPTOR_PROBE_BYTES  = 64      # scratch buffer for _descriptor_class_size();
                                    # must comfortably exceed either real descriptor
                                    # size or a parser that reads past it would look
                                    # like a clean, in-bounds size instead of failing


class HandleDescriptorLayoutError(Exception):
    """Raised when the installed minidump library's HandleDataStream
    descriptor classes no longer match the on-disk layout dumpex assumes
    (MINIDUMP_HANDLE_DESCRIPTOR == 32 bytes, MINIDUMP_HANDLE_DESCRIPTOR_2
    == 40 bytes, and the two must differ) -- an explicit exception rather
    than a bare `assert`, since `assert` is compiled out entirely under
    `python -O`/`PYTHONOPTIMIZE=1`, silently leaving SizeOfDescriptor
    comparisons against whatever the drifted parse() happens to consume.
    Raised lazily, from inside parse_handle_stream() (not at import time),
    so a layout that fails to validate is caught by open_dump()'s
    per-stream isolation like any other stream parser's exception --
    every OTHER command still runs; only --handles / the pipe hunter's
    handle scan lose this stream."""


def _descriptor_class_size(descriptor_cls) -> int:
    """The number of bytes descriptor_cls.parse() consumes for one
    descriptor, derived by actually parsing a zero-filled scratch buffer
    rather than trusting a `.size` class attribute: MINIDUMP_HANDLE_
    DESCRIPTOR carries one, but the installed library's MINIDUMP_HANDLE_
    DESCRIPTOR_2 does not -- reading `.size` on it raises AttributeError.
    This reports the same fact `.size` would, symmetrically for both
    classes, without assuming the attribute exists on either.

    Raises HandleDescriptorLayoutError if parse() consumes the entire
    probe buffer (the true size could be >= _DESCRIPTOR_PROBE_BYTES and
    would otherwise be silently misreported as exactly that many bytes),
    or if the class DOES carry a `.size` attribute that disagrees with
    what parse() actually consumed -- that disagreement is itself the
    most direct signal of upstream drift, and dropping it (rather than
    just never reading `.size` at all) would remove a detector the
    original library code depends on for the very same branch."""
    probe = io.BytesIO(bytes(_DESCRIPTOR_PROBE_BYTES))
    descriptor_cls.parse(probe)
    consumed = probe.tell()
    if consumed >= _DESCRIPTOR_PROBE_BYTES:
        raise HandleDescriptorLayoutError(
            f"{descriptor_cls.__name__}.parse() consumed the entire "
            f"{_DESCRIPTOR_PROBE_BYTES}-byte probe buffer -- its real size "
            f"cannot be determined from this probe")
    declared = getattr(descriptor_cls, "size", None)
    if declared is not None and declared != consumed:
        raise HandleDescriptorLayoutError(
            f"{descriptor_cls.__name__}.size ({declared}) disagrees with what "
            f"its own parse() actually consumes on a zero-filled probe "
            f"({consumed} bytes)")
    return consumed


def validated_descriptor_layout(v1_descriptor, v2_descriptor, class_size) -> "tuple[int, int]":
    """Returns (v1_size, v2_size) -- the MS-defined on-disk sizes the
    SizeOfDescriptor branch in parse_bounded_handle_stream() relies on to
    pick a parser class -- derived by `class_size` (normally
    _descriptor_class_size) from the two descriptor classes and validated.
    Derives afresh on every call; dumpex.core.memory._handle_descriptor_layout
    holds the process-lifetime cache of the result.

    Raises HandleDescriptorLayoutError -- explicitly, not via `assert`,
    so the check survives `python -O` -- if either derived size disagrees
    with the MS-defined 32/40, if the two derived sizes are equal (which
    would make the MINIDUMP_HANDLE_DESCRIPTOR_2 branch permanently
    unreachable, silently parsing every v2 stream as v1), or if
    `class_size` itself fails."""
    try:
        v1_size = class_size(v1_descriptor)
        v2_size = class_size(v2_descriptor)
    except HandleDescriptorLayoutError:
        raise
    except Exception as e:
        raise HandleDescriptorLayoutError(
            f"could not determine HandleDataStream descriptor sizes from the "
            f"installed minidump library: {type(e).__name__}: {e}") from e

    # Checked ahead of the exact 32/40 values below: this is the invariant
    # the SizeOfDescriptor branch in parse_bounded_handle_stream() actually needs
    # (two distinct strides to choose between) and holds independently of
    # what the two specific expected sizes are, so it stays meaningful
    # even if a future change to the exact-value checks below is ever
    # loosened.
    if v1_size == v2_size:
        raise HandleDescriptorLayoutError(
            f"MINIDUMP_HANDLE_DESCRIPTOR and MINIDUMP_HANDLE_DESCRIPTOR_2 both "
            f"parse as {v1_size} bytes -- the v2 branch would never be reachable")
    if v1_size != 32:
        raise HandleDescriptorLayoutError(
            f"minidump.streams.HandleDataStream.MINIDUMP_HANDLE_DESCRIPTOR now "
            f"parses as {v1_size} bytes, not the 32 dumpex assumes")
    if v2_size != 40:
        raise HandleDescriptorLayoutError(
            f"minidump.streams.HandleDataStream.MINIDUMP_HANDLE_DESCRIPTOR_2 now "
            f"parses as {v2_size} bytes, not the 40 dumpex assumes")

    return v1_size, v2_size


class HandleStreamFramingError(Exception):
    """Raised by parse_handle_stream() when the stream's own framing
    cannot be trusted at all (header short-read, SizeOfHeader out of
    bounds, or an unrecognized SizeOfDescriptor) -- distinct from a
    truncated-but-otherwise-usable stream (see HANDLE_STREAM_TRUNCATED
    in the #37 contract), which is not an error at this layer: the
    caller still gets every descriptor that fits. Caught by open_dump()'s
    per-stream isolation like any other stream parser's exception."""


class ParsedHandleDescriptor:
    """One HandleDataStream descriptor, normalized just enough to be
    safe to hold: bounded name reads, no ObjectInfos walk. Deliberately
    exposes the SAME attribute set as the library's own
    MinidumpHandleDescriptor (Handle, TypeName, ObjectName, Attributes,
    GrantedAccess, HandleCount, PointerCount, ObjectInfos) so
    dumpex.core.memory.get_handles() and its existing hunt consumers
    (the pipe hunter reads TypeName/ObjectName) keep working unchanged.

    TypeNameRva/ObjectNameRva are ALSO carried (beyond that compatibility
    set) purely so a future --handles record builder (#42) can tell "no
    name at all" (Rva == 0) apart from "a name that should be there but
    could not be read" (Rva != 0, TypeName/ObjectName is None) -- both
    collapse to the same None here, and only the raw Rva can still
    distinguish them. Existing consumers reading only the documented
    attributes are unaffected."""
    __slots__ = ("Handle", "TypeName", "ObjectName", "Attributes", "GrantedAccess",
                 "HandleCount", "PointerCount", "ObjectInfos",
                 "TypeNameRva", "ObjectNameRva")

    def __init__(self, *, handle, type_name, object_name, attributes, granted_access,
                 handle_count, pointer_count, type_name_rva, object_name_rva):
        self.Handle         = handle
        self.TypeName       = type_name
        self.ObjectName     = object_name
        self.Attributes     = attributes
        self.GrantedAccess  = granted_access
        self.HandleCount    = handle_count
        self.PointerCount   = pointer_count
        self.ObjectInfos    = []   # never walked -- see module-level comment above
        self.TypeNameRva    = type_name_rva
        self.ObjectNameRva  = object_name_rva


class _BoundedDescriptorReader:
    """A `.read(n)`-only view over `chunk`, limited to the byte range
    `[start, end)` belonging to ONE descriptor -- raises
    HandleDescriptorLayoutError the MOMENT a read call would cross
    `end`, rather than letting descriptor_cls.parse() silently read past
    its own stride and finding out afterward (or not at all).

    This exists because a raw BytesIO's read(n) SILENTLY CLAMPS to
    however many bytes physically remain in the whole shared buffer --
    it never raises, it just returns fewer bytes than asked for. For any
    descriptor OTHER than the last one, an over-read spills into the
    NEXT descriptor's real bytes, and the post-parse tell()-delta check
    in parse_handle_stream() catches the mismatch (consumed > declared).
    But for the LAST descriptor, there is nothing real left in the
    buffer to spill into -- an over-read attempt just hits the buffer's
    own physical end and gets clamped there, exactly where tell() would
    ALSO land for a legitimate full read of that stride. The two cases
    are byte-for-byte indistinguishable from the tell()-delta check's
    point of view once they've already happened; this class stops the
    read from happening in the first place, so it doesn't matter whether
    anything real exists past the boundary or not."""
    __slots__ = ("_chunk", "_end", "_descriptor_index")

    def __init__(self, chunk, end, descriptor_index):
        self._chunk = chunk
        self._end = end
        self._descriptor_index = descriptor_index

    def read(self, n=-1):
        pos = self._chunk.tell()
        if n is None or n < 0:
            n = self._end - pos
        if pos + n > self._end:
            raise HandleDescriptorLayoutError(
                f"a descriptor parse attempted to read {n} byte(s) starting "
                f"at buffer offset {pos} for descriptor {self._descriptor_index}, "
                f"which would cross its own SizeOfDescriptor boundary at "
                f"{self._end} -- the installed minidump library's layout no "
                f"longer matches what this stride was selected for")
        return self._chunk.read(n)

    def tell(self):
        return self._chunk.tell()


class ParsedHandleDataStream:
    """Return value of parse_handle_stream(): `.header` (the raw
    MINIDUMP_HANDLE_DATA_STREAM) and `.handles` (a list of
    ParsedHandleDescriptor, at most min(header.NumberOfDescriptors,
    MAX_HANDLE_DESCRIPTORS, however many whole descriptors actually fit
    in the stream's own DataSize) long).

    The caller can always recover how many were truncated as
    header.NumberOfDescriptors - len(handles) -- through
    truncated_descriptor_count() below, which is that rule's one
    implementation and the only place either attribute is read for it."""
    __slots__ = ("header", "handles")

    def __init__(self, header, handles):
        self.header  = header
        self.handles = handles


class HandleStreamContractError(RuntimeError):
    """`parse_handle_stream`'s returned object does not expose the shape
    its readers require -- no `.header`/`.handles` attribute, or a header
    with no `NumberOfDescriptors` field at all.

    A defect in this module or in the minidump library it parses with,
    never a property of the dump: every path that produces a
    ParsedHandleDataStream sets both attributes. Raised rather than
    absorbed because the alternative answer -- "0 descriptors declared",
    hence "nothing was truncated" -- is indistinguishable from a complete
    stream, which is exactly the silent-clean-result outcome the
    truncation limitation exists to prevent. Same fail-loud reasoning as
    HandleDescriptorLayoutError above.
    """


def declared_descriptor_count(parsed) -> "int | None":
    """`header.NumberOfDescriptors` off a parsed HandleDataStream: how
    many descriptors the stream says its array holds, independent of how
    many `parse_handle_stream` could actually read.

    None for `parsed is None` (no stream, nothing declared) and for a
    declared count that is not usable as one -- `None`, a bool, a
    non-int, or a negative -- which is exactly how `parse_handle_stream`
    itself treats those values when it bounds its own read. A caller
    wanting a number reads that None as "nothing is KNOWN to be
    declared", never as zero descriptors declared.

    A `parsed` object with no `.header`, or a header with no
    `NumberOfDescriptors` attribute, raises HandleStreamContractError: an
    attribute that has been renamed or a return shape that has changed
    must not degrade into a silent "nothing was truncated".
    """
    if parsed is None:
        return None
    try:
        header = parsed.header
    except AttributeError as exc:
        raise HandleStreamContractError(
            f"{type(parsed).__name__} exposes no .header -- "
            f"parse_handle_stream's return shape has changed") from exc
    try:
        declared = header.NumberOfDescriptors
    except AttributeError as exc:
        raise HandleStreamContractError(
            f"{type(header).__name__} exposes no NumberOfDescriptors -- the "
            f"HandleDataStream header layout has changed") from exc
    if declared is None or isinstance(declared, bool) or not isinstance(declared, int):
        return None
    return declared if declared >= 0 else None


def truncated_descriptor_count(parsed) -> int:
    """The descriptor tail a parsed HandleDataStream declared but did not
    deliver: `header.NumberOfDescriptors - len(handles)`, floored at 0.
    ParsedHandleDataStream's own docstring states this recovery rule; this
    is the one implementation of it, shared by every reader
    (`--handles`, `--profile`, `--hunt pipe`) so a truncated dump cannot
    be described three different ways in one case file.

    Read off the parsed object, NEVER recomputed from the stream's own
    declared framing (`(DataSize - SizeOfHeader) // SizeOfDescriptor`,
    bounded by NumberOfDescriptors and MAX_HANDLE_DESCRIPTORS):
    parse_handle_stream bounds what it delivers by a FOURTH term that
    framing omits -- how many bytes the file actually held -- so a
    recomputation reports a SMALLER gap than reality on exactly the
    truncated file this count exists for, and none at all when the
    framing claims room the file never had.

    0 when nothing is known to be missing: no stream, no usable declared
    count, or a stream that delivered everything it declared. 0 as well
    when it delivered MORE than it declared -- that is a contradiction in
    the dump's own numbers, not a negative shortfall, and no descriptor
    is missing either way.
    """
    declared = declared_descriptor_count(parsed)
    if declared is None:
        return 0
    try:
        delivered = parsed.handles
    except AttributeError as exc:
        raise HandleStreamContractError(
            f"{type(parsed).__name__} exposes no .handles -- "
            f"parse_handle_stream's return shape has changed") from exc
    return max(0, declared - len(delivered or ()))


def _read_handle_string(rva: int, file_handle, max_bytes: int = MAX_HANDLE_STRING_BYTES):
    """MINIDUMP_STRING.get_from_rva(), but bounded and returning None
    (never the library's own '<STRING_DECODE_FAILED>' placeholder, and
    never an unbounded read of a dump-controlled Length) on any failure.
    Returns "" -- not None -- for a non-zero RVA whose Length is
    genuinely 0: that's a successful read of an empty name, a different
    fact from "could not be read" (see the #37 contract's §5.2.1). The
    caller must not call this for rva == 0 (that's "no name at all",
    handled by the caller before ever reaching here)."""
    pos = file_handle.tell()
    try:
        file_handle.seek(rva, 0)
        length_bytes = file_handle.read(4)
        if len(length_bytes) < 4:
            return None
        length = int.from_bytes(length_bytes, byteorder="little", signed=False)
        if length == 0:
            return ""
        if length > max_bytes:
            return None
        raw = file_handle.read(length)
        if len(raw) < length:
            return None
        return raw.decode("utf-16-le")
    except Exception:
        return None
    finally:
        file_handle.seek(pos, 0)


def parse_bounded_handle_stream(directory, file_handle, *, descriptor_layout,
                                v1_descriptor, v2_descriptor,
                                max_descriptors) -> ParsedHandleDataStream:
    """dumpex's own bounded, validated HandleDataStream parser -- see the
    module-level comment above for why the library's own
    MinidumpHandleDataStream.parse is not used. `directory` is the
    stream's own MINIDUMP_DIRECTORY entry (its `.Location` gives the
    stream's Rva/DataSize within the file); `file_handle` is the dump's
    raw file object (HandleDataStream Rva values are FILE offsets, not
    virtual addresses -- there is no process-memory reader involved).

    `descriptor_layout()` returns the validated (v1_size, v2_size) pair
    and is called only once the header's own framing has been checked;
    `v1_descriptor`/`v2_descriptor` are the parser classes for those two
    strides; `max_descriptors` caps how many descriptors are parsed.
    dumpex.core.memory.parse_handle_stream binds all four.

    Raises HandleStreamFramingError when the stream's own framing cannot
    be trusted (header short-read, an out-of-bounds SizeOfHeader, or an
    unrecognized SizeOfDescriptor) -- nothing in the stream can be
    located reliably in that case. A NumberOfDescriptors beyond what
    `max_descriptors`/the stream's own DataSize can support is NOT
    an error here: it is silently capped, and the caller can recover the
    truncated count as header.NumberOfDescriptors - len(result.handles)."""
    location = directory.Location
    if location.DataSize < 16:
        raise HandleStreamFramingError(
            f"HandleDataStream is {location.DataSize} byte(s), too small to "
            f"contain its own 16-byte header")

    file_handle.seek(location.Rva, 0)
    header_bytes = file_handle.read(16)
    if len(header_bytes) < 16:
        raise HandleStreamFramingError("HandleDataStream header short read")
    header = MINIDUMP_HANDLE_DATA_STREAM.parse(io.BytesIO(header_bytes))

    # The library seeks to Location.Rva, reads the header, then reads
    # descriptors from immediately after it -- ignoring SizeOfHeader
    # entirely. A header the producer declared as larger than 16 bytes
    # carries fields dumpex does not know; reading descriptors from a
    # hardcoded +16 in that case would silently misread every one of
    # them, so the descriptor array's start is computed from the
    # declared SizeOfHeader instead, once it's been range-checked.
    if not (16 <= header.SizeOfHeader <= location.DataSize):
        raise HandleStreamFramingError(
            f"HandleDataStream SizeOfHeader {header.SizeOfHeader} is out of bounds "
            f"for a {location.DataSize}-byte stream")

    v1_size, v2_size = descriptor_layout()
    if header.SizeOfDescriptor == v1_size:
        descriptor_cls = v1_descriptor
    elif header.SizeOfDescriptor == v2_size:
        descriptor_cls = v2_descriptor
    else:
        raise HandleStreamFramingError(
            f"HandleDataStream SizeOfDescriptor {header.SizeOfDescriptor} is neither "
            f"{v1_size} (MINIDUMP_HANDLE_DESCRIPTOR) nor "
            f"{v2_size} (MINIDUMP_HANDLE_DESCRIPTOR_2)")

    available_bytes = location.DataSize - header.SizeOfHeader
    fits = available_bytes // header.SizeOfDescriptor   # a trailing partial
                                                          # descriptor is not parsed
    declared = header.NumberOfDescriptors if header.NumberOfDescriptors is not None else 0
    usable = max(0, min(declared, max_descriptors, fits))

    file_handle.seek(location.Rva + header.SizeOfHeader, 0)
    raw_descriptors = file_handle.read(usable * header.SizeOfDescriptor)
    # `fits` above is derived from location.DataSize -- the PRODUCER's own
    # declared stream size, not from how many bytes the underlying file
    # object actually had left to give. A dump truncated partway through
    # the descriptor array (the file ends before DataSize says it should)
    # would otherwise hand descriptor_cls.parse() a short/empty buffer for
    # the missing descriptors; parse() reading b"" back as all-zero fields
    # (Handle=0, HandleCount=0, ...) rather than raising fabricates
    # descriptors that were never on disk, AND breaks the "header.
    # NumberOfDescriptors - len(handles) recovers the truncated count"
    # contract documented on ParsedHandleDataStream below, since every
    # such fabricated zero-descriptor still gets appended to handles. The
    # actual byte count read is a fourth, independent upper bound on how
    # many WHOLE descriptors can be parsed, alongside declared/
    # max_descriptors/fits.
    usable = min(usable, len(raw_descriptors) // header.SizeOfDescriptor)
    chunk = io.BytesIO(raw_descriptors)

    handles = []
    for i in range(usable):
        # Seeking to this descriptor's own stride-aligned offset before
        # every parse prevents CROSS-descriptor misalignment (a parser
        # that over/under-reads for descriptor i can no longer corrupt
        # where descriptor i+1 starts). Wrapping `chunk` in a
        # _BoundedDescriptorReader limited to exactly this descriptor's
        # own [start, end) range catches an OVER-read the moment it's
        # attempted -- including for the LAST descriptor, where a raw
        # BytesIO's read(n) would otherwise silently clamp to the
        # buffer's own physical end (indistinguishable, from the
        # caller's side, from a legitimate full read) rather than raise.
        # The tell()-delta check below still independently catches
        # UNDER-consumption (parse() finishing early, never attempting
        # to cross the boundary at all) -- the two checks are
        # complementary, not redundant: the reader stops an over-read
        # from happening; the delta check notices a parse that simply
        # never read enough in the first place.
        start = i * header.SizeOfDescriptor
        end = start + header.SizeOfDescriptor
        chunk.seek(start)
        raw = descriptor_cls.parse(_BoundedDescriptorReader(chunk, end, i))
        consumed = chunk.tell() - start
        if consumed != header.SizeOfDescriptor:
            # Not a HandleStreamFramingError: the STREAM's own framing
            # (SizeOfDescriptor, SizeOfHeader, ...) is exactly what it
            # declared to be -- this is the INSTALLED minidump library's
            # descriptor_cls.parse() disagreeing with the stride that was
            # selected for it, i.e. an upstream layout drift, the same
            # class of error validated_descriptor_layout() raises.
            raise HandleDescriptorLayoutError(
                f"{descriptor_cls.__name__}.parse() consumed {consumed} bytes "
                f"for descriptor {i}, not the declared SizeOfDescriptor "
                f"{header.SizeOfDescriptor} -- the installed minidump "
                f"library's layout no longer matches what this stride was "
                f"selected for")
        type_name = (_read_handle_string(raw.TypeNameRva, file_handle)
                     if raw.TypeNameRva else None)
        object_name = (_read_handle_string(raw.ObjectNameRva, file_handle)
                       if raw.ObjectNameRva else None)
        handles.append(ParsedHandleDescriptor(
            handle=raw.Handle, type_name=type_name, object_name=object_name,
            attributes=raw.Attributes, granted_access=raw.GrantedAccess,
            handle_count=raw.HandleCount, pointer_count=raw.PointerCount,
            type_name_rva=raw.TypeNameRva, object_name_rva=raw.ObjectNameRva,
        ))

    return ParsedHandleDataStream(header=header, handles=handles)
