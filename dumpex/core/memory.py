"""Core memory helpers: address translation, region lookup, module lookup."""
import bisect
import io
import os
import ntpath
import sys
import re
from pathlib import Path
from typing import NamedTuple

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    print("[!] minidump not installed. Run: pip install minidump")
    sys.exit(1)

from minidump.header import MinidumpHeader
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR
from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
from minidump.streams import (
    MinidumpThreadList, MinidumpModuleList, MinidumpMemoryList,
    MinidumpSystemInfo, MinidumpThreadExList, MinidumpMemory64List,
    CommentStreamA, CommentStreamW, ExceptionList,
    MinidumpUnloadedModuleList, MinidumpMiscInfo,
    MinidumpMemoryInfoList, MinidumpThreadInfoList,
)
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from minidump.streams.ContextStream import CONTEXT, WOW64_CONTEXT
from minidump.streams.HandleDataStream import (
    MINIDUMP_HANDLE_DATA_STREAM, MINIDUMP_HANDLE_DESCRIPTOR, MINIDUMP_HANDLE_DESCRIPTOR_2,
)
from minidump.structures.peb import PEB

from dumpex.ui.colors import RED, DIM, YELLOW, GREEN
from dumpex.output.coverage import SourceObservation, SourceState

SYSTEM_RANGE = 0x7FF000000000

def parse_hex_or_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def prot_str(protect) -> str:
    try:    return protect.name
    except: return str(protect)


# ── Handle stream: a dumpex-owned bounded parse (issue #37 §5.1) ───────────
# Registered in _STREAM_DISPATCH below IN PLACE OF the library's own
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


_HANDLE_DESCRIPTOR_LAYOUT_CACHE = None


def _handle_descriptor_layout() -> "tuple[int, int]":
    """Returns (v1_size, v2_size) -- the MS-defined on-disk sizes this
    file's SizeOfDescriptor branch (below) relies on to pick a parser
    class -- deriving and validating them the first time this is called
    (from inside parse_handle_stream(), never at import), then caching
    the result for the life of the process.

    Raises HandleDescriptorLayoutError -- explicitly, not via `assert`,
    so the check survives `python -O` -- if either derived size disagrees
    with the MS-defined 32/40, if the two derived sizes are equal (which
    would make the MINIDUMP_HANDLE_DESCRIPTOR_2 branch below permanently
    unreachable, silently parsing every v2 stream as v1), or if
    _descriptor_class_size() itself fails."""
    global _HANDLE_DESCRIPTOR_LAYOUT_CACHE
    if _HANDLE_DESCRIPTOR_LAYOUT_CACHE is not None:
        return _HANDLE_DESCRIPTOR_LAYOUT_CACHE

    try:
        v1_size = _descriptor_class_size(MINIDUMP_HANDLE_DESCRIPTOR)
        v2_size = _descriptor_class_size(MINIDUMP_HANDLE_DESCRIPTOR_2)
    except HandleDescriptorLayoutError:
        raise
    except Exception as e:
        raise HandleDescriptorLayoutError(
            f"could not determine HandleDataStream descriptor sizes from the "
            f"installed minidump library: {type(e).__name__}: {e}") from e

    # Checked ahead of the exact 32/40 values below: this is the invariant
    # the SizeOfDescriptor branch in parse_handle_stream() actually needs
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

    _HANDLE_DESCRIPTOR_LAYOUT_CACHE = (v1_size, v2_size)
    return _HANDLE_DESCRIPTOR_LAYOUT_CACHE


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
    in the stream's own DataSize) long -- the caller can always recover
    how many were truncated as header.NumberOfDescriptors -
    len(handles))."""
    __slots__ = ("header", "handles")

    def __init__(self, header, handles):
        self.header  = header
        self.handles = handles


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


def parse_handle_stream(directory, file_handle) -> ParsedHandleDataStream:
    """dumpex's own bounded, validated HandleDataStream parser -- see the
    module-level comment above for why the library's own
    MinidumpHandleDataStream.parse is not used. `directory` is the
    stream's own MINIDUMP_DIRECTORY entry (its `.Location` gives the
    stream's Rva/DataSize within the file); `file_handle` is the dump's
    raw file object (HandleDataStream Rva values are FILE offsets, not
    virtual addresses -- there is no process-memory reader involved).

    Raises HandleStreamFramingError when the stream's own framing cannot
    be trusted (header short-read, an out-of-bounds SizeOfHeader, or an
    unrecognized SizeOfDescriptor) -- nothing in the stream can be
    located reliably in that case. A NumberOfDescriptors beyond what
    MAX_HANDLE_DESCRIPTORS/the stream's own DataSize can support is NOT
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

    v1_size, v2_size = _handle_descriptor_layout()
    if header.SizeOfDescriptor == v1_size:
        descriptor_cls = MINIDUMP_HANDLE_DESCRIPTOR
    elif header.SizeOfDescriptor == v2_size:
        descriptor_cls = MINIDUMP_HANDLE_DESCRIPTOR_2
    else:
        raise HandleStreamFramingError(
            f"HandleDataStream SizeOfDescriptor {header.SizeOfDescriptor} is neither "
            f"{v1_size} (MINIDUMP_HANDLE_DESCRIPTOR) nor "
            f"{v2_size} (MINIDUMP_HANDLE_DESCRIPTOR_2)")

    available_bytes = location.DataSize - header.SizeOfHeader
    fits = available_bytes // header.SizeOfDescriptor   # a trailing partial
                                                          # descriptor is not parsed
    declared = header.NumberOfDescriptors if header.NumberOfDescriptors is not None else 0
    usable = max(0, min(declared, MAX_HANDLE_DESCRIPTORS, fits))

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
    # MAX_HANDLE_DESCRIPTORS/fits.
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
            # class of error _handle_descriptor_layout() raises.
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


# ── Loader: open_dump() with per-stream isolation (issue #37 §2) ──────────
# Mirrors MinidumpFile._parse()'s three phases (.venv/Lib/site-packages/
# minidump/minidumpfile.py) using the library's own PUBLIC parser classes,
# with each stream individually guarded -- not a fork of the installed
# package. Before this, a parse exception in ANY single stream propagated
# out of the whole dump-open call: one malformed stream cost the analyst
# every command, exit 1, no structured output. Per-stream isolation
# changes observable behavior for commands that already ship -- see the
# contract's §2.4 for the full, frozen per-command consequence matrix.

_STREAM_DISPATCH = {
    MINIDUMP_STREAM_TYPE.ThreadListStream:         ("threads", MinidumpThreadList.parse),
    MINIDUMP_STREAM_TYPE.ModuleListStream:         ("modules", MinidumpModuleList.parse),
    MINIDUMP_STREAM_TYPE.MemoryListStream:         ("memory_segments", MinidumpMemoryList.parse),
    MINIDUMP_STREAM_TYPE.SystemInfoStream:         ("sysinfo", MinidumpSystemInfo.parse),
    MINIDUMP_STREAM_TYPE.ThreadExListStream:       ("threads_ex", MinidumpThreadExList.parse),
    MINIDUMP_STREAM_TYPE.Memory64ListStream:       ("memory_segments_64", MinidumpMemory64List.parse),
    MINIDUMP_STREAM_TYPE.CommentStreamA:           ("comment_a", CommentStreamA.parse),
    MINIDUMP_STREAM_TYPE.CommentStreamW:           ("comment_w", CommentStreamW.parse),
    MINIDUMP_STREAM_TYPE.ExceptionStream:          ("exception", ExceptionList.parse),
    MINIDUMP_STREAM_TYPE.HandleDataStream:         ("handles", parse_handle_stream),
    MINIDUMP_STREAM_TYPE.UnloadedModuleListStream: ("unloaded_modules", MinidumpUnloadedModuleList.parse),
    MINIDUMP_STREAM_TYPE.MiscInfoStream:           ("misc_info", MinidumpMiscInfo.parse),
    MINIDUMP_STREAM_TYPE.MemoryInfoListStream:     ("memory_info", MinidumpMemoryInfoList.parse),
    MINIDUMP_STREAM_TYPE.ThreadInfoListStream:     ("thread_info", MinidumpThreadInfoList.parse),
}

# Public view of _STREAM_DISPATCH's own keys/attr-name mapping, for a
# caller outside this module that needs to know "does dumpex parse this
# stream type at all, and if so onto which mf.<attr>?" (dumpex.commands.
# profile's stream inventory) without importing the private dict itself
# (whose values also carry each parse function -- not this module's to
# hand out) or hand-maintaining a second copy of the same association
# that could drift from it.
DISPATCHED_STREAM_TYPES = frozenset(_STREAM_DISPATCH.keys())
STREAM_ATTR_NAMES = {stream_type: attr_name for stream_type, (attr_name, _) in _STREAM_DISPATCH.items()}


# ── MINIDUMP_HEADER's union: an installed-library layout misread ──────────
# The real MINIDUMP_HEADER (dbghelp.h) is 32 bytes and declares
# Reserved/TimeDateStamp as a UNION -- the SAME four bytes at offset 0x14 --
# followed by a ULONG64 Flags:
#
#   0x00 Signature            0x04 Version + ImplementationVersion
#   0x08 NumberOfStreams      0x0C StreamDirectoryRva      0x10 CheckSum
#   0x14 union { ULONG32 Reserved; ULONG32 TimeDateStamp; }
#   0x18 ULONG64 Flags
#
# The installed library (.venv/Lib/site-packages/minidump/header.py,
# MinidumpHeader.parse) reads the union as two CONSECUTIVE UINT32s and
# Flags as a UINT32, so its fields still total exactly 32 bytes -- the
# parse succeeds, the signature check passes, nothing raises -- but every
# field from 0x14 on lands one slot too late:
#   header.Reserved      <- 0x14: the REAL TimeDateStamp
#   header.TimeDateStamp <- 0x18: Flags's low 32 bits
#   header.Flags         <- 0x1C: Flags's high 32 bits (0 for every
#                                 currently-defined MINIDUMP_TYPE bit)
# Left uncorrected, --sysinfo's `dump_time_utc` (§4.2.2) renders a dump's
# TYPE FLAGS as epoch seconds: a small, constant, producer-dependent 1970
# date (0x00021826 -> 1970-01-02) that reads as real evidence and is wrong
# for every dump ever written. The fix-up below re-reads those trailing 12
# bytes at their true offsets, so `header.TimeDateStamp` means what its
# name says for every `mf` that came from open_dump().

_HEADER_UNION_OFFSET = 0x14    # union { Reserved, TimeDateStamp }
_HEADER_UNION_SIZE   = 4       # ULONG32 Reserved / TimeDateStamp
_HEADER_FLAGS_SIZE   = 8       # ULONG64 Flags
_HEADER_TAIL_SIZE    = _HEADER_UNION_SIZE + _HEADER_FLAGS_SIZE


def _correct_header_union(header, file_handle) -> None:
    """Re-read MINIDUMP_HEADER's trailing 12 bytes at their REAL offsets
    and write them back onto an already-parsed `header`, in place (see the
    block comment above for the upstream misread this compensates for).
    TimeDateStamp and Reserved are set to the same value BECAUSE they are
    one union -- not a copy of one field into another.

    A field whose bytes are not ALL present is set to the value
    MinidumpHeader.__init__ gives it before any parse (0 for the union,
    None for Flags), never left holding what the upstream parse put there:
    a file truncated inside the header still parses successfully upstream
    (int.from_bytes(b'') is 0, and MINIDUMP_TYPE(0) is a valid
    MiniDumpNormal), so "the header parsed" is no proof that 32 bytes were
    there to read -- and the shifted value sitting in TimeDateStamp is
    precisely the flags-as-a-1970-date artifact this whole fix-up exists
    to stop publishing. The two fields are decided independently: bytes
    0x14-0x17 being present is the only thing the timestamp depends on, so
    a header truncated inside Flags still yields a real dump time.

    Flags is corrected too, not just the field --sysinfo reads: half-fixing
    a shifted layout leaves the other half as a landmine for the next
    caller, who would have no reason to suspect the field is a high dword.
    A mask the enum cannot decode is kept as the plain int rather than
    dropped -- the raw value is still the most faithful thing available,
    and this fix-up exists to make header fields MORE accurate, never to
    turn an odd one into a parse failure."""
    file_handle.seek(_HEADER_UNION_OFFSET, 0)
    tail = file_handle.read(_HEADER_TAIL_SIZE)

    if len(tail) >= _HEADER_UNION_SIZE:
        time_date_stamp = int.from_bytes(
            tail[:_HEADER_UNION_SIZE], byteorder="little", signed=False)
    else:
        time_date_stamp = 0
    header.TimeDateStamp = time_date_stamp
    header.Reserved = time_date_stamp

    if len(tail) != _HEADER_TAIL_SIZE:
        header.Flags = None
        return
    flags = int.from_bytes(tail[_HEADER_UNION_SIZE:], byteorder="little", signed=False)
    try:
        header.Flags = MINIDUMP_TYPE(flags)
    except Exception:
        header.Flags = flags


def _parse_directory_entry(file_handle):
    """Parse one directory entry while preserving unknown stream ids.

    Recognized stream ids remain enum members. Unrecognized and user-stream ids
    remain raw integers, and their Location descriptor is still parsed, so
    inventory commands retain RVA and DataSize instead of dropping the entry.
    Unknown ids therefore bypass stream dispatch without aborting an otherwise
    readable dump. This function never returns None.
    """
    raw_value = MINIDUMP_DIRECTORY.get_stream_type_value(file_handle)
    is_recognized = raw_value in MINIDUMP_STREAM_TYPE._value2member_map_
    d = MINIDUMP_DIRECTORY()
    d.StreamType = MINIDUMP_STREAM_TYPE(raw_value) if is_recognized else raw_value
    d.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(file_handle)
    return d


def open_dump(path: str) -> MinidumpFile:
    # Phase 0 -- unchanged, existing behavior, still exit 1.
    if not os.path.exists(path):
        print(RED(f"[!] File not found: {path}"))
        sys.exit(1)

    mf = MinidumpFile()
    mf.filename = path

    # Phase 1 -- header + directory table. Identical to
    # MinidumpFile.__parse_header(): reads only each directory entry's
    # StreamType/Rva/DataSize, so no per-stream parser runs here. A
    # failure in this phase means the file is not a usable minidump AT
    # ALL -- there is no per-stream evidence to salvage -- so it keeps
    # today's exact message and exit code (tests/unit/test_open_dump.py
    # asserts this unmodified).
    try:
        mf.file_handle = open(path, "rb")
        mf.header = MinidumpHeader.parse(mf.file_handle)
        # Before anything reads a header field: the parse above lands
        # TimeDateStamp/Reserved/Flags on the wrong bytes (see
        # _correct_header_union). The directory walk below seeks
        # absolutely, so the file position this leaves behind is
        # irrelevant to it.
        _correct_header_union(mf.header, mf.file_handle)
        # header.NumberOfStreams is an attacker-controlled uint32 with no
        # relationship enforced to the file's real size -- a directory
        # entry is a fixed 12 bytes (StreamType(4) + Location(8)), so a
        # file of size S can back at most (S - StreamDirectoryRva) // 12
        # of them, however large NumberOfStreams claims to be. Walking
        # past that bound reads past EOF, where file.read(n) silently
        # returns FEWER than n bytes (b'' at the very end) rather than
        # raising -- and int.from_bytes(b'', ...) is 0, a real,
        # recognized MINIDUMP_STREAM_TYPE.UnusedStream value. Unbounded,
        # this fabricates one plausible-looking directory entry per
        # missing byte range out of a file that may be only tens of
        # bytes long: a trivially small, easily crafted input claiming a
        # near-uint32-max stream count turns into minutes of CPU time and
        # a directories list sized to match, none of which the file
        # actually contains. Bounding the walk here -- BEFORE any entry
        # is read, not by catching a short read afterwards -- is what
        # keeps a corrupted/truncated/adversarial directory table a
        # cheap, bounded fact instead of a DoS.
        file_size = os.fstat(mf.file_handle.fileno()).st_size
        max_readable_entries = max(0, (file_size - mf.header.StreamDirectoryRva) // 12)
        walkable_streams = min(mf.header.NumberOfStreams, max_readable_entries)
        # The declared count itself is not separately cached -- it is
        # already directly readable as mf.header.NumberOfStreams, so a
        # second copy here would be redundant state with nothing to keep
        # it in sync. Only the DERIVED shortfall (declared - readable) is
        # worth caching, since directory_truncated_count() is the one
        # fact callers actually need and recomputing it inline at every
        # call site would risk two different subtractions drifting apart.
        mf._dumpex_directory_truncated_count = mf.header.NumberOfStreams - walkable_streams
        for i in range(walkable_streams):
            mf.file_handle.seek(mf.header.StreamDirectoryRva + i * 12, 0)
            d = _parse_directory_entry(mf.file_handle)
            if d:   # never actually falsy any more (see that function's own
                     # docstring) -- kept as a defensive guard, not a live branch
                mf.directories.append(d)
    except Exception as e:
        print(RED(f"[!] Could not parse {path} as a minidump file: "
                   f"{type(e).__name__}: {e}"))
        print(DIM(f"    The file may be corrupted, truncated, or not a Windows "
                   f"minidump (.dmp) at all."))
        sys.exit(1)

    # Phase 2 -- the actual fix: each stream's own parse is individually
    # guarded, so one stream raising no longer aborts every other
    # stream's parse or the dump-open call as a whole.
    stream_failures = {}   # {MINIDUMP_STREAM_TYPE: "ExcType: message"}
    for d in mf.directories:
        entry = _STREAM_DISPATCH.get(d.StreamType)
        if entry is None:
            continue   # unrecognized / not-yet-implemented stream type -- the
                       # same silent skip __parse_directories()'s own unhandled
                       # branches take, not a failure.
        attr_name, parse = entry
        try:
            setattr(mf, attr_name, parse(d, mf.file_handle))
        except Exception as e:
            stream_failures[d.StreamType] = f"{type(e).__name__}: {e}"
            # mf.<attr_name> stays at its MinidumpFile.__init__ default
            # (None) -- isolated; every OTHER branch still runs.

    # Phase 3a -- thread contexts. Reproduces
    # MinidumpFile.__parse_thread_context() exactly, including its guard,
    # so thread.ContextObject consumers (get_thread_contexts(), and
    # through it the stomping/pipe/cs-beacon hunters) do not regress.
    try:
        if mf.sysinfo and mf.threads:
            for thread in mf.threads.threads:
                mf.file_handle.seek(thread.ThreadContext.Rva)
                if mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
                    thread.ContextObject = CONTEXT.parse(mf.file_handle)
                elif mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
                    thread.ContextObject = WOW64_CONTEXT.parse(mf.file_handle)
    except Exception:
        pass   # same swallow-and-continue as the library's own guard

    # Phase 3b -- PEB. Same precondition and same swallow as
    # __parse_peb()/_parse().
    try:
        if mf.sysinfo and mf.threads:
            mf.peb = PEB.from_minidump(mf)
    except Exception:
        pass

    mf._dumpex_stream_failures = stream_failures
    return mf


def stream_failure(mf: MinidumpFile, stream_type) -> "str | None":
    """The failure detail for `stream_type` (an entry in
    mf._dumpex_stream_failures), or None when that stream parsed (or was
    never present). The single place any command asks "did this stream
    fail to parse?" -- an `mf` built by a test/fixture that never went
    through open_dump() has no `_dumpex_stream_failures` attribute at
    all, so a missing attribute is treated as "no failures" rather than
    raising."""
    failures = getattr(mf, "_dumpex_stream_failures", None) or {}
    return failures.get(stream_type)


def has_stream_directory(mf: MinidumpFile, stream_type) -> bool:
    """True when the dump's own directory table carries an entry for
    `stream_type` -- i.e. the stream WAS captured, whatever later became
    of parsing it. The complement of stream_failure() for a command that
    must tell "this dump was never captured with that stream" apart from
    "it was captured and something went wrong with it": mf.<attr> is None
    in BOTH cases, so absence of the parsed object alone cannot decide it.

    Reads mf.directories (populated by open_dump()'s phase 1, before any
    per-stream parser runs, so it is unaffected by phase 2's isolation).
    An `mf` assembled by a test/fixture without a directories list at all
    is treated as declaring no streams rather than raising -- the same
    missing-attribute tolerance stream_failure() applies."""
    directories = getattr(mf, "directories", None) or ()
    return any(getattr(d, "StreamType", None) == stream_type for d in directories)


def directory_truncated_count(mf: MinidumpFile) -> int:
    """How many directory entries `mf.header.NumberOfStreams` declared
    that open_dump()'s Phase 1 walk could not actually read from the
    file (see open_dump()'s own file-size bound, next to where this
    attribute is set) -- 0 for a dump whose declared count and real size
    agree, or whenever `mf` was never built by open_dump() at all (a
    test/fixture `mf` is treated as declaring no shortfall, the same
    missing-attribute tolerance stream_failure()/has_stream_directory()
    apply)."""
    return getattr(mf, "_dumpex_directory_truncated_count", 0) or 0


def observe_stream(mf: MinidumpFile, name: str, stream_type, obj, items: list) -> SourceObservation:
    """The observe_source() every command currently hand-rolls via
    `bool(mf.X)` plus `len(items)`, extended with SourceState.FAILED for
    a stream-backed source: FAILED (with the parser's own detail) when
    `stream_type` is in mf._dumpex_stream_failures, otherwise exactly
    observe_source()'s existing absent/present_empty/present inference
    over `obj`/`items`."""
    detail = stream_failure(mf, stream_type)
    if detail is not None:
        return SourceObservation(name=name, state=SourceState.FAILED, record_count=None,
                                  detail=detail)
    if not obj:
        return SourceObservation(name=name, state=SourceState.ABSENT, record_count=None)
    items = items or []
    if not items:
        return SourceObservation(name=name, state=SourceState.PRESENT_EMPTY, record_count=0)
    return SourceObservation(name=name, state=SourceState.PRESENT, record_count=len(items))


class RegionReadError(RuntimeError):
    """Raised by a caller wrapping read_region() (see
    dumpex.commands.extract.collect_extract/collect_strings) to narrow
    what "the read itself failed" means -- read_region() here never
    raises this itself (report.py/hunt's own call sites are unaffected
    and keep seeing whatever exception the reader naturally raises), it
    exists so a command's own try/except around a wrapped read_region()
    call can distinguish an actual read failure from an unrelated
    exception (a write failure, a bad --grep regex, a record/schema
    construction bug) that happens to occur later in the same try block --
    see cmd_extract/cmd_strings for why that distinction matters."""


def read_region(mf: MinidumpFile, addr: int, size: int) -> bytes:
    reader = mf.get_reader().get_buffered_reader()
    reader.move(addr)
    return reader.read(size)


def clamped_reader(mf: MinidumpFile):
    """Returns a `read(addr, size) -> bytes` callable, bound to ONE
    MinidumpBufferedReader instance reused across every call -- for a
    caller (dumpex.core.pe_utils.parse_iat, via dumpex.commands.process)
    that issues many bounded reads in a single walk and would otherwise
    reconstruct a fresh reader (re-triggering its underlying chunked file
    read) on every single one, the same way read_region() does for a
    one-shot caller.

    The returned callable never asks for more than the CURRENT memory
    segment (the same segment `reader.read()` itself reads through and
    raises past the end of) actually has left, via the identical
    `reader.current_segment.remaining_len(reader.current_position)`
    pattern dumpex.core.process_info._env_read_capture() already uses for
    the same reason. It returns whatever the segment has, up to `size`
    (possibly fewer bytes, possibly `b""` if nothing is captured at
    `addr` at all); it never raises. Neither does clamped_reader() itself:
    if `mf.get_reader()`/`get_buffered_reader()` raises while BUILDING
    the bound reader, that is caught here too, and the callable returned
    in that case simply answers every read with `b""` -- the whole point
    of this primitive is "hand back bytes, never an exception", and that
    guarantee has to cover construction as well as every individual read,
    or a caller trusting the docstring alone would still see an
    unexpected exception propagate out of the one call site (this
    function itself) it never occurred to it to guard.

    Every read after the first that lands in a NEW segment grows this one
    MinidumpBufferedReader's own internal chunk cache for the lifetime of
    the returned callable (the underlying library reads a whole segment
    at once for a segment <= 20 KiB, or >= 10 KiB chunks otherwise, and
    never evicts what it has already read) -- reusing one reader across a
    whole walk trades the per-call reader-reconstruction cost a naive
    version of this primitive would otherwise pay for a bounded but
    NOT-byte-budgeted memory footprint of its own, on top of whatever the
    caller's own read-count/byte budgets already track. Bounded by
    however many distinct segments the caller's own walk can touch (for
    dumpex.core.pe_utils.parse_iat, MAX_IAT_READ_OPERATIONS caps that),
    but not by MAX_IAT_BYTES_READ, which only counts bytes actually
    returned to the caller, not this reader's own chunk cache -- a
    caller with an unusually large per-call read-count budget should
    weigh this before reusing one bound reader across an equally large
    number of distinct segments.

    Deliberately NOT built on va_range_captured_bytes(): that function
    accumulates bytes across CONTIGUOUS segments (its own docstring:
    "accumulates a CONTIGUOUS run"), while read_region()'s underlying
    MinidumpBufferedReader.read() only ever reads through the CURRENT
    segment's own buffered reader and raises the moment a request runs
    past ITS extent -- regardless of whether a later, adjacent segment
    would have covered the rest. Clamping to va_range_captured_bytes()
    alone would still raise (and still have to be treated as a hard
    failure by a caller expecting bytes, not an exception) for a read
    sitting near the end of one segment with another captured segment
    immediately following it -- exactly the layout a real full-memory
    dump's own VirtualQuery-derived region table produces at every
    protection-attribute boundary inside one mapped image (.text RX |
    .rdata R | .data RW are adjacent descriptors). A caller that treats a
    short-but-successful result as partial evidence (rather than a
    fixed-size read that must fully succeed or fail outright) gets a
    real, fully-present value read out of a small captured segment
    instead of losing it purely because the REQUEST size exceeded what
    that one segment holds."""
    try:
        reader = mf.get_reader().get_buffered_reader()
    except Exception:
        return lambda addr, size: b""

    def read(addr: int, size: int) -> bytes:
        try:
            reader.move(addr)
            remaining = reader.current_segment.remaining_len(reader.current_position)
        except Exception:
            return b""
        if not remaining:
            return b""
        want = min(size, remaining)
        try:
            return reader.read(want)
        except Exception:
            return b""
    return read


def read_region_clamped(mf: MinidumpFile, addr: int, size: int) -> bytes:
    """One-shot form of clamped_reader() -- matches read_region()'s own
    per-call convention for a caller that only needs a single clamped
    read, not a reusable bound reader."""
    return clamped_reader(mf)(addr, size)


def read_region_spanning(mf: MinidumpFile, addr: int, size: int) -> bytes:
    """Like read_region(), but walks across every CONTIGUOUS segment
    covering `[addr, addr + size)` -- the same contiguous-run boundary
    va_range_captured_bytes() computes -- instead of one reader.read()
    call that only ever reads through the CURRENT segment and raises the
    moment a request runs past its own extent.

    This exists because read_region(mf, addr, va_range_captured_bytes(mf,
    addr, size)) is NOT a safe combination whenever the captured range
    spans more than one segment: va_range_captured_bytes() reports the
    FULL contiguous length across all of them, but a single
    reader.read() called with that length only ever succeeds if the
    WHOLE thing fits inside whichever ONE segment reader.move(addr)
    landed on -- exactly the layout a real full-memory dump's own
    VirtualQuery-derived region/segment table produces whenever a
    structure (e.g. one main image's PE header) happens to straddle a
    protection-attribute boundary. Without this, a caller combining
    those two functions the obvious way silently gets `checked=False`/
    "nothing could be read" for evidence that is, in full, genuinely
    present in the dump.

    Re-`move()`s before every chunk (unlike clamped_reader(), which
    deliberately stays within whatever ONE segment the caller's own
    `addr` landed on) so each chunk picks up whichever segment actually
    covers the current read position, including a DIFFERENT segment than
    the one the read started in. Returns however many bytes were
    actually read -- up to `size`, fewer if the contiguous run genuinely
    ends before `size` is reached; never raises."""
    if size <= 0:
        return b""
    try:
        reader = mf.get_reader().get_buffered_reader()
    except Exception:
        return b""
    data = bytearray()
    remaining = size
    position = addr
    while remaining > 0:
        try:
            reader.move(position)
            segment_left = reader.current_segment.remaining_len(reader.current_position)
        except Exception:
            break
        if not segment_left:
            break
        want = min(remaining, segment_left)
        try:
            chunk = reader.read(want)
        except Exception:
            break
        if not chunk:
            break
        data.extend(chunk)
        remaining -= len(chunk)
        position += len(chunk)
    return bytes(data)


def get_modules(mf: MinidumpFile) -> list:
    if mf.modules and mf.modules.modules:
        return mf.modules.modules
    return []


def get_thread_infos(mf: MinidumpFile) -> list:
    if mf.thread_info and mf.thread_info.infos:
        return mf.thread_info.infos
    return []


def get_memory_regions(mf: MinidumpFile) -> list:
    if mf.memory_info and mf.memory_info.infos:
        return mf.memory_info.infos
    return []


def get_thread_contexts(mf: MinidumpFile) -> list:
    """
    Return the CURRENT instruction pointer per thread, as recorded in
    ThreadListStream's per-thread CONTEXT/WOW64_CONTEXT at the moment the
    dump was taken — this is the register state actually in flight, unlike
    ThreadInfoListStream.StartAddress (where the thread BEGAN, which tells
    you nothing about where it is executing right now).

    minidump.MinidumpFile.parse() already parses each thread's context
    into thread.ContextObject during open_dump() (__parse_thread_context);
    this just extracts the one field hunt modules need in a uniform shape,
    handling both native x64 (CONTEXT.Rip) and WOW64 32-bit-on-64-bit
    (WOW64_CONTEXT.Eip) — distinguished via hasattr, NOT via "is the value
    zero", since a genuinely-zero RIP/EIP is indistinguishable from
    "attribute absent" once read through getattr(..., default=0).

    Returns list of {"ThreadId": int, "ip": int, "ip_reg": "RIP"|"EIP",
    "is_wow64": bool} — one entry per thread whose context was actually
    parsed. A thread with no ContextObject (context stream missing/
    unparseable for that thread) is silently omitted, not defaulted to 0 —
    callers must treat "not in this list" as "no live IP available", not
    "IP is 0".
    """
    out = []
    if not (mf.threads and mf.threads.threads):
        return out
    for th in mf.threads.threads:
        ctx = getattr(th, 'ContextObject', None)
        if ctx is None:
            continue
        if hasattr(ctx, 'Rip'):
            out.append({"ThreadId": th.ThreadId, "ip": ctx.Rip, "ip_reg": "RIP", "is_wow64": False})
        elif hasattr(ctx, 'Eip'):
            out.append({"ThreadId": th.ThreadId, "ip": ctx.Eip, "ip_reg": "EIP", "is_wow64": True})
    return out


def group_regions_by_allocation(regions: list, key=lambda r: r.AllocationBase) -> dict:
    """
    Group MemoryInfo regions (or any region-like object `key` can read an
    allocation base from) by AllocationBase — the address a single
    VirtualAlloc/VirtualAllocEx call originally reserved. A single
    allocation is routinely split into multiple MemoryInfo entries with
    different BaseAddress/Protect/State (e.g. a header page, a RW-then-
    reprotected-to-RX code page, a guard page) after VirtualProtect calls;
    correlating suspicious signals by AllocationBase catches this — two
    regions that are RWX and "hidden PE" respectively but sit at DIFFERENT
    BaseAddress within the SAME allocation are still one suspicious
    allocation, not two unrelated ones.

    `key` defaults to raw minidump Region objects' own `.AllocationBase`
    attribute; pass e.g. `key=lambda ref: ref.allocation_base` to group an
    already-converted immutable region-ref/Evidence type instead (see
    dumpex.hunt.injection.correlation's own callers) without needing a
    second, hand-rolled grouping loop.

    Returns {AllocationBase: [region, ...]}, insertion order preserved
    within each group.
    """
    groups: dict = {}
    for r in regions:
        groups.setdefault(key(r), []).append(r)
    return groups


def get_handles(mf: MinidumpFile) -> list:
    """
    Return HandleDataStream descriptors, or [] if the dump doesn't carry
    one (MiniDumpWithHandleData wasn't set when the dump was captured —
    common for a plain MiniDumpWithFullMemory dump). Each descriptor has
    .Handle, .TypeName (e.g. "File", "Event", "Mutant"), .ObjectName (the
    kernel object name, e.g. "\\Device\\NamedPipe\\mypipe" for a pipe
    handle), .GrantedAccess, .HandleCount, .PointerCount.

    This is the actual OS-level record of "this process holds an open
    handle to this named kernel object" — independent of and much
    stronger than finding the bytes "\\pipe\\something" sitting in memory,
    which proves only that the bytes exist somewhere, not that anything
    ever opened a pipe by that name.
    """
    if mf.handles and mf.handles.handles:
        return mf.handles.handles
    return []


def module_name_only(full_path: str) -> str:
    """Extract just the filename from a full module path. Module paths
    recorded in a minidump are always Windows paths (e.g.
    "C:\\Windows\\System32\\foo.dll") regardless of the host OS this tool
    runs on -- os.path.basename only splits on "/" on a POSIX analysis
    host, silently returning the whole backslash-separated string
    unchanged there and breaking cross-dump module matching (the same
    module at two different directories would compare unequal). Uses
    ntpath.basename, not os.path.basename, for the same reason
    dumpex.commands.modules/threads and dumpex.hunt.stomping.memory_scan's
    own _module_basename already do."""
    return ntpath.basename(full_path).lower() if full_path else ""


def addr_to_module(addr: int, modules: list):
    """Return module if address falls within it, else None."""
    for m in modules:
        if m.baseaddress <= addr < m.endaddress:
            return m
    return None


def _memory_segments(mf: MinidumpFile) -> list:
    """The dump's own memory segment table (Memory64List preferred, falling
    back to the older MemoryList) -- the ONE place that preference order is
    decided, shared by va_to_file_offset() and va_range_captured_bytes()
    below so the two can never resolve a VA against two different segment
    lists."""
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        return mf.memory_segments_64.memory_segments
    if mf.memory_segments and mf.memory_segments.memory_segments:
        return mf.memory_segments.memory_segments
    return []


def get_memory_segments(mf: MinidumpFile) -> list:
    """Public wrapper over _memory_segments() for callers outside this
    module (dumpex.commands.profile's memory-capture facts and
    injection-artifact-analysis capability gating) that need the exact
    same Memory64List-preferred-over-MemoryList segment table
    read_region()/va_to_file_offset() already resolve VAs against --
    without a second, independently-maintained copy of that preference
    order that could drift from this one."""
    return _memory_segments(mf)


def va_to_file_offset(mf: MinidumpFile, va: int):
    """
    Translate a Virtual Address (in the target process) to its byte offset
    inside the .dmp file, using the memory segment table.

    Returns None if the VA is not covered by any segment in the dump.

    Address types in a minidump
    ───────────────────────────
      Virtual Address (VA)
          The address as seen by the target process at the time of the dump.
          Every field named BaseAddress / StartAddress / baseaddress /
          StartOfMemoryRange carries a VA. It is NOT a physical RAM address.

      File offset  (dump-file offset)
          Byte position inside the .dmp file where that memory was written.
          Formula: segment.start_file_address + (va - segment.start_virtual_address)
          This is the closest thing to a "physical" locator that a minidump
          exposes, but it refers to the file, not to RAM.

      Physical address (RAM)
          The real hardware address. Minidumps do NOT record this; it is
          only available in kernel / full memory dumps with PFN tables.
    """
    if not va:
        return None
    for seg in _memory_segments(mf):
        if seg.start_virtual_address <= va < seg.end_virtual_address:
            return seg.start_file_address + (va - seg.start_virtual_address)
    return None


def _segments_by_va(mf: MinidumpFile) -> tuple:
    """`(segments_in_ascending_VA_order, running_max_end_address)`,
    resolved once per dump and memoized on `mf` itself.

    The segment table is fixed once the dump is parsed, so re-sorting it
    per lookup is pure repeated work -- and `va_range_captured_bytes()`
    below runs once per ELIGIBLE region on a hunter's scan path, not just
    on the rare skip/failure path, so that work is the difference between
    an O(regions) and an O(regions x segments log segments) scan.

    The second list is a running maximum of the end addresses seen so far,
    which is non-decreasing and therefore searchable: `max_ends[i] <= va`
    means EVERY segment up to `i` ends at or before `va` and cannot
    contribute to a range starting there. Start addresses alone cannot
    answer that -- a table where a long segment is followed by shorter
    ones nested inside it has entries that end before `va` sitting between
    the entry that covers it and `va`'s own position in start order.

    The cache is keyed on the identity of the underlying segment list, so
    a caller that swaps `mf`'s stream out (tests do) gets a rebuilt index
    rather than a stale one. A reader that refuses attribute assignment
    still works -- it just recomputes."""
    raw = _memory_segments(mf)
    cached = getattr(mf, "_dumpex_segments_by_va", None)
    if cached is not None and cached[0] is raw:
        return cached[1], cached[2]
    ordered = sorted(raw, key=lambda s: s.start_virtual_address)
    max_ends = []
    running = 0
    for seg in ordered:
        running = max(running, seg.end_virtual_address)
        max_ends.append(running)
    try:
        mf._dumpex_segments_by_va = (raw, ordered, max_ends)
    except Exception:
        pass
    return ordered, max_ends


def va_range_captured_bytes(mf: MinidumpFile, va: int, size: int) -> int:
    """How many of the `size` bytes starting at `va` are actually present
    in the .dmp file, per the dump's own segment table -- a STRUCTURAL
    fact about what the dump captured, independent of whether any hunt's
    own live-memory read attempt at that address succeeded or failed.

    Returns a value in `[0, size]`: `0` if `va` itself isn't covered by any
    segment at all, `size` if the whole range is captured by one or more
    CONTIGUOUS segments, and something in between for a range whose
    capture stops partway through (the common case behind a short read --
    the dump's own segment table simply doesn't extend as far as the
    region's declared size claims).

    This exists because `va_to_file_offset()` alone only proves the START
    of a range is captured -- for a short-read target specifically (see
    dumpex.output.coverage.ScanTarget.capture_state), "the start resolves"
    and "the whole requested size is present" are different claims, and an
    investigation-action consumer deciding between "extract what's here"
    and "recollect a fuller dump" needs to know which one is true.

    Walks segments in ascending virtual-address order and accumulates a
    CONTIGUOUS run starting at `va`; a gap (the next segment in address
    order starts past where the run currently ends) stops the walk at
    whatever contiguous prefix was already found -- a segment further
    along in the address space that happens to cover the range's TAIL,
    with a gap in between, does not count as "captured" for this purpose,
    since the missing middle still can't be extracted as one contiguous
    read.
    """
    if size <= 0 or not va:
        return 0
    end = va + size
    cursor = va
    segments, max_ends = _segments_by_va(mf)
    # The first segment whose prefix reaches past `va` -- everything
    # before it ends at or before `va` and would only be skipped. Searched
    # on the running maximum rather than on start addresses, so a segment
    # nested inside an earlier, longer one cannot hide that longer one
    # (see _segments_by_va).
    index = bisect.bisect_right(max_ends, va)
    for seg in segments[index:]:
        if seg.end_virtual_address <= cursor:
            continue   # entirely before the still-uncovered start of the run
        if seg.start_virtual_address > cursor:
            break      # gap right where the contiguous run needs to continue
        cursor = min(seg.end_virtual_address, end)
        if cursor >= end:
            break
    return cursor - va


def addr_label(mf: MinidumpFile, va: int, region_base=None, indent: int = 2) -> str:
    """
    Return a consistent multi-line annotation for any VA returned by hunt/report.

      VA (process)   0x<va>          — address in the target process
      File offset    0x<offset>      — byte position inside the .dmp file
      Region base    0x<base>        — start of the enclosing memory region
                                       (omitted when same as va or not given)

    Physical Address (RAM) is not available in minidumps.
    """
    pad = " " * indent
    lines = [f"{pad}{'VA (process)':<16} 0x{va:016x}"]

    fo = va_to_file_offset(mf, va)
    if fo is not None:
        lines.append(f"{pad}{'File offset (.dmp)':<20} 0x{fo:016x}")
    else:
        lines.append(f"{pad}{'File offset (.dmp)':<20} {DIM('(VA not captured in dump)')}")

    if region_base is not None and region_base != va:
        lines.append(f"{pad}{'Region base (VA)':<20} 0x{region_base:016x}")

    return "\n".join(lines)


MAX_REGION_READ = 256 * 1024 * 1024   # hard ceiling for an AUTO-sized single read
                                       # (--extract/--strings/--report without an
                                       # explicit --size). A region's declared
                                       # RegionSize comes straight from the dump file
                                       # and isn't otherwise validated — a corrupted or
                                       # crafted dump could claim a huge size and force
                                       # an equally huge single read/allocation nobody
                                       # asked for. An explicit --size is deliberate
                                       # user intent and is NOT clamped here.


def _resolve_size(mf: MinidumpFile, addr: int, requested_size: int | None) -> int:
    """
    If the user didn't specify --size, look up the memory region that contains
    addr and return its actual size (capped at the region boundary and at
    MAX_REGION_READ). An explicit requested_size is returned as-is — that's
    the user's own choice, not an auto-derived value that needs a safety net.
    Falls back to 0x10000 if the region cannot be found.
    """
    if requested_size is not None:
        return requested_size
    for r in get_memory_regions(mf):
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            actual = r.RegionSize - (addr - r.BaseAddress)
            return min(actual, MAX_REGION_READ)
    return 0x10000  # fallback if region not in memory info



# ── Shared analysis helpers ──────────────────────────────────────────────────
# These helpers are used by hunt modules and report.py.
# They live here so every module can import them from dumpex.core.memory.

def _get_region_at(addr: int, regions: list):
    """Find the memory region containing addr."""
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return r
    return None

def _extract_strings_from_data(data: bytes, min_len: int = 6, encoding: str = "both") -> list:
    """\n    Extract ASCII and/or UTF-16LE strings.\n    Returns list of (offset, enc, string).\n    UTF-16LE covers Windows API names, registry paths, and wide-char C2\n    configs that pure ASCII scans miss entirely.\n\n    `encoding` ("ascii" | "unicode" | "both", default "both") selects
    which pattern(s) run -- report.py's own call site never passes it
    (always wants both), so the default preserves its exact existing
    behavior; --strings' own ASCII/UTF16/both modes are the reason this
    parameter exists at all (extract.py used to duplicate this whole
    function inline just to add the encoding filter -- see extract.py's
    own history)."""
    results = []
    if encoding in ("ascii", "both"):
        pat_ascii = rb'[ -~]{' + str(min_len).encode() + rb',}'
        results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                    for m in re.finditer(pat_ascii, data)]
    if encoding in ("unicode", "both"):
        pat_uni = rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}'
        results += [(m.start(), "UTF16", m.group().decode("utf-16-le", errors="replace"))
                    for m in re.finditer(pat_uni, data)]
    results.sort(key=lambda x: x[0])
    return results

def _hexdump_context(data: bytes, offset: int, region_base: int,
                     before: int = 128, after: int = 128) -> str:
    """\n    Hex+ASCII mixed dump of bytes surrounding offset within data.\n    Used for context-aware IOC display (e.g. UA string near C2 IP/port).\n    """
    start     = max(0, offset - before)
    end       = min(len(data), offset + after)
    chunk     = data[start:end]
    hit_rel   = offset - start

    lines = []
    for i in range(0, len(chunk), 16):
        row     = chunk[i:i+16]
        addr    = region_base + start + i
        hex_col = " ".join(f"{b:02x}" for b in row).ljust(48)
        asc_col = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        if i <= hit_rel < i + 16:
            lines.append(f"    {YELLOW(f'0x{addr:016x}')}  {YELLOW(hex_col)}  {YELLOW(asc_col)}")
        else:
            lines.append(f"    {DIM(f'0x{addr:016x}')}  {hex_col}  {DIM(asc_col)}")
    return "\n".join(lines)

INDICATOR_DIMS = {
    "unbacked_thread": "Unbacked thread execution (start addr outside all known modules)",
    "rwx_private":     "Anomalous memory protection (RWX + MEM_PRIVATE)",
    "injected_pe":     "Injected PE (MZ header in unregistered private memory)",
    "ioc_strings":     "IOC string pattern(s) matched in region",
}

VERDICT_CLEAN                    = "CLEAN"
VERDICT_SUSPICIOUS                = "SUSPICIOUS"
VERDICT_LIKELY_MALICIOUS          = "LIKELY_MALICIOUS"
VERDICT_HIGH_CONFIDENCE_MALICIOUS = "HIGH_CONFIDENCE_MALICIOUS"


def verdict_for(dims: dict) -> str:
    """The machine-readable tier for a MECE dims dict -- `_verdict()`
    below derives its colored console string from this, so the wire
    value (TriageCardRecord.verdict) and the console text are provably
    the same rule, not two hand-maintained copies that could drift."""
    score = len(dims)
    if score == 0:
        return VERDICT_CLEAN
    if score == 1:
        return VERDICT_SUSPICIOUS
    if score == 2:
        return VERDICT_LIKELY_MALICIOUS
    return VERDICT_HIGH_CONFIDENCE_MALICIOUS


def _verdict(dims: dict) -> str:
    tier = verdict_for(dims)
    score = len(dims)
    if tier == VERDICT_CLEAN:
        return GREEN("CLEAN — no suspicious indicators found")
    if tier == VERDICT_SUSPICIOUS:
        return YELLOW("SUSPICIOUS — 1 independent indicator")
    if tier == VERDICT_LIKELY_MALICIOUS:
        return YELLOW("LIKELY MALICIOUS — 2 independent indicators")
    return RED(f"HIGH CONFIDENCE MALICIOUS — {score} independent indicators")

class StringSearchStats(NamedTuple):
    """Whole-scan telemetry _search_string_in_memory() can't express through
    `hits` alone: `skipped` is how many committed regions raised on
    read_region() and were skipped entirely (couldn't read anything at
    all); `clamped` is how many regions were bigger than MAX_REGION_READ,
    so the scan deliberately asked for less than the region's own size --
    a self-imposed policy choice, not evidence going missing (see
    dumpex.commands.report.collect_report's own execution_status
    derivation, which treats this the same as a per-card MAX_REGION_READ
    clamp); `truncated` is how many regions came back SHORTER than
    whatever was actually requested (post-clamp) -- read_region() itself
    couldn't back that much, a genuine evidence-completeness gap
    independent of `clamped`. A single region can be both `clamped` and
    `truncated` at once (asked for less than its own size, then even that
    reduced request came up short); the two counters are orthogonal, not
    mutually exclusive."""
    skipped: int
    clamped: int
    truncated: int


def _search_string_in_memory(mf: MinidumpFile, needle: str) -> tuple:
    """
    Search all committed memory regions for needle (ASCII and UTF-16LE).
    Returns (hits, stats): hits is a list of (region, offset, encoding)
    tuples, one per hit region (deduplicated by region base so we report
    each region once); stats is a StringSearchStats -- see its own
    docstring. A needle that only appears past a `clamped`/`truncated`
    region's own read boundary is a genuine false negative: the caller
    must not report "not found" as if the whole dump were exhaustively
    searched when either counter is nonzero (see collect_report's own
    scoped wording).
    """
    regions   = get_memory_regions(mf)
    hits      = []
    seen      = set()
    skipped   = 0
    clamped   = 0
    truncated = 0
    needle_b  = needle.encode("ascii", errors="replace")
    needle_w  = needle.encode("utf-16-le")

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.BaseAddress in seen:
            continue
        requested = min(r.RegionSize, MAX_REGION_READ)
        if requested < r.RegionSize:
            clamped += 1
        try:
            data = read_region(mf, r.BaseAddress, requested)
        except Exception:
            skipped += 1
            continue
        if len(data) < requested:
            truncated += 1

        off_a = data.find(needle_b)
        if off_a != -1:
            hits.append((r, off_a, "ASCII"))
            seen.add(r.BaseAddress)
            continue

        off_w = data.find(needle_w)
        if off_w != -1:
            hits.append((r, off_w, "UTF16"))
            seen.add(r.BaseAddress)

    return hits, StringSearchStats(skipped=skipped, clamped=clamped, truncated=truncated)

def _extract_ioc_strings(data: bytes, base_addr: int) -> list:
    """
    Extract IOC-relevant strings with full length preservation.
    Uses two strategies:
      1. Standard printable-ASCII regex (catches most strings)
      2. Anchor-and-extend for known prefixes (https://, http://) that may
         be followed by bytes that break the printable-ASCII run — this
         prevents truncation of URLs stored with mixed-case or encoded chars.
    Returns list of (offset, enc, string).
    """
    results = []
    seen_offsets = set()

    # Strategy 1: standard printable ASCII, min 8 chars
    pat = rb'[ -~]{8,}'
    for m in re.finditer(pat, data):
        results.append((m.start(), "ASCII", m.group().decode("ascii", errors="replace")))
        seen_offsets.add(m.start())

    # Strategy 2: anchor-and-extend for URL prefixes
    # Read forward from the prefix until we hit a null or non-printable run > 1
    URL_ANCHORS = [b'https://', b'http://']
    for anchor in URL_ANCHORS:
        pos = 0
        while True:
            idx = data.find(anchor, pos)
            if idx == -1:
                break
            if idx not in seen_offsets:
                # Extend forward: accept printable ASCII + common URL chars
                end = idx
                while end < len(data) and (32 <= data[end] < 127):
                    end += 1
                s = data[idx:end].decode("ascii", errors="replace")
                if len(s) >= 8:
                    results.append((idx, "ASCII-URL", s))
                    seen_offsets.add(idx)
            pos = idx + 1

    # UTF-16LE
    pat_uni = rb'(?:[ -~]\x00){8,}'
    for m in re.finditer(pat_uni, data):
        if m.start() not in seen_offsets:
            results.append((m.start(), "UTF16",
                            m.group().decode("utf-16-le", errors="replace")))

    results.sort(key=lambda x: x[0])
    return results
