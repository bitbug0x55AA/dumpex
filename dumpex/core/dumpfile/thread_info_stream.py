"""ThreadInfoListStream parsing: one validated record layout, bounded
entry reads, and the declared-versus-delivered record counts.

A record field the stream does not cover stays None; nothing here
interprets DumpFlags or start addresses -- `dumpex.core.memory` derives
those from the parsed records. The one bound entry point is
`dumpex.core.memory.parse_thread_info_stream`, which supplies the entry cap
from the legacy module's namespace.
"""
import io

from minidump.streams.ThreadInfoListStream import DumpFlags, MINIDUMP_THREAD_INFO_LIST


# ── ThreadInfoListStream: a dumpex-owned, single-layout parse ─────────────
# Registered in dumpex.core.memory's _STREAM_DISPATCH IN PLACE OF the library's own
# MinidumpThreadInfoList.parse, for two reasons, each grounded in the
# installed library's code (.venv/Lib/site-packages/minidump/streams/
# ThreadInfoListStream.py):
#
#   1. MINIDUMP_THREAD_INFO.parse() reads DumpFlags through a
#      single-member `DumpFlags(value)` Enum lookup inside a bare
#      `except: pass`. Two very different on-disk values both come back
#      as `DumpFlags is None`: 0x00000000 (the producer set no flag at
#      all -- the ordinary case for a healthy thread) and any
#      COMBINATION, e.g. 0x14 == INVALID_CONTEXT | EXITED_THREAD, which
#      MiniDumpWriteDump emits routinely and no single Enum member can
#      represent. Every fact dumpex derives from DumpFlags -- whether a
#      record's own thread information is valid at all, and whether it
#      disputes the base ThreadListStream's captured CONTEXT -- is
#      safety-relevant, so those two cases must not be indistinguishable.
#      The raw UINT32 is kept on every entry as `.RawDumpFlags`.
#
#   2. That parse walks entries at its own hardcoded 64-byte layout and
#      reads each field with `buff.read(n)` -- which returns b"" once the
#      chunk runs out, and `int.from_bytes(b"", ...)` is 0. A record the
#      dump declares SHORTER than 64 bytes, or one the stream's own
#      DataSize cuts off partway, therefore yields StartAddress == 0:
#      indistinguishable from a thread that really started at address 0,
#      and, run through addr_to_module, a CONFIRMED "not in any module"
#      finding manufactured out of bytes that were never on disk. It also
#      ignores the stream's declared SizeOfEntry entirely, so a producer
#      that declares a longer stride has every entry after the first read
#      from the wrong offset.
#
# Every field here comes from ONE layout, validated once: the entry array
# is walked at the stream's OWN declared SizeOfEntry, and within each
# entry a field is read only when the bytes that actually exist for that
# entry cover it -- whether they stop short because the producer
# declared a shorter record, or because the stream or the file cuts the
# last one off. A field that is not covered stays None -- "this record
# did not carry this fact" -- and never becomes a zero. A cut-short
# trailing entry keeps the fields it DID carry rather than being
# dropped; only one with less than ThreadId+DumpFlags left is not
# offered, and that shortfall is reportable as
# truncated_thread_info_count(). The read
# is bounded by the stream's declared extent, by MAX_THREAD_INFO_ENTRIES/
# _THREAD_INFO_MAX_ENTRY_SIZE, and by MAX_THREAD_INFO_RAW_BYTES: every
# term it multiplies is a dump-controlled UINT32, and it must neither
# size an allocation from one nor read a byte from outside the stream it
# describes.

MAX_THREAD_INFO_ENTRIES        = 65536   # entries parsed from ThreadInfoListStream
MAX_THREAD_INFO_RAW_BYTES      = 8 * 1024 * 1024   # ceiling on the one entry-array read
_THREAD_INFO_LIST_HEADER_SIZE  = 12      # MINIDUMP_THREAD_INFO_LIST, on disk
_THREAD_INFO_ENTRY_SIZE        = 64      # MINIDUMP_THREAD_INFO, on disk
_THREAD_INFO_MIN_ENTRY_SIZE    = 4       # ThreadId (UINT32) -- the one field that
                                          # attributes a record to a thread at all, and
                                          # therefore the least a record can carry and
                                          # still be a record
_THREAD_INFO_MAX_ENTRY_SIZE    = 4096    # a producer may declare a longer stride for
                                          # fields dumpex does not read, but a
                                          # dump-controlled UINT32 must never size an
                                          # allocation on its own

# MINIDUMP_THREAD_INFO, as (attribute, byte offset, width). The one
# layout every field on a ParsedThreadInfo comes from, so ThreadId,
# DumpFlags and StartAddress always describe the same record -- a walk
# that reads some fields at one stride and confirms them at another can
# agree on ThreadId while every later field belongs to different bytes.
# https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_thread_info
_THREAD_INFO_LAYOUT = (
    ("ThreadId",     0,  4),
    ("RawDumpFlags", 4,  4),
    ("DumpError",    8,  4),
    ("ExitStatus",  12,  4),
    ("CreateTime",  16,  8),
    ("ExitTime",    24,  8),
    ("KernelTime",  32,  8),
    ("UserTime",    40,  8),
    ("StartAddress", 48, 8),
    ("Affinity",    56,  8),
)


class ThreadInfoStreamFramingError(Exception):
    """Raised by parse_thread_info_stream() when the stream's own framing
    cannot be trusted (header short read, an out-of-bounds SizeOfHeader,
    or a SizeOfEntry too small to hold even a ThreadId or large enough to
    be an allocation request) -- nothing in the stream can be
    located reliably in that case, so no record is offered rather than
    records read at a guessed offset. A NumberOfEntries beyond what
    MAX_THREAD_INFO_ENTRIES/the stream's own DataSize can support is NOT
    an error: it is capped, and the caller can recover the truncated
    count as header.NumberOfEntries - len(result.infos)."""


class ParsedThreadInfo:
    """One MINIDUMP_THREAD_INFO record, every field read from the single
    validated layout in _THREAD_INFO_LAYOUT.

    A field is None when this stream's own declared record size does not
    cover it -- the producer never wrote that fact, which is not the same
    claim as writing a zero. `RawDumpFlags` is the exact on-disk UINT32;
    `DumpFlags` is the library's single-member Enum view of that same
    value, None for 0x0 and for any combination it cannot represent (see
    dumpex.core.memory.dump_flags_value, which every DumpFlags consumer goes through
    instead). Attribute names match the installed library's own
    MinidumpThreadInfo so every existing reader is unaffected."""
    __slots__ = ("ThreadId", "RawDumpFlags", "DumpFlags", "DumpError", "ExitStatus",
                 "CreateTime", "ExitTime", "KernelTime", "UserTime", "StartAddress",
                 "Affinity")

    def __init__(self):
        for name in self.__slots__:
            setattr(self, name, None)


class ParsedThreadInfoList:
    """parse_thread_info_stream()'s return value: `.header` (the raw
    MINIDUMP_THREAD_INFO_LIST, whose NumberOfEntries is the PRODUCER's
    declared count) and `.infos` (the records actually parsed, capped by
    the stream's own extent). Same two attribute names the library's
    MinidumpThreadInfoList exposes, so `mf.thread_info` consumers are
    unaffected."""
    __slots__ = ("header", "infos")

    def __init__(self, header, infos):
        self.header = header
        self.infos = list(infos)


def parse_bounded_thread_info_stream(directory, file_handle, *,
                                     max_entries) -> ParsedThreadInfoList:
    """dumpex's own bounded, single-layout ThreadInfoListStream parser --
    see the module-level comment above for why the library's own
    MINIDUMP_THREAD_INFO.parse is not used. `directory` is the stream's
    own MINIDUMP_DIRECTORY entry (its `.Location` gives the stream's
    Rva/DataSize within the file); `file_handle` is the dump's raw file
    object; `max_entries` caps how many records are parsed
    (dumpex.core.memory.parse_thread_info_stream binds
    MAX_THREAD_INFO_ENTRIES).

    Raises ThreadInfoStreamFramingError when the stream's own framing
    cannot be trusted. A declared entry count or stride that simply
    reaches past the stream's own extent is not an error: only whole
    entries the stream actually covers are parsed, and a record whose
    declared size stops short of a field leaves that field None."""
    location = directory.Location
    data_size = getattr(location, "DataSize", None)
    if not isinstance(data_size, int) or data_size < _THREAD_INFO_LIST_HEADER_SIZE:
        raise ThreadInfoStreamFramingError(
            f"ThreadInfoListStream is {data_size} byte(s), too small to contain its own "
            f"{_THREAD_INFO_LIST_HEADER_SIZE}-byte header")

    file_handle.seek(location.Rva, 0)
    header_bytes = file_handle.read(_THREAD_INFO_LIST_HEADER_SIZE)
    if len(header_bytes) < _THREAD_INFO_LIST_HEADER_SIZE:
        raise ThreadInfoStreamFramingError("ThreadInfoListStream header short read")
    header = MINIDUMP_THREAD_INFO_LIST.parse(io.BytesIO(header_bytes))

    size_of_header = header.SizeOfHeader
    size_of_entry  = header.SizeOfEntry
    if not isinstance(size_of_header, int) or not (
            _THREAD_INFO_LIST_HEADER_SIZE <= size_of_header <= data_size):
        raise ThreadInfoStreamFramingError(
            f"ThreadInfoListStream SizeOfHeader {size_of_header} is out of bounds for a "
            f"{data_size}-byte stream")
    if not isinstance(size_of_entry, int) or not (
            _THREAD_INFO_MIN_ENTRY_SIZE <= size_of_entry <= _THREAD_INFO_MAX_ENTRY_SIZE):
        raise ThreadInfoStreamFramingError(
            f"ThreadInfoListStream SizeOfEntry {size_of_entry} is outside the supported "
            f"range [{_THREAD_INFO_MIN_ENTRY_SIZE}, {_THREAD_INFO_MAX_ENTRY_SIZE}]")

    declared = header.NumberOfEntries if isinstance(header.NumberOfEntries, int) else 0
    wanted = max(0, min(declared, max_entries))
    # Three independent bounds on the one read: the stream's own declared
    # extent, dumpex's byte budget, and (below) how many bytes the file
    # actually had left.
    available = max(0, min(data_size - size_of_header, MAX_THREAD_INFO_RAW_BYTES))

    file_handle.seek(location.Rva + size_of_header, 0)
    raw_entries = file_handle.read(min(wanted * size_of_entry, available))

    # A trailing entry the stream or the file cuts short is still parsed
    # for the fields it DID carry, rather than dropped: its ThreadId and
    # DumpFlags are captured evidence, and discarding them would lose a
    # thread the base ThreadListStream still lists -- which reads
    # downstream as a thread that is not there at all. Fields the
    # surviving bytes do not cover stay None, exactly as they do for a
    # record the producer declared shorter. A ThreadId alone is enough
    # for the entry to be a record: it names a thread, and dropping it
    # is what makes that thread look absent from this stream. Only an
    # entry with less than a whole ThreadId left is not offered, and
    # that shortfall is recoverable as truncated_thread_info_count().
    infos = []
    for index in range(wanted):
        start = index * size_of_entry
        covered = min(size_of_entry, _THREAD_INFO_ENTRY_SIZE, max(0, len(raw_entries) - start))
        if covered < _THREAD_INFO_MIN_ENTRY_SIZE:
            break
        infos.append(_parse_thread_info_entry(raw_entries, start, covered))
    return ParsedThreadInfoList(header=header, infos=infos)


def declared_thread_info_count(parsed) -> "int | None":
    """`header.NumberOfEntries` off a parsed ThreadInfoListStream: how
    many records the stream says its array holds, independent of how many
    parse_thread_info_stream could actually read.

    None when nothing is KNOWN to be declared -- no stream, no header
    (a hand-built fixture, or the library's own list object), or a
    declared count that is not usable as one. Never read as zero records
    declared, which would report a truncated stream as complete."""
    if parsed is None:
        return None
    declared = getattr(getattr(parsed, "header", None), "NumberOfEntries", None)
    if declared is None or isinstance(declared, bool) or not isinstance(declared, int):
        return None
    return declared if declared >= 0 else None


def truncated_thread_info_count(parsed) -> int:
    """The record tail a parsed ThreadInfoListStream declared but did not
    deliver: `header.NumberOfEntries - len(infos)`, floored at 0. The one
    implementation of that rule, shared by every reader, so a truncated
    dump cannot be described two different ways in one case file.

    Read off the parsed object, never recomputed from the stream's own
    declared framing: parse_thread_info_stream bounds what it delivers by
    a term that framing omits -- how many bytes the file actually held --
    so a recomputation reports a smaller gap than reality on exactly the
    truncated file this count exists for.

    0 when nothing is known to be missing, and 0 as well when the stream
    delivered MORE than it declared: that is a contradiction in the
    dump's own numbers, not a negative shortfall, and no record is
    missing either way."""
    declared = declared_thread_info_count(parsed)
    if declared is None:
        return 0
    return max(0, declared - len(getattr(parsed, "infos", None) or ()))


def _parse_thread_info_entry(buf: bytes, start: int, covered: int) -> ParsedThreadInfo:
    """One entry of `buf`, read at the single validated layout.
    `covered` is how much of the known 64-byte record actually exists for
    this entry: a producer may declare a LONGER stride (trailing fields
    dumpex does not read) or a SHORTER record (fields that genuinely do
    not exist in it), and the stream or the file may cut the last entry
    short. Only fields covered in full are read at all; the rest stay
    None, which is what every reader treats as "this record did not
    carry this fact"."""
    info = ParsedThreadInfo()
    for name, offset, width in _THREAD_INFO_LAYOUT:
        if offset + width > covered:
            continue
        field = buf[start + offset:start + offset + width]
        setattr(info, name, int.from_bytes(field, byteorder="little", signed=False))
    # The library's single-member Enum view of the same raw value, kept
    # so a caller holding a ParsedThreadInfo sees the attribute it would
    # have seen from the library's own parse. dumpex.core.memory.dump_flags_value is what
    # every DumpFlags consumer actually reads.
    if info.RawDumpFlags is not None:
        try:
            info.DumpFlags = DumpFlags(info.RawDumpFlags)
        except ValueError:
            info.DumpFlags = None
    return info
