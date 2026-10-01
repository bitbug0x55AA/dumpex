"""The `dumpex.core.memory` compatibility entry point.

Every command, hunter and test imports the dump-loading, thread, lookup,
string-search, verdict and presentation names from here. None of them is
implemented here:

* loading, the HandleDataStream and ThreadInfoListStream parsers,
  stream-state observation, the segment table and captured-memory reads
  are in `dumpex.core.dumpfile`;
* thread-record interpretation and context joins, module/region/handle
  lookup and read-size resolution, and string/IOC extraction and search
  are in `dumpex.core.dumpquery`;
* verdict tiers are in `dumpex.core.verdict`;
* address, hexdump, verdict and open-failure text is in
  `dumpex.ui.memory_presentation`.

This module re-exports the owners' own objects and keeps a small
delegating entry point for each consumer of a name tests replace here (a
parser, cap, cache, reader or thread interpretation), so a replacement on
this module reaches the executions that use it. It holds the stream
dispatch table and the process-lifetime handle-layout cache, and nothing
else of its own; new capabilities go in their owner module. See
docs/developer/memory_layout.md for the owner of every name.
"""
import sys

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    print("[!] minidump not installed. Run: pip install minidump")
    sys.exit(1)

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams import (
    MinidumpThreadList, MinidumpModuleList, MinidumpMemoryList,
    MinidumpSystemInfo, MinidumpThreadExList, MinidumpMemory64List,
    CommentStreamA, CommentStreamW, ExceptionList,
    MinidumpUnloadedModuleList, MinidumpMiscInfo,
    MinidumpMemoryInfoList,
)
from minidump.streams.ContextStream import CONTEXT, WOW64_CONTEXT
from minidump.streams.HandleDataStream import (
    MINIDUMP_HANDLE_DESCRIPTOR, MINIDUMP_HANDLE_DESCRIPTOR_2,
)
from minidump.structures.peb import PEB

from dumpex.output.coverage import SourceObservation
from dumpex.core.dumpfile.handle_stream import (
    MAX_HANDLE_DESCRIPTORS,
    MAX_HANDLE_STRING_BYTES,
    _DESCRIPTOR_PROBE_BYTES,
    HandleDescriptorLayoutError,
    HandleStreamContractError,
    HandleStreamFramingError,
    ParsedHandleDataStream,
    ParsedHandleDescriptor,
    _descriptor_class_size,
    _read_handle_string,
    declared_descriptor_count,
    parse_bounded_handle_stream,
    truncated_descriptor_count,
    validated_descriptor_layout,
)
from dumpex.core.dumpfile.thread_info_stream import (
    MAX_THREAD_INFO_ENTRIES,
    MAX_THREAD_INFO_RAW_BYTES,
    ParsedThreadInfo,
    ParsedThreadInfoList,
    ThreadInfoStreamFramingError,
    declared_thread_info_count,
    parse_bounded_thread_info_stream,
    truncated_thread_info_count,
)
from dumpex.core.dumpfile.loader import (
    DumpFileNotFoundError,
    DumpFormatError,
    directory_truncated_count,
    has_stream_directory,
    load_minidump,
    peb_failure,
    stream_failure,
)
from dumpex.core.dumpfile.stream_state import (
    UNPARSED_HANDLE_STREAM_DETAIL,
    handle_stream_state,
    stream_observation,
)
from dumpex.core.dumpfile.segments import (
    _memory_segments,
    captured_range_length,
    segment_file_offset,
)
from dumpex.core.dumpfile.reads import (
    RegionReadError,
    clamped_reader,
    read_region,
    read_region_spanning,
)
from dumpex.core.dumpquery.threads import (
    DUMP_FLAG_ERROR_THREAD,
    DUMP_FLAG_EXITED_THREAD,
    DUMP_FLAG_INVALID_CONTEXT,
    DUMP_FLAG_INVALID_INFO,
    DUMP_FLAG_INVALID_TEB,
    DUMP_FLAG_WRITING_THREAD,
    DUMP_FLAGS_ABSENT,
    DUMP_FLAGS_RESOLVED,
    DUMP_FLAGS_UNRESOLVED,
    START_ADDRESS_ABSENT,
    START_ADDRESS_INVALID,
    START_ADDRESS_RECORDED,
    START_ADDRESS_UNVERIFIED,
    RawThreadInfo,
    _is_real_thread_info,
    dump_flags_value,
    get_thread_contexts,
    get_thread_infos,
    join_thread_contexts,
    thread_context_conflict,
    thread_dump_flags_state,
    thread_dump_flags_tags,
    thread_start_address,
)
from dumpex.core.dumpquery.lookup import (
    MAX_REGION_READ,
    SYSTEM_RANGE,
    _get_region_at,
    addr_to_module,
    get_handles,
    get_memory_regions,
    get_modules,
    group_regions_by_allocation,
    module_name_only,
    parse_hex_or_int,
    prot_str,
    resolve_read_size,
)
from dumpex.core.dumpquery.strings import (
    IOC_STRING_ENCODING_WIDTHS,
    StringSearchStats,
    _extract_ioc_strings,
    _extract_strings_from_data,
    search_committed_regions,
)
from dumpex.core.verdict import (
    INDICATOR_DIMS,
    VERDICT_CLEAN,
    VERDICT_HIGH_CONFIDENCE_MALICIOUS,
    VERDICT_LIKELY_MALICIOUS,
    VERDICT_SUSPICIOUS,
    verdict_for,
)
from dumpex.ui.memory_presentation import (
    _hexdump_context,
    _verdict,
    address_label,
    dump_format_error_lines,
    dump_not_found_lines,
)


# ── HandleDataStream entry points ─────────────────────────────────────────
# The parser is dumpex.core.dumpfile.handle_stream. These two entry points
# bind the descriptor classes, the descriptor cap, the size probe and the
# process-lifetime layout cache from this module's namespace at call time.

_HANDLE_DESCRIPTOR_LAYOUT_CACHE = None


def _handle_descriptor_layout() -> "tuple[int, int]":
    """Returns (v1_size, v2_size) -- the validated on-disk descriptor sizes
    parse_handle_stream() selects a parser class by (see
    validated_descriptor_layout) -- deriving them from this module's
    MINIDUMP_HANDLE_DESCRIPTOR/_2 through its _descriptor_class_size the
    first time this is called (from inside parse_handle_stream(), never at
    import), then caching the result in _HANDLE_DESCRIPTOR_LAYOUT_CACHE
    for the life of the process. A failed derivation raises
    HandleDescriptorLayoutError and caches nothing."""
    global _HANDLE_DESCRIPTOR_LAYOUT_CACHE
    if _HANDLE_DESCRIPTOR_LAYOUT_CACHE is not None:
        return _HANDLE_DESCRIPTOR_LAYOUT_CACHE
    _HANDLE_DESCRIPTOR_LAYOUT_CACHE = validated_descriptor_layout(
        MINIDUMP_HANDLE_DESCRIPTOR, MINIDUMP_HANDLE_DESCRIPTOR_2, _descriptor_class_size)
    return _HANDLE_DESCRIPTOR_LAYOUT_CACHE


def parse_handle_stream(directory, file_handle) -> ParsedHandleDataStream:
    """dumpex's own bounded, validated HandleDataStream parser (see
    dumpex.core.dumpfile.handle_stream.parse_bounded_handle_stream), with
    this module's _handle_descriptor_layout, MINIDUMP_HANDLE_DESCRIPTOR/_2
    and MAX_HANDLE_DESCRIPTORS. Raises HandleStreamFramingError when the
    stream's own framing cannot be trusted; a declared descriptor count
    beyond the cap or the stream's extent is capped, recoverable as
    truncated_descriptor_count()."""
    return parse_bounded_handle_stream(
        directory, file_handle,
        descriptor_layout=_handle_descriptor_layout,
        v1_descriptor=MINIDUMP_HANDLE_DESCRIPTOR,
        v2_descriptor=MINIDUMP_HANDLE_DESCRIPTOR_2,
        max_descriptors=MAX_HANDLE_DESCRIPTORS)


# ── ThreadInfoListStream entry point ──────────────────────────────────────
# The parser is dumpex.core.dumpfile.thread_info_stream; parse_thread_info_stream
# binds this module's MAX_THREAD_INFO_ENTRIES at call time.

def parse_thread_info_stream(directory, file_handle) -> ParsedThreadInfoList:
    """dumpex's own bounded, single-layout ThreadInfoListStream parser (see
    dumpex.core.dumpfile.thread_info_stream.parse_bounded_thread_info_stream),
    capped at this module's MAX_THREAD_INFO_ENTRIES. Raises
    ThreadInfoStreamFramingError when the stream's own framing cannot be
    trusted; a record the stream does not fully cover keeps the fields it
    carried and leaves the rest None."""
    return parse_bounded_thread_info_stream(
        directory, file_handle, max_entries=MAX_THREAD_INFO_ENTRIES)


# ── Thread interpretation entry points ────────────────────────────────────
# The interpretations are dumpex.core.dumpquery.threads. Each entry point
# binds this module's _is_real_thread_info, dump_flags_value, stream
# readers and per-thread interpretations at call time.

def dump_flags_state(thread_info) -> str:
    """One of DUMP_FLAGS_RESOLVED / _UNRESOLVED / _ABSENT for this record
    (see dumpex.core.dumpquery.threads.thread_dump_flags_state), with this
    module's _is_real_thread_info and dump_flags_value."""
    return thread_dump_flags_state(
        thread_info, is_recorded=_is_real_thread_info, flags_value=dump_flags_value)


def dump_flags_tags(thread_info) -> list:
    """Every DumpFlags bit set on this record as a `--threads` tag, in bit
    order (see dumpex.core.dumpquery.threads.thread_dump_flags_tags), with
    this module's dump_flags_value."""
    return thread_dump_flags_tags(thread_info, flags_value=dump_flags_value)


def recorded_start_address(thread_info) -> tuple:
    """`(start_address, state)` for one thread, state one of
    START_ADDRESS_RECORDED / _INVALID / _UNVERIFIED / _ABSENT (see
    dumpex.core.dumpquery.threads.thread_start_address), with this
    module's _is_real_thread_info and dump_flags_value."""
    return thread_start_address(
        thread_info, is_recorded=_is_real_thread_info, flags_value=dump_flags_value)


def ip_context_conflict_for(ip: "int | None", thread_info) -> "bool | None":
    """Tri-state join of a thread's captured `ip` against its own
    ThreadInfoListStream record's DumpFlags (see
    dumpex.core.dumpquery.threads.thread_context_conflict), with this
    module's _is_real_thread_info and dump_flags_value."""
    return thread_context_conflict(
        ip, thread_info, is_recorded=_is_real_thread_info, flags_value=dump_flags_value)


def enriched_thread_contexts(mf: MinidumpFile) -> list:
    """Each captured thread context joined with its own TID's recorded
    start address, start-address state and context-conflict state (see
    dumpex.core.dumpquery.threads.join_thread_contexts), through this
    module's get_thread_infos, get_thread_contexts, recorded_start_address
    and ip_context_conflict_for."""
    return join_thread_contexts(
        mf,
        thread_infos=get_thread_infos,
        thread_contexts=get_thread_contexts,
        start_address=recorded_start_address,
        context_conflict=ip_context_conflict_for)


# ── Stream dispatch ───────────────────────────────────────────────────────
# Which stream types open_dump() parses, onto which mf.<attr>, with which
# parser. dumpex's own HandleDataStream and ThreadInfoListStream parsers
# replace the library's; every other stream uses the library's own public
# parser class. A stream type not listed here is skipped, not failed.

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
    MINIDUMP_STREAM_TYPE.ThreadInfoListStream:     ("thread_info", parse_thread_info_stream),
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


# ── Loading, stream-state and captured-range entry points ─────────────────

def open_dump(path: str) -> MinidumpFile:
    """Open and parse the minidump at `path` with per-stream isolation
    (see dumpex.core.dumpfile.loader.load_minidump), dispatching through
    this module's _STREAM_DISPATCH and parsing thread contexts and the PEB
    through its CONTEXT, WOW64_CONTEXT and PEB.

    A missing file, or one whose header or directory table cannot be read,
    is reported on stdout and exits 1: there is no per-stream evidence to
    salvage from either."""
    try:
        return load_minidump(path, stream_dispatch=_STREAM_DISPATCH, context=CONTEXT,
                             wow64_context=WOW64_CONTEXT, peb=PEB)
    except DumpFileNotFoundError:
        for line in dump_not_found_lines(path):
            print(line)
        sys.exit(1)
    except DumpFormatError as e:
        for line in dump_format_error_lines(path, e.cause):
            print(line)
        sys.exit(1)


def handle_stream_evidence(mf: MinidumpFile) -> "tuple[str, object, str | None]":
    """-> (state, parsed_stream_or_None, failure_detail_or_None), where
    state is "absent", "failed" or "parsed" -- see
    dumpex.core.dumpfile.stream_state.handle_stream_state, given the
    HandleDataStream failure this module's stream_failure reports."""
    return handle_stream_state(
        mf, stream_failure(mf, MINIDUMP_STREAM_TYPE.HandleDataStream))


def observe_stream(mf: MinidumpFile, name: str, stream_type, obj, items: list) -> SourceObservation:
    """The SourceObservation of a stream-backed source: FAILED with the
    parser's own detail when this module's stream_failure reports one for
    `stream_type`, otherwise absent/present_empty/present over
    `obj`/`items` -- see dumpex.core.dumpfile.stream_state.stream_observation."""
    return stream_observation(name, stream_failure(mf, stream_type), obj, items)


def read_region_clamped(mf: MinidumpFile, addr: int, size: int) -> bytes:
    """One-shot form of clamped_reader() -- matches read_region()'s own
    per-call convention for a caller that only needs a single clamped
    read, not a reusable bound reader."""
    return clamped_reader(mf)(addr, size)


def get_memory_segments(mf: MinidumpFile) -> list:
    """The dump's segment table as this module's _memory_segments(mf)
    resolves it -- the same Memory64List-preferred-over-MemoryList table
    read_region() and va_to_file_offset() resolve VAs against."""
    return _memory_segments(mf)


def va_to_file_offset(mf: MinidumpFile, va: int):
    """The .dmp file offset of process VA `va`, or None when no segment of
    this module's _memory_segments(mf) covers it -- see
    dumpex.core.dumpfile.segments.segment_file_offset for the address
    types a minidump carries."""
    return segment_file_offset(mf, va, segment_table=_memory_segments)


def va_range_captured_bytes(mf: MinidumpFile, va: int, size: int) -> int:
    """How many of the `size` bytes at `va` the dump captured as one
    contiguous run of this module's _memory_segments(mf), in `[0, size]` --
    see dumpex.core.dumpfile.segments.captured_range_length."""
    return captured_range_length(mf, va, size, segment_table=_memory_segments)


def addr_label(mf: MinidumpFile, va: int, region_base=None, indent: int = 2) -> str:
    """The VA / .dmp file offset / region base annotation for `va` (see
    dumpex.ui.memory_presentation.address_label), with the file offset
    this module's va_to_file_offset resolves."""
    return address_label(va, va_to_file_offset(mf, va), region_base, indent)


# ── Read-size and string-search entry points ──────────────────────────────

def _resolve_size(mf: MinidumpFile, addr: int, requested_size: int | None) -> int:
    """The size a read at `addr` uses (see
    dumpex.core.dumpquery.lookup.resolve_read_size): `requested_size` when
    given, otherwise the rest of the containing region capped at this
    module's MAX_REGION_READ, or 0x10000 when no region contains `addr`."""
    return resolve_read_size(mf, addr, requested_size, max_read=MAX_REGION_READ)


def _search_string_in_memory(mf: MinidumpFile, needle: str) -> tuple:
    """(hits, StringSearchStats) for `needle` across every committed
    region (see dumpex.core.dumpquery.strings.search_committed_regions),
    read through this module's read_region and capped per region at its
    MAX_REGION_READ."""
    return search_committed_regions(mf, needle, read=read_region, max_read=MAX_REGION_READ)
