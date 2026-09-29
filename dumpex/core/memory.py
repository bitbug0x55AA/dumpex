"""The `dumpex.core.memory` entry point: dump loading, stream parsing,
captured-range access, thread-record interpretation, region and module
lookup, string search and verdict helpers.

Loading, the HandleDataStream and ThreadInfoListStream parsers,
stream-state observation, the segment table and captured-memory reads are
implemented in `dumpex.core.dumpfile`; this module re-exports them and
keeps a small delegating entry point for each one that consults a name
tests replace here (a parser, cap, cache or reader), so a replacement on
this module reaches the executions that use it. See
docs/developer/memory_layout.md for the owner of every name.
"""
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

from dumpex.ui.colors import RED, DIM, YELLOW, GREEN
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

SYSTEM_RANGE = 0x7FF000000000

def parse_hex_or_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def prot_str(protect) -> str:
    try:    return protect.name
    except: return str(protect)



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


# ── ThreadInfoListStream: record interpretation ───────────────────────────
# The parser is dumpex.core.dumpfile.thread_info_stream; parse_thread_info_stream
# below binds this module's MAX_THREAD_INFO_ENTRIES at call time.

DUMP_FLAG_ERROR_THREAD    = 0x00000001   # placeholder record: only ThreadId is valid
DUMP_FLAG_WRITING_THREAD  = 0x00000002
DUMP_FLAG_EXITED_THREAD   = 0x00000004
DUMP_FLAG_INVALID_INFO    = 0x00000008   # thread information could not be retrieved
DUMP_FLAG_INVALID_CONTEXT = 0x00000010
DUMP_FLAG_INVALID_TEB     = 0x00000020

# Bit order, so a combined value renders as a stable, reproducible tag
# list. The tag strings themselves are the vocabulary `--threads` has
# always rendered (bracketed there: `[NO_CTX]`).
_DUMP_FLAG_TAGS = (
    (DUMP_FLAG_ERROR_THREAD,    "ERROR"),
    (DUMP_FLAG_WRITING_THREAD,  "DUMPER"),
    (DUMP_FLAG_EXITED_THREAD,   "EXITED"),
    (DUMP_FLAG_INVALID_INFO,    "NO_INFO"),
    (DUMP_FLAG_INVALID_CONTEXT, "NO_CTX"),
    (DUMP_FLAG_INVALID_TEB,     "NO_TEB"),
)

# The flags that make everything in a MINIDUMP_THREAD_INFO record EXCEPT
# ThreadId meaningless: ERROR_THREAD is documented as "a placeholder
# thread due to an error accessing the thread -- no thread information
# exists beyond the thread identifier", and INVALID_INFO as "thread
# information could not be retrieved". StartAddress in such a record is
# an unwritten field, not an address the process ever had.
_DUMP_FLAGS_INFO_INVALID = DUMP_FLAG_ERROR_THREAD | DUMP_FLAG_INVALID_INFO

# `dump_flags_state`: can this record's DumpFlags value be established?
DUMP_FLAGS_RESOLVED   = "resolved"     # value known (0 == genuinely no flags set)
DUMP_FLAGS_UNRESOLVED = "unresolved"   # record exists, its value could not be read
DUMP_FLAGS_ABSENT     = "absent"       # no ThreadInfoListStream record for this TID

# `recorded_start_address`: what standing does this record's StartAddress have?
START_ADDRESS_RECORDED   = "recorded"     # flags known and not invalidating, field present
START_ADDRESS_INVALID    = "invalid"      # flags mark the record's own info invalid
START_ADDRESS_UNVERIFIED = "unverified"   # field present, its validity unestablished
START_ADDRESS_ABSENT     = "absent"       # no address was recorded for this thread



def parse_thread_info_stream(directory, file_handle) -> ParsedThreadInfoList:
    """dumpex's own bounded, single-layout ThreadInfoListStream parser (see
    dumpex.core.dumpfile.thread_info_stream.parse_bounded_thread_info_stream),
    capped at this module's MAX_THREAD_INFO_ENTRIES. Raises
    ThreadInfoStreamFramingError when the stream's own framing cannot be
    trusted; a record the stream does not fully cover keeps the fields it
    carried and leaves the rest None."""
    return parse_bounded_thread_info_stream(
        directory, file_handle, max_entries=MAX_THREAD_INFO_ENTRIES)


def _is_real_thread_info(thread_info) -> bool:
    """True only for an actual ThreadInfoListStream record. A missing
    record is either None (the caller's own lookup came up empty) or a
    RawThreadInfo placeholder, and the two mean the same thing: this TID
    has no ThreadInfoListStream entry to read anything off."""
    return thread_info is not None and not isinstance(thread_info, RawThreadInfo)


def dump_flags_value(thread_info) -> "int | None":
    """This record's DumpFlags as a raw bit mask, or None when the value
    cannot be established -- the single derivation every DumpFlags
    consumer goes through, so "no flags set" and "value unknown" cannot
    diverge between them.

    Prefers `.RawDumpFlags` (see parse_thread_info_stream). Falls back to
    a `.DumpFlags` enum's own `.value`, which IS the exact on-disk value
    wherever that single-member lookup succeeded at all. A record with
    neither reports None: 0x0 and an unrepresentable combination are
    indistinguishable at that point, and only one of them is harmless."""
    raw = getattr(thread_info, "RawDumpFlags", None)
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    value = getattr(getattr(thread_info, "DumpFlags", None), "value", None)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def dump_flags_state(thread_info) -> str:
    """One of DUMP_FLAGS_RESOLVED / _UNRESOLVED / _ABSENT for this record
    -- the fact that tells a consumer whether an empty `dump_flags_tags`
    list means "this thread carries no flags" or "nothing is known about
    this thread's flags"."""
    if not _is_real_thread_info(thread_info):
        return DUMP_FLAGS_ABSENT
    return (DUMP_FLAGS_RESOLVED if dump_flags_value(thread_info) is not None
            else DUMP_FLAGS_UNRESOLVED)


def dump_flags_tags(thread_info) -> list:
    """Every DumpFlags bit set on this record, as the short tags
    `--threads` renders, in bit order -- a combined value yields one tag
    per bit rather than collapsing to a single name or to nothing. Empty
    for a record whose value is unresolved or absent; a caller
    distinguishing those from a genuinely flagless thread reads
    `dump_flags_state`."""
    value = dump_flags_value(thread_info)
    if value is None:
        return []
    return [tag for bit, tag in _DUMP_FLAG_TAGS if value & bit]


def recorded_start_address(thread_info) -> tuple:
    """`(start_address, state)` for one thread -- the single derivation
    every command and hunter reads a thread's StartAddress through, so a
    start address that its own record disowns, or never carried, cannot
    be trusted by one consumer and rejected by another.

    `state` is one of START_ADDRESS_RECORDED / _INVALID / _UNVERIFIED /
    _ABSENT:

    * _RECORDED -- a real record whose DumpFlags are known and carry
      neither ERROR_THREAD nor INVALID_INFO, and which actually carried
      a StartAddress field. The address is evidence.
    * _INVALID -- the record's own DumpFlags say only ThreadId is valid
      (see _DUMP_FLAGS_INFO_INVALID). `start_address` is None: a field
      the producer never filled in is missing evidence, and reporting
      its zero bytes as address 0x0 would manufacture a confirmed "not
      in any module" finding out of that absence.
    * _UNVERIFIED -- a real record that carried an address, but whose
      DumpFlags value could not be established. The address is returned
      unchanged -- it is real data and discarding it would lose evidence
      -- but nothing establishes that the producer stood behind it, so it
      must not feed a confirmed finding on its own.
    * _ABSENT -- no start address was recorded for this thread at all:
      no ThreadInfoListStream record (see RawThreadInfo), or one whose
      own declared record size stopped short of the StartAddress field
      (see parse_thread_info_stream). Readable DumpFlags say nothing
      about whether the address field was captured, so they never
      promote this case. `start_address` is None, never coerced to 0.

    A thread's own captured current IP is an independent fact from an
    independent stream and is neither consulted nor substituted here;
    see get_thread_contexts."""
    if not _is_real_thread_info(thread_info):
        return None, START_ADDRESS_ABSENT
    value = dump_flags_value(thread_info)
    if value is not None and value & _DUMP_FLAGS_INFO_INVALID:
        return None, START_ADDRESS_INVALID
    address = getattr(thread_info, "StartAddress", None)
    if address is None:
        return None, START_ADDRESS_ABSENT
    if value is None:
        return address, START_ADDRESS_UNVERIFIED
    return address, START_ADDRESS_RECORDED


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
        print(RED(f"[!] File not found: {path}"))
        sys.exit(1)
    except DumpFormatError as e:
        cause = e.cause
        print(RED(f"[!] Could not parse {path} as a minidump file: "
                   f"{type(cause).__name__}: {cause}"))
        print(DIM(f"    The file may be corrupted, truncated, or not a Windows "
                   f"minidump (.dmp) at all."))
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



def get_modules(mf: MinidumpFile) -> list:
    if mf.modules and mf.modules.modules:
        return mf.modules.modules
    return []


def get_thread_infos(mf: MinidumpFile) -> list:
    if mf.thread_info and mf.thread_info.infos:
        return mf.thread_info.infos
    return []


class RawThreadInfo:
    """
    Stand-in for a MINIDUMP_THREAD_INFO record, for a TID that exists in
    the base ThreadListStream but has no entry in the optional
    ThreadInfoListStream (that whole stream may be absent, or just this
    one TID may be missing from an otherwise-present stream).
    StartAddress/CreateTime/ExitTime/KernelTime/UserTime/ExitStatus/
    DumpFlags don't exist on the raw MINIDUMP_THREAD structure, so they
    stay None here rather than being guessed at -- this TID's CONTEXT
    (see get_thread_contexts) is unaffected and independently available.

    Shared by dumpex.commands.threads (--threads) and dumpex.commands.
    report (--report): both need the identical "this TID is real, but
    ThreadInfoListStream never covered it" placeholder, and a TID present
    only in the base stream must be reported the same way -- start
    address unknown, current IP independently available -- by either
    command.
    """
    __slots__ = ("ThreadId", "StartAddress", "CreateTime", "ExitTime",
                 "KernelTime", "UserTime", "ExitStatus", "DumpFlags",
                 "RawDumpFlags")

    def __init__(self, tid):
        self.ThreadId     = tid
        self.StartAddress = None
        self.CreateTime    = None
        self.ExitTime      = None
        self.KernelTime    = None
        self.UserTime      = None
        self.ExitStatus    = None
        self.DumpFlags     = None
        # No ThreadInfoListStream record means no raw DumpFlags value to
        # read either -- see parse_thread_info_stream.
        self.RawDumpFlags  = None


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


def ip_context_conflict_for(ip: "int | None", thread_info) -> "bool | None":
    """Tri-state join of a thread's captured CONTEXT (`ip`, from the base
    ThreadListStream/get_thread_contexts) against its own
    ThreadInfoListStream record's DumpFlags -- the single derivation
    dumpex.commands.threads (--threads) and dumpex.commands.report
    (--report) both consume, so a TID's dispute status cannot read
    differently between the two commands.

    `thread_info` is the record this TID resolved to: a real
    ThreadInfoListStream entry, or None/a RawThreadInfo placeholder when
    the stream never covered it.

    False when `ip` is None: there is no captured value to dispute,
    regardless of whether ThreadInfoListStream covers this TID at all.

    Otherwise None -- undeterminable, never a confirmed False -- in both
    states where the join cannot actually be performed:

    * no ThreadInfoListStream entry for this TID at all (see
      RawThreadInfo): there is nothing to join `ip` against, and
    * an entry whose DumpFlags value could not be established (see
      dump_flags_value): a value that cannot be read disputes nothing
      and clears nothing.

    Only when a real record's flags are actually known is the join
    performed: True exactly when MINIDUMP_THREAD_INFO_INVALID_CONTEXT is
    among them (the `[NO_CTX]` tag --threads renders), which a combined
    flag value satisfies the same as a lone one."""
    if ip is None:
        return False
    flags = dump_flags_value(thread_info) if _is_real_thread_info(thread_info) else None
    if flags is None:
        return None
    return bool(flags & DUMP_FLAG_INVALID_CONTEXT)


def enriched_thread_contexts(mf: MinidumpFile) -> list:
    """`get_thread_contexts(mf)`'s dicts, each augmented with this same
    TID's own ThreadInfoListStream-sourced `"start_address"`/
    `"start_address_state"` (see `recorded_start_address`) and tri-state
    `"ip_context_conflict"` (see `ip_context_conflict_for`) -- the single
    join `dumpex.commands.threads`, `dumpex.commands.report`, and every
    `--hunt` hunter that reads a thread's current RIP/EIP (injection,
    stomping, pipe) now share, so the SAME TID's start address and
    dispute status cannot read differently across commands or across
    hunters. Existing dict consumers (`tc["ip"]`, `tc["ip_reg"]`,
    `tc["ThreadId"]`) are unaffected -- this only adds keys, never
    removes or renames any.

    `"start_address"` is the record's own address only where that record
    stands behind it: a record whose DumpFlags mark its thread
    information invalid contributes None here, exactly like a TID the
    stream never covered, and `"start_address_state"` says which of the
    two it was."""
    infos_by_tid = {ti.ThreadId: ti for ti in get_thread_infos(mf)}
    out = []
    for c in get_thread_contexts(mf):
        ti = infos_by_tid.get(c["ThreadId"])
        start_address, start_address_state = recorded_start_address(ti)
        out.append({
            **c,
            "start_address": start_address,
            "start_address_state": start_address_state,
            "ip_context_conflict": ip_context_conflict_for(c["ip"], ti),
        })
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
    "injected_pe":     "Injected PE (valid PE header outside any loaded module, "
                       "in private or executable memory)",
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

# The encoding tag `_extract_ioc_strings` attaches to each string it
# extracts, and how many BYTES one character of such a string occupies.
#
# The two belong together: a caller matching a pattern against the DECODED
# text gets a CHARACTER index back, and resolving that to a region byte
# offset needs the width. Defining the widths beside the tags — rather than
# leaving a consumer to restate them — is what stops a new or renamed tag
# from silently taking a wrong width in a caller that never learned about
# it. A consumer indexes this map directly (never `.get(enc, 1)`): an
# unknown tag is an in-module inconsistency between this map and the three
# `results.append(...)` calls below, not something a dump can produce.
_IOC_ENC_ASCII = "ASCII"
_IOC_ENC_ASCII_URL = "ASCII-URL"
_IOC_ENC_UTF16 = "UTF16"

IOC_STRING_ENCODING_WIDTHS = {
    _IOC_ENC_ASCII:     1,
    _IOC_ENC_ASCII_URL: 1,
    _IOC_ENC_UTF16:     2,
}


def _extract_ioc_strings(data: bytes, base_addr: int) -> list:
    """
    Extract IOC-relevant strings with full length preservation.
    Uses two strategies:
      1. Standard printable-ASCII regex (catches most strings)
      2. Anchor-and-extend for known prefixes (https://, http://) that may
         be followed by bytes that break the printable-ASCII run — this
         prevents truncation of URLs stored with mixed-case or encoded chars.
    Returns list of (offset, enc, string). `offset` is a BYTE offset into
    `data`; `enc` is one of `IOC_STRING_ENCODING_WIDTHS`' keys above, whose
    value is the byte width of one character of `string`.
    """
    results = []
    seen_offsets = set()

    # Strategy 1: standard printable ASCII, min 8 chars
    pat = rb'[ -~]{8,}'
    for m in re.finditer(pat, data):
        results.append((m.start(), _IOC_ENC_ASCII,
                        m.group().decode("ascii", errors="replace")))
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
                    results.append((idx, _IOC_ENC_ASCII_URL, s))
                    seen_offsets.add(idx)
            pos = idx + 1

    # UTF-16LE
    pat_uni = rb'(?:[ -~]\x00){8,}'
    for m in re.finditer(pat_uni, data):
        if m.start() not in seen_offsets:
            results.append((m.start(), _IOC_ENC_UTF16,
                            m.group().decode("utf-16-le", errors="replace")))

    results.sort(key=lambda x: x[0])
    return results
