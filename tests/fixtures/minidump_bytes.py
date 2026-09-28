"""
Byte-level synthetic minidump writer.

Every other dump fixture in this tree hands a command an already-parsed
object graph (`tests.fixtures.fakes.FakeMF`), which never exercises
`dumpex.core.memory.open_dump()`'s header/directory walk, its per-stream
parser isolation, or the installed `minidump` library's own buffered reader
underneath `read_region()` and friends. This module writes a real `.dmp`
file instead, so a test can drive the loader and every captured-range read
through exactly the code a real invocation runs.

The layout is deliberately plain and fully determined by the spec:

    0x00                 MINIDUMP_HEADER (32 bytes)
    0x20                 directory table (12 bytes per declared stream)
    ...                  stream bodies, strings and thread contexts
    ...                  captured memory bytes (Memory64List first, then
                         MemoryList), always last

Captured memory sits at the end of the file so `truncate_to` can cut a
segment's backing bytes short -- a genuine short read -- without disturbing
any stream metadata that precedes it.

Only synthetic values are written. Nothing here reads or reproduces real
case evidence.
"""
import struct
from dataclasses import dataclass, field

from minidump.constants import MINIDUMP_STREAM_TYPE

# MINIDUMP_STREAM_TYPE values, written as raw integers.
THREAD_LIST = MINIDUMP_STREAM_TYPE.ThreadListStream.value
MODULE_LIST = MINIDUMP_STREAM_TYPE.ModuleListStream.value
MEMORY_LIST = MINIDUMP_STREAM_TYPE.MemoryListStream.value
SYSTEM_INFO = MINIDUMP_STREAM_TYPE.SystemInfoStream.value
MEMORY64_LIST = MINIDUMP_STREAM_TYPE.Memory64ListStream.value
HANDLE_DATA = MINIDUMP_STREAM_TYPE.HandleDataStream.value
MISC_INFO = MINIDUMP_STREAM_TYPE.MiscInfoStream.value
MEMORY_INFO_LIST = MINIDUMP_STREAM_TYPE.MemoryInfoListStream.value
THREAD_INFO_LIST = MINIDUMP_STREAM_TYPE.ThreadInfoListStream.value

ARCH_AMD64 = 9
ARCH_INTEL = 0

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

MINIDUMP_WITH_FULL_MEMORY = 0x2
MINIDUMP_WITH_HANDLE_DATA = 0x4

X64_CONTEXT_SIZE = 1232
X64_CONTEXT_RIP_OFFSET = 0xF8
WOW64_CONTEXT_SIZE = 716
WOW64_CONTEXT_EIP_OFFSET = 0xB8

_HEADER_SIZE = 32
_DIRECTORY_ENTRY_SIZE = 12


@dataclass(frozen=True)
class ModuleSpec:
    base: int
    size: int
    path: str
    checksum: int = 0
    timestamp: int = 0


@dataclass(frozen=True)
class ThreadSpec:
    tid: int
    ip: "int | None" = None      # None: no thread context is written
    teb: int = 0
    suspend_count: int = 0
    priority: int = 8


@dataclass(frozen=True)
class ThreadInfoSpec:
    tid: int
    dump_flags: int = 0
    start_address: int = 0
    exit_status: int = 0
    create_time: int = 0
    exit_time: int = 0
    kernel_time: int = 0
    user_time: int = 0


@dataclass(frozen=True)
class RegionSpec:
    base: int
    size: int
    state: int = MEM_COMMIT
    protect: int = PAGE_READWRITE
    type: int = MEM_PRIVATE
    allocation_base: "int | None" = None
    allocation_protect: int = PAGE_READWRITE


@dataclass(frozen=True)
class SegmentSpec:
    va: int
    data: bytes


@dataclass(frozen=True)
class HandleSpec:
    handle: int
    type_name: "str | None" = None
    object_name: "str | None" = None
    attributes: int = 0
    granted_access: int = 0
    handle_count: int = 1
    pointer_count: int = 1


@dataclass(frozen=True)
class RawStreamSpec:
    """A directory entry with a caller-owned body -- an unrecognized stream
    id, or a recognized one whose body is deliberately malformed."""
    stream_type: int
    body: bytes


@dataclass
class DumpSpec:
    architecture: "int | None" = ARCH_AMD64     # None: no SystemInfoStream
    flags: int = MINIDUMP_WITH_FULL_MEMORY
    time_date_stamp: int = 0x5F5E1000
    modules: "tuple | None" = ()                 # None: no ModuleListStream
    threads: "tuple | None" = ()                 # None: no ThreadListStream
    thread_infos: "tuple | None" = None          # None: no ThreadInfoListStream
    regions: "tuple | None" = ()                 # None: no MemoryInfoListStream
    memory64: "tuple | None" = ()                # None: no Memory64ListStream
    memory32: "tuple | None" = None              # None: no MemoryListStream
    handles: "tuple | None" = None               # None: no HandleDataStream
    process_id: "int | None" = None              # None: no MiscInfoStream
    raw_streams: tuple = ()
    declared_stream_count: "int | None" = None
    truncate_to: "int | None" = None
    extra: dict = field(default_factory=dict)


class _Arena:
    """Append-only byte buffer that hands back each blob's absolute RVA."""

    def __init__(self, base: int):
        self.base = base
        self.buf = bytearray()

    def put(self, data: bytes, align: int = 4) -> int:
        pad = (-(self.base + len(self.buf))) % align
        self.buf += b"\x00" * pad
        rva = self.base + len(self.buf)
        self.buf += data
        return rva


def _minidump_string(text: str) -> bytes:
    encoded = text.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded + b"\x00\x00"


def _system_info_body(arena: _Arena, architecture: int) -> bytes:
    csd_rva = arena.put(_minidump_string(""))
    return (struct.pack("<HHHBB", architecture, 6, 0, 4, 1)
            + struct.pack("<IIII", 10, 0, 19045, 2)
            + struct.pack("<IHH", csd_rva, 0, 0)
            + b"\x00" * 24)


def _module_list_body(arena: _Arena, modules) -> bytes:
    body = bytearray(struct.pack("<I", len(modules)))
    for m in modules:
        name_rva = arena.put(_minidump_string(m.path))
        body += struct.pack("<QIIII", m.base, m.size, m.checksum, m.timestamp, name_rva)
        body += b"\x00" * 52           # VS_FIXEDFILEINFO
        body += struct.pack("<IIII", 0, 0, 0, 0)   # CvRecord, MiscRecord
        body += struct.pack("<QQ", 0, 0)           # Reserved0, Reserved1
    return bytes(body)


def _thread_context(architecture: int, ip: int) -> bytes:
    if architecture == ARCH_INTEL:
        ctx = bytearray(WOW64_CONTEXT_SIZE)
        struct.pack_into("<I", ctx, WOW64_CONTEXT_EIP_OFFSET, ip)
    else:
        ctx = bytearray(X64_CONTEXT_SIZE)
        struct.pack_into("<Q", ctx, X64_CONTEXT_RIP_OFFSET, ip)
    return bytes(ctx)


def _thread_list_body(arena: _Arena, threads, architecture) -> bytes:
    body = bytearray(struct.pack("<I", len(threads)))
    for t in threads:
        if t.ip is None:
            ctx_rva, ctx_size = 0, 0
        else:
            ctx = _thread_context(architecture if architecture is not None else ARCH_AMD64, t.ip)
            ctx_rva, ctx_size = arena.put(ctx, align=16), len(ctx)
        body += struct.pack("<IIII", t.tid, t.suspend_count, 0, t.priority)
        body += struct.pack("<Q", t.teb)
        body += struct.pack("<QII", 0, 0, 0)          # Stack: MINIDUMP_MEMORY_DESCRIPTOR
        body += struct.pack("<II", ctx_size, ctx_rva)  # ThreadContext
    return bytes(body)


def _thread_info_list_body(infos) -> bytes:
    body = bytearray(struct.pack("<III", 12, 64, len(infos)))
    for i in infos:
        body += struct.pack("<IIIIQQQQQQ", i.tid, i.dump_flags, 0, i.exit_status,
                            i.create_time, i.exit_time, i.kernel_time, i.user_time,
                            i.start_address, 0)
    return bytes(body)


def _memory_info_list_body(regions) -> bytes:
    body = bytearray(struct.pack("<IIQ", 16, 48, len(regions)))
    for r in regions:
        allocation_base = r.base if r.allocation_base is None else r.allocation_base
        body += struct.pack("<QQIIQIIII", r.base, allocation_base, r.allocation_protect, 0,
                            r.size, r.state, r.protect, r.type, 0)
    return bytes(body)


def _handle_data_body(arena: _Arena, handles) -> bytes:
    body = bytearray(struct.pack("<IIII", 16, 32, len(handles), 0))
    for h in handles:
        rvas = []
        for name in (h.type_name, h.object_name):
            rvas.append(0 if name is None else arena.put(_minidump_string(name)))
        body += struct.pack("<QIIIIII", h.handle, rvas[0], rvas[1], h.attributes,
                            h.granted_access, h.handle_count, h.pointer_count)
    return bytes(body)


def _misc_info_body(process_id: int) -> bytes:
    # MINIDUMP_MISC_INFO: SizeOfInfo, Flags1 (MINIDUMP_MISC1_PROCESS_ID), ProcessId, 3 times.
    return struct.pack("<IIIIII", 24, 0x1, process_id, 0, 0, 0)


def build_minidump(spec: DumpSpec) -> bytes:
    """The complete file bytes for `spec` (see the module docstring)."""
    streams = []   # (stream_type, body_builder(arena) -> bytes)
    if spec.architecture is not None:
        streams.append((SYSTEM_INFO, lambda a: _system_info_body(a, spec.architecture)))
    if spec.modules is not None:
        streams.append((MODULE_LIST, lambda a: _module_list_body(a, spec.modules)))
    if spec.threads is not None:
        streams.append((THREAD_LIST, lambda a: _thread_list_body(a, spec.threads, spec.architecture)))
    if spec.thread_infos is not None:
        streams.append((THREAD_INFO_LIST, lambda a: _thread_info_list_body(spec.thread_infos)))
    if spec.regions is not None:
        streams.append((MEMORY_INFO_LIST, lambda a: _memory_info_list_body(spec.regions)))
    if spec.handles is not None:
        streams.append((HANDLE_DATA, lambda a: _handle_data_body(a, spec.handles)))
    if spec.process_id is not None:
        streams.append((MISC_INFO, lambda a: _misc_info_body(spec.process_id)))
    for raw in spec.raw_streams:
        streams.append((raw.stream_type, lambda a, body=raw.body: body))
    # Memory lists last: their descriptors point at the trailing data area.
    if spec.memory64 is not None:
        streams.append((MEMORY64_LIST, None))
    if spec.memory32 is not None:
        streams.append((MEMORY_LIST, None))

    arena = _Arena(_HEADER_SIZE + _DIRECTORY_ENTRY_SIZE * len(streams))
    directory = []
    for stream_type, builder in streams:
        if builder is None:
            continue
        body = builder(arena)
        directory.append((stream_type, arena.put(body), len(body)))

    mem64_desc_size = 16 + 16 * len(spec.memory64 or ())
    mem32_desc_size = 4 + 16 * len(spec.memory32 or ())
    mem64_desc_rva = arena.put(b"\x00" * mem64_desc_size, align=8) if spec.memory64 is not None else None
    mem32_desc_rva = arena.put(b"\x00" * mem32_desc_size, align=8) if spec.memory32 is not None else None

    if spec.memory64 is not None:
        data_rva = arena.put(b"".join(s.data for s in spec.memory64), align=16)
        desc = bytearray(struct.pack("<QQ", len(spec.memory64), data_rva))
        for s in spec.memory64:
            desc += struct.pack("<QQ", s.va, len(s.data))
        start = mem64_desc_rva - arena.base
        arena.buf[start:start + len(desc)] = desc
        directory.append((MEMORY64_LIST, mem64_desc_rva, len(desc)))
    if spec.memory32 is not None:
        desc = bytearray(struct.pack("<I", len(spec.memory32)))
        for s in spec.memory32:
            rva = arena.put(s.data, align=16)
            desc += struct.pack("<QII", s.va, len(s.data), rva)
        start = mem32_desc_rva - arena.base
        arena.buf[start:start + len(desc)] = desc
        directory.append((MEMORY_LIST, mem32_desc_rva, len(desc)))

    order = {stream_type: i for i, (stream_type, _) in enumerate(streams)}
    directory.sort(key=lambda entry: order[entry[0]])
    declared = len(directory) if spec.declared_stream_count is None else spec.declared_stream_count
    header = (b"MDMP" + struct.pack("<HH", 0xA793, 0)
              + struct.pack("<III", declared, _HEADER_SIZE, 0)
              + struct.pack("<I", spec.time_date_stamp)
              + struct.pack("<Q", spec.flags))
    table = b"".join(struct.pack("<III", stype, size, rva) for stype, rva, size in directory)
    out = header + table + bytes(arena.buf)
    if spec.truncate_to is not None:
        out = out[:spec.truncate_to]
    return out


def write_minidump(path, spec: DumpSpec) -> str:
    data = build_minidump(spec)
    with open(path, "wb") as fh:
        fh.write(data)
    return str(path)
