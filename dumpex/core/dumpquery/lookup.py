"""Lookups over a loaded dump's module, memory-info and handle streams:
the stream accessors, the module and region that contain an address,
allocation grouping, module base names, protection and state names,
address arguments, and the size an unsized read resolves to.

Read-size resolution takes its ceiling as an argument; the bound entry
point `dumpex.core.memory._resolve_size` passes the legacy module's
`MAX_REGION_READ`.
"""
import ntpath

from minidump.minidumpfile import MinidumpFile


SYSTEM_RANGE = 0x7FF000000000

MAX_REGION_READ = 256 * 1024 * 1024   # hard ceiling for an AUTO-sized single read
                                       # (--extract/--strings/--report without an
                                       # explicit --size). A region's declared
                                       # RegionSize comes straight from the dump file
                                       # and isn't otherwise validated — a corrupted or
                                       # crafted dump could claim a huge size and force
                                       # an equally huge single read/allocation nobody
                                       # asked for. An explicit --size is deliberate
                                       # user intent and is NOT clamped here.


def parse_hex_or_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def prot_str(protect) -> str:
    try:    return protect.name
    except: return str(protect)


def get_modules(mf: MinidumpFile) -> list:
    if mf.modules and mf.modules.modules:
        return mf.modules.modules
    return []


def get_memory_regions(mf: MinidumpFile) -> list:
    if mf.memory_info and mf.memory_info.infos:
        return mf.memory_info.infos
    return []


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


def module_name_only(full_path: str) -> str:
    """Extract just the filename from a full module path. Module paths
    recorded in a minidump are always Windows paths (e.g.
    "C:\\Windows\\System32\\foo.dll") regardless of the host OS this tool
    runs on -- os.path.basename only splits on "/" on a POSIX analysis
    host, returning the whole backslash-separated string unchanged there
    and breaking cross-dump module matching (the same module at two
    different directories would compare unequal). Uses ntpath.basename,
    not os.path.basename, for the same reason dumpex.commands.modules/
    threads and dumpex.hunt.stomping.memory_scan's own _module_basename
    do."""
    return ntpath.basename(full_path).lower() if full_path else ""


def addr_to_module(addr: int, modules: list):
    """Return module if address falls within it, else None."""
    for m in modules:
        if m.baseaddress <= addr < m.endaddress:
            return m
    return None


def _get_region_at(addr: int, regions: list):
    """Find the memory region containing addr."""
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return r
    return None


def resolve_read_size(mf: MinidumpFile, addr: int, requested_size: "int | None", *,
                      max_read: int) -> int:
    """
    The size a read at `addr` uses. An explicit `requested_size` is
    returned as-is -- that's the user's own choice, not an auto-derived
    value that needs a safety net -- and the memory-info stream is then
    not consulted. Without one, the memory region that contains `addr`
    gives the size: from `addr` to the region boundary, capped at
    `max_read` (dumpex.core.memory._resolve_size passes MAX_REGION_READ).
    Falls back to 0x10000 if the region cannot be found.
    """
    if requested_size is not None:
        return requested_size
    for r in get_memory_regions(mf):
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            actual = r.RegionSize - (addr - r.BaseAddress)
            return min(actual, max_read)
    return 0x10000  # fallback if region not in memory info
