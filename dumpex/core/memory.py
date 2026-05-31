"""Core memory helpers: address translation, region lookup, module lookup."""
import os
import sys
import re
from pathlib import Path

try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    print("[!] minidump not installed. Run: pip install minidump")
    sys.exit(1)

from dumpex.ui.colors import RED, DIM

SYSTEM_RANGE = 0x7FF000000000

def parse_hex_or_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def prot_str(protect) -> str:
    try:    return protect.name
    except: return str(protect)


def open_dump(path: str) -> MinidumpFile:
    if not os.path.exists(path):
        print(RED(f"[!] File not found: {path}"))
        sys.exit(1)
    return MinidumpFile.parse(path)


def read_region(mf: MinidumpFile, addr: int, size: int) -> bytes:
    reader = mf.get_reader().get_buffered_reader()
    reader.move(addr)
    return reader.read(size)


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


def module_name_only(full_path: str) -> str:
    """Extract just the filename from a full module path."""
    return os.path.basename(full_path).lower() if full_path else ""


def addr_to_module(addr: int, modules: list):
    """Return module if address falls within it, else None."""
    for m in modules:
        if m.baseaddress <= addr < m.endaddress:
            return m
    return None


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
    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments
    for seg in segs:
        if seg.start_virtual_address <= va < seg.end_virtual_address:
            return seg.start_file_address + (va - seg.start_virtual_address)
    return None


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


def _resolve_size(mf: MinidumpFile, addr: int, requested_size: int | None) -> int:
    """
    If the user didn't specify --size, look up the memory region that contains
    addr and return its actual size (capped at the region boundary).
    Falls back to 0x10000 if the region cannot be found.
    """
    if requested_size is not None:
        return requested_size
    for r in get_memory_regions(mf):
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            actual = r.RegionSize - (addr - r.BaseAddress)
            return actual
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

def _extract_strings_from_data(data: bytes, min_len: int = 6) -> list:
    """\n    Extract ASCII and UTF-16LE strings.\n    Returns list of (offset, enc, string).\n    UTF-16LE covers Windows API names, registry paths, and wide-char C2\n    configs that pure ASCII scans miss entirely.\n    """
    results = []
    pat_ascii = rb'[ -~]{' + str(min_len).encode() + rb',}'
    results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                for m in re.finditer(pat_ascii, data)]
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

def _verdict(dims: dict) -> str:
    score = len(dims)
    if score == 0:
        return GREEN("CLEAN — no suspicious indicators found")
    if score == 1:
        return YELLOW("SUSPICIOUS — 1 independent indicator")
    if score == 2:
        return YELLOW("LIKELY MALICIOUS — 2 independent indicators")
    return RED(f"HIGH CONFIDENCE MALICIOUS — {score} independent indicators")

def _search_string_in_memory(mf: MinidumpFile, needle: str) -> list:
    """\n    Search all committed memory regions for needle (ASCII and UTF-16LE).\n    Returns list of (region, offset, encoding) tuples, one per hit region\n    (deduplicated by region base so we report each region once).\n    """
    regions  = get_memory_regions(mf)
    hits     = []
    seen     = set()
    needle_b = needle.encode("ascii", errors="replace")
    needle_w = needle.encode("utf-16-le")

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.BaseAddress in seen:
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        off_a = data.find(needle_b)
        if off_a != -1:
            hits.append((r, off_a, "ASCII"))
            seen.add(r.BaseAddress)
            continue

        off_w = data.find(needle_w)
        if off_w != -1:
            hits.append((r, off_w, "UTF16"))
            seen.add(r.BaseAddress)

    return hits

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
