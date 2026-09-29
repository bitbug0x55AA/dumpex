"""The captured-memory segment table: Memory64List-over-MemoryList
precedence, the per-dump address-ordered index, VA-to-file-offset mapping
and captured-range accounting.

Mapping and accounting take the segment-table lookup as an argument; the
bound entry points `dumpex.core.memory.va_to_file_offset`,
`va_range_captured_bytes` and `get_memory_segments` pass the legacy
module's `_memory_segments`.
"""
import bisect

from minidump.minidumpfile import MinidumpFile


def _memory_segments(mf: MinidumpFile) -> list:
    """The dump's own memory segment table (Memory64List preferred, falling
    back to the older MemoryList) -- the ONE place that preference order is
    decided, shared by va_to_file_offset() and va_range_captured_bytes()
    (through segment_file_offset() and captured_range_length() below) so
    the two can never resolve a VA against two different segment lists."""
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        return mf.memory_segments_64.memory_segments
    if mf.memory_segments and mf.memory_segments.memory_segments:
        return mf.memory_segments.memory_segments
    return []


def segment_file_offset(mf: MinidumpFile, va: int, *, segment_table):
    """
    Translate a Virtual Address (in the target process) to its byte offset
    inside the .dmp file, using the memory segment table
    `segment_table(mf)` returns (dumpex.core.memory.va_to_file_offset
    passes _memory_segments). The table is not consulted for a falsy `va`.

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
    for seg in segment_table(mf):
        if seg.start_virtual_address <= va < seg.end_virtual_address:
            return seg.start_file_address + (va - seg.start_virtual_address)
    return None


def _segments_by_va(mf: MinidumpFile, segment_table) -> tuple:
    """`(segments_in_ascending_VA_order, running_max_end_address)` over
    the list `segment_table(mf)` returns, resolved once per dump and
    memoized on `mf` itself.

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
    raw = segment_table(mf)
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


def captured_range_length(mf: MinidumpFile, va: int, size: int, *, segment_table) -> int:
    """How many of the `size` bytes starting at `va` are actually present
    in the .dmp file, per the dump's own segment table -- a STRUCTURAL
    fact about what the dump captured, independent of whether any hunt's
    own live-memory read attempt at that address succeeded or failed.

    The table is the list `segment_table(mf)` returns
    (dumpex.core.memory.va_range_captured_bytes passes _memory_segments);
    it is not consulted for a non-positive `size` or a falsy `va`.

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
    segments, max_ends = _segments_by_va(mf, segment_table)
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
