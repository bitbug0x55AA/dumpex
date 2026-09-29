"""Reads of captured process memory: the checked single-segment read,
the clamped reader that never raises, and the spanning read across
contiguous segments. Each reads through the `MinidumpBufferedReader` that
`mf.get_reader().get_buffered_reader()` builds; the one-shot clamped read
is `dumpex.core.memory.read_region_clamped`.
"""
from minidump.minidumpfile import MinidumpFile


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
