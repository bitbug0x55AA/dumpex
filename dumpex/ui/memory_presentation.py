"""Console presentation of the `dumpex.core.memory` entry point's
results: the address annotation block, the hexdump context around a hit,
the colored verdict line, and the messages `open_dump()` prints when a
dump cannot be opened.

Every function here formats values it is given; none reads a dump. The
bound entry point `dumpex.core.memory.addr_label` resolves the file
offset through the legacy module's `va_to_file_offset` and passes it in.
"""
from dumpex.core.verdict import (
    VERDICT_CLEAN,
    VERDICT_LIKELY_MALICIOUS,
    VERDICT_SUSPICIOUS,
    verdict_for,
)
from dumpex.ui.colors import DIM, GREEN, RED, YELLOW


def address_label(va: int, file_offset, region_base=None, indent: int = 2) -> str:
    """
    A consistent multi-line annotation for any VA returned by hunt/report,
    given the .dmp file offset that VA maps to (None when the dump did not
    capture it).

      VA (process)   0x<va>          — address in the target process
      File offset    0x<offset>      — byte position inside the .dmp file
      Region base    0x<base>        — start of the enclosing memory region
                                       (omitted when same as va or not given)

    Physical Address (RAM) is not available in minidumps.
    """
    pad = " " * indent
    lines = [f"{pad}{'VA (process)':<16} 0x{va:016x}"]

    if file_offset is not None:
        lines.append(f"{pad}{'File offset (.dmp)':<20} 0x{file_offset:016x}")
    else:
        lines.append(f"{pad}{'File offset (.dmp)':<20} {DIM('(VA not captured in dump)')}")

    if region_base is not None and region_base != va:
        lines.append(f"{pad}{'Region base (VA)':<20} 0x{region_base:016x}")

    return "\n".join(lines)


def _hexdump_context(data: bytes, offset: int, region_base: int,
                     before: int = 128, after: int = 128) -> str:
    """
    Hex+ASCII mixed dump of bytes surrounding offset within data, with the
    row that holds `offset` highlighted.
    Used for context-aware IOC display (e.g. UA string near C2 IP/port).
    """
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


def _verdict(dims: dict) -> str:
    """The colored console line for `verdict_for(dims)`'s tier."""
    tier = verdict_for(dims)
    score = len(dims)
    if tier == VERDICT_CLEAN:
        return GREEN("CLEAN — no suspicious indicators found")
    if tier == VERDICT_SUSPICIOUS:
        return YELLOW("SUSPICIOUS — 1 independent indicator")
    if tier == VERDICT_LIKELY_MALICIOUS:
        return YELLOW("LIKELY MALICIOUS — 2 independent indicators")
    return RED(f"HIGH CONFIDENCE MALICIOUS — {score} independent indicators")


def dump_not_found_lines(path: str) -> tuple:
    """The lines `open_dump()` prints for a dump path that does not exist."""
    return (RED(f"[!] File not found: {path}"),)


def dump_format_error_lines(path: str, cause: BaseException) -> tuple:
    """The lines `open_dump()` prints for a file whose header or directory
    table cannot be read as a minidump; `cause` is the underlying error."""
    return (RED(f"[!] Could not parse {path} as a minidump file: "
                f"{type(cause).__name__}: {cause}"),
            DIM(f"    The file may be corrupted, truncated, or not a Windows "
                f"minidump (.dmp) at all."))
