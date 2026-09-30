"""String extraction over captured bytes, IOC string extraction and its
encoding vocabulary, and the committed-memory string search with its
whole-scan telemetry.

The search takes its reader and its per-region read ceiling as
arguments; the bound entry point `dumpex.core.memory._search_string_in_memory`
passes the legacy module's `read_region` and `MAX_REGION_READ`.
"""
import re
from typing import NamedTuple

from minidump.minidumpfile import MinidumpFile

from dumpex.core.dumpquery.lookup import get_memory_regions, prot_str


def _extract_strings_from_data(data: bytes, min_len: int = 6, encoding: str = "both") -> list:
    """
    Extract ASCII and/or UTF-16LE strings.
    Returns list of (offset, enc, string), sorted by offset.
    UTF-16LE covers Windows API names, registry paths, and wide-char C2
    configs that pure ASCII scans miss entirely.

    `encoding` ("ascii" | "unicode" | "both", default "both") selects
    which pattern(s) run: --report always wants both, --strings passes its
    own ASCII/UTF16/both mode.
    """
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


class StringSearchStats(NamedTuple):
    """Whole-scan telemetry a string search can't express through `hits`
    alone: `skipped` is how many committed regions raised on their read
    and were skipped entirely (couldn't read anything at all); `clamped`
    is how many regions were bigger than the per-region read ceiling
    (MAX_REGION_READ), so the scan deliberately asked for less than the
    region's own size -- a self-imposed policy choice, not evidence going
    missing (see dumpex.commands.report.collect_report's own
    execution_status derivation, which treats this the same as a per-card
    MAX_REGION_READ clamp); `truncated` is how many regions came back
    SHORTER than whatever was actually requested (post-clamp) -- the
    reader itself couldn't back that much, a genuine evidence-completeness
    gap independent of `clamped`. A single region can be both `clamped`
    and `truncated` at once (asked for less than its own size, then even
    that reduced request came up short); the two counters are orthogonal,
    not mutually exclusive."""
    skipped: int
    clamped: int
    truncated: int


def search_committed_regions(mf: MinidumpFile, needle: str, *, read, max_read: int) -> tuple:
    """
    Search all committed memory regions for needle (ASCII and UTF-16LE),
    in memory-info order, reading each region with `read(mf, base, size)`
    (dumpex.core.memory._search_string_in_memory passes read_region) for
    at most `max_read` bytes (MAX_REGION_READ). A region whose read raises
    is counted as skipped. The ASCII form is looked for first; the UTF-16LE
    form only when the ASCII form is absent from that region.

    Returns (hits, stats): hits is a list of (region, offset, encoding)
    tuples, one per hit region (deduplicated by region base so each region
    is reported once); stats is a StringSearchStats -- see its own
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
        requested = min(r.RegionSize, max_read)
        if requested < r.RegionSize:
            clamped += 1
        try:
            data = read(mf, r.BaseAddress, requested)
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
