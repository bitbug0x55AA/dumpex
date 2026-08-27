"""Pipe-name canonicalization, regex patterns, and streaming string/match
iterators shared by handle_scan.py, memory_scan.py, and correlation.py.
"""
import re
from dumpex.hunt.pipe.config import _MIN_RUN_LEN

_ASCII_RUN_PAT = re.compile(rb'[ -~]{%d,}' % _MIN_RUN_LEN)
_UTF16_RUN_PAT = re.compile(rb'(?:[ -~]\x00){%d,}' % _MIN_RUN_LEN)

# Handle ObjectName patterns identifying a named-pipe kernel object.
_HANDLE_PIPE_PAT = re.compile(r'\\Device\\NamedPipe\\|\\pipe\\', re.IGNORECASE)

# Pipe name patterns — match pipe names in both ASCII and UTF-16LE. Built
# once at import time (not per-hunt-call): the UTF-16LE pattern is built
# from an encoded literal to avoid null bytes in source, a style choice
# that has nothing to do with WHEN it gets compiled.
PIPE_PAT_ASCII = re.compile(
    rb'(?:\\[?]{0,2}\\pipe\\|\\pipe\\|\\.\\pipe\\)',
    re.IGNORECASE
)
_utf16_pipe = '\\pipe\\'.encode('utf-16-le')
PIPE_PAT_UTF16 = re.compile(re.escape(_utf16_pipe), re.IGNORECASE)

# Known prefix forms a pipe reference can appear under — a kernel handle's
# ObjectName ("\Device\NamedPipe\foo"), a Win32 device-namespace string
# ("\\.\pipe\foo"), an NT-namespace string ("\??\pipe\foo"), or the bare
# ("\pipe\foo") form the byte-pattern scan matches.
#
# "\.\pipe\foo" (single leading backslash) is ALSO listed even though the
# genuine Win32 string is "\\.\pipe\foo" (two leading backslashes): the
# byte-pattern regex's "\\.\\pipe\\" alternative only anchors on ONE
# literal backslash before the "." (its second character class is "any
# byte", which the following literal backslash of the double-backslash
# prefix happens to satisfy) — so PIPE_PAT_ASCII/UTF16 always match
# starting one byte INTO a genuine "\\.\pipe\" string, and every preview
# built from that match (memory_scan._extract_pipe_name) is missing the
# first backslash. Without this second entry, canonicalizing a string-scan
# hit never strips anything for that form and silently fails to line up
# with a handle's full "\Device\NamedPipe\foo" name.
_CANONICAL_PIPE_PREFIXES = (
    "\\device\\namedpipe\\",
    "\\\\.\\pipe\\",
    "\\.\\pipe\\",
    "\\??\\pipe\\",
    "\\pipe\\",
)


def canonical_pipe_name(name: str) -> str:
    """
    Strip any known pipe-namespace prefix and casefold, so the SAME pipe
    referenced via a kernel handle ("\\Device\\NamedPipe\\foo"), a Win32
    string ("\\\\.\\pipe\\foo"), or an NT-namespace string ("\\??\\pipe\\foo")
    all normalize to the identical "foo" for comparison.

    Callers MUST compare two canonical names for EXACT equality, never
    substring containment ("a in b or b in a") — substring containment
    means any pipe name that happens to be a prefix/suffix of another
    (e.g. "lsass" inside "lsass-rpc", or an empty/near-empty canonical
    name after a malformed match) silently links two UNRELATED pipes,
    which previously let a coincidental short-name match manufacture a
    handle+string "corroboration" that was never actually about the same
    pipe.
    """
    n = (name or "").strip().casefold()
    for prefix in _CANONICAL_PIPE_PREFIXES:
        if n.startswith(prefix):
            return n[len(prefix):]
    return n


def is_pipe_handle_object_name(object_name: str) -> bool:
    """True if a handle's ObjectName looks like a named-pipe kernel object."""
    return bool(_HANDLE_PIPE_PAT.search(object_name))


def framework_match(name: str, known_framework_pipes) -> "tuple|None":
    """Return (framework, technique, mitre) for the first known
    C2/lateral-movement framework naming convention `name` matches, or
    None. Shared by handle_scan.py (handle ObjectNames) and correlation.py
    (string-lead pipe names) so both use the identical matching rule."""
    for pat, framework, technique, mitre in known_framework_pipes:
        if pat.search(name):
            return (framework, technique, mitre)
    return None


def _iter_printable_runs(data: bytes):
    """
    Yield (byte_offset, text, is_utf16) for each ASCII and UTF16LE
    printable run in `data` — one pass each via re.finditer, so nothing is
    collected into a persisted list. `text` is only meant for transient use
    by the caller (matching a pattern against it); it is not retained here
    and callers must not retain it either beyond what they actually need
    to keep (see _iter_c2_matches).
    """
    for m in _ASCII_RUN_PAT.finditer(data):
        yield m.start(), m.group().decode('ascii', errors='replace'), False
    for m in _UTF16_RUN_PAT.finditer(data):
        yield m.start(), m.group().decode('utf-16-le', errors='replace'), True


def _iter_c2_matches(data: bytes, pattern, budget, truncated_out: list = None):
    """
    Stream C2_PAT matches against each ASCII/UTF16LE printable run found in
    `data` individually — matching the same string boundaries a human or
    the original _extract_strings_from_data-based scan would see — rather
    than running the pattern against the ENTIRE region decoded as one
    latin-1 blob. Matching against the whole region breaks two things:
    end-anchored patterns like `/ca$` (the `$` then anchors to the
    region's end instead of each individual string's end, so it almost
    never matches) and UTF16LE C2 strings entirely (interleaved NUL bytes
    prevent any match against a pattern written for contiguous ASCII).

    There is deliberately NO fixed "matches examined" ceiling here (issue
    #24's own follow-up): a caller deciding whether a match is proximity-
    relevant (see `is_proximity_match`) has to see every match in the
    region, and a count-based cutoff before that -- at 5, at 200, at any
    fixed N -- silently reintroduces the exact scan-order false negative
    issue #24 reports, just at a different threshold, with nothing in
    `dumpex.hunt.pipe.models.PipeScanCoverage` to show it happened.

    Instead, `budget` (the whole-hunt c2_budget, a
    `dumpex.hunt._budget.ScanBudget`) is polled every 16 examined matches
    — the same convention `dumpex.hunt.encoding.decoding`'s own XOR-key
    brute force uses for its cheap-per-iteration loop — so a scan that
    gets cut short is cut short by the SAME accountable budget that
    already feeds `PipeScanCoverage.c2_budget_exhausted` /
    `c2_budget_reason`, and only by an expired whole-hunt deadline or a
    budget already exhausted from an earlier region — never by a count
    silently reached partway through this one.

    Each run's decoded text is used only transiently for matching here;
    only the short, bounded match token and its BYTE offset within `data`
    are ever yielded — the full run itself (which can be enormous) is
    never retained.

    `truncated_out`, when given, is a one-element list set to `True` iff the
    match stream was cut short by the budget rather than run to its natural
    end -- what a caller needs to decide whether this region's C2 coverage
    is actually incomplete, without reverse-inferring it from a
    lazily-observed budget state after the fact.
    """
    count = 0
    for run_offset, text, is_utf16 in _iter_printable_runs(data):
        if not budget.poll():
            if truncated_out is not None:
                truncated_out[0] = True
            return
        for m in pattern.finditer(text):
            count += 1
            if count % 16 == 0 and not budget.poll():
                if truncated_out is not None:
                    truncated_out[0] = True
                return
            if is_utf16:
                byte_start = run_offset + m.start() * 2
                byte_end   = run_offset + m.end() * 2
            else:
                byte_start = run_offset + m.start()
                byte_end   = run_offset + m.end()
            yield byte_start, byte_end, m.group(0)


def is_proximity_match(start: int, pipe_offsets, context_distance: int) -> bool:
    """
    True if a C2 match's region-relative byte offset `start` is proximity
    evidence — within `context_distance` of AT LEAST ONE offset in
    `pipe_offsets` (that SAME region's own retained pipe-name hit offsets;
    both share `data`'s coordinate space, so no VA resolution is needed
    here). False means context-only evidence.

    A pure predicate rather than a batch "select" function (issue #24's
    original fix used one, which required buffering every examined match
    before retaining any of them — see memory_scan.scan_pipe_names for
    why that buffering was itself a bounded-memory concern for a crafted,
    match-dense region, and why retention is now two independent
    streaming passes over `_iter_c2_matches` instead of one buffered
    pass over this function's output).
    """
    return any(abs(start - po) <= context_distance for po in pipe_offsets)
