"""Bounded, terminal-safe previews of raw evidence bytes.

A preview is a display projection and nothing else: it quotes at most a
fixed number of leading bytes, escapes every character a terminal would
act on, and states how many bytes it left out. The retained evidence is
never altered, no additional read is performed to build one, and the
exact bytes stay available in `--json`.

Two renderings are offered because content decides which one is readable:
text for content an analyst reads as text, hex for content that is not
text at all. Both are deterministic -- the same bytes and the same limit
always produce the same string.
"""
import hashlib

from dumpex.ui.colors import console_safe

# Unit a truncation marker counts in. Bytes is what a preview always cuts
# on; an encoded string whose own length is reported in characters says
# so, so the omitted count and the length beside it read in the same unit.
UNIT_BYTES = "bytes"
UNIT_CHARS = "chars"


def _omitted_marker(total: int, shown: int, unit: str) -> str:
    """"" when the preview carries the whole value -- truncation is
    explicit, and its absence means nothing was left out."""
    omitted = total - shown
    return f"[+{omitted}{unit} omitted]" if omitted else ""


def text_preview(data: bytes, limit: int, unit: str = UNIT_BYTES) -> str:
    r"""`data`'s first `limit` bytes as a quoted, escaped, single-line string.

    Undecodable bytes become a visible `\xNN` (the `backslashreplace`
    decode handler), and every character a terminal acts on -- controls,
    DEL, C1, bidi overrides -- becomes a visible escape via
    `console_safe()`, so decoded content can neither move the cursor,
    colour the output, nor reorder the line around it. A multi-byte
    sequence the limit cuts through renders as those `\xNN` escapes,
    like any other incomplete sequence.
    """
    head = data[:limit]
    body = console_safe(head.decode("utf-8", errors="backslashreplace"))
    return f'"{body}"{_omitted_marker(len(data), len(head), unit)}'


def hex_preview(data: bytes, limit: int) -> str:
    """`data`'s first `limit` bytes as lowercase hex.

    The rendering for content that is not text: hex digits are inert on
    every terminal, so binary content needs no escaping decision at all.
    """
    head = data[:limit]
    return f"{head.hex()}{_omitted_marker(len(data), len(head), UNIT_BYTES)}"


def content_digest(data: bytes) -> str:
    """SHA-256 of the WHOLE value, not of the previewed prefix -- what
    identifies content a bounded preview only partly shows, and what
    lets two hits whose previews look alike be told apart."""
    return hashlib.sha256(data).hexdigest()
