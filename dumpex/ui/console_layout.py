"""Shared, subsystem-agnostic console-formatting primitives: terminal-width
resolution, ANSI-aware text wrapping with hanging indent, and aligned
label/value blocks.

Lived at `dumpex/hunt/_console.py` until `--sysinfo --verbose`'s
environment listing needed the same width policy (issue #41): a recon
command reaching into another subsystem's PRIVATE module would invert the
layering, and this module's own docstring already described it as
hunt-agnostic. `dumpex.hunt._console` remains as a re-export shim, so
every existing hunt import keeps working unchanged.

Kept a leaf module -- it imports nothing from dumpex at all -- so any
package can import it without a cycle.
"""
import re
import shutil
import sys

# The module's public surface, declared explicitly so `dumpex.hunt.
# _console`'s compatibility shim can be checked against it by name rather
# than against dir(), which would also pick up the `re`/`shutil`/`sys`
# imports and demand the shim re-export those too.
__all__ = [
    "MIN_WIDTH", "MAX_WIDTH", "FALLBACK_WIDTH",
    "strip_ansi", "visible_len", "resolve_width", "wrap_text", "render_kv_block",
    "column_width",
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Clamp range for a resolved terminal width -- wide enough that wrapping
# still reads as prose, narrow enough that a very wide terminal doesn't
# stretch a paragraph across the whole screen.
MIN_WIDTH = 80
MAX_WIDTH = 120
# Deterministic width used whenever stdout isn't a real terminal (every
# test run, and any redirected/piped invocation) -- see resolve_width()'s
# own docstring for why this must never depend on the actual environment.
FALLBACK_WIDTH = 100


def strip_ansi(s: str) -> str:
    """Remove ANSI CSI color/style escape sequences from `s`. Used by
    `visible_len()` so color codes never count toward wrap width."""
    return _ANSI_RE.sub("", s)


def visible_len(s: str) -> int:
    """Length of `s` as it will actually occupy on screen -- ANSI escape
    sequences excluded."""
    return len(strip_ansi(s))


def resolve_width(width: "int | None" = None) -> int:
    """The single width-resolution policy every wrapping call in the hunt
    package goes through:

      - an explicit `width` (tests, or a future --width flag) is clamped
        to [MIN_WIDTH, MAX_WIDTH] and used as-is;
      - otherwise, when stdout is a real terminal, the terminal's own
        column count is read and clamped the same way;
      - otherwise (piped/redirected output, and -- critically -- every
        pytest run, since `capsys`/`capfd`-captured stdout is never a
        TTY) a fixed FALLBACK_WIDTH is used, so console golden fixtures
        and wrapping tests are reproducible across machines/CI runners
        regardless of the real terminal they happen to run in.
    """
    if width is not None:
        return max(MIN_WIDTH, min(MAX_WIDTH, width))
    if sys.stdout.isatty():
        cols = shutil.get_terminal_size(fallback=(FALLBACK_WIDTH, 24)).columns
        return max(MIN_WIDTH, min(MAX_WIDTH, cols))
    return FALLBACK_WIDTH


def wrap_text(text: str, width: int, hang_indent: int = 0) -> list:
    """Word-wrap `text` to `width` *visible* columns (ANSI escape
    sequences, if any survive into `text`, never count toward the width
    budget). Returns a list of lines: the first line carries no extra
    indent (a caller that's printing a label prefix on that same line is
    expected to prepend it itself); every line after the first is
    prefixed with `hang_indent` spaces, so continuation lines align under
    wherever the caller's own first-line content started.

    A single word longer than the available width is never split --
    it's placed alone on its own line and allowed to overflow, rather
    than breaking a hash/path/long token mid-character."""
    if not text:
        return []
    avail = max(1, width - hang_indent)
    words = text.split()
    lines = []
    current = []
    current_len = 0
    for word in words:
        wl = visible_len(word)
        added = wl if not current else wl + 1
        if current and current_len + added > avail:
            lines.append(" ".join(current))
            current = [word]
            current_len = wl
        else:
            current.append(word)
            current_len += added
    if current:
        lines.append(" ".join(current))
    pad = " " * hang_indent
    return [lines[0]] + [pad + line for line in lines[1:]]


def render_kv_block(pairs: list, indent: int = 2, label_width: "int | None" = None) -> list:
    """Render an aligned `LABEL  value` block -- one line per `(label,
    value)` pair, labels left-padded to a common column so values line
    up. `label_width` defaults to the longest label in `pairs`; a caller
    with several blocks it wants visually aligned to the SAME column
    (none currently do) can pass a fixed value instead.

    A value may be a plain string, which is emitted verbatim on one line
    however long it is, or a LIST of lines for a row the caller has
    already wrapped: the first goes after the label and the rest are
    padded to the value column, so the whole value reads as one block
    under one label.

    Wrapping stays the CALLER's: it is the caller that knows the width it
    is drawing to, and which of its rows carry text worth breaking rather
    than an identifier that must not be. This function only guarantees
    that lines it is handed stay in the value's own column."""
    if label_width is None:
        label_width = max((len(k) for k, _ in pairs), default=0)
    pad = " " * indent
    lines = []
    for label, value in pairs:
        prefix = f"{pad}{label:<{label_width}}  "
        value_lines = [value] if isinstance(value, str) else (list(value) or [""])
        lines.append(prefix + value_lines[0])
        lines.extend(" " * len(prefix) + line for line in value_lines[1:])
    return lines


def column_width(header: str, cells, *, minimum: int = 0, cap: "int | None" = None) -> int:
    """The width that lets every cell in ONE render of a table sit in its
    own column: the widest value present, floored by the header text and
    by `minimum`, and capped by `cap`.

    Tables built from a fixed per-column width are not aligned, they are
    merely separated. A width in a format spec (`{value:<14}`) is a
    MINIMUM, never a truncation, so a single over-wide cell pushes the
    rest of ITS OWN row right while every other row stays put -- the
    table reads as ragged below its own header, and a column-wise read
    (or `awk`, or a copy-paste into a report) is worthless. Sizing to the
    data instead lines every row up with every other row and with the
    header, without ever dropping a character.

    `cap` is the safety valve for columns fed by dump-derived text, which
    is attacker-controlled: without a ceiling, one 4,000-character name
    would pad EVERY row to 4,000 columns and destroy the table for all
    the other records. A cell wider than `cap` is still printed in full
    -- its own row simply overflows and pushes right, which is the
    ordinary fixed-width behaviour, now confined to the pathological case
    instead of being the normal one.

    Measured with visible_len(), so a cell that already carries ANSI
    styling is sized by what it occupies on screen rather than by its
    escape sequences. Linear in the number of cells, with no state
    carried between renders."""
    widest = max((visible_len(cell) for cell in cells), default=0)
    width = max(minimum, visible_len(header), widest)
    return width if cap is None else min(width, cap)
