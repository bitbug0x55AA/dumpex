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
    (none currently do) can pass a fixed value instead."""
    if label_width is None:
        label_width = max((len(k) for k, _ in pairs), default=0)
    pad = " " * indent
    return [f"{pad}{label:<{label_width}}  {value}" for label, value in pairs]
