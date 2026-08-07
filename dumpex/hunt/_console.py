"""Shared, hunter-agnostic console-formatting primitives: terminal-width
resolution, ANSI-aware text wrapping with hanging indent, aligned
label/value blocks, and the one status-text -> icon/color classification
table `_ui.py`'s `_print_check()` reads from.

Kept a leaf module (no imports from `_finding.py`/`_ui.py`/any hunter
package) so every other hunt module can import it without a cycle --
`_finding.py` imports `wrap_text`/`resolve_width` for `Finding.print()`'s
wrapping, and `_ui.py` imports `classify_status_icon` for `_print_check()`.
"""
import re
import shutil
import sys

from dumpex.ui.colors import RED, YELLOW, DIM, GREEN

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
    """Remove ANSI CSI color/style escape sequences from `s`. Used both by
    `visible_len()` (so color codes never count toward wrap width) and by
    `classify_status_icon()` (so a status string that's already been
    wrapped in a color function, e.g. `YELLOW("LEAD")`, still matches on
    its plain text)."""
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


# ── Status-text -> icon/color classification ────────────────────────────
# The one place every `_print_check()` call's status word maps to an icon.
# Priority-ordered (first match wins), matched CASE-SENSITIVELY against
# `strip_ansi(status_text)` -- every real call site in this codebase writes
# its status KEYWORD in ALL-CAPS at the start of the string (SUSPICIOUS/
# CLEAN/LEAD/NOTABLE/OBSERVATION/DETECTION/INCOMPLETE/"CONTEXT UNVERIFIED"/
# "NOT AVAILABLE"/"NOT EVALUATED"/INCONCLUSIVE), while the free-text detail
# that follows is ordinary sentence-case prose. Case-FOLDING that
# distinction away (matching case-insensitively) reintroduces a false
# positive this table exists to prevent: "CLEAN — no anomalous entropy in
# private regions" contains the lowercase word "anomalous", which would
# wrongly match the "ANOMAL" stem (itself a deliberate prefix match for
# "ANOMALOUS"/"ANOMALY"/"ANOMALIES") under case-insensitive comparison,
# misreporting a clean status as a red detection. Staying case-sensitive
# both avoids that and keeps this table's own "unknown status -> neutral"
# rule honest: a status word actually written in a different case is
# exactly the kind of thing that SHOULD fall through to "[?]" rather than
# being silently coerced into a match. See this module's own docstring for
# the LEAD/OBSERVATION/INCOMPLETE/CONTEXT UNVERIFIED/NOT AVAILABLE ->
# green-default bug this table closes.
_RED_WORDS       = ("SUSPICIOUS", "ANOMAL", "DETECTION")
_YELLOW_WORDS    = ("LEAD", "NOTABLE", "INCONCLUSIVE", "INCOMPLETE", "CONTEXT UNVERIFIED")
_DIM_INFO_WORDS  = ("OBSERVATION",)
_DIM_DASH_WORDS  = ("NOT AVAILABLE", "NOT EVALUATED")
_GREEN_WORDS     = ("CLEAN",)


# Words matched as a whole word (\b...\b), not a bare substring -- "LEAD"
# as a plain substring also matches inside "Leadership"/"misLEADing" or
# (the real regression this closes) the plural "leads" -- e.g. pipe's own
# "CLEAN — no known framework patterns among string leads" status text,
# which must classify as green, not yellow. Every OTHER word below is
# matched as a bare substring deliberately -- "ANOMAL" in particular is an
# intentional stem prefix (matches "ANOMALOUS"/"ANOMALY"/"ANOMALIES"
# alike, and only within the case-sensitive ALL-CAPS keyword position --
# see this section's own top comment), and none of this table's other
# entries are short/common enough to collide the way "LEAD" does, so
# whole-word matching is opt-in per word rather than the default.
_WHOLE_WORD_ONLY = frozenset({"LEAD"})


def _contains_word(plain: str, word: str) -> bool:
    if word in _WHOLE_WORD_ONLY:
        return re.search(rf"\b{re.escape(word)}\b", plain) is not None
    return word in plain


def classify_status_icon(status_text: str) -> str:
    """Return the fully-colored icon string (e.g. `RED("[!]")`) for a
    `_print_check()`-style status string. Never raises -- an unrecognized
    status text is exactly the case this function exists to make visibly
    neutral rather than silently green."""
    plain = strip_ansi(status_text)
    if any(_contains_word(plain, word) for word in _RED_WORDS):
        return RED("[!]")
    if any(_contains_word(plain, word) for word in _YELLOW_WORDS):
        return YELLOW("[~]")
    if any(_contains_word(plain, word) for word in _DIM_INFO_WORDS):
        return DIM("[i]")
    if any(_contains_word(plain, word) for word in _DIM_DASH_WORDS):
        return DIM("[-]")
    if any(_contains_word(plain, word) for word in _GREEN_WORDS):
        return GREEN("[✓]")
    return DIM("[?]")
