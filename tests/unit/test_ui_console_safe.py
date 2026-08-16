"""Unit tests for dumpex.ui.colors.console_safe() -- the projection any
renderer applies to text that came out of a dump before writing it to a
terminal.

It lives in dumpex.ui.colors (not in the --handles command that first
needed it) because the exposure is not specific to handle names: module
paths, process paths, and pipe names are all decoded from dump-controlled
bytes too. These tests pin the helper's own contract so another renderer
can adopt it without re-deriving what it does.
"""
import pytest

from dumpex.ui.colors import console_safe


def test_ordinary_text_is_returned_unchanged():
    for text in ("File", "\\Device\\NamedPipe\\mypipe", "C:\\Windows\\System32\\ntdll.dll",
                  "Ключ", "テスト", "emoji \U0001f600", ""):
        assert console_safe(text) == text


@pytest.mark.parametrize("raw,expected", [
    ("a\nb", "a\\x0ab"),        # forges a new output line
    ("a\rb", "a\\x0db"),        # repaints the current line
    ("a\tb", "a\\x09b"),        # shifts the columns of a table row
    ("\x00", "\\x00"),
    ("\x07", "\\x07"),          # BEL
    ("\x1b[2J", "\\x1b[2J"),    # ANSI: clear screen
    ("\x7f", "\\x7f"),          # DEL
    ("\x9b[31m", "\\x9b[31m"),  # C1 CSI -- an ESC-free way to the same place
])
def test_control_characters_become_visible_escapes(raw, expected):
    assert console_safe(raw) == expected


@pytest.mark.parametrize("codepoint", [
    0x200E, 0x200F,                     # LTR/RTL marks
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,   # embeddings and overrides
    0x2066, 0x2067, 0x2068, 0x2069,     # isolates
    0x2028, 0x2029,                      # line/paragraph separators
    0xFEFF,                              # zero-width no-break space
])
def test_bidi_and_separator_formatting_is_escaped(codepoint):
    """These are "printable" by Python's definition but reorder or break
    the line on a real terminal -- the Trojan Source trick, applied to
    evidence: "user\\u202egnp.exe" reads as "userexe.png"."""
    raw = f"a{chr(codepoint)}b"
    assert console_safe(raw) == f"a\\u{codepoint:04x}b"
    assert chr(codepoint) not in console_safe(raw)


def test_nothing_is_dropped():
    """Escaping, never stripping: an analyst must still be able to see
    that something was there, and what."""
    escaped = console_safe("Evil\n  [~] fully parsed")
    assert "Evil" in escaped and "[~] fully parsed" in escaped
    assert "\n" not in escaped


def test_backslashes_are_not_doubled():
    """A deliberate trade: doubling them would make the projection
    reversible, at the cost of rendering every Windows path in the tool
    with doubled separators. --json is where exact bytes are read."""
    assert console_safe("\\Device\\Null") == "\\Device\\Null"


def test_non_string_values_pass_through():
    """Renderers hand this whatever a record field holds; a None or an
    int must not raise on its way to an f-string."""
    assert console_safe(None) is None
    assert console_safe(7) == 7
