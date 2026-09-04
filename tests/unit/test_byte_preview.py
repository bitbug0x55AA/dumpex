"""Contract of the bounded byte-preview projection.

Previews quote a fixed prefix, state what they left out, and cannot let the
previewed bytes reach the terminal as anything a terminal acts on.
"""
import hashlib

import pytest

from dumpex.ui.byte_preview import (
    UNIT_BYTES, UNIT_CHARS, content_digest, hex_preview, text_preview,
)
from dumpex.ui.colors import _CONSOLE_ESCAPES


# Every codepoint console_safe() rewrites, none excepted: a preview is a
# single-line field inside a larger line, so even a newline is a character
# it must never emit.
HOSTILE_CODEPOINTS = tuple(sorted(_CONSOLE_ESCAPES))


# ── Bounds and truncation ────────────────────────────────────────────────

def test_text_preview_of_a_short_value_is_complete_and_unmarked():
    assert text_preview(b"configurationVersion=1", 96) == '"configurationVersion=1"'


def test_text_preview_at_exactly_the_limit_is_not_marked_as_truncated():
    assert text_preview(b"A" * 16, 16) == '"' + "A" * 16 + '"'


def test_text_preview_states_how_many_bytes_it_left_out():
    assert text_preview(b"A" * 20, 8) == '"AAAAAAAA"[+12bytes omitted]'


def test_text_preview_counts_omitted_content_in_the_unit_it_is_told():
    assert text_preview(b"A" * 20, 8, UNIT_CHARS) == '"AAAAAAAA"[+12chars omitted]'
    assert text_preview(b"A" * 20, 8, UNIT_BYTES) == '"AAAAAAAA"[+12bytes omitted]'


def test_hex_preview_is_lowercase_hex_of_the_leading_bytes():
    assert hex_preview(b"MZ\x90\x00", 4) == "4d5a9000"


def test_hex_preview_states_how_many_bytes_it_left_out():
    assert hex_preview(b"MZ\x90\x00", 2) == "4d5a[+2bytes omitted]"


def test_empty_input_previews_as_an_empty_value_not_as_truncation():
    assert text_preview(b"", 96) == '""'
    assert hex_preview(b"", 32) == ""


# ── Terminal safety ──────────────────────────────────────────────────────

@pytest.mark.parametrize("codepoint", HOSTILE_CODEPOINTS)
def test_no_character_a_terminal_acts_on_survives_a_text_preview(codepoint):
    data = f"start{chr(codepoint)}end".encode("utf-8")
    rendered = text_preview(data, 4096)
    assert chr(codepoint) not in rendered
    assert "start" in rendered and "end" in rendered


def test_ansi_escape_sequences_are_shown_rather_than_executed():
    rendered = text_preview(b"before\x1b[31;1mafter\x1b[0m", 4096)
    assert "\x1b" not in rendered
    assert rendered == '"before\\x1b[31;1mafter\\x1b[0m"'


def test_crlf_tab_and_nul_render_as_visible_escapes():
    assert text_preview(b"a\r\n\tb\x00c", 4096) == '"a\\x0d\\x0a\\x09b\\x00c"'


def test_invalid_utf8_renders_as_a_deterministic_byte_escape():
    rendered = text_preview(b"key=\xff\xfe", 4096)
    assert rendered == '"key=\\xff\\xfe"'
    assert rendered == text_preview(b"key=\xff\xfe", 4096)


def test_a_multibyte_sequence_the_limit_cuts_through_renders_as_byte_escapes():
    # "é" is two bytes: a limit landing between them keeps the byte it did
    # take, as an escape, rather than raising or dropping it.
    assert text_preview("é".encode("utf-8"), 1) == '"\\xc3"[+1bytes omitted]'


def test_valid_non_ascii_text_is_preserved_rather_than_escaped():
    assert text_preview("naïve café".encode("utf-8"), 96) == '"naïve café"'


def test_hex_preview_of_hostile_bytes_emits_only_hex_digits():
    rendered = hex_preview(bytes(range(32)) + b"\x1b[31m", 64)
    assert set(rendered) <= set("0123456789abcdef")


# ── Digest ───────────────────────────────────────────────────────────────

def test_content_digest_covers_the_whole_value_not_the_previewed_prefix():
    data = b"A" * 200
    assert content_digest(data) == hashlib.sha256(data).hexdigest()
    assert content_digest(data) != content_digest(data[:8])
