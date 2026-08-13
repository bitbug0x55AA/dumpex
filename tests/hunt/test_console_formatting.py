"""Unit tests for dumpex.hunt._console -- the shared width/wrap primitives
every hunter's console rendering reads from. Pure functions, no
hunt-package/FakeMF dependency."""
import re

from dumpex.hunt import _console
from dumpex.ui.colors import RED


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(s: str) -> str:
    return _ANSI_RE.sub("", s)


# ── resolve_width ────────────────────────────────────────────────────────

def test_resolve_width_explicit_value_used_as_is_within_range():
    assert _console.resolve_width(90) == 90


def test_resolve_width_explicit_value_clamped_below_min():
    assert _console.resolve_width(40) == _console.MIN_WIDTH


def test_resolve_width_explicit_value_clamped_above_max():
    assert _console.resolve_width(500) == _console.MAX_WIDTH


def test_resolve_width_non_tty_fallback_is_deterministic(monkeypatch):
    # pytest's captured stdout is never a real TTY, so plain resolve_width()
    # already exercises this path -- pin it explicitly and repeatedly so a
    # future change can't make it environment-dependent.
    monkeypatch.setattr(_console.sys.stdout, "isatty", lambda: False)
    assert _console.resolve_width() == _console.FALLBACK_WIDTH == 100
    assert _console.resolve_width() == _console.resolve_width()


def test_resolve_width_tty_reads_terminal_size_clamped(monkeypatch):
    monkeypatch.setattr(_console.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(_console.shutil, "get_terminal_size",
                         lambda fallback=None: _console.shutil.os.terminal_size((200, 40)))
    assert _console.resolve_width() == _console.MAX_WIDTH

    monkeypatch.setattr(_console.shutil, "get_terminal_size",
                         lambda fallback=None: _console.shutil.os.terminal_size((60, 40)))
    assert _console.resolve_width() == _console.MIN_WIDTH

    monkeypatch.setattr(_console.shutil, "get_terminal_size",
                         lambda fallback=None: _console.shutil.os.terminal_size((100, 40)))
    assert _console.resolve_width() == 100


# ── visible_len / strip_ansi ─────────────────────────────────────────────

def test_visible_len_ignores_ansi_codes():
    # dumpex.ui.colors only emits real escape codes when stdout is a TTY
    # (never true under pytest capture) -- build the escaped form directly
    # so this test doesn't depend on that environment detail.
    colored = "\x1b[91mhello\x1b[0m"
    assert len(colored) != 5
    assert _console.visible_len("hello") == 5
    assert _console.visible_len(colored) == 5


def test_strip_ansi_removes_color_codes():
    assert _console.strip_ansi("\x1b[91mSUSPICIOUS\x1b[0m") == "SUSPICIOUS"


# ── wrap_text ─────────────────────────────────────────────────────────────

def test_wrap_text_empty_string_returns_no_lines():
    assert _console.wrap_text("", 80) == []


def test_wrap_text_short_text_single_line():
    lines = _console.wrap_text("short text", 80)
    assert lines == ["short text"]


def test_wrap_text_respects_width_at_80():
    text = " ".join(f"word{i}" for i in range(30))
    lines = _console.wrap_text(text, 80)
    assert len(lines) > 1
    for line in lines:
        assert _console.visible_len(line) <= 80


def test_wrap_text_respects_width_at_100():
    text = " ".join(f"word{i}" for i in range(30))
    lines = _console.wrap_text(text, 100)
    for line in lines:
        assert _console.visible_len(line) <= 100


def test_wrap_text_respects_width_at_120():
    text = " ".join(f"word{i}" for i in range(30))
    lines = _console.wrap_text(text, 120)
    for line in lines:
        assert _console.visible_len(line) <= 120


def test_wrap_text_hanging_indent_applied_to_continuation_only():
    text = " ".join(f"word{i}" for i in range(30))
    lines = _console.wrap_text(text, 40, hang_indent=6)
    assert not lines[0].startswith(" ")
    for line in lines[1:]:
        assert line.startswith(" " * 6)
        assert not line.startswith(" " * 7) or line[7:8] != " "  # no extra indent drift


def test_wrap_text_reassembles_to_original_words():
    text = "the quick brown fox jumps over the lazy dog many more times today"
    lines = _console.wrap_text(text, 30, hang_indent=4)
    rejoined = " ".join(line.strip() for line in lines)
    assert rejoined.split() == text.split()


def test_wrap_text_does_not_split_long_unsplittable_token():
    long_hash = "a" * 200
    text = f"prefix {long_hash} suffix"
    lines = _console.wrap_text(text, 40, hang_indent=4)
    assert any(long_hash in line for line in lines)
    # the long token itself is never broken mid-character
    joined = "".join(lines)
    assert long_hash in joined


def test_wrap_text_ansi_colored_words_not_counted_beyond_visible_width():
    colored_words = [RED(f"word{i}") for i in range(20)]
    text = " ".join(colored_words)
    lines = _console.wrap_text(text, 40)
    for line in lines:
        assert _console.visible_len(line) <= 40


# ── render_kv_block ───────────────────────────────────────────────────────

def test_render_kv_block_aligns_values_to_common_column():
    pairs = [("A", "1"), ("BB", "2"), ("CCC", "3")]
    lines = _console.render_kv_block(pairs, indent=2)
    expected_col = 2 + max(len(k) for k, _ in pairs) + 2
    for line, (_, value) in zip(lines, pairs):
        assert line[expected_col:] == value
        assert line[:expected_col].endswith("  ")


def test_render_kv_block_uses_indent():
    lines = _console.render_kv_block([("A", "1")], indent=4)
    assert lines[0].startswith("    ")


def test_render_kv_block_explicit_label_width_overrides_longest():
    lines = _console.render_kv_block([("A", "1")], indent=0, label_width=10)
    assert lines[0].startswith("A" + " " * 9 + "  1")
