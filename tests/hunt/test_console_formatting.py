"""Unit tests for dumpex.hunt._console -- the shared width/wrap/icon
primitives every hunter's console rendering (via _ui.py's _print_check()
and, for injection, its own Finding-tag-keyed KEY SIGNALS section) reads
from. Pure functions, no hunt-package/FakeMF dependency."""
import re

from dumpex.hunt import _console
from dumpex.ui.colors import RED, YELLOW, DIM, GREEN


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


# ── classify_status_icon ──────────────────────────────────────────────────

def test_lead_is_never_green():
    icon = _plain(_console.classify_status_icon("LEAD"))
    assert icon != "[✓]"
    assert icon == "[~]"


def test_observation_and_clean_and_not_evaluated_are_visually_distinct():
    obs = _plain(_console.classify_status_icon("OBSERVATION — not scored"))
    clean = _plain(_console.classify_status_icon("CLEAN — nothing found"))
    not_eval = _plain(_console.classify_status_icon("NOT EVALUATED — no stream"))
    assert len({obs, clean, not_eval}) == 3


def test_detection_is_red():
    assert _plain(_console.classify_status_icon("DETECTION — payload found")) == "[!]"


def test_suspicious_and_anomal_are_red():
    assert _plain(_console.classify_status_icon("SUSPICIOUS")) == "[!]"
    assert _plain(_console.classify_status_icon("ANOMALOUS PROTECTION")) == "[!]"


def test_incomplete_and_context_unverified_are_yellow():
    assert _plain(_console.classify_status_icon("INCOMPLETE — some regions could not be read")) == "[~]"
    assert _plain(_console.classify_status_icon("CONTEXT UNVERIFIED — reason")) == "[~]"


def test_inconclusive_and_notable_are_yellow():
    assert _plain(_console.classify_status_icon("INCONCLUSIVE — reason")) == "[~]"
    assert _plain(_console.classify_status_icon("NOTABLE — region not found")) == "[~]"


def test_not_available_is_dim_dash():
    assert _plain(_console.classify_status_icon("NOT AVAILABLE — no handle data")) == "[-]"


def test_clean_is_green():
    assert _plain(_console.classify_status_icon("CLEAN — none found")) == "[✓]"


def test_unrecognized_status_is_neutral_not_green():
    icon = _plain(_console.classify_status_icon("SOME BRAND NEW STATUS WORD"))
    assert icon == "[?]"
    assert icon != "[✓]"


def test_clean_status_containing_the_word_leads_is_not_misclassified_as_lead():
    # Regression: "LEAD" as a bare substring also matches inside "leads"
    # (the plural noun) -- pipe/presentation.py's own CLEAN status text
    # ("no known framework patterns among string leads") must classify as
    # green, not yellow, despite containing that substring.
    icon = _plain(_console.classify_status_icon(
        "CLEAN — no known framework patterns among string leads"))
    assert icon == "[✓]"


def test_clean_status_containing_lowercase_anomalous_prose_is_not_misclassified_as_red():
    # Regression: obfuscation/presentation.py's own CLEAN status text says
    # "no anomalous entropy in private regions" -- case-INSENSITIVE
    # matching would fold "anomalous" up to match the "ANOMAL" stem
    # (itself a deliberate match for the ALL-CAPS "ANOMALOUS PROTECTION"
    # status hollowing.py emits), wrongly turning a clean result red.
    # Matching stays case-sensitive specifically so lowercase prose never
    # collides with an ALL-CAPS status keyword.
    icon = _plain(_console.classify_status_icon(
        "CLEAN — no anomalous entropy in private regions"))
    assert icon == "[✓]"


def test_word_boundary_matching_does_not_false_positive_on_substrings():
    assert _plain(_console.classify_status_icon("CLEAN — misleading text is fine")) == "[✓]"
    assert _plain(_console.classify_status_icon("CLEAN — the leader module")) == "[✓]"


def test_classification_ignores_pre_applied_ansi_color():
    # A caller typically passes an already-colored string (e.g. YELLOW("LEAD"))
    # -- classification must still match on the plain text underneath.
    assert _plain(_console.classify_status_icon(YELLOW("LEAD"))) == "[~]"
    assert _plain(_console.classify_status_icon(GREEN("CLEAN — ok"))) == "[✓]"
    assert _plain(_console.classify_status_icon(DIM("NOT EVALUATED"))) == "[-]"
