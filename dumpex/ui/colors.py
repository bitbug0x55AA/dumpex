"""ANSI colour helpers — cross-platform via colorama."""
import sys

# Some console codepages (e.g. Windows CP1252, still the default for
# cmd.exe/PowerShell 5.x outside a UTF-8-forced environment) can't encode
# the arrow/box-drawing characters used throughout dumpex's console labels,
# raising UnicodeEncodeError on the very first print. Widen the error
# handling (not the encoding itself, so terminals that DO support these
# characters keep rendering them normally) before colorama wraps the
# stream below, so writes through the wrapper are covered too. PyInstaller
# builds sidestep this by forcing UTF-8 mode (--python-option "X utf8");
# `pip install` / `python -m dumpex` don't get that for free.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except Exception:
            pass

# colorama.init() on Windows translates ANSI escape codes into Win32
# Console API calls, fixing the raw escape output in PowerShell 5.x.
# On Linux/macOS it's a no-op.
try:
    import colorama
    colorama.init(autoreset=False)
except ImportError:
    pass   # graceful degradation — colors may not render on Windows

USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def RED(t):    return _c("91", t)
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def CYAN(t):   return _c("96", t)
def BOLD(t):   return _c("1",  t)
def DIM(t):    return _c("2",  t)


# ── Console safety for untrusted text ────────────────────────────────────
# Anything dumpex reads OUT OF A DUMP is attacker-controlled: a handle's
# TypeName/ObjectName, a module path, an extracted string. Printed raw,
# such a value is not just data on a line -- it is input to the terminal's
# own parser:
#
#   * a newline lets it forge dumpex's own output, e.g. a type name
#     containing "\n  [~] HandleDataStream fully parsed, 0 limitations"
#     prints an extra line indistinguishable from a real coverage reason;
#   * ESC introduces ANSI control sequences -- clear the screen, move the
#     cursor over lines already printed, recolor, or (on some terminals)
#     alter the title bar;
#   * bidirectional overrides (U+202E and friends) visually REORDER the
#     characters around them, so "user<RLO>gnp.exe" reads as "userexe.png"
#     while naming a .exe -- the Trojan Source trick, applied to evidence.
#
# The value itself is never altered: JSON keeps the exact decoded string
# (json.dumps escapes control characters on its own), and this projection
# is applied only where text is written to a terminal.
_CONSOLE_ESCAPES = {
    # C0 controls and DEL, C1 controls: everything a terminal may act on.
    **{c: f"\\x{c:02x}" for c in range(0x20)},
    0x7F: "\\x7f",
    **{c: f"\\x{c:02x}" for c in range(0x80, 0xA0)},
    # Bidi/paragraph formatting: printable by Python's definition, but
    # they reorder or break the surrounding line on a real terminal.
    **{c: f"\\u{c:04x}" for c in (0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF)},
    **{c: f"\\u{c:04x}" for c in range(0x202A, 0x202F)},
    **{c: f"\\u{c:04x}" for c in range(0x2066, 0x206A)},
}


def console_safe(text):
    """Render untrusted text harmless for a terminal, WITHOUT dropping
    evidence: every character a terminal would act on becomes a visible
    `\\xNN`/`\\uNNNN` escape, so the analyst still sees that something was
    there (and what). Ordinary printable text -- including non-ASCII
    names -- is returned unchanged.

    Backslashes are deliberately NOT doubled. Escaping them would make
    this projection strictly reversible, but almost every object name in
    a real dump is a Windows path (`\\Device\\NamedPipe\\mypipe`), and
    rendering all of those with doubled separators costs far more
    readability than the residual ambiguity is worth: a name containing
    the literal text `\\x0a` and one containing a real newline print the
    same. The exact bytes are always available in `--json`, which is the
    right place to disambiguate.

    Apply this to the TEXT, before wrapping it in any colour helper above
    -- colouring first would feed dumpex's own escape codes back through
    the escaper."""
    return text.translate(_CONSOLE_ESCAPES) if isinstance(text, str) else text