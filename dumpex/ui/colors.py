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