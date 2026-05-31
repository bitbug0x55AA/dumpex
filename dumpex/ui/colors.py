"""ANSI colour helpers — auto-disabled when stdout is not a TTY."""
import sys

USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def RED(t):    return _c("91", t)


def GREEN(t):  return _c("92", t)


def YELLOW(t): return _c("93", t)


def CYAN(t):   return _c("96", t)


def BOLD(t):   return _c("1",  t)


def DIM(t):    return _c("2",  t)

