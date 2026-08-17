"""Compatibility re-export of dumpex.ui.console_layout.

These primitives moved to `dumpex/ui/console_layout.py` when `--sysinfo
--verbose` needed the same terminal-width policy (issue #41): they were
never hunt-specific -- this module's own docstring called them
"hunter-agnostic" -- and a recon command importing another subsystem's
private module would invert the package layering.

The names below are re-exported rather than the ten hunt call sites being
rewritten, so this move stays a pure relocation with no behavioural diff
to review. New code should import from `dumpex.ui.console_layout`
directly; nothing here is deprecated for existing callers.
"""
from dumpex.ui.console_layout import (   # noqa: F401
    MIN_WIDTH, MAX_WIDTH, FALLBACK_WIDTH,
    strip_ansi, visible_len, resolve_width, wrap_text, render_kv_block,
)

__all__ = [
    "MIN_WIDTH", "MAX_WIDTH", "FALLBACK_WIDTH",
    "strip_ansi", "visible_len", "resolve_width", "wrap_text", "render_kv_block",
]
