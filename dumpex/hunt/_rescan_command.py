"""Synthesis of the ``--hunt-addr`` command an eligible investigation action
tells the analyst to run next.

A synthesized command is console presentation only. ``--json`` carries the
structured facts a rescan is built from -- the target's own ``base_address`` and
``size``, and the ``targeted_hunter_rescan`` action's own ``hunters`` -- and
never a command string: quoting belongs to whichever shell reads the line, not
to a result document, so a consumer that needs to run one builds it from those
fields under its own quoting rules.

Capability and each analyzer's request ceiling are the analyzer registry's
answer (``dumpex.hunt._registry.REGISTRY``); this module keeps no hunter table
of its own. A hunter with no targeted capability is named as unsupported rather
than given a command it could not run, and a target whose bytes this dump never
captured gets no command at all -- its ``targeted_hunter_rescan`` action is
absent, and recollection is the recommendation that remains.

A target larger than the ceiling of the hunter that skipped it gets one capped
command covering the first ceiling-sized piece of the range. That command is
supplementary: it closes nothing beyond the piece it names, repeating it over
later pieces does not close the original gap, and the queue entry's
``coverage_effect`` stays unresolved either way.
"""
from dataclasses import dataclass

from dumpex.hunt import _registry
from dumpex.hunt._investigation import InvestigationAction, InvestigationActionType
from dumpex.output.records import HUNTERS
from dumpex.ui.colors import console_safe

__all__ = [
    "PROGRAM_NAME",
    "RescanCommand",
    "quote_argument",
    "build_rescan_commands",
    "unsupported_rescan_hunters",
]

# The console renders the installed entry point's own name, never `python -m
# dumpex` or an absolute interpreter path: an analyst copies one line, and the
# line has to be the one the packaged tool answers to.
PROGRAM_NAME = "dumpex"

# Characters that survive an unquoted argument identically in POSIX shells,
# PowerShell, and cmd.exe. A path built only from these is rendered bare;
# anything else -- a space above all -- takes double quotes.
_SAFE_ARGUMENT_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "@%+=:,./_-\\"
)


def quote_argument(value: str) -> str:
    """`value` as one shell argument: bare when every character is safe
    unquoted, double-quoted otherwise, with any embedded `"` backslash-escaped.

    Double quotes rather than POSIX single quotes because the same line has to
    survive `cmd.exe` and PowerShell, where single quotes are either not quote
    characters at all or do not accept the escape POSIX expects, and because a
    Windows dump path's own backslashes stay literal inside double quotes in
    all three. A path holding a metacharacter double quotes do not neutralize
    (`$` in POSIX shells, a backtick in PowerShell) is still rendered
    faithfully: the analyst reads back the path they passed, and re-quotes it
    for their own shell if it needs it.

    Control characters are stripped by `console_safe` before quoting -- a dump
    path is argv text rather than dump content, but nothing this function
    returns is allowed to move a terminal cursor.
    """
    text = console_safe(value)
    if not text:
        return '""'
    if all(ch in _SAFE_ARGUMENT_CHARS for ch in text):
        return text
    return '"' + text.replace('"', '\\"') + '"'


def _request_ceiling(hunter: str) -> int:
    """The registry's own frozen request ceiling for `hunter` -- the largest
    single range its targeted executor accepts."""
    return _registry.REGISTRY.get(hunter).targeted_capability.request_ceiling


@dataclass(frozen=True)
class RescanCommand:
    """One copyable `--hunt-addr` invocation for one hunter and one skipped
    target. `size` is what the command asks for and `target_size` is the whole
    skipped target: the two differ exactly when the target is larger than the
    hunter's request ceiling, which is what `capped` reports."""
    hunter: str
    dump_path: str
    base_address: int
    size: int
    target_size: int

    def __post_init__(self):
        if self.hunter not in HUNTERS:
            raise ValueError(f"RescanCommand.hunter must be in {HUNTERS}, got {self.hunter!r}")
        if not isinstance(self.dump_path, str) or not self.dump_path:
            raise ValueError(f"RescanCommand.dump_path must be a non-empty str, "
                             f"got {self.dump_path!r}")
        for name in ("base_address", "size", "target_size"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"RescanCommand.{name} must be a non-negative int, "
                                 f"got {value!r}")
        if self.size <= 0:
            raise ValueError(f"RescanCommand.size must be positive, got {self.size!r}")
        if self.size > self.target_size:
            raise ValueError(
                f"RescanCommand.size {self.size!r} exceeds target_size {self.target_size!r} -- "
                f"a rescan command never asks for more than the skipped target it came from")

    @property
    def capped(self) -> bool:
        """True when the command covers only the leading `size` bytes of a
        target too large for this hunter's request ceiling."""
        return self.size != self.target_size

    @property
    def source(self) -> str:
        """The one coverage source this invocation evaluates -- part of the
        `hunter + source + scope + base_address + size` key a new result is
        matched back to its originating relationship by."""
        return _registry.REGISTRY.targeted_source(self.hunter)

    @property
    def argv(self) -> tuple:
        """The invocation as separate arguments, before any quoting."""
        return (PROGRAM_NAME, self.dump_path, "--hunt", self.hunter,
                "--hunt-addr", f"0x{self.base_address:x}", "--size", f"0x{self.size:x}")

    def render(self) -> str:
        """The command as one copyable line."""
        return " ".join(quote_argument(arg) for arg in self.argv)


def build_rescan_commands(action: InvestigationAction, dump_path: str) -> tuple:
    """One `RescanCommand` per hunter the action's own `targeted_hunter_rescan`
    recommendation names, in that recommendation's order, or `()` when the
    action carries no such recommendation.

    Deduplication and capability filtering already happened in
    `build_investigation_queue()`: a target skipped by pipe's `pipe_name` and
    `c2_context` relationships at once names `pipe` once, so it gets exactly one
    pipe command, and a target with no captured bytes carries no rescan
    recommendation and so gets none.
    """
    if type(action) is not InvestigationAction:
        raise TypeError("build_rescan_commands() action must be an InvestigationAction")
    rescan = next((a for a in action.recommended_actions
                   if a.type == InvestigationActionType.TARGETED_HUNTER_RESCAN.value), None)
    if rescan is None:
        return ()
    return tuple(
        RescanCommand(
            hunter=hunter,
            dump_path=dump_path,
            base_address=action.target.base_address,
            size=min(action.target.size, _request_ceiling(hunter)),
            target_size=action.target.size,
        )
        for hunter in rescan.hunters
    )


def unsupported_rescan_hunters(action: InvestigationAction) -> tuple:
    """Every hunter that skipped this target but has no targeted capability, in
    `HUNTERS` order. Named explicitly rather than left out silently: the gap
    those hunters left is real, and no `--hunt-addr` invocation can close it.
    """
    if type(action) is not InvestigationAction:
        raise TypeError("unsupported_rescan_hunters() action must be an InvestigationAction")
    capable = frozenset(_registry.REGISTRY.targeted_identities())
    skipping = {rel.hunter for rel in action.skipped_by}
    return tuple(h for h in HUNTERS if h in skipping and h not in capable)
