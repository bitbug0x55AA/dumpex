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

Rendering a command line is refused outright for a dump path no single quoting
rule can carry through POSIX shells, PowerShell, and ``cmd.exe`` alike -- see
:func:`is_renderable_argument`. A command is offered only when copying it runs
the dump it names; otherwise the entry shows the arguments without the path and
the analyst supplies it under their own shell's rules. There is no third option
here: emitting a line that reads correctly but resolves to another file (or
executes a substitution embedded in a filename) is worse than emitting none.
"""
from dataclasses import dataclass

from dumpex.hunt import _registry
from dumpex.hunt._investigation import InvestigationAction, InvestigationActionType
from dumpex.output.records import HUNTERS

__all__ = [
    "PROGRAM_NAME",
    "RescanCommand",
    "UnrenderableArgument",
    "is_renderable_argument",
    "quote_argument",
    "build_rescan_commands",
    "unsupported_rescan_hunters",
]

# The console renders the installed entry point's own name, never `python -m
# dumpex` or an absolute interpreter path: an analyst copies one line, and the
# line has to be the one the packaged tool answers to.
PROGRAM_NAME = "dumpex"

# Characters an unquoted token carries through all three shells unchanged.
# Deliberately minimal, and notably WITHOUT the backslash: a POSIX shell reads
# an unquoted `\` as an escape, so bare `C:\a\b.dmp` arrives as `C:ab.dmp`.
# `%` is expanded by cmd.exe, and `@` and `,` are PowerShell operators in
# leading position. Everything outside this set goes inside double quotes,
# which is where essentially every Windows path lands. A leading `-` needs no
# special handling: quoting does not stop dumpex's own argument parser reading
# a token as a flag, so it would buy nothing here.
_BARE_ARGUMENT_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    ":./_-"
)

# Characters double quotes do NOT neutralize in at least one of the three
# shells, so a token holding one cannot be rendered at all:
#
#   %   cmd.exe expands %VAR% inside double quotes.
#   $   POSIX shells and PowerShell both expand $VAR inside double quotes, and
#       POSIX additionally runs $(...) command substitution there.
#   `   PowerShell's escape character, and POSIX command substitution.
#   "   ends the quoted run; the escape differs per shell (POSIX and cmd.exe
#       take a backslash, PowerShell a backtick or a doubled quote), so no
#       single spelling is correct everywhere.
#   !   cmd.exe expands !VAR! inside double quotes under delayed expansion.
#
# This is a fixed, closed set: widening it means finding a spelling all three
# shells read identically, not deciding one shell matters less.
_UNQUOTABLE_ARGUMENT_CHARS = frozenset("%$`\"!")

# Inside double quotes a POSIX shell still treats a backslash as an escape when
# the next character is one of `$`, a backtick, `"`, `\`, or a newline. The
# first three and the newline are already refused outright above, which leaves
# the doubled backslash: `"\\srv\share"` reaches the program as `\srv\share`.
# That is exactly a UNC path, so a UNC dump path gets the arguments-only
# presentation rather than a command line naming a different location.
_POSIX_QUOTED_ESCAPE = "\\\\"


class UnrenderableArgument(ValueError):
    """`quote_argument()` was handed a value no shell-independent quoting can
    carry. Raised rather than returning a best effort: a caller must choose to
    show something other than a command line, never emit one that resolves
    somewhere else."""

    def __init__(self, value):
        self.value = value
        super().__init__(
            "no single quoting rule carries this value through POSIX shells, "
            "PowerShell, and cmd.exe alike")


def is_renderable_argument(value: str) -> bool:
    """Whether `value` can appear in a command line that means the same thing in
    a POSIX shell, PowerShell, and `cmd.exe`.

    False for a value carrying any of `_UNQUOTABLE_ARGUMENT_CHARS`; for one
    ending in a backslash, which would escape the closing quote in a POSIX
    shell; for one containing a doubled backslash (`_POSIX_QUOTED_ESCAPE`),
    which a POSIX shell collapses to one inside double quotes; for a control
    character, since the only way to print one safely is to replace it, and a
    command naming an altered path is a command naming a different file; and
    for the empty string, which is not a path.

    Windows filenames cannot contain `"`, and none of `%`, `$`, a backtick, or
    `!` appears in an ordinary case path, so this refuses almost nothing real
    beyond UNC paths -- and refuses exactly the paths a naively quoted command
    line would resolve somewhere else, or would execute.
    """
    if not isinstance(value, str) or not value:
        return False
    if value.endswith("\\") or _POSIX_QUOTED_ESCAPE in value:
        return False
    return not any(
        ch in _UNQUOTABLE_ARGUMENT_CHARS or ch < " " or ch == "\x7f" for ch in value)


def quote_argument(value: str) -> str:
    """`value` as one command-line token, bare when every character survives
    unquoted and double-quoted otherwise.

    Double quotes rather than POSIX single quotes because the same line has to
    survive `cmd.exe` and PowerShell, where single quotes are either not quote
    characters at all or do not accept the escape POSIX expects, and because a
    Windows path's own backslashes stay literal inside double quotes in all
    three. Within what `is_renderable_argument()` admits, no escaping is needed
    at all: everything double quotes fail to neutralize in any one of the three
    shells is refused instead.

    Raises `UnrenderableArgument` for anything else.
    """
    if not is_renderable_argument(value):
        raise UnrenderableArgument(value)
    if all(ch in _BARE_ARGUMENT_CHARS for ch in value):
        return value
    return '"' + value + '"'


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
        """The invocation as separate arguments, before any quoting. Always
        available, whatever the dump path holds -- this is the structured form,
        and it is what a caller falls back to describing when the path cannot
        appear in a command line."""
        return (PROGRAM_NAME, self.dump_path, "--hunt", self.hunter,
                "--hunt-addr", f"0x{self.base_address:x}", "--size", f"0x{self.size:x}")

    @property
    def renderable(self) -> bool:
        """Whether `render()` can produce a line that runs this dump in a POSIX
        shell, PowerShell, and `cmd.exe` alike. Only the dump path can fail:
        the program name, the hunter, and two hex numbers are bare-safe by
        construction."""
        return is_renderable_argument(self.dump_path)

    def render(self) -> str:
        """The command as one copyable line, identical in meaning in all three
        shells. Raises `UnrenderableArgument` when the dump path cannot appear
        in one -- check `renderable` first and show `render_arguments()`
        instead."""
        return " ".join(quote_argument(arg) for arg in self.argv)

    def render_arguments(self) -> str:
        """Everything but the program name and the dump path: what to run once
        the analyst has quoted the path for their own shell. Always available,
        since none of these tokens can fail to render."""
        return " ".join(quote_argument(arg) for arg in self.argv[2:])


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
