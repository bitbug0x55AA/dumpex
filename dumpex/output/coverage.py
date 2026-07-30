"""
First-class coverage/provenance model, extracted from the ad hoc
bool(mf.X)-check-plus-hand-written-reason-string pattern every recon
command previously hand-rolled independently (see dumpex/commands/
list_cmd.py, modules.py, threads.py, sysinfo.py, peb.py -- the last three
still use that older pattern; this module is validated on list/modules
first before they migrate).

Layered as: SourceObservation (what state was ONE underlying minidump
stream in) -> CoverageLimitation (one specific, machine-readable way
coverage fell short, with human text rendered from its code -- never a
hand-written string at the call site) -> CoverageReport (the reduction of
all of a command's sources + limitations into one status) -> a single
exit_code_for() mapping, so "which status becomes which process exit
code" is defined exactly once.

This is also the neutral vocabulary home for EXECUTION_* (execution
status: completed/partial/failed, independent of coverage status) --
dumpex.output.envelope imports it from here, not the reverse, and this
module imports nothing from dumpex.output.envelope or dumpex.hunt.*: the
dependency direction is command/domain model -> output adapter ->
envelope/serializer, never backwards. It happens to share its three
coverage-status strings with dumpex.hunt._coverage by design (detection
findings and recon coverage should read the same way), but does not
import from it.

Enum classes below are `str, Enum` (not `enum.StrEnum`, 3.11+ only) so a
member is interchangeable with the plain string constants kept alongside
for import-compatible call sites (`SOURCE_ABSENT == "absent"` is True
either way, and `from ... import SOURCE_ABSENT` still works). Only the
small closed sets this module's own logic branches on -- source state,
coverage status, execution status, limitation code -- are validated at
construction time; `source`/`SourceObservation.name` stay open string
vocabularies since new minidump streams can be added without touching
this module.
"""
from dataclasses import dataclass, field
from enum import Enum

# ── Execution status (independent axis from coverage status: a command
# can finish, execution_status=EXECUTION_COMPLETED, while still
# reporting incomplete evidence, coverage.status=COVERAGE_PARTIAL) ──────


class ExecutionStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL   = "partial"
    FAILED    = "failed"


EXECUTION_COMPLETED = ExecutionStatus.COMPLETED
EXECUTION_PARTIAL   = ExecutionStatus.PARTIAL
EXECUTION_FAILED    = ExecutionStatus.FAILED

# ── Source state ──────────────────────────────────────────────────────────


class SourceState(str, Enum):
    ABSENT        = "absent"          # the stream is not present in the dump at all
    PRESENT_EMPTY = "present_empty"   # stream present, reports zero items
    PRESENT       = "present"         # stream present, reports >=1 items
    FAILED        = "failed"          # stream present but reading/parsing it raised


SOURCE_ABSENT        = SourceState.ABSENT
SOURCE_PRESENT_EMPTY = SourceState.PRESENT_EMPTY
SOURCE_PRESENT       = SourceState.PRESENT
SOURCE_FAILED        = SourceState.FAILED


@dataclass(frozen=True)
class SourceObservation:
    """The state of ONE underlying minidump stream ("source"), as
    observed during a single collect_*() call. `record_count`'s legal
    range is tied to `state` and enforced in __post_init__ -- None for
    ABSENT/FAILED, 0 for PRESENT_EMPTY, >0 for PRESENT -- so a caller
    can't construct a self-contradictory observation (e.g.
    state=PRESENT, record_count=0)."""
    name: str
    state: SourceState
    record_count: "int | None" = None
    detail: "str | None" = None   # error text, meaningful only when state == FAILED

    def __post_init__(self):
        state = SourceState(self.state)
        object.__setattr__(self, "state", state)

        if state in (SourceState.ABSENT, SourceState.FAILED):
            if self.record_count is not None:
                raise ValueError(
                    f"SourceObservation {self.name!r}: record_count must be None "
                    f"for state={state.value!r}, got {self.record_count!r}")
        elif state == SourceState.PRESENT_EMPTY:
            if self.record_count != 0:
                raise ValueError(
                    f"SourceObservation {self.name!r}: record_count must be 0 "
                    f"for state=present_empty, got {self.record_count!r}")
        elif state == SourceState.PRESENT:
            if not self.record_count or self.record_count <= 0:
                raise ValueError(
                    f"SourceObservation {self.name!r}: record_count must be > 0 "
                    f"for state=present, got {self.record_count!r}")


def observe_source(name: str, *, present: bool, items: list = None) -> SourceObservation:
    """The absent/present_empty/present inference every command
    currently hand-rolls via `bool(mf.X)` plus `len(items)`. Does not
    cover SOURCE_FAILED -- a command whose source access can genuinely
    raise should catch that itself and construct the SourceObservation
    directly (there is no generic way to know what "read failed" means
    for an arbitrary source without knowing its own exception surface)."""
    if not present:
        return SourceObservation(name=name, state=SourceState.ABSENT, record_count=None)
    items = items or []
    if not items:
        return SourceObservation(name=name, state=SourceState.PRESENT_EMPTY, record_count=0)
    return SourceObservation(name=name, state=SourceState.PRESENT, record_count=len(items))


# ── Coverage limitations ────────────────────────────────────────────────


class LimitationCode(str, Enum):
    SOURCE_ABSENT       = "SOURCE_ABSENT"
    SOURCE_FAILED       = "SOURCE_FAILED"
    SOURCE_KEY_MISMATCH = "SOURCE_KEY_MISMATCH"   # e.g. two sources describing the
                                                    # same entities disagree on which
                                                    # keys (TIDs, names, ...) exist


LIMITATION_SOURCE_ABSENT       = LimitationCode.SOURCE_ABSENT
LIMITATION_SOURCE_FAILED       = LimitationCode.SOURCE_FAILED
LIMITATION_SOURCE_KEY_MISMATCH = LimitationCode.SOURCE_KEY_MISMATCH


@dataclass(frozen=True)
class CoverageLimitation:
    """One specific, machine-readable way coverage fell short. `scope`
    names the granularity affected (e.g. "dump", "thread", "module");
    `affected_count`/`unavailable_fields` are optional detail a renderer
    or a future JSON `limitations` array can use. Human text is never
    written at the call site -- see render_limitation(). `code` is a
    closed vocabulary (unlike `source`, which stays open) since every
    branch of render_limitation() is hand-written per code; an unrecognized
    code would otherwise silently render as vague fallback text instead of
    failing at construction time."""
    code: LimitationCode
    source: str
    scope: "str | None" = None
    affected_count: "int | None" = None
    unavailable_fields: tuple = field(default_factory=tuple)
    detail: "str | None" = None

    def __post_init__(self):
        object.__setattr__(self, "code", LimitationCode(self.code))
        if not self.source:
            raise ValueError("CoverageLimitation.source must be a non-empty string")
        if not isinstance(self.unavailable_fields, tuple):
            object.__setattr__(self, "unavailable_fields", tuple(self.unavailable_fields))


# Human names for known sources, used only by render_limitation() below.
# Kept separate from the bare source key (e.g. "memory_info") so the
# rendered text stays exactly what analysts/consumers already see in
# existing JSON output ("MemoryInfoListStream", not "memory_info").
_SOURCE_DISPLAY_NAMES = {
    "memory_info": "MemoryInfoListStream",
    "modules":     "ModuleListStream",
    "threads":     "ThreadListStream",
    "thread_info": "ThreadInfoListStream",
    "misc_info":   "MiscInfo stream",
    "exception":   "Exception stream",
    "peb":         "PEB",
}


def _display_name(source: str) -> str:
    return _SOURCE_DISPLAY_NAMES.get(source, source)


def render_limitation(limitation: CoverageLimitation) -> str:
    """The ONE place a CoverageLimitation becomes human text. Must
    reproduce today's exact, already-shipped strings for the sources
    already migrated onto this model (memory_info/modules) so JSON
    output is unchanged; new sources/codes can extend this as they're
    migrated without touching any call site that already relies on it."""
    name = _display_name(limitation.source)
    code = limitation.code

    if code == LimitationCode.SOURCE_ABSENT:
        return f"{name} not present in this dump"

    if code == LimitationCode.SOURCE_FAILED:
        detail = f": {limitation.detail}" if limitation.detail else ""
        return f"{name} present but could not be read{detail}"

    if code == LimitationCode.SOURCE_KEY_MISMATCH:
        count = limitation.affected_count if limitation.affected_count is not None else "some"
        fields = (f" ({', '.join(limitation.unavailable_fields)} unavailable for those)"
                   if limitation.unavailable_fields else "")
        scope = limitation.scope or "item"
        return f"{count} {scope}(s) missing from {name}{fields}"

    raise AssertionError(f"unhandled limitation code: {code!r}")   # unreachable: LimitationCode is closed


# ── Coverage report ──────────────────────────────────────────────────────


class CoverageStatus(str, Enum):
    COMPLETE      = "complete"
    PARTIAL       = "partial"
    NOT_EVALUATED = "not_evaluated"


COVERAGE_COMPLETE      = CoverageStatus.COMPLETE
COVERAGE_PARTIAL       = CoverageStatus.PARTIAL
COVERAGE_NOT_EVALUATED = CoverageStatus.NOT_EVALUATED


@dataclass
class CoverageReport:
    status: str
    sources: dict = field(default_factory=dict)       # {name: SourceObservation}
    limitations: list = field(default_factory=list)   # list[CoverageLimitation]

    @property
    def reasons(self) -> list:
        """Backward-compatible flat text list -- exactly today's v2 JSON
        `coverage.reasons` array, rendered from limitations. This is what
        lets the wire format stay byte-identical while limitations become
        the real, structured source of truth internally."""
        return [render_limitation(l) for l in self.limitations]


def _derive_required_source_limitation(source: SourceObservation) -> "CoverageLimitation | None":
    if source.state == SourceState.ABSENT:
        return CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source=source.name, scope="dump")
    if source.state == SourceState.FAILED:
        return CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source=source.name,
                                   scope="dump", detail=source.detail)
    return None


def build_coverage_report(
    sources: dict,
    *,
    evaluation_sources: "set | None" = None,
    completeness_required_sources: "set | None" = None,
    extra_limitations: "list | None" = None,
) -> CoverageReport:
    """
    The single reduction rule every command's coverage status derives
    from. Unlike the prior version of this function, it does NOT trust a
    caller-supplied `limitations` list for required-source absence/
    failure -- it derives those limitations itself from `sources`, so a
    caller that forgets to keep a hand-built limitations list in sync
    with its own SourceObservations can no longer produce a silent,
    false "complete" result (the exact bug this replaces: `modules`
    observed as SOURCE_FAILED with no limitation passed in used to
    reduce to COVERAGE_COMPLETE).

      - `evaluation_sources`: if given and non-empty, and EVERY one of
        those sources is SOURCE_ABSENT, the command had literally
        nothing to evaluate: not_evaluated, regardless of any other
        limitation. (list/modules: {"memory_info"}. threads: {"threads",
        "thread_info"}. sysinfo: set() -- never not_evaluated, because
        dump_file is always real regardless of which of its 5 sources
        exist. pid: its 3 sources, same all-absent rule as threads.)

      - `completeness_required_sources`: for each of these whose
        observed state is SOURCE_ABSENT or SOURCE_FAILED, a
        CoverageLimitation is derived automatically here
        (LIMITATION_SOURCE_ABSENT / LIMITATION_SOURCE_FAILED) and folded
        into the report. Callers must NOT hand-construct these two
        limitation kinds themselves -- that would recreate the two-
        sources-of-truth bug this split exists to remove. Usually equal
        to `evaluation_sources`, but they answer different questions:
        evaluation_sources gates "was there anything to look at" (only
        matters when ALL are absent); completeness_required_sources
        gates "is what we found the full picture" (any ONE missing/
        failed already contributes a limitation).

      - `extra_limitations`: caller-supplied limitations for anything
        the reducer cannot infer from source states alone (e.g.
        LIMITATION_SOURCE_KEY_MISMATCH across two present sources that
        disagree on which entities exist) -- the only limitation kind a
        caller is still responsible for constructing directly.

    Status: evaluation_sources (if non-empty) all SOURCE_ABSENT ->
    not_evaluated. Else: any limitation (derived or extra) -> partial.
    Else -> complete. A required source that's SOURCE_FAILED (not
    ABSENT) never triggers not_evaluated by itself -- evaluation was
    attempted and hit an error, which is partial territory, not never
    evaluated.
    """
    evaluation_sources = evaluation_sources or set()
    completeness_required_sources = completeness_required_sources or set()
    extra_limitations = list(extra_limitations) if extra_limitations else []

    derived = []
    for name in completeness_required_sources:
        limitation = _derive_required_source_limitation(sources[name])
        if limitation is not None:
            derived.append(limitation)

    limitations = derived + extra_limitations

    if evaluation_sources and all(
        sources[name].state == SourceState.ABSENT for name in evaluation_sources
    ):
        status = CoverageStatus.NOT_EVALUATED
    elif limitations:
        status = CoverageStatus.PARTIAL
    else:
        status = CoverageStatus.COMPLETE

    return CoverageReport(status=status, sources=sources, limitations=limitations)


# ── Exit codes ───────────────────────────────────────────────────────────

EXIT_OK            = 0
EXIT_PARTIAL       = 3
EXIT_NOT_EVALUATED = 4


def exit_code_for(status: str) -> int:
    """The ONE place a coverage status becomes a process exit code.
    Raises on any status outside the closed vocabulary -- a coverage
    status the mapping doesn't know about is a bug to surface immediately,
    not something to silently default to success."""
    try:
        status = CoverageStatus(status)
    except ValueError:
        raise ValueError(f"unknown coverage status: {status!r}") from None
    if status == CoverageStatus.COMPLETE:
        return EXIT_OK
    if status == CoverageStatus.PARTIAL:
        return EXIT_PARTIAL
    return EXIT_NOT_EVALUATED
