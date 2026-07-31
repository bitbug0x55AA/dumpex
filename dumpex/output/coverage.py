"""
First-class coverage/provenance model, extracted from the ad hoc
bool(mf.X)-check-plus-hand-written-reason-string pattern every recon
command previously hand-rolled independently (see dumpex/commands/
list_cmd.py, modules.py, threads.py, peb.py, sysinfo.py -- the last one
holds both --sysinfo and --pid). All six of dumpex's original recon
commands are migrated onto this model.

Layered as: SourceObservation (what state was ONE underlying minidump
stream in) -> CoverageLimitation (one specific, machine-readable way
coverage fell short, with human text rendered from its code -- never a
hand-written string at the call site) -> CoverageReport (the reduction of
all of a command's sources + limitations into one status) -> a single
exit_code_for() mapping, so "which status becomes which process exit
code" is defined exactly once.

The reducer (build_coverage_report) is the single place that turns a
SourceObservation's state into a CoverageLimitation for a source a
command requires for completeness -- a command supplies WHICH sources it
requires (as a plain source name or a SourceRequirement, when it needs a
specific wording variant) via `completeness_checks`, never a hand-built
SOURCE_ABSENT/SOURCE_FAILED CoverageLimitation itself. This is what
prevents the "two sources of truth" bug this module exists to close: a
caller cannot forget to keep a hand-written limitations list in sync with
its own SourceObservations, because the caller never builds that
particular kind of limitation at all -- only the reducer does, reading
the SAME SourceObservation the caller already had to construct. The only
limitation kind a caller still builds directly is SOURCE_KEY_MISMATCH (a
genuine cross-source business-logic fact -- e.g. two streams describing
the same entities disagreeing on which keys exist -- that the reducer
cannot infer from source state alone).

There is deliberately no free-text escape hatch (no "detail string a
command composes itself and the model renders verbatim"): every
CoverageLimitation's text is produced by a specific, hardcoded branch of
render_limitation() selected by its `code`, parametrized only by
structured fields (source names, field-name tuples, counts). A command
whose existing wording doesn't fit an existing code's template gets a
new, purpose-built code and template here, in this module, reviewable
and testable alongside every other one -- never a caller-composed string
smuggled through an opaque field. See threads.py for how a command with
several bespoke reason strings (a field-impact SOURCE_ABSENT variant, a
two-way SOURCE_KEY_MISMATCH, a dedicated MODULE_CLASSIFICATION_UNAVAILABLE
template) is expressed entirely through structured parameters.

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
    SOURCE_GROUP_ABSENT = "SOURCE_GROUP_ABSENT"    # every source in an evaluation
                                                    # group is absent -- see
                                                    # build_coverage_report's
                                                    # not_evaluated branch
    MODULE_CLASSIFICATION_UNAVAILABLE = "MODULE_CLASSIFICATION_UNAVAILABLE"
    # ^ ModuleListStream absent: a specific, fully fixed sentence (not a
    # generic template) about why a start-address-to-module classification
    # can't be attempted. New sources/codes are added here, fully spelled
    # out, as commands migrate and need wording an existing template can't
    # produce -- never passed in as caller-composed free text.
    PEB_UNAVAILABLE = "PEB_UNAVAILABLE"
    # ^ PEB absent: --peb's single-source not_evaluated case, whose
    # existing wording ("PEB could not be parsed (missing sysinfo or
    # thread list in dump)") explains WHY in terms other streams, not
    # just "not present in this dump" -- fully fixed, no interpolation.
    PID_SOURCES_ABSENT = "PID_SOURCES_ABSENT"
    # ^ --pid's 3-source (misc_info/threads/exception) not_evaluated case
    # -- fully fixed sentence, represents the group as a whole (see
    # EvaluationRequirement), not any one member.
    PID_THREAD_LIST_FALLBACK = "PID_THREAD_LIST_FALLBACK"
    # ^ MiscInfo didn't yield a PID; the base thread list is used as a
    # weaker cross-check. source="misc_info" (the preferred source that
    # came up empty), counterpart_source="threads", related_tids carries
    # every TID found -- the renderer does the hex formatting and
    # truncate-to-8-plus-ellipsis, never the caller.
    PID_EXCEPTION_TID_FALLBACK = "PID_EXCEPTION_TID_FALLBACK"
    # ^ Last-resort fallback: the exception stream's faulting TID (a
    # Thread ID, not a Process ID) is surfaced as a hint. source=
    # "exception", thread_id carries the raw TID -- the renderer hex-
    # formats it, never the caller.
    PID_NO_USABLE_FALLBACK = "PID_NO_USABLE_FALLBACK"
    # ^ pid is None, at least one of the three sources exists, but
    # neither fallback above produced anything usable -- fully fixed
    # sentence, no fields.
    SYSINFO_SYSTEM_INFO_UNAVAILABLE = "SYSINFO_SYSTEM_INFO_UNAVAILABLE"
    SYSINFO_MISC_INFO_UNAVAILABLE   = "SYSINFO_MISC_INFO_UNAVAILABLE"
    SYSINFO_PEB_UNAVAILABLE         = "SYSINFO_PEB_UNAVAILABLE"
    SYSINFO_THREADS_UNAVAILABLE     = "SYSINFO_THREADS_UNAVAILABLE"
    SYSINFO_MODULES_UNAVAILABLE     = "SYSINFO_MODULES_UNAVAILABLE"
    # ^ --sysinfo's five independent per-source absence reasons. Each is
    # its own dedicated, fully fixed sentence -- none matches the generic
    # SOURCE_ABSENT template's exact punctuation ("X not present in this
    # dump"), and SYSINFO_PEB_UNAVAILABLE's wording ("PEB not available
    # (requires sysinfo + thread list)") differs from --peb's own
    # PEB_UNAVAILABLE text, so it needs a distinctly-named code rather
    # than reusing that one.


LIMITATION_SOURCE_ABSENT       = LimitationCode.SOURCE_ABSENT
LIMITATION_SOURCE_FAILED       = LimitationCode.SOURCE_FAILED
LIMITATION_SOURCE_KEY_MISMATCH = LimitationCode.SOURCE_KEY_MISMATCH

# PID_SOURCES_ABSENT's rendered sentence names these three sources
# explicitly and only these -- it must never be selected for, or attached
# to, any other source combination (that would render a sentence naming
# streams that aren't actually the ones being described).
_PID_SOURCES_ABSENT_SOURCES = ("misc_info", "threads", "exception")

# Codes whose rendered text is a fully fixed sentence about ONE specific
# source -- construction requires `source` to match exactly, since using
# any of these with a different source would render a sentence describing
# a stream other than the one actually observed. One shared check instead
# of a growing pile of near-identical per-code `if` blocks as more
# commands migrate.
_FIXED_SOURCE_CODES = {
    LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE: "modules",
    LimitationCode.PEB_UNAVAILABLE: "peb",
    LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE: "sysinfo",
    LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE: "misc_info",
    LimitationCode.SYSINFO_PEB_UNAVAILABLE: "peb",
    LimitationCode.SYSINFO_THREADS_UNAVAILABLE: "threads",
    LimitationCode.SYSINFO_MODULES_UNAVAILABLE: "modules",
}


@dataclass(frozen=True)
class CoverageLimitation:
    """One specific, machine-readable way coverage fell short. `scope`
    names the granularity affected (e.g. "dump", "thread", "module").
    `unavailable_fields`/`available_fields` are a SOURCE_ABSENT limitation's
    optional field-level impact (which fields become unavailable, and
    which stay available from another source) -- e.g. threads.py's
    "ThreadInfoListStream not present; StartAddress/.../unavailable
    (TID/.../only)". `counterpart_source` is SOURCE_KEY_MISMATCH's other
    source (the one the affected entities ARE present in).
    `related_sources` is SOURCE_GROUP_ABSENT's full source list, in
    caller-declared order. `related_tids` is PID_THREAD_LIST_FALLBACK's
    full TID list (the renderer truncates/formats it, never the caller).
    `thread_id` is PID_EXCEPTION_TID_FALLBACK's single TID. Human text is
    never written at the call site -- see render_limitation(). `code` is
    a closed vocabulary (unlike `source`, which stays open) since every
    branch of render_limitation() is hand-written per code; an
    unrecognized code would otherwise silently render as vague fallback
    text instead of failing at construction time."""
    code: LimitationCode
    source: str
    scope: "str | None" = None
    affected_count: "int | None" = None
    unavailable_fields: tuple = field(default_factory=tuple)
    available_fields: tuple = field(default_factory=tuple)
    counterpart_source: "str | None" = None
    related_sources: tuple = field(default_factory=tuple)
    related_tids: tuple = field(default_factory=tuple)
    thread_id: "int | None" = None
    detail: "str | None" = None   # SOURCE_FAILED only: the underlying error text

    def __post_init__(self):
        object.__setattr__(self, "code", LimitationCode(self.code))
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("CoverageLimitation.source must be a non-empty string")
        if not isinstance(self.unavailable_fields, tuple):
            object.__setattr__(self, "unavailable_fields", tuple(self.unavailable_fields))
        if not isinstance(self.available_fields, tuple):
            object.__setattr__(self, "available_fields", tuple(self.available_fields))
        if not isinstance(self.related_sources, tuple):
            object.__setattr__(self, "related_sources", tuple(self.related_sources))
        if not isinstance(self.related_tids, tuple):
            object.__setattr__(self, "related_tids", tuple(self.related_tids))
        if self.code == LimitationCode.SOURCE_GROUP_ABSENT and len(self.related_sources) < 2:
            raise ValueError(
                "CoverageLimitation(code=SOURCE_GROUP_ABSENT) requires >= 2 related_sources")
        if self.code in _FIXED_SOURCE_CODES and self.source != _FIXED_SOURCE_CODES[self.code]:
            raise ValueError(
                f"CoverageLimitation(code={self.code.value}) is a fixed sentence -- source must "
                f"be {_FIXED_SOURCE_CODES[self.code]!r}, got {self.source!r}")
        if self.code == LimitationCode.PID_SOURCES_ABSENT:
            if self.related_sources != _PID_SOURCES_ABSENT_SOURCES:
                raise ValueError(
                    "CoverageLimitation(code=PID_SOURCES_ABSENT) is a fixed sentence naming "
                    f"MiscInfo/thread list/exception stream specifically -- related_sources must "
                    f"be {_PID_SOURCES_ABSENT_SOURCES!r}, got {self.related_sources!r}")
            if self.source != _PID_SOURCES_ABSENT_SOURCES[0]:
                raise ValueError(
                    f"CoverageLimitation(code=PID_SOURCES_ABSENT) requires source == "
                    f"{_PID_SOURCES_ABSENT_SOURCES[0]!r} (consistent with related_sources), "
                    f"got {self.source!r}")

        if self.code == LimitationCode.PID_THREAD_LIST_FALLBACK:
            if self.source != "misc_info":
                raise ValueError(
                    "CoverageLimitation(code=PID_THREAD_LIST_FALLBACK) requires source='misc_info', "
                    f"got {self.source!r}")
            if self.counterpart_source != "threads":
                raise ValueError(
                    "CoverageLimitation(code=PID_THREAD_LIST_FALLBACK) requires "
                    f"counterpart_source='threads', got {self.counterpart_source!r}")
            if not self.related_tids or any(
                    not isinstance(t, int) or isinstance(t, bool) or t <= 0 for t in self.related_tids):
                raise ValueError(
                    "CoverageLimitation(code=PID_THREAD_LIST_FALLBACK) requires related_tids to be "
                    f"a non-empty tuple of positive integers, got {self.related_tids!r}")
        elif self.related_tids:
            raise ValueError(
                f"related_tids is only valid for PID_THREAD_LIST_FALLBACK, not {self.code.value}")

        if self.code == LimitationCode.PID_EXCEPTION_TID_FALLBACK:
            if self.source != "exception":
                raise ValueError(
                    "CoverageLimitation(code=PID_EXCEPTION_TID_FALLBACK) requires source='exception', "
                    f"got {self.source!r}")
            if (not isinstance(self.thread_id, int) or isinstance(self.thread_id, bool)
                    or self.thread_id <= 0):
                raise ValueError(
                    "CoverageLimitation(code=PID_EXCEPTION_TID_FALLBACK) requires thread_id to be "
                    f"a positive integer, got {self.thread_id!r}")
        elif self.thread_id is not None:
            raise ValueError(
                f"thread_id is only valid for PID_EXCEPTION_TID_FALLBACK, not {self.code.value}")


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


def _render_present_in_but_missing_from(name: str, limitation: CoverageLimitation) -> str:
    """Shared by SOURCE_ABSENT (when a required source turns out entirely
    absent but a counterpart source's records reveal exactly how many
    entities are affected -- e.g. threads.py's ThreadListStream) and
    SOURCE_KEY_MISMATCH (when both sources are present but their key sets
    partially disagree). Same wording either way: what actually happened
    to the underlying source (fully absent vs. partially mismatched)
    surfaces through `code`, not through different text."""
    count = limitation.affected_count if limitation.affected_count is not None else "some"
    scope = limitation.scope or "item"
    fields = (f" ({'/'.join(limitation.unavailable_fields)} unavailable for those)"
               if limitation.unavailable_fields else "")
    counterpart_name = _display_name(limitation.counterpart_source)
    return f"{count} {scope}(s) present in {counterpart_name} but missing from {name}{fields}"


def render_limitation(limitation: CoverageLimitation) -> str:
    """The ONE place a CoverageLimitation becomes human text. Must
    reproduce today's exact, already-shipped strings for every source
    already migrated onto this model so JSON output is unchanged; new
    sources/codes can extend this as they're migrated without touching
    any call site that already relies on it."""
    name = _display_name(limitation.source)
    code = limitation.code

    if code == LimitationCode.SOURCE_ABSENT:
        if limitation.counterpart_source:
            return _render_present_in_but_missing_from(name, limitation)
        if limitation.unavailable_fields:
            avail = (f" ({'/'.join(limitation.available_fields)} only)"
                      if limitation.available_fields else "")
            return (f"{name} not present; {'/'.join(limitation.unavailable_fields)} "
                    f"unavailable{avail}")
        return f"{name} not present in this dump"

    if code == LimitationCode.SOURCE_FAILED:
        detail = f": {limitation.detail}" if limitation.detail else ""
        return f"{name} present but could not be read{detail}"

    if code == LimitationCode.SOURCE_KEY_MISMATCH:
        if limitation.counterpart_source:
            return _render_present_in_but_missing_from(name, limitation)
        count = limitation.affected_count if limitation.affected_count is not None else "some"
        scope = limitation.scope or "item"
        fields = (f" ({'/'.join(limitation.unavailable_fields)} unavailable for those)"
                   if limitation.unavailable_fields else "")
        return f"{count} {scope}(s) missing from {name}{fields}"

    if code == LimitationCode.SOURCE_GROUP_ABSENT:
        names = [_display_name(s) for s in limitation.related_sources]
        if len(names) == 2:
            return f"Neither {names[0]} nor {names[1]} present in this dump"
        return f"None of {', '.join(names)} present in this dump"

    if code == LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE:
        return (f"{name} not present; thread backing-module classification unavailable "
                f"(cannot confirm whether a start address is backed by a known module)")

    if code == LimitationCode.PEB_UNAVAILABLE:
        return "PEB could not be parsed (missing sysinfo or thread list in dump)"

    if code == LimitationCode.PID_SOURCES_ABSENT:
        return ("MiscInfo, thread list, and exception stream are all absent from this "
                "dump; PID could not be evaluated")

    if code == LimitationCode.PID_THREAD_LIST_FALLBACK:
        tids = limitation.related_tids
        shown = ", ".join(f"0x{t:x}" for t in tids[:8])
        suffix = " …" if len(tids) > 8 else ""
        return (f"MiscInfo stream absent — PID not directly recoverable from thread list.\n"
                f"    {len(tids)} thread(s) found: {shown}{suffix}")

    if code == LimitationCode.PID_EXCEPTION_TID_FALLBACK:
        return (f"Exception stream present: faulting TID = 0x{limitation.thread_id:x} "
                f"(this is a Thread ID, not a Process ID)")

    if code == LimitationCode.PID_NO_USABLE_FALLBACK:
        return ("PID not found in MINIDUMP_MISC_INFO, and no usable cross-check data "
                "was available from the thread list or exception stream")

    if code == LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE:
        return "SystemInfoStream not present"

    if code == LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE:
        return "MiscInfo stream not present"

    if code == LimitationCode.SYSINFO_PEB_UNAVAILABLE:
        return "PEB not available (requires sysinfo + thread list)"

    if code == LimitationCode.SYSINFO_THREADS_UNAVAILABLE:
        return "ThreadListStream not present (thread_count unavailable)"

    if code == LimitationCode.SYSINFO_MODULES_UNAVAILABLE:
        return "ModuleListStream not present (module_count unavailable)"

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

    def __post_init__(self):
        try:
            self.status = CoverageStatus(self.status)
        except ValueError:
            raise ValueError(f"unknown coverage status: {self.status!r}") from None

    @property
    def reasons(self) -> list:
        """Backward-compatible flat text list -- exactly today's v2 JSON
        `coverage.reasons` array, rendered from limitations. This is what
        lets the wire format stay byte-identical while limitations become
        the real, structured source of truth internally."""
        return [render_limitation(l) for l in self.limitations]


# The closed set of codes a SourceRequirement's absent_code may select --
# every one of these means, semantically, "this source turned out to be
# absent" (in some rendering variant). Extend this explicitly, alongside
# a new LimitationCode member, as a future command needs another
# dedicated absence template -- never open it up generically, or a typo'd
# absent_code (e.g. SOURCE_KEY_MISMATCH, which describes a PRESENT
# source's partial mismatch, not an absent one) could render nonsense
# like "some dump(s) missing from ModuleListStream" for a plain absence.
_ABSENT_CAPABLE_CODES = (
    LimitationCode.SOURCE_ABSENT,
    LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE,
    LimitationCode.PEB_UNAVAILABLE,
    LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE,
    LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE,
    LimitationCode.SYSINFO_PEB_UNAVAILABLE,
    LimitationCode.SYSINFO_THREADS_UNAVAILABLE,
    LimitationCode.SYSINFO_MODULES_UNAVAILABLE,
)


@dataclass(frozen=True)
class SourceRequirement:
    """One entry in a command's `completeness_checks`: 'this source is
    required for a complete result.' If its observed state is
    SOURCE_ABSENT/SOURCE_FAILED, build_coverage_report() derives a
    CoverageLimitation from the SourceObservation itself -- the caller
    never builds that limitation by hand, closing the two-sources-of-
    truth gap a bare `if absent: limitations.append(...)` would reopen.

    `absent_code` lets a command select a specific absence rendering
    instead of the plain "not present in this dump" default -- restricted
    to `_ABSENT_CAPABLE_CODES` (SOURCE_ABSENT, or a dedicated code such as
    MODULE_CLASSIFICATION_UNAVAILABLE), never a code describing something
    other than absence. `counterpart_source`/`affected_count`/`scope` let
    a fully-absent source still be reported with the wording of "N things
    present in COUNTERPART but missing from SOURCE" -- e.g. threads.py's
    ThreadListStream, entirely absent while ThreadInfoListStream has real
    entries, must render (and be coded) as SOURCE_ABSENT for ThreadListStream
    with that count/counterpart attached, not as a SOURCE_KEY_MISMATCH
    (which would misrepresent a fully-absent source as merely partially
    mismatched). Either way the actual text is produced by
    render_limitation(), never composed here or by the caller."""
    source: str
    absent_code: LimitationCode = LimitationCode.SOURCE_ABSENT
    unavailable_fields: tuple = field(default_factory=tuple)
    available_fields: tuple = field(default_factory=tuple)
    counterpart_source: "str | None" = None
    affected_count: "int | None" = None
    scope: "str | None" = None

    def __post_init__(self):
        object.__setattr__(self, "absent_code", LimitationCode(self.absent_code))
        if self.absent_code not in _ABSENT_CAPABLE_CODES:
            raise ValueError(
                f"SourceRequirement.absent_code must be one of "
                f"{[c.value for c in _ABSENT_CAPABLE_CODES]}, got {self.absent_code.value!r}")
        if (self.absent_code in _FIXED_SOURCE_CODES
                and self.source != _FIXED_SOURCE_CODES[self.absent_code]):
            raise ValueError(
                f"SourceRequirement(absent_code={self.absent_code.value}) requires "
                f"source={_FIXED_SOURCE_CODES[self.absent_code]!r}, got {self.source!r}")
        if not isinstance(self.unavailable_fields, tuple):
            object.__setattr__(self, "unavailable_fields", tuple(self.unavailable_fields))
        if not isinstance(self.available_fields, tuple):
            object.__setattr__(self, "available_fields", tuple(self.available_fields))


# Codes EvaluationRequirement.all_absent_code may select for a
# SINGLE-source group: everything SourceRequirement.absent_code allows --
# each of these renders from `source` alone, ignoring any other group
# members, which is exactly why they must NEVER be used for a 2+-source
# group (that would silently drop every source but the first from the
# rendered text -- the bug this validation exists to prevent).
_SINGLE_SOURCE_EVALUATION_CODES = _ABSENT_CAPABLE_CODES

# Codes valid for a MULTI-source (2+) group: each of these either
# enumerates every member in its rendered text (SOURCE_GROUP_ABSENT) or is
# a fully-fixed sentence that represents the group AS A WHOLE by
# definition (PID_SOURCES_ABSENT: misc_info/threads/exception all absent).
_GROUP_EVALUATION_CODES = (LimitationCode.SOURCE_GROUP_ABSENT, LimitationCode.PID_SOURCES_ABSENT)


@dataclass(frozen=True)
class EvaluationRequirement:
    """Declares the group of sources build_coverage_report checks for
    "was there anything to evaluate at all" -- not_evaluated fires when
    EVERY one of `sources` is SOURCE_ABSENT. This is its OWN type,
    separate from SourceRequirement (which describes ONE source's
    completeness), because the resulting limitation is a fact about the
    GROUP as a whole, not about any single member: pinning a custom
    `all_absent_code` to "whichever source happens to be listed first"
    would make a group-level fact depend on an arbitrary member source,
    which is exactly the kind of ambiguity this split avoids.

    `all_absent_code` defaults to None, meaning "pick the usual automatic
    default": plain SOURCE_ABSENT for a single source (list/modules'
    shape) or SOURCE_GROUP_ABSENT for two or more (threads' shape) --
    passing a bare tuple of source names to `evaluation_sources` gets
    exactly this default behavior, unchanged from before this type
    existed. Set `all_absent_code` explicitly only when a command's
    existing, already-shipped wording needs a dedicated code instead
    (e.g. PID's 3-source "MiscInfo, thread list, and exception stream
    are all absent ..." sentence, which fits neither automatic
    template).

    Validated as a whole, not just per-field, because `all_absent_code`'s
    validity depends on how many sources there are: a single-source-only
    code (e.g. PEB_UNAVAILABLE) used with a 2+-source group would render
    text that silently ignores every source but the first, and a
    multi-source code (SOURCE_GROUP_ABSENT) used with zero or one source
    is either meaningless or already rejected elsewhere
    (CoverageLimitation itself requires >= 2 related_sources for it)."""
    sources: tuple
    all_absent_code: "LimitationCode | None" = None

    def __post_init__(self):
        if not isinstance(self.sources, tuple):
            object.__setattr__(self, "sources", tuple(self.sources))

        if not self.sources:
            if self.all_absent_code is not None:
                raise ValueError(
                    "EvaluationRequirement with empty sources cannot set all_absent_code "
                    "-- there is no group for it to describe")
            return

        if any(not isinstance(s, str) or not s for s in self.sources):
            raise ValueError(
                f"EvaluationRequirement.sources must be non-empty strings, got {self.sources!r}")
        if len(set(self.sources)) != len(self.sources):
            raise ValueError(
                f"EvaluationRequirement.sources must not contain duplicates, got {self.sources!r}")

        if self.all_absent_code is None:
            return
        code = LimitationCode(self.all_absent_code)
        allowed = (_SINGLE_SOURCE_EVALUATION_CODES if len(self.sources) == 1
                   else _GROUP_EVALUATION_CODES)
        if code not in allowed:
            raise ValueError(
                f"EvaluationRequirement.all_absent_code={code.value!r} is not valid for "
                f"{len(self.sources)} source(s) -- must be one of {[c.value for c in allowed]}")
        if code == LimitationCode.PID_SOURCES_ABSENT and self.sources != _PID_SOURCES_ABSENT_SOURCES:
            raise ValueError(
                f"EvaluationRequirement.all_absent_code=PID_SOURCES_ABSENT requires sources == "
                f"{_PID_SOURCES_ABSENT_SOURCES!r}, got {self.sources!r}")
        if code in _FIXED_SOURCE_CODES and self.sources[0] != _FIXED_SOURCE_CODES[code]:
            raise ValueError(
                f"EvaluationRequirement.all_absent_code={code.value} requires "
                f"sources[0]={_FIXED_SOURCE_CODES[code]!r}, got {self.sources[0]!r}")
        object.__setattr__(self, "all_absent_code", code)


# Codes a caller may hand-build directly into completeness_checks (as
# opposed to a bare source name / SourceRequirement, which the reducer
# turns into a limitation itself) -- genuine business facts the reducer
# cannot infer from source state alone. Everything else -- SOURCE_ABSENT/
# SOURCE_FAILED (must be derived from a SourceObservation, never hand-
# asserted), SOURCE_GROUP_ABSENT/PID_SOURCES_ABSENT (only the
# not_evaluated branch produces these), MODULE_CLASSIFICATION_UNAVAILABLE/
# PEB_UNAVAILABLE (only SourceRequirement's absent_code produces these) --
# is rejected, so a caller can't force a limitation the reducer never
# actually verified against source state.
_CALLER_BUILDABLE_COMPLETENESS_CODES = (
    LimitationCode.SOURCE_KEY_MISMATCH,
    LimitationCode.PID_THREAD_LIST_FALLBACK,
    LimitationCode.PID_EXCEPTION_TID_FALLBACK,
    LimitationCode.PID_NO_USABLE_FALLBACK,
)


def _completeness_check_source_name(check) -> str:
    if isinstance(check, CoverageLimitation):
        return check.source
    if isinstance(check, SourceRequirement):
        return check.source
    return check   # bare source-name string


def _completeness_check_counterpart(check) -> "str | None":
    if isinstance(check, (CoverageLimitation, SourceRequirement)):
        return check.counterpart_source
    return None


def _validate_build_coverage_report_inputs(sources, evaluation_sources, completeness_checks):
    for key, obs in sources.items():
        if obs.name != key:
            raise ValueError(
                f"sources[{key!r}].name is {obs.name!r} -- the dict key and the "
                f"SourceObservation's own name must match")

    referenced = (
        set(evaluation_sources)
        | {_completeness_check_source_name(c) for c in completeness_checks}
        | {c for c in (_completeness_check_counterpart(chk) for chk in completeness_checks) if c}
    )
    unknown = referenced - sources.keys()
    if unknown:
        raise ValueError(f"evaluation_sources/completeness_checks reference "
                          f"unknown source(s) not present in `sources`: {sorted(unknown)}")

    for check in completeness_checks:
        if not isinstance(check, CoverageLimitation):
            continue
        if check.code not in _CALLER_BUILDABLE_COMPLETENESS_CODES:
            raise ValueError(
                f"completeness_checks must not contain a pre-built {check.code.value} "
                f"CoverageLimitation (source={check.source!r}) -- only "
                f"{[c.value for c in _CALLER_BUILDABLE_COMPLETENESS_CODES]} may be hand-built; "
                f"anything describing source absence must be a bare source name or "
                f"SourceRequirement instead, so it's derived from the SourceObservation "
                f"itself rather than hand-asserted")
        if check.code == LimitationCode.SOURCE_KEY_MISMATCH:
            # A SOURCE_KEY_MISMATCH claims two sources are both genuinely
            # present but disagree on keys -- if either side is actually
            # ABSENT/FAILED, that's not a mismatch, it's an absence, and
            # must go through SourceRequirement auto-derivation instead
            # (see the threads-absent fix this guards against
            # regressing). This does NOT generalize to every caller-
            # buildable code: PID_THREAD_LIST_FALLBACK's source
            # ("misc_info") is EXPECTED to not have yielded a usable PID
            # -- that is the fallback's entire trigger condition, not an
            # error.
            for side, name in (("source", check.source), ("counterpart_source", check.counterpart_source)):
                if name is None:
                    continue
                if sources[name].state in (SourceState.ABSENT, SourceState.FAILED):
                    raise ValueError(
                        f"SOURCE_KEY_MISMATCH.{side}={name!r} is {sources[name].state.value} -- "
                        f"a key mismatch requires both sides to be present; an absent/failed source "
                        f"must be expressed via a bare source name or SourceRequirement instead")
            if check.affected_count is not None and check.affected_count <= 0:
                raise ValueError(
                    f"SOURCE_KEY_MISMATCH.affected_count must be None or > 0, "
                    f"got {check.affected_count!r} (source={check.source!r})")

        elif check.code == LimitationCode.PID_THREAD_LIST_FALLBACK:
            # Unlike SOURCE_KEY_MISMATCH, `source` (misc_info) being
            # unusable is this fallback's entire trigger condition -- but
            # `counterpart_source` (threads) supplying the actual TID list
            # must be genuinely present, and the TID count claimed must
            # match what the source itself reports, or the two are two
            # independent, driftable claims about the same fact.
            threads_obs = sources["threads"]
            if threads_obs.state != SourceState.PRESENT:
                raise ValueError(
                    f"PID_THREAD_LIST_FALLBACK requires threads to be present, "
                    f"got {threads_obs.state.value}")
            if len(check.related_tids) != threads_obs.record_count:
                raise ValueError(
                    f"PID_THREAD_LIST_FALLBACK.related_tids has {len(check.related_tids)} "
                    f"entries, but threads reports record_count={threads_obs.record_count}")

        elif check.code == LimitationCode.PID_EXCEPTION_TID_FALLBACK:
            exception_obs = sources["exception"]
            if exception_obs.state != SourceState.PRESENT:
                raise ValueError(
                    f"PID_EXCEPTION_TID_FALLBACK requires exception to be present, "
                    f"got {exception_obs.state.value}")


def _derive_required_source_limitation(obs: SourceObservation, req: "SourceRequirement | None",
                                        sources: dict) -> "CoverageLimitation | None":
    req = req or SourceRequirement(source=obs.name)
    if obs.state == SourceState.ABSENT:
        if req.counterpart_source and req.affected_count == 0:
            # affected_count=0 only means "nothing was actually affected"
            # if the counterpart ITSELF confirms zero entries -- checked
            # against its real SourceObservation, not taken on faith from
            # the caller's count. A counterpart that's PRESENT with real
            # records (or ABSENT/FAILED, telling us nothing) does NOT
            # justify suppressing this source's absence; that would hide
            # a genuine gap behind a caller's inconsistent count.
            counterpart_obs = sources[req.counterpart_source]
            if counterpart_obs.state != SourceState.PRESENT_EMPTY:
                raise ValueError(
                    f"SourceRequirement({obs.name!r}) has affected_count=0 but counterpart "
                    f"{req.counterpart_source!r} is {counterpart_obs.state.value!r}, not "
                    f"present_empty -- affected_count=0 must reflect the counterpart genuinely "
                    f"reporting zero entries, not be asserted independently of its real state")
            # Counterpart genuinely has zero entries (e.g. threads.py's
            # ThreadInfoListStream present but reporting no real threads)
            # -- nothing was actually affected by this source's absence,
            # so there is no real coverage gap to report. Without this,
            # the rendered text would be a nonsensical "0 thing(s) present
            # in COUNTERPART but missing from SOURCE".
            return None
        return CoverageLimitation(code=req.absent_code, source=obs.name,
                                   scope=req.scope or "dump",
                                   unavailable_fields=req.unavailable_fields,
                                   available_fields=req.available_fields,
                                   counterpart_source=req.counterpart_source,
                                   affected_count=req.affected_count)
    if obs.state == SourceState.FAILED:
        return CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source=obs.name,
                                   scope="dump", detail=obs.detail)
    return None


def build_coverage_report(
    sources: dict,
    *,
    evaluation_sources: "tuple | None" = None,
    completeness_checks: "list | None" = None,
) -> CoverageReport:
    """
    The single reduction rule every command's coverage status derives
    from.

      - `evaluation_sources`: either an ORDERED tuple of source names, or
        an EvaluationRequirement (when a command needs a dedicated
        all-absent code instead of the automatic default -- see that
        class). If the resulting source group is non-empty and EVERY one
        of those sources is SOURCE_ABSENT, the command had literally
        nothing to evaluate: not_evaluated, regardless of
        completeness_checks. With the automatic default: a single-source
        group renders as plain SOURCE_ABSENT ("X not present in this
        dump" -- list/modules: ("memory_info",)); a multi-source group
        renders as SOURCE_GROUP_ABSENT ("Neither X nor Y present in this
        dump" for 2, "None of X, Y, Z present in this dump" for more --
        threads: ("threads", "thread_info")). Either way this is
        generated automatically here, never by the caller. A required
        source that's SOURCE_FAILED (not ABSENT) never triggers
        not_evaluated by itself -- evaluation was attempted and hit an
        error, which is partial territory, not never evaluated.

      - `completeness_checks`: an ORDERED list, each entry one of:
          * a bare source-name string, or a SourceRequirement -- the
            reducer derives a SOURCE_ABSENT/SOURCE_FAILED
            CoverageLimitation from that source's OWN SourceObservation
            automatically (see SourceRequirement for how to select a
            richer wording than the plain default), or contributes
            nothing if the source is present.
          * an already-built CoverageLimitation with a code in
            `_CALLER_BUILDABLE_COMPLETENESS_CODES` (a genuine business
            fact the reducer cannot infer from source state alone; every
            other code is rejected, so a caller can't force e.g. a
            MODULE_CLASSIFICATION_UNAVAILABLE limitation the reducer
            never actually checked against modules' real state).
        Final `limitations` preserves this exact order, so a command's
        existing reason ordering survives the migration unchanged.

    Status: evaluation_sources (if non-empty) all SOURCE_ABSENT ->
    not_evaluated. Else: any limitation -> partial. Else -> complete.
    """
    if isinstance(evaluation_sources, EvaluationRequirement):
        eval_req = evaluation_sources
    else:
        eval_req = EvaluationRequirement(sources=tuple(evaluation_sources) if evaluation_sources else ())
    completeness_checks = list(completeness_checks) if completeness_checks else []

    _validate_build_coverage_report_inputs(sources, eval_req.sources, completeness_checks)

    if eval_req.sources and all(
        sources[name].state == SourceState.ABSENT for name in eval_req.sources
    ):
        code = eval_req.all_absent_code
        if code is None:
            code = (LimitationCode.SOURCE_ABSENT if len(eval_req.sources) == 1
                     else LimitationCode.SOURCE_GROUP_ABSENT)
        related = eval_req.sources if len(eval_req.sources) >= 2 else ()
        group_limitation = CoverageLimitation(
            code=code, source=eval_req.sources[0], scope="dump", related_sources=related)
        return CoverageReport(status=CoverageStatus.NOT_EVALUATED, sources=sources,
                               limitations=[group_limitation])

    limitations = []
    for check in completeness_checks:
        if isinstance(check, CoverageLimitation):
            limitations.append(check)
            continue
        req = check if isinstance(check, SourceRequirement) else None
        name = check.source if isinstance(check, SourceRequirement) else check
        limitation = _derive_required_source_limitation(sources[name], req, sources)
        if limitation is not None:
            limitations.append(limitation)

    status = CoverageStatus.PARTIAL if limitations else CoverageStatus.COMPLETE
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
