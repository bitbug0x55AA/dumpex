"""
First-class coverage/provenance model, extracted from the ad hoc
bool(mf.X)-check-plus-hand-written-reason-string pattern every recon
command previously hand-rolled independently (see dumpex/commands/
list_cmd.py, modules.py, threads.py, sysinfo.py, peb.py -- the last two
still use that older pattern).

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


LIMITATION_SOURCE_ABSENT       = LimitationCode.SOURCE_ABSENT
LIMITATION_SOURCE_FAILED       = LimitationCode.SOURCE_FAILED
LIMITATION_SOURCE_KEY_MISMATCH = LimitationCode.SOURCE_KEY_MISMATCH


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
    caller-declared order. Human text is never written at the call site
    -- see render_limitation(). `code` is a closed vocabulary (unlike
    `source`, which stays open) since every branch of render_limitation()
    is hand-written per code; an unrecognized code would otherwise
    silently render as vague fallback text instead of failing at
    construction time."""
    code: LimitationCode
    source: str
    scope: "str | None" = None
    affected_count: "int | None" = None
    unavailable_fields: tuple = field(default_factory=tuple)
    available_fields: tuple = field(default_factory=tuple)
    counterpart_source: "str | None" = None
    related_sources: tuple = field(default_factory=tuple)
    detail: "str | None" = None   # SOURCE_FAILED only: the underlying error text

    def __post_init__(self):
        object.__setattr__(self, "code", LimitationCode(self.code))
        if not self.source:
            raise ValueError("CoverageLimitation.source must be a non-empty string")
        if not isinstance(self.unavailable_fields, tuple):
            object.__setattr__(self, "unavailable_fields", tuple(self.unavailable_fields))
        if not isinstance(self.available_fields, tuple):
            object.__setattr__(self, "available_fields", tuple(self.available_fields))
        if not isinstance(self.related_sources, tuple):
            object.__setattr__(self, "related_sources", tuple(self.related_sources))
        if self.code == LimitationCode.SOURCE_GROUP_ABSENT and len(self.related_sources) < 2:
            raise ValueError(
                "CoverageLimitation(code=SOURCE_GROUP_ABSENT) requires >= 2 related_sources")
        if self.code == LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE and self.source != "modules":
            raise ValueError(
                "CoverageLimitation(code=MODULE_CLASSIFICATION_UNAVAILABLE) is a fixed sentence "
                f"about ModuleListStream specifically -- source must be 'modules', got {self.source!r}")


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
_ABSENT_CAPABLE_CODES = (LimitationCode.SOURCE_ABSENT, LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE)


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
        if self.absent_code == LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE and self.source != "modules":
            raise ValueError(
                "SourceRequirement(absent_code=MODULE_CLASSIFICATION_UNAVAILABLE) "
                f"requires source='modules', got {self.source!r}")
        if not isinstance(self.unavailable_fields, tuple):
            object.__setattr__(self, "unavailable_fields", tuple(self.unavailable_fields))
        if not isinstance(self.available_fields, tuple):
            object.__setattr__(self, "available_fields", tuple(self.available_fields))


# The only code a caller may hand-build directly into completeness_checks
# (as opposed to a bare source name / SourceRequirement, which the reducer
# turns into a limitation itself). Everything else -- SOURCE_ABSENT/
# SOURCE_FAILED (must be derived from a SourceObservation, never hand-
# asserted), SOURCE_GROUP_ABSENT (only the not_evaluated branch produces
# this), MODULE_CLASSIFICATION_UNAVAILABLE (only SourceRequirement's
# absent_code produces this) -- is rejected, so a caller can't force a
# limitation the reducer never actually verified against source state.
_CALLER_BUILDABLE_COMPLETENESS_CODES = (LimitationCode.SOURCE_KEY_MISMATCH,)


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
        # A SOURCE_KEY_MISMATCH claims two sources are both genuinely
        # present but disagree on keys -- if either side is actually
        # ABSENT/FAILED, that's not a mismatch, it's an absence, and must
        # go through SourceRequirement auto-derivation instead (see the
        # threads-absent fix this guards against regressing).
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


def _derive_required_source_limitation(obs: SourceObservation,
                                        req: "SourceRequirement | None") -> "CoverageLimitation | None":
    req = req or SourceRequirement(source=obs.name)
    if obs.state == SourceState.ABSENT:
        if req.counterpart_source and req.affected_count == 0:
            # The counterpart genuinely has zero entries (e.g. threads.py's
            # ThreadInfoListStream present but reporting no real threads) --
            # nothing was actually affected by this source's absence, so
            # there is no real coverage gap to report. Without this, the
            # rendered text would be a nonsensical "0 thing(s) present in
            # COUNTERPART but missing from SOURCE".
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

      - `evaluation_sources`: an ORDERED tuple of source names (order
        matters -- it drives SOURCE_GROUP_ABSENT's wording below). If
        given and non-empty, and EVERY one of those sources is
        SOURCE_ABSENT, the command had literally nothing to evaluate:
        not_evaluated, regardless of completeness_checks. A single-source
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
          * an already-built CoverageLimitation with code SOURCE_KEY_MISMATCH
            (the only code a caller may hand-build here -- a genuine
            cross-source fact the reducer cannot infer from source state
            alone; every other code is rejected, so a caller can't force
            e.g. a MODULE_CLASSIFICATION_UNAVAILABLE limitation the
            reducer never actually checked against modules' real state).
        Final `limitations` preserves this exact order, so a command's
        existing reason ordering survives the migration unchanged.

    Status: evaluation_sources (if non-empty) all SOURCE_ABSENT ->
    not_evaluated. Else: any limitation -> partial. Else -> complete.
    """
    evaluation_sources = tuple(evaluation_sources) if evaluation_sources else ()
    completeness_checks = list(completeness_checks) if completeness_checks else []

    _validate_build_coverage_report_inputs(sources, evaluation_sources, completeness_checks)

    if evaluation_sources and all(
        sources[name].state == SourceState.ABSENT for name in evaluation_sources
    ):
        if len(evaluation_sources) == 1:
            group_limitation = CoverageLimitation(
                code=LimitationCode.SOURCE_ABSENT, source=evaluation_sources[0], scope="dump")
        else:
            group_limitation = CoverageLimitation(
                code=LimitationCode.SOURCE_GROUP_ABSENT, source=evaluation_sources[0],
                related_sources=evaluation_sources)
        return CoverageReport(status=CoverageStatus.NOT_EVALUATED, sources=sources,
                               limitations=[group_limitation])

    limitations = []
    for check in completeness_checks:
        if isinstance(check, CoverageLimitation):
            limitations.append(check)
            continue
        req = check if isinstance(check, SourceRequirement) else None
        name = check.source if isinstance(check, SourceRequirement) else check
        limitation = _derive_required_source_limitation(sources[name], req)
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
