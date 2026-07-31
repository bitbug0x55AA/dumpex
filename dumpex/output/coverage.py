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
the SAME SourceObservation the caller already had to construct. The
limitation kinds a caller still builds directly are the ones marked
caller_buildable in _CODE_SPECS (SOURCE_KEY_MISMATCH and the PID_*
fallback codes) -- genuine cross-source business facts (e.g. two streams
describing the same entities disagreeing on which keys exist, or a
weaker fallback source substituting for one that yielded nothing usable)
that the reducer cannot infer from source state alone.

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
from typing import Callable, Optional

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

    # FAILED is a real, first-class state this model supports (see
    # build_coverage_report's not_evaluated branch and render_limitation's
    # SOURCE_FAILED template) -- but is currently N/A for all six of
    # dumpex's original recon commands (list/modules/threads/peb/pid/
    # sysinfo): none of their mf.<stream> attribute accesses are wrapped
    # in a try/except, so a parsing error there propagates as a fatal,
    # uncaught exception (crashing before open_dump even returns) rather
    # than becoming a SOURCE_FAILED SourceObservation. FAILED is reserved
    # for a future command whose source access can genuinely raise and
    # recover (e.g. comparison/diff reading two dumps, where one side
    # failing shouldn't abort the other) -- a caller must construct
    # SourceObservation(state=FAILED, ...) itself (see observe_source's
    # own docstring); nothing here does it automatically.


SOURCE_ABSENT        = SourceState.ABSENT
SOURCE_PRESENT_EMPTY = SourceState.PRESENT_EMPTY
SOURCE_PRESENT       = SourceState.PRESENT
SOURCE_FAILED        = SourceState.FAILED


# ── Shared field-shape validators ─────────────────────────────────────────
# Every wire-bound string/int/tuple field on SourceObservation and
# CoverageLimitation is validated through exactly one of these, rather
# than each field growing its own hand-rolled check -- the JSON Schema's
# corresponding $defs (sourceObservation/coverageLimitation) enforce the
# identical constraints on the other side, and drift between the two
# is what lets the Python model construct an object whose to_dict()
# the schema then rejects.

def _require_non_empty_str(value, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string, got {value!r}")


def _require_optional_str(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{field_name} must be None or a non-empty string, got {value!r}")


def _require_optional_positive_int(value, field_name: str) -> None:
    # bool is a subclass of int in Python (True == 1, False == 0), so a
    # plain `isinstance(value, int)` or `value <= 0` check would silently
    # accept a bool -- explicitly excluded, since the JSON Schema's
    # "integer" type rejects `true`/`false` on the wire.
    if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value <= 0):
        raise ValueError(
            f"{field_name} must be None or a plain positive int (not bool), got {value!r}")


def _require_optional_nonnegative_int(value, field_name: str) -> None:
    # Distinct from _require_optional_positive_int above: SourceRequirement.
    # affected_count's own legal range includes exactly 0 (the caller's
    # explicit assertion that a counterpart_source is genuinely present_
    # empty, checked against its real SourceObservation in _derive_
    # required_source_limitation) -- unlike CoverageLimitation.
    # affected_count, which can never actually be constructed as 0 (a
    # SourceRequirement with a valid affected_count=0 either gets
    # suppressed to no limitation at all, or raises, before a
    # CoverageLimitation is ever built from it).
    if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0):
        raise ValueError(
            f"{field_name} must be None or a plain non-negative int (not bool), got {value!r}")


def _normalize_tuple(value, field_name: str) -> tuple:
    # Restricted to list/tuple specifically, not "anything iterable":
    # tuple(value) would otherwise also accept a bare string (silently
    # exploding "ab" into ('a', 'b') instead of raising on what's almost
    # always a forgotten [ ] at the call site), a set/dict (whose
    # iteration order is hash-dependent -- process-randomized in Python
    # for str keys -- so the resulting tuple order, and therefore the
    # rendered reason text/JSON array/frozen-test snapshot, could drift
    # between runs), or a one-shot generator (works once, then silently
    # empty on a second read of the same field).
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            f"{field_name} must be a list or tuple, got {type(value).__name__}")
    return tuple(value)


def _normalize_non_empty_str_tuple(value, field_name: str) -> tuple:
    value = _normalize_tuple(value, field_name)
    if any(not isinstance(v, str) or not v for v in value):
        raise ValueError(f"{field_name} must contain only non-empty strings, got {value!r}")
    return value


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
        _require_non_empty_str(self.name, "SourceObservation.name")
        state = SourceState(self.state)
        object.__setattr__(self, "state", state)

        # record_count must be a plain int (bool excluded -- see
        # _require_optional_positive_int's docstring) or None; unlike
        # affected_count this may legitimately be 0 (present_empty), so
        # the shared positive-int helper doesn't apply here -- checked
        # directly instead of relying on the state-specific comparisons
        # below to catch a non-int (e.g. a float slips past `<= 0`).
        if self.record_count is not None and (
                not isinstance(self.record_count, int) or isinstance(self.record_count, bool)):
            raise ValueError(
                f"SourceObservation {self.name!r}: record_count must be a plain int "
                f"(not bool) or None, got {self.record_count!r}")
        _require_optional_str(self.detail, f"SourceObservation {self.name!r}: detail")

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

    def to_dict(self) -> dict:
        """`name` is deliberately excluded -- the wire representation is a
        dict keyed by name (coverage.sources[name] = {...}), same as this
        object already lives in CoverageReport.sources, so repeating the
        name inside its own value would be redundant."""
        return {"state": self.state.value, "record_count": self.record_count,
                "detail": self.detail}


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

# Human names for known sources, used only by the render_* functions
# below. Kept separate from the bare source key (e.g. "memory_info") so
# the rendered text stays exactly what analysts/consumers already see in
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


def _render_present_in_but_missing_from(name: str, limitation: "CoverageLimitation") -> str:
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


# ── Per-code registry ──────────────────────────────────────────────────
# Every LimitationCode's rules used to be scattered across five places
# (a fixed-source dict, an absent-capable tuple, a group-capable tuple, a
# caller-buildable tuple, and per-code branches split between this
# class's __post_init__ and _validate_build_coverage_report_inputs) --
# each new code meant touching up to five separate spots, easy to
# under-update (exactly the pattern that caused the PID trust-boundary
# bugs this module was hardened against earlier). _CODE_SPECS is the one
# place a code's full contract lives: who may construct it, which source
# it's pinned to (if any), whether it's usable for an absent/group
# evaluation or a hand-built completeness check, its shape-only field
# validation, and its cross-source validation.
#
# Adding a new LimitationCode always means adding one _CODE_SPECS entry
# here -- test_output_coverage.py enforces this mechanically
# (set(_CODE_SPECS) == set(LimitationCode)), but that only catches a
# missing entry, not a wrong one: a new code's own source/field/state
# contract still needs its own dedicated tests, following the existing
# PID_*/SYSINFO_* tests in test_output_coverage.py as the pattern.
@dataclass(frozen=True)
class _CodeSpec:
    render: Callable[["CoverageLimitation"], str]
    # Fully fixed-sentence codes about ONE specific source -- construction
    # requires `source` to match exactly (a mismatch would render a
    # sentence describing a stream other than the one actually observed).
    fixed_source: Optional[str] = None
    # PID_SOURCES_ABSENT's exact 3-tuple -- related_sources must equal
    # this precisely, since the rendered sentence names those three
    # streams specifically.
    fixed_related_sources: Optional[tuple] = None
    # SOURCE_GROUP_ABSENT: related_sources must have at least this many
    # entries for the "None/Neither of ..." wording to make sense.
    min_related_sources: Optional[int] = None
    # Usable as SourceRequirement.absent_code, or a single-source
    # EvaluationRequirement.all_absent_code.
    absent_capable: bool = False
    # Usable as a multi-source (2+) EvaluationRequirement.all_absent_code.
    group_capable: bool = False
    # Usable as a caller-hand-built CoverageLimitation in
    # completeness_checks (a genuine business fact the reducer cannot
    # infer from source state alone).
    caller_buildable: bool = False
    # Shape-only per-code field validation (no `sources` dict needed),
    # invoked from CoverageLimitation.__post_init__.
    validate_fields: Optional[Callable[["CoverageLimitation"], None]] = None
    # Cross-source validation (needs the `sources` dict), invoked from
    # _validate_build_coverage_report_inputs for caller-buildable codes.
    validate_against_sources: Optional[Callable[["CoverageLimitation", dict], None]] = None
    # The structured fields (see _STRUCTURED_FIELD_DEFAULTS below) this
    # code's renderer/semantics actually consumes -- every OTHER
    # structured field must stay at its default. Without this, a caller
    # can attach contradictory data a fixed-sentence renderer silently
    # ignores (e.g. affected_count/unavailable_fields/detail all set on
    # PID_NO_USABLE_FALLBACK, whose own enum comment says "fully fixed
    # sentence, no fields" -- nothing previously enforced that).
    #
    # `scope` is included here like any other field, NOT unconditionally
    # exempted: codes reached via an auto-derivation path
    # (_derive_required_source_limitation for absent_capable codes,
    # build_coverage_report's not_evaluated branch for group_capable
    # codes) always end up with scope="dump" unless the caller overrides
    # it via SourceRequirement.scope, regardless of whether the renderer
    # actually reads it -- so those codes list "scope" in allowed_fields.
    # A caller_buildable-ONLY code (PID_THREAD_LIST_FALLBACK/
    # PID_EXCEPTION_TID_FALLBACK/PID_NO_USABLE_FALLBACK) is never reached
    # through that path and never receives scope from any production call
    # site, so it does NOT list "scope" -- confirmed empirically: the only
    # call sites (sysinfo.py's collect_pid) never pass scope= to any of
    # the three. SOURCE_KEY_MISMATCH is caller_buildable too but DOES list
    # "scope" since it's a real, rendered part of its text
    # (threads.py passes scope="thread" explicitly).
    allowed_fields: frozenset = frozenset()


def _render_source_absent(limitation: "CoverageLimitation") -> str:
    name = _display_name(limitation.source)
    if limitation.counterpart_source:
        return _render_present_in_but_missing_from(name, limitation)
    if limitation.unavailable_fields:
        avail = (f" ({'/'.join(limitation.available_fields)} only)"
                  if limitation.available_fields else "")
        return (f"{name} not present; {'/'.join(limitation.unavailable_fields)} "
                f"unavailable{avail}")
    return f"{name} not present in this dump"


def _render_source_failed(limitation: "CoverageLimitation") -> str:
    name = _display_name(limitation.source)
    detail = f": {limitation.detail}" if limitation.detail else ""
    return f"{name} present but could not be read{detail}"


def _render_source_key_mismatch(limitation: "CoverageLimitation") -> str:
    name = _display_name(limitation.source)
    if limitation.counterpart_source:
        return _render_present_in_but_missing_from(name, limitation)
    count = limitation.affected_count if limitation.affected_count is not None else "some"
    scope = limitation.scope or "item"
    fields = (f" ({'/'.join(limitation.unavailable_fields)} unavailable for those)"
               if limitation.unavailable_fields else "")
    return f"{count} {scope}(s) missing from {name}{fields}"


def _render_source_group_absent(limitation: "CoverageLimitation") -> str:
    names = [_display_name(s) for s in limitation.related_sources]
    if len(names) == 2:
        return f"Neither {names[0]} nor {names[1]} present in this dump"
    return f"None of {', '.join(names)} present in this dump"


def _render_module_classification_unavailable(limitation: "CoverageLimitation") -> str:
    name = _display_name(limitation.source)
    return (f"{name} not present; thread backing-module classification unavailable "
            f"(cannot confirm whether a start address is backed by a known module)")


def _render_pid_sources_absent(limitation: "CoverageLimitation") -> str:
    return ("MiscInfo, thread list, and exception stream are all absent from this "
            "dump; PID could not be evaluated")


def _render_pid_thread_list_fallback(limitation: "CoverageLimitation") -> str:
    tids = limitation.related_tids
    shown = ", ".join(f"0x{t:x}" for t in tids[:8])
    suffix = " …" if len(tids) > 8 else ""
    return (f"MiscInfo stream absent — PID not directly recoverable from thread list.\n"
            f"    {len(tids)} thread(s) found: {shown}{suffix}")


def _render_pid_exception_tid_fallback(limitation: "CoverageLimitation") -> str:
    return (f"Exception stream present: faulting TID = 0x{limitation.thread_id:x} "
            f"(this is a Thread ID, not a Process ID)")


def _render_pid_no_usable_fallback(limitation: "CoverageLimitation") -> str:
    return ("PID not found in MINIDUMP_MISC_INFO, and no usable cross-check data "
            "was available from the thread list or exception stream")


def _render_fixed_text(text: str) -> Callable[["CoverageLimitation"], str]:
    """Factory for the fully fixed-sentence codes (no field
    interpolation at all) -- avoids five near-identical one-line lambdas."""
    return lambda limitation: text


def _validate_source_absent_fields(limitation: "CoverageLimitation") -> None:
    # affected_count only means anything paired with a counterpart (it's
    # "N present in counterpart but missing from source") -- a bare count
    # with no counterpart is meaningless and the renderer never reads it
    # in that shape (falls through to the plain "not present" sentence).
    if limitation.affected_count is not None and limitation.counterpart_source is None:
        raise ValueError(
            "CoverageLimitation(code=SOURCE_ABSENT) requires counterpart_source when "
            f"affected_count is set, got affected_count={limitation.affected_count!r} with "
            f"counterpart_source=None")
    # _render_source_absent branches on counterpart_source FIRST -- when
    # it's set, available_fields is never reached at all (that branch
    # only ever reads affected_count/scope/unavailable_fields via
    # _render_present_in_but_missing_from); available_fields is only
    # consumed in the OTHER branch (no counterpart_source, unavailable_
    # fields set, "X unavailable (Y only)"). So available_fields requires
    # BOTH unavailable_fields set AND counterpart_source unset -- having
    # unavailable_fields alone (the check below) is necessary but not
    # sufficient, since counterpart_source being set would still route
    # away from the branch that reads available_fields at all.
    if limitation.available_fields and limitation.counterpart_source is not None:
        raise ValueError(
            "CoverageLimitation(code=SOURCE_ABSENT) requires counterpart_source to be unset "
            f"when available_fields is set, got available_fields={limitation.available_fields!r} "
            f"with counterpart_source={limitation.counterpart_source!r} -- the counterpart branch "
            f"never reads available_fields")
    if limitation.available_fields and not limitation.unavailable_fields:
        raise ValueError(
            "CoverageLimitation(code=SOURCE_ABSENT) requires unavailable_fields when "
            f"available_fields is set, got available_fields={limitation.available_fields!r} "
            f"with unavailable_fields=()")
    if limitation.counterpart_source is not None and limitation.counterpart_source == limitation.source:
        raise ValueError(
            "CoverageLimitation(code=SOURCE_ABSENT) requires counterpart_source to differ from "
            f"source -- both are {limitation.source!r}, which would render as present in X but "
            f"missing from that same X")


def _validate_source_absent_against_sources(limitation: "CoverageLimitation", sources: dict) -> None:
    # A SOURCE_ABSENT limitation with counterpart_source claims "N items
    # present in COUNTERPART but missing from SOURCE" -- that claim is
    # only true if the counterpart itself is genuinely present with real
    # records. (A PRESENT_EMPTY counterpart with affected_count == 0 is
    # the "nothing was actually affected" case _derive_required_source_
    # limitation already short-circuits to None before ever constructing
    # this object -- so anything that reaches here with a counterpart
    # must be backed by a counterpart that's truly PRESENT.)
    if limitation.counterpart_source is None:
        return
    counterpart_obs = sources[limitation.counterpart_source]
    if counterpart_obs.state != SourceState.PRESENT:
        raise ValueError(
            f"SOURCE_ABSENT.counterpart_source={limitation.counterpart_source!r} claims records "
            f"present there, but its own state is {counterpart_obs.state.value!r}, not present")
    # source is entirely absent, so EVERY one of the counterpart's records
    # is, by definition, "present in counterpart but missing from source"
    # -- an explicit affected_count must equal that total exactly, or the
    # two numbers are free to drift apart with nothing keeping them in
    # sync (affected_count itself is never independently derived from
    # counterpart_obs.record_count -- it's whatever the caller passed).
    if (limitation.affected_count is not None
            and limitation.affected_count != counterpart_obs.record_count):
        raise ValueError(
            f"SOURCE_ABSENT.affected_count={limitation.affected_count!r} does not match "
            f"counterpart_source={limitation.counterpart_source!r}'s record_count="
            f"{counterpart_obs.record_count!r} -- source is entirely absent, so every one of "
            f"the counterpart's records is affected, and the two counts must agree")


def _validate_pid_thread_list_fallback_fields(limitation: "CoverageLimitation") -> None:
    # `source == "misc_info"` is enforced generically via this code's own
    # fixed_source (see _CODE_SPECS) -- putting a fixed_source on a
    # caller_buildable/group_capable-only code does NOT make it eligible
    # for SourceRequirement/EvaluationRequirement (both gate on
    # absent_capable/group_capable membership first, before ever
    # consulting a fixed source), so it's safe to declare here too.
    if limitation.counterpart_source != "threads":
        raise ValueError(
            "CoverageLimitation(code=PID_THREAD_LIST_FALLBACK) requires "
            f"counterpart_source='threads', got {limitation.counterpart_source!r}")
    if not limitation.related_tids or any(
            not isinstance(t, int) or isinstance(t, bool) or t <= 0
            for t in limitation.related_tids):
        raise ValueError(
            "CoverageLimitation(code=PID_THREAD_LIST_FALLBACK) requires related_tids to be "
            f"a non-empty tuple of positive integers, got {limitation.related_tids!r}")


def _validate_pid_exception_tid_fallback_fields(limitation: "CoverageLimitation") -> None:
    # `source == "exception"` is enforced generically via fixed_source --
    # see _validate_pid_thread_list_fallback_fields's comment above.
    if (not isinstance(limitation.thread_id, int) or isinstance(limitation.thread_id, bool)
            or limitation.thread_id <= 0):
        raise ValueError(
            "CoverageLimitation(code=PID_EXCEPTION_TID_FALLBACK) requires thread_id to be "
            f"a positive integer, got {limitation.thread_id!r}")


def _validate_source_key_mismatch_against_sources(limitation: "CoverageLimitation",
                                                    sources: dict) -> None:
    # A SOURCE_KEY_MISMATCH claims two sources are both genuinely present
    # but disagree on keys -- if either side is actually ABSENT/FAILED,
    # that's not a mismatch, it's an absence, and must go through
    # SourceRequirement auto-derivation instead (see the threads-absent
    # fix this guards against regressing). This does NOT generalize to
    # every caller-buildable code: PID_THREAD_LIST_FALLBACK's source
    # ("misc_info") is EXPECTED to not have yielded a usable PID -- that
    # is the fallback's entire trigger condition, not an error.
    for side, name in (("source", limitation.source),
                        ("counterpart_source", limitation.counterpart_source)):
        if name is None:
            continue
        if sources[name].state in (SourceState.ABSENT, SourceState.FAILED):
            raise ValueError(
                f"SOURCE_KEY_MISMATCH.{side}={name!r} is {sources[name].state.value} -- "
                f"a key mismatch requires both sides to be present; an absent/failed source "
                f"must be expressed via a bare source name or SourceRequirement instead")


def _validate_pid_thread_list_fallback_against_sources(limitation: "CoverageLimitation",
                                                          sources: dict) -> None:
    # Unlike SOURCE_KEY_MISMATCH, `source` (misc_info) being unusable is
    # this fallback's entire trigger condition -- but `counterpart_source`
    # (threads) supplying the actual TID list must be genuinely present,
    # and the TID count claimed must match what the source itself
    # reports, or the two are two independent, driftable claims about the
    # same fact.
    threads_obs = sources["threads"]
    if threads_obs.state != SourceState.PRESENT:
        raise ValueError(
            f"PID_THREAD_LIST_FALLBACK requires threads to be present, "
            f"got {threads_obs.state.value}")
    if len(limitation.related_tids) != threads_obs.record_count:
        raise ValueError(
            f"PID_THREAD_LIST_FALLBACK.related_tids has {len(limitation.related_tids)} "
            f"entries, but threads reports record_count={threads_obs.record_count}")


def _validate_pid_exception_tid_fallback_against_sources(limitation: "CoverageLimitation",
                                                            sources: dict) -> None:
    exception_obs = sources["exception"]
    if exception_obs.state != SourceState.PRESENT:
        raise ValueError(
            f"PID_EXCEPTION_TID_FALLBACK requires exception to be present, "
            f"got {exception_obs.state.value}")


_CODE_SPECS = {
    LimitationCode.SOURCE_ABSENT: _CodeSpec(
        render=_render_source_absent, absent_capable=True,
        validate_fields=_validate_source_absent_fields,
        validate_against_sources=_validate_source_absent_against_sources,
        allowed_fields=frozenset({
            "scope", "affected_count", "unavailable_fields", "available_fields",
            "counterpart_source"})),
    LimitationCode.SOURCE_FAILED: _CodeSpec(
        render=_render_source_failed, allowed_fields=frozenset({"scope", "detail"})),
    LimitationCode.SOURCE_KEY_MISMATCH: _CodeSpec(
        render=_render_source_key_mismatch, caller_buildable=True,
        validate_against_sources=_validate_source_key_mismatch_against_sources,
        allowed_fields=frozenset({
            "scope", "affected_count", "unavailable_fields", "counterpart_source"})),
    LimitationCode.SOURCE_GROUP_ABSENT: _CodeSpec(
        render=_render_source_group_absent, min_related_sources=2, group_capable=True,
        allowed_fields=frozenset({"scope", "related_sources"})),
    LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE: _CodeSpec(
        render=_render_module_classification_unavailable, fixed_source="modules",
        absent_capable=True, allowed_fields=frozenset({"scope"})),
    LimitationCode.PEB_UNAVAILABLE: _CodeSpec(
        render=_render_fixed_text("PEB could not be parsed (missing sysinfo or thread list in dump)"),
        fixed_source="peb", absent_capable=True, allowed_fields=frozenset({"scope"})),
    LimitationCode.PID_SOURCES_ABSENT: _CodeSpec(
        render=_render_pid_sources_absent, fixed_source=_PID_SOURCES_ABSENT_SOURCES[0],
        fixed_related_sources=_PID_SOURCES_ABSENT_SOURCES, group_capable=True,
        allowed_fields=frozenset({"scope", "related_sources"})),
    LimitationCode.PID_THREAD_LIST_FALLBACK: _CodeSpec(
        render=_render_pid_thread_list_fallback, fixed_source="misc_info",
        caller_buildable=True, validate_fields=_validate_pid_thread_list_fallback_fields,
        validate_against_sources=_validate_pid_thread_list_fallback_against_sources,
        # No "scope": never rendered, and never set by the one production
        # call site (sysinfo.py's collect_pid) -- unlike SOURCE_ABSENT/
        # SOURCE_FAILED/SOURCE_KEY_MISMATCH/the group codes, this one is
        # never reached through an auto-derivation path that would
        # otherwise force scope="dump" on it regardless of code.
        allowed_fields=frozenset({"counterpart_source", "related_tids"})),
    LimitationCode.PID_EXCEPTION_TID_FALLBACK: _CodeSpec(
        render=_render_pid_exception_tid_fallback, fixed_source="exception",
        caller_buildable=True, validate_fields=_validate_pid_exception_tid_fallback_fields,
        validate_against_sources=_validate_pid_exception_tid_fallback_against_sources,
        allowed_fields=frozenset({"thread_id"})),   # no "scope" -- see PID_THREAD_LIST_FALLBACK above
    LimitationCode.PID_NO_USABLE_FALLBACK: _CodeSpec(
        render=_render_pid_no_usable_fallback, fixed_source="misc_info", caller_buildable=True),
        # allowed_fields defaults to empty: no "scope" either -- this
        # code's own enum comment says "fully fixed sentence, no fields",
        # and sysinfo.py's one call site never sets scope on it.
    LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE: _CodeSpec(
        render=_render_fixed_text("SystemInfoStream not present"),
        fixed_source="sysinfo", absent_capable=True, allowed_fields=frozenset({"scope"})),
    LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE: _CodeSpec(
        render=_render_fixed_text("MiscInfo stream not present"),
        fixed_source="misc_info", absent_capable=True, allowed_fields=frozenset({"scope"})),
    LimitationCode.SYSINFO_PEB_UNAVAILABLE: _CodeSpec(
        render=_render_fixed_text("PEB not available (requires sysinfo + thread list)"),
        fixed_source="peb", absent_capable=True, allowed_fields=frozenset({"scope"})),
    LimitationCode.SYSINFO_THREADS_UNAVAILABLE: _CodeSpec(
        render=_render_fixed_text("ThreadListStream not present (thread_count unavailable)"),
        fixed_source="threads", absent_capable=True, allowed_fields=frozenset({"scope"})),
    LimitationCode.SYSINFO_MODULES_UNAVAILABLE: _CodeSpec(
        render=_render_fixed_text("ModuleListStream not present (module_count unavailable)"),
        fixed_source="modules", absent_capable=True, allowed_fields=frozenset({"scope"})),
}

# Derived collections -- every other call site (SourceRequirement,
# EvaluationRequirement, CoverageLimitation, _validate_build_coverage_
# report_inputs) reads from these instead of hand-maintaining its own
# copy, so _CODE_SPECS above is the single place a code's membership in
# any of these groups is decided.
_FIXED_SOURCE_CODES = {code: spec.fixed_source for code, spec in _CODE_SPECS.items()
                        if spec.fixed_source is not None}
_ABSENT_CAPABLE_CODES = tuple(code for code, spec in _CODE_SPECS.items() if spec.absent_capable)
_GROUP_EVALUATION_CODES = tuple(code for code, spec in _CODE_SPECS.items() if spec.group_capable)
_CALLER_BUILDABLE_COMPLETENESS_CODES = tuple(
    code for code, spec in _CODE_SPECS.items() if spec.caller_buildable)
# Codes EvaluationRequirement.all_absent_code may select for a
# SINGLE-source group: everything SourceRequirement.absent_code allows --
# each of these renders from `source` alone, ignoring any other group
# members, which is exactly why they must NEVER be used for a 2+-source
# group (that would silently drop every source but the first from the
# rendered text -- the bug this validation exists to prevent).
_SINGLE_SOURCE_EVALUATION_CODES = _ABSENT_CAPABLE_CODES

# Every CoverageLimitation field besides code/source, and the value it
# must hold unless the code's own _CodeSpec.allowed_fields says
# otherwise -- see _CodeSpec.allowed_fields' docstring for the per-code
# reasoning (including why "scope" is here despite most codes allowing
# it: those are the ones reached via auto-derivation, which always sets
# it, not a blanket exemption).
_STRUCTURED_FIELD_DEFAULTS = {
    "scope": None,
    "affected_count": None,
    "unavailable_fields": (),
    "available_fields": (),
    "counterpart_source": None,
    "related_sources": (),
    "related_tids": (),
    "thread_id": None,
    "detail": None,
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
        _require_non_empty_str(self.source, "CoverageLimitation.source")
        # affected_count always means "count of affected items" whenever
        # it's set, regardless of code -- validated once here rather than
        # per-code, the same way `source` is.
        _require_optional_positive_int(self.affected_count, "CoverageLimitation.affected_count")
        _require_optional_str(self.scope, "CoverageLimitation.scope")
        _require_optional_str(self.counterpart_source, "CoverageLimitation.counterpart_source")
        _require_optional_str(self.detail, "CoverageLimitation.detail")
        object.__setattr__(self, "unavailable_fields", _normalize_non_empty_str_tuple(
            self.unavailable_fields, "CoverageLimitation.unavailable_fields"))
        object.__setattr__(self, "available_fields", _normalize_non_empty_str_tuple(
            self.available_fields, "CoverageLimitation.available_fields"))
        object.__setattr__(self, "related_sources", _normalize_non_empty_str_tuple(
            self.related_sources, "CoverageLimitation.related_sources"))
        object.__setattr__(self, "related_tids",
                            _normalize_tuple(self.related_tids, "CoverageLimitation.related_tids"))
        spec = _CODE_SPECS[self.code]
        if spec.min_related_sources is not None and len(self.related_sources) < spec.min_related_sources:
            raise ValueError(
                f"CoverageLimitation(code={self.code.value}) requires >= "
                f"{spec.min_related_sources} related_sources")
        if spec.fixed_source is not None and self.source != spec.fixed_source:
            raise ValueError(
                f"CoverageLimitation(code={self.code.value}) is a fixed sentence -- source must "
                f"be {spec.fixed_source!r}, got {self.source!r}")
        if spec.fixed_related_sources is not None and self.related_sources != spec.fixed_related_sources:
            raise ValueError(
                f"CoverageLimitation(code={self.code.value}) is a fixed sentence naming "
                f"MiscInfo/thread list/exception stream specifically -- related_sources must "
                f"be {spec.fixed_related_sources!r}, got {self.related_sources!r}")
        if spec.validate_fields is not None:
            spec.validate_fields(self)

        # Every structured field this code's spec doesn't list in
        # allowed_fields must stay at its default -- closes the gap where
        # e.g. affected_count/unavailable_fields/detail could be attached
        # to PID_NO_USABLE_FALLBACK (or any other fixed-sentence code)
        # and silently ignored by its renderer, leaving the machine
        # fields and the human text contradicting each other.
        for field_name, default in _STRUCTURED_FIELD_DEFAULTS.items():
            if field_name in spec.allowed_fields:
                continue
            value = getattr(self, field_name)
            if value != default:
                raise ValueError(
                    f"CoverageLimitation(code={self.code.value}) does not use {field_name} "
                    f"-- got {value!r}; only {sorted(spec.allowed_fields)} may be set on this "
                    f"code besides code/source")

    def to_dict(self) -> dict:
        """Every field, always -- no per-code custom shaping. Matches the
        same "always emit the full fixed field set, null/[] where unset"
        convention every record dataclass's own to_dict() already follows
        (e.g. ModuleRecord.to_dict() always emits checksum: None), rather
        than a bespoke wire shape per code."""
        return {
            "code": self.code.value,
            "source": self.source,
            "scope": self.scope,
            "affected_count": self.affected_count,
            "unavailable_fields": list(self.unavailable_fields),
            "available_fields": list(self.available_fields),
            "counterpart_source": self.counterpart_source,
            "related_sources": list(self.related_sources),
            "related_tids": list(self.related_tids),
            "thread_id": self.thread_id,
            "detail": self.detail,
        }


def render_limitation(limitation: CoverageLimitation) -> str:
    """The ONE place a CoverageLimitation becomes human text -- a thin
    dispatch onto the code's own _CodeSpec.render (see _CODE_SPECS,
    defined above CoverageLimitation). Must reproduce today's exact,
    already-shipped strings for every source already migrated onto this
    model so JSON output is unchanged; new sources/codes can extend
    _CODE_SPECS as they're migrated without touching any call site that
    already relies on this function."""
    return _CODE_SPECS[limitation.code].render(limitation)


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
        keeps `coverage.reasons`' own text byte-identical to what it was
        before `sources`/`limitations` existed, while limitations become
        the real, structured source of truth internally. (The wire format
        as a WHOLE is no longer byte-identical to that point in time --
        `coverage.sources`/`coverage.limitations` are new, additive
        fields alongside it; see envelope.Result/collector.py.)"""
        return [render_limitation(l) for l in self.limitations]


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
        # 0 is legal here (unlike CoverageLimitation.affected_count) --
        # it's the caller's explicit assertion that counterpart_source is
        # genuinely present_empty, checked against its real
        # SourceObservation in _derive_required_source_limitation.
        # Validated here, at construction time, so a bad value (a
        # negative count, a string, a bool) fails immediately rather than
        # silently reaching that check's `== 0`/`!= 0` comparisons, where
        # a non-zero-but-still-wrong value could slip past undetected.
        _require_optional_nonnegative_int(self.affected_count, "SourceRequirement.affected_count")
        if not isinstance(self.unavailable_fields, tuple):
            object.__setattr__(self, "unavailable_fields", tuple(self.unavailable_fields))
        if not isinstance(self.available_fields, tuple):
            object.__setattr__(self, "available_fields", tuple(self.available_fields))


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
        fixed_related_sources = _CODE_SPECS[code].fixed_related_sources
        if fixed_related_sources is not None and self.sources != fixed_related_sources:
            raise ValueError(
                f"EvaluationRequirement.all_absent_code={code.value} requires sources == "
                f"{fixed_related_sources!r}, got {self.sources!r}")
        if code in _FIXED_SOURCE_CODES and self.sources[0] != _FIXED_SOURCE_CODES[code]:
            raise ValueError(
                f"EvaluationRequirement.all_absent_code={code.value} requires "
                f"sources[0]={_FIXED_SOURCE_CODES[code]!r}, got {self.sources[0]!r}")
        object.__setattr__(self, "all_absent_code", code)


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
        # affected_count's own None-or-positive-int shape (and every other
        # generic field shape) is already enforced by CoverageLimitation.
        # __post_init__ at construction time -- only cross-source checks
        # (which need `sources`, not available at construction time)
        # remain here, one per caller-buildable code, in _CODE_SPECS.
        _validate_limitation_against_sources(check, sources)


def _validate_limitation_against_sources(limitation: CoverageLimitation, sources: dict) -> None:
    """The one place a constructed CoverageLimitation's cross-source
    checks run, regardless of HOW it was constructed -- a caller-built
    limitation goes through _validate_build_coverage_report_inputs before
    ever being handed here, but a reducer-derived one (SOURCE_ABSENT/
    SOURCE_FAILED via _derive_required_source_limitation, or the
    not_evaluated branch's group limitation) has no other checkpoint,
    so both paths call this rather than only the caller-buildable one."""
    validate_against_sources = _CODE_SPECS[limitation.code].validate_against_sources
    if validate_against_sources is not None:
        validate_against_sources(limitation, sources)


def _derive_required_source_limitation(obs: SourceObservation, req: "SourceRequirement | None",
                                        sources: dict) -> "CoverageLimitation | None":
    req = req or SourceRequirement(source=obs.name)
    if obs.state == SourceState.ABSENT:
        if req.counterpart_source:
            counterpart_obs = sources[req.counterpart_source]
            # affected_count=0 can never be constructed directly --
            # CoverageLimitation.affected_count only accepts None or a
            # positive int (see _require_optional_positive_int), by
            # design: "nothing affected" is expressed as no limitation at
            # all (return None below), never as a limitation whose count
            # happens to be 0. So a present_empty counterpart -- the only
            # state that legitimately means "nothing affected" -- is
            # handled as its own up-front case, checked BOTH ways: it
            # must suppress only when the caller's own affected_count
            # agrees (None or exactly 0), not for an arbitrary value the
            # caller happened to pass (SourceRequirement.affected_count's
            # own shape validation already excludes bool/negative/non-int
            # values -- this checks the remaining case, a positive int
            # that contradicts a counterpart confirmed to have zero
            # entries, e.g. affected_count=5 must not be silently
            # swallowed just because req.affected_count != 0 was the only
            # thing previously checked here).
            if counterpart_obs.state == SourceState.PRESENT_EMPTY:
                if req.affected_count not in (None, 0):
                    raise ValueError(
                        f"SourceRequirement({obs.name!r}) has affected_count="
                        f"{req.affected_count!r} but counterpart {req.counterpart_source!r} is "
                        f"present_empty (0 records) -- affected_count must reflect the "
                        f"counterpart genuinely reporting zero entries, not be asserted "
                        f"independently of its real state")
                return None
            if req.affected_count == 0:
                # counterpart is NOT present_empty (excluded above) -- an
                # explicit 0 contradicts whatever its real state actually
                # is (PRESENT with real records, ABSENT, or FAILED).
                raise ValueError(
                    f"SourceRequirement({obs.name!r}) has affected_count=0 but counterpart "
                    f"{req.counterpart_source!r} is {counterpart_obs.state.value!r}, not "
                    f"present_empty -- affected_count=0 must reflect the counterpart "
                    f"genuinely reporting zero entries, not be asserted independently of "
                    f"its real state")
            # source is entirely absent, so EVERY one of the counterpart's
            # records is, by definition, affected -- affected_count is
            # DERIVED from counterpart_obs.record_count when the caller
            # doesn't supply one, rather than left None. counterpart_obs.
            # record_count is itself None for ABSENT/FAILED (present_
            # empty is already excluded above), which is fine:
            # _validate_limitation_against_sources below is the single
            # place that rejects a non-PRESENT counterpart or a caller-
            # supplied count that doesn't match the derived one -- not
            # duplicated here, so there's exactly one rule to update if
            # it ever needs to change.
            affected_count = (req.affected_count if req.affected_count is not None
                               else counterpart_obs.record_count)
            # scope stays whatever the caller passed (None if omitted,
            # rendering as the generic "item" default) -- unlike the
            # plain-absence branch below, nothing here forces a "dump"
            # default: none of today's six commands' counterpart_source
            # call sites rely on it (all three pass an explicit entity
            # scope, e.g. threads.py's scope="thread").
            limitation = CoverageLimitation(code=req.absent_code, source=obs.name,
                                             scope=req.scope,
                                             unavailable_fields=req.unavailable_fields,
                                             available_fields=req.available_fields,
                                             counterpart_source=req.counterpart_source,
                                             affected_count=affected_count)
            _validate_limitation_against_sources(limitation, sources)
            return limitation
        limitation = CoverageLimitation(code=req.absent_code, source=obs.name,
                                         scope=req.scope or "dump",
                                         unavailable_fields=req.unavailable_fields,
                                         available_fields=req.available_fields,
                                         counterpart_source=None,
                                         affected_count=req.affected_count)
        _validate_limitation_against_sources(limitation, sources)
        return limitation
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
        _validate_limitation_against_sources(group_limitation, sources)
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
