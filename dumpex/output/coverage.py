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

Deliberately independent of dumpex.hunt._coverage (hunters' own
derive_coverage_status/derive_status/CoverageTracker) -- that module
belongs to detection logic and is out of scope for this refactor, even
though the two vocabularies happen to share the same three status
strings by design (complete/partial/not_evaluated), so a future reader
comparing hunt findings against recon coverage isn't looking at two
unrelated vocabularies that happen to look similar.
"""
from dataclasses import dataclass, field

# ── Source state ──────────────────────────────────────────────────────────

SOURCE_ABSENT       = "absent"          # the stream is not present in the dump at all
SOURCE_PRESENT_EMPTY = "present_empty"  # stream present, reports zero items
SOURCE_PRESENT      = "present"         # stream present, reports >=1 items
SOURCE_FAILED       = "failed"          # stream present but reading/parsing it raised


@dataclass
class SourceObservation:
    """The state of ONE underlying minidump stream ("source"), as
    observed during a single collect_*() call. `record_count` is None
    for ABSENT/FAILED (nothing was counted), 0 for PRESENT_EMPTY, and the
    real count for PRESENT."""
    name: str
    state: str
    record_count: "int | None" = None


def observe_source(name: str, *, present: bool, items: list = None) -> SourceObservation:
    """The absent/present_empty/present inference every command
    currently hand-rolls via `bool(mf.X)` plus `len(items)`. Does not
    cover SOURCE_FAILED -- a command whose source access can genuinely
    raise should catch that itself and construct the SourceObservation
    directly (there is no generic way to know what "read failed" means
    for an arbitrary source without knowing its own exception surface)."""
    if not present:
        return SourceObservation(name=name, state=SOURCE_ABSENT, record_count=None)
    items = items or []
    if not items:
        return SourceObservation(name=name, state=SOURCE_PRESENT_EMPTY, record_count=0)
    return SourceObservation(name=name, state=SOURCE_PRESENT, record_count=len(items))


# ── Coverage limitations ────────────────────────────────────────────────

LIMITATION_SOURCE_ABSENT       = "SOURCE_ABSENT"
LIMITATION_SOURCE_FAILED       = "SOURCE_FAILED"
LIMITATION_SOURCE_KEY_MISMATCH = "SOURCE_KEY_MISMATCH"   # e.g. two sources describing the
                                                           # same entities disagree on which
                                                           # keys (TIDs, names, ...) exist


@dataclass
class CoverageLimitation:
    """One specific, machine-readable way coverage fell short. `scope`
    names the granularity affected (e.g. "dump", "thread", "module");
    `affected_count`/`unavailable_fields` are optional detail a renderer
    or a future JSON `limitations` array can use. Human text is never
    written at the call site -- see render_limitation()."""
    code: str
    source: str
    scope: "str | None" = None
    affected_count: "int | None" = None
    unavailable_fields: list = field(default_factory=list)
    detail: "str | None" = None


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

    if limitation.code == LIMITATION_SOURCE_ABSENT:
        return f"{name} not present in this dump"

    if limitation.code == LIMITATION_SOURCE_FAILED:
        detail = f": {limitation.detail}" if limitation.detail else ""
        return f"{name} present but could not be read{detail}"

    if limitation.code == LIMITATION_SOURCE_KEY_MISMATCH:
        count = limitation.affected_count if limitation.affected_count is not None else "some"
        fields = (f" ({', '.join(limitation.unavailable_fields)} unavailable for those)"
                   if limitation.unavailable_fields else "")
        scope = limitation.scope or "item"
        return f"{count} {scope}(s) missing from {name}{fields}"

    # Unknown code -- still produce something rather than raising, since
    # a limitation reaching here is a display-layer concern, not a fatal
    # error; the detail field (if any) is the best fallback text.
    return limitation.detail or f"{name}: {limitation.code}"


# ── Coverage report ──────────────────────────────────────────────────────

COVERAGE_COMPLETE      = "complete"
COVERAGE_PARTIAL       = "partial"
COVERAGE_NOT_EVALUATED = "not_evaluated"


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


def build_coverage_report(sources: dict, limitations: list,
                           required_sources: "set | None" = None) -> CoverageReport:
    """
    The single reduction rule every command's coverage status derives
    from:

      - If `required_sources` is given and non-empty, and EVERY one of
        those sources is SOURCE_ABSENT, the command had literally
        nothing to evaluate: not_evaluated, regardless of any other
        limitation. A required source that's SOURCE_FAILED (not ABSENT)
        does NOT trigger this -- evaluation was attempted and hit an
        error, which is 'partial' territory, not 'never evaluated'.
      - Otherwise: any limitation at all -> partial; none -> complete.

    Validated against every coverage rule already hand-built this
    session: a single required source (list/modules: absence ->
    not_evaluated), multiple required sources (threads: not_evaluated
    only when ALL of {threads, thread_info} are absent), and an empty
    required-source set (sysinfo: never not_evaluated because dump_file
    is always real regardless of which of its 5 sources exist; pid:
    not_evaluated only when all 3 of its sources are absent -- three
    required sources, same rule as threads' two).
    """
    required_sources = required_sources or set()
    if required_sources and all(
        sources[name].state == SOURCE_ABSENT for name in required_sources
    ):
        status = COVERAGE_NOT_EVALUATED
    elif limitations:
        status = COVERAGE_PARTIAL
    else:
        status = COVERAGE_COMPLETE
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
    if status == COVERAGE_COMPLETE:
        return EXIT_OK
    if status == COVERAGE_PARTIAL:
        return EXIT_PARTIAL
    if status == COVERAGE_NOT_EVALUATED:
        return EXIT_NOT_EVALUATED
    raise ValueError(f"unknown coverage status: {status!r}")
