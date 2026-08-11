"""The canonical, recursively immutable domain model for the named-pipe
C2 / lateral-movement hunter -- `PipeReport` plus the coverage snapshot and
evidence container it is built from. Mirrors
`dumpex.hunt.injection.domain`, `dumpex.hunt.encoding.domain`, and
`dumpex.hunt.stomping.domain` (the three completed reference pilots): see
those modules' own docstrings for the general "one canonical result
representation" rationale this module applies to the pipe hunter.

Before this migration, `dumpex.hunt.pipe.aggregate.Report` kept the same
facts several times over: a `findings` dict (JSON-facing, holding rendered
`Finding.to_dict()` entries AND the raw evidence lists), a `findings_list`
(the same findings a second time, as `Finding` objects), a `score`/
`status`/`coverage_status`/`coverage_reasons` field that each duplicated
the identically-named `findings` key, an `evaluated`/
`handle_stream_available` pair, a pre-rendered `verdict_reason` string, the
whole `handle_scan`/`pipe_name_scan`/`correlation` scan results (holding
live minidump `Handle`/`MinidumpMemoryInfo`/`ThreadInfo` objects, a live
`CoverageTracker`, and both live `ScanBudget`s), and a `coverage_report`
attribute assigned from OUTSIDE the aggregator entirely. Nothing
structural kept any of those in agreement.

`PipeReport` stores each fact exactly once:

  score      -- 0..3, this hunter's own decision (an OS-confirmed open
                pipe handle matching a known framework naming convention,
                and/or a handle-confirmed pipe corroborated by nearby C2
                context and/or live RIP/EIP execution).
  results    -- the checks this hunter produced, as typed
                `dumpex.hunt._domain.CheckResult`s carrying typed evidence.
  evidence   -- the observed items, in their hunter-meaningful buckets;
                the SAME objects `results` reference, never a copy.
  coverage   -- the immutable snapshot of what this run could and could
                not see.

and DERIVES everything else -- `status`, `verdict_level`, `confidence`,
`lead_count`, `review_priority`, `max_score` -- as properties, through the
same shared reducers (`dumpex.hunt._coverage`, `dumpex.hunt._finding`)
`aggregate.py` calls.
"""
from dataclasses import dataclass, field

from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._domain import CheckResult, require_recursively_immutable, as_tuple
from dumpex.hunt._finding import (
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.pipe.models import (
    C2ContextEvidence, CorroboratedHandleEvidence, FrameworkStringHitEvidence,
    PipeHandleEvidence, PipeStringEvidence, StartAddressLeadEvidence, UnbackedThreadEvidence,
)
from dumpex.output.coverage import ScanTarget, format_scan_target_preview

# This hunter's own score -> verdict_level table (see
# dumpex.hunt._finding.verdict_level) -- the canonical home for it is here,
# on the domain model that owns the score, rather than in aggregate.py
# (which imports it from here).
#
#   1 -- a handle-confirmed pipe matches a known C2/lateral-movement
#        framework naming convention, with no further corroboration.
#   2 -- ANY handle-confirmed pipe is corroborated by nearby C2 context OR
#        live RIP/EIP execution.
#   3 -- corroborated by BOTH at once.
VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "likely", 3: "high"}

# The top of this hunter's score scale.
MAX_SCORE = 3

# Labels for the region scan's own coverage gaps, in ONE place because
# THREE consumers describe the same gap: the hunter's coverage_reasons
# (report_facts.project_coverage_v1), the structured CoverageReport
# (report_facts.project_coverage_report), and report_console.py's COVERAGE
# section/impact. Worded and ordered to match
# `dumpex.hunt._coverage.CoverageTracker.build_reasons` exactly -- including
# the same bounded VA/size preview the structured
# SCAN_REGION_OVERSIZED_SKIPPED limitation renders
# (`format_scan_target_preview`), so the console reason and --json's own
# coverage.reasons describe the identical skips identically.
#
# These are byte-identical to the label strings the pre-migration
# `aggregate.build_report()` passed to `CoverageTracker.build_reasons()`:
# the v1.1 `coverage_reasons` array is part of the frozen output contract
# (tests/integration/test_hunt_cli_compat_freeze.py), so the wording moved
# here without changing.
OVERSIZE_LABEL    = "oversized region(s) skipped"
READ_FAILED_LABEL = "region(s) failed to read"
SHORT_READ_LABEL  = ("region(s) returned fewer bytes than declared (short read) — "
                      "not fully scanned")


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {value!r}")


def _require_str(value, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, got {value!r}")


def _require_count(value, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be a non-negative int, got {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_scan_targets(value, field_name: str) -> tuple:
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if type(item) is not ScanTarget:
            raise TypeError(
                f"{field_name}[{index}] must be a ScanTarget, got "
                f"{type(item).__name__}: {item!r}")
    require_recursively_immutable(items, field_name)
    return items


def _require_str_items(value, field_name: str) -> tuple:
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if type(item) is not str:
            raise TypeError(
                f"{field_name}[{index}] must be a str, got {type(item).__name__}: {item!r}")
    return items


def _require_items_of(value, field_name: str, expected) -> tuple:
    """Normalize to a tuple and require every item to be an instance of
    `expected`, immutable, and not a duplicate (by equality) of another
    item already in the bucket -- the same poison-object/dedup barrier
    `dumpex.hunt.injection.domain`/`dumpex.hunt.encoding.domain`/
    `dumpex.hunt.stomping.domain` apply to their own evidence buckets.
    See `dumpex.hunt.pipe.models.dedupe_evidence` for where an exact
    duplicate observation is legitimately collapsed instead (the scan
    layer that observed it)."""
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if not isinstance(item, expected):
            raise TypeError(
                f"{field_name}[{index}] must be a {expected.__name__}, got "
                f"{type(item).__name__}: {item!r}")
    require_recursively_immutable(items, field_name)
    seen = []
    for index, item in enumerate(items):
        if any(item == earlier for earlier in seen):
            raise ValueError(
                f"{field_name}[{index}] is already in this bucket (identical "
                f"or equal to an earlier item): {item!r}")
        seen.append(item)
    return items


def _require_subset(subset, superset, subset_name: str, superset_name: str) -> None:
    """Every item of `subset` must BE (by identity) an item of `superset` --
    mirrors `dumpex.hunt.stomping.domain._require_subset`: correlation.py
    pairs an EXISTING handle/string-lead evidence object with its
    corroborating signal, never a reconstructed equal copy."""
    allowed = {id(item) for item in superset}
    for item in subset:
        if id(item) not in allowed:
            raise ValueError(
                f"{subset_name} holds an item that is not one of "
                f"{superset_name}'s own objects: {item!r}")


@dataclass(frozen=True)
class CoverageSnapshot:
    """What this run could and could not see, as FACTS rather than as
    rendered reasons.

    Replaces the pre-migration mix of a live `CoverageTracker`, two live
    `ScanBudget`s, and two loose booleans that `aggregate.build_report()`
    and `_pipe_coverage_report()` each interrogated separately (and could
    therefore answer differently).

    The two budgets stay SEPARATE -- see dumpex/hunt/pipe/config.py for why
    merging them would let one signal's exhaustion silently misreport the
    other signal's coverage.
    """
    memory_info_stream:  bool
    handle_data_stream:  bool

    # The pipe-name/C2 region scan's own gaps. Oversized skips keep full
    # region identity (a ScanTarget each -- what --extract/--strings needs
    # to act on the gap); read failures/short reads are counts, matching
    # every other hunter's own generic gap reporting.
    skipped_oversize: tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    read_failed:      int = 0
    short_reads:      int = 0

    # The two INDEPENDENT whole-hunt budgets, each with the reason it ran
    # out ("deadline"/"max_hits"/... -- see dumpex.hunt._budget.ScanBudget).
    c2_budget_exhausted:        bool = False
    c2_budget_reason:           str = ""
    pipe_name_budget_exhausted: bool = False
    pipe_name_budget_reason:    str = ""

    # Pipe references found inside Microsoft system DLLs -- NOT a gap:
    # those regions WERE fully read, and a pipe name in
    # System32/SysWOW64/WinSxS code is expected. A scan-detail fact
    # report_console.py surfaces under --verbose.
    image_pipe_refs:    int = 0
    image_pipe_modules: tuple = field(default_factory=tuple)   # tuple[str]

    def __post_init__(self):
        for name in ("memory_info_stream", "handle_data_stream",
                     "c2_budget_exhausted", "pipe_name_budget_exhausted"):
            _require_bool(getattr(self, name), f"CoverageSnapshot.{name}")
        for name in ("read_failed", "short_reads", "image_pipe_refs"):
            _require_count(getattr(self, name), f"CoverageSnapshot.{name}")
        for name in ("c2_budget_reason", "pipe_name_budget_reason"):
            _require_str(getattr(self, name), f"CoverageSnapshot.{name}")
        object.__setattr__(self, "skipped_oversize", _require_scan_targets(
            self.skipped_oversize, "CoverageSnapshot.skipped_oversize"))
        object.__setattr__(self, "image_pipe_modules", _require_str_items(
            self.image_pipe_modules, "CoverageSnapshot.image_pipe_modules"))

    # ── Derived coverage facts ────────────────────────────────────────────

    @property
    def budget_exhausted(self) -> bool:
        """Either whole-hunt budget having run out. The v1.1 findings
        dict's own `budget_exhausted` key, derived rather than stored."""
        return self.c2_budget_exhausted or self.pipe_name_budget_exhausted

    @property
    def region_scan_complete(self) -> bool:
        """Whether the `\\pipe\\` region walk itself got through every
        eligible region -- the pre-migration `coverage_counts.complete and
        not budget_exhausted`, and the v1.1 findings dict's own
        `scan_complete` key."""
        return not (self.skipped_oversize or self.read_failed or self.short_reads
                    or self.budget_exhausted)

    @property
    def evaluated(self) -> bool:
        """OR-of-presence, deliberately: EITHER stream alone is enough for
        this hunter to have done real work. With HandleDataStream but no
        MemoryInfoListStream the scored handle checks still run (the
        string scan simply finds nothing); with MemoryInfoListStream but no
        HandleDataStream the unscored string scan still runs and still
        produces real leads. Only losing BOTH means nothing was looked at
        at all.

        This is why `report_facts.project_coverage_report` gives
        `memory_info`/`handle_data` ONE combined evaluation group, unlike
        stomping's AND-of-presence two-group shape.
        """
        return self.memory_info_stream or self.handle_data_stream

    @property
    def complete(self) -> bool:
        """HandleDataStream is required, plus a region walk that finished:
        the PRIMARY, scored check is handle-anchored, so without that
        stream a score of 0 is "never checked", not "checked and clean".

        `memory_info_stream` deliberately does NOT appear here -- only in
        `evaluated` above. A dump captured with MiniDumpWithHandleData but
        no MemoryInfoListStream still ran this hunter's whole scored path
        to completion; calling that "partial" would report a coverage gap
        where the scored signal has none (see
        tests/hunt/test_pipe_collect.py::
        test_memory_info_absent_alone_does_not_force_partial).
        """
        return self.handle_data_stream and self.region_scan_complete

    @property
    def status(self) -> str:
        return derive_coverage_status(self.evaluated, self.complete)

    def region_gap_reasons(self) -> tuple:
        """The region scan's coverage gaps as human-readable reason
        strings, in `CoverageTracker.build_reasons`' own fixed order --
        empty when the walk got through every eligible region within both
        budgets.

        The ONE canonical wording (see OVERSIZE_LABEL/READ_FAILED_LABEL/
        SHORT_READ_LABEL above): `report_facts.project_coverage_v1` embeds
        these in `coverage_reasons`, and report_console.py renders them in
        COVERAGE. Deriving them from the snapshot means the two can never
        describe the same skip two slightly different ways.
        """
        reasons = []
        if self.skipped_oversize:
            reasons.append(f"{len(self.skipped_oversize)} {OVERSIZE_LABEL}: "
                            f"{format_scan_target_preview(self.skipped_oversize)}")
        if self.read_failed:
            reasons.append(f"{self.read_failed} {READ_FAILED_LABEL}")
        if self.short_reads:
            reasons.append(f"{self.short_reads} {SHORT_READ_LABEL}")
        if self.c2_budget_exhausted:
            reasons.append(f"C2-context scan budget exhausted ({self.c2_budget_reason})")
        if self.pipe_name_budget_exhausted:
            reasons.append(f"pipe-name scan budget exhausted ({self.pipe_name_budget_reason})")
        return tuple(reasons)


@dataclass(frozen=True)
class PipeEvidence:
    """Every item this hunter observed, in the buckets its own output
    contract is defined in terms of -- see
    `dumpex.hunt.injection.domain.InjectionEvidence` for the general
    "held once, cited by identity" rationale.

    `corroborated_handles`/`start_address_leads` are NOT independent
    buckets: each entry pairs one of `handle_pipes`' OWN objects and one of
    `string_leads`' OWN objects (by identity, enforced below) with the
    signal that corroborated them, the same way
    `dumpex.hunt.stomping.domain.StompingEvidence` enforces its
    `rip_correlated_leads` against `protection_leads`.

    There is deliberately no `framework_pipes` bucket: the framework-
    matched handles are exactly `framework_handles` below, a derived view
    of `handle_pipes`. Storing that subset separately is what let the
    pre-migration `HandleScan` carry three parallel lists over the same
    handles.
    """
    handle_pipes:          tuple = field(default_factory=tuple)
    string_leads:          tuple = field(default_factory=tuple)
    corroborated_handles:  tuple = field(default_factory=tuple)
    start_address_leads:   tuple = field(default_factory=tuple)
    c2_context:            tuple = field(default_factory=tuple)
    framework_string_hits: tuple = field(default_factory=tuple)
    unbacked_threads:      tuple = field(default_factory=tuple)

    _BUCKET_TYPES = (
        ("handle_pipes",          PipeHandleEvidence),
        ("string_leads",          PipeStringEvidence),
        ("corroborated_handles",  CorroboratedHandleEvidence),
        ("start_address_leads",   StartAddressLeadEvidence),
        ("c2_context",            C2ContextEvidence),
        ("framework_string_hits", FrameworkStringHitEvidence),
        ("unbacked_threads",      UnbackedThreadEvidence),
    )

    def __post_init__(self):
        for name, expected in self._BUCKET_TYPES:
            object.__setattr__(self, name, _require_items_of(
                getattr(self, name), f"PipeEvidence.{name}", expected))
        for name in ("corroborated_handles", "start_address_leads"):
            entries = getattr(self, name)
            _require_subset([e.handle for e in entries], self.handle_pipes,
                             f"PipeEvidence.{name}", "PipeEvidence.handle_pipes")
            _require_subset([e.string_hit for e in entries], self.string_leads,
                             f"PipeEvidence.{name}", "PipeEvidence.string_leads")
        # `c2_context`/`framework_string_hits` each cite one of
        # `string_leads`' OWN objects (by identity) too, via their own
        # `string_hit` field -- the same "held once, cited by identity"
        # guarantee `corroborated_handles`/`start_address_leads` already
        # get above. Without this, a Report could accept a C2/framework
        # string observation that describes a region/name the Report's own
        # `string_leads` bucket never actually holds.
        for name in ("c2_context", "framework_string_hits"):
            entries = getattr(self, name)
            _require_subset([e.string_hit for e in entries], self.string_leads,
                             f"PipeEvidence.{name}", "PipeEvidence.string_leads")

    @property
    def framework_handles(self) -> tuple:
        """The handle-confirmed pipes whose names match a known
        C2/lateral-movement framework naming convention -- a DERIVED view
        of `handle_pipes`, never a stored second bucket, so the two can
        never disagree. This is what the v1.1 `framework_pipes` key and the
        v2 `PipeDetails.framework_pipes` field both project from."""
        return tuple(h for h in self.handle_pipes if h.framework is not None)

    def canonical_items(self) -> tuple:
        """Every evidence object this container holds at the top level --
        the exact set a `CheckResult` on the same Report may cite."""
        items = []
        for name, _expected in self._BUCKET_TYPES:
            items.extend(getattr(self, name))
        return tuple(items)


@dataclass(frozen=True)
class PipeReport:
    """The pipe hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: a `MinidumpFile`/`mf`, a
    `read_region`/`get_thread_contexts` callable, a live `CoverageTracker`
    or `ScanBudget`, a rules/pattern list, a verbosity or DetailLevel flag,
    a `Finding`/`HunterRecord`/legacy-dict/`CoverageReport` field, and any
    console-formatted string (including the pre-migration
    `verdict_reason`, which was rendered prose stored on the model).
    """
    score: int
    coverage: CoverageSnapshot
    results:  tuple = field(default_factory=tuple)
    evidence: PipeEvidence = field(default_factory=PipeEvidence)

    def __post_init__(self):
        _require_count(self.score, "PipeReport.score")
        if self.score > MAX_SCORE:
            raise ValueError(
                f"PipeReport.score must be <= {MAX_SCORE}, got {self.score}")
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"PipeReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, PipeEvidence):
            raise TypeError(
                f"PipeReport.evidence must be a PipeEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        object.__setattr__(self, "results", _require_items_of(
            self.results, "PipeReport.results", CheckResult))
        self._require_results_cite_this_reports_own_evidence()

    def _require_results_cite_this_reports_own_evidence(self) -> None:
        canonical = {id(item) for item in self.evidence.canonical_items()}
        for result in self.results:
            for item in result.evidence:
                if id(item) not in canonical:
                    raise ValueError(
                        f"PipeReport: check {result.check!r} cites evidence "
                        f"that is not one of this Report's own evidence objects: "
                        f"{item!r}")

    @property
    def max_score(self) -> int:
        return MAX_SCORE

    @property
    def status(self) -> str:
        return derive_status(self.coverage.evaluated, self.score > 0, self.coverage.complete)

    @property
    def confidence(self) -> str:
        return overall_confidence(self.results, self.score)

    @property
    def verdict_level(self) -> str:
        return verdict_level(self.score, VERDICT_LEVEL_BY_SCORE, status=self.status)

    @property
    def lead_count(self) -> int:
        return lead_count(self.results)

    @property
    def review_priority(self) -> str:
        return review_priority(self.results, self.score, self.status)
