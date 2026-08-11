"""The canonical, recursively immutable domain model for the module-
stomping hunter -- `StompingReport` plus the coverage snapshot and evidence
container it is built from. Mirrors `dumpex.hunt.injection.domain` and
`dumpex.hunt.encoding.domain` (the two completed reference pilots): see
those modules' own docstrings for the general "one canonical result
representation" rationale this module applies to the stomping hunter.

Before this migration, `dumpex.hunt.stomping.aggregate.Report` kept the
same facts several times over: a `findings` dict (JSON-facing, holding
rendered `Finding.to_dict()` entries), a `findings_list` (the same findings
a second time, as `Finding` objects), a `verified_changes` list ALSO held
under `findings["verified_changes"]`, a `score`/`status`/`coverage_status`/
`coverage_reasons` field that each duplicated the identically-named
`findings` key, plus `ioc_scan` (the whole raw scan result, holding live
`MinidumpMemoryInfo`/`Module` objects), `ioc_coverage_reasons`, `ref_dir`
(a live filesystem path), and a `coverage_report` attribute assigned from
OUTSIDE the aggregator entirely. Nothing structural kept any of those in
agreement.

`StompingReport` stores each fact exactly once:

  score      -- 0..2, this hunter's own decision (a verified, relocation-
                normalized content diff, optionally corroborated by a
                thread's live RIP/EIP inside the changed bytes).
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
from dumpex.hunt.stomping.models import (
    IdentityMismatchEvidence, IocHitEvidence, ParseFailedEvidence, ProtectionLeadEvidence,
    RipCorrelatedLeadEvidence, VerifiedChangeEvidence,
)
from dumpex.output.coverage import ScanTarget, format_scan_target_preview

# This hunter's own score -> verdict_level table (see
# dumpex.hunt._finding.verdict_level) -- the canonical home for it is here,
# on the domain model that owns the score, rather than in aggregate.py
# (which imports it from here).
#
# No "3": this hunter's max score is 2 (verified change, optionally
# corroborated by live RIP/EIP — there's no third independent signal).
VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "high"}
# score==1 (verified content diff, no RIP corroboration) maps to "possible"
# rather than "likely" — see report_console.py's DETECTED verdict text for
# why: an uncorroborated diff is equally consistent with a benign
# hotpatch/EDR hook, so "likely [stomping]" would over-attribute intent
# from a table that's meant to be a plain display transform of the score,
# not a second place to encode that judgment call.

# The top of this hunter's score scale.
MAX_SCORE = 2

# Labels for the unscored IOC-string scan's own coverage gaps, in ONE place
# because THREE consumers describe the same gap: the hunter's
# coverage_reasons (report_facts.project_coverage_v1), the
# stomping.ioc_string_lead CheckResult's `limitations` (aggregate.py), and
# report_console.py's COVERAGE section/impact. Worded and ordered to match
# `dumpex.hunt._coverage.CoverageTracker.build_reasons` exactly -- including
# the same bounded VA/size preview the structured
# SCAN_REGION_OVERSIZED_SKIPPED limitation renders
# (`format_scan_target_preview`), so the console reason and --json's own
# coverage.reasons describe the identical skips identically. The wording
# says "never scanned", not "skipped": an analyst has to be able to tell
# that this memory was not looked at, not merely that something found in it
# was suppressed.
IOC_OVERSIZE_LABEL    = "oversized executable module region(s) never scanned for IOC strings"
IOC_READ_FAILED_LABEL = "region(s) failed to read and were not scanned for IOC strings"
IOC_SHORT_READ_LABEL  = ("region(s) returned fewer bytes than declared and were only "
                          "partially scanned for IOC strings")

# The 10 `coverage_counts` keys the v1.1 findings dict has always carried,
# in their historical order -- see CoverageSnapshot's own docstring for why
# the snapshot stores them as named fields instead of as a dict, and
# report_facts.project_coverage_v1 for where the dict is rebuilt.
COVERAGE_COUNT_FIELDS = (
    "modules_total", "headers_parsed", "sections_total", "sections_compared",
    "reference_missing", "reference_mismatch", "reference_read_failed",
    "memory_read_failed", "short_reads", "relocation_failed",
)


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {value!r}")


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
    `dumpex.hunt.injection.domain`/`dumpex.hunt.encoding.domain` apply to
    their own evidence buckets."""
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
    mirrors `dumpex.hunt.encoding.domain._require_subset`: correlation.py
    pairs an EXISTING `ProtectionLeadEvidence` with a thread, never a
    reconstructed equal copy."""
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

    The ten `modules_total`..`relocation_failed` counters replace the
    pre-migration mutable `coverage_counts: dict` -- named fields instead
    of a mapping, since a dict (or a `MappingProxyType` view of one) can
    never be recursively immutable (see `dumpex.hunt._domain.
    require_recursively_immutable`'s own docstring). The v1.1 dict is
    rebuilt, key-for-key, at projection time
    (report_facts.project_coverage_v1) -- see COVERAGE_COUNT_FIELDS.

    `ref_dir_supplied` is a plain bool, deliberately NOT the --ref-dir
    path: whether a reference directory was given is a coverage FACT the
    verdict depends on; the path itself is a live filesystem handle the
    domain model must not retain.

    Every one of the six reference/section counters is a reason the ONE
    scored signal in this hunter could not run to completion for at least
    one eligible section -- see `content_complete`. Bare pass/fail booleans
    can't distinguish "checked everything, all clean" from "silently
    skipped N sections", which is exactly the gap these close.
    """
    memory_info_stream: bool
    module_list_stream: bool
    ref_dir_supplied:   bool = False

    modules_total:         int = 0   # loaded modules the walk started from
    headers_parsed:        int = 0   # modules whose own PE header validated
    sections_total:        int = 0   # eligible (exec, non-writable) sections found
    sections_compared:     int = 0   # sections that got a real, identity-matched comparison
    reference_missing:     int = 0   # --ref-dir given, no matching file for the module
    reference_mismatch:    int = 0   # matching-name file found, header identity differs
    reference_read_failed: int = 0   # matching-name file found, couldn't be read/parsed
    memory_read_failed:    int = 0   # couldn't read the section's live memory bytes
    short_reads:           int = 0   # read succeeded but nothing usable could be compared
    relocation_failed:     int = 0   # delta != 0 but normalization couldn't be completed

    # Module HEADER reads that raised, and headers that failed PE
    # structural validation -- distinct from the per-SECTION counters
    # above, and from each other (a read that never returned bytes is not
    # the same fact as bytes that turned out not to be a valid header).
    header_read_failed:  int = 0
    header_parse_failed: int = 0

    # The unscored IOC-string sub-scan's own gaps. Oversized skips keep
    # full region identity (a ScanTarget each); read failures/short reads
    # are counts, matching every other hunter's own generic gap reporting.
    ioc_oversized:   tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    ioc_read_failed: int = 0
    ioc_short_reads: int = 0
    # Whitelisted network DLLs whose regions WERE scanned, just without the
    # network-IOC pattern set (network strings are expected there) -- not a
    # gap, a scan-detail fact report_console.py surfaces under --verbose.
    ioc_whitelisted_modules: tuple = field(default_factory=tuple)   # tuple[str]

    def __post_init__(self):
        for name in ("memory_info_stream", "module_list_stream", "ref_dir_supplied"):
            _require_bool(getattr(self, name), f"CoverageSnapshot.{name}")
        for name in (*COVERAGE_COUNT_FIELDS, "header_read_failed", "header_parse_failed",
                     "ioc_read_failed", "ioc_short_reads"):
            _require_count(getattr(self, name), f"CoverageSnapshot.{name}")
        object.__setattr__(self, "ioc_oversized", _require_scan_targets(
            self.ioc_oversized, "CoverageSnapshot.ioc_oversized"))
        object.__setattr__(self, "ioc_whitelisted_modules", _require_str_items(
            self.ioc_whitelisted_modules, "CoverageSnapshot.ioc_whitelisted_modules"))

    # ── Derived coverage facts ────────────────────────────────────────────

    @property
    def content_complete(self) -> bool:
        """Specifically about the ONE scored signal (the verified content
        diff): it requires --ref-dir AND every eligible section actually
        being compared, with zero failures of any kind along the way."""
        return (self.ref_dir_supplied
                and self.sections_compared == self.sections_total
                and not any((self.reference_missing, self.reference_mismatch,
                             self.reference_read_failed, self.memory_read_failed,
                             self.short_reads, self.relocation_failed)))

    @property
    def ioc_complete(self) -> bool:
        return not (self.ioc_oversized or self.ioc_read_failed or self.ioc_short_reads)

    @property
    def evaluated(self) -> bool:
        """Both streams are required: the module/section walk needs
        ModuleListStream to know which modules exist and
        MemoryInfoListStream to read live protections, so EITHER one being
        absent means the scored check never ran at all.

        This is also the ONE place coverage_status/status deliberately do
        NOT move together with the IOC sub-scan: that scan only needs
        MemoryInfoListStream (it does its own per-region module lookup and
        tolerates an absent module list), so it can still run -- and still
        find a real gap -- while this hunter is NOT_EVALUATED. The gap is
        still surfaced (see report_facts.project_coverage_report, which
        appends the IOC limitations to the already-built CoverageReport for
        exactly that case); it just cannot make a run that never evaluated
        anything read as though it had.
        """
        return self.memory_info_stream and self.module_list_stream

    @property
    def complete(self) -> bool:
        """Covers BOTH the scored verified-content diff and the unscored
        IOC-string region scan: a region the IOC scan skipped for being
        oversized, or could not read, is eligible memory this hunter never
        looked at, so nothing here may report "complete". That single
        boolean then flows into status the same way it does for every other
        hunter (dumpex.hunt._coverage.derive_status), which means a score-0
        run with an IOC gap is INCONCLUSIVE rather than
        NOT_DETECTED_IN_SCANNED_SCOPE.

        That is deliberate, not an accident of reusing one variable:

          - coverage_status and status are not independently choosable. The
            wire contract pins the pair (schema hunterRecord: status
            NOT_DETECTED_IN_SCANNED_SCOPE requires coverage.status
            "complete"; INCONCLUSIVE requires "partial"), and the typed
            CoverageReport report_facts.py builds turns ANY limitation into
            "partial". Recording the skipped regions -- which is the whole
            point -- therefore settles status too.
          - the alternative (record nothing, keep saying "complete") is
            exactly the bug this closes: an unexamined 5 MiB+ executable
            mapping reported as a clean, complete scan.

        What an IOC gap still does NOT do: change `score`, `verdict_level`
        for a real detection, or suppress any finding. A DETECTED run stays
        DETECTED with coverage_status "partial" (derive_status lets a real
        hit win over incomplete coverage), so an oversized region can
        neither invent nor hide a verified content change -- it only stops
        a score-0 result from being presented as a clean bill of health
        over memory nobody read.
        """
        return not (self.header_read_failed or self.header_parse_failed
                    or not self.content_complete or not self.ioc_complete)

    @property
    def status(self) -> str:
        return derive_coverage_status(self.evaluated, self.complete)

    def ioc_gap_reasons(self) -> tuple:
        """The IOC sub-scan's coverage gaps as human-readable reason
        strings, in `CoverageTracker.build_reasons`' own fixed order --
        empty when the scan got through every eligible region.

        The ONE canonical wording (see IOC_*_LABEL above): aggregate.py
        embeds these in the stomping.ioc_string_lead CheckResult's
        `limitations`, report_facts.py appends them to `coverage_reasons`,
        and report_console.py renders them in COVERAGE. Deriving them from
        the snapshot means those three can never describe the same skip
        three slightly different ways.
        """
        reasons = []
        if self.ioc_oversized:
            reasons.append(f"{len(self.ioc_oversized)} {IOC_OVERSIZE_LABEL}: "
                            f"{format_scan_target_preview(self.ioc_oversized)}")
        if self.ioc_read_failed:
            reasons.append(f"{self.ioc_read_failed} {IOC_READ_FAILED_LABEL}")
        if self.ioc_short_reads:
            reasons.append(f"{self.ioc_short_reads} {IOC_SHORT_READ_LABEL}")
        return tuple(reasons)

    def coverage_counts(self) -> dict:
        """The v1.1 `coverage_counts` dict, rebuilt key-for-key from the
        named fields above -- a FRESH dict on every call (never a stored
        one), so a caller mutating what a projector handed it can never
        reach back into this snapshot."""
        return {name: getattr(self, name) for name in COVERAGE_COUNT_FIELDS}


@dataclass(frozen=True)
class StompingEvidence:
    """Every item this hunter observed, in the buckets its own output
    contract is defined in terms of -- see
    `dumpex.hunt.injection.domain.InjectionEvidence` for the general
    "held once, cited by identity" rationale.

    `rip_correlated_leads` is NOT an independent bucket: each entry pairs
    one of `protection_leads`' OWN objects (by identity, enforced below)
    with the thread executing inside it, the same way
    `dumpex.hunt.encoding.domain.EncodingEvidence` enforces its
    `pe_hits`/`shellcode_hits` partitions against the source hit buckets.
    """
    protection_leads:     tuple = field(default_factory=tuple)
    rip_correlated_leads: tuple = field(default_factory=tuple)
    verified_changes:     tuple = field(default_factory=tuple)
    identity_mismatches:  tuple = field(default_factory=tuple)
    parse_failures:       tuple = field(default_factory=tuple)
    ioc_hits:             tuple = field(default_factory=tuple)

    _BUCKET_TYPES = (
        ("protection_leads",     ProtectionLeadEvidence),
        ("rip_correlated_leads", RipCorrelatedLeadEvidence),
        ("verified_changes",     VerifiedChangeEvidence),
        ("identity_mismatches",  IdentityMismatchEvidence),
        ("parse_failures",       ParseFailedEvidence),
        ("ioc_hits",             IocHitEvidence),
    )

    def __post_init__(self):
        for name, expected in self._BUCKET_TYPES:
            object.__setattr__(self, name, _require_items_of(
                getattr(self, name), f"StompingEvidence.{name}", expected))
        _require_subset([c.lead for c in self.rip_correlated_leads], self.protection_leads,
                         "StompingEvidence.rip_correlated_leads",
                         "StompingEvidence.protection_leads")

    def canonical_items(self) -> tuple:
        """Every evidence object this container holds at the top level --
        the exact set a `CheckResult` on the same Report may cite."""
        items = []
        for name, _expected in self._BUCKET_TYPES:
            items.extend(getattr(self, name))
        return tuple(items)


@dataclass(frozen=True)
class StompingReport:
    """The stomping hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: a `MinidumpFile`/`mf`, a
    `read_region`/`get_thread_contexts` callable, a `--ref-dir` PATH (only
    `coverage.ref_dir_supplied`, a bool), a rules/whitelist/pattern list, a
    verbosity or DetailLevel flag, a `Finding`/`HunterRecord`/legacy-dict/
    `CoverageReport` field, and any console-formatted string.
    """
    score: int
    coverage: CoverageSnapshot
    results:  tuple = field(default_factory=tuple)
    evidence: StompingEvidence = field(default_factory=StompingEvidence)

    def __post_init__(self):
        _require_count(self.score, "StompingReport.score")
        if self.score > MAX_SCORE:
            raise ValueError(
                f"StompingReport.score must be <= {MAX_SCORE}, got {self.score}")
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"StompingReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, StompingEvidence):
            raise TypeError(
                f"StompingReport.evidence must be a StompingEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        object.__setattr__(self, "results", _require_items_of(
            self.results, "StompingReport.results", CheckResult))
        self._require_results_cite_this_reports_own_evidence()

    def _require_results_cite_this_reports_own_evidence(self) -> None:
        canonical = {id(item) for item in self.evidence.canonical_items()}
        for result in self.results:
            for item in result.evidence:
                if id(item) not in canonical:
                    raise ValueError(
                        f"StompingReport: check {result.check!r} cites evidence "
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
