"""Immutable domain model for Cobalt Strike configuration analysis.

Structurally valid configs, independent memory context, scan coverage, and
derived verdict fields are validated together. Static evidence does not encode a
live or dormant activity claim.
"""
from dataclasses import dataclass, field

from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._domain import CheckResult, require_recursively_immutable, as_tuple
from dumpex.hunt._finding import (
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.cs_beacon.models import ConfigEvidence, CorroborationEvidence
from dumpex.output.coverage import ScanTarget

# This hunter's own score -> verdict_level table (see
# dumpex.hunt._finding.verdict_level) -- the canonical home for it is here,
# on the domain model that owns the score (previously
# dumpex.hunt.cs_beacon.schema._VERDICT_LEVEL_BY_SCORE).
#
#   1 -- at least one structurally-valid config found, with no independent
#        memory-context corroboration ("likely": a beacon config surviving
#        in memory is itself strong, hard-to-fake evidence).
#   2 -- additionally corroborated by memory context independent of the
#        config bytes themselves.
VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}

# The top of this hunter's score scale.
MAX_SCORE = 2


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}: {value!r}")


def _require_count(value, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be a non-negative int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


def _require_str(value, field_name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a str, got {type(value).__name__}: {value!r}")


def _require_optional_str(value, field_name: str) -> None:
    if value is not None:
        _require_str(value, field_name)


def _require_scan_targets(value, field_name: str) -> tuple:
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if type(item) is not ScanTarget:
            raise TypeError(
                f"{field_name}[{index}] must be a ScanTarget, got {type(item).__name__}: "
                f"{item!r}")
    return items


def _require_items_of(value, field_name: str, expected) -> tuple:
    """Normalize to a tuple and require every item to be an instance of
    `expected`, immutable, and not a duplicate (by equality) of another
    item already in the bucket -- the same poison-object/dedup barrier
    every other migrated hunter's own domain.py applies to its evidence
    buckets."""
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
                f"{field_name}[{index}] is already in this bucket (identical or equal to an "
                f"earlier item): {item!r}")
        seen.append(item)
    return items


def _require_subset(subset, superset, subset_name: str, superset_name: str) -> None:
    """Every item of `subset` must BE (by identity) an item of `superset` --
    mirrors dumpex.hunt.hollowing.domain._require_subset: context.py pairs
    the EXISTING hit objects, never reconstructed equal copies."""
    allowed = {id(item) for item in superset}
    for item in subset:
        if id(item) not in allowed:
            raise ValueError(
                f"{subset_name} holds an item that is not one of {superset_name}'s own "
                f"objects: {item!r}")


@dataclass(frozen=True)
class ScanDiagnostics:
    """What scanner.py actually did across every captured memory segment --
    resource-budget/coverage FACTS, resolved once at scan time, rather than
    a live `CoverageTracker`/`ScanOutcome` the Report would otherwise have
    to keep reachable. Mirrors `dumpex.hunt.hollowing.domain.
    CoverageSnapshot`'s own "facts, not rendered reasons" rule -- every
    coverage_reasons/console text string is derived FROM these fields by
    report_facts.py, never stored redundantly here.
    """
    segment_count:              int
    total_candidates:           int = 0
    total_decoded_bytes:        int = 0
    total_scanned_bytes:        int = 0
    skipped_oversize_targets:   tuple = field(default_factory=tuple)
    read_failed_targets:        tuple = field(default_factory=tuple)
    short_read_targets:         tuple = field(default_factory=tuple)
    budget_exhausted:           bool = False
    budget_reason:               "str | None" = None
    budget_exhausted_targets:   tuple = field(default_factory=tuple)
    budget_exhausted_kind:       "str | None" = None
    budget_exhausted_limit:      "int | None" = None
    budget_exhausted_consumed:   "int | None" = None
    # The scan's reconciliation ledger. `segment_count` is every segment
    # in the dump; `eligible_total` is the subset this scan actually took
    # into scope (a whole-scan budget can stop the walk early), and
    # `scanned`/`not_applicable` plus the read-failed/oversize target
    # tuples above are the outcomes those eligible segments reached.
    scanned:                     int = 0
    eligible_total:              int = 0
    eligible_bytes:              int = 0
    not_applicable:              int = 0
    budget_skipped:              int = 0
    unaccounted:                 int = 0
    over_accounted:              int = 0

    def __post_init__(self):
        _require_count(self.segment_count, "ScanDiagnostics.segment_count")
        _require_count(self.total_candidates, "ScanDiagnostics.total_candidates")
        _require_count(self.total_decoded_bytes, "ScanDiagnostics.total_decoded_bytes")
        _require_count(self.total_scanned_bytes, "ScanDiagnostics.total_scanned_bytes")
        for name in ("scanned", "eligible_total", "eligible_bytes", "not_applicable",
                     "budget_skipped", "unaccounted", "over_accounted"):
            _require_count(getattr(self, name), f"ScanDiagnostics.{name}")
        object.__setattr__(self, "skipped_oversize_targets", _require_scan_targets(
            self.skipped_oversize_targets, "ScanDiagnostics.skipped_oversize_targets"))
        object.__setattr__(self, "read_failed_targets", _require_scan_targets(
            self.read_failed_targets, "ScanDiagnostics.read_failed_targets"))
        object.__setattr__(self, "short_read_targets", _require_scan_targets(
            self.short_read_targets, "ScanDiagnostics.short_read_targets"))
        _require_bool(self.budget_exhausted, "ScanDiagnostics.budget_exhausted")
        _require_optional_str(self.budget_reason, "ScanDiagnostics.budget_reason")
        object.__setattr__(self, "budget_exhausted_targets", _require_scan_targets(
            self.budget_exhausted_targets, "ScanDiagnostics.budget_exhausted_targets"))
        _require_optional_str(self.budget_exhausted_kind, "ScanDiagnostics.budget_exhausted_kind")
        _require_optional_count(self.budget_exhausted_limit,
                                 "ScanDiagnostics.budget_exhausted_limit")
        _require_optional_count(self.budget_exhausted_consumed,
                                 "ScanDiagnostics.budget_exhausted_consumed")
        require_recursively_immutable(self, "ScanDiagnostics")

    @property
    def skipped_oversize(self) -> int:
        return len(self.skipped_oversize_targets)

    @property
    def read_failed(self) -> int:
        return len(self.read_failed_targets)

    @property
    def short_reads(self) -> int:
        return len(self.short_read_targets)

    @property
    def has_real_budget_gap(self) -> bool:
        """`budget_exhausted` alone is NOT a coverage gap -- it can be True
        with an EMPTY `budget_exhausted_targets` when the whole-scan budget
        is only discovered exhausted after the very last segment already
        finished its own candidate scan cleanly (pure wall-clock/resource
        telemetry, nothing left unexamined). Only a non-empty target list
        means genuinely unresolved scope."""
        return self.budget_exhausted and bool(self.budget_exhausted_targets)

    @property
    def accounted(self) -> int:
        """Every disposition carried across this boundary, summed exactly
        as `dumpex.hunt._coverage.CoverageTracker.accounted` sums them --
        see its DISPOSITION_COUNTERS for the set both have to agree on."""
        return (self.scanned + self.not_applicable + self.budget_skipped
                + self.read_failed + self.skipped_oversize)

    @property
    def ledger_imbalance(self) -> int:
        """Items with no trustworthy outcome BEYOND the two direction
        counts. The books balance when the dispositions plus the items
        nobody dispositioned equal the items taken into scope plus the
        outcomes that belonged to no item:

            accounted + unaccounted == eligible_total + over_accounted

        Anything left over is a count that did not survive the trip from
        the scan to here -- invisible to both direction counts, since a
        counter that never arrived reads as zero."""
        return abs(self.accounted + self.unaccounted
                   - self.eligible_total - self.over_accounted)

    @property
    def reconciled(self) -> bool:
        """Every eligible item accounted for exactly once, nothing
        accounted for that was never eligible, and the books balancing --
        see `ledger_imbalance`."""
        return (not self.unaccounted and not self.over_accounted
                and not self.ledger_imbalance)


    @property
    def unreconciled(self) -> int:
        """Segments with no trustworthy outcome, in every direction at once:
        taken into scope and never dispositioned, dispositioned without
        being in scope, and whatever the books are still short by. One
        number, because that is what a reader has to act on -- the
        directions are what the reasons distinguish."""
        return (self.unaccounted + self.over_accounted
                + self.ledger_imbalance)

    @property
    def scan_complete(self) -> bool:
        """True iff every eligible segment reached a recorded outcome and
        none of those outcomes was a gap. Does not by itself decide
        `CoverageSnapshot.complete` -- that also needs `mem_info_available`
        and the thread-context gap."""
        return not (self.skipped_oversize or self.read_failed or self.short_reads
                    or self.has_real_budget_gap) and self.reconciled


@dataclass(frozen=True)
class CoverageSnapshot:
    """What this CS Beacon run could and could not see, as FACTS.

      scan                          -- this run's own `ScanDiagnostics`.
      mem_info_available            -- MemoryInfoListStream present and
                                        non-empty. Gates region/execution-
                                        context corroboration for every hit,
                                        NOT config detection itself -- a
                                        structurally-valid config still
                                        scores at least 1 without it.
      thread_list_stream_available  -- ThreadListStream present and
                                        non-empty.
      threads_total                 -- total thread count from ThreadList.
      contexts_parsed                -- how many of those had a parsed
                                        CONTEXT (RIP/EIP).
    """
    scan:                          ScanDiagnostics
    mem_info_available:            bool = False
    thread_list_stream_available:  bool = False
    threads_total:                  int = 0
    contexts_parsed:                int = 0

    def __post_init__(self):
        if not isinstance(self.scan, ScanDiagnostics):
            raise TypeError(
                f"CoverageSnapshot.scan must be a ScanDiagnostics, got "
                f"{type(self.scan).__name__}: {self.scan!r}")
        _require_bool(self.mem_info_available, "CoverageSnapshot.mem_info_available")
        _require_bool(self.thread_list_stream_available,
                      "CoverageSnapshot.thread_list_stream_available")
        _require_count(self.threads_total, "CoverageSnapshot.threads_total")
        _require_count(self.contexts_parsed, "CoverageSnapshot.contexts_parsed")
        if self.contexts_parsed > self.threads_total:
            raise ValueError(
                f"CoverageSnapshot.contexts_parsed ({self.contexts_parsed}) cannot exceed "
                f"threads_total ({self.threads_total})")
        require_recursively_immutable(self, "CoverageSnapshot")

    @property
    def evaluated(self) -> bool:
        """At least one memory segment existed to scan (Memory64ListStream/
        MemoryListStream present and non-empty) -- the sole gate for
        whether this hunter ran at all."""
        return self.scan.segment_count > 0

    @property
    def contexts_missing(self) -> int:
        return self.threads_total - self.contexts_parsed

    @property
    def thread_context_gap(self) -> bool:
        """RIP/EIP-based corroboration could not fully run for a hit that
        isn't otherwise corroborated by region protection -- either the
        whole stream was missing, or it was present but incomplete."""
        return (not self.thread_list_stream_available) or self.contexts_missing > 0

    def complete(self, *, has_hits: bool = False, any_corroborated: bool = False) -> bool:
        """Whether this run counts as fully covered. Unlike every other
        migrated hunter's own `complete` (a pure property of `coverage`
        alone), the thread-context gap only actually matters when at
        least one hit exists and NONE was already corroborated by region
        protection -- so this reducer takes those two outcome-dependent
        bits explicitly, exactly the way `aggregate.py` derived it before
        this migration, rather than letting a CoverageSnapshot silently
        disagree with itself depending on who asks. A dump with no hits at
        all never needed thread-context corroboration in the first place,
        so ThreadListStream's absence must not make an otherwise-clean
        scan read as partial."""
        if not self.scan.scan_complete or not self.mem_info_available:
            return False
        if has_hits and not any_corroborated and self.thread_context_gap:
            return False
        return True


@dataclass(frozen=True)
class CSBeaconEvidence:
    """Every item this hunter observed, in the buckets its own output
    contract is defined in terms of.

      hits           -- every structurally-valid config found, in scan
                        order (VA ascending within a segment, segment
                        order otherwise -- see scanner.scan_segments).
      corroborations -- one `CorroborationEvidence` per CORROBORATED hit
                        (never one per hit -- an uncorroborated hit has
                        none). Each cites its own `hit` by IDENTITY against
                        `hits` (enforced below), the same way
                        `dumpex.hunt.hollowing.domain.HollowingEvidence`
                        enforces its own correlation buckets.
    """
    hits:            tuple = field(default_factory=tuple)
    corroborations:  tuple = field(default_factory=tuple)

    def __post_init__(self):
        object.__setattr__(self, "hits",
                            _require_items_of(self.hits, "CSBeaconEvidence.hits", ConfigEvidence))
        object.__setattr__(self, "corroborations", _require_items_of(
            self.corroborations, "CSBeaconEvidence.corroborations", CorroborationEvidence))
        _require_subset([c.hit for c in self.corroborations], self.hits,
                         "CSBeaconEvidence.corroborations", "CSBeaconEvidence.hits")
        seen_hits = set()
        for corroboration in self.corroborations:
            if id(corroboration.hit) in seen_hits:
                raise ValueError(
                    "CSBeaconEvidence.corroborations holds more than one entry for the same "
                    f"hit: {corroboration.hit!r}")
            seen_hits.add(id(corroboration.hit))

    def canonical_items(self) -> tuple:
        """Every evidence object this container holds at the top level --
        the exact set a `CheckResult` on the same Report may cite."""
        return self.hits + self.corroborations

    def corroboration_for(self, hit: ConfigEvidence) -> "CorroborationEvidence | None":
        for corroboration in self.corroborations:
            if corroboration.hit is hit:
                return corroboration
        return None


@dataclass(frozen=True)
class CSBeaconReport:
    """The CS Beacon hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: `mf`, a raw minidump
    `MemoryInfo` region, a parser-owned `dict`, a `hit_records`/
    `findings_list` parallel representation, a `coverage_report` field
    assigned after construction, a `scan_note`, and any console-formatted
    string.
    """
    score:     int
    coverage:  CoverageSnapshot
    results:   tuple = field(default_factory=tuple)
    evidence:  CSBeaconEvidence = field(default_factory=CSBeaconEvidence)

    def __post_init__(self):
        _require_count(self.score, "CSBeaconReport.score")
        if self.score > MAX_SCORE:
            raise ValueError(f"CSBeaconReport.score must be <= {MAX_SCORE}, got {self.score}")
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"CSBeaconReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, CSBeaconEvidence):
            raise TypeError(
                f"CSBeaconReport.evidence must be a CSBeaconEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        object.__setattr__(self, "results",
                            _require_items_of(self.results, "CSBeaconReport.results", CheckResult))
        self._require_results_cite_this_reports_own_evidence()
        self._require_structural_config_pairing()
        # score > 0 requires at least one hit, and vice versa: score is a
        # pure function of evidence.hits/any_corroborated, pinned as an
        # invariant rather than left to convention (see aggregate.py, the
        # ONE place this Report is constructed).
        if self.score > 0 and not self.evidence.hits:
            raise ValueError(
                "CSBeaconReport.score is nonzero but evidence.hits is empty -- score must be "
                "derived from at least one structurally-valid config")
        if self.score == 0 and self.evidence.hits:
            raise ValueError(
                "CSBeaconReport.score is 0 but evidence.hits is non-empty -- at least one "
                "structurally-valid config was found, so score must be >= 1")
        if self.evidence.corroborations and self.score < MAX_SCORE:
            raise ValueError(
                f"CSBeaconReport.score must be {MAX_SCORE} whenever any hit is corroborated, "
                f"got {self.score}")
        # Final, whole-graph immutability sweep -- everything above only
        # checked TYPES (isinstance(self.coverage, CoverageSnapshot), ...)
        # and evidence-citation identity, none of which re-verifies that
        # the coverage/evidence objects ATTACHED here are still themselves
        # recursively immutable at this exact moment. `CSBeaconEvidence`/
        # `ConfigEvidence`/etc. already validate their OWN state when
        # THEY are constructed, but a caller could poison an
        # already-validated instance afterward (via `object.__setattr__`,
        # the same escape hatch `require_recursively_immutable`'s own
        # docstring names) and then hand that poisoned object to THIS
        # constructor -- the per-field isinstance checks above would not
        # catch it. Run last, over the whole assembled Report, so nothing
        # reachable from it can be a live list/dict/set/dump handle
        # regardless of when or how it was poisoned.
        require_recursively_immutable(self, "CSBeaconReport")

    def _require_structural_config_pairing(self) -> None:
        """Every hit in `evidence.hits` must correspond to EXACTLY one
        `cs_beacon.structural_config` result, in the SAME order, citing
        that hit (by identity) as its own first evidence item -- the
        structural guarantee that replaces the pre-migration console-layer
        `zip(hit_records, structural_config_findings, strict=True)` runtime
        check: report_console.py/report_legacy.py/report_record.py can now
        rely on this pairing rather than re-verifying it themselves."""
        structural = [r for r in self.results if r.check == "cs_beacon.structural_config"]
        if len(structural) != len(self.evidence.hits):
            raise ValueError(
                f"CSBeaconReport: {len(self.evidence.hits)} hit(s) in evidence.hits but "
                f"{len(structural)} cs_beacon.structural_config result(s) -- aggregate.py "
                f"must append exactly one per hit, in the same order")
        for index, (result, hit) in enumerate(zip(structural, self.evidence.hits)):
            if not result.evidence or result.evidence[0] is not hit:
                raise ValueError(
                    f"CSBeaconReport: cs_beacon.structural_config result at position {index} "
                    f"does not cite evidence.hits[{index}] as its own first evidence item -- "
                    f"hit/result pairing must be by identity and in order")

    def _require_results_cite_this_reports_own_evidence(self) -> None:
        canonical = {id(item) for item in self.evidence.canonical_items()}
        for result in self.results:
            for item in result.evidence:
                if id(item) not in canonical:
                    raise ValueError(
                        f"CSBeaconReport: check {result.check!r} cites evidence that is not "
                        f"one of this Report's own evidence objects: {item!r}")

    @property
    def max_score(self) -> int:
        return MAX_SCORE

    @property
    def evaluated(self) -> bool:
        return self.coverage.evaluated

    @property
    def any_corroborated(self) -> bool:
        return bool(self.evidence.corroborations)

    @property
    def config_count(self) -> int:
        return len(self.evidence.hits)

    @property
    def _coverage_complete(self) -> bool:
        return self.coverage.complete(has_hits=bool(self.evidence.hits),
                                       any_corroborated=self.any_corroborated)

    @property
    def status(self) -> str:
        return derive_status(self.evaluated, self.score > 0, self._coverage_complete)

    @property
    def coverage_status(self) -> str:
        return derive_coverage_status(self.evaluated, self._coverage_complete)

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
