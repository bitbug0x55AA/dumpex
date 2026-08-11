"""The canonical, recursively immutable domain model for the process-
hollowing hunter -- `HollowingReport` plus the coverage snapshot and
evidence container it is built from. Mirrors `dumpex.hunt.injection.domain`,
`dumpex.hunt.encoding.domain`, `dumpex.hunt.stomping.domain`, and
`dumpex.hunt.pipe.domain` (the four completed reference pilots): see those
modules' own docstrings for the general "one canonical result
representation" rationale this module applies to the hollowing hunter.

Before this migration, `dumpex.hunt.hollowing.Report` kept the same facts
several times over: a `findings` list (JSON-facing, holding rendered
`Finding.to_dict()` entries), a `findings_list` (the same findings a second
time, as `Finding` objects), a `score`/`status`/`coverage_status`/
`coverage_reasons`/`confidence`/`verdict_level`/`lead_count`/
`review_priority` field that each stored a value the shared reducers in
`dumpex.hunt._coverage`/`dumpex.hunt._finding` had already derived, a
`coverage_report` object built by a helper OUTSIDE the builder, a live
`MinidumpMemoryInfo` (`base_region`) and a live `Module` (`main_mod`) kept
"ONLY for console formatting", and SIX loose booleans (`mem_private`,
`mz_read_failed`, `mz_wiped`, `is_rwx`, `module_list_unavailable`,
`name_mismatch`) restating what those objects and the header read already
said. Nothing structural kept any of those in agreement -- and because the
renderer could not get protection/type/file-offset text out of the Report
without them, `_render_hollowing_console()` had to take `mf` as its first
parameter and re-run `prot_str()`/`va_to_file_offset()` at render time.

`HollowingReport` stores each fact exactly once:

  score      -- 0..2, this hunter's own decision (MEM_PRIVATE at the image
                base correlated with a wiped MZ header and/or RWX
                protection at that same address).
  coverage   -- the immutable snapshot of what this run could and could
                not see.
  context    -- the image base's resolved identity/memory/module facts
                (dumpex.hunt.hollowing.models.ImageBaseContext), or None
                when the PEB itself was missing and there was no image base
                to resolve at all.
  results    -- the checks this hunter produced, as typed
                `dumpex.hunt._domain.CheckResult`s carrying typed evidence.
  evidence   -- the observed items, in their hunter-meaningful buckets;
                the SAME objects `results` reference, never a copy.

and DERIVES everything else -- `status`, `verdict_level`, `confidence`,
`lead_count`, `review_priority`, `max_score` -- as properties, through the
same shared reducers (`dumpex.hunt._coverage`, `dumpex.hunt._finding`)
`aggregate.py` calls.

`context` is the one field here that has no counterpart on the other
migrated hunters' Reports, and it is deliberate rather than a leftover:
this hunter's whole scope is a SINGLE address, so "what the image base
looked like" is a fact about the run itself (like `coverage`), not a
per-item observation that belongs in an evidence bucket. It is what lets
`report_record.py` distinguish `mem_private_at_base: false` (checked,
clean) from `null` (the region was never captured) without the Report
keeping a parallel set of booleans, and what lets `report_console.py`
render VA/file-offset/protection/header detail without ever seeing `mf`.
"""
from dataclasses import dataclass, field

from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._domain import CheckResult, require_recursively_immutable, as_tuple
from dumpex.hunt._finding import (
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.hollowing.models import (
    ImageBaseContext, MemPrivateEvidence, NameMismatchEvidence, RwxProtectionEvidence,
    StructuralCorrelationEvidence, WipedHeaderEvidence,
)

# This hunter's own score -> verdict_level table (see
# dumpex.hunt._finding.verdict_level) -- the canonical home for it is here,
# on the domain model that owns the score, rather than in aggregate.py
# (which imports it from here).
#
#   1 -- MEM_PRIVATE at the image base correlated with EITHER a wiped MZ
#        header OR RWX protection at that same address.
#   2 -- all three at once.
#
# No "3": this hunter has no third independent signal. The unscored
# name-mismatch corroborator never moves the score at all (see
# aggregate.py), so there is no tier above "high".
VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}

# The top of this hunter's score scale.
MAX_SCORE = 2

# The three coverage-gap reasons, in ONE place because TWO consumers
# describe the same gap: the hunter's `coverage_reasons`
# (report_facts.project_coverage_v1) and report_console.py's COVERAGE
# section, which renders that same list. Byte-identical to the strings the
# pre-migration `_build_hollowing_report()` appended inline -- the v1.1
# `coverage_reasons` array is part of the frozen output contract
# (tests/integration/test_hunt_cli_compat_freeze.py), so the wording moved
# here without changing.
PEB_MISSING_REASON = "PEB stream missing from this dump"
REGION_MISSING_REASON = ("Image base page not captured in this dump — memory-type and "
                          "RWX checks could not run")
HEADER_READ_FAILED_REASON = ("Image base MZ header could not be read — MZ-header check "
                              "could not run")
MODULE_LIST_MISSING_REASON = ("ModuleListStream missing/empty from this dump — module-list "
                               "sanity check could not run")


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {value!r}")


def _require_count(value, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be a non-negative int, got {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_items_of(value, field_name: str, expected) -> tuple:
    """Normalize to a tuple and require every item to be an instance of
    `expected`, immutable, and not a duplicate (by equality) of another
    item already in the bucket -- the same poison-object/dedup barrier
    `dumpex.hunt.stomping.domain`/`dumpex.hunt.pipe.domain` apply to their
    own evidence buckets."""
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


def _require_at_most_one(items, field_name: str) -> None:
    """Every bucket on this hunter is 0-or-1: each check is anchored on the
    ONE address the PEB reports, so there is exactly one region, one header
    read, and one module-list comparison per run. Enforced rather than
    merely documented -- a second entry would mean two different answers
    for the same address, and every projector below reads `bucket[0]`."""
    if len(items) > 1:
        raise ValueError(
            f"{field_name} may hold at most one item -- every hollowing check is anchored "
            f"on the single image base the PEB reports, got {len(items)}")


def _require_subset(subset, superset, subset_name: str, superset_name: str) -> None:
    """Every item of `subset` must BE (by identity) an item of `superset` --
    mirrors `dumpex.hunt.stomping.domain._require_subset`: correlation.py
    pairs the EXISTING anchor/corroborator evidence objects, never
    reconstructed equal copies."""
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

    Four booleans, one per thing that had to be available for one of this
    hunter's four checks to actually run:

      peb_present             -- the PEB stream itself. Every check is
                                  anchored on the image base IT reports, so
                                  without it nothing ran at all: this alone
                                  decides `evaluated`.
      image_base_region_found -- the MemoryInfo region covering that base.
                                  Anchor 1 (memory type) and corroborator 3
                                  (RWX) both need it.
      mz_read_failed          -- whether the single header read at the image
                                  base came back unusable (raised, or fewer
                                  than `config.MZ_MIN_BYTES` bytes). Anchor
                                  2 reads a fixed window INDEPENDENTLY of
                                  the region above, and a failure there was
                                  previously only printed, never folded into
                                  coverage -- so as long as a region existed
                                  the result claimed "complete" even though
                                  anchor 2 never actually ran.
      modules_available       -- ModuleListStream being present and
                                  non-empty. `get_modules()` returns `[]`
                                  both when the stream is missing AND when
                                  it is present but genuinely has no entry
                                  for this address; those are different
                                  situations for corroborator 4 (the first
                                  means the check never ran, the second is a
                                  real signal), and only this flag can tell
                                  them apart.
    """
    peb_present:             bool
    image_base_region_found: bool = False
    mz_read_failed:          bool = False
    modules_available:       bool = False

    def __post_init__(self):
        for name in ("peb_present", "image_base_region_found", "mz_read_failed",
                     "modules_available"):
            _require_bool(getattr(self, name), f"CoverageSnapshot.{name}")

    # ── Derived coverage facts ────────────────────────────────────────────

    @property
    def evaluated(self) -> bool:
        """The PEB alone: it is the sole source of the image base every one
        of this hunter's four checks is anchored on, so its absence means
        nothing was looked at, and its presence means the run genuinely
        happened however incomplete it turned out to be."""
        return self.peb_present

    @property
    def complete(self) -> bool:
        """All four checks actually ran. Reproduces the pre-migration
        `complete = base_region is not None and not mz_read_failed and not
        module_list_unavailable` exactly."""
        return (self.image_base_region_found and not self.mz_read_failed
                and self.modules_available)

    @property
    def status(self) -> str:
        return derive_coverage_status(self.evaluated, self.complete)

    def gap_reasons(self) -> tuple:
        """The per-check coverage gaps of an EVALUATED run, as
        human-readable reason strings in the pre-migration order (region,
        then header read, then module list) -- empty when all four checks
        ran.

        Deliberately does NOT include the PEB's own absence: that is the
        `evaluated` gate, not a gap within a run that happened, and
        `report_facts.project_coverage_v1` renders it as its own single
        reason instead (see PEB_MISSING_REASON). Calling this on a
        `peb_present=False` snapshot would report all three per-check gaps
        for checks that were never even reached.
        """
        reasons = []
        if not self.image_base_region_found:
            reasons.append(REGION_MISSING_REASON)
        if self.mz_read_failed:
            reasons.append(HEADER_READ_FAILED_REASON)
        if not self.modules_available:
            reasons.append(MODULE_LIST_MISSING_REASON)
        return tuple(reasons)


@dataclass(frozen=True)
class HollowingEvidence:
    """Every item this hunter observed, in the buckets its own output
    contract is defined in terms of -- see
    `dumpex.hunt.injection.domain.InjectionEvidence` for the general "held
    once, cited by identity" rationale.

    Each bucket holds at most ONE item (see `_require_at_most_one`): this
    hunter examines a single address, so "the region at the image base is
    MEM_PRIVATE" is one observation, not a list of them. The buckets are
    still tuples rather than `X | None` fields so every projector reads
    them the same way the other four migrated hunters' projectors read
    theirs, and so `canonical_items()` is a plain concatenation.

    `correlations` is NOT an independent bucket: its single entry cites
    `mem_private`'s, `wiped_headers`', and `rwx`'s OWN objects (by
    identity, enforced below) -- the same way
    `dumpex.hunt.stomping.domain.StompingEvidence` enforces its
    `rip_correlated_leads` against `protection_leads`. Without that, a
    Report could accept a correlation describing an anchor its own buckets
    never held.
    """
    mem_private:     tuple = field(default_factory=tuple)
    wiped_headers:   tuple = field(default_factory=tuple)
    rwx:             tuple = field(default_factory=tuple)
    name_mismatches: tuple = field(default_factory=tuple)
    correlations:    tuple = field(default_factory=tuple)

    _BUCKET_TYPES = (
        ("mem_private",     MemPrivateEvidence),
        ("wiped_headers",   WipedHeaderEvidence),
        ("rwx",             RwxProtectionEvidence),
        ("name_mismatches", NameMismatchEvidence),
        ("correlations",    StructuralCorrelationEvidence),
    )

    def __post_init__(self):
        for name, expected in self._BUCKET_TYPES:
            items = _require_items_of(getattr(self, name), f"HollowingEvidence.{name}", expected)
            _require_at_most_one(items, f"HollowingEvidence.{name}")
            object.__setattr__(self, name, items)
        _require_subset([c.mem_private for c in self.correlations], self.mem_private,
                         "HollowingEvidence.correlations", "HollowingEvidence.mem_private")
        _require_subset([c.wiped_header for c in self.correlations if c.wiped_header is not None],
                         self.wiped_headers,
                         "HollowingEvidence.correlations", "HollowingEvidence.wiped_headers")
        _require_subset([c.rwx for c in self.correlations if c.rwx is not None], self.rwx,
                         "HollowingEvidence.correlations", "HollowingEvidence.rwx")

    def canonical_items(self) -> tuple:
        """Every evidence object this container holds at the top level --
        the exact set a `CheckResult` on the same Report may cite."""
        items = []
        for name, _expected in self._BUCKET_TYPES:
            items.extend(getattr(self, name))
        return tuple(items)


@dataclass(frozen=True)
class HollowingReport:
    """The hollowing hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: a `MinidumpFile`/`mf`, a
    raw `MinidumpMemoryInfo`/`Module`/PEB object, a `read_region` callable,
    a rules/suspicious-protection list, a verbosity or DetailLevel flag, a
    `Finding`/`HunterRecord`/legacy-dict/`CoverageReport` field, and any
    console-formatted string.
    """
    score: int
    coverage: CoverageSnapshot
    context:  "ImageBaseContext | None" = None
    results:  tuple = field(default_factory=tuple)
    evidence: HollowingEvidence = field(default_factory=HollowingEvidence)

    def __post_init__(self):
        _require_count(self.score, "HollowingReport.score")
        if self.score > MAX_SCORE:
            raise ValueError(
                f"HollowingReport.score must be <= {MAX_SCORE}, got {self.score}")
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"HollowingReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, HollowingEvidence):
            raise TypeError(
                f"HollowingReport.evidence must be a HollowingEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        if self.context is not None and not isinstance(self.context, ImageBaseContext):
            raise TypeError(
                f"HollowingReport.context must be an ImageBaseContext or None, got "
                f"{type(self.context).__name__}: {self.context!r}")
        # The PEB is the ONLY source of an image base, so "evaluated" and
        # "there is a resolved context" are the same fact stated twice --
        # pinned as an invariant rather than left to convention, because a
        # Report that claimed the run evaluated while carrying no context
        # would make report_record.py emit `image_base: null` for a run
        # whose coverage says a real image base was examined.
        if self.coverage.peb_present and self.context is None:
            raise ValueError(
                "HollowingReport.context is required whenever coverage.peb_present is True -- "
                "the image base every check is anchored on was resolved, so the Report must "
                "carry it")
        if not self.coverage.peb_present and self.context is not None:
            raise ValueError(
                "HollowingReport.context must be None when coverage.peb_present is False -- "
                "there is no image base to report at all in that case")
        object.__setattr__(self, "results", _require_items_of(
            self.results, "HollowingReport.results", CheckResult))
        self._require_results_cite_this_reports_own_evidence()

    def _require_results_cite_this_reports_own_evidence(self) -> None:
        canonical = {id(item) for item in self.evidence.canonical_items()}
        for result in self.results:
            for item in result.evidence:
                if id(item) not in canonical:
                    raise ValueError(
                        f"HollowingReport: check {result.check!r} cites evidence "
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
