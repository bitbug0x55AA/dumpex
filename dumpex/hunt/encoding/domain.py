"""The canonical, recursively immutable domain model for the encoding
(obfuscation) hunter -- `EncodingReport` plus the coverage snapshot and
evidence container it is built from. Mirrors
`dumpex.hunt.injection.domain` (the completed reference pilot): see that
module's own docstring for the general "one canonical result
representation" rationale this module applies to the encoding hunter.

Before this migration, `dumpex.hunt.encoding.aggregate.EncodingReport`
kept the same facts several times over: a `findings` dict (JSON-facing,
holding rendered `Finding.to_dict()` entries) and a `findings_list` (the
same findings a second time, as `Finding` objects) -- plus a further set
of raw `sleep_mask_hits`/`entropy_hits`/`base64_hits`/`xor_hits`/
`compressed_hits`/`all_pe_hits`/`all_shellcode_hits` lists presentation.py
read directly for its own per-layer status lines. Nothing structural kept
those in agreement, and the raw hits held a live minidump region object
by reference all the way through to render time.

`EncodingReport` stores each fact exactly once:

  score      -- 0..2, this hunter's own decision (confirmed sleep-mask
                decode and/or a validated PE payload found via any layer).
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
from dumpex.hunt.encoding.models import DecodedHit, EntropyHit
from dumpex.output.coverage import ScanTarget

# This hunter's own score -> verdict_level table -- the canonical home for
# it is here, on the domain model that owns the score, rather than in
# aggregate.py (which imports it from here).
VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}

# The top of this hunter's score scale: confirmed sleep-mask decode
# (+1) and/or a validated PE payload found via any layer (+1). Raw
# entropy/Base64/GZIP/XOR presence and the shellcode-bootstrap prefix
# never contribute.
MAX_SCORE = 2

# Fixed order the three scan layers' oversized-skip reasons are reported
# in -- see CoverageSnapshot.oversized_targets_by_layer().
OVERSIZE_SCAN_LAYERS = ("sleep_mask", "entropy", "decode")


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {value!r}")


def _require_count(value, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be a non-negative int, got {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


def _require_scan_targets(value, field_name: str) -> tuple:
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if type(item) is not ScanTarget:
            raise TypeError(
                f"{field_name}[{index}] must be a ScanTarget, got "
                f"{type(item).__name__}: {item!r}")
    require_recursively_immutable(items, field_name)
    return items


def _require_items_of(value, field_name: str, expected) -> tuple:
    """Normalize to a tuple and require every item to be an instance of
    `expected`, immutable, and not a duplicate (by equality) of another
    item already in the bucket -- the same poison-object/dedup barrier
    `dumpex.hunt.injection.domain` applies to its own evidence buckets."""
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if not isinstance(item, expected):
            raise TypeError(
                f"{field_name}[{index}] must be a {expected.__name__}, got "
                f"{type(item).__name__}: {item!r}")
    require_recursively_immutable(items, field_name)
    seen = set()
    for index, item in enumerate(items):
        if item in seen:
            raise ValueError(
                f"{field_name}[{index}] is already in this bucket (identical "
                f"or equal to an earlier item): {item!r}")
        seen.add(item)
    return items


def _require_subset(subset, superset, subset_name: str, superset_name: str) -> None:
    """Every item of `subset` must BE (by identity) an item of
    `superset` -- mirrors `dumpex.hunt.injection.domain._require_subset`:
    `aggregate.py` partitions the five hit buckets' own lists into
    pe_hits/shellcode_hits by reference, never by reconstructing an equal
    copy."""
    allowed = {id(item) for item in superset}
    for item in subset:
        if id(item) not in allowed:
            raise ValueError(
                f"{subset_name} holds an item that is not one of "
                f"{superset_name}'s own objects: {item!r}")


@dataclass(frozen=True)
class CoverageSnapshot:
    """What this run could and could not see, as FACTS rather than as
    rendered reasons -- see `dumpex.hunt.injection.domain.CoverageSnapshot`
    for the general rationale.

    `sleep_mask_oversized`/`entropy_oversized`/`decode_oversized` replace
    the old mutable `oversized_by_layer: dict` -- three named tuple
    fields instead of a mapping, since a dict/MappingProxyType can never
    be recursively immutable (see `dumpex.hunt._domain.
    require_recursively_immutable`'s own docstring). Each layer's own
    oversized skips stay attributed to that layer: summing them and
    calling the result a region count is a correctness bug (the same
    physical region can exceed several layers' independent size caps),
    not a rounding of one.
    """
    memory_info_stream: bool
    region_count: "int | None" = None
    any_region_scanned: bool = False
    sleep_mask_oversized: tuple = field(default_factory=tuple)
    entropy_oversized:    tuple = field(default_factory=tuple)
    decode_oversized:     tuple = field(default_factory=tuple)
    read_failed:  int = 0
    short_reads:  int = 0
    budget_exhausted: bool = False
    exhausted_reason: str = ""

    def __post_init__(self):
        _require_bool(self.memory_info_stream, "CoverageSnapshot.memory_info_stream")
        _require_optional_count(self.region_count, "CoverageSnapshot.region_count")
        _require_bool(self.any_region_scanned, "CoverageSnapshot.any_region_scanned")
        for name in ("sleep_mask_oversized", "entropy_oversized", "decode_oversized"):
            object.__setattr__(self, name, _require_scan_targets(
                getattr(self, name), f"CoverageSnapshot.{name}"))
        for name in ("read_failed", "short_reads"):
            _require_count(getattr(self, name), f"CoverageSnapshot.{name}")
        _require_bool(self.budget_exhausted, "CoverageSnapshot.budget_exhausted")
        if not isinstance(self.exhausted_reason, str):
            raise TypeError(
                f"CoverageSnapshot.exhausted_reason must be a str, got "
                f"{self.exhausted_reason!r}")

    def oversized_targets_by_layer(self) -> tuple:
        """`((layer_name, targets), ...)` for every layer with at least
        one oversized skip, in OVERSIZE_SCAN_LAYERS' fixed order --
        replaces the old `oversized_by_layer.items()` dict iteration."""
        by_layer = {
            "sleep_mask": self.sleep_mask_oversized,
            "entropy":    self.entropy_oversized,
            "decode":     self.decode_oversized,
        }
        return tuple((layer, by_layer[layer]) for layer in OVERSIZE_SCAN_LAYERS
                     if by_layer[layer])

    @property
    def any_oversized(self) -> bool:
        return bool(self.sleep_mask_oversized or self.entropy_oversized or self.decode_oversized)

    @property
    def fully_skipped(self) -> bool:
        """All regions existed (MemoryInfo present, region_count > 0) but
        every single layer's own filters skipped every one of them --
        nothing was actually read despite the stream being present. A
        negative result in that case is not the same claim as "scanned
        and clean"."""
        return bool(self.memory_info_stream and self.region_count
                    and not self.any_region_scanned)

    @property
    def evaluated(self) -> bool:
        """This hunter's ONLY evaluation gate is MemoryInfoListStream --
        matches today's `mem_info_available`."""
        return self.memory_info_stream

    @property
    def complete(self) -> bool:
        return not (self.fully_skipped or self.any_oversized or self.read_failed
                    or self.short_reads or self.budget_exhausted)

    @property
    def status(self) -> str:
        return derive_coverage_status(self.evaluated, self.complete)


@dataclass(frozen=True)
class EncodingEvidence:
    """Every item this hunter observed, in the buckets its own output
    contract is defined in terms of -- see
    `dumpex.hunt.injection.domain.InjectionEvidence` for the general
    "held once, cited by identity" rationale.

    `pe_hits`/`shellcode_hits` are NOT independent buckets: they are
    `aggregate.py`'s own partition (by reference) of
    `sleep_mask_hits`/`base64_hits`/`xor_hits`/`compressed_hits` where
    `classification.is_pe`/`is_shellcode` -- enforced here by identity,
    the same way `dumpex.hunt.injection.domain` enforces
    `suspicious_pe_hits`/`informational_pe_hits` against
    `validated_pe_hits`. `shellcode_context_hits` is, in turn, the subset
    of `shellcode_hits` sitting inside an executable+private region.
    """
    sleep_mask_hits: tuple = field(default_factory=tuple)
    entropy_hits:    tuple = field(default_factory=tuple)
    base64_hits:     tuple = field(default_factory=tuple)
    xor_hits:        tuple = field(default_factory=tuple)
    compressed_hits: tuple = field(default_factory=tuple)
    pe_hits:               tuple = field(default_factory=tuple)
    shellcode_hits:         tuple = field(default_factory=tuple)
    shellcode_context_hits: tuple = field(default_factory=tuple)

    _HIT_BUCKETS = ("sleep_mask_hits", "base64_hits", "xor_hits", "compressed_hits")

    def __post_init__(self):
        for name in self._HIT_BUCKETS:
            object.__setattr__(self, name, _require_items_of(
                getattr(self, name), f"EncodingEvidence.{name}", DecodedHit))
        object.__setattr__(self, "entropy_hits", _require_items_of(
            self.entropy_hits, "EncodingEvidence.entropy_hits", EntropyHit))
        for name in ("pe_hits", "shellcode_hits", "shellcode_context_hits"):
            object.__setattr__(self, name, _require_items_of(
                getattr(self, name), f"EncodingEvidence.{name}", DecodedHit))
        self._require_bucket_relations()

    def _require_bucket_relations(self) -> None:
        source_hits = tuple(item for name in self._HIT_BUCKETS for item in getattr(self, name))
        _require_subset(self.pe_hits, source_hits,
                         "EncodingEvidence.pe_hits", "its own source hit buckets")
        _require_subset(self.shellcode_hits, source_hits,
                         "EncodingEvidence.shellcode_hits", "its own source hit buckets")
        _require_subset(self.shellcode_context_hits, self.shellcode_hits,
                         "EncodingEvidence.shellcode_context_hits",
                         "EncodingEvidence.shellcode_hits")
        pe_ids = {id(h) for h in self.pe_hits}
        shellcode_ids = {id(h) for h in self.shellcode_hits}
        if pe_ids & shellcode_ids:
            raise ValueError(
                "EncodingEvidence: a hit is in both pe_hits and shellcode_hits -- "
                "classification is mutually exclusive")
        for hit in self.pe_hits:
            if not hit.classification.is_pe:
                raise ValueError(
                    f"EncodingEvidence.pe_hits holds {hit!r}, whose classification "
                    f"is not is_pe")
        for hit in self.shellcode_hits:
            if not hit.classification.is_shellcode:
                raise ValueError(
                    f"EncodingEvidence.shellcode_hits holds {hit!r}, whose "
                    f"classification is not is_shellcode")
        for hit in self.shellcode_context_hits:
            if not (hit.region.type == "MEM_PRIVATE" and hit.region.is_rwx):
                raise ValueError(
                    f"EncodingEvidence.shellcode_context_hits holds {hit!r}, whose "
                    f"region is not MEM_PRIVATE + RWX-suspicious")

    def canonical_items(self) -> tuple:
        """Every evidence object this container holds at the top level --
        the exact set a `CheckResult` on the same Report may cite. Deep
        subset buckets (`pe_hits`/`shellcode_hits`/
        `shellcode_context_hits`) hold the SAME objects as the source hit
        buckets, so listing both is safe (a set(), not a sum) but only
        the source buckets plus entropy_hits are strictly necessary --
        listed explicitly for clarity and to keep this in step if a
        future bucket is added."""
        items = []
        for name in self._HIT_BUCKETS:
            items.extend(getattr(self, name))
        items.extend(self.entropy_hits)
        return tuple(items)


@dataclass(frozen=True)
class EncodingReport:
    """The encoding hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: a `MinidumpFile`/`mf`, a
    `read_region`/address-resolver callable, a rules/`susp_prots` list, a
    live `ScanBudget`, a verbosity or DetailLevel flag, a `Finding`/
    `HunterRecord`/legacy-dict field, and any console-formatted string.
    """
    score: int
    coverage: CoverageSnapshot
    results:  tuple = field(default_factory=tuple)
    evidence: EncodingEvidence = field(default_factory=EncodingEvidence)

    def __post_init__(self):
        _require_count(self.score, "EncodingReport.score")
        if self.score > MAX_SCORE:
            raise ValueError(
                f"EncodingReport.score must be <= {MAX_SCORE}, got {self.score}")
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"EncodingReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, EncodingEvidence):
            raise TypeError(
                f"EncodingReport.evidence must be an EncodingEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        object.__setattr__(self, "results", _require_items_of(
            self.results, "EncodingReport.results", CheckResult))
        self._require_results_cite_this_reports_own_evidence()

    def _require_results_cite_this_reports_own_evidence(self) -> None:
        canonical = {id(item) for item in self.evidence.canonical_items()}
        for result in self.results:
            for item in result.evidence:
                if id(item) not in canonical:
                    raise ValueError(
                        f"EncodingReport: check {result.check!r} cites evidence "
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
