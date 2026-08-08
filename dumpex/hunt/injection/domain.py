"""The canonical, recursively immutable domain model for the injection
hunter -- `InjectionReport` plus the coverage snapshot and evidence
container it is built from.

This is the "one canonical result representation" side of the hunt
output-source migration. Today's `dumpex.hunt.injection.aggregate.Report`
keeps the same facts several times over: `findings` (a dict whose
`"findings"` key holds already-rendered Finding dicts, alongside Evidence
tuples under other keys), `findings_list` (the same findings a second time
as Finding objects), and then `rwx`/`validated_pe_hits`/`mz_only_hits`/
`suspicious_pe_hits`/`informational_pe_hits`/`start_threads` as a third
copy of the evidence those findings were rendered from. Nothing structural
keeps those three in agreement.

`InjectionReport` stores each fact exactly once:

  score      -- the hunter's own 0..3 decision, the only judgment value
                 that is genuinely chosen rather than derived.
  results    -- the checks this hunter produced, as typed
                 `dumpex.hunt._domain.CheckResult`s carrying typed
                 evidence (not rendered facts text).
  evidence   -- the observed items, in their hunter-meaningful buckets;
                 the SAME objects `results` reference, never a copy.
  coverage   -- the immutable snapshot of what this run could and could
                 not see.

and DERIVES everything else -- `status`, `verdict_level`, `confidence`,
`lead_count`, `review_priority`, `max_score` -- as properties, through the
same shared reducers (`dumpex.hunt._coverage`, `dumpex.hunt._finding`)
today's aggregate.py already calls. A derived property cannot drift from
the score/coverage/results it is derived from, which is the failure mode
storing all seven judgment fields side by side in a dict invites.

Additive as of this change: nothing constructs an `InjectionReport` in
production yet (see the Injection 2A issue's "no aggregate or caller
cutover" non-goal), and no console/JSON behavior changes. The legacy v1.1
dict, the v2.7 `HunterRecord`, and the console renderer become pure
projections of this type in the follow-up issues; this one only fixes the
shape and proves its immutability.
"""
import dataclasses
from dataclasses import dataclass, field

from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._domain import CheckResult, require_recursively_immutable, as_tuple
from dumpex.hunt._finding import (
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.injection.models import (
    Correlation, CorrelatedAllocationEvidence, HiddenPeEvidence, RwxRegionEvidence,
    ThreadContext, UnbackedThreadEvidence,
)

# This hunter's own score -> verdict_level table. The canonical home for
# it is here, on the domain model that owns the score, rather than in
# aggregate.py (which imports it from here) -- see
# dumpex.hunt._finding.verdict_level for why each hunter must supply an
# explicit table instead of deriving a tier from score/max_score
# arithmetic.
VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "likely", 3: "high"}

# The top of this hunter's score scale -- reachable only through live
# RIP/EIP correlation (see aggregate.build_report's own scoring comment).
MAX_SCORE = 3


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {value!r}")


def _require_count(value, field_name: str) -> None:
    # bool excluded explicitly: it is an int subclass, and a stray boolean
    # where a count was meant is a caller bug, not a 0/1 count.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be a non-negative int, got {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


def _require_address_inside_region(addr: int, region, hit, hits_name: str) -> None:
    """`addr` must fall within `[region.base_address, region.base_address +
    region.size)` -- `dumpex.hunt.injection.correlation._region_for_addr`'s
    own containment test, re-run against the SAME `RegionRef` the hit
    already carries. Both operands (`addr` and the region's own bounds)
    live entirely on the hit itself, so this needs no raw MemoryInfo list
    -- unlike proving THAT region is the geometrically correct one among
    every region in the dump (which this model cannot re-derive; see
    `_require_rip_hits_match_thread_contexts`'s own docstring), whether the
    address the hit claims lands inside the region it was paired with is
    fully checkable from the hit's own fields."""
    if not (region.base_address <= addr < region.base_address + region.size):
        raise ValueError(
            f"{hits_name} holds {hit!r}, whose address 0x{addr:x} does not fall "
            f"within its own region [0x{region.base_address:x}, "
            f"0x{region.base_address + region.size:x}) -- correlate() only ever "
            f"attaches the region that geometrically contains the address")


def _require_items_of(value, field_name: str, expected) -> tuple:
    """Normalize to a tuple and require every item to be an instance of
    `expected` -- the poison-object barrier for the Report's own evidence
    buckets. A raw minidump Region/ThreadInfo, a `MinidumpFile`, a resolver
    callable, a hand-rolled dict, or a rendered console string all fail
    this check at construction time rather than surfacing later as a
    projector that happens to read the wrong attribute."""
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if not isinstance(item, expected):
            raise TypeError(
                f"{field_name}[{index}] must be a {expected.__name__}, got "
                f"{type(item).__name__}: {item!r}")
    # Immutability is confirmed before the dedup check below relies on
    # hashing: every type this function accepts as a leaf/container is
    # hashable by construction (a frozen dataclass whose own fields are
    # all themselves proven hashable here, or a tuple/frozenset/scalar of
    # them), so this also guarantees the `set()` below cannot raise.
    require_recursively_immutable(items, field_name)
    # One evidence object is one observation. The same object listed
    # twice in one bucket, or an EQUAL-BUT-DISTINCT duplicate of it (two
    # separately-constructed value objects describing the same region/
    # hit/thread), is the same fact counted twice -- which every
    # projection would then render twice and every count would
    # over-report. Equality dedup (not `id()`) is what actually catches
    # the second case: two distinct objects with identical fields compare
    # equal and hash equal, so a `set()` here is a strictly stronger check
    # than an identity set -- it also happens to catch the same-object-
    # twice case, since `x == x` trivially holds.
    seen = set()
    for index, item in enumerate(items):
        if item in seen:
            raise ValueError(
                f"{field_name}[{index}] is already in this bucket (identical "
                f"or equal to an earlier item): {item!r}")
        seen.add(item)
    return items


def _own_correlation(correlation) -> Correlation:
    """Return a Correlation the DOMAIN owns, and validate its contents.

    `Correlation` normalizes its per-allocation maps to
    `types.MappingProxyType`, which is a read-only VIEW rather than an
    immutable value: whoever still holds the dict behind it can mutate it
    afterwards. `Correlation.__post_init__` wraps a FRESH dict, so
    re-running it here (`dataclasses.replace`) is what makes the mapping
    behind the stored proxies unreachable to the caller -- the copy
    boundary the "mutating constructor inputs cannot change the Report"
    guardrail needs. Evidence identity is unaffected: re-normalizing
    rebuilds the containers, never the hits or region refs inside them.

    Contents are validated field by field rather than by handing the whole
    Correlation to `require_recursively_immutable`, which refuses a
    MappingProxyType outright (correctly -- it cannot tell an owned proxy
    from a borrowed one; only this function, which just created it, can).
    """
    if not isinstance(correlation, Correlation):
        raise TypeError(
            f"InjectionEvidence.correlation must be a Correlation, got "
            f"{type(correlation).__name__}: {correlation!r}")
    owned = dataclasses.replace(correlation)
    for map_name in ("rwx_by_alloc", "pe_by_alloc"):
        for allocation_base, regions in getattr(owned, map_name).items():
            require_recursively_immutable(
                allocation_base, f"InjectionEvidence.correlation.{map_name}{{key}}")
            require_recursively_immutable(
                regions, f"InjectionEvidence.correlation.{map_name}{{}}")
    for name in ("rwx_and_pe_alloc_bases", "suspicious_alloc_bases",
                 "rip_hits", "rip_full_correlation", "start_hits"):
        require_recursively_immutable(getattr(owned, name),
                                       f"InjectionEvidence.correlation.{name}")

    # Self-consistency of Correlation's OWN fields -- independent of
    # whether rwx_and_pe_alloc_bases/suspicious_alloc_bases themselves
    # turn out to correctly reflect the top-level rwx/validated_pe_hits
    # buckets (a separate question `_require_correlation_matches_buckets`
    # asks later, once those buckets exist). `correlate()` only ever adds
    # a RipHitEvidence/StartHitEvidence to rip_hits/start_hits when its
    # region's allocation_base is already in suspicious_alloc_bases -- a
    # hit whose own region fails that membership test could not have been
    # produced by the real correlation logic. Each hit's own address must
    # ALSO fall geometrically inside its own region -- unlike "is this
    # region among the ones the buckets recorded" (which needs the raw
    # MemoryInfo list this model deliberately does not hold, see
    # `_require_rip_hits_match_thread_contexts`'s own docstring), "does
    # this ip/start_address fall within [region.base_address,
    # region.base_address + region.size)" is fully determined by the hit's
    # own fields -- `_region_for_addr`'s own containment test, re-run here
    # against the SAME region the hit already carries.
    for hit in owned.rip_hits:
        if hit.region.allocation_base not in owned.suspicious_alloc_bases:
            raise ValueError(
                f"correlation.rip_hits holds {hit!r}, whose allocation base "
                f"0x{hit.region.allocation_base:x} is not in "
                f"suspicious_alloc_bases -- correlate() only ever adds a hit "
                f"whose region already qualified")
        _require_address_inside_region(hit.ip, hit.region, hit, "correlation.rip_hits")
    for hit in owned.start_hits:
        if hit.region.allocation_base not in owned.suspicious_alloc_bases:
            raise ValueError(
                f"correlation.start_hits holds {hit!r}, whose allocation base "
                f"0x{hit.region.allocation_base:x} is not in "
                f"suspicious_alloc_bases -- correlate() only ever adds a hit "
                f"whose region already qualified")
        # 0-substituted lookup address, matching correlate()'s own
        # `ti.start_address or 0` -- start_hit.start_address itself stays
        # the thread's TRUE (possibly None) value, never the substitution
        # (see StartHitEvidence's own docstring); the geometric test uses
        # the same local substitution correlate() used to find this region
        # in the first place.
        _require_address_inside_region(hit.start_address or 0, hit.region, hit,
                                        "correlation.start_hits")

    # rip_full_correlation is `correlate()`'s own filter of rip_hits --
    # `[hit for hit in rip_hits if hit.region.allocation_base in
    # rwx_and_pe_alloc_bases]`, over the SAME list, by reference. Checking
    # this as an EXACT filter (not merely a subset) is what catches both a
    # hit that should not have qualified (wrong allocation) and a
    # qualifying hit that was silently dropped, in either direction, while
    # still requiring rip_hits' own relative order to survive the filter.
    _require_exact_filtered_subsequence(
        owned.rip_full_correlation, owned.rip_hits,
        lambda hit: hit.region.allocation_base in owned.rwx_and_pe_alloc_bases,
        "correlation.rip_full_correlation", "correlation.rip_hits",
        "region.allocation_base in rwx_and_pe_alloc_bases")
    return owned


def _require_exact_filtered_subsequence(filtered, source, predicate,
                                         filtered_name: str, source_name: str,
                                         predicate_description: str) -> None:
    """`filtered` must equal exactly `[item for item in source if
    predicate(item)]` -- by identity, in `source`'s own order. Stronger
    than a subset check both ways: a `filtered` item the predicate
    rejects, or a qualifying `source` item missing from `filtered`, are
    both caught, and `filtered` is exactly ONE possible list, not any
    reordering of the right multiset."""
    expected = [item for item in source if predicate(item)]
    if [id(item) for item in filtered] != [id(item) for item in expected]:
        raise ValueError(
            f"{filtered_name} must be exactly the items of {source_name} "
            f"satisfying {predicate_description}, in {source_name}'s own "
            f"relative order -- got a different set, a different order, or "
            f"both")


def _require_subset(subset, superset, subset_name: str, superset_name: str) -> None:
    """Every item of `subset` must BE (by identity) an item of
    `superset` -- not merely equal to one. This mirrors how the real
    producers build these relationships: `aggregate._split_scoreable_pe_hits`
    partitions `validated_pe_hits`' own list into suspicious/informational,
    and `correlation.correlate` filters `rip_hits`' own list into
    `rip_full_correlation` -- both by reference, never by reconstructing an
    equal copy. An equal-but-distinct object here would mean this
    Report's own subset was NOT built that way, which is itself a
    signal the buckets disagree about where an item's own identity came
    from."""
    allowed = {id(item) for item in superset}
    for item in subset:
        if id(item) not in allowed:
            raise ValueError(
                f"{subset_name} holds an item that is not one of "
                f"{superset_name}'s own objects: {item!r}")


def _group_by_allocation(items, region_of) -> dict:
    """`{allocation_base: (region, ...)}`, built from `items` in order --
    the exact grouping `dumpex.core.memory.group_regions_by_allocation`
    (the only real producer of `Correlation.rwx_by_alloc`/`pe_by_alloc`)
    performs, re-derived here so `_require_correlation_matches_buckets`
    has something to compare the stored maps against. A key appears only
    when at least one item actually mapped to it -- the source function's
    own `dict.setdefault(key, []).append(...)` never creates an
    empty-valued key, so neither does this."""
    groups: dict = {}
    for item in items:
        groups.setdefault(region_of(item).allocation_base, []).append(region_of(item))
    return {base: tuple(regions) for base, regions in groups.items()}


def _require_grouped_map_matches(actual, expected: dict, actual_name: str,
                                  source_name: str) -> None:
    """`actual` (a `Correlation` map) must hold EXACTLY `expected`'s keys,
    and for each key, the identical region objects in the identical order
    -- not equal copies, not a different grouping order. Order matters:
    it is what a projection iterates when it lists "every region sharing
    this allocation"."""
    actual_keys, expected_keys = set(actual), set(expected)
    if actual_keys != expected_keys:
        raise ValueError(
            f"{actual_name} covers allocation base(s) "
            f"{sorted(hex(b) for b in actual_keys)}, but grouping "
            f"{source_name} by allocation base gives "
            f"{sorted(hex(b) for b in expected_keys)} -- {actual_name} must be "
            f"exactly that grouping, not an independently supplied map")
    for base in expected_keys:
        if [id(r) for r in actual[base]] != [id(r) for r in expected[base]]:
            raise ValueError(
                f"{actual_name}[0x{base:x}] does not hold exactly "
                f"{source_name}'s own region objects, in the order those "
                f"regions appear in {source_name}")


def _require_correlation_matches_buckets(correlation: Correlation, rwx: tuple,
                                          validated_pe_hits: tuple) -> None:
    """`Correlation.rwx_by_alloc`/`pe_by_alloc`/`rwx_and_pe_alloc_bases`/
    `suspicious_alloc_bases` are not independent facts a caller supplies
    alongside the top-level `rwx`/`validated_pe_hits` buckets -- they are
    `dumpex.hunt.injection.correlation.correlate()`'s own derivation FROM
    those exact buckets (group `[ev.region for ev in rwx]` and
    `[h.region for h in validated_pe_hits]` by allocation base; the two
    alloc-base sets are this correlation's intersection and union). A
    Correlation describing a DIFFERENT set of regions than the buckets it
    is attached to would let one projection read "what shares this
    allocation" from the buckets and another read it from the
    Correlation, with no guarantee the two agree.
    """
    expected_rwx_by_alloc = _group_by_allocation(rwx, lambda ev: ev.region)
    expected_pe_by_alloc = _group_by_allocation(validated_pe_hits, lambda h: h.region)
    _require_grouped_map_matches(correlation.rwx_by_alloc, expected_rwx_by_alloc,
                                  "InjectionEvidence.correlation.rwx_by_alloc",
                                  "InjectionEvidence.rwx")
    _require_grouped_map_matches(correlation.pe_by_alloc, expected_pe_by_alloc,
                                  "InjectionEvidence.correlation.pe_by_alloc",
                                  "InjectionEvidence.validated_pe_hits")

    expected_rwx_and_pe = set(expected_rwx_by_alloc) & set(expected_pe_by_alloc)
    if set(correlation.rwx_and_pe_alloc_bases) != expected_rwx_and_pe:
        raise ValueError(
            f"InjectionEvidence.correlation.rwx_and_pe_alloc_bases "
            f"({sorted(hex(b) for b in correlation.rwx_and_pe_alloc_bases)}) must be "
            f"exactly the allocation bases rwx and validated_pe_hits share "
            f"({sorted(hex(b) for b in expected_rwx_and_pe)})")
    expected_suspicious = set(expected_rwx_by_alloc) | set(expected_pe_by_alloc)
    if set(correlation.suspicious_alloc_bases) != expected_suspicious:
        raise ValueError(
            f"InjectionEvidence.correlation.suspicious_alloc_bases "
            f"({sorted(hex(b) for b in correlation.suspicious_alloc_bases)}) must be "
            f"exactly every allocation base carrying RWX or a validated PE "
            f"({sorted(hex(b) for b in expected_suspicious)})")


def _require_ordered_subsequence(hit_keys: list, source_keys: list,
                                  hits_name: str, source_name: str) -> None:
    """`hit_keys` must be an order-preserving subsequence of `source_keys`
    -- every key present, in the same relative order, none invented. This
    is the one relationship this model CAN verify between a correlation
    hit list and the thread evidence it was filtered from without a raw
    region list: `correlate()`'s own geometric "does this ip/StartAddress
    land inside allocation X" test is not re-derivable here (the domain
    model deliberately holds no `mf`/region list -- see this module's own
    docstring), so this does not re-prove WHICH thread_contexts/
    start_threads entries should have survived the filter, only that every
    one the Correlation claims survived is a genuine, unfabricated
    (thread_id, ...) combination drawn from the bucket in its own order.
    """
    it = iter(source_keys)
    for key in hit_keys:
        for candidate in it:
            if candidate == key:
                break
        else:
            raise ValueError(
                f"{hits_name} holds {key!r}, which is not one of {source_name}'s "
                f"own entries in the expected relative order -- a correlation hit "
                f"must be drawn from the thread evidence it claims to correlate, "
                f"never invented or reordered")


def _require_rip_hits_match_thread_contexts(rip_hits: tuple, thread_contexts: tuple) -> None:
    """Every `RipHitEvidence` in `rip_hits` must be an order-preserving
    subsequence match, by (thread_id, ip, ip_reg), of `InjectionEvidence.
    thread_contexts` -- `correlate()` builds `rip_hits` by iterating
    `thread_contexts` and copying those three fields verbatim onto
    whichever entries pass its geometric filter."""
    hit_keys = [(hit.thread_id, hit.ip, hit.ip_reg) for hit in rip_hits]
    source_keys = [(tc.thread_id, tc.ip, tc.ip_reg) for tc in thread_contexts]
    _require_ordered_subsequence(hit_keys, source_keys,
                                  "InjectionEvidence.correlation.rip_hits",
                                  "InjectionEvidence.thread_contexts")


def _require_start_hits_match_start_threads(start_hits: tuple, start_threads: tuple) -> None:
    """Same relationship as `_require_rip_hits_match_thread_contexts`, for
    `StartHitEvidence`/`start_threads` -- keyed on (thread_id,
    start_address), the two fields `correlate()` copies verbatim from the
    `UnbackedThreadEvidence` a `StartHitEvidence` was built from."""
    hit_keys = [(hit.thread_id, hit.start_address) for hit in start_hits]
    source_keys = [(t.thread_id, t.start_address) for t in start_threads]
    _require_ordered_subsequence(hit_keys, source_keys,
                                  "InjectionEvidence.correlation.start_hits",
                                  "InjectionEvidence.start_threads")


@dataclass(frozen=True)
class CoverageSnapshot:
    """What this run could and could not see, as FACTS rather than as
    rendered reasons.

    Today those facts exist three times in different shapes: the v1.1
    `coverage` dict of booleans and counts, the hand-written
    `coverage_reasons` string list, and the structured
    `dumpex.output.coverage.CoverageReport` built from `observe_source()`
    calls. The three are kept in step only by a comment in aggregate.py
    asking the next editor to keep them in the same order.

    This snapshot holds only the underlying observations. Each of those
    three shapes becomes a projection of it, so a dump that is missing one
    stream can no longer be reported as `partial` by one of them and
    `complete` by another (a real, previously-confirmed regression --
    see aggregate.build_report's own note on `completeness_checks`).

    `region_count`/`thread_info_count`/`module_count` are the record
    counts the structured projection needs for its `sources` entries.
    `None` means "the caller did not supply the underlying list", which is
    a distinct input from an empty list (`0`) -- exactly the distinction
    `observe_source(present=True, items=None)` collapses today, and which
    must be preserved here so the projection can reproduce it verbatim.
    """
    memory_info_stream: bool
    thread_info_stream: bool
    module_list_stream: bool
    thread_list_stream: bool
    threads_total:   int = 0
    contexts_parsed: int = 0
    pe_read_failed:  int = 0
    pe_short_reads:  int = 0
    region_count:      "int | None" = None
    thread_info_count: "int | None" = None
    module_count:      "int | None" = None

    def __post_init__(self):
        for name in ("memory_info_stream", "thread_info_stream",
                     "module_list_stream", "thread_list_stream"):
            _require_bool(getattr(self, name), f"CoverageSnapshot.{name}")
        for name in ("threads_total", "contexts_parsed", "pe_read_failed", "pe_short_reads"):
            _require_count(getattr(self, name), f"CoverageSnapshot.{name}")
        for name in ("region_count", "thread_info_count", "module_count"):
            _require_optional_count(getattr(self, name), f"CoverageSnapshot.{name}")

    @property
    def thread_context(self) -> bool:
        """True iff at least one thread's CONTEXT (RIP/EIP) was parsed --
        i.e. live-execution correlation was able to run at all. Derived
        from `contexts_parsed` rather than stored separately, matching
        today's `coverage["thread_context"] = bool(thread_contexts)`."""
        return self.contexts_parsed > 0

    @property
    def contexts_missing(self) -> int:
        """Threads with no parsed CONTEXT. Clamped at 0: a dump reporting
        more parsed contexts than threads is malformed, not a negative
        gap."""
        return max(0, self.threads_total - self.contexts_parsed)

    @property
    def evaluated(self) -> bool:
        """This hunter ran at all. MemoryInfo OR ThreadInfo is enough --
        RWX/hidden-PE need the first, unbacked threads need the second,
        and either one alone still produces a real (if narrower) result."""
        return self.memory_info_stream or self.thread_info_stream

    @property
    def complete(self) -> bool:
        """Everything in scope was actually examined. A partially-parsed
        thread-context set counts against completeness the same way a
        missing stream does: RIP/EIP correlation is the ONLY path to this
        hunter's HIGH tier, so a thread whose context was never parsed is
        a live-execution correlation that could not be ruled out, not one
        that was checked and came back negative."""
        return (self.memory_info_stream and self.thread_info_stream
                and self.module_list_stream
                and self.pe_read_failed == 0 and self.pe_short_reads == 0
                and self.thread_context and self.contexts_missing == 0)

    @property
    def status(self) -> str:
        """"not_evaluated" / "partial" / "complete", through the shared
        reducer every hunter uses -- never re-derived locally."""
        return derive_coverage_status(self.evaluated, self.complete)


@dataclass(frozen=True)
class InjectionEvidence:
    """Every item this hunter observed, in the buckets its own output
    contract is defined in terms of -- each bucket a tuple of typed,
    immutable evidence, each item type-checked at construction.

    Held once. `InjectionReport.results` reference these SAME objects
    rather than carrying their own copies, so "what the RWX check
    reported" and "what `rwx` contains" cannot describe the same region
    differently -- enforced by identity when the Report is constructed
    (see `InjectionReport._require_results_cite_this_reports_own_evidence`
    and `canonical_items()` below).

    Buckets exist independently of the checks because they are not the
    same set: `validated_pe_hits` is the FULL validated-PE
    set the legacy dict exposes, while the checks report its
    suspicious/informational split (see aggregate._split_scoreable_pe_hits).

    Buckets are not independent of EACH OTHER, though, and the
    relationships between them are enforced by identity too (see
    `_require_bucket_relations`). Type-checking each bucket on its own
    still admits a `validated_pe_hits` describing a PE at 0x1000 while
    `suspicious_pe_hits` -- which is supposed to be a subset of it --
    describes one at 0x2000: two buckets asserting different facts about
    the same split, exactly the drift this model exists to remove, one
    level below the result-versus-bucket case.
    """
    rwx:                   tuple = field(default_factory=tuple)
    validated_pe_hits:     tuple = field(default_factory=tuple)
    mz_only_hits:          tuple = field(default_factory=tuple)
    suspicious_pe_hits:    tuple = field(default_factory=tuple)
    informational_pe_hits: tuple = field(default_factory=tuple)
    start_threads:         tuple = field(default_factory=tuple)
    thread_contexts:       tuple = field(default_factory=tuple)
    correlated_allocations: tuple = field(default_factory=tuple)
    correlation: Correlation = field(default_factory=Correlation)

    _ITEM_TYPES = {
        "rwx":                   RwxRegionEvidence,
        "validated_pe_hits":     HiddenPeEvidence,
        "mz_only_hits":          HiddenPeEvidence,
        "suspicious_pe_hits":    HiddenPeEvidence,
        "informational_pe_hits": HiddenPeEvidence,
        "start_threads":         UnbackedThreadEvidence,
        "thread_contexts":       ThreadContext,
        "correlated_allocations": CorrelatedAllocationEvidence,
    }

    def __post_init__(self):
        # Correlation first: the bucket relations below are checked
        # against the OWNED copy's containers, never the caller's.
        object.__setattr__(self, "correlation", _own_correlation(self.correlation))
        for name, item_type in self._ITEM_TYPES.items():
            object.__setattr__(self, name, _require_items_of(
                getattr(self, name), f"InjectionEvidence.{name}", item_type))
        self._require_bucket_relations()

    def _require_bucket_relations(self) -> None:
        """The relationships between buckets, which come straight from how
        the scan/correlation layer produces them:

          * `suspicious_pe_hits` and `informational_pe_hits` are the exact
            partition of `validated_pe_hits` that
            `aggregate._split_scoreable_pe_hits` produces -- every hit in
            one or the other, never both, never a hit belonging to
            neither, and each keeping validated's own relative order.
            Enforced by IDENTITY: the real producer partitions
            `validated_pe_hits`' own list by reference, never by
            reconstructing an equal copy (see `_require_subset`'s own
            docstring);
          * `mz_only_hits` and `validated_pe_hits` are the two disjoint
            halves of `memory_scan.split_hidden_pe_hits`' output.
            Enforced by EQUALITY, unlike the split above: these two
            buckets are not built one FROM the other by reference (they
            are the two independent output lists of one classification
            pass), so the fact this check protects is "no hit is claimed
            on both sides of that classification", which an
            equal-but-distinct copy violates exactly as much as the
            literal same object would;
          * `correlation.rwx_by_alloc`/`pe_by_alloc`/
            `rwx_and_pe_alloc_bases`/`suspicious_alloc_bases` are exactly
            `rwx`/`validated_pe_hits` grouped by allocation base (see
            `_require_correlation_matches_buckets`), by IDENTITY --
            `group_regions_by_allocation` groups references, never copies;
          * `correlated_allocations` is the materialized join of
            `correlation.rwx_and_pe_alloc_bases` with the two
            per-allocation maps -- one entry per correlated allocation,
            ascending by base, each holding exactly that allocation's RWX
            regions followed by its validated-PE regions, by IDENTITY;
          * `correlation.rip_hits`/`start_hits` are drawn from
            `thread_contexts`/`start_threads` -- see
            `_require_rip_hits_match_thread_contexts`/
            `_require_start_hits_match_start_threads` for exactly what is
            (and, since this model holds no raw region list, is not)
            verified about that relationship.
        """
        _require_correlation_matches_buckets(self.correlation, self.rwx, self.validated_pe_hits)
        _require_rip_hits_match_thread_contexts(self.correlation.rip_hits, self.thread_contexts)
        _require_start_hits_match_start_threads(self.correlation.start_hits, self.start_threads)
        _require_subset(self.suspicious_pe_hits, self.validated_pe_hits,
                         "InjectionEvidence.suspicious_pe_hits",
                         "InjectionEvidence.validated_pe_hits")
        _require_subset(self.informational_pe_hits, self.validated_pe_hits,
                         "InjectionEvidence.informational_pe_hits",
                         "InjectionEvidence.validated_pe_hits")
        suspicious_ids = {id(hit) for hit in self.suspicious_pe_hits}
        informational_ids = {id(hit) for hit in self.informational_pe_hits}
        overlap = suspicious_ids & informational_ids
        if overlap:
            raise ValueError(
                "InjectionEvidence: a validated PE hit is in both "
                "suspicious_pe_hits and informational_pe_hits -- the split is "
                "a partition, and a hit that scores cannot also be "
                "context-only")
        if len(suspicious_ids) + len(informational_ids) != len(self.validated_pe_hits):
            raise ValueError(
                f"InjectionEvidence: suspicious_pe_hits "
                f"({len(suspicious_ids)}) + informational_pe_hits "
                f"({len(informational_ids)}) must partition validated_pe_hits "
                f"({len(self.validated_pe_hits)}) exactly -- a validated hit "
                f"in neither is a hit no projection would ever account for")
        for name, subset_ids in (("suspicious_pe_hits", suspicious_ids),
                                  ("informational_pe_hits", informational_ids)):
            in_validated_order = [id(hit) for hit in self.validated_pe_hits
                                   if id(hit) in subset_ids]
            if in_validated_order != [id(hit) for hit in getattr(self, name)]:
                raise ValueError(
                    f"InjectionEvidence.{name} must keep validated_pe_hits' own "
                    f"relative order -- evidence ordering is part of the output "
                    f"contract, not an implementation detail")

        # Equality, not identity: an equal-but-distinct HiddenPeEvidence in
        # mz_only_hits describing the same region as one in
        # validated_pe_hits is still claiming that region on both sides of
        # a mutually exclusive classification, whether or not it is the
        # literal same Python object.
        validated_set = set(self.validated_pe_hits)
        for hit in self.mz_only_hits:
            if hit in validated_set:
                raise ValueError(
                    f"InjectionEvidence: {hit!r} is in both mz_only_hits and "
                    f"validated_pe_hits -- a hit either passed structural PE "
                    f"validation or it did not")

        bases = [item.allocation_base for item in self.correlated_allocations]
        if bases != sorted(bases) or len(set(bases)) != len(bases):
            raise ValueError(
                f"InjectionEvidence.correlated_allocations must be in ascending "
                f"allocation-base order with no repeats, got "
                f"{[hex(b) for b in bases]}")
        if set(bases) != set(self.correlation.rwx_and_pe_alloc_bases):
            raise ValueError(
                f"InjectionEvidence.correlated_allocations must materialize "
                f"exactly correlation.rwx_and_pe_alloc_bases "
                f"({sorted(hex(b) for b in self.correlation.rwx_and_pe_alloc_bases)}), "
                f"got {sorted(hex(b) for b in bases)}")
        for item in self.correlated_allocations:
            expected = (self.correlation.rwx_by_alloc.get(item.allocation_base, ())
                        + self.correlation.pe_by_alloc.get(item.allocation_base, ()))
            if [id(r) for r in item.regions] != [id(r) for r in expected]:
                raise ValueError(
                    f"InjectionEvidence.correlated_allocations entry for "
                    f"0x{item.allocation_base:x} must hold exactly that "
                    f"allocation's own RWX regions followed by its validated-PE "
                    f"regions, as correlation already recorded them")

    def canonical_items(self) -> tuple:
        """Every evidence object this container holds AT THE TOP LEVEL --
        the exact set a `CheckResult` on the same Report may cite, and the
        set `InjectionReport` enforces citations against.

        Top-level deliberately: an object merely REACHABLE from here (a
        `RegionRef` nested inside an `RwxRegionEvidence`, or inside
        `Correlation.rwx_by_alloc`) is not citable on its own. Admitting
        nested objects would make the containment check vacuous -- almost
        anything is reachable from something -- and would let a check
        report a bare region that no bucket ever accounted for. A future
        check that genuinely needs to cite something new has to have it
        added to a bucket first, which is the point.

        `Correlation`'s own hit tuples are included: `rip_hits`/
        `rip_full_correlation`/`start_hits` ARE top-level evidence
        collections (the live-execution correlation checks cite them
        directly), they just live on the correlation result rather than in
        a separate bucket that would duplicate them.
        """
        items = []
        for name in self._ITEM_TYPES:
            items.extend(getattr(self, name))
        items.extend(self.correlation.rip_hits)
        items.extend(self.correlation.rip_full_correlation)
        items.extend(self.correlation.start_hits)
        return tuple(items)


@dataclass(frozen=True)
class InjectionReport:
    """The injection hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: a `MinidumpFile`/`mf`, a
    `read_region`/address-resolver callable, a verbosity or DetailLevel
    flag, a `Finding`/`HunterRecord`/legacy-dict field, and any
    console-formatted string. Everything a projection needs is already
    reachable from `results`/`evidence`/`coverage`; anything that is not
    is a fact this model is missing, not a reason to hand a projector the
    dump back.
    """
    score: int
    coverage: CoverageSnapshot
    results:  tuple = field(default_factory=tuple)
    evidence: InjectionEvidence = field(default_factory=InjectionEvidence)

    def __post_init__(self):
        _require_count(self.score, "InjectionReport.score")
        if self.score > MAX_SCORE:
            raise ValueError(
                f"InjectionReport.score must be <= {MAX_SCORE}, got {self.score}")
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"InjectionReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, InjectionEvidence):
            raise TypeError(
                f"InjectionReport.evidence must be an InjectionEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        object.__setattr__(self, "results", _require_items_of(
            self.results, "InjectionReport.results", CheckResult))
        self._require_results_cite_this_reports_own_evidence()

    def _require_results_cite_this_reports_own_evidence(self) -> None:
        """"Exactly one canonical result/evidence representation" is a
        structural claim, and this is what makes it one.

        Type-checking `results` and `evidence` separately is not enough:
        it admits a Report whose RWX check reports a region at 0x1000
        while `evidence.rwx` holds a different region at 0x2000. Both
        halves are individually well-formed, and every projection built
        from them would disagree about what this hunter actually observed
        -- the exact parallel-representation drift this model exists to
        remove, present from the moment of construction.

        Membership is checked by IDENTITY, not equality: two equal-but-
        distinct value objects are a second copy of the same fact, which
        is what "held once" forbids, even though nothing could later make
        them differ. Identity also makes the check exact -- a citation
        either is one of this Report's own evidence objects or it is not.
        """
        canonical = {id(item) for item in self.evidence.canonical_items()}
        for result in self.results:
            for item in result.evidence:
                if id(item) not in canonical:
                    raise ValueError(
                        f"InjectionReport: check {result.check!r} cites evidence "
                        f"that is not one of this Report's own evidence objects: "
                        f"{item!r} -- a result may only reference the SAME "
                        f"objects InjectionEvidence holds (see "
                        f"InjectionEvidence.canonical_items), never a second "
                        f"copy or an unaccounted-for item")

    @property
    def max_score(self) -> int:
        """This hunter's fixed score ceiling. A property, not a field:
        `max_score` is a property of the hunter's scoring rule, and a
        per-report value would let one run claim a different scale than
        the one `score` was actually computed against."""
        return MAX_SCORE

    @property
    def status(self) -> str:
        """DETECTED / NOT_DETECTED_IN_SCANNED_SCOPE / INCONCLUSIVE /
        NOT_EVALUATED, derived from score + coverage through the shared
        reducer. Not stored: it is a pure function of two things this
        Report already holds, and storing it is what allows a report whose
        status disagrees with its own score."""
        return derive_status(self.coverage.evaluated, self.score > 0, self.coverage.complete)

    @property
    def confidence(self) -> str:
        """Top-level confidence, reduced from the detection-tagged results
        that actually justified the score -- never inflated from the score
        alone (see overall_confidence's own docstring)."""
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
