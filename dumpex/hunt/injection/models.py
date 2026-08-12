"""Internal, immutable Evidence value objects for the injection scan/
correlation pipeline -- built once, at the scan/correlation boundary
(memory_scan.py/thread_scan.py/correlation.py, the only modules that still
touch `mf`/raw minidump Region/ThreadInfo objects), and read by
aggregate.py without ever needing `mf`, a raw minidump object, or a
separate address-lookup table (see aggregate.py's own docstring on the
"raw object + parallel Location dict" pattern this replaces).

Not the public JSON shape -- dumpex/hunt/injection/collect.py projects
these into the v2.6 HunterRecord's typed refs (HuntRegionRef/
HuntPeHeaderHit/HuntThreadRef); aggregate.py's `facts`/Finding.
verbose_facts project them into console/--json text. Both read the SAME
Evidence, so they can never disagree about what a region/hit/thread
actually was.
"""
from dataclasses import dataclass, field
from types import MappingProxyType

from dumpex.hunt._location import Location


@dataclass(frozen=True)
class RegionRef:
    """Immutable snapshot of a MemoryInfo region's identity -- everything
    console/JSON ever need about a region, without holding the region
    object itself. Shared shape across every injection Evidence type that
    references "a region" (RWX/hidden-PE/RIP-hit/StartAddress-hit) -- an
    injection-package-internal reuse, not a cross-hunter abstraction (see
    dumpex/hunt/injection/aggregate.py's own comment on why a shared
    Evidence base class across DIFFERENT hunters isn't adopted yet)."""
    base_address: int
    allocation_base: int
    size: int
    type: str      # prot_str(region.Type), resolved once at scan time
    protect: str   # prot_str(region.Protect), resolved once at scan time


@dataclass(frozen=True)
class PeHeaderInfo:
    """Lean, immutable projection of dumpex.core.pe_utils.parse_pe_header()'s
    dict result -- carries exactly the fields this hunter's Finding/console/
    v2.6-record consumers actually read (see aggregate._pe_facts()/
    _hidden_pe_verbose_fact(), collect._pe_hit_ref()). parse_pe_header()
    itself is a shared dumpex.core.pe_utils utility (also used by
    dumpex.hunt.stomping) and stays untouched -- this is a one-way,
    injection-scoped projection built once at scan time, not a redesign of
    that shared function's own return shape. Deliberately does NOT carry
    sections/data_directories/e_lfanew/machine/has_mz/has_pe_sig/
    time_date_stamp/size_of_image -- nothing in this hunter reads them."""
    valid: bool
    machine_name: "str | None"
    is_pe32_plus: "bool | None"
    number_of_sections: "int | None"
    address_of_entry_point: "int | None"
    image_base: "int | None"
    reason: str


@dataclass(frozen=True)
class RwxRegionEvidence:
    """One PAGE_EXECUTE_READWRITE/WRITECOPY region, with its file offset
    already resolved -- built once in memory_scan._hunt_rwx()."""
    region: RegionRef
    location: Location


@dataclass(frozen=True)
class HiddenPeEvidence:
    """One MZ candidate found by memory_scan._hunt_hidden_pe(), with its
    structural PE validation result and file offset already resolved.

    `region` is the containing MemoryInfo region -- region identity (and
    with it `allocation_base`, which allocation correlation is keyed on)
    describes where the candidate LIVES, never where it starts.

    `location` is the candidate's OWN address: `location.va` is the
    address the 'MZ' was actually found at, `location.region_offset` how
    far into `region` that is, and `location.file_offset` where those
    bytes sit in the .dmp. The two are equal for a PE at a region's base
    and deliberately not equal otherwise -- a PE mapped partway into an
    allocation is exactly the case the region-base-only scan could not see
    at all (issue #26), so collapsing its address back onto
    `region.base_address` would report evidence at an address where there
    is no PE header."""
    region: RegionRef
    pe: PeHeaderInfo
    in_module_list: bool
    location: Location


@dataclass(frozen=True)
class UnbackedThreadEvidence:
    """One thread whose StartAddress has no module backing, with its file
    offset already resolved -- built once in
    thread_scan._hunt_unbacked_threads().

    start_address: the THREAD's OWN raw StartAddress, preserved exactly as
    ThreadInfoListStream reported it -- including None, when a real
    ThreadInfo entry carries no StartAddress at all. Never substitute 0
    for None here: doing so would fabricate a fake "known address" that
    the v2.6 HunterRecord adapter (dumpex/hunt/injection/collect.py's
    _thread_ref_from_evidence) would then hex-format as if it were real,
    where the correct wire value is `null`. Classification (addr_to_module)
    and Location resolution both need a concrete int to work with, so
    thread_scan.py uses a LOCAL 0-substituted lookup address for those two
    purposes only, never storing that substitution back onto this field."""
    thread_id: int
    start_address: "int | None"
    location: Location


@dataclass(frozen=True)
class RipHitEvidence:
    """One thread whose CURRENT RIP/EIP lands inside a suspicious
    allocation -- built once in correlation.correlate()."""
    thread_id: int
    ip: int
    ip_reg: str
    region: RegionRef


@dataclass(frozen=True)
class StartHitEvidence:
    """One unbacked thread whose StartAddress lands inside a suspicious
    allocation -- built once in correlation.correlate(). `start_address`
    is the thread's TRUE StartAddress (possibly None -- see
    UnbackedThreadEvidence's own docstring); the geometric lookup that
    produced `region` uses a 0-substituted address internally but never
    stores that substitution here."""
    thread_id: int
    start_address: "int | None"
    region: RegionRef


@dataclass(frozen=True)
class ThreadContext:
    """One thread's CURRENT instruction pointer, as
    dumpex.core.memory.get_thread_contexts() read it out of
    ThreadListStream's per-thread CONTEXT/WOW64_CONTEXT.

    That function returns plain `{"ThreadId", "ip", "ip_reg", "is_wow64"}`
    dicts -- the last hand-rolled dict shape still flowing through this
    hunter's Report (`findings["thread_contexts"]`), and the reason
    dumpex/hunt/injection/collect.py still needs a dict-subscripting
    `_thread_ref_from_context(ctx)` adapter where every other ref adapter
    next to it reads a typed Evidence attribute. This is that dict's typed
    equivalent: same four facts, same names in Evidence style, immutable,
    and unable to acquire a stray extra key later.

    A thread whose context could not be parsed at all is simply ABSENT
    from the collected tuple -- never present with ip=0 (see
    get_thread_contexts()'s own docstring: "not in this list" means "no
    live IP available", which is a different claim than "IP is 0")."""
    thread_id: int
    ip: int
    ip_reg: str      # "RIP" (native x64) or "EIP" (WOW64 32-on-64)
    is_wow64: bool


@dataclass(frozen=True)
class CorrelatedAllocationEvidence:
    """One AllocationBase that carries BOTH an RWX sub-region AND a
    validated hidden PE header -- the structural (non-live-execution)
    correlation aggregate.py currently re-joins at render time by looking
    each allocation base up in Correlation.rwx_by_alloc and
    Correlation.pe_by_alloc and concatenating the two.

    Built once as its own value object so that join happens in the
    correlation layer that already owns those maps, and every projection
    reads the SAME already-joined region tuple. `regions` keeps that
    concatenation's existing order (every RWX region for this allocation,
    then every validated-PE region) -- ordering is part of the output
    contract, not an implementation detail."""
    allocation_base: int
    regions: tuple           # tuple[RegionRef, ...] once constructed

    def __post_init__(self):
        # list/tuple only, never "anything iterable": a bare string would
        # silently explode into its characters, a set/dict would carry
        # hash-order-dependent ordering into a field whose order IS the
        # contract, and a generator would work once and then read empty.
        # Element type is checked too -- this tuple is what every
        # projection renders, so a non-RegionRef here surfaces as a
        # projector reading an attribute that does not exist rather than
        # as a construction error.
        if not isinstance(self.regions, (list, tuple)):
            raise TypeError(
                f"CorrelatedAllocationEvidence.regions must be a list or tuple, "
                f"got {type(self.regions).__name__}")
        for index, region in enumerate(self.regions):
            if not isinstance(region, RegionRef):
                raise TypeError(
                    f"CorrelatedAllocationEvidence.regions[{index}] must be a "
                    f"RegionRef, got {type(region).__name__}: {region!r}")
        object.__setattr__(self, "regions", tuple(self.regions))


@dataclass(frozen=True)
class BudgetTargetGroup:
    """One (budget_kind, budget_limit, budget_consumed) attribution and
    EVERY ScanTarget whose region actually stopped on exactly that budget
    (issue #28 P5 follow-up). `HiddenPeScan.scan_truncated_groups`/
    `scan_not_started_groups` hold one of these per DISTINCT budget kind
    that stopped at least one region during a single `_hunt_hidden_pe`
    call -- replacing a prior version's single first-occurrence-only
    attribution, which silently misattributed every OTHER budget's own
    targets to whichever budget happened to exhaust first (e.g. region 1
    truncated by `validations_per_region`, a DIFFERENT region 2 truncated
    later in the same call by `validations_total`, both previously
    reported under one `scope=validations_per_region` limitation, falsely
    implying region 2 was ALSO stopped by `validations_per_region`).

    `budget_limit`/`budget_consumed` are always equal (see
    `memory_scan._ScanBudget.exhausted_budget_info()`'s own docstring for
    why: a budget is only ever attributed once it is fully exhausted) and
    are the SAME two values for every group sharing this `budget_kind`
    within one call, since a `_ScanBudget`'s own configured limits never
    change mid-call."""
    budget_kind: str
    budget_limit: int
    budget_consumed: int
    targets: tuple

    def __post_init__(self):
        object.__setattr__(self, "targets", tuple(self.targets))


@dataclass(frozen=True)
class HiddenPeScan:
    """Result of memory_scan._hunt_hidden_pe(): every MZ candidate found
    anywhere in an eligible region as a HiddenPeEvidence, plus how many
    regions could not be fully examined, by reason -- `read_failed` (a
    read raised), `short_reads` (a read came back with fewer bytes than
    requested, leaving candidate offsets or a candidate's own header
    unexamined), `scan_truncated` (this region's OWN search got PART of it
    before the read budget ran out -- an unfinished remainder),
    `scan_not_started` (issue #28: a LATER region the whole-hunt budget
    was already exhausted before this call's own search ever issued a
    single read for -- nothing here was examined at all, a materially
    different fact from a partially-searched region). Each counts
    REGIONS, never reads: one region whose search needed many reads
    contributes at most 1 to each.

    All three exist so a negative result can state what it actually
    covered: "no hidden PE found in the parts of memory that were
    searched" is a different claim from "no hidden PE in this process",
    and only the counters make the difference visible (see
    dumpex.hunt.injection.domain.CoverageSnapshot.complete).

    `read_failed_targets`/`short_read_targets` (issue #28) are the region
    identity behind their own counters above -- one ScanTarget per region
    where that gap happened, built at memory_scan._hunt_hidden_pe's own
    region loop (where the raw MemoryInfo region is still in scope)
    rather than reduced to a count before it ever reaches
    CoverageLimitation. `size_limit` stays None on every one of these:
    none of the four gaps is "the region was too big", so there is no cap
    to record (see ScanTarget's own docstring).

    `scan_truncated_groups`/`scan_not_started_groups` (issue #28 P5
    follow-up, replacing a prior flat-targets-plus-single-attribution
    shape) are `tuple[BudgetTargetGroup, ...]` -- see that class's own
    docstring for why grouping by budget_kind, rather than one
    first-occurrence attribution for the whole scan, is required for
    correctness once a hunt run's regions can stop on more than one
    distinct budget. `scan_truncated`/`scan_not_started` above still
    count every affected region (the sum of every group's own
    `len(targets)`), independent of how many distinct budget kinds
    stopped them.

    `validated_dropped`/`unvalidated_dropped` are a DIFFERENT kind of
    fact: those candidates WERE read, found, and structurally validated --
    they simply exceeded the scan's evidence cap (see
    memory_scan._ScanBudget) and are therefore not listed. Both are stated
    as an explicit count on the check they belong to (aggregate.py), and
    the two are treated differently beyond that, because they are not
    equally consequential:

      validated_dropped   -- a validated hidden PE header that is not in
                             the report is detection-relevant, so it also
                             counts against coverage completeness
                             (CoverageSnapshot.pe_evidence_capped). It
                             takes hundreds of structurally-valid PE
                             headers in unbacked memory to reach the cap
                             at all, which is not something a benign dump
                             does, so this cannot become routine noise.
      unvalidated_dropped -- an 'MZ' that failed validation is
                             informational only and occurs ~16 times per
                             MB in ordinary memory, so counting it against
                             coverage would mark essentially every dump
                             partial and tell an analyst nothing.

    `hits` is normalized to a tuple in __post_init__ (accepts list OR
    tuple on construction, same defensive-copy reasoning as
    dumpex.hunt._finding.Finding's own list fields) so a caller can never
    mutate this Report-bound scan result in place after construction by
    holding onto the list it passed in."""
    hits: tuple              # tuple[HiddenPeEvidence, ...] once constructed
    read_failed: int = 0
    read_failed_targets: tuple = ()      # tuple[ScanTarget, ...] -- issue #28
    short_reads: int = 0
    short_read_targets: tuple = ()       # tuple[ScanTarget, ...] -- issue #28
    scan_truncated: int = 0
    scan_truncated_groups: tuple = ()    # tuple[BudgetTargetGroup, ...] -- issue #28 P5
    scan_not_started: int = 0
    scan_not_started_groups: tuple = ()  # tuple[BudgetTargetGroup, ...] -- issue #28 P5
    validated_dropped: int = 0
    unvalidated_dropped: int = 0

    def __post_init__(self):
        object.__setattr__(self, "hits", tuple(self.hits))
        object.__setattr__(self, "read_failed_targets", tuple(self.read_failed_targets))
        object.__setattr__(self, "short_read_targets", tuple(self.short_read_targets))
        object.__setattr__(self, "scan_truncated_groups", tuple(self.scan_truncated_groups))
        object.__setattr__(self, "scan_not_started_groups", tuple(self.scan_not_started_groups))
        if any(type(g) is not BudgetTargetGroup for g in self.scan_truncated_groups):
            raise TypeError("HiddenPeScan.scan_truncated_groups must contain only BudgetTargetGroup")
        if any(type(g) is not BudgetTargetGroup for g in self.scan_not_started_groups):
            raise TypeError("HiddenPeScan.scan_not_started_groups must contain only BudgetTargetGroup")


@dataclass(frozen=True)
class Correlation:
    """Everything correlation.py derived from the raw scan results:
    allocation-based structural correlation plus live-execution (RIP/EIP)
    and StartAddress correlation.

    frozen=True alone only stops REASSIGNING these fields -- it does not
    stop `correlation.rwx_by_alloc[addr] = (...)` in place on a plain
    dict, the same in-place-mutation gap Finding's own list fields close
    by normalizing to tuple. __post_init__ closes it here too:
    rwx_by_alloc/pe_by_alloc become `types.MappingProxyType` wrapping a
    FRESH dict (never the caller's own dict object) with tuple values, and
    rip_hits/rip_full_correlation/start_hits are normalized to tuples --
    accepting list/dict on construction (for callers building these
    incrementally) but never leaving a mutable container reachable from
    the constructed instance."""
    rwx_by_alloc: "dict | MappingProxyType" = field(default_factory=dict)          # {alloc_base: tuple[RegionRef, ...]}
    pe_by_alloc: "dict | MappingProxyType" = field(default_factory=dict)            # {alloc_base: tuple[RegionRef, ...]}
    rwx_and_pe_alloc_bases: frozenset = field(default_factory=frozenset)
    suspicious_alloc_bases: frozenset = field(default_factory=frozenset)
    rip_hits: tuple = ()               # tuple[RipHitEvidence, ...]
    rip_full_correlation: tuple = ()   # subset of rip_hits
    start_hits: tuple = ()              # tuple[StartHitEvidence, ...]

    def __post_init__(self):
        object.__setattr__(self, "rwx_by_alloc", MappingProxyType(
            {k: tuple(v) for k, v in self.rwx_by_alloc.items()}))
        object.__setattr__(self, "pe_by_alloc", MappingProxyType(
            {k: tuple(v) for k, v in self.pe_by_alloc.items()}))
        object.__setattr__(self, "rwx_and_pe_alloc_bases", frozenset(self.rwx_and_pe_alloc_bases))
        object.__setattr__(self, "suspicious_alloc_bases", frozenset(self.suspicious_alloc_bases))
        object.__setattr__(self, "rip_hits", tuple(self.rip_hits))
        object.__setattr__(self, "rip_full_correlation", tuple(self.rip_full_correlation))
        object.__setattr__(self, "start_hits", tuple(self.start_hits))
