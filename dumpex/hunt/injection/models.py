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
    """One MZ-prefixed candidate region from memory_scan._hunt_hidden_pe(),
    with its structural PE validation result and file offset already
    resolved."""
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
class HiddenPeScan:
    """Result of memory_scan._hunt_hidden_pe(): every MZ-prefixed
    candidate region as a HiddenPeEvidence, plus how many regions could
    not be fully examined. `hits` is normalized to a tuple in
    __post_init__ (accepts list OR tuple on construction, same defensive-
    copy reasoning as dumpex.hunt._finding.Finding's own list fields) so a
    caller can never mutate this Report-bound scan result in place after
    construction by holding onto the list it passed in."""
    hits: tuple              # tuple[HiddenPeEvidence, ...] once constructed
    read_failed: int = 0
    short_reads: int = 0

    def __post_init__(self):
        object.__setattr__(self, "hits", tuple(self.hits))


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
