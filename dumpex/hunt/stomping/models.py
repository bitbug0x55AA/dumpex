"""Immutable module-stomping evidence values.

Module, section, region, reference identity, relocation, byte-difference, thread,
and IOC facts are snapshotted by value. The model preserves the distinction
between verified content change, protection-only leads, and incomplete
comparison coverage.
"""
import ntpath
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._domain import as_tuple, require_recursively_immutable
from dumpex.output.coverage import ScanTarget


# ── Shared field validators ───────────────────────────────────────────────
# Same two-layer defense dumpex.hunt.encoding.models applies: an exact
# item/field TYPE check (so a poison reference is refused at the earliest,
# most specific point, with a message naming the field) plus a
# `require_recursively_immutable` depth walk (so a mutable payload smuggled
# a level or more INSIDE an otherwise well-typed field cannot survive
# either).

def _require_type(value, expected, field_name: str) -> None:
    if not isinstance(value, expected):
        expected_names = (expected.__name__ if isinstance(expected, type)
                          else " or ".join(t.__name__ for t in expected))
        raise TypeError(
            f"{field_name} must be a {expected_names}, got {type(value).__name__}: {value!r}")


def _require_optional_type(value, expected, field_name: str) -> None:
    if value is not None:
        _require_type(value, expected, field_name)


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}: {value!r}")


def _require_str(value, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, got {type(value).__name__}: {value!r}")


def _require_count(value, field_name: str) -> None:
    # bool is excluded explicitly: it is an int subclass, and a stray
    # boolean where a count/address was meant is a caller bug, not 0/1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be a non-negative int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


def _require_typed_tuple(value, expected, field_name: str) -> tuple:
    """Normalize to a tuple, require every item to be `expected`, and walk
    the whole tuple for immutability -- see this module's own docstring for
    why both halves are needed (a shallow `tuple(value)` only copies the
    OUTER container; a `list` smuggled inside item[0] would still be
    reachable and still mutable afterward)."""
    expected_names = (expected.__name__ if isinstance(expected, type)
                      else " or ".join(t.__name__ for t in expected))
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if not isinstance(item, expected):
            raise TypeError(
                f"{field_name}[{index}] must be a {expected_names}, got "
                f"{type(item).__name__}: {item!r}")
    require_recursively_immutable(items, field_name)
    return items


def _require_diff_ranges(value, field_name: str) -> tuple:
    """`((offset, length), ...)` -- normalized to a tuple of 2-tuples of
    non-negative ints. `diff_byte_ranges()` produces a list of tuples; this
    is the one place that becomes an immutable, validated shape, so no
    projector has to defend against a range whose length is a string."""
    items = as_tuple(value, field_name)
    out = []
    for index, item in enumerate(items):
        pair = as_tuple(item, f"{field_name}[{index}]")
        if len(pair) != 2:
            raise ValueError(
                f"{field_name}[{index}] must be an (offset, length) pair, got {pair!r}")
        _require_count(pair[0], f"{field_name}[{index}].offset")
        _require_count(pair[1], f"{field_name}[{index}].length")
        out.append((pair[0], pair[1]))
    return tuple(out)


# ── Identity snapshots ────────────────────────────────────────────────────

def _module_basename(module) -> str:
    """
    Module paths recorded in a minidump are from the ORIGINAL Windows
    system (e.g. 'C:\\Windows\\System32\\foo.dll'). os.path.basename only
    splits on '/' when running on a POSIX analysis host, so it returns the
    whole backslash-separated string unchanged there — ntpath.basename
    always applies Windows path rules regardless of the host OS this
    tool itself runs on.

    Lives here (rather than in memory_scan.py, where it used to) because
    it is now part of building a `ModuleRef`: the basename is resolved
    exactly ONCE, at scan time, and every later consumer reads
    `ModuleRef.basename` instead of re-deriving it from a raw `Module` the
    domain model must not retain. `memory_scan.py`/`disk_reference.py`
    re-export/import it from here, so their own call sites are unchanged.
    """
    return ntpath.basename(module.name or "") if module.name else ""


def module_ref(module) -> "ModuleRef":
    """The ONE place a raw minidump `Module` becomes an immutable identity
    snapshot -- `basename` is resolved through `_module_basename()` here,
    once, so no projector ever needs the `Module` object (or `ntpath`)
    again."""
    return ModuleRef(name=module.name or "", basename=_module_basename(module),
                      base_address=module.baseaddress, size=module.size or 0)


def section_ref(section: dict) -> "SectionRef":
    """The ONE place one entry of `dumpex.core.pe_utils.parse_pe_header()`'s
    `sections` list becomes an immutable value object. Every field that
    dict carries is copied through -- the v2 `StompingDetails` wire shape
    already exposes all nine verbatim (`dict(lead["section"])`), and that
    content must not shrink as part of this migration."""
    return SectionRef(
        name=section["name"], virtual_address=section["virtual_address"],
        virtual_size=section["virtual_size"],
        pointer_to_raw_data=section["pointer_to_raw_data"],
        size_of_raw_data=section["size_of_raw_data"],
        characteristics=section["characteristics"],
        is_executable=bool(section["is_executable"]),
        is_writable=bool(section["is_writable"]),
        is_readable=bool(section["is_readable"]))


def region_ref(region) -> "RegionRef":
    """The ONE place a raw minidump MemoryInfo region becomes an immutable
    `RegionRef` -- `state`/`protect`/`type` go through `prot_str()` here,
    once, so no projector ever calls it on a live region again."""
    return RegionRef(base_address=region.BaseAddress,
                      allocation_base=getattr(region, "AllocationBase", None),
                      size=region.RegionSize, state=prot_str(region.State),
                      protect=prot_str(region.Protect), type=prot_str(region.Type))


@dataclass(frozen=True)
class ModuleRef:
    """Immutable snapshot of one loaded module's identity -- everything any
    projection ever needs about a module, without holding the `Module`
    object itself. `name` is the module's own recorded (Windows) path, kept
    because the v2 `StompingDetails` wire shape exposes it verbatim;
    `basename` is `_module_basename(module)`, resolved once at scan time."""
    name: str
    basename: str
    base_address: int
    size: int = 0

    def __post_init__(self):
        _require_str(self.name, "ModuleRef.name")
        _require_str(self.basename, "ModuleRef.basename")
        _require_count(self.base_address, "ModuleRef.base_address")
        _require_count(self.size, "ModuleRef.size")


@dataclass(frozen=True)
class SectionRef:
    """Immutable projection of one `parse_pe_header()['sections']` entry --
    stomping's own type rather than an import of
    `dumpex.hunt.encoding.models.PeSectionInfo`: the two hunters are
    independently owned, and a shared evidence type across DIFFERENT
    hunters would couple two output contracts that are free to diverge."""
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int
    characteristics: int
    is_executable: bool
    is_writable: bool
    is_readable: bool

    def __post_init__(self):
        _require_str(self.name, "SectionRef.name")
        for attribute in ("virtual_address", "virtual_size", "pointer_to_raw_data",
                          "size_of_raw_data", "characteristics"):
            _require_count(getattr(self, attribute), f"SectionRef.{attribute}")
        for attribute in ("is_executable", "is_writable", "is_readable"):
            _require_bool(getattr(self, attribute), f"SectionRef.{attribute}")


@dataclass(frozen=True)
class RegionRef:
    """Immutable snapshot of a MemoryInfo region's identity. `state`/
    `protect`/`type` are `prot_str()`-resolved once at scan time (see
    `region_ref()` above)."""
    base_address: int
    allocation_base: "int | None"
    size: int
    state: str      # prot_str(region.State),   resolved once at scan time
    protect: str    # prot_str(region.Protect), resolved once at scan time
    type: str       # prot_str(region.Type),    resolved once at scan time

    def __post_init__(self):
        _require_count(self.base_address, "RegionRef.base_address")
        _require_optional_count(self.allocation_base, "RegionRef.allocation_base")
        _require_count(self.size, "RegionRef.size")
        for attribute in ("state", "protect", "type"):
            _require_str(getattr(self, attribute), f"RegionRef.{attribute}")


@dataclass(frozen=True)
class ThreadHitRef:
    """One thread's CURRENT instruction pointer, as
    `dumpex.core.memory.get_thread_contexts()` read it out of
    ThreadListStream's per-thread CONTEXT/WOW64_CONTEXT.

    That function returns plain `{"ThreadId", "ip", "ip_reg", "is_wow64"}`
    dicts; this is that dict's typed equivalent, so a raw thread-context
    dict never survives past correlation.py into the Report (mirrors
    `dumpex.hunt.injection.models.ThreadContext`)."""
    thread_id: int
    ip: int
    ip_reg: str     # "RIP" (native x64) or "EIP" (WOW64 32-on-64)

    def __post_init__(self):
        _require_count(self.thread_id, "ThreadHitRef.thread_id")
        _require_count(self.ip, "ThreadHitRef.ip")
        _require_str(self.ip_reg, "ThreadHitRef.ip_reg")

    @classmethod
    def from_context(cls, context: dict) -> "ThreadHitRef":
        return cls(thread_id=context["ThreadId"], ip=context["ip"],
                   ip_reg=context.get("ip_reg", "RIP"))


# ── Evidence ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProtectionLeadEvidence:
    """One declared-executable, declared-non-writable section whose LIVE
    protection deviates from the normal, unmodified-mapping set -- an
    unscored LEAD (see dumpex/hunt/stomping/__init__.py's module docstring
    for why deviation alone proves nothing about content either way).

    Replaces the pre-migration `{"module": <Module>, "section": <dict>,
    "region": <MinidumpMemoryInfo>, ...}` hand-rolled dict, which kept two
    live minidump objects reachable from the Report."""
    module:   ModuleRef
    section:  SectionRef
    region:   RegionRef
    expected: str
    actual:   str
    va_start: int
    va_end:   int
    file_offset: "int | None" = None   # .dmp offset of va_start, or None if
                                        # those bytes were never captured

    def __post_init__(self):
        _require_type(self.module, ModuleRef, "ProtectionLeadEvidence.module")
        _require_type(self.section, SectionRef, "ProtectionLeadEvidence.section")
        _require_type(self.region, RegionRef, "ProtectionLeadEvidence.region")
        _require_str(self.expected, "ProtectionLeadEvidence.expected")
        _require_str(self.actual, "ProtectionLeadEvidence.actual")
        _require_count(self.va_start, "ProtectionLeadEvidence.va_start")
        _require_count(self.va_end, "ProtectionLeadEvidence.va_end")
        _require_optional_count(self.file_offset, "ProtectionLeadEvidence.file_offset")
        require_recursively_immutable(self, "ProtectionLeadEvidence")


@dataclass(frozen=True)
class RipCorrelatedLeadEvidence:
    """One protection-deviation lead that ALSO has a thread's current
    RIP/EIP executing inside that exact section's VA range.

    `lead` is the SAME `ProtectionLeadEvidence` instance the Report's own
    `protection_leads` bucket holds (never a copy) -- enforced by identity
    in `StompingEvidence`, so the two buckets can never describe the same
    section differently."""
    lead:   ProtectionLeadEvidence
    thread: ThreadHitRef

    def __post_init__(self):
        _require_type(self.lead, ProtectionLeadEvidence, "RipCorrelatedLeadEvidence.lead")
        _require_type(self.thread, ThreadHitRef, "RipCorrelatedLeadEvidence.thread")
        require_recursively_immutable(self, "RipCorrelatedLeadEvidence")


@dataclass(frozen=True)
class VerifiedChangeEvidence:
    """One section with relocation-normalized, byte-level content
    differences against an identity-matched --ref-dir reference file -- the
    ONLY evidence type that can move this hunter's score.

    RIP correlation (`rip_in_changed_range`) and display truncation
    (`diff_ranges` capped at `config.MAX_DIFF_RANGES`, `total_ranges`
    keeping the real total) are BOTH applied at construction time, in
    correlation.py: the RIP scan must see every range the diff produced
    (up to MAX_DIFF_RANGES_SCAN), not the display-truncated slice, so doing
    it any later would silently lose a hit in e.g. the 21st range."""
    module:               ModuleRef
    section:              SectionRef
    va_start:             int
    diff_ranges:          tuple = field(default_factory=tuple)   # ((offset, length), ...)
    ranges_truncated:     bool = False
    total_ranges:         int = 0
    compared_len:         int = 0
    rip_in_changed_range: bool = False
    disk_sha256:          str = ""
    mem_sha256:           str = ""
    file_offset:          "int | None" = None   # .dmp offset of va_start, or None
                                                 # if those bytes were never captured

    def __post_init__(self):
        _require_type(self.module, ModuleRef, "VerifiedChangeEvidence.module")
        _require_type(self.section, SectionRef, "VerifiedChangeEvidence.section")
        _require_count(self.va_start, "VerifiedChangeEvidence.va_start")
        object.__setattr__(self, "diff_ranges", _require_diff_ranges(
            self.diff_ranges, "VerifiedChangeEvidence.diff_ranges"))
        _require_bool(self.ranges_truncated, "VerifiedChangeEvidence.ranges_truncated")
        _require_count(self.total_ranges, "VerifiedChangeEvidence.total_ranges")
        _require_count(self.compared_len, "VerifiedChangeEvidence.compared_len")
        _require_bool(self.rip_in_changed_range, "VerifiedChangeEvidence.rip_in_changed_range")
        _require_str(self.disk_sha256, "VerifiedChangeEvidence.disk_sha256")
        _require_str(self.mem_sha256, "VerifiedChangeEvidence.mem_sha256")
        _require_optional_count(self.file_offset, "VerifiedChangeEvidence.file_offset")
        if self.total_ranges < len(self.diff_ranges):
            raise ValueError(
                f"VerifiedChangeEvidence.total_ranges ({self.total_ranges}) must be >= the "
                f"{len(self.diff_ranges)} range(s) kept for display -- total_ranges is the "
                f"real count before display truncation, never a smaller one")
        require_recursively_immutable(self, "VerifiedChangeEvidence")


@dataclass(frozen=True)
class IdentityMismatchEvidence:
    """One section whose matching-basename reference file under --ref-dir
    failed the build-identity check (Machine/SizeOfImage/TimeDateStamp), so
    the comparison was skipped rather than risk a false positive from
    diffing against a different build -- a coverage gap, not a result."""
    module:  ModuleRef
    section: SectionRef
    reason:  str

    def __post_init__(self):
        _require_type(self.module, ModuleRef, "IdentityMismatchEvidence.module")
        _require_type(self.section, SectionRef, "IdentityMismatchEvidence.section")
        _require_str(self.reason, "IdentityMismatchEvidence.reason")
        require_recursively_immutable(self, "IdentityMismatchEvidence")


@dataclass(frozen=True)
class ParseFailedEvidence:
    """One loaded, known module whose OWN PE header failed structural
    validation at its recorded base address -- itself unusual (the loader
    required a valid header to map it), and a module that could not be
    checked for stomping at all.

    Carries a `ModuleRef` rather than a bare base address: the raw `Module`
    is always in scope at the one construction site (the header READ
    succeeded; only `parse_pe_header()` rejected the bytes), so there is no
    case where the module's identity is unavailable here."""
    module: ModuleRef
    reason: str

    def __post_init__(self):
        _require_type(self.module, ModuleRef, "ParseFailedEvidence.module")
        _require_str(self.reason, "ParseFailedEvidence.reason")
        require_recursively_immutable(self, "ParseFailedEvidence")


@dataclass(frozen=True)
class IocTokenHit:
    """One IOC-pattern token match inside one scanned region. `offset` is a
    region-relative BYTE offset (`_extract_ioc_strings` reports each run's
    byte offset, and `_classify_ioc_hits` scales the match's character index
    inside that run by the run's own encoding width); `va` is the absolute
    process address, resolved once here so no projector re-adds
    `region.base_address + offset` and risks disagreeing with another."""
    offset:   int
    va:       int
    # One of `dumpex.core.memory.IOC_STRING_ENCODING_WIDTHS`' keys, which is
    # also where that encoding's byte-per-character width is defined.
    encoding: str
    token:    str
    is_weak:  bool = False   # an API name that also appears in plenty of
                              # benign code (see memory_scan._WEAK_IOC_TERMS)

    def __post_init__(self):
        _require_count(self.offset, "IocTokenHit.offset")
        _require_count(self.va, "IocTokenHit.va")
        _require_str(self.encoding, "IocTokenHit.encoding")
        _require_str(self.token, "IocTokenHit.token")
        _require_bool(self.is_weak, "IocTokenHit.is_weak")


@dataclass(frozen=True)
class IocHitEvidence:
    """One executable MEM_IMAGE region with at least one STRONG (non-weak)
    IOC-keyword token in it. Replaces the pre-migration
    `(region, module, hits, not_whitelisted)` 4-tuple, whose first two
    members were a live `MinidumpMemoryInfo` and a live `Module`.

    `module` is None when `addr_to_module()` could not attribute the region
    to any known module -- a real, distinct state the projections render as
    "(unknown)", never as an empty name."""
    region:           RegionRef
    module:           "ModuleRef | None"
    tokens:           tuple = field(default_factory=tuple)   # tuple[IocTokenHit]
    not_whitelisted:  bool = True

    def __post_init__(self):
        _require_type(self.region, RegionRef, "IocHitEvidence.region")
        _require_optional_type(self.module, ModuleRef, "IocHitEvidence.module")
        object.__setattr__(self, "tokens", _require_typed_tuple(
            self.tokens, IocTokenHit, "IocHitEvidence.tokens"))
        _require_bool(self.not_whitelisted, "IocHitEvidence.not_whitelisted")
        require_recursively_immutable(self, "IocHitEvidence")


# ── Scan-layer transport shapes ───────────────────────────────────────────
# Frozen like everything else, but never retained on the Report itself:
# these are what a scan function RETURNS, consumed once by the
# orchestration loop / aggregate.py. Frozen anyway so a scan's own result
# cannot be mutated between collection and that one read (the same
# reasoning dumpex.hunt.encoding.models.LayerResult/DecodeResult document).

@dataclass(frozen=True)
class IocCoverage:
    """Immutable snapshot of the unscored IOC-string scan's own
    `dumpex.hunt._coverage.CoverageTracker` at the point that scan
    finished -- the ONE place that live, still-mutable tracker gets frozen
    before it can cross the scan/aggregate boundary. Without this, the
    tracker itself (an ordinary, non-frozen dataclass with a mutable
    `skipped_oversize_targets` list) would stay reachable -- and mutable --
    after `scan_ioc_strings()` returns.

    `whitelisted_skipped` is not a coverage GAP: it records the whitelisted
    network DLLs whose regions WERE fully scanned, just with the network-
    IOC pattern set deliberately not applied (network strings are expected
    there). It rides along here because it is the same scan's own
    "what did this pass actually do" record."""
    skipped_oversize_targets: tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    read_failed:              int = 0
    read_failed_targets:      tuple = field(default_factory=tuple)   # tuple[ScanTarget] -- issue #28
    short_reads:              int = 0
    short_read_targets:       tuple = field(default_factory=tuple)   # tuple[ScanTarget] -- issue #28
    whitelisted_skipped:      tuple = field(default_factory=tuple)   # tuple[str]
    # Every whitelisted module whose region was scanned with the NETWORK IOC
    # pattern set withheld, recorded whether or not that region then produced
    # a non-network hit. `whitelisted_skipped` above is the narrower
    # console-facing fact (whitelisted regions that yielded nothing at all);
    # this one answers "was a whole pattern class not applied to these bytes",
    # which is what stops a scan that deliberately narrowed itself from
    # reading as a full-search negative.
    network_ioc_withheld:     tuple = field(default_factory=tuple)   # tuple[str]
    # The tracker's reconciliation ledger, carried across the scan/
    # aggregate boundary rather than collapsed into a bool -- see
    # `unaccounted` below.
    scanned:                  int = 0
    eligible_total:           int = 0
    # Captured bytes the regions behind `eligible_total` add up to --
    # the scale an unscanned proportion is read against (see
    # dumpex.output.coverage.CoverageReport.eligible_bytes).
    eligible_bytes:           "int | None" = None
    not_applicable:           int = 0
    budget_skipped:           int = 0
    unaccounted:              int = 0
    over_accounted:           int = 0

    def __post_init__(self):
        object.__setattr__(self, "skipped_oversize_targets", _require_typed_tuple(
            self.skipped_oversize_targets, ScanTarget, "IocCoverage.skipped_oversize_targets"))
        _require_count(self.read_failed, "IocCoverage.read_failed")
        _require_count(self.short_reads, "IocCoverage.short_reads")
        for name in ("scanned", "eligible_total", "not_applicable",
                     "budget_skipped", "unaccounted", "over_accounted"):
            _require_count(getattr(self, name), f"IocCoverage.{name}")
        _require_optional_count(self.eligible_bytes, "IocCoverage.eligible_bytes")
        object.__setattr__(self, "read_failed_targets", _require_typed_tuple(
            self.read_failed_targets, ScanTarget, "IocCoverage.read_failed_targets"))
        object.__setattr__(self, "short_read_targets", _require_typed_tuple(
            self.short_read_targets, ScanTarget, "IocCoverage.short_read_targets"))
        object.__setattr__(self, "whitelisted_skipped", _require_typed_tuple(
            self.whitelisted_skipped, str, "IocCoverage.whitelisted_skipped"))
        object.__setattr__(self, "network_ioc_withheld", _require_typed_tuple(
            self.network_ioc_withheld, str, "IocCoverage.network_ioc_withheld"))
        require_recursively_immutable(self, "IocCoverage")

    @property
    def accounted(self) -> int:
        """Every disposition carried across this boundary, summed exactly
        as `dumpex.hunt._coverage.CoverageTracker.accounted` sums them --
        see its DISPOSITION_COUNTERS for the set both have to agree on."""
        return (self.scanned + self.not_applicable + self.budget_skipped
                + self.read_failed + len(self.skipped_oversize_targets))

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

    @classmethod
    def from_tracker(cls, tracker, whitelisted_skipped=(),
                      network_ioc_withheld=()) -> "IocCoverage":
        return cls(skipped_oversize_targets=tuple(tracker.skipped_oversize_targets),
                   read_failed=tracker.read_failed,
                   read_failed_targets=tuple(tracker.read_failed_targets),
                   short_reads=tracker.short_reads,
                   short_read_targets=tuple(tracker.short_read_targets),
                   whitelisted_skipped=tuple(whitelisted_skipped),
                   network_ioc_withheld=tuple(network_ioc_withheld),
                   scanned=tracker.scanned, eligible_total=tracker.total,
                   eligible_bytes=tracker.eligible_bytes,
                   not_applicable=tracker.not_applicable,
                   budget_skipped=tracker.budget_skipped,
                   unaccounted=tracker.unaccounted,
                   over_accounted=tracker.over_accounted)

    @property
    def complete(self) -> bool:
        return not (self.skipped_oversize_targets or self.read_failed
                    or self.short_reads) and self.reconciled


@dataclass(frozen=True)
class IocScanResult:
    """What `memory_scan.scan_ioc_strings()` returns.

    `weak_only_regions` counts regions whose ONLY matches were weak/common-
    API tokens, which are deliberately not surfaced as a lead. Nothing
    projects it today (nothing did before this migration either) -- it is
    kept as a plain count on this scan-layer transport shape rather than
    promoted onto the Report, so the fact is not lost while also not
    becoming an unread field of the canonical domain model."""
    hits:              tuple = field(default_factory=tuple)   # tuple[IocHitEvidence]
    coverage:          IocCoverage = field(default_factory=IocCoverage)
    weak_only_regions: int = 0

    def __post_init__(self):
        object.__setattr__(self, "hits", _require_typed_tuple(
            self.hits, IocHitEvidence, "IocScanResult.hits"))
        _require_type(self.coverage, IocCoverage, "IocScanResult.coverage")
        _require_count(self.weak_only_regions, "IocScanResult.weak_only_regions")
        # isinstance() alone only proves `coverage` is TYPED as an
        # IocCoverage, not that its CURRENT state is still well-formed: a
        # caller holding a reference can poison an already-built one via
        # object.__setattr__ (frozen blocks reassignment, not that).
        require_recursively_immutable(self, "IocScanResult")


@dataclass(frozen=True)
class SectionDiffResult:
    """One eligible section's raw on-disk-vs-memory diff result, BEFORE RIP
    correlation and display truncation are applied -- the pre-migration
    `VerifiedChangeCandidate`, now frozen and holding identity snapshots
    instead of a raw `Module` and a `parse_pe_header()` section dict.
    Consumed exactly once, by `correlation.build_verified_changes()`, which
    turns it into the `VerifiedChangeEvidence` the Report actually keeps."""
    module:                   ModuleRef
    section:                  SectionRef
    va_start:                 int
    all_ranges:               tuple = field(default_factory=tuple)  # every range, up to
                                                                     # MAX_DIFF_RANGES_SCAN
    ranges_truncated_by_scan: bool = False
    compared_len:             int = 0
    disk_sha256:              str = ""
    mem_sha256:               str = ""
    file_offset:              "int | None" = None

    def __post_init__(self):
        _require_type(self.module, ModuleRef, "SectionDiffResult.module")
        _require_type(self.section, SectionRef, "SectionDiffResult.section")
        _require_count(self.va_start, "SectionDiffResult.va_start")
        object.__setattr__(self, "all_ranges", _require_diff_ranges(
            self.all_ranges, "SectionDiffResult.all_ranges"))
        _require_bool(self.ranges_truncated_by_scan, "SectionDiffResult.ranges_truncated_by_scan")
        _require_count(self.compared_len, "SectionDiffResult.compared_len")
        _require_str(self.disk_sha256, "SectionDiffResult.disk_sha256")
        _require_str(self.mem_sha256, "SectionDiffResult.mem_sha256")
        _require_optional_count(self.file_offset, "SectionDiffResult.file_offset")
        require_recursively_immutable(self, "SectionDiffResult")
