"""Immutable named-pipe evidence values.

Raw handle, region, thread, and context objects are converted to deterministic
plain-value references at collection time. Handle-confirmed pipes remain
separate from string leads, while scan coverage records independent pipe-name and
C2-context limitations.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._domain import as_tuple, require_recursively_immutable
from dumpex.output.coverage import ScanTarget


# ── Shared field validators ───────────────────────────────────────────────
# Same two-layer defense dumpex.hunt.stomping.models applies: an exact
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


def _require_bytes(value, field_name: str) -> None:
    # Exactly `bytes`, never `bytearray`: a bytearray is mutable, and the
    # C2 context window is retained verbatim on the Report.
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes, got {type(value).__name__}: {value!r}")


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


def dedupe_evidence(items) -> tuple:
    """`items` with any item EQUAL to an earlier one dropped, order
    otherwise preserved.

    The domain's own evidence buckets reject a duplicate-by-equality item
    outright (see `dumpex.hunt.pipe.domain._require_items_of`, the same
    barrier all three completed pilots apply). Two observations that
    compare equal are, by construction, the same observed fact recorded
    twice -- and this hunter has genuinely reachable ways to produce one:
    two distinct `\\pipe\\` string occurrences in the SAME region whose
    bounded previews (capped at config.PIPE_NAME_MAX_CHARS) coincide would
    otherwise yield two identical C2-context/framework-attribution
    entries describing the same region and the same name. Collapsing them
    HERE, in the scan/correlation layer that observed them, keeps that a
    scan-layer fact rather than a construction-time crash in the domain
    model.
    """
    out = []
    for item in items:
        if not any(item == earlier for earlier in out):
            out.append(item)
    return tuple(out)


# ── Identity snapshots ────────────────────────────────────────────────────

def handle_ref(handle) -> "HandleRef":
    """The ONE place a raw HandleDataStream entry
    (`MinidumpHandleDescriptor`) becomes an immutable identity snapshot --
    so no projector ever needs the live handle object again."""
    return HandleRef(handle=handle.Handle,
                      type_name=getattr(handle, "TypeName", None) or "",
                      object_name=handle.ObjectName or "",
                      granted_access=getattr(handle, "GrantedAccess", 0) or 0)


def region_ref(region) -> "RegionRef":
    """The ONE place a raw minidump MemoryInfo region becomes an immutable
    `RegionRef` -- `state`/`protect`/`type` go through `prot_str()` here,
    once, so no projector ever calls it on a live region again."""
    return RegionRef(base_address=region.BaseAddress,
                      allocation_base=getattr(region, "AllocationBase", None),
                      size=region.RegionSize, state=prot_str(region.State),
                      protect=prot_str(region.Protect), type=prot_str(region.Type))


def thread_hit_ref(context: dict) -> "ThreadHitRef":
    """One `dumpex.core.memory.get_thread_contexts()` dict -> its typed
    equivalent, so a raw thread-context dict never survives past
    correlation.py into the Report."""
    return ThreadHitRef(thread_id=context["ThreadId"], ip=context["ip"],
                         ip_reg=context.get("ip_reg", "RIP"))


def thread_start_ref(info) -> "ThreadStartRef":
    """One ThreadInfoListStream entry -> its typed equivalent. Deliberately
    a DIFFERENT type from `ThreadHitRef`: a StartAddress records where a
    thread BEGAN, a live RIP/EIP records where it is executing NOW, and
    this hunter scores only the latter (see
    `pipe.start_address_proximity_lead`). Two names for the two facts means
    no projector can quietly render one as the other."""
    return ThreadStartRef(thread_id=info.ThreadId, start_address=info.StartAddress)


def framework_attribution(match) -> "FrameworkAttribution | None":
    """`dumpex.hunt.pipe.patterns.framework_match()`'s
    `(framework, technique, mitre)` 3-tuple -> its typed equivalent, or
    None when the name matched no known convention. A positional 3-tuple
    reads identically whether it was built in the right order or not; the
    named fields make the ordering a compile-time-ish fact instead of a
    convention every consumer has to remember."""
    if match is None:
        return None
    framework, technique, mitre = match
    return FrameworkAttribution(framework=framework, technique=technique, mitre=mitre)


@dataclass(frozen=True)
class HandleRef:
    """Immutable snapshot of one open handle's identity, as
    HandleDataStream (MiniDumpWithHandleData) recorded it.

    `granted_access` is an access-mask BITFIELD, not an address/pointer/
    handle -- it stays a plain int here and a plain JSON integer in every
    projection, per this project's own hex-formatting rule."""
    handle:         int
    type_name:      str
    object_name:    str
    granted_access: int = 0

    def __post_init__(self):
        _require_count(self.handle, "HandleRef.handle")
        _require_str(self.type_name, "HandleRef.type_name")
        _require_str(self.object_name, "HandleRef.object_name")
        _require_count(self.granted_access, "HandleRef.granted_access")


@dataclass(frozen=True)
class RegionRef:
    """Immutable snapshot of a MemoryInfo region's identity. `state`/
    `protect`/`type` are `prot_str()`-resolved once at scan time (see
    `region_ref()` above).

    This hunter's own type rather than an import of
    `dumpex.hunt.stomping.models.RegionRef`: the two hunters are
    independently owned, and a shared evidence type across DIFFERENT
    hunters would couple two output contracts that are free to diverge."""
    base_address:    int
    allocation_base: "int | None"
    size:            int
    state:           str    # prot_str(region.State),   resolved once at scan time
    protect:         str    # prot_str(region.Protect), resolved once at scan time
    type:            str    # prot_str(region.Type),    resolved once at scan time

    def __post_init__(self):
        _require_count(self.base_address, "RegionRef.base_address")
        _require_optional_count(self.allocation_base, "RegionRef.allocation_base")
        _require_count(self.size, "RegionRef.size")
        for attribute in ("state", "protect", "type"):
            _require_str(getattr(self, attribute), f"RegionRef.{attribute}")

    @property
    def is_executable(self) -> bool:
        """Whether this region's live protection actually permits
        execution -- the gate RIP/EIP corroboration applies (a thread's
        instruction pointer sitting near a pipe-name string in data-only
        memory cannot be running code from there). Derived from the
        already-resolved `protect` string, so correlation.py never needs
        the live region back to ask."""
        return "EXECUTE" in self.protect


@dataclass(frozen=True)
class ThreadHitRef:
    """One thread's CURRENT instruction pointer, as
    `dumpex.core.memory.get_thread_contexts()` read it out of
    ThreadListStream's per-thread CONTEXT/WOW64_CONTEXT."""
    thread_id: int
    ip:        int
    ip_reg:    str    # "RIP" (native x64) or "EIP" (WOW64 32-on-64)

    def __post_init__(self):
        _require_count(self.thread_id, "ThreadHitRef.thread_id")
        _require_count(self.ip, "ThreadHitRef.ip")
        _require_str(self.ip_reg, "ThreadHitRef.ip_reg")


@dataclass(frozen=True)
class ThreadStartRef:
    """One thread's recorded StartAddress, from ThreadInfoListStream.

    `start_address` is `int | None`, not `int`: a ThreadInfo entry can
    legitimately carry no StartAddress at all, and the v2 wire shape
    renders that as JSON `null` (`hex_address(None)`), never as address
    zero -- an ordinary, valid address."""
    thread_id:     int
    start_address: "int | None"

    def __post_init__(self):
        _require_count(self.thread_id, "ThreadStartRef.thread_id")
        _require_optional_count(self.start_address, "ThreadStartRef.start_address")


@dataclass(frozen=True)
class FrameworkAttribution:
    """One known C2/lateral-movement framework naming convention a pipe
    name matched, from rules.yaml's own `framework_pipes` entries. `mitre`
    is a real ATT&CK id from that ruleset -- never invented here."""
    framework: str
    technique: str
    mitre:     str

    def __post_init__(self):
        for attribute in ("framework", "technique", "mitre"):
            _require_str(getattr(self, attribute), f"FrameworkAttribution.{attribute}")

    def as_tuple(self) -> tuple:
        """The `(framework, technique, mitre)` 3-tuple the v1.1 findings
        dict's `handle_pipes[].framework_match` has always carried --
        rebuilt at projection time (report_legacy.py) rather than stored,
        so the wire shape stays byte-identical without the domain model
        keeping a second, positional copy of the same three facts."""
        return (self.framework, self.technique, self.mitre)


# ── Evidence ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PipeHandleEvidence:
    """One open handle to a named-pipe kernel object, per HandleDataStream
    -- the OS's own record that this process actually opened that pipe,
    which is what makes this hunter's scored path handle-anchored rather
    than string-anchored (see dumpex/hunt/pipe/__init__.py's docstring).

    Replaces the pre-migration `{"handle": <Handle>, "canonical_name":
    str, "framework_match": tuple|None}` hand-rolled dict, which kept a
    live minidump handle object reachable from the Report.

    `framework` is None when the name matched no known convention -- a
    real, distinct state (an ordinary IPC/RPC pipe), never an empty
    attribution."""
    handle:         HandleRef
    canonical_name: str
    framework:      "FrameworkAttribution | None" = None

    def __post_init__(self):
        _require_type(self.handle, HandleRef, "PipeHandleEvidence.handle")
        _require_str(self.canonical_name, "PipeHandleEvidence.canonical_name")
        _require_optional_type(self.framework, FrameworkAttribution,
                                "PipeHandleEvidence.framework")
        require_recursively_immutable(self, "PipeHandleEvidence")


@dataclass(frozen=True)
class PipeStringEvidence:
    """One `\\pipe\\` name occurrence found by the byte-pattern memory scan
    -- a LEAD ONLY, and never scored on its own. See
    dumpex/hunt/pipe/__init__.py's own docstring for why: bytes sitting in
    memory prove nothing about whether any handle was ever opened by that
    name, and this hunter's phase-two policy is that a bare pipe string
    never becomes scored handle evidence.

    `name` is the BOUNDED preview (config.PIPE_NAME_MAX_CHARS); `sha256`/
    `original_length` describe the FULL printable run the scan walked, so
    two long names sharing a truncated preview are still distinguishable.
    `va` (absolute process address) and `file_offset` (.dmp offset, or
    None when those bytes were never captured) are both resolved once, at
    scan time."""
    region:          RegionRef
    offset:          int
    name:            str
    sha256:          str
    original_length: int
    truncated:       bool
    encoding:        str    # "ascii" / "utf16le"
    va:              int
    file_offset:     "int | None" = None

    def __post_init__(self):
        _require_type(self.region, RegionRef, "PipeStringEvidence.region")
        _require_count(self.offset, "PipeStringEvidence.offset")
        _require_str(self.name, "PipeStringEvidence.name")
        _require_str(self.sha256, "PipeStringEvidence.sha256")
        _require_count(self.original_length, "PipeStringEvidence.original_length")
        _require_bool(self.truncated, "PipeStringEvidence.truncated")
        _require_str(self.encoding, "PipeStringEvidence.encoding")
        _require_count(self.va, "PipeStringEvidence.va")
        _require_optional_count(self.file_offset, "PipeStringEvidence.file_offset")
        if self.va != self.region.base_address + self.offset:
            raise ValueError(
                f"PipeStringEvidence.va (0x{self.va:x}) must be this hit's own region base "
                f"plus its region-relative offset (0x{self.region.base_address:x} + "
                f"0x{self.offset:x}) -- the absolute address is resolved once, at scan time, "
                f"and no projector may re-derive a different one")
        require_recursively_immutable(self, "PipeStringEvidence")


@dataclass(frozen=True)
class C2ContextRecord:
    """One C2-style artifact (an IP:port, an HTTP URL, a known URI token)
    matched inside a pipe-bearing region, with a bounded slice of its
    surrounding bytes.

    `context` is `bytes` (config.PIPE_C2_CONTEXT_BYTES at most), NOT a
    `bytearray`: the v2 wire shape hex-encodes it verbatim, so it has to be
    a value the Report can hold without anyone being able to edit it
    afterward. `match` is the bounded token preview
    (config.PIPE_C2_TOKEN_PREVIEW); `original_length` is the real match
    length before that bound."""
    match:           str
    context:         bytes
    va:              int
    sha256:          str
    original_length: int

    def __post_init__(self):
        _require_str(self.match, "C2ContextRecord.match")
        _require_bytes(self.context, "C2ContextRecord.context")
        _require_count(self.va, "C2ContextRecord.va")
        _require_str(self.sha256, "C2ContextRecord.sha256")
        _require_count(self.original_length, "C2ContextRecord.original_length")


@dataclass(frozen=True)
class C2ContextEvidence:
    """One region that holds BOTH a `\\pipe\\` name string and at least one
    C2-style artifact, with no open handle correlating the two --
    informational context, never scored on its own (the scored form is
    `CorroboratedHandleEvidence`, which additionally requires an
    OS-confirmed handle AND proximity to that pipe name's own VA).

    Replaces the pre-migration `(region, pipe_name, records)` 3-tuple,
    whose first member was a live `MinidumpMemoryInfo`.

    `string_hit` is the SAME `PipeStringEvidence` instance the Report's own
    `string_leads` bucket holds (never a reconstructed copy) -- enforced by
    identity in `dumpex.hunt.pipe.domain.PipeEvidence`, the same "held once,
    cited by identity" guarantee `CorroboratedHandleEvidence`/
    `StartAddressLeadEvidence` already apply to their own `string_hit`.
    `region`/`pipe_name` are DERIVED from it rather than a second stored
    copy, so this evidence and the string lead it describes can never
    disagree about which region or which name is meant."""
    string_hit: PipeStringEvidence
    records:    tuple = field(default_factory=tuple)   # tuple[C2ContextRecord]

    def __post_init__(self):
        _require_type(self.string_hit, PipeStringEvidence, "C2ContextEvidence.string_hit")
        object.__setattr__(self, "records", _require_typed_tuple(
            self.records, C2ContextRecord, "C2ContextEvidence.records"))
        require_recursively_immutable(self, "C2ContextEvidence")

    @property
    def region(self) -> RegionRef:
        return self.string_hit.region

    @property
    def pipe_name(self) -> str:
        return self.string_hit.name.strip()


@dataclass(frozen=True)
class CorroboratedHandleEvidence:
    """One handle-confirmed pipe whose matching string occurrence ALSO has
    C2-style context and/or a thread's live RIP/EIP within
    config.PIPE_CONTEXT_DISTANCE of that string's OWN address -- this
    hunter's strongest signal, and the only one that can take the score
    past 1.

    `handle` and `string_hit` are the SAME `PipeHandleEvidence`/
    `PipeStringEvidence` instances the Report's own buckets hold (never
    copies) -- enforced by identity in `PipeEvidence`, so the two views
    can never describe the same handle or the same string differently.

    `nearby_c2` holds the subset of that region's C2 records actually
    inside the window (not the region's whole record list), and `rip_hit`
    is None when no thread's live instruction pointer qualified. Both are
    the CORROBORATION itself, so both are stored rather than re-derived:
    the window test needs the pipe name's own VA plus every record's VA,
    neither of which a projector should be recomputing.

    `pipe_va` is NOT a stored field: it is always this entry's own
    `string_hit.va`, and storing it a second time would let the two
    disagree with no constraint catching it. It stays a property so every
    existing `ev.pipe_va` read (report_facts.py/report_console.py) is
    unaffected."""
    handle:      PipeHandleEvidence
    string_hit:  PipeStringEvidence
    nearby_c2:   tuple = field(default_factory=tuple)   # tuple[C2ContextRecord]
    rip_hit:     "ThreadHitRef | None" = None

    def __post_init__(self):
        _require_type(self.handle, PipeHandleEvidence, "CorroboratedHandleEvidence.handle")
        _require_type(self.string_hit, PipeStringEvidence,
                       "CorroboratedHandleEvidence.string_hit")
        object.__setattr__(self, "nearby_c2", _require_typed_tuple(
            self.nearby_c2, C2ContextRecord, "CorroboratedHandleEvidence.nearby_c2"))
        _require_optional_type(self.rip_hit, ThreadHitRef, "CorroboratedHandleEvidence.rip_hit")
        if not self.nearby_c2 and self.rip_hit is None:
            raise ValueError(
                "CorroboratedHandleEvidence must carry at least one corroborating signal "
                "(nearby C2 context and/or a live RIP/EIP hit) -- an entry with neither is "
                "not corroboration, and would silently score a bare open handle")
        require_recursively_immutable(self, "CorroboratedHandleEvidence")

    @property
    def pipe_va(self) -> int:
        return self.string_hit.va

    @property
    def fully_corroborated(self) -> bool:
        """BOTH independent memory signals at once -- the score-3 case, and
        the only one `pipe.corroboration` reports at HIGH confidence."""
        return bool(self.nearby_c2) and self.rip_hit is not None


@dataclass(frozen=True)
class StartAddressLeadEvidence:
    """One handle-confirmed pipe whose matching string occurrence has an
    unbacked thread's STARTADDRESS -- not its current RIP/EIP -- within
    config.PIPE_CONTEXT_DISTANCE.

    A LEAD ONLY, never scored: StartAddress records where a thread BEGAN,
    not where it is executing now. Kept as its own evidence type (rather
    than a flag on `CorroboratedHandleEvidence`) precisely so nothing can
    accidentally fold it into the scored path.

    `pipe_va` is likewise NOT a stored field -- see
    `CorroboratedHandleEvidence`'s own docstring for why it is derived from
    `string_hit.va` instead."""
    handle:     PipeHandleEvidence
    string_hit: PipeStringEvidence
    thread:     ThreadStartRef

    def __post_init__(self):
        _require_type(self.handle, PipeHandleEvidence, "StartAddressLeadEvidence.handle")
        _require_type(self.string_hit, PipeStringEvidence,
                       "StartAddressLeadEvidence.string_hit")
        _require_type(self.thread, ThreadStartRef, "StartAddressLeadEvidence.thread")
        require_recursively_immutable(self, "StartAddressLeadEvidence")

    @property
    def pipe_va(self) -> int:
        return self.string_hit.va


@dataclass(frozen=True)
class FrameworkStringHitEvidence:
    """One `\\pipe\\` STRING lead whose name matches a known framework
    naming convention, with no corresponding open handle -- framework
    ATTRIBUTION only, never scored.

    Deliberately a different evidence type from
    `PipeHandleEvidence.framework`: the scored
    `pipe.handle_framework_match` check requires an OS-confirmed handle,
    and merging the two would let a bare string acquire the standing of a
    handle -- exactly the distinction this hunter exists to preserve.

    `string_hit` is the SAME `PipeStringEvidence` instance the Report's own
    `string_leads` bucket holds (never a reconstructed copy) -- enforced by
    identity in `dumpex.hunt.pipe.domain.PipeEvidence`, mirroring
    `C2ContextEvidence`'s own `string_hit` field. `region`/`pipe_name` are
    DERIVED from it, never a second stored copy."""
    string_hit: PipeStringEvidence
    framework:  FrameworkAttribution

    def __post_init__(self):
        _require_type(self.string_hit, PipeStringEvidence,
                       "FrameworkStringHitEvidence.string_hit")
        _require_type(self.framework, FrameworkAttribution,
                       "FrameworkStringHitEvidence.framework")
        require_recursively_immutable(self, "FrameworkStringHitEvidence")

    @property
    def region(self) -> RegionRef:
        return self.string_hit.region

    @property
    def pipe_name(self) -> str:
        return self.string_hit.name.strip()


@dataclass(frozen=True)
class UnbackedThreadEvidence:
    """One thread whose StartAddress falls inside a region that also holds
    a `\\pipe\\` name string, and which no loaded module accounts for --
    analyst visibility only, never independently scored (the scored,
    handle-anchored form is `CorroboratedHandleEvidence`).

    Replaces the pre-migration `(thread_info, region)` 2-tuple, whose two
    members were a live `MinidumpThreadInfo` and a live
    `MinidumpMemoryInfo`."""
    thread: ThreadStartRef
    region: RegionRef

    def __post_init__(self):
        _require_type(self.thread, ThreadStartRef, "UnbackedThreadEvidence.thread")
        _require_type(self.region, RegionRef, "UnbackedThreadEvidence.region")
        require_recursively_immutable(self, "UnbackedThreadEvidence")


# ── Scan-layer transport shapes ───────────────────────────────────────────
# Frozen like everything else, but never retained on the Report itself:
# these are what a scan function RETURNS, consumed once by the
# orchestration loop / correlation.py / aggregate.py. Frozen anyway so a
# scan's own result cannot be mutated between collection and that one read
# (the same reasoning dumpex.hunt.stomping.models.IocScanResult documents).

@dataclass(frozen=True)
class HandleScanResult:
    """What `handle_scan.scan_handles()` returns.

    The framework-matched SUBSET is deliberately not a second field here
    (nor a second bucket on the Report): it is exactly
    `tuple(h for h in handles if h.framework)`, and storing it separately
    is how the pre-migration `HandleScan` ended up with
    `handle_pipe_hits`/`handle_classified`/`framework_handle_hits` -- three
    parallel lists over the same handles, two of which were the same list.
    See `dumpex.hunt.pipe.domain.PipeEvidence.framework_handles`."""
    handles: tuple = field(default_factory=tuple)   # tuple[PipeHandleEvidence]

    def __post_init__(self):
        object.__setattr__(self, "handles", _require_typed_tuple(
            self.handles, PipeHandleEvidence, "HandleScanResult.handles"))
        require_recursively_immutable(self, "HandleScanResult")


@dataclass(frozen=True)
class RegionC2Records:
    """Every C2-context record the scan gathered from ONE pipe-bearing
    region. The immutable stand-in for the pre-migration
    `region_c2_records: dict` (region base address -> records list): a dict
    can never be recursively immutable (see
    `dumpex.hunt._domain.require_recursively_immutable`), so the mapping is
    carried as a tuple of these pairs and rebuilt as a plain local lookup
    dict inside correlation.py, where it never crosses a boundary."""
    region:  RegionRef
    records: tuple = field(default_factory=tuple)   # tuple[C2ContextRecord]

    def __post_init__(self):
        _require_type(self.region, RegionRef, "RegionC2Records.region")
        object.__setattr__(self, "records", _require_typed_tuple(
            self.records, C2ContextRecord, "RegionC2Records.records"))
        require_recursively_immutable(self, "RegionC2Records")


@dataclass(frozen=True)
class PipeScanCoverage:
    """Immutable snapshot of the pipe-name/C2 region scan's own
    `dumpex.hunt._coverage.CoverageTracker` and its two independent
    `dumpex.hunt._budget.ScanBudget`s, at the point that scan finished --
    the ONE place those live, still-mutable objects get frozen before they
    can cross the scan/aggregate boundary. Without this, the tracker
    itself (an ordinary, non-frozen dataclass with a mutable
    `skipped_oversize_targets` list) and both budgets would stay
    reachable -- and mutable -- after `scan_pipe_names()` returns, which is
    exactly how the pre-migration `PipeNameScan` handed them straight
    through to `aggregate.build_report()` and on to
    `_pipe_coverage_report()`.

    The two budgets stay SEPARATE fields, never merged into one
    "budget_exhausted" flag: c2_budget bounds only C2-context gathering
    and pipe_name_budget bounds only pipe-name collection, so which one
    ran out determines which signal's coverage is actually partial (see
    dumpex/hunt/pipe/config.py).

    `image_pipe_refs`/`image_pipe_modules` are NOT a coverage gap: those
    regions WERE fully read, and pipe references inside Microsoft system
    DLLs under System32/SysWOW64/WinSxS are expected. They ride along here
    because they are the same scan's own "what did this pass actually do"
    record (the same slot stomping's `IocCoverage.whitelisted_skipped`
    occupies)."""
    skipped_oversize_targets:   tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    read_failed:                int = 0
    read_failed_targets:        tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    short_reads:                int = 0
    short_read_targets:         tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    c2_budget_exhausted:        bool = False
    c2_budget_reason:           str = ""
    pipe_name_budget_exhausted: bool = False
    pipe_name_budget_reason:    str = ""
    # One ScanTarget per eligible region a spent budget left unresolved for
    # its own scope, kept SEPARATE because the two budgets stop different
    # work: `pipe_name_budget_exhausted_targets` holds each region whose
    # pipe-name matching could not run to completion within budget;
    # `c2_budget_exhausted_targets` holds each region that yielded new
    # private pipe-name leads whose C2 context the c2_budget could not
    # gather. Either can be empty while its `_exhausted` flag is True.
    # Deduped by physical region. Every target has `size_limit=None`:
    # budget exhaustion is not a size-cap skip.
    pipe_name_budget_exhausted_targets: tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    c2_budget_exhausted_targets:        tuple = field(default_factory=tuple)   # tuple[ScanTarget]
    image_pipe_refs:            int = 0
    image_pipe_modules:         tuple = field(default_factory=tuple)   # tuple[str]
    # The tracker's reconciliation ledger, carried across the scan/
    # aggregate boundary rather than collapsed into a bool -- see
    # `unaccounted` below.
    scanned:                    int = 0
    eligible_total:             int = 0
    eligible_bytes:             int = 0
    not_applicable:             int = 0
    budget_skipped:             int = 0
    unaccounted:                int = 0
    over_accounted:             int = 0

    def __post_init__(self):
        object.__setattr__(self, "skipped_oversize_targets", _require_typed_tuple(
            self.skipped_oversize_targets, ScanTarget,
            "PipeScanCoverage.skipped_oversize_targets"))
        object.__setattr__(self, "read_failed_targets", _require_typed_tuple(
            self.read_failed_targets, ScanTarget, "PipeScanCoverage.read_failed_targets"))
        object.__setattr__(self, "short_read_targets", _require_typed_tuple(
            self.short_read_targets, ScanTarget, "PipeScanCoverage.short_read_targets"))
        for name in ("pipe_name_budget_exhausted_targets", "c2_budget_exhausted_targets"):
            targets = _require_typed_tuple(getattr(self, name), ScanTarget,
                                          f"PipeScanCoverage.{name}")
            capped = [f"0x{t.base_address:x}" for t in targets if t.size_limit is not None]
            if capped:
                raise ValueError(
                    f"PipeScanCoverage.{name} must all have size_limit=None -- budget "
                    f"exhaustion is not a size-cap skip, got a cap on target(s) at {capped!r}")
            object.__setattr__(self, name, targets)
        for name in ("read_failed", "short_reads", "image_pipe_refs",
                     "scanned", "eligible_total", "eligible_bytes", "not_applicable",
                     "budget_skipped", "unaccounted", "over_accounted"):
            _require_count(getattr(self, name), f"PipeScanCoverage.{name}")
        for name in ("c2_budget_exhausted", "pipe_name_budget_exhausted"):
            _require_bool(getattr(self, name), f"PipeScanCoverage.{name}")
        for name in ("c2_budget_reason", "pipe_name_budget_reason"):
            _require_str(getattr(self, name), f"PipeScanCoverage.{name}")
        object.__setattr__(self, "image_pipe_modules", _require_typed_tuple(
            self.image_pipe_modules, str, "PipeScanCoverage.image_pipe_modules"))
        require_recursively_immutable(self, "PipeScanCoverage")

    @property
    def accounted(self) -> int:
        """Every disposition carried across this boundary, summed exactly
        as `dumpex.hunt._coverage.CoverageTracker.accounted` sums them --
        see its DISPOSITION_COUNTERS for the set both have to agree on."""
        return (self.budget_skipped + self.scanned + self.not_applicable + self.read_failed
                + len(self.skipped_oversize_targets))

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
    def from_scan(cls, tracker, pipe_name_budget, c2_budget, *,
                   image_pipe_refs: int = 0, image_pipe_modules=(),
                   pipe_name_budget_exhausted_targets=(),
                   c2_budget_exhausted_targets=()) -> "PipeScanCoverage":
        """Freeze a finished scan's live tracker/budgets. `exhausted()` is
        called (not `exhausted_reason` read directly) because a budget only
        notices an expired DEADLINE when asked -- see
        `dumpex.hunt._budget.ScanBudget.exhausted`."""
        return cls(skipped_oversize_targets=tuple(tracker.skipped_oversize_targets),
                   read_failed=tracker.read_failed,
                   read_failed_targets=tuple(tracker.read_failed_targets),
                   short_reads=tracker.short_reads,
                   short_read_targets=tuple(tracker.short_read_targets),
                   c2_budget_exhausted=c2_budget.exhausted(),
                   c2_budget_reason=c2_budget.exhausted_reason or "",
                   pipe_name_budget_exhausted=pipe_name_budget.exhausted(),
                   pipe_name_budget_reason=pipe_name_budget.exhausted_reason or "",
                   image_pipe_refs=image_pipe_refs,
                   image_pipe_modules=tuple(image_pipe_modules),
                   pipe_name_budget_exhausted_targets=tuple(pipe_name_budget_exhausted_targets),
                   c2_budget_exhausted_targets=tuple(c2_budget_exhausted_targets),
                   scanned=tracker.scanned, eligible_total=tracker.total,
                   eligible_bytes=tracker.eligible_bytes,
                   not_applicable=tracker.not_applicable,
                   budget_skipped=tracker.budget_skipped,
                   unaccounted=tracker.unaccounted,
                   over_accounted=tracker.over_accounted)

@dataclass(frozen=True)
class PipeNameScanResult:
    """What `memory_scan.scan_pipe_names()` returns."""
    string_leads: tuple = field(default_factory=tuple)   # tuple[PipeStringEvidence]
    c2_regions:   tuple = field(default_factory=tuple)   # tuple[RegionC2Records]
    coverage:     PipeScanCoverage = field(default_factory=PipeScanCoverage)

    def __post_init__(self):
        object.__setattr__(self, "string_leads", _require_typed_tuple(
            self.string_leads, PipeStringEvidence, "PipeNameScanResult.string_leads"))
        object.__setattr__(self, "c2_regions", _require_typed_tuple(
            self.c2_regions, RegionC2Records, "PipeNameScanResult.c2_regions"))
        _require_type(self.coverage, PipeScanCoverage, "PipeNameScanResult.coverage")
        # isinstance() alone only proves `coverage` is TYPED as a
        # PipeScanCoverage, not that its CURRENT state is still well-formed:
        # a caller holding a reference can poison an already-built one via
        # object.__setattr__ (frozen blocks reassignment, not that).
        require_recursively_immutable(self, "PipeNameScanResult")


@dataclass(frozen=True)
class CorrelationResult:
    """What `correlation.correlate()` returns -- every relationship this
    hunter derived by relating handle facts to string facts and to thread
    state. Consumed once, by `dumpex/hunt/pipe/__init__.py`'s builder,
    which hands each tuple straight to `aggregate.build_report()`."""
    corroborated_handles:  tuple = field(default_factory=tuple)
    start_address_leads:   tuple = field(default_factory=tuple)
    c2_context:            tuple = field(default_factory=tuple)
    framework_string_hits: tuple = field(default_factory=tuple)
    unbacked_threads:      tuple = field(default_factory=tuple)

    _BUCKET_TYPES = (
        ("corroborated_handles",  CorroboratedHandleEvidence),
        ("start_address_leads",   StartAddressLeadEvidence),
        ("c2_context",            C2ContextEvidence),
        ("framework_string_hits", FrameworkStringHitEvidence),
        ("unbacked_threads",      UnbackedThreadEvidence),
    )

    def __post_init__(self):
        for name, expected in self._BUCKET_TYPES:
            object.__setattr__(self, name, _require_typed_tuple(
                getattr(self, name), expected, f"CorrelationResult.{name}"))
        require_recursively_immutable(self, "CorrelationResult")
