"""
Immutable Evidence value objects for the encoding/obfuscation scan
pipeline -- built once, at the scan boundary (sleep_mask.py/entropy.py/
decoding.py, the only modules that still touch `mf`/raw minidump region
objects), and read by aggregate.py/the report_* projectors without ever
needing `mf`, a raw minidump object, or a live address-lookup call (see
dumpex/hunt/_location.py's `resolve_location`, called exactly once per
region/hit here).

This is the "one canonical evidence representation" half of the encoding
hunter's output-source migration (see dumpex/hunt/encoding/domain.py for
the Report/Evidence container these feed). Not the public JSON shape --
dumpex/hunt/encoding/report_legacy.py and report_record.py project these
into the v1.1 findings dict / v2.10 ObfuscationDetails; report_console.py
projects them into console text. All three read the SAME evidence, so
they can never disagree about what a region/hit actually was.

A layer function itself makes NO decision about score/status/verdict and
prints nothing -- it returns typed evidence. That decision-making lives
entirely in aggregate.py; rendering lives entirely in report_console.py.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._domain import as_tuple, require_recursively_immutable
from dumpex.hunt._location import Location
from dumpex.output.coverage import ScanTarget


def _require_type(value, expected, field_name: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(
            f"{field_name} must be a {expected.__name__}, got {type(value).__name__}: {value!r}")


def _require_optional_type(value, expected, field_name: str) -> None:
    if value is not None:
        _require_type(value, expected, field_name)


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}: {value!r}")


def _require_count(value, field_name: str) -> None:
    # bool is excluded explicitly: it is an int subclass, and a stray
    # boolean where a count was meant is a caller bug, not a 0/1 count.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be a non-negative int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_typed_tuple(value, expected, field_name: str) -> tuple:
    """Normalize to a tuple, require every item to be exactly `expected`,
    and require the whole tuple to be recursively immutable -- the same
    two-layer defense (item-type check + depth check) `dumpex.hunt.
    encoding.domain`'s bucket validation uses, applied here at the scan-
    layer/aggregate transport boundary so a poison reference (a raw
    minidump object, a live tracker, a bare list) can never survive a
    `LayerResult`/`DecodeResult` construction, and a mutable object
    nested a level or more inside an otherwise well-typed item cannot
    either (a shallow `tuple(value)` alone would only copy the OUTER
    container -- a `list` smuggled inside item[0] would still be
    reachable and still mutable afterward)."""
    expected_names = expected.__name__ if isinstance(expected, type) else \
        " or ".join(t.__name__ for t in expected)
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if not isinstance(item, expected):
            raise TypeError(
                f"{field_name}[{index}] must be a {expected_names}, got "
                f"{type(item).__name__}: {item!r}")
    require_recursively_immutable(items, field_name)
    return items


def region_ref(r, susp_prots=()) -> "RegionRef":
    """Convert a raw minidump region into an immutable RegionRef -- the
    ONE place each scan layer (sleep_mask.py/entropy.py/decoding.py)
    reads a region's raw State/Protect/Type enum values and formats them
    via prot_str(), so every evidence type that carries "a region" does
    so with the SAME already-formatted strings, never a second prot_str()
    call at aggregate/console time. `susp_prots` (the rules-derived
    suspicious-protection string list) is consulted here too, once, to
    resolve `is_rwx` -- entropy's threshold pick and the shellcode-
    bootstrap "executable+private" context lead both need "is this
    region's protection RWX-suspicious", and resolving it at scan time
    (like every other region fact) means aggregate.py never needs the
    rules list itself."""
    protect = prot_str(r.Protect)
    return RegionRef(base_address=r.BaseAddress, allocation_base=getattr(r, "AllocationBase", None),
                      size=r.RegionSize, state=prot_str(r.State), protect=protect,
                      type=prot_str(r.Type),
                      is_rwx=any(s in protect for s in susp_prots))


@dataclass(frozen=True)
class RegionRef:
    """Immutable snapshot of a MemoryInfo region's identity -- everything
    a projection ever needs about a region, without holding the region
    object itself. `state`/`protect`/`type` are `prot_str()`-resolved,
    and `is_rwx` is resolved against the rules-derived suspicious-
    protection list, once at scan time (see `region_ref()` above), so no
    projector ever calls `prot_str()` on a live region or needs the rules
    list again."""
    base_address: int
    allocation_base: "int | None"
    size: int
    state: str      # prot_str(region.State), resolved once at scan time
    protect: str    # prot_str(region.Protect), resolved once at scan time
    type: str       # prot_str(region.Type), resolved once at scan time
    is_rwx: bool = False   # protect matches a rules-derived suspicious pattern


@dataclass(frozen=True)
class PeSectionInfo:
    """Immutable projection of one entry from
    dumpex.core.pe_utils.parse_pe_header()'s `sections` list."""
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int
    characteristics: int
    is_executable: bool
    is_writable: bool
    is_readable: bool


@dataclass(frozen=True)
class PeHeaderInfo:
    """Full-fidelity, immutable projection of
    dumpex.core.pe_utils.parse_pe_header()'s dict result -- carries every
    field that dict has (unlike dumpex.hunt.injection.models.PeHeaderInfo,
    which only needs a lean subset), because this hunter's existing --json
    output (`Hit.to_dict()['cls']['pe_info']`, see
    tests/fixtures/hunt_cli_golden/obfuscation_hunt_dict.json) already
    exposes the full dict verbatim and that wire content must not shrink
    as part of this migration. `sections` becomes a tuple[PeSectionInfo]
    and `data_directories` a tuple of (rva, size) tuples so the whole
    object stays recursively immutable; every other field is copied
    through unchanged."""
    valid: bool
    has_mz: bool
    has_pe_sig: bool
    e_lfanew: "int | None"
    machine: "int | None"
    machine_name: "str | None"
    time_date_stamp: "int | None"
    is_pe32_plus: "bool | None"
    number_of_sections: "int | None"
    size_of_image: "int | None"
    address_of_entry_point: "int | None"
    image_base: "int | None"
    sections: tuple = field(default_factory=tuple)             # tuple[PeSectionInfo]
    data_directories: tuple = field(default_factory=tuple)     # tuple[tuple[int, int]]
    reason: str = ""

    def __post_init__(self):
        object.__setattr__(self, "sections", tuple(self.sections))
        object.__setattr__(self, "data_directories",
                            tuple(tuple(d) for d in self.data_directories))


@dataclass(frozen=True)
class Classification:
    """Immutable replacement for `_classify_decoded()`'s old mutable dict
    result -- what decoded/decompressed content IS, once decoded."""
    kind: str               # 'binary' | 'pe' | 'shellcode' | 'ioc_text' | 'plaintext' | 'high_entropy'
    is_pe: bool
    is_shellcode: bool
    ioc_strings: tuple = field(default_factory=tuple)
    hex_prefix: str = ""
    entropy: float = 0.0
    pe_info: "PeHeaderInfo | None" = None

    def __post_init__(self):
        object.__setattr__(self, "ioc_strings", tuple(self.ioc_strings))


@dataclass(frozen=True)
class DecodedHit:
    """One decoded/classified payload from any of the four content-
    producing layers (sleep_mask, base64, xor, gzip/zlib -- `layer` is
    'sleep_mask' | 'base64' | 'xor' | 'gzip' | 'zlib'). Replaces the old
    mutable `Hit`: `region`/`location` are resolved once at scan time
    (see each scan layer's own construction site), and the byte offset
    within the region is `location.region_offset` -- there is no separate
    `offset` field to drift from it."""
    layer: str
    region: RegionRef
    location: Location
    decoded: bytes
    classification: Classification
    complete: bool = True   # gzip/zlib only: whether decompression verified the
                             # stream end-to-end (see decoding._bounded_decompress);
                             # always True for the other three layers.
    known_module: bool = False   # addr_to_module(location.va, modules) is not
                                  # None -- resolved once at scan time (like
                                  # everything else on this type) so the
                                  # structural_payload check's "module_status"
                                  # fact never needs the raw modules list again.
    raw: "bytes | None" = None        # original encoded bytes, where meaningful
                                       # (base64 only -- reports the encoded
                                       # string's own length)
    key: "int | bytes | None" = None  # XOR key: int for the xor layer, bytes for
                                       # sleep_mask
    key_offset: "int | None" = None   # sleep_mask's key rotation offset
                                       # (0..key_size-1)

    def __post_init__(self):
        _require_type(self.region, RegionRef, "DecodedHit.region")
        _require_type(self.location, Location, "DecodedHit.location")
        _require_type(self.classification, Classification, "DecodedHit.classification")
        # Depth check: catches a mutable payload smuggled a level or more
        # inside an otherwise correctly-TYPED field (e.g. `classification`
        # is a genuine `Classification`, but a caller hand-built one whose
        # own `ioc_strings` was assigned a list via object.__setattr__)
        # that the isinstance checks above cannot see.
        require_recursively_immutable(self, "DecodedHit")


@dataclass(frozen=True)
class EntropyHit:
    """One high-entropy region flagged by the entropy layer -- a
    statistical observation, never classified/decoded content."""
    region: RegionRef
    location: Location
    entropy: float
    threshold: float

    def __post_init__(self):
        _require_type(self.region, RegionRef, "EntropyHit.region")
        _require_type(self.location, Location, "EntropyHit.location")
        require_recursively_immutable(self, "EntropyHit")


@dataclass(frozen=True)
class LayerCoverage:
    """Immutable snapshot of a `dumpex.hunt._coverage.CoverageTracker` at
    the point a scan layer finished -- the ONE place a scan layer's live,
    still-mutable tracker gets frozen before it can be returned inside a
    `LayerResult`/`DecodeResult`. Without this, the tracker itself (an
    ordinary, non-frozen dataclass with a mutable `skipped_oversize_targets`
    list) would stay reachable -- and mutable -- after the scan function
    returns, between collection and aggregate.py ever consuming it.
    Carries only the fields encoding's own scan layers actually set on
    their tracker (`total`/`timed_out`/`reasons` are never touched by
    sleep_mask.py/entropy.py/decoding.py); `dumpex.hunt._coverage.
    CoverageTracker` itself stays the general-purpose, hunter-neutral
    accumulator, still fully mutable DURING a scan loop -- only what
    crosses the scan/aggregate boundary is frozen here."""
    scanned: int = 0
    read_failed: int = 0
    short_reads: int = 0
    budget_exhausted: bool = False
    skipped_oversize_targets: tuple = field(default_factory=tuple)

    def __post_init__(self):
        _require_count(self.scanned, "LayerCoverage.scanned")
        _require_count(self.read_failed, "LayerCoverage.read_failed")
        _require_count(self.short_reads, "LayerCoverage.short_reads")
        _require_bool(self.budget_exhausted, "LayerCoverage.budget_exhausted")
        object.__setattr__(self, "skipped_oversize_targets", _require_typed_tuple(
            self.skipped_oversize_targets, ScanTarget, "LayerCoverage.skipped_oversize_targets"))
        # Depth check, same reasoning as DecodedHit/EntropyHit's own
        # __post_init__: the four scalar/bool checks above only look at
        # LayerCoverage's own direct fields, so this is what still catches
        # a mutable payload smuggled a level or more inside (e.g. a
        # ScanTarget whose own field was poisoned via object.__setattr__).
        require_recursively_immutable(self, "LayerCoverage")

    @classmethod
    def from_tracker(cls, tracker) -> "LayerCoverage":
        return cls(scanned=tracker.scanned, read_failed=tracker.read_failed,
                   short_reads=tracker.short_reads, budget_exhausted=tracker.budget_exhausted,
                   skipped_oversize_targets=tuple(tracker.skipped_oversize_targets))


@dataclass(frozen=True)
class LayerResult:
    """hits: tuple[DecodedHit] for sleep_mask, tuple[EntropyHit] for
    entropy -- coverage (a frozen `LayerCoverage`, never the live
    tracker) is the one thing every layer's result has in common. A
    scan-layer-internal transport shape, consumed once by aggregate.py
    and never retained on the immutable Report (see domain.py) -- frozen
    regardless, so nothing can mutate a scan's own result between
    collection and that one read."""
    hits: tuple = field(default_factory=tuple)
    coverage: "LayerCoverage | None" = None

    def __post_init__(self):
        object.__setattr__(self, "hits", _require_typed_tuple(
            self.hits, (DecodedHit, EntropyHit), "LayerResult.hits"))
        _require_optional_type(self.coverage, LayerCoverage, "LayerResult.coverage")
        # `isinstance(coverage, LayerCoverage)` alone only proves TYPE, not
        # current state: LayerCoverage validates its own fields at ITS OWN
        # construction time, but frozen only blocks attribute
        # REASSIGNMENT -- a caller (or anything holding a reference before
        # this constructor ever sees it) can still poison an already-built
        # LayerCoverage via object.__setattr__ and hand it in here. Walking
        # the whole of `self` -- not just re-validating `hits` again -- is
        # what actually catches that, since it inspects CURRENT state
        # rather than trusting a check LayerCoverage ran in the past.
        require_recursively_immutable(self, "LayerResult")


@dataclass(frozen=True)
class DecodeResult:
    """Combined result of the Base64/XOR/GZIP-ZLIB region scan
    (decoding.scan_decode_layers) -- one shared per-region read/coverage
    pass produces all three layers' hit lists together."""
    base64: tuple = field(default_factory=tuple)       # tuple[DecodedHit]
    xor: tuple = field(default_factory=tuple)           # tuple[DecodedHit]
    compressed: tuple = field(default_factory=tuple)    # tuple[DecodedHit]
    coverage: "LayerCoverage | None" = None

    def __post_init__(self):
        object.__setattr__(self, "base64",
                            _require_typed_tuple(self.base64, DecodedHit, "DecodeResult.base64"))
        object.__setattr__(self, "xor",
                            _require_typed_tuple(self.xor, DecodedHit, "DecodeResult.xor"))
        object.__setattr__(self, "compressed", _require_typed_tuple(
            self.compressed, DecodedHit, "DecodeResult.compressed"))
        _require_optional_type(self.coverage, LayerCoverage, "DecodeResult.coverage")
        # See LayerResult.__post_init__'s own comment: isinstance alone
        # only proves `coverage` is TYPED as a LayerCoverage, not that its
        # current state is still well-formed -- this re-walks it (and
        # everything else reachable from `self`) to catch a LayerCoverage
        # poisoned via object.__setattr__ after its own construction.
        require_recursively_immutable(self, "DecodeResult")
