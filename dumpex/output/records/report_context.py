"""`--report` per-card context: exception address, allocation
neighborhood, handle correlation and string context.
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    ENRICHMENT_TEXT_CAP,
    _require_bool,
    _require_bounded_text,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)
from dumpex.output.records.extraction import _STRING_RECORD_ENCODINGS
from dumpex.output.records.report_common import (
    ENRICHMENT_SCOPE_CARD,
    EnrichmentSection,
    _require_enrichment_section,
    _require_optional_bounded_text,
)


ACCESS_VIOLATION_TYPES = ("read", "write", "execute")


@dataclass(frozen=True)
class ReportAddressContext:
    """Where one address published by an exception record actually lives.

    Resolution reuses the region table and module list the card already
    holds, so an exception address and the card's own region can never
    disagree. Every field but `address` is None when no captured region
    contains it -- an address outside the region table is not a claim that
    the address is invalid, only that this dump does not describe it."""
    address:        str
    region_base:    "str | None"
    region_size:    "int | None"
    protection:     "str | None"
    type:           "str | None"
    module_owner:   "str | None"
    module_owner_truncated: bool = False

    def __post_init__(self):
        _require_hex_address(self.address, "ReportAddressContext.address")
        _require_optional_hex_address(self.region_base, "ReportAddressContext.region_base")
        _require_optional_nonneg_int(self.region_size, "ReportAddressContext.region_size")
        for field_name in ("protection", "type", "module_owner"):
            _require_optional_diff_str(getattr(self, field_name),
                                       f"ReportAddressContext.{field_name}")
        _require_optional_bounded_text(self.module_owner,
                                       "ReportAddressContext.module_owner")
        _require_bool(self.module_owner_truncated,
                      "ReportAddressContext.module_owner_truncated")
        if self.module_owner_truncated and self.module_owner is None:
            raise ValueError(
                "ReportAddressContext.module_owner_truncated requires a module_owner")
        if self.region_base is None and (self.region_size is not None
                                         or self.protection is not None
                                         or self.type is not None):
            raise ValueError(
                "ReportAddressContext region facts require a resolved region_base -- an "
                "unresolved address describes no region")

    def to_dict(self) -> dict:
        return {
            "address":      self.address,
            "region_base":  self.region_base,
            "region_size":  self.region_size,
            "protection":   self.protection,
            "type":         self.type,
            "module_owner": self.module_owner,
            "module_owner_truncated": self.module_owner_truncated,
        }


EXCEPTION_SELECTION_REASONS = (
    "anchor_thread",       # the record's own ThreadId is this card's anchor TID
    "anchor_region",       # the record's ExceptionAddress falls inside this card's region
    "process_exception",   # the dump's first exception record, kept as process crash context
)


@dataclass(frozen=True)
class ReportExceptionEntry:
    """One retained MINIDUMP_EXCEPTION_STREAM record.

    `exception_code_name` is the parser's own decoded name, or None for a
    code it does not recognize; `exception_code` carries the raw value
    either way. An exception is execution state, never in itself a
    maliciousness observation -- `selection_reason` says only how the
    record relates to this card's anchor."""
    index:                int
    thread_id:            "int | None"
    exception_code:       "str | None"   # raw 32-bit code, "0x" hex; None when the captured
                                           # value is not usable as one -- never a fabricated
                                           # 0x0, which is itself a meaningful code
    exception_code_name:  "str | None"
    exception_flags:      "int | None"
    exception_address:    "str | None"
    parameters:           tuple          # bounded tuple of "0x" hex strings
    parameters_truncated: bool
    selection_reason:     str
    access_type:          "str | None" = None   # ACCESS_VIOLATION_TYPES, decoded from the
                                                  # first parameter of an access-violation or
                                                  # in-page-error record; None for every other
                                                  # code and for a first parameter outside the
                                                  # documented vocabulary
    referenced_address:   "str | None" = None   # the address the faulting instruction touched,
                                                  # from the second parameter of those same two
                                                  # codes -- distinct from exception_address,
                                                  # which is where execution stopped
    address_context:      "ReportAddressContext | None" = None
    referenced_context:   "ReportAddressContext | None" = None

    def __post_init__(self):
        _require_nonneg_int(self.index, "ReportExceptionEntry.index")
        if self.thread_id is not None:
            _require_nonneg_int(self.thread_id, "ReportExceptionEntry.thread_id")
        if self.exception_code is not None and (
                not isinstance(self.exception_code, str)
                or not self.exception_code.startswith("0x")):
            raise ValueError(
                "ReportExceptionEntry.exception_code must be None or a '0x' hex string")
        if self.access_type is not None and self.access_type not in ACCESS_VIOLATION_TYPES:
            raise ValueError(
                f"ReportExceptionEntry.access_type must be None or one of "
                f"{ACCESS_VIOLATION_TYPES}, got {self.access_type!r}")
        _require_optional_hex_address(self.referenced_address,
                                      "ReportExceptionEntry.referenced_address")
        for field_name, source in (("address_context", self.exception_address),
                                   ("referenced_context", self.referenced_address)):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, ReportAddressContext):
                raise TypeError(
                    f"ReportExceptionEntry.{field_name} must be None or a ReportAddressContext")
            if value is not None and source is None:
                raise ValueError(
                    f"ReportExceptionEntry.{field_name} requires the address it resolves")
            if value is not None and value.address != source:
                raise ValueError(
                    f"ReportExceptionEntry.{field_name}.address must be the address it resolves")
        _require_optional_diff_str(self.exception_code_name,
                                   "ReportExceptionEntry.exception_code_name")
        _require_optional_diff_int(self.exception_flags, "ReportExceptionEntry.exception_flags")
        _require_optional_hex_address(self.exception_address,
                                      "ReportExceptionEntry.exception_address")
        object.__setattr__(self, "parameters", tuple(self.parameters))
        if any(not isinstance(p, str) or not p.startswith("0x") for p in self.parameters):
            raise ValueError("ReportExceptionEntry.parameters must be '0x' hex strings")
        _require_bool(self.parameters_truncated, "ReportExceptionEntry.parameters_truncated")
        if self.selection_reason not in EXCEPTION_SELECTION_REASONS:
            raise ValueError(
                f"ReportExceptionEntry.selection_reason must be one of "
                f"{EXCEPTION_SELECTION_REASONS}, got {self.selection_reason!r}")

    def to_dict(self) -> dict:
        return {
            "index":                self.index,
            "thread_id":            self.thread_id,
            "exception_code":       self.exception_code,
            "exception_code_name":  self.exception_code_name,
            "exception_flags":      self.exception_flags,
            "exception_address":    self.exception_address,
            "parameters":           list(self.parameters),
            "parameters_truncated": self.parameters_truncated,
            "selection_reason":     self.selection_reason,
            "access_type":          self.access_type,
            "referenced_address":   self.referenced_address,
            "address_context":      (self.address_context.to_dict()
                                     if self.address_context else None),
            "referenced_context":   (self.referenced_context.to_dict()
                                     if self.referenced_context else None),
        }


@dataclass(frozen=True)
class ReportExceptionContext:
    """This card's bounded view of the dump's ExceptionStream."""
    section: EnrichmentSection
    entries: tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportExceptionContext.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="exception")
        object.__setattr__(self, "entries", tuple(self.entries))
        if any(not isinstance(e, ReportExceptionEntry) for e in self.entries):
            raise TypeError(
                "ReportExceptionContext.entries must be ReportExceptionEntry instances")
        if len(self.entries) != self.section.included:
            raise ValueError("ReportExceptionContext.entries length must equal section.included")
        indexes = [e.index for e in self.entries]
        if len(set(indexes)) != len(indexes):
            raise ValueError(
                "ReportExceptionContext.entries must be deduplicated by stream index")

    def to_dict(self) -> dict:
        return {"section": self.section.to_dict(),
                "entries": [e.to_dict() for e in self.entries]}


NEIGHBOR_RELATIONS = (
    "anchor",           # the card's own resolved region
    "same_allocation",  # a different region sharing the anchor's allocation base
    "preceding",        # a nearest region below the anchor
    "following",        # a nearest region above the anchor
)


@dataclass(frozen=True)
class ReportNeighborRegion:
    """One region of the anchor's allocation neighborhood.

    `distance` is the gap in bytes between this region and the anchor
    region -- 0 for the anchor itself and for an immediately adjacent
    region. Adjacency is layout, not causation: a neighbor is a place to
    look next, never evidence of a relationship to the anchor."""
    base_address:    str
    size:            int
    state:           "str | None"
    type:            "str | None"
    protection:      "str | None"
    allocation_base: "str | None"
    relation:        str
    distance:        int
    module_owner:    "str | None" = None   # the loaded module whose range holds this region's
                                             # base, or None for an unregistered mapping and for
                                             # a dump with no module list to resolve against
    module_owner_truncated: bool = False

    def __post_init__(self):
        _require_hex_address(self.base_address, "ReportNeighborRegion.base_address")
        _require_nonneg_int(self.size, "ReportNeighborRegion.size")
        _require_optional_diff_str(self.module_owner, "ReportNeighborRegion.module_owner")
        _require_optional_bounded_text(self.module_owner,
                                       "ReportNeighborRegion.module_owner")
        _require_bool(self.module_owner_truncated,
                      "ReportNeighborRegion.module_owner_truncated")
        if self.module_owner_truncated and self.module_owner is None:
            raise ValueError(
                "ReportNeighborRegion.module_owner_truncated requires a module_owner")
        for field_name in ("state", "type", "protection"):
            _require_optional_diff_str(getattr(self, field_name),
                                       f"ReportNeighborRegion.{field_name}")
        _require_optional_hex_address(self.allocation_base,
                                      "ReportNeighborRegion.allocation_base")
        if self.relation not in NEIGHBOR_RELATIONS:
            raise ValueError(
                f"ReportNeighborRegion.relation must be one of {NEIGHBOR_RELATIONS}, "
                f"got {self.relation!r}")
        _require_nonneg_int(self.distance, "ReportNeighborRegion.distance")
        if self.relation == "anchor" and self.distance != 0:
            raise ValueError("ReportNeighborRegion.distance must be 0 for the anchor region")

    def to_dict(self) -> dict:
        return {
            "base_address":    self.base_address,
            "size":            self.size,
            "state":           self.state,
            "type":            self.type,
            "protection":      self.protection,
            "allocation_base": self.allocation_base,
            "relation":        self.relation,
            "distance":        self.distance,
            "module_owner":    self.module_owner,
            "module_owner_truncated": self.module_owner_truncated,
        }


@dataclass(frozen=True)
class ReportAllocationNeighborhood:
    """The bounded region layout immediately around this card's anchor.

    `allocation_base` is the anchor region's own reservation base, or None
    when the region table carries none. Entries are in ascending address
    order so the neighborhood reads as the memory map it is."""
    section:         EnrichmentSection
    allocation_base: "str | None"
    entries:         tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportAllocationNeighborhood.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="allocation")
        _require_optional_hex_address(self.allocation_base,
                                      "ReportAllocationNeighborhood.allocation_base")
        object.__setattr__(self, "entries", tuple(self.entries))
        if any(not isinstance(e, ReportNeighborRegion) for e in self.entries):
            raise TypeError(
                "ReportAllocationNeighborhood.entries must be ReportNeighborRegion instances")
        if len(self.entries) != self.section.included:
            raise ValueError(
                "ReportAllocationNeighborhood.entries length must equal section.included")
        addresses = [int(e.base_address, 16) for e in self.entries]
        if addresses != sorted(addresses):
            raise ValueError(
                "ReportAllocationNeighborhood.entries must be in ascending address order")
        if len(set(addresses)) != len(addresses):
            raise ValueError(
                "ReportAllocationNeighborhood.entries must be deduplicated by base address")

    def to_dict(self) -> dict:
        return {"section": self.section.to_dict(),
                "allocation_base": self.allocation_base,
                "entries": [e.to_dict() for e in self.entries]}


HANDLE_SELECTION_REASONS = (
    "object_name_in_anchor_strings",   # the handle's object name occurs in text captured
                                         # from this card's own examined range
)


@dataclass(frozen=True)
class ReportCorrelatedHandle:
    """One handle whose named kernel object also appears in the text this
    card examined.

    The correlation is textual: the same name was captured in two
    independent places in the same dump. It is not proof that the anchor
    uses the handle, and a generic handle fact carries no maliciousness on
    its own. The complete inventory remains `--handles`."""
    handle:                 str
    type_name:              "str | None"
    object_name:            str
    granted_access:         "int | None"
    selection_reason:       str
    type_name_truncated:    bool = False   # a type name is dump-derived text like any other
                                             # here, so it obeys the same cap
    object_name_truncated:  bool = False   # the captured name was longer than
                                             # ENRICHMENT_TEXT_CAP and `object_name` holds its
                                             # leading characters -- the match itself is made
                                             # against the whole captured name, so a truncated
                                             # value can lack the segment that selected it
    attributes:             "int | None" = None   # raw, undecoded descriptor fields, carried so
    handle_count:           "int | None" = None   # a correlated handle can be assessed without
    pointer_count:          "int | None" = None   # a second --handles run

    def __post_init__(self):
        _require_hex_address(self.handle, "ReportCorrelatedHandle.handle")
        _require_optional_diff_str(self.type_name, "ReportCorrelatedHandle.type_name")
        _require_optional_bounded_text(self.type_name, "ReportCorrelatedHandle.type_name")
        _require_bool(self.type_name_truncated,
                      "ReportCorrelatedHandle.type_name_truncated")
        if self.type_name_truncated and self.type_name is None:
            raise ValueError(
                "ReportCorrelatedHandle.type_name_truncated requires a type_name")
        _require_bounded_text(self.object_name, "ReportCorrelatedHandle.object_name",
                              ENRICHMENT_TEXT_CAP)
        _require_optional_diff_int(self.granted_access, "ReportCorrelatedHandle.granted_access")
        if self.selection_reason not in HANDLE_SELECTION_REASONS:
            raise ValueError(
                f"ReportCorrelatedHandle.selection_reason must be one of "
                f"{HANDLE_SELECTION_REASONS}, got {self.selection_reason!r}")
        _require_bool(self.object_name_truncated,
                      "ReportCorrelatedHandle.object_name_truncated")
        for field_name in ("attributes", "handle_count", "pointer_count"):
            _require_optional_diff_int(getattr(self, field_name),
                                       f"ReportCorrelatedHandle.{field_name}")

    def to_dict(self) -> dict:
        return {
            "handle":                self.handle,
            "type_name":             self.type_name,
            "object_name":           self.object_name,
            "granted_access":        self.granted_access,
            "selection_reason":      self.selection_reason,
            "type_name_truncated":   self.type_name_truncated,
            "object_name_truncated": self.object_name_truncated,
            "attributes":            self.attributes,
            "handle_count":          self.handle_count,
            "pointer_count":         self.pointer_count,
        }


@dataclass(frozen=True)
class ReportHandleCorrelation:
    """This card's bounded, deduplicated subset of the process-wide handle
    inventory."""
    section: EnrichmentSection
    entries: tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportHandleCorrelation.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="handle_correlation")
        object.__setattr__(self, "entries", tuple(self.entries))
        if any(not isinstance(e, ReportCorrelatedHandle) for e in self.entries):
            raise TypeError(
                "ReportHandleCorrelation.entries must be ReportCorrelatedHandle instances")
        if len(self.entries) != self.section.included:
            raise ValueError("ReportHandleCorrelation.entries length must equal section.included")
        handles = [e.handle for e in self.entries]
        if len(set(handles)) != len(handles):
            raise ValueError("ReportHandleCorrelation.entries must be deduplicated by handle")

    def to_dict(self) -> dict:
        return {"section": self.section.to_dict(),
                "entries": [e.to_dict() for e in self.entries]}


STRING_CONTEXT_SELECTION_REASONS = (
    "query_match",         # the exact string --report-string searched for
    "ioc_pattern",         # a string matching the report's own IOC vocabulary
    "adjacent_to_anchor",  # a string retained for its proximity to the anchor address
)


@dataclass(frozen=True)
class ReportStringContextEntry:
    """One string retained as navigation context for this card's anchor.

    `distance` is the absolute byte distance from the anchor address, and
    is None for the `query_match` entry, which IS the anchor. Proximity is
    layout: an adjacent string is not claimed to be referenced or executed
    by anything at the anchor."""
    address:          str
    offset:           int
    encoding:         str
    text:             str
    text_truncated:   bool
    selection_reason: str
    distance:         "int | None"

    def __post_init__(self):
        _require_hex_address(self.address, "ReportStringContextEntry.address")
        _require_nonneg_int(self.offset, "ReportStringContextEntry.offset")
        if self.encoding not in _STRING_RECORD_ENCODINGS:
            raise ValueError(
                f"ReportStringContextEntry.encoding must be one of {_STRING_RECORD_ENCODINGS}, "
                f"got {self.encoding!r}")
        _require_bounded_text(self.text, "ReportStringContextEntry.text", ENRICHMENT_TEXT_CAP)
        _require_bool(self.text_truncated, "ReportStringContextEntry.text_truncated")
        if self.selection_reason not in STRING_CONTEXT_SELECTION_REASONS:
            raise ValueError(
                f"ReportStringContextEntry.selection_reason must be one of "
                f"{STRING_CONTEXT_SELECTION_REASONS}, got {self.selection_reason!r}")
        _require_optional_nonneg_int(self.distance, "ReportStringContextEntry.distance")
        if (self.selection_reason == "query_match") != (self.distance is None):
            raise ValueError(
                "ReportStringContextEntry.distance must be None exactly for a 'query_match' "
                "entry -- the query hit is the anchor, so it has no distance from itself")

    def to_dict(self) -> dict:
        return {
            "address":          self.address,
            "offset":           self.offset,
            "encoding":         self.encoding,
            "text":             self.text,
            "text_truncated":   self.text_truncated,
            "selection_reason": self.selection_reason,
            "distance":         self.distance,
        }


@dataclass(frozen=True)
class ReportStringContext:
    """The anchor-aware, bounded string projection of this card's own
    content scan.

    `anchor_address` is the card's own anchor;
    `distance_anchor_address` is the address every entry's `distance` is
    measured from -- the matched string's own VA for a `string_hit` card,
    and the anchor itself otherwise. `query_text` is the needle that was
    searched for, kept apart from the `query_match` entry's own `text`,
    which is the string actually captured at the hit: an embedded needle
    means the two differ, and a consumer must be able to tell them apart.
    The exact hit location stays on the card's own `string_hit`.

    One captured string yields at most one entry. The string enclosing the
    hit is published as the `query_match` entry and never re-emitted as
    adjacent context: it IS the anchor, so labelling it "adjacent to the
    anchor" would be false and would also spend a retention slot on a
    duplicate.

    `examined_base_address`/`examined_size` are the range the card already
    read; `requested_bytes`/`bytes_read` are that read's own budget and
    result. Nothing is scanned a second time -- every entry is selected
    out of the strings the card's single content read already produced, so
    an entry can never describe bytes outside the declared examined
    range."""
    section:               EnrichmentSection
    anchor_address:        str
    distance_anchor_address: str
    query_text:            "str | None"
    examined_base_address: str
    examined_size:         int
    requested_bytes:       int
    bytes_read:            int
    total_strings:         int
    entries:               tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportStringContext.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="string_context")
        _require_hex_address(self.anchor_address, "ReportStringContext.anchor_address")
        _require_hex_address(self.distance_anchor_address,
                             "ReportStringContext.distance_anchor_address")
        if self.query_text is not None:
            _require_bounded_text(self.query_text, "ReportStringContext.query_text",
                                  ENRICHMENT_TEXT_CAP)
        _require_hex_address(self.examined_base_address,
                             "ReportStringContext.examined_base_address")
        _require_nonneg_int(self.examined_size, "ReportStringContext.examined_size")
        _require_nonneg_int(self.requested_bytes, "ReportStringContext.requested_bytes")
        _require_nonneg_int(self.bytes_read, "ReportStringContext.bytes_read")
        _require_nonneg_int(self.total_strings, "ReportStringContext.total_strings")
        if self.bytes_read > self.requested_bytes:
            raise ValueError(
                "ReportStringContext.bytes_read must not exceed requested_bytes -- a read can "
                "come up short, never long")
        object.__setattr__(self, "entries", tuple(self.entries))
        if any(not isinstance(e, ReportStringContextEntry) for e in self.entries):
            raise TypeError(
                "ReportStringContext.entries must be ReportStringContextEntry instances")
        if len(self.entries) != self.section.included:
            raise ValueError("ReportStringContext.entries length must equal section.included")
        base = int(self.examined_base_address, 16)
        for entry in self.entries:
            if int(entry.address, 16) != base + entry.offset:
                raise ValueError(
                    "ReportStringContextEntry.address must equal the examined base plus its own "
                    "offset -- a context entry never describes bytes outside the examined range")
            if entry.offset >= self.bytes_read:
                raise ValueError(
                    "ReportStringContextEntry.offset must fall inside the bytes actually read -- "
                    "unread bytes are not evidence")
        query_entries = [e for e in self.entries if e.selection_reason == "query_match"]
        if len(query_entries) > 1:
            raise ValueError("ReportStringContext retains at most one 'query_match' entry")
        if query_entries and self.query_text is None:
            raise ValueError(
                "ReportStringContext.query_text is required alongside a 'query_match' entry -- "
                "the searched needle and the string captured at the hit are different facts "
                "and must stay separately readable")
        offsets = [e.offset for e in self.entries]
        if len(set(offsets)) != len(offsets):
            raise ValueError(
                "ReportStringContext.entries must not describe the same offset twice -- one "
                "captured string is one entry, whichever class selected it")

    def to_dict(self) -> dict:
        return {
            "section":               self.section.to_dict(),
            "anchor_address":        self.anchor_address,
            "distance_anchor_address": self.distance_anchor_address,
            "query_text":            self.query_text,
            "examined_base_address": self.examined_base_address,
            "examined_size":         self.examined_size,
            "requested_bytes":       self.requested_bytes,
            "bytes_read":            self.bytes_read,
            "total_strings":         self.total_strings,
            "entries":               [e.to_dict() for e in self.entries],
        }
