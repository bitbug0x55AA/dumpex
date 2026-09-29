"""Hunt scope and references: targeted-scope measurements and the region,
thread and PE-header references a hunter's details carry.
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)


def _require_list_of(value, cls, field_name: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, cls) for item in value):
        raise TypeError(f"{field_name} must be a list of {cls.__name__}")


_CAPTURE_STATES = ("none", "partial", "complete")
# ``not_applicable`` and ``not_evaluated`` are two different facts and stay
# apart: a source whose descriptor-eligibility gate declines the target never
# applied to it, while a source that would have applied and was stopped by an
# evidence or execution gap did not get to run. Only the second is a coverage
# failure a re-collection, a larger budget, or a narrower request could close.
_COVERAGE_STATUSES = ("not_applicable", "not_evaluated", "partial", "complete")

# What a measurement's ``value`` is counted in. ``text`` carries a short
# enumerated word (``exhaustive``/``sampled``, a protection string); ``flag``
# carries a bool.
_MEASUREMENT_UNITS = ("bytes", "count", "bits_per_byte", "seconds", "text", "flag")


@dataclass(frozen=True)
class TargetedMeasurement:
    """One neutral measurement a targeted closure retained, as it appears in a
    ``targeted_scope`` entry's ``measurements``.

    A measurement is an observation and nothing more: it creates no finding,
    moves no score, and says nothing about any source other than the closure
    carrying it. It exists so a completed no-hit closure still records what it
    actually did -- how many bytes it read, what it measured over them, which
    of its own bounds it reached -- rather than reducing to an unexplained
    negative.

    ``value`` is ``None`` only when the closure genuinely did not measure this
    quantity. ``base_address``/``size`` locate a measurement inside the
    requested range when it has a location (an entropy window); both are absent
    for a measurement about the closure as a whole.

    ``name`` is not unique within a closure: a bounded top-N list is N entries
    sharing one name, in the order the closure ranked them.
    """
    name:         str
    value:        "int | float | bool | str | None"
    unit:         str
    base_address: "str | None" = None
    size:         "int | None" = None

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise ValueError(
                f"TargetedMeasurement.name must be a non-empty str, got {self.name!r}")
        if self.unit not in _MEASUREMENT_UNITS:
            raise ValueError(
                f"TargetedMeasurement.unit must be one of {_MEASUREMENT_UNITS}, "
                f"got {self.unit!r}")
        value = self.value
        if value is not None:
            if self.unit == "flag":
                if not isinstance(value, bool):
                    raise ValueError(
                        f"TargetedMeasurement.value for unit 'flag' must be a bool, "
                        f"got {value!r}")
            elif self.unit == "text":
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"TargetedMeasurement.value for unit 'text' must be a non-empty "
                        f"str, got {value!r}")
            elif isinstance(value, bool) or not isinstance(value, (int, float)):
                # bool is excluded explicitly: it is an int subclass, and a
                # stray boolean where a quantity was meant is a caller bug.
                raise ValueError(
                    f"TargetedMeasurement.value for unit {self.unit!r} must be an int or "
                    f"float, got {value!r}")
            elif value < 0:
                raise ValueError(
                    f"TargetedMeasurement.value for unit {self.unit!r} must be "
                    f"non-negative, got {value!r}")
        if self.base_address is not None:
            _require_hex_address(self.base_address, "TargetedMeasurement.base_address")
        if self.size is not None:
            if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size <= 0:
                raise ValueError(
                    f"TargetedMeasurement.size must be None or a positive plain int, "
                    f"got {self.size!r}")
        if self.size is not None and self.base_address is None:
            raise ValueError(
                "TargetedMeasurement.size describes an extent at base_address -- a size "
                "without one locates nothing")

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "value":        self.value,
            "unit":         self.unit,
            "base_address": self.base_address,
            "size":         self.size,
        }


@dataclass(frozen=True)
class TargetedScopeRecord:
    """One closure of a targeted (``--hunt-addr``) rescan, as it appears in
    ``details.targeted_scope``.

    Capture and evaluation are two independent facts and stay separate here:
    ``captured_size``/``capture_state`` describe how much of the requested
    range the dump actually holds, and ``coverage_status`` describes how far
    the source's own algorithm got over what it received. A complete capture
    can still evaluate partially (a retained budget), and a partial capture
    can be ``not_evaluated`` (the bytes never reached the algorithm's minimum
    input).

    ``coverage_status`` ``not_applicable`` is the source declining the target
    outright -- its own descriptor-eligibility gate excluded it, so there was
    never anything here for this source to miss. It is not a coverage failure,
    and ``applicability_reason`` names the exact gate. Every other status
    leaves ``applicability_reason`` ``None``: a source that applied has no
    reason not to have.

    ``measurements`` is what the closure retained about work it completed
    without producing a hit -- bytes evaluated, values measured, bounds
    reached. Observations only: they create no finding, move no score, and
    speak for no other source.

    ``base_address``/``size`` are the REQUESTED range, always -- never the
    containing descriptor and never the captured prefix -- so one closure's
    identity is ``(hunter, source, scope, base_address, size)`` regardless of
    capture outcome. ``scope`` is the closure scope (a layer name) and
    ``None`` for an unscoped source. ``captured_size`` is ``None`` only when
    byte availability is genuinely unknown.
    """
    source:              str
    scope:               "str | None"
    base_address:        str
    size:                int
    captured_size:       "int | None"
    capture_state:       str
    coverage_status:     str
    applicability_reason: "str | None" = None
    measurements:        tuple = ()

    def __post_init__(self):
        if not isinstance(self.source, str) or not self.source:
            raise ValueError(
                f"TargetedScopeRecord.source must be a non-empty str, got {self.source!r}")
        if self.scope is not None and (not isinstance(self.scope, str) or not self.scope):
            raise ValueError(
                f"TargetedScopeRecord.scope must be None or a non-empty str, got {self.scope!r}")
        _require_hex_address(self.base_address, "TargetedScopeRecord.base_address")
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size <= 0:
            raise ValueError(
                f"TargetedScopeRecord.size must be a positive plain int, got {self.size!r}")
        _require_optional_nonneg_int(self.captured_size, "TargetedScopeRecord.captured_size")
        if self.captured_size is not None and self.captured_size > self.size:
            raise ValueError(
                f"TargetedScopeRecord.captured_size ({self.captured_size}) cannot exceed the "
                f"requested size ({self.size})")
        if self.capture_state not in _CAPTURE_STATES:
            raise ValueError(
                f"TargetedScopeRecord.capture_state must be one of {_CAPTURE_STATES}, "
                f"got {self.capture_state!r}")
        if self.coverage_status not in _COVERAGE_STATUSES:
            raise ValueError(
                f"TargetedScopeRecord.coverage_status must be one of {_COVERAGE_STATUSES}, "
                f"got {self.coverage_status!r}")
        if self.coverage_status == "complete" and self.capture_state != "complete":
            raise ValueError(
                "TargetedScopeRecord.coverage_status 'complete' requires capture_state "
                f"'complete', got {self.capture_state!r}")
        if self.coverage_status == "not_applicable":
            if not isinstance(self.applicability_reason, str) or not self.applicability_reason:
                raise ValueError(
                    "TargetedScopeRecord.coverage_status 'not_applicable' requires a "
                    "non-empty applicability_reason -- 'does not apply' without the gate "
                    f"that declined it is not actionable, got {self.applicability_reason!r}")
        elif self.applicability_reason is not None:
            raise ValueError(
                f"TargetedScopeRecord.applicability_reason belongs to coverage_status "
                f"'not_applicable' only, got {self.coverage_status!r} with "
                f"{self.applicability_reason!r}")
        object.__setattr__(self, "measurements", tuple(self.measurements))
        for item in self.measurements:
            if not isinstance(item, TargetedMeasurement):
                raise TypeError(
                    "TargetedScopeRecord.measurements entries must be "
                    f"TargetedMeasurement instances, got {item!r}")

    def to_dict(self) -> dict:
        return {
            "source":               self.source,
            "scope":                self.scope,
            "base_address":         self.base_address,
            "size":                 self.size,
            "captured_size":        self.captured_size,
            "capture_state":        self.capture_state,
            "coverage_status":      self.coverage_status,
            "applicability_reason": self.applicability_reason,
            "measurements":         [m.to_dict() for m in self.measurements],
        }


def _require_optional_targeted_scope(value, field_name: str) -> None:
    """``targeted_scope`` is ``None`` for a full-scope result and a non-empty
    list of :class:`TargetedScopeRecord` for a targeted one. ``None`` and
    ``[]`` are different facts -- a targeted rescan always projects at least
    one closure -- so an empty list is rejected rather than normalized."""
    if value is None:
        return
    if not isinstance(value, list) or not value:
        raise TypeError(
            f"{field_name} must be None or a non-empty list of TargetedScopeRecord")
    _require_list_of(value, TargetedScopeRecord, field_name)


def _targeted_scope_dict(details) -> dict:
    """The ``targeted_scope`` key for a details ``to_dict()``, or no key at
    all for a full-scope result. A full-scope details object omits the key
    completely rather than emitting ``null``."""
    if details.targeted_scope is None:
        return {}
    return {"targeted_scope": [item.to_dict() for item in details.targeted_scope]}


@dataclass
class HuntRegionRef:
    """A deterministic, value-based memory-region reference in hunt details.

    Raw parser objects must not reach JSON because their string form can
    contain analysis-host heap addresses.
    """
    base_address:    str
    allocation_base: "str | None"
    size:            int
    type:            str
    protect:         str

    def __post_init__(self):
        _require_hex_address(self.base_address, "HuntRegionRef.base_address")
        _require_optional_hex_address(self.allocation_base, "HuntRegionRef.allocation_base")
        _require_nonneg_int(self.size, "HuntRegionRef.size")
        if not isinstance(self.type, str) or not self.type:
            raise ValueError("HuntRegionRef.type must be a non-empty string")
        if not isinstance(self.protect, str) or not self.protect:
            raise ValueError("HuntRegionRef.protect must be a non-empty string")

    def to_dict(self) -> dict:
        return {
            "base_address":    self.base_address,
            "allocation_base": self.allocation_base,
            "size":            self.size,
            "type":            self.type,
            "protect":         self.protect,
        }


@dataclass
class HuntThreadRef:
    """A thread reference inside a hunter's `details` -- TID plus optional
    StartAddress / current instruction pointer, hex-formatted. Same
    non-reproducibility problem as HuntRegionRef above for the raw
    ThreadInfo/Thread objects it replaces.

    `start_address` is None whenever no start address was established
    for this thread -- ThreadInfoListStream never covered this TID, or
    the record it did carry disowns every field but ThreadId (see
    dumpex.core.memory.recorded_start_address) -- and is never address
    0x0 standing in for either.

    `ip_context_conflict` is the same tri-state dumpex.core.memory.
    ip_context_conflict_for result ReportThreadInfo/ThreadRecord publish
    for the identical fact on the same TID: True (this TID's own
    ThreadInfoListStream record flags its context as invalid despite the
    parsed `ip`), False (`ip` is None, or a real record's readable flags
    confirm no dispute), or None (`ip` is set but no DumpFlags value
    could be established for this TID, whether because no
    ThreadInfoListStream record exists or because that record's flags
    could not be read -- undeterminable, never a confirmed False). A
    hunter
    that turns a disputed or undeterminable `ip` into a "currently
    executing" claim must qualify it -- see e.g.
    dumpex.hunt.injection.aggregate's own handling of rip_hits."""
    tid:            int
    start_address:  "str | None" = None
    ip:             "str | None" = None
    ip_reg:         "str | None" = None
    ip_context_conflict: "bool | None" = False

    def __post_init__(self):
        _require_nonneg_int(self.tid, "HuntThreadRef.tid")
        _require_optional_hex_address(self.start_address, "HuntThreadRef.start_address")
        _require_optional_hex_address(self.ip, "HuntThreadRef.ip")
        if self.ip_reg is not None and not isinstance(self.ip_reg, str):
            raise ValueError("HuntThreadRef.ip_reg must be None or a string")
        if self.ip is not None and self.ip_reg is None:
            raise ValueError("HuntThreadRef.ip_reg is required when ip is set")
        if self.ip is None and self.ip_reg is not None:
            raise ValueError("HuntThreadRef.ip_reg must be None when ip is None")
        if self.ip_context_conflict is not None and not isinstance(self.ip_context_conflict, bool):
            raise ValueError("HuntThreadRef.ip_context_conflict must be None or a bool")
        if self.ip is None and self.ip_context_conflict is not False:
            raise ValueError(
                "HuntThreadRef.ip_context_conflict must be False when ip is None -- there is "
                "no captured value to dispute regardless of ThreadInfoListStream coverage")

    def to_dict(self) -> dict:
        return {"tid": self.tid, "start_address": self.start_address,
                "ip": self.ip, "ip_reg": self.ip_reg,
                "ip_context_conflict": self.ip_context_conflict}


@dataclass
class HuntThreadRegionHit:
    """A thread correlated with a specific region -- e.g. a thread's
    current RIP/EIP executing inside a flagged allocation, or its
    StartAddress falling inside one. Raw correlation.py output is a
    `(thread_ctx_or_info, region)` tuple; a bare `HuntThreadRef` alone
    would lose WHICH region/allocation the thread was actually correlated
    with, making it impossible for a consumer to re-verify a "full
    correlation" claim against InjectionDetails' `rwx`/`hidden_pe_validated`."""
    thread: HuntThreadRef
    region: HuntRegionRef

    def __post_init__(self):
        if not isinstance(self.thread, HuntThreadRef):
            raise TypeError("HuntThreadRegionHit.thread must be a HuntThreadRef")
        if not isinstance(self.region, HuntRegionRef):
            raise TypeError("HuntThreadRegionHit.region must be a HuntRegionRef")

    def to_dict(self) -> dict:
        return {"thread": self.thread.to_dict(), "region": self.region.to_dict()}


@dataclass
class HuntPeHeaderHit:
    """One MZ candidate examined for a hidden PE header (injection's
    hidden_pe_validated/hidden_pe_unvalidated) -- where the candidate is,
    the CONTAINING region, and the structural-validation outcome.
    `entry_point_rva` stays a plain int (an RVA is relative to a
    not-yet-established image base, not itself a memory address -- see
    the type rule in dumpex.output.records.common); `image_base` (the PE
    header's OWN declared base) is a real address, hex-formatted.

    `va`/`region_offset`/`file_offset` (schema_version 2.11) are the
    candidate's OWN location: the process address its 'MZ' was found at,
    how far into `region` that is, and where those bytes sit in the .dmp
    (`null` when the VA is not covered by any captured segment -- NOT the
    same claim as offset zero). They exist because `region` alone stopped
    being able to answer "where is the PE" once the hidden-PE scan started
    searching whole regions instead of only their base addresses (issue
    #26): a PE mapped partway into an allocation shares its region with
    everything else in that allocation, so a consumer given only the
    region cannot carve it, correlate it, or tell two hits in one region
    apart. `region` still describes where the candidate LIVES -- it is
    what allocation correlation is keyed on -- and for a PE at a region's
    base `va` equals `region.base_address`."""
    region:              HuntRegionRef
    valid:               bool
    va:                  "str | None" = None
    region_offset:       int = 0
    file_offset:         "str | None" = None
    machine_name:        "str | None" = None
    is_pe32_plus:        "bool | None" = None
    number_of_sections:  "int | None" = None
    entry_point_rva:     "int | None" = None
    image_base:          "str | None" = None
    reason:              "str | None" = None   # only set when valid is False

    def __post_init__(self):
        if not isinstance(self.region, HuntRegionRef):
            raise TypeError("HuntPeHeaderHit.region must be a HuntRegionRef")
        _require_bool(self.valid, "HuntPeHeaderHit.valid")
        _require_optional_hex_address(self.va, "HuntPeHeaderHit.va")
        _require_optional_hex_address(self.file_offset, "HuntPeHeaderHit.file_offset")
        _require_nonneg_int(self.region_offset, "HuntPeHeaderHit.region_offset")
        _require_optional_hex_address(self.image_base, "HuntPeHeaderHit.image_base")
        if self.number_of_sections is not None:
            _require_nonneg_int(self.number_of_sections, "HuntPeHeaderHit.number_of_sections")
        if self.entry_point_rva is not None:
            _require_nonneg_int(self.entry_point_rva, "HuntPeHeaderHit.entry_point_rva")
        pe_fields = ("machine_name", "is_pe32_plus", "number_of_sections",
                     "entry_point_rva", "image_base")
        if self.valid:
            if self.reason is not None:
                raise ValueError("HuntPeHeaderHit.reason must be None when valid is True")
            for f_name in pe_fields:
                if getattr(self, f_name) is None:
                    raise ValueError(
                        f"HuntPeHeaderHit.{f_name} must be set when valid is True -- a "
                        f"structurally-valid PE header always carries these facts")
            if not isinstance(self.machine_name, str) or not self.machine_name:
                raise ValueError(
                    "HuntPeHeaderHit.machine_name must be a non-empty string when valid is True")
            _require_bool(self.is_pe32_plus, "HuntPeHeaderHit.is_pe32_plus")
        else:
            for f_name in pe_fields:
                if getattr(self, f_name) is not None:
                    raise ValueError(
                        f"HuntPeHeaderHit.{f_name} must be None when valid is False")
            if not isinstance(self.reason, str) or not self.reason:
                raise ValueError(
                    "HuntPeHeaderHit.reason must be a non-empty string when valid is False")

    def to_dict(self) -> dict:
        return {
            "region":             self.region.to_dict(),
            "valid":              self.valid,
            "va":                 self.va,
            "region_offset":      self.region_offset,
            "file_offset":        self.file_offset,
            "machine_name":       self.machine_name,
            "is_pe32_plus":       self.is_pe32_plus,
            "number_of_sections": self.number_of_sections,
            "entry_point_rva":    self.entry_point_rva,
            "image_base":         self.image_base,
            "reason":             self.reason,
        }
