"""`--process`'s canonical main-image PE profile records.

See docs/developer/recon_process_sysinfo_handles_contract.md §3.10 for the
wire shape and docs/developer/pe_image_profile_contract.md for the
meanings it carries. Every record here projects an already-built
dumpex.core.pe_profile.PeImageProfile and its
dumpex.core.pe_correlation.MainImageCorrelation: a renderer or a builder
here re-reads no memory, re-parses no header, and recomputes no state
(§9's first projection rule).

The tiers of the PE contract's §1.1 stay separated on the wire too: the
profile's own decoded facts and byte provenance live in ProcessPeRecord's
scalar fields, sections, directories, and `acquisition`, while every
comparison lives in `observations` as a three-valued observation. No
field here is a verdict: `conflict` is a disagreement between two captured
facts, and `structural_state` describes the acquisition, never the image's
intent.
"""
from dataclasses import dataclass

from dumpex.output.records.base import _MODULE_CONTEXTS
from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)
from dumpex.output.records.pe_observation import PE_OBSERVATION_STATES, PeObservationRecord


# ComponentState's five values (PE contract §1.2), carried verbatim.
PROCESS_PE_COMPONENT_STATES = (
    "complete", "partial", "unavailable", "malformed", "declared_absent")

# The six components of §1.2, in the contract's frozen declaration order.
PROCESS_PE_COMPONENTS = (
    "dos_header", "coff_header", "optional_header", "directory_array",
    "directory_descriptors", "section_table")

# PeStage's ladder (§6.1), lowercased for the wire.
PROCESS_PE_STAGES = ("dos", "coff", "optional", "sections")

# SourceKind's memory-indexed kinds (§2.1). `disk_reference` is excluded
# because it has no `actual_base`: a profile of file bytes cannot be
# correlated against process memory and never reaches this record.
PROCESS_PE_SOURCE_KINDS = ("peb_image_base", "module_list_entry", "memory_candidate")

PROCESS_PE_FORMATS = ("PE32", "PE32+")

# CaptureState's three values (dumpex.core.va_range), carried verbatim.
PROCESS_PE_CAPTURE_STATES = ("none", "partial", "complete")

# Why no profile was built. `no_image_base` is the PEB claim itself being
# absent or unnormalizable, `header_unreadable` is an image base that was
# there with nothing readable at it, and `collection_failed` is dumpex
# declining to build a profile from bytes it did hold. The three have
# different remedies, so they are different tokens rather than one
# "unavailable" -- in particular `collection_failed` is a defect in dumpex
# and must never be read as a fact about the image.
PROCESS_PE_UNAVAILABLE_REASONS = ("no_image_base", "header_unreadable", "collection_failed")

# What became of one of the dump's own tables. The five are distinct
# because they have distinct remedies, and because three of them are
# routinely confused: a table that is not in the dump, one that is in the
# dump and yielded nothing usable, and one that parsed and legitimately
# carries no entries are three different statements about evidence, and
# none of them may be reported as another.
PROCESS_PE_TABLE_STATES = (
    "absent",       # the dump does not carry this stream at all
    "failed",       # the stream is in the dump and no usable table came back
    "enumerated",   # walked; every descriptor it carries is representable,
                    # including a table that carries none
    "lossy",        # walked, but at least one descriptor was not representable
    "unreadable",   # the walk itself raised: nothing about the table is established
)

# The states in which a table establishes nothing a check may rest on.
# Each yields `None` to the correlation layer -- "not usable evidence" --
# rather than an empty table, which would answer as a table that looked
# and found nothing.
PROCESS_PE_UNUSABLE_TABLE_STATES = ("absent", "failed", "unreadable")

# How a data directory's `value` addresses what it points at (PE contract
# §2.5). Index 4 (Security) is a file offset into the on-disk image and
# is not part of the mapping; every other index is an image RVA.
PROCESS_PE_VALUE_KINDS = ("rva", "file_offset")

# `dumpex.core.pe_profile.ModuleIdentity.form`.
PROCESS_PE_IDENTITY_FORMS = ("path", "name")


def _require_optional_enum(value, allowed, field_name: str) -> None:
    if value is not None and value not in allowed:
        raise ValueError(f"{field_name} must be None or one of {allowed}, got {value!r}")


@dataclass(frozen=True)
class ProcessPeSectionRecord:
    """One section header of the main image, in section-table order.

    `virtual_address` / `virtual_size` are RVAs and sizes as the header
    declares them; `mapped_base_address` / `mapped_size` are the same
    section resolved against the image's *actual* base, and are null when
    that arithmetic is not representable. `declared_readable` /
    `declared_writable` / `declared_executable` are the header's own
    Characteristics bits. `live_protections` is the distinct protection
    names of the captured regions the mapped range falls in -- context,
    never an observation: `PAGE_EXECUTE_WRITECOPY` is ordinary loader
    context for an executable image section. The per-section observations
    live in the record's flat `observations` array, each carrying this
    `section_index` in its operands."""
    section_index:        int
    name:                 str
    virtual_address:      int
    virtual_size:         int
    size_of_raw_data:     int
    characteristics:      int
    declared_readable:    bool
    declared_writable:    bool
    declared_executable:  bool
    mapped_base_address:  "str | None"
    mapped_size:          "int | None"
    capture_state:        "str | None"
    live_protections:     tuple = ()

    def __post_init__(self):
        _require_nonneg_int(self.section_index, "ProcessPeSectionRecord.section_index")
        if not isinstance(self.name, str):
            raise ValueError("ProcessPeSectionRecord.name must be a string")
        for field_name in ("virtual_address", "virtual_size", "size_of_raw_data",
                            "characteristics"):
            _require_nonneg_int(getattr(self, field_name),
                                 f"ProcessPeSectionRecord.{field_name}")
        for field_name in ("declared_readable", "declared_writable", "declared_executable"):
            _require_bool(getattr(self, field_name), f"ProcessPeSectionRecord.{field_name}")
        _require_optional_hex_address(self.mapped_base_address,
                                       "ProcessPeSectionRecord.mapped_base_address")
        _require_optional_nonneg_int(self.mapped_size, "ProcessPeSectionRecord.mapped_size")
        # A mapped range is one fact in two fields: half of it would let a
        # consumer read a start with no extent, or an extent with no place.
        if (self.mapped_base_address is None) != (self.mapped_size is None):
            raise ValueError(
                "ProcessPeSectionRecord.mapped_base_address and mapped_size are one mapped "
                "range: both are set or both are null")
        _require_optional_enum(self.capture_state, PROCESS_PE_CAPTURE_STATES,
                                "ProcessPeSectionRecord.capture_state")
        object.__setattr__(self, "live_protections", tuple(self.live_protections))
        if any(not isinstance(p, str) or not p for p in self.live_protections):
            raise ValueError("ProcessPeSectionRecord.live_protections must be non-empty strings")

    def to_dict(self) -> dict:
        return {
            "section_index":        self.section_index,
            "name":                 self.name,
            "virtual_address":      self.virtual_address,
            "virtual_size":         self.virtual_size,
            "size_of_raw_data":     self.size_of_raw_data,
            "characteristics":      self.characteristics,
            "declared_readable":    self.declared_readable,
            "declared_writable":    self.declared_writable,
            "declared_executable":  self.declared_executable,
            "mapped_base_address":  self.mapped_base_address,
            "mapped_size":          self.mapped_size,
            "capture_state":        self.capture_state,
            "live_protections":     list(self.live_protections),
        }


@dataclass(frozen=True)
class ProcessPeDirectoryRecord:
    """One data-directory descriptor, in index order. All sixteen are
    always present: an omitted descriptor would make "not captured"
    indistinguishable from "not declared".

    `present` is three-valued presence read from the descriptor's own
    value once four bytes are in hand, and `descriptor_state` describes
    the eight descriptor bytes -- never the contents they point at.
    `value_kind` says how `value` is addressed: index 4 (Security) is a
    file offset, every other index is an RVA, so index 4 carries no
    containing section and no capture claim."""
    index:                     int
    name:                      str
    value:                     "int | None"
    value_kind:                str
    size:                      "int | None"
    bytes_read:                int
    present:                   "bool | None"
    descriptor_state:          str
    containing_section_index:  "int | None"
    capture_state:             "str | None"

    def __post_init__(self):
        _require_nonneg_int(self.index, "ProcessPeDirectoryRecord.index")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("ProcessPeDirectoryRecord.name must be a non-empty string")
        _require_optional_nonneg_int(self.value, "ProcessPeDirectoryRecord.value")
        if self.value_kind not in PROCESS_PE_VALUE_KINDS:
            raise ValueError(
                f"ProcessPeDirectoryRecord.value_kind must be 'rva' or 'file_offset', "
                f"got {self.value_kind!r}")
        _require_optional_nonneg_int(self.size, "ProcessPeDirectoryRecord.size")
        _require_nonneg_int(self.bytes_read, "ProcessPeDirectoryRecord.bytes_read")
        if self.present is not None:
            _require_bool(self.present, "ProcessPeDirectoryRecord.present")
        if self.descriptor_state not in PROCESS_PE_COMPONENT_STATES:
            raise ValueError(
                f"ProcessPeDirectoryRecord.descriptor_state must be one of "
                f"{PROCESS_PE_COMPONENT_STATES}, got {self.descriptor_state!r}")
        _require_optional_nonneg_int(self.containing_section_index,
                                      "ProcessPeDirectoryRecord.containing_section_index")
        _require_optional_enum(self.capture_state, PROCESS_PE_CAPTURE_STATES,
                                "ProcessPeDirectoryRecord.capture_state")

    def to_dict(self) -> dict:
        return {
            "index":                     self.index,
            "name":                      self.name,
            "value":                     self.value,
            "value_kind":                self.value_kind,
            "size":                      self.size,
            "bytes_read":                self.bytes_read,
            "present":                   self.present,
            "descriptor_state":          self.descriptor_state,
            "containing_section_index":  self.containing_section_index,
            "capture_state":             self.capture_state,
        }


# Everything an entry point resolves into the process. Each is null for
# an image that declares no entry point, and each is the correlation's
# work rather than the header's.
_ENTRY_POINT_RESOLVED_FIELDS = (
    "va", "section_index", "section_name", "capture_state", "region_state",
    "region_type", "region_protection",
)


@dataclass(frozen=True)
class ProcessPeEntryPointRecord:
    """The entry point resolved into the process, and the memory evidence
    around it -- context for the `entry_point_in_section` observation,
    never a second verdict.

    A zero `AddressOfEntryPoint` is "no entry point": `rva` is 0 and every
    other field is null, because resolving `actual_base + 0` would present
    the header page as where execution begins. `rva` is itself null when
    the optional header's own field was never decoded -- a question with
    no answer, not an entry point at zero. `va_overflow` says the addition
    wrapped the 64-bit space and no VA could be formed."""
    rva:                "int | None"
    va:                 "str | None"
    va_overflow:        bool
    section_index:      "int | None"
    section_name:       "str | None"
    capture_state:      "str | None"
    region_state:       "str | None"
    region_type:        "str | None"
    region_protection:  "str | None"

    def __post_init__(self):
        _require_optional_nonneg_int(self.rva, "ProcessPeEntryPointRecord.rva")
        _require_optional_hex_address(self.va, "ProcessPeEntryPointRecord.va")
        _require_bool(self.va_overflow, "ProcessPeEntryPointRecord.va_overflow")
        _require_optional_nonneg_int(self.section_index,
                                      "ProcessPeEntryPointRecord.section_index")
        for field_name in ("section_name", "region_state", "region_type", "region_protection"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"ProcessPeEntryPointRecord.{field_name} must be None or a string")
        _require_optional_enum(self.capture_state, PROCESS_PE_CAPTURE_STATES,
                                "ProcessPeEntryPointRecord.capture_state")
        if self.va is not None and self.va_overflow:
            raise ValueError(
                "ProcessPeEntryPointRecord.va_overflow says no VA could be formed, so va "
                "must be null")
        # A zero `AddressOfEntryPoint` is "this image declares no entry
        # point", so nothing was resolved into the process: resolving
        # `actual_base + 0` would present the header page as where
        # execution begins, and every field that would have said so is
        # null. The addition was never attempted either, so there is no
        # overflow to report.
        if self.rva == 0:
            if self.va_overflow:
                raise ValueError(
                    "ProcessPeEntryPointRecord.va_overflow must be false for a zero entry "
                    "point: no address was formed to overflow")
            for field_name in _ENTRY_POINT_RESOLVED_FIELDS:
                if getattr(self, field_name) is not None:
                    raise ValueError(
                        f"ProcessPeEntryPointRecord.{field_name} must be null for a zero "
                        f"entry point -- the image declares none, so nothing was resolved")

    def to_dict(self) -> dict:
        return {
            "rva":                self.rva,
            "va":                 self.va,
            "va_overflow":        self.va_overflow,
            "section_index":      self.section_index,
            "section_name":       self.section_name,
            "capture_state":      self.capture_state,
            "region_state":       self.region_state,
            "region_type":        self.region_type,
            "region_protection":  self.region_protection,
        }


@dataclass(frozen=True)
class ProcessPeAcquisitionRecord:
    """How the profile was acquired: the stage ladder it climbed, the
    three independent byte facts, any bounded stop, the per-component
    states, and the byte ranges nothing looked at.

    `requested_bytes` / `captured_bytes` / `read_bytes` are never
    collapsed: `captured < requested` is a collection gap and
    `read < captured` is a read failure over bytes that were present, and
    the two have different remedies. `captured_bytes` is null when the
    dump supplied no segment table to resolve the request against --
    absence of the provenance, not a claim that nothing was captured.
    A staged acquisition stops when its ladder is satisfied, so
    `read_bytes` is normally far below both on a healthy image;
    `target_io_short` is the three-valued judgement over
    `read_target_bytes`, so no consumer re-derives it. `unexamined` is a
    statement about bytes only: never that the image is intact there, and
    never that it is damaged there.

    `segment_table` and `region_table` say how completely the dump's own
    tables could be walked. They are provenance for everything resting on
    them: a table dumpex could not represent in full bounds nothing, and
    the gap it leaves belongs to that table rather than to the image.
    `capture_overlapping` is the segment table claiming one address twice
    inside the captured prefix -- a contradictory table whose byte
    provenance a consumer must not trust; it is `null` when no capture
    slice was resolved at all."""
    requested_stage:          str
    highest_completed_stage:  "str | None"
    requested_bytes:          int
    captured_bytes:           "int | None"
    read_bytes:               int
    read_target_bytes:        int
    target_io_short:          "bool | None"
    bounded_stop:             "dict | None"
    components:               dict
    segment_table:            str
    region_table:             str
    capture_overlapping:      "bool | None"
    unexamined:               tuple = ()

    def __post_init__(self):
        if self.requested_stage not in PROCESS_PE_STAGES:
            raise ValueError(
                f"ProcessPeAcquisitionRecord.requested_stage must be one of "
                f"{PROCESS_PE_STAGES}, got {self.requested_stage!r}")
        _require_optional_enum(self.highest_completed_stage, PROCESS_PE_STAGES,
                                "ProcessPeAcquisitionRecord.highest_completed_stage")
        for field_name in ("requested_bytes", "read_bytes", "read_target_bytes"):
            _require_nonneg_int(getattr(self, field_name),
                                 f"ProcessPeAcquisitionRecord.{field_name}")
        _require_optional_nonneg_int(self.captured_bytes,
                                      "ProcessPeAcquisitionRecord.captured_bytes")
        if self.target_io_short is not None:
            _require_bool(self.target_io_short, "ProcessPeAcquisitionRecord.target_io_short")
        if self.bounded_stop is not None:
            if not isinstance(self.bounded_stop, dict):
                raise TypeError(
                    "ProcessPeAcquisitionRecord.bounded_stop must be None or a dict")
            if set(self.bounded_stop) != {"scope", "budget_limit", "budget_consumed"}:
                raise ValueError(
                    "ProcessPeAcquisitionRecord.bounded_stop must carry exactly "
                    "scope/budget_limit/budget_consumed -- an unattributed stop is "
                    "indistinguishable from a structural end")
        if not isinstance(self.components, dict):
            raise TypeError("ProcessPeAcquisitionRecord.components must be a dict")
        if tuple(self.components) != PROCESS_PE_COMPONENTS:
            raise ValueError(
                f"ProcessPeAcquisitionRecord.components must carry exactly "
                f"{PROCESS_PE_COMPONENTS} in that order, got {tuple(self.components)}")
        for name, state in self.components.items():
            # A component outside the requested stage carries null: it is
            # not part of the answer at all, which is a different fact
            # from a component that was asked for and came back
            # `unavailable`.
            _require_optional_enum(state, PROCESS_PE_COMPONENT_STATES,
                                    f"ProcessPeAcquisitionRecord.components[{name!r}]")
        for field_name in ("segment_table", "region_table"):
            value = getattr(self, field_name)
            if value not in PROCESS_PE_TABLE_STATES:
                raise ValueError(
                    f"ProcessPeAcquisitionRecord.{field_name} must be one of "
                    f"{PROCESS_PE_TABLE_STATES}, got {value!r}")
        if self.capture_overlapping is not None:
            _require_bool(self.capture_overlapping,
                           "ProcessPeAcquisitionRecord.capture_overlapping")
        # The overlap is a property of a resolved capture slice, and
        # `captured_bytes` is what says one was resolved: claiming either
        # answer without one would describe a table nothing was compared
        # against.
        if (self.captured_bytes is None) != (self.capture_overlapping is None):
            raise ValueError(
                "ProcessPeAcquisitionRecord.capture_overlapping is an answer about a "
                "resolved capture slice, so it is set exactly when captured_bytes is")
        # Only a segment table that enumerated whole can resolve that
        # slice. The implication runs one way: an `enumerated` table may
        # still leave the byte provenance unresolved, because a slice
        # accounting for fewer bytes than the read returned is refused as
        # well. `region_table` does not enter it -- the region table
        # bounds no read.
        if self.segment_table != "enumerated" and self.captured_bytes is not None:
            raise ValueError(
                f"ProcessPeAcquisitionRecord.captured_bytes must be null when the segment "
                f"table is {self.segment_table!r}: a table that established nothing cannot "
                f"have resolved a capture slice")
        object.__setattr__(self, "unexamined", tuple(self.unexamined))
        for span in self.unexamined:
            if not isinstance(span, dict) or set(span) != {"base_address", "size"}:
                raise ValueError(
                    "ProcessPeAcquisitionRecord.unexamined entries must carry exactly "
                    "base_address/size")
            _require_hex_address(span["base_address"],
                                  "ProcessPeAcquisitionRecord.unexamined[].base_address")
            _require_nonneg_int(span["size"], "ProcessPeAcquisitionRecord.unexamined[].size")

    def to_dict(self) -> dict:
        return {
            "requested_stage":          self.requested_stage,
            "highest_completed_stage":  self.highest_completed_stage,
            "requested_bytes":          self.requested_bytes,
            "captured_bytes":           self.captured_bytes,
            "read_bytes":               self.read_bytes,
            "read_target_bytes":        self.read_target_bytes,
            "target_io_short":          self.target_io_short,
            "bounded_stop":             (dict(self.bounded_stop)
                                          if self.bounded_stop is not None else None),
            "components":               dict(self.components),
            "segment_table":            self.segment_table,
            "region_table":             self.region_table,
            "capture_overlapping":      self.capture_overlapping,
            "unexamined":               [dict(span) for span in self.unexamined],
        }


@dataclass(frozen=True)
class ProcessPeRecord:
    """`--process`'s `pe_image` object -- the canonical main-image PE
    profile and its correlation with process memory evidence. Always
    present as an object, never null.

    `collected` is whether a profile was built at all, and
    `unavailable_reason` says why when it was not. An uncollected profile
    leaves every fact here null or empty and changes nothing about the
    process identity fields beside it: this evidence is optional, and its
    absence can neither erase nor downgrade what the PEB, MiscInfo, and
    ModuleList claims independently established.

    `structural_state` is the profile's own rollup over the components the
    requested stage covered. It answers "is the image defective?", not
    "will re-reading help?" -- the legacy `identity_evidence.main_image_pe`
    `checked`/`valid`/`reason` triple keeps answering the second question
    unchanged, and neither is derived from the other. `observations`
    carries every evaluated comparison, `observation_coverage` tallies
    them, and nothing in either is a score, a confidence, or a verdict.

    `correlated` is the second discriminator, and it exists so an empty
    tally can never be read as a clean image: a correlation that ran
    always produces observations, so `total: 0` means one did not run.
    Everything the correlation establishes -- the observations, each
    section's mapped range and live protections, and the entry point's VA
    and memory context -- is withheld when it is false, while the
    profile's own decoded facts stay exactly what they were."""
    collected:             bool
    correlated:            bool
    unavailable_reason:    "str | None"
    source_kind:           "str | None"
    module_identity:       dict
    actual_base:           "str | None"
    preferred_image_base:  "str | None"
    format:                "str | None"
    machine:               "int | None"
    machine_name:          "str | None"
    time_date_stamp:       "int | None"
    checksum:              "int | None"
    subsystem:             "int | None"
    dll_characteristics:   "int | None"
    coff_characteristics:  "int | None"
    size_of_image:         "int | None"
    size_of_headers:       "int | None"
    section_alignment:     "int | None"
    file_alignment:        "int | None"
    declared_section_count: "int | None"
    decoded_section_count:  int
    structural_state:      "str | None"
    relocation:            dict
    entry_point:           ProcessPeEntryPointRecord
    acquisition:           "ProcessPeAcquisitionRecord | None"
    directory_summary:     dict
    module_match:          "str | None"
    observation_coverage:  dict
    sections:              tuple = ()
    directories:           tuple = ()
    observations:          tuple = ()

    def __post_init__(self):
        _require_bool(self.collected, "ProcessPeRecord.collected")
        _require_bool(self.correlated, "ProcessPeRecord.correlated")
        if self.correlated and not self.collected:
            raise ValueError(
                "ProcessPeRecord.correlated requires a profile to have been collected -- "
                "there is nothing to correlate otherwise")
        _require_optional_enum(self.unavailable_reason, PROCESS_PE_UNAVAILABLE_REASONS,
                                "ProcessPeRecord.unavailable_reason")
        if self.collected != (self.unavailable_reason is None):
            raise ValueError(
                "ProcessPeRecord.unavailable_reason is set exactly when no profile was "
                "collected")
        _require_optional_enum(self.source_kind, PROCESS_PE_SOURCE_KINDS,
                                "ProcessPeRecord.source_kind")
        if not isinstance(self.module_identity, dict):
            raise TypeError("ProcessPeRecord.module_identity must be a dict")
        if set(self.module_identity) != {"value", "form", "truncated"}:
            raise ValueError(
                "ProcessPeRecord.module_identity must carry exactly value/form/truncated")
        identity_value = self.module_identity["value"]
        if identity_value is not None and not isinstance(identity_value, str):
            raise ValueError("ProcessPeRecord.module_identity['value'] must be None or a string")
        _require_optional_enum(self.module_identity["form"], PROCESS_PE_IDENTITY_FORMS,
                                "ProcessPeRecord.module_identity['form']")
        _require_bool(self.module_identity["truncated"],
                       "ProcessPeRecord.module_identity['truncated']")
        # A shortened string is never shown as a whole one, and the flag
        # is what says so: a name nobody supplied cannot be a shortened
        # one, and an identity with a value has to say which form it is.
        if identity_value is None:
            if self.module_identity["form"] is not None:
                raise ValueError(
                    "ProcessPeRecord.module_identity['form'] must be null when there is no value")
            if self.module_identity["truncated"]:
                raise ValueError(
                    "ProcessPeRecord.module_identity['truncated'] must be false when there is "
                    "no value")
        elif self.module_identity["form"] is None:
            raise ValueError(
                "ProcessPeRecord.module_identity['form'] must be set when there is a value")
        for field_name in ("actual_base", "preferred_image_base"):
            _require_optional_hex_address(getattr(self, field_name),
                                           f"ProcessPeRecord.{field_name}")
        _require_optional_enum(self.format, PROCESS_PE_FORMATS, "ProcessPeRecord.format")
        for field_name in ("machine", "time_date_stamp", "checksum", "subsystem",
                            "dll_characteristics", "coff_characteristics", "size_of_image",
                            "size_of_headers", "section_alignment", "file_alignment",
                            "declared_section_count"):
            _require_optional_nonneg_int(getattr(self, field_name),
                                          f"ProcessPeRecord.{field_name}")
        if self.machine_name is not None and not isinstance(self.machine_name, str):
            raise ValueError("ProcessPeRecord.machine_name must be None or a string")
        _require_nonneg_int(self.decoded_section_count, "ProcessPeRecord.decoded_section_count")
        _require_optional_enum(self.structural_state, PROCESS_PE_COMPONENT_STATES,
                                "ProcessPeRecord.structural_state")
        self._check_relocation()
        if not isinstance(self.entry_point, ProcessPeEntryPointRecord):
            raise TypeError("ProcessPeRecord.entry_point must be a ProcessPeEntryPointRecord")
        if self.acquisition is not None and not isinstance(self.acquisition,
                                                            ProcessPeAcquisitionRecord):
            raise TypeError(
                "ProcessPeRecord.acquisition must be None or a ProcessPeAcquisitionRecord")
        self._check_directory_summary()
        if self.module_match is not None and self.module_match not in _MODULE_CONTEXTS:
            raise ValueError(
                f"ProcessPeRecord.module_match must be None or one of {_MODULE_CONTEXTS}, "
                f"got {self.module_match!r}")
        self._check_observation_coverage()
        object.__setattr__(self, "sections", tuple(self.sections))
        object.__setattr__(self, "directories", tuple(self.directories))
        object.__setattr__(self, "observations", tuple(self.observations))
        if any(not isinstance(s, ProcessPeSectionRecord) for s in self.sections):
            raise TypeError("ProcessPeRecord.sections must be ProcessPeSectionRecord instances")
        for expected, section in enumerate(self.sections):
            if section.section_index != expected:
                raise ValueError("ProcessPeRecord.sections must be in section-table order")
        if len(self.sections) != self.decoded_section_count:
            raise ValueError(
                "ProcessPeRecord.decoded_section_count must be the number of decoded sections "
                "-- the header's own NumberOfSections is declared_section_count")
        if any(not isinstance(d, ProcessPeDirectoryRecord) for d in self.directories):
            raise TypeError(
                "ProcessPeRecord.directories must be ProcessPeDirectoryRecord instances")
        # All sixteen or none: a collected profile carries every
        # descriptor -- an omitted one would make "not captured"
        # indistinguishable from "not declared" -- and an uncollected one
        # has no descriptor array to report at all.
        if len(self.directories) != (16 if self.collected else 0):
            raise ValueError(
                "ProcessPeRecord.directories carries all sixteen descriptors when a profile "
                "was collected, and none when it was not")
        for expected, descriptor in enumerate(self.directories):
            if descriptor.index != expected:
                raise ValueError("ProcessPeRecord.directories must be in index order 0..15")
        if any(not isinstance(o, PeObservationRecord) for o in self.observations):
            raise TypeError("ProcessPeRecord.observations must be PeObservationRecord instances")
        if len(self.observations) != self.observation_coverage["total"]:
            raise ValueError(
                "ProcessPeRecord.observations carries every observation the correlation "
                "produced, so its length is observation_coverage['total']")
        if self.collected:
            self._check_collected()
        else:
            self._check_uncollected()
        self._check_correlated()

    # Fields that exist only because a profile was built: a record that
    # reports no profile while carrying any of them describes evidence
    # that came from nowhere, and `collected` would stop being the one
    # discriminator a consumer can branch on.
    _PROFILE_ONLY_FIELDS = (
        "source_kind", "actual_base", "preferred_image_base", "format", "machine",
        "machine_name", "time_date_stamp", "checksum", "subsystem", "dll_characteristics",
        "coff_characteristics", "size_of_image", "size_of_headers", "section_alignment",
        "file_alignment", "declared_section_count", "structural_state", "acquisition",
        "module_match",
    )

    def _check_uncollected(self) -> None:
        for field_name in self._PROFILE_ONLY_FIELDS:
            if getattr(self, field_name) is not None:
                raise ValueError(
                    f"ProcessPeRecord.{field_name} must be null when no profile was "
                    f"collected, got {getattr(self, field_name)!r}")
        if self.decoded_section_count:
            raise ValueError(
                "ProcessPeRecord.decoded_section_count must be 0 when no profile was collected")
        if self.sections or self.directories or self.observations:
            raise ValueError(
                "ProcessPeRecord carries no section, descriptor, or observation when no "
                "profile was collected")
        if self.module_identity != {"value": None, "form": None, "truncated": False}:
            raise ValueError(
                "ProcessPeRecord.module_identity names nothing when no profile was collected")
        for name, value in self.relocation.items():
            if value is not None:
                raise ValueError(
                    f"ProcessPeRecord.relocation[{name!r}] must be null when no profile was "
                    f"collected")
        for name, value in self.directory_summary.items():
            if value is not None:
                raise ValueError(
                    f"ProcessPeRecord.directory_summary[{name!r}] must be null when no "
                    f"profile was collected")
        # The tally needs no check of its own here: it sums to `total`,
        # `total` is the length of `observations`, and the array is empty
        # by the check above, so every count is already zero.
        entry_point = self.entry_point
        if entry_point.va_overflow or any(
                getattr(entry_point, name) is not None
                for name in ("rva", "va", "section_index", "section_name", "capture_state",
                              "region_state", "region_type", "region_protection")):
            raise ValueError(
                "ProcessPeRecord.entry_point establishes nothing when no profile was collected")

    def _check_correlated(self) -> None:
        """A correlation that ran produces observations -- the frozen
        checks, the identity triple, and one per descriptor at least -- so
        an empty `observations` array with `correlated` true would claim a
        correlation that established nothing, and a populated one with
        `correlated` false would carry evidence nothing produced."""
        if self.correlated and not self.observations:
            raise ValueError(
                "ProcessPeRecord.correlated says a correlation ran, so it carries the "
                "observations that correlation produced")
        if not self.correlated:
            if self.observations:
                raise ValueError(
                    "ProcessPeRecord carries no observation when no correlation was produced")
            # The tally follows the empty array through the same two
            # invariants it does in `_check_uncollected`, so it is already
            # all zeros here.
            # Every per-section and per-entry-point fact below is the
            # correlation's, not the profile's: reporting one without it
            # would present a resolution nothing performed.
            for section in self.sections:
                if (section.mapped_base_address is not None or section.capture_state is not None
                        or section.live_protections):
                    raise ValueError(
                        "ProcessPeRecord.sections carry no mapped range, capture state, or "
                        "live protection when no correlation was produced")
            entry_point = self.entry_point
            if entry_point.va is not None or entry_point.section_index is not None or any(
                    getattr(entry_point, name) is not None
                    for name in ("capture_state", "region_state", "region_type",
                                  "region_protection")):
                raise ValueError(
                    "ProcessPeRecord.entry_point resolves nothing into the process when no "
                    "correlation was produced")
            # A descriptor's own decoded fields are the profile's; which
            # section holds it and how much of it the dump captured are
            # resolutions the correlation performs.
            for descriptor in self.directories:
                if (descriptor.containing_section_index is not None
                        or descriptor.capture_state is not None):
                    raise ValueError(
                        "ProcessPeRecord.directories carry no containing section and no "
                        "capture state when no correlation was produced")

    def _check_collected(self) -> None:
        # The converse: a profile that was built has a source, a base it
        # was read at, a state, the acquisition that produced it, and an
        # answer about the loader's own record. A null in any of them is a
        # profile that does not exist reported as one that does.
        for field_name in ("source_kind", "actual_base", "structural_state", "acquisition",
                            "module_match"):
            if getattr(self, field_name) is None:
                raise ValueError(
                    f"ProcessPeRecord.{field_name} must be set when a profile was collected")
        # The BASERELOC descriptor is one of the sixteen a collected
        # profile always carries, so how much of it was read is always an
        # answer -- `unavailable` when nothing of it arrived, never a
        # null. The other four relocation facts stay nullable: each is a
        # field that may not have been decoded.
        if self.relocation["basereloc_descriptor_state"] is None:
            raise ValueError(
                "ProcessPeRecord.relocation['basereloc_descriptor_state'] must be set when a "
                "profile was collected -- every descriptor has a state, including one nothing "
                "was read of")

    @classmethod
    def uncollected(cls, reason: str) -> "ProcessPeRecord":
        """The `pe_image` object of a run that built no profile: every
        fact null, every array empty, and the absence stated once in
        `unavailable_reason`. The object itself is never omitted -- a
        consumer must be able to tell "this producer built no profile"
        from "this key is missing because the producer is older"."""
        return cls(
            collected=False, correlated=False, unavailable_reason=reason, source_kind=None,
            module_identity={"value": None, "form": None, "truncated": False},
            actual_base=None, preferred_image_base=None, format=None, machine=None,
            machine_name=None, time_date_stamp=None, checksum=None, subsystem=None,
            dll_characteristics=None, coff_characteristics=None, size_of_image=None,
            size_of_headers=None, section_alignment=None, file_alignment=None,
            declared_section_count=None, decoded_section_count=0, structural_state=None,
            relocation={"delta": None, "relocs_stripped": None, "dynamic_base": None,
                         "basereloc_present": None, "basereloc_descriptor_state": None},
            entry_point=ProcessPeEntryPointRecord(
                rva=None, va=None, va_overflow=False, section_index=None, section_name=None,
                capture_state=None, region_state=None, region_type=None,
                region_protection=None),
            acquisition=None,
            directory_summary={"declared_count": None, "declared_count_raw": None,
                                "readable_count": None, "unprojected_count": None},
            module_match=None,
            observation_coverage={"total": 0, "consistent": 0, "conflict": 0,
                                   "unavailable": 0, "not_applicable": 0})

    def _check_relocation(self) -> None:
        if not isinstance(self.relocation, dict):
            raise TypeError("ProcessPeRecord.relocation must be a dict")
        expected = ("delta", "relocs_stripped", "dynamic_base", "basereloc_present",
                     "basereloc_descriptor_state")
        if tuple(self.relocation) != expected:
            raise ValueError(
                f"ProcessPeRecord.relocation must carry exactly {expected} in that order")
        delta = self.relocation["delta"]
        # The delta is signed: an image loaded below its preferred base
        # has moved down, and clamping that at zero would report a
        # relocation that did not happen.
        if delta is not None and (not isinstance(delta, int) or isinstance(delta, bool)):
            raise ValueError("ProcessPeRecord.relocation['delta'] must be None or an int")
        for key in ("relocs_stripped", "dynamic_base", "basereloc_present"):
            value = self.relocation[key]
            if value is not None:
                _require_bool(value, f"ProcessPeRecord.relocation[{key!r}]")
        _require_optional_enum(self.relocation["basereloc_descriptor_state"],
                                PROCESS_PE_COMPONENT_STATES,
                                "ProcessPeRecord.relocation['basereloc_descriptor_state']")

    def _check_directory_summary(self) -> None:
        if not isinstance(self.directory_summary, dict):
            raise TypeError("ProcessPeRecord.directory_summary must be a dict")
        expected = ("declared_count", "declared_count_raw", "readable_count",
                     "unprojected_count")
        if tuple(self.directory_summary) != expected:
            raise ValueError(
                f"ProcessPeRecord.directory_summary must carry exactly {expected} in that order")
        for key, value in self.directory_summary.items():
            _require_optional_nonneg_int(value, f"ProcessPeRecord.directory_summary[{key!r}]")

    def _check_observation_coverage(self) -> None:
        if not isinstance(self.observation_coverage, dict):
            raise TypeError("ProcessPeRecord.observation_coverage must be a dict")
        expected = ("total", "consistent", "conflict", "unavailable", "not_applicable")
        if tuple(self.observation_coverage) != expected:
            raise ValueError(
                f"ProcessPeRecord.observation_coverage must carry exactly {expected} in that "
                f"order")
        for key, value in self.observation_coverage.items():
            _require_nonneg_int(value, f"ProcessPeRecord.observation_coverage[{key!r}]")
        tally = self.observation_coverage
        if sum(tally[state] for state in PE_OBSERVATION_STATES) != tally["total"]:
            raise ValueError(
                "ProcessPeRecord.observation_coverage's four states must sum to its total")

    def to_dict(self) -> dict:
        return {
            "collected":               self.collected,
            "correlated":              self.correlated,
            "unavailable_reason":      self.unavailable_reason,
            "source_kind":             self.source_kind,
            "module_identity":         dict(self.module_identity),
            "actual_base":             self.actual_base,
            "preferred_image_base":    self.preferred_image_base,
            "format":                  self.format,
            "machine":                 self.machine,
            "machine_name":            self.machine_name,
            "time_date_stamp":         self.time_date_stamp,
            "checksum":                self.checksum,
            "subsystem":               self.subsystem,
            "dll_characteristics":     self.dll_characteristics,
            "coff_characteristics":    self.coff_characteristics,
            "size_of_image":           self.size_of_image,
            "size_of_headers":         self.size_of_headers,
            "section_alignment":       self.section_alignment,
            "file_alignment":          self.file_alignment,
            "declared_section_count":  self.declared_section_count,
            "decoded_section_count":   self.decoded_section_count,
            "structural_state":        self.structural_state,
            "relocation":              dict(self.relocation),
            "entry_point":             self.entry_point.to_dict(),
            "acquisition":             (self.acquisition.to_dict()
                                         if self.acquisition is not None else None),
            "directory_summary":       dict(self.directory_summary),
            "module_match":            self.module_match,
            "observation_coverage":    dict(self.observation_coverage),
            "sections":                [s.to_dict() for s in self.sections],
            "directories":             [d.to_dict() for d in self.directories],
            "observations":            [o.to_dict() for o in self.observations],
        }
