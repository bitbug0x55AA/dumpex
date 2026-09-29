"""`--report` PE context: the process-wide main-image ReportPeContext and
the per-card ReportAnchorPeContext.

Phase 2 of the report enrichment contract is one process-wide
ReportPeContext for the invocation (the main image's identity and the
correlation layer's conflicts), plus per-card anchor-PE, instruction, and
IAT projections (this module, report_instruction and report_iat).
Everything there is captured evidence and navigation context: none of it
reaches findings, verdict, coverage status, or the exit code, and every
section carries its own missing/partial/complete state like the Phase 1
sections (report_process, report_context).
"""
from dataclasses import dataclass

from dumpex.output.records.base import _MODULE_CONTEXTS
from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)
from dumpex.output.records.pe_observation import PeObservationRecord
from dumpex.output.records.report_common import (
    ENRICHMENT_SCOPE_CARD,
    ENRICHMENT_SCOPE_PROCESS,
    EnrichmentSection,
    _require_enrichment_section,
    _require_optional_bounded_text,
)


# Shares the process-identity snapshot's own vocabulary for one concept:
# `resolved` -- the image base is inside a captured module.
PE_MODULE_MATCH_STATES = _MODULE_CONTEXTS


@dataclass(frozen=True)
class ReportPeContext:
    """The one process-wide PE projection of a `--report` run: the main
    image's identity, and the correlation layer's tally and conflicts.

    The identity fields are the canonical
    :class:`dumpex.core.pe_profile.PeImageProfile`'s own decoded values.
    ``consistent_count`` / ``conflict_count`` / ``unavailable_count`` /
    ``not_applicable_count`` tally every observation the correlation
    produced, one count per state; ``observations`` carries only the
    retained conflicts, so ``section.total`` is the conflict count and
    ``section.included`` is how many survived the cap."""
    section:              EnrichmentSection
    image_base:           "str | None"
    preferred_image_base: "str | None"
    machine:              "int | None"
    machine_name:         "str | None"
    time_date_stamp:      "int | None"
    size_of_image:        "int | None"
    entry_point_rva:      "int | None"
    entry_point_va:       "str | None"
    section_count:        "int | None"
    pe32_plus:            "bool | None"
    module_match:         "str | None"
    consistent_count:     int
    conflict_count:       int
    unavailable_count:    int
    not_applicable_count: int
    observations:         tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportPeContext.section",
                                    scope=ENRICHMENT_SCOPE_PROCESS, name="pe_context")
        _require_optional_hex_address(self.image_base, "ReportPeContext.image_base")
        _require_optional_hex_address(self.preferred_image_base,
                                     "ReportPeContext.preferred_image_base")
        _require_optional_diff_int(self.machine, "ReportPeContext.machine")
        _require_optional_diff_str(self.machine_name, "ReportPeContext.machine_name")
        _require_optional_bounded_text(self.machine_name, "ReportPeContext.machine_name")
        _require_optional_diff_int(self.time_date_stamp, "ReportPeContext.time_date_stamp")
        _require_optional_nonneg_int(self.size_of_image, "ReportPeContext.size_of_image")
        _require_optional_nonneg_int(self.entry_point_rva, "ReportPeContext.entry_point_rva")
        _require_optional_hex_address(self.entry_point_va, "ReportPeContext.entry_point_va")
        _require_optional_nonneg_int(self.section_count, "ReportPeContext.section_count")
        if self.pe32_plus is not None:
            _require_bool(self.pe32_plus, "ReportPeContext.pe32_plus")
        if self.module_match is not None and self.module_match not in PE_MODULE_MATCH_STATES:
            raise ValueError(
                f"ReportPeContext.module_match must be None or one of "
                f"{PE_MODULE_MATCH_STATES}, got {self.module_match!r}")
        for field_name in ("consistent_count", "conflict_count", "unavailable_count",
                            "not_applicable_count"):
            _require_nonneg_int(getattr(self, field_name), f"ReportPeContext.{field_name}")
        object.__setattr__(self, "observations", tuple(self.observations))
        if any(not isinstance(o, PeObservationRecord) for o in self.observations):
            raise TypeError("ReportPeContext.observations must be PeObservationRecord instances")
        if len(self.observations) != self.section.included:
            raise ValueError("ReportPeContext.observations length must equal section.included")
        if any(o.state != "conflict" for o in self.observations):
            raise ValueError(
                "ReportPeContext.observations carries only the retained conflict observations")
        if self.section.total is not None and self.section.total != self.conflict_count:
            raise ValueError(
                "ReportPeContext.section.total must be the conflict_count -- the eligible "
                "population this section retains from")

    def to_dict(self) -> dict:
        return {
            "section":              self.section.to_dict(),
            "image_base":           self.image_base,
            "preferred_image_base": self.preferred_image_base,
            "machine":              self.machine,
            "machine_name":         self.machine_name,
            "time_date_stamp":      self.time_date_stamp,
            "size_of_image":        self.size_of_image,
            "entry_point_rva":      self.entry_point_rva,
            "entry_point_va":       self.entry_point_va,
            "section_count":        self.section_count,
            "pe32_plus":            self.pe32_plus,
            "module_match":         self.module_match,
            "consistent_count":     self.consistent_count,
            "conflict_count":       self.conflict_count,
            "unavailable_count":    self.unavailable_count,
            "not_applicable_count": self.not_applicable_count,
            "observations":         [o.to_dict() for o in self.observations],
        }


ANCHOR_PE_CLASSIFICATIONS = (
    "headers",        # the anchor RVA is inside SizeOfHeaders
    "code",           # inside an executable section
    "data",           # inside a non-executable section
    "import_iat",     # inside the IMPORT or IAT data directory's range
    "relocation",     # inside the BASERELOC data directory's range
    "unmapped",       # inside the image bound but no section covers the RVA
    "outside_image",  # the anchor is registered to a module but past SizeOfImage
    "module",         # inside a loaded module whose PE profile was not available to place it
    # The next five are all "no module owns this address", split by the
    # region's own CONFIRMED type -- and, for MEM_IMAGE specifically, by
    # whether registration itself was even checkable -- rather than
    # collapsed into one "private" bucket (module absence alone never
    # implies private memory) -- see
    # dumpex.commands.report_enrichment._classify_anchor's own docstring
    # for exactly which (region_type, registration) pair produces which.
    "private",                # confirmed MEM_PRIVATE
    "mapped",                 # confirmed MEM_MAPPED (e.g. a resource-only file view) --
                              # added in schema v2.20
    "unregistered_image",     # confirmed MEM_IMAGE AND confirmed unregistered (a module list
                              # was available and genuinely does not cover this address) -- a
                              # manually mapped or stomped module -- added in schema v2.20
    "image_registration_unavailable",  # confirmed MEM_IMAGE, but no module list was available
                                        # to check registration at all -- a DIFFERENT gap from
                                        # "confirmed unregistered": the region's type is known,
                                        # its registration status is not -- added in v2.20
    "region_type_unavailable",  # the region's own type is None or an unrecognized/numeric
                                # value -- a genuine gap, never asserted as "mapped" --
                                # added in schema v2.20
    "unresolved",     # no module and no region place the anchor
)

ANCHOR_PE_REGISTRATIONS = ("registered", "unregistered", "unavailable")


@dataclass(frozen=True)
class ReportAnchorPeContext:
    """This card's anchor placed against the PE image that owns it.

    ``classification`` says what kind of image location the anchor is --
    headers, code, data, import/IAT, relocation, unmapped, or, when no
    module owns it, private, mapped, unregistered_image,
    image_registration_unavailable, region_type_unavailable, or
    unresolved -- see ``ANCHOR_PE_CLASSIFICATIONS`` for why those five "no
    module owns this" states are kept distinct rather than collapsing to
    one "private" bucket.
    ``protection_matches_declared`` compares the section's own R/W/X bits
    with the live region protection; a mismatch is an observation an
    analyst follows up, never a verdict."""
    section:                     EnrichmentSection
    anchor_address:              str
    classification:              str
    registration:                str
    module_owner:                "str | None" = None
    module_owner_truncated:      bool = False
    module_base:                 "str | None" = None
    module_rva:                  "int | None" = None
    section_index:               "int | None" = None
    section_name:                "str | None" = None
    section_name_truncated:      bool = False
    declared_readable:           "bool | None" = None
    declared_writable:           "bool | None" = None
    declared_executable:         "bool | None" = None
    live_protection:             "str | None" = None
    protection_matches_declared: "bool | None" = None
    region_base:                 "str | None" = None
    region_type:                 "str | None" = None

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportAnchorPeContext.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="anchor_pe_context")
        _require_hex_address(self.anchor_address, "ReportAnchorPeContext.anchor_address")
        if self.classification not in ANCHOR_PE_CLASSIFICATIONS:
            raise ValueError(
                f"ReportAnchorPeContext.classification must be one of "
                f"{ANCHOR_PE_CLASSIFICATIONS}, got {self.classification!r}")
        if self.registration not in ANCHOR_PE_REGISTRATIONS:
            raise ValueError(
                f"ReportAnchorPeContext.registration must be one of "
                f"{ANCHOR_PE_REGISTRATIONS}, got {self.registration!r}")
        _require_optional_diff_str(self.module_owner, "ReportAnchorPeContext.module_owner")
        _require_optional_bounded_text(self.module_owner, "ReportAnchorPeContext.module_owner")
        _require_bool(self.module_owner_truncated,
                      "ReportAnchorPeContext.module_owner_truncated")
        if self.module_owner_truncated and self.module_owner is None:
            raise ValueError(
                "ReportAnchorPeContext.module_owner_truncated requires a module_owner")
        _require_optional_hex_address(self.module_base, "ReportAnchorPeContext.module_base")
        _require_optional_nonneg_int(self.module_rva, "ReportAnchorPeContext.module_rva")
        _require_optional_nonneg_int(self.section_index, "ReportAnchorPeContext.section_index")
        _require_optional_diff_str(self.section_name, "ReportAnchorPeContext.section_name")
        _require_optional_bounded_text(self.section_name, "ReportAnchorPeContext.section_name")
        _require_bool(self.section_name_truncated,
                      "ReportAnchorPeContext.section_name_truncated")
        if self.section_name_truncated and self.section_name is None:
            raise ValueError(
                "ReportAnchorPeContext.section_name_truncated requires a section_name")
        for field_name in ("declared_readable", "declared_writable", "declared_executable",
                           "protection_matches_declared"):
            value = getattr(self, field_name)
            if value is not None:
                _require_bool(value, f"ReportAnchorPeContext.{field_name}")
        _require_optional_diff_str(self.live_protection, "ReportAnchorPeContext.live_protection")
        _require_optional_diff_str(self.region_type, "ReportAnchorPeContext.region_type")
        _require_optional_hex_address(self.region_base, "ReportAnchorPeContext.region_base")

    def to_dict(self) -> dict:
        return {
            "section":                     self.section.to_dict(),
            "anchor_address":              self.anchor_address,
            "classification":              self.classification,
            "registration":                self.registration,
            "module_owner":                self.module_owner,
            "module_owner_truncated":      self.module_owner_truncated,
            "module_base":                 self.module_base,
            "module_rva":                  self.module_rva,
            "section_index":               self.section_index,
            "section_name":                self.section_name,
            "section_name_truncated":      self.section_name_truncated,
            "declared_readable":           self.declared_readable,
            "declared_writable":           self.declared_writable,
            "declared_executable":         self.declared_executable,
            "live_protection":             self.live_protection,
            "protection_matches_declared": self.protection_matches_declared,
            "region_base":                 self.region_base,
            "region_type":                 self.region_type,
        }
