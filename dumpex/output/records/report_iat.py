"""`--report` IAT correlation: the IAT slots retained for one card. Part
of report enrichment Phase 2 (see dumpex.output.records.report_pe).
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    _require_bool,
    _require_optional_diff_str,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)
from dumpex.output.records.report_common import (
    ENRICHMENT_SCOPE_CARD,
    EnrichmentSection,
    _require_enrichment_section,
    _require_optional_bounded_text,
)
from dumpex.output.records.report_pe import ANCHOR_PE_REGISTRATIONS


IAT_IMPORT_BY = ("name", "ordinal", "unavailable")

IAT_ENTRY_SELECTION_REASONS = (
    "instruction_correlated",     # a branch in this card's instruction window targets the slot
    "target_unregistered",        # the live thunk target is in no registered module
    "target_private_executable",  # the live thunk target is in private executable memory
    "slot_out_of_bounds",         # the slot is outside the declared IAT directory range
)


@dataclass(frozen=True)
class ReportIatCorrelatedEntry:
    """One IAT slot retained for this card: instruction-correlated, or
    with a live thunk target unusual enough to be an investigation lead.

    ``iat_slot_va`` is the slot's own address; ``resolved_target_va`` is
    the pointer currently in it. The ``target_*`` fields describe wherever
    that pointer lands. A private, unregistered, or redirected target is a
    lead, never a verdict dimension."""
    import_by:                     str
    selection_reason:              str
    dll:                           "str | None" = None
    dll_truncated:                 bool = False
    symbol:                        "str | None" = None
    symbol_truncated:              bool = False
    ordinal:                       "int | None" = None
    iat_slot_va:                   "str | None" = None
    resolved_target_va:            "str | None" = None
    target_module_owner:           "str | None" = None
    target_module_owner_truncated: bool = False
    target_section_name:           "str | None" = None
    target_section_name_truncated: bool = False
    target_region_type:            "str | None" = None
    target_registration:           "str | None" = None
    also_selected_for:             tuple = ()

    def __post_init__(self):
        if self.import_by not in IAT_IMPORT_BY:
            raise ValueError(
                f"ReportIatCorrelatedEntry.import_by must be one of {IAT_IMPORT_BY}, "
                f"got {self.import_by!r}")
        if self.selection_reason not in IAT_ENTRY_SELECTION_REASONS:
            raise ValueError(
                f"ReportIatCorrelatedEntry.selection_reason must be one of "
                f"{IAT_ENTRY_SELECTION_REASONS}, got {self.selection_reason!r}")
        for name in ("dll", "symbol", "target_module_owner", "target_section_name"):
            _require_optional_diff_str(getattr(self, name),
                                       f"ReportIatCorrelatedEntry.{name}")
            _require_optional_bounded_text(getattr(self, name),
                                           f"ReportIatCorrelatedEntry.{name}")
        for value_field, flag_field in (
                ("dll", "dll_truncated"), ("symbol", "symbol_truncated"),
                ("target_module_owner", "target_module_owner_truncated"),
                ("target_section_name", "target_section_name_truncated")):
            _require_bool(getattr(self, flag_field),
                          f"ReportIatCorrelatedEntry.{flag_field}")
            if getattr(self, flag_field) and getattr(self, value_field) is None:
                raise ValueError(
                    f"ReportIatCorrelatedEntry.{flag_field} requires a {value_field}")
        _require_optional_nonneg_int(self.ordinal, "ReportIatCorrelatedEntry.ordinal")
        _require_optional_hex_address(self.iat_slot_va,
                                     "ReportIatCorrelatedEntry.iat_slot_va")
        _require_optional_hex_address(self.resolved_target_va,
                                     "ReportIatCorrelatedEntry.resolved_target_va")
        _require_optional_diff_str(self.target_region_type,
                                   "ReportIatCorrelatedEntry.target_region_type")
        if (self.target_registration is not None
                and self.target_registration not in ANCHOR_PE_REGISTRATIONS):
            raise ValueError(
                f"ReportIatCorrelatedEntry.target_registration must be None or one of "
                f"{ANCHOR_PE_REGISTRATIONS}, got {self.target_registration!r}")
        object.__setattr__(self, "also_selected_for", tuple(self.also_selected_for))
        for reason in self.also_selected_for:
            if reason not in IAT_ENTRY_SELECTION_REASONS or reason == self.selection_reason:
                raise ValueError(
                    "ReportIatCorrelatedEntry.also_selected_for must be distinct additional "
                    f"reasons from {IAT_ENTRY_SELECTION_REASONS}")

    def to_dict(self) -> dict:
        return {
            "import_by":                     self.import_by,
            "selection_reason":              self.selection_reason,
            "dll":                           self.dll,
            "dll_truncated":                 self.dll_truncated,
            "symbol":                        self.symbol,
            "symbol_truncated":              self.symbol_truncated,
            "ordinal":                       self.ordinal,
            "iat_slot_va":                   self.iat_slot_va,
            "resolved_target_va":            self.resolved_target_va,
            "target_module_owner":           self.target_module_owner,
            "target_module_owner_truncated": self.target_module_owner_truncated,
            "target_section_name":           self.target_section_name,
            "target_section_name_truncated": self.target_section_name_truncated,
            "target_region_type":            self.target_region_type,
            "target_registration":           self.target_registration,
            "also_selected_for":             list(self.also_selected_for),
        }


@dataclass(frozen=True)
class ReportIatCorrelation:
    """This card's bounded view of the anchor module's import address
    table.

    ``module_owner`` is the module the anchor resolved to -- the one whose
    IAT this projects. ``dll_count`` / ``entry_count`` summarise what the
    canonical IAT parser found; ``entries`` carries only the retained
    unusual or instruction-correlated slots. An anchor in no module, or a
    module with no import directory, leaves this `missing`."""
    section:                  EnrichmentSection
    module_owner:             "str | None"
    module_owner_truncated:   bool
    module_base:              "str | None"
    dll_count:                "int | None"
    entry_count:              "int | None"
    import_directory_present: "bool | None"
    iat_directory_present:    "bool | None"
    entries:                  tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportIatCorrelation.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="iat_correlation")
        _require_optional_diff_str(self.module_owner, "ReportIatCorrelation.module_owner")
        _require_optional_bounded_text(self.module_owner, "ReportIatCorrelation.module_owner")
        _require_bool(self.module_owner_truncated,
                      "ReportIatCorrelation.module_owner_truncated")
        if self.module_owner_truncated and self.module_owner is None:
            raise ValueError(
                "ReportIatCorrelation.module_owner_truncated requires a module_owner")
        _require_optional_hex_address(self.module_base, "ReportIatCorrelation.module_base")
        _require_optional_nonneg_int(self.dll_count, "ReportIatCorrelation.dll_count")
        _require_optional_nonneg_int(self.entry_count, "ReportIatCorrelation.entry_count")
        for field_name in ("import_directory_present", "iat_directory_present"):
            value = getattr(self, field_name)
            if value is not None:
                _require_bool(value, f"ReportIatCorrelation.{field_name}")
        object.__setattr__(self, "entries", tuple(self.entries))
        if any(not isinstance(e, ReportIatCorrelatedEntry) for e in self.entries):
            raise TypeError(
                "ReportIatCorrelation.entries must be ReportIatCorrelatedEntry instances")
        if len(self.entries) != self.section.included:
            raise ValueError("ReportIatCorrelation.entries length must equal section.included")
        slots = [e.iat_slot_va for e in self.entries if e.iat_slot_va is not None]
        if len(set(slots)) != len(slots):
            raise ValueError("ReportIatCorrelation.entries must be deduplicated by IAT slot")

    def to_dict(self) -> dict:
        return {
            "section":                  self.section.to_dict(),
            "module_owner":             self.module_owner,
            "module_owner_truncated":   self.module_owner_truncated,
            "module_base":              self.module_base,
            "dll_count":                self.dll_count,
            "entry_count":              self.entry_count,
            "import_directory_present": self.import_directory_present,
            "iat_directory_present":    self.iat_directory_present,
            "entries":                  [e.to_dict() for e in self.entries],
        }
