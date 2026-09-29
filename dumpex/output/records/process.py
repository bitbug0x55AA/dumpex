"""`--process` records: IAT entries, diagnostics, the IAT and the process
record that composes them with the main-image PE profile.

See docs/developer/recon_process_sysinfo_handles_contract.md §3.1/§3.4/§3.5
for the frozen JSON shape. identity_evidence's misc_info_claim/peb_claim/
module_claim/main_image_pe sub-objects are built as plain dicts by
dumpex.commands.process: a direct, fixed translation of
dumpex.core.process_info's own frozen claim dataclasses (already validated
at THAT boundary) into the wire's null/hex-address/UTC-string conventions,
with no independent invariants of their own to enforce a second time.
identity_evidence's own `diagnostics` entries, and every `iat.diagnostics`
entry, are NOT plain dicts -- both go through ProcessDiagnosticRecord
(constructed, then .to_dict()'d) so a malformed diagnostic (an unknown
severity, a non-positive affected_count, ...) is rejected at construction
time regardless of which of the two arrays it ends up in, rather than only
the IAT side being checked.
"""
import copy
from dataclasses import dataclass, field

from dumpex.output.records.common import (
    _require_nonneg_int,
    _require_optional_diff_int,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)
from dumpex.output.records.process_pe import ProcessPeRecord


_IMPORT_BY_VALUES = ("name", "ordinal", "unavailable")
_PROCESS_DIAGNOSTIC_SEVERITIES = ("info", "warning")


@dataclass(frozen=True)
class ImportEntryRecord:
    """One IAT thunk slot -- §3.5.3."""
    dll:                 "str | None"
    import_by:            str
    symbol:               "str | None"
    ordinal:              "int | None"
    iat_slot_va:          "str | None"
    resolved_target_va:   "str | None"
    slot_in_bounds:       "bool | None"

    def __post_init__(self):
        if self.dll is not None and not isinstance(self.dll, str):
            raise ValueError("ImportEntryRecord.dll must be None or a string")
        if self.import_by not in _IMPORT_BY_VALUES:
            raise ValueError(
                f"ImportEntryRecord.import_by must be one of {_IMPORT_BY_VALUES}, "
                f"got {self.import_by!r}")
        if self.symbol is not None and not isinstance(self.symbol, str):
            raise ValueError("ImportEntryRecord.symbol must be None or a string")
        if self.import_by != "name" and self.symbol is not None:
            raise ValueError("ImportEntryRecord.symbol must be None unless import_by == 'name'")
        _require_optional_diff_int(self.ordinal, "ImportEntryRecord.ordinal")
        if self.import_by != "ordinal" and self.ordinal is not None:
            raise ValueError("ImportEntryRecord.ordinal must be None unless import_by == 'ordinal'")
        if self.import_by == "ordinal" and self.ordinal is None:
            # Unlike `symbol` (a separate, fallible bounded read that can
            # genuinely come back empty for a captured entry -- §3.5.3's
            # "captured targets are preserved" rule), `ordinal` is decoded
            # directly from the thunk value already in hand (the low 16
            # bits under IMAGE_ORDINAL_FLAG32/64) -- there is no "ordinal
            # read failed" case an import_by == "ordinal" entry can
            # legitimately report null for.
            raise ValueError("ImportEntryRecord.ordinal must be set when import_by == 'ordinal'")
        _require_optional_hex_address(self.iat_slot_va, "ImportEntryRecord.iat_slot_va")
        _require_optional_hex_address(self.resolved_target_va, "ImportEntryRecord.resolved_target_va")
        if self.slot_in_bounds is not None and not isinstance(self.slot_in_bounds, bool):
            raise ValueError("ImportEntryRecord.slot_in_bounds must be None or a bool")

    def to_dict(self) -> dict:
        return {
            "dll":                 self.dll,
            "import_by":           self.import_by,
            "symbol":              self.symbol,
            "ordinal":             self.ordinal,
            "iat_slot_va":         self.iat_slot_va,
            "resolved_target_va":  self.resolved_target_va,
            "slot_in_bounds":      self.slot_in_bounds,
        }


# The closed, frozen seven-code registry from
# docs/developer/recon_process_sysinfo_handles_contract.md §6.2 -- code -> the exact
# `details` key set that code carries. Mirrors dumpex-output-v2.13.
# schema.json's own processDiagnosticRecord allOf (code -> per-code
# closed `details` shape) so the two can never drift silently: a code or
# a details key set that the schema would reject is now also rejected
# here, at construction time, not only by an external validator run
# against the eventual --json output. This is the single place every
# diagnostic reaches on its way to to_dict() -- core/process_info.py's
# ProcessDiagnostic and core/pe_utils.py's IatDiagnostic are deliberately
# separate, uncoupled types (see IatDiagnostic's own docstring on why),
# both translated into this type by dumpex/commands/process.py before
# anything is serialized, so enforcing the contract here covers both
# origins with one check.
_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA = {
    "PROCESS_MODULE_BASE_UNMATCHED":     frozenset({"peb_base"}),
    "PROCESS_MODULE_BASE_CONFLICT":      frozenset({"name", "module_base", "peb_base"}),
    "PROCESS_MODULE_NAME_AMBIGUOUS":     frozenset({"name", "count"}),
    "PROCESS_MODULE_IDENTITY_MISMATCH":  frozenset({"peb_name", "module_name"}),
    "PROCESS_PATH_SOURCE_FALLBACK":      frozenset({"module_path"}),
    "IAT_BOUNDS_CHECK_UNAVAILABLE":      frozenset({"import_directory_va"}),
    "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS":  frozenset({"table_va", "table_size",
                                                      "first_out_of_bounds_slot_va"}),
}


@dataclass(frozen=True)
class ProcessDiagnosticRecord:
    """One `identity_evidence.diagnostics`/`iat.diagnostics` entry --
    §3.4.4/§6.2. Never carries verdict semantics: `severity` is `"info"`
    or `"warning"` only, and `code`/`details` are both closed to the
    frozen seven-entry registry in `_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA` --
    a code outside that registry (e.g. a fabricated "PEB_TRUSTED") or a
    `details` key set that doesn't exactly match the registered code's own
    keys cannot be constructed at all."""
    code:            str
    severity:        str
    message:         str
    affected_count:  "int | None" = None
    details:         dict = field(default_factory=dict)

    def __post_init__(self):
        if self.code not in _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA:
            raise ValueError(
                f"ProcessDiagnosticRecord.code must be one of "
                f"{sorted(_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA)}, got {self.code!r}")
        if self.severity not in _PROCESS_DIAGNOSTIC_SEVERITIES:
            raise ValueError(
                f"ProcessDiagnosticRecord.severity must be one of "
                f"{_PROCESS_DIAGNOSTIC_SEVERITIES}, got {self.severity!r}")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("ProcessDiagnosticRecord.message must be a non-empty string")
        if self.affected_count is not None and (
                not isinstance(self.affected_count, int) or isinstance(self.affected_count, bool)
                or self.affected_count <= 0):
            raise ValueError(
                "ProcessDiagnosticRecord.affected_count must be None or a positive int, "
                f"got {self.affected_count!r}")
        if not isinstance(self.details, dict):
            raise ValueError("ProcessDiagnosticRecord.details must be a dict")
        expected_keys = _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA[self.code]
        if set(self.details) != expected_keys:
            raise ValueError(
                f"ProcessDiagnosticRecord.details for code {self.code!r} must have exactly "
                f"the keys {sorted(expected_keys)}, got {sorted(self.details)}")

    def to_dict(self) -> dict:
        return {
            "code":            self.code,
            "severity":        self.severity,
            "message":         self.message,
            "affected_count":  self.affected_count,
            "details":         dict(self.details),
        }


@dataclass(frozen=True)
class IatRecord:
    """`--process`'s `iat` object -- §3.5. Always present as an object,
    never null. `table_present`/`import_directory_present` are each
    `true | false | null` (§3.5.2's three-state presence, never a bare
    bool) -- see docs/developer/recon_process_sysinfo_handles_contract.md for what
    each state means; this record only enforces shape, not that policy."""
    table_present:              "bool | None"
    table_va:                   "str | None"
    table_size:                 "int | None"
    import_directory_present:   "bool | None"
    import_directory_va:        "str | None"
    import_directory_size:      "int | None"
    has_entries:                bool
    dll_count:                  int
    entry_count:                int
    entries:                    tuple   # tuple[ImportEntryRecord], walk order
    diagnostics:                tuple   # tuple[ProcessDiagnosticRecord], §6.2 order

    def __post_init__(self):
        if self.table_present is not None and not isinstance(self.table_present, bool):
            raise ValueError("IatRecord.table_present must be None or a bool")
        _require_optional_hex_address(self.table_va, "IatRecord.table_va")
        _require_optional_nonneg_int(self.table_size, "IatRecord.table_size")
        # §3.5.2: table_present is not True (false or undetermined/null)
        # means there is no range to report at all, so table_va/
        # table_size must both be None in that case -- an address paired
        # with a false/null presence flag would be a self-contradictory
        # record no renderer/consumer could act on correctly. The
        # REVERSE is deliberately NOT required: dumpex.core.pe_utils.
        # parse_iat() can legitimately report table_present=True with
        # table_va/table_size BOTH still None when the range's own
        # address arithmetic overflows a real 64-bit address
        # (bounds_exceeded) -- "the image declares this directory" and
        # "its range is a usable address" are different facts, and the
        # former can be true while the latter isn't. table_va/table_size
        # are always set or unset TOGETHER either way (parse_iat() never
        # produces one without the other), so that pairing is still safe
        # to require.
        if self.table_present is not True and (self.table_va is not None or self.table_size is not None):
            raise ValueError(
                "IatRecord.table_va and table_size must both be None when table_present "
                f"is not True, got table_present={self.table_present!r} "
                f"table_va={self.table_va!r} table_size={self.table_size!r}")
        if (self.table_va is None) != (self.table_size is None):
            raise ValueError(
                "IatRecord.table_va and table_size must both be None or both set together, "
                f"got table_va={self.table_va!r} table_size={self.table_size!r}")

        if self.import_directory_present is not None and not isinstance(
                self.import_directory_present, bool):
            raise ValueError("IatRecord.import_directory_present must be None or a bool")
        _require_optional_hex_address(self.import_directory_va, "IatRecord.import_directory_va")
        _require_optional_nonneg_int(self.import_directory_size, "IatRecord.import_directory_size")
        # Same "not True -> both None" direction as table_present above.
        # Unlike table_va/table_size, import_directory_va and
        # import_directory_size are NOT required to be paired:
        # parse_iat() records the declared Size unconditionally once
        # import_directory_present is true, independent of whether the
        # RVA's own address arithmetic overflowed -- so
        # import_directory_size can legitimately be set while
        # import_directory_va is None (the same overflow case as above,
        # applied to the Import Directory instead of the IAT Directory).
        if self.import_directory_present is not True and (
                self.import_directory_va is not None or self.import_directory_size is not None):
            raise ValueError(
                "IatRecord.import_directory_va and import_directory_size must both be None "
                f"when import_directory_present is not True, got "
                f"import_directory_present={self.import_directory_present!r} "
                f"import_directory_va={self.import_directory_va!r} "
                f"import_directory_size={self.import_directory_size!r}")

        if not isinstance(self.has_entries, bool):
            raise ValueError("IatRecord.has_entries must be a bool")
        _require_nonneg_int(self.dll_count, "IatRecord.dll_count")
        _require_nonneg_int(self.entry_count, "IatRecord.entry_count")
        if not isinstance(self.entries, tuple) or any(
                type(e) is not ImportEntryRecord for e in self.entries):
            raise TypeError("IatRecord.entries must be a tuple of ImportEntryRecord instances")
        if not isinstance(self.diagnostics, tuple) or any(
                type(d) is not ProcessDiagnosticRecord for d in self.diagnostics):
            raise TypeError("IatRecord.diagnostics must be a tuple of ProcessDiagnosticRecord instances")
        if self.has_entries != (self.entry_count > 0):
            raise ValueError(
                f"IatRecord.has_entries ({self.has_entries}) must equal entry_count > 0 "
                f"({self.entry_count})")
        if len(self.entries) != self.entry_count:
            raise ValueError(
                f"IatRecord.entries has {len(self.entries)} item(s) but entry_count is "
                f"{self.entry_count}")

    def to_dict(self) -> dict:
        return {
            "table_present":              self.table_present,
            "table_va":                   self.table_va,
            "table_size":                 self.table_size,
            "import_directory_present":   self.import_directory_present,
            "import_directory_va":        self.import_directory_va,
            "import_directory_size":      self.import_directory_size,
            "has_entries":                self.has_entries,
            "dll_count":                  self.dll_count,
            "entry_count":                self.entry_count,
            "entries":                    [e.to_dict() for e in self.entries],
            "diagnostics":                [d.to_dict() for d in self.diagnostics],
        }


@dataclass
class ProcessRecord:
    """`--process`'s record -- §3.1. Exactly one per result, always
    emitted even when every scalar field is null. `identity_evidence` is a
    plain dict (§3.4's nested claim shape, built by
    dumpex.commands.process from dumpex.core.process_info.
    ProcessIdentitySnapshot); `peb_extended` is a plain dict present only
    under `--verbose` (§3.6) -- its KEY's presence depends only on the
    flag, never on the data, so this stays a bare None-vs-dict field
    rather than an always-present dict with its own null members.

    `pe_image` (§3.10) is the canonical main-image PE profile and its
    correlation, always present as an object and carrying the complete
    collected record regardless of `--verbose`: verbosity changes console
    presentation, never evidence collection."""
    process_name:        "str | None"
    pid:                  "int | None"
    process_path:         "str | None"
    command_line:         "str | None"
    process_start_utc:    "str | None"
    image_base_address:   "str | None"
    iat:                  IatRecord
    identity_evidence:    dict
    pe_image:             ProcessPeRecord
    peb_extended:         "dict | None" = None

    def __post_init__(self):
        if self.process_name is not None and not isinstance(self.process_name, str):
            raise ValueError("ProcessRecord.process_name must be None or a string")
        _require_optional_diff_int(self.pid, "ProcessRecord.pid")
        if self.process_path is not None and not isinstance(self.process_path, str):
            raise ValueError("ProcessRecord.process_path must be None or a string")
        if self.command_line is not None and not isinstance(self.command_line, str):
            raise ValueError("ProcessRecord.command_line must be None or a string")
        if self.process_start_utc is not None and not isinstance(self.process_start_utc, str):
            raise ValueError("ProcessRecord.process_start_utc must be None or a string")
        _require_optional_hex_address(self.image_base_address, "ProcessRecord.image_base_address")
        if not isinstance(self.iat, IatRecord):
            raise TypeError("ProcessRecord.iat must be an IatRecord")
        if not isinstance(self.identity_evidence, dict):
            raise TypeError("ProcessRecord.identity_evidence must be a dict")
        if not isinstance(self.pe_image, ProcessPeRecord):
            raise TypeError("ProcessRecord.pe_image must be a ProcessPeRecord")
        if self.peb_extended is not None and not isinstance(self.peb_extended, dict):
            raise TypeError("ProcessRecord.peb_extended must be None or a dict")

    def to_dict(self) -> dict:
        out = {
            "process_name":        self.process_name,
            "pid":                 self.pid,
            "process_path":        self.process_path,
            "command_line":        self.command_line,
            "process_start_utc":   self.process_start_utc,
            "image_base_address":  self.image_base_address,
            "iat":                 self.iat.to_dict(),
            # deepcopy, not dict(...): identity_evidence nests dicts/lists
            # of its own (misc_info_claim, peb_claim, module_claim,
            # diagnostics, ...) -- a shallow copy would still hand a
            # caller a live reference into THOSE, letting a mutation of
            # the returned to_dict() silently corrupt this record's own
            # internal state.
            "identity_evidence":   copy.deepcopy(self.identity_evidence),
            "pe_image":            self.pe_image.to_dict(),
        }
        if self.peb_extended is not None:
            out["peb_extended"] = copy.deepcopy(self.peb_extended)
        return out
