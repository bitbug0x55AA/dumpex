"""`--diff` comparison records.

Tagged-union members for result.data.records (kind="comparison").
`entity_type` is the discriminator. Each `change_type` carries only the
before/after values that exist for that side of the comparison.

Every `change_type` is an inventory relation between two captures, not an
observed event: `added` is present only in the target, `removed` only in
the baseline, `rebased` the same module name at a different base, and
`protection_changed` the same region base with a different protection.
"Before" is the baseline and "after" the target, whatever their capture
order. ComparisonPremiseRecord (result.summary.premise) states what the two
captures are known to share.

The field-shape validators all three apply (dumpex.output.records.common)
each mirror a constraint the v2.1 schema's own moduleDiffRecord/
threadDiffRecord/memoryDiffRecord $defs already enforce on the wire --
closing the gap where the Python model could construct (and freely
.to_dict()) a shape its own schema rejects.
"""
import re
from dataclasses import dataclass, field

from dumpex.output.records.base import MODULE_CONTEXT_RESOLVED, _MODULE_CONTEXTS
from dumpex.output.records.common import (
    _HEX_ADDRESS_RE,
    _require_optional_diff_bool,
    _require_optional_diff_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
)


MODULE_DIFF_ADDED   = "added"
MODULE_DIFF_REMOVED = "removed"
MODULE_DIFF_REBASED = "rebased"
_MODULE_DIFF_CHANGE_TYPES = (MODULE_DIFF_ADDED, MODULE_DIFF_REMOVED, MODULE_DIFF_REBASED)


@dataclass(frozen=True)
class ModuleDiffRecord:
    """An added, removed, or rebased module between two evidence inputs.

    Before/after null pairing follows ``change_type``. ``name`` is a display
    name and may differ from the internal anonymous-module match key.
    """
    change_type:         str   # MODULE_DIFF_ADDED / _REMOVED / _REBASED
    name:                 str   # display name -- "(unnamed)" for an anonymous module,
                                  # never the raw (possibly colliding) match key
    full_path_before:     "str | None"
    full_path_after:      "str | None"
    base_address_before:  "str | None"
    base_address_after:   "str | None"
    entity_type: str = field(default="module", init=False)

    def __post_init__(self):
        if self.change_type not in _MODULE_DIFF_CHANGE_TYPES:
            raise ValueError(
                f"ModuleDiffRecord.change_type must be one of {_MODULE_DIFF_CHANGE_TYPES}, "
                f"got {self.change_type!r}")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("ModuleDiffRecord.name must be a non-empty string")
        _require_optional_diff_str(self.full_path_before, "ModuleDiffRecord.full_path_before")
        _require_optional_diff_str(self.full_path_after, "ModuleDiffRecord.full_path_after")
        _require_optional_hex_address(self.base_address_before,
                                       "ModuleDiffRecord.base_address_before")
        _require_optional_hex_address(self.base_address_after,
                                       "ModuleDiffRecord.base_address_after")
        if self.change_type == MODULE_DIFF_ADDED:
            if self.full_path_before is not None or self.base_address_before is not None:
                raise ValueError(
                    "ModuleDiffRecord(change_type='added') must not carry a before value -- "
                    "there is no baseline-side module to report one from")
            if self.base_address_after is None:
                raise ValueError(
                    "ModuleDiffRecord(change_type='added') requires base_address_after")
        elif self.change_type == MODULE_DIFF_REMOVED:
            if self.full_path_after is not None or self.base_address_after is not None:
                raise ValueError(
                    "ModuleDiffRecord(change_type='removed') must not carry an after value -- "
                    "there is no target-side module to report one from")
            if self.base_address_before is None:
                raise ValueError(
                    "ModuleDiffRecord(change_type='removed') requires base_address_before")
        else:   # rebased
            if self.base_address_before is None or self.base_address_after is None:
                raise ValueError(
                    "ModuleDiffRecord(change_type='rebased') requires both "
                    "base_address_before and base_address_after")
            if self.base_address_before == self.base_address_after:
                raise ValueError(
                    "ModuleDiffRecord(change_type='rebased') requires base_address_before != "
                    "base_address_after -- a module whose address didn't change isn't 'rebased'")

    def to_dict(self) -> dict:
        return {
            "entity_type":         self.entity_type,
            "change_type":         self.change_type,
            "name":                self.name,
            "full_path_before":    self.full_path_before,
            "full_path_after":     self.full_path_after,
            "base_address_before": self.base_address_before,
            "base_address_after":  self.base_address_after,
        }


THREAD_DIFF_ADDED   = "added"
THREAD_DIFF_REMOVED = "removed"
_THREAD_DIFF_CHANGE_TYPES = (THREAD_DIFF_ADDED, THREAD_DIFF_REMOVED)


@dataclass(frozen=True)
class ThreadDiffRecord:
    """An added or removed thread between two evidence inputs.

    Module context is resolved only for an added thread with a known target
    start address. ``unregistered`` and ``unavailable`` remain distinct so
    missing module evidence is not reported as a confirmed anomaly.
    """
    change_type:             str   # THREAD_DIFF_ADDED / THREAD_DIFF_REMOVED
    tid:                      int
    start_address_before:     "str | None"
    start_address_after:      "str | None"
    backing_module_after:     "str | None" = None
    backing_module_context:   "str | None" = None
    entity_type: str = field(default="thread", init=False)

    def __post_init__(self):
        if self.change_type not in _THREAD_DIFF_CHANGE_TYPES:
            raise ValueError(
                f"ThreadDiffRecord.change_type must be one of {_THREAD_DIFF_CHANGE_TYPES}, "
                f"got {self.change_type!r}")
        if not isinstance(self.tid, int) or isinstance(self.tid, bool):
            raise ValueError(f"ThreadDiffRecord.tid must be a plain int, got {self.tid!r}")
        _require_optional_hex_address(self.start_address_before,
                                       "ThreadDiffRecord.start_address_before")
        _require_optional_hex_address(self.start_address_after,
                                       "ThreadDiffRecord.start_address_after")
        _require_optional_diff_str(self.backing_module_after,
                                    "ThreadDiffRecord.backing_module_after")
        if self.backing_module_context is not None and self.backing_module_context not in _MODULE_CONTEXTS:
            raise ValueError(
                f"ThreadDiffRecord.backing_module_context must be None or one of "
                f"{_MODULE_CONTEXTS}, got {self.backing_module_context!r}")
        if self.change_type == THREAD_DIFF_ADDED:
            if self.start_address_before is not None:
                raise ValueError(
                    "ThreadDiffRecord(change_type='added') must not carry "
                    "start_address_before -- there is no baseline-side thread to report one from")
            if self.start_address_after is None:
                if self.backing_module_after is not None or self.backing_module_context is not None:
                    raise ValueError(
                        "ThreadDiffRecord(change_type='added') with start_address_after=None "
                        "must not carry backing_module_after/backing_module_context -- module "
                        "resolution is never attempted when the start address itself is unknown")
            else:
                if self.backing_module_context is None:
                    raise ValueError(
                        "ThreadDiffRecord(change_type='added') with a known start_address_after "
                        "requires backing_module_context (module resolution is always attempted "
                        "once the start address is known)")
                if self.backing_module_context == MODULE_CONTEXT_RESOLVED:
                    if self.backing_module_after is None:
                        raise ValueError(
                            "ThreadDiffRecord(backing_module_context='resolved') requires "
                            "backing_module_after")
                elif self.backing_module_after is not None:
                    raise ValueError(
                        f"ThreadDiffRecord(backing_module_context={self.backing_module_context!r}) "
                        f"must not carry backing_module_after")
        else:   # removed
            if (self.start_address_after is not None or self.backing_module_after is not None
                    or self.backing_module_context is not None):
                raise ValueError(
                    "ThreadDiffRecord(change_type='removed') must not carry "
                    "start_address_after/backing_module_after/backing_module_context -- "
                    "diff_threads never attempts target-side/backing-module resolution "
                    "for a removed thread")

    def to_dict(self) -> dict:
        return {
            "entity_type":            self.entity_type,
            "change_type":            self.change_type,
            "tid":                    self.tid,
            "start_address_before":   self.start_address_before,
            "start_address_after":    self.start_address_after,
            "backing_module_after":   self.backing_module_after,
            "backing_module_context": self.backing_module_context,
        }


MEMORY_DIFF_ADDED              = "added"
MEMORY_DIFF_REMOVED            = "removed"
MEMORY_DIFF_PROTECTION_CHANGED = "protection_changed"
_MEMORY_DIFF_CHANGE_TYPES = (MEMORY_DIFF_ADDED, MEMORY_DIFF_REMOVED, MEMORY_DIFF_PROTECTION_CHANGED)


@dataclass(frozen=True)
class MemoryDiffRecord:
    """An added, removed, or protection-changed memory region.

    ``suspicious_before`` and ``suspicious_after`` use the structured
    ``MemoryRegionRecord`` policy, independent of console categorization.
    """
    change_type:         str   # MEMORY_DIFF_ADDED / _REMOVED / _PROTECTION_CHANGED
    base_address:         str   # BaseAddress -- the match key
    size_before:           "int | None"
    size_after:            "int | None"
    protect_before:         "str | None"
    protect_after:           "str | None"
    type_before:              "str | None"
    type_after:                "str | None"
    suspicious_before:          "bool | None"
    suspicious_after:            "bool | None"
    entity_type: str = field(default="memory_region", init=False)

    def __post_init__(self):
        if self.change_type not in _MEMORY_DIFF_CHANGE_TYPES:
            raise ValueError(
                f"MemoryDiffRecord.change_type must be one of {_MEMORY_DIFF_CHANGE_TYPES}, "
                f"got {self.change_type!r}")
        if not isinstance(self.base_address, str) or not _HEX_ADDRESS_RE.match(self.base_address):
            raise ValueError(
                f"MemoryDiffRecord.base_address must be a normalized hex address string "
                f"(\"0x\" + 16 lowercase hex digits, see hex_address()), got {self.base_address!r}")
        _require_optional_diff_int(self.size_before, "MemoryDiffRecord.size_before")
        _require_optional_diff_int(self.size_after, "MemoryDiffRecord.size_after")
        _require_optional_diff_str(self.protect_before, "MemoryDiffRecord.protect_before")
        _require_optional_diff_str(self.protect_after, "MemoryDiffRecord.protect_after")
        _require_optional_diff_str(self.type_before, "MemoryDiffRecord.type_before")
        _require_optional_diff_str(self.type_after, "MemoryDiffRecord.type_after")
        _require_optional_diff_bool(self.suspicious_before, "MemoryDiffRecord.suspicious_before")
        _require_optional_diff_bool(self.suspicious_after, "MemoryDiffRecord.suspicious_after")
        if self.change_type == MEMORY_DIFF_ADDED:
            if any(v is not None for v in (self.size_before, self.protect_before,
                                             self.type_before, self.suspicious_before)):
                raise ValueError(
                    "MemoryDiffRecord(change_type='added') must not carry a before value -- "
                    "there is no baseline-side region to report one from")
        elif self.change_type == MEMORY_DIFF_REMOVED:
            if any(v is not None for v in (self.size_after, self.protect_after,
                                             self.type_after, self.suspicious_after)):
                raise ValueError(
                    "MemoryDiffRecord(change_type='removed') must not carry an after value -- "
                    "there is no target-side region to report one from")
        else:   # protection_changed
            if self.protect_before is None or self.protect_after is None:
                raise ValueError(
                    "MemoryDiffRecord(change_type='protection_changed') requires both "
                    "protect_before and protect_after")
            if self.protect_before == self.protect_after:
                raise ValueError(
                    "MemoryDiffRecord(change_type='protection_changed') requires "
                    "protect_before != protect_after -- a region whose protection didn't "
                    "change isn't 'protection_changed'")
            if self.suspicious_before is None or self.suspicious_after is None:
                raise ValueError(
                    "MemoryDiffRecord(change_type='protection_changed') requires both "
                    "suspicious_before and suspicious_after")

    def to_dict(self) -> dict:
        return {
            "entity_type":       self.entity_type,
            "change_type":       self.change_type,
            "base_address":      self.base_address,
            "size_before":       self.size_before,
            "size_after":        self.size_after,
            "protect_before":    self.protect_before,
            "protect_after":     self.protect_after,
            "type_before":       self.type_before,
            "type_after":        self.type_after,
            "suspicious_before": self.suspicious_before,
            "suspicious_after":  self.suspicious_after,
        }


# ── comparison premise ────────────────────────────────────────────────────

COMPARISON_SCOPE_INVENTORY = "inventory"

FACT_CAPTURE_TIME           = "capture_time"
FACT_PROCESS_ID             = "process_id"
FACT_PROCESS_CREATE_TIME    = "process_create_time"
FACT_HOST_ARCHITECTURE      = "host_architecture"
FACT_OS_VERSION             = "os_version"
FACT_IMAGE_MACHINE          = "image_machine"
FACT_PEB_IMAGE_PATH         = "peb_image_path"
FACT_MODULE_IMAGE_PATH      = "module_image_path"
FACT_MODULE_IMAGE_SIZE      = "module_image_size"
FACT_MODULE_IMAGE_TIMESTAMP = "module_image_timestamp"
# Wire order of ComparisonPremiseRecord.facts. Each fact has one source:
#   capture_time            minidump header TimeDateStamp
#   process_id, process_create_time
#                           MiscInfoStream
#   host_architecture, os_version
#                           SystemInfoStream (the host, not the process)
#   image_machine           COFF Machine of the PE header at the PEB image
#                           base (the process's own code width)
#   peb_image_path          PEB ProcessParameters ImagePathName
#   module_image_path, module_image_size, module_image_timestamp
#                           the ModuleListStream entry registered at the
#                           PEB image base
COMPARISON_FACTS = (
    FACT_CAPTURE_TIME, FACT_PROCESS_ID, FACT_PROCESS_CREATE_TIME, FACT_HOST_ARCHITECTURE,
    FACT_OS_VERSION, FACT_IMAGE_MACHINE, FACT_PEB_IMAGE_PATH, FACT_MODULE_IMAGE_PATH,
    FACT_MODULE_IMAGE_SIZE, FACT_MODULE_IMAGE_TIMESTAMP,
)
_INTEGER_FACTS = frozenset({FACT_PROCESS_ID, FACT_MODULE_IMAGE_SIZE,
                            FACT_MODULE_IMAGE_TIMESTAMP})
_UTC_TIME_FACTS = frozenset({FACT_CAPTURE_TIME, FACT_PROCESS_CREATE_TIME})
# Compared without regard to case: Windows paths are case-insensitive.
_CASE_INSENSITIVE_FACTS = frozenset({FACT_PEB_IMAGE_PATH, FACT_MODULE_IMAGE_PATH})
_FACT_UINT32_MAX = 0xFFFFFFFF
# "%Y-%m-%d %H:%M:%S UTC" -- fixed width, so lexical order is time order.
_UTC_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$")

# Why one capture holds, or does not hold, a fact's value.
FACT_STATE_RECORDED        = "recorded"         # the value is set
FACT_STATE_ABSENT          = "absent"           # the fact's source is not in the dump
FACT_STATE_FAILED          = "failed"           # the source is in the dump but could not be read
FACT_STATE_UNSET           = "unset"            # the source holds no usable value for the fact
FACT_STATE_UNRECONSTRUCTED = "unreconstructed"  # PEB: SystemInfoStream or ThreadListStream,
                                                # which reconstructing it needs, is absent or
                                                # could not be read
FACT_STATE_BASE_UNKNOWN    = "base_unknown"     # no PEB image base to locate the fact at
FACT_STATE_UNMATCHED       = "unmatched"        # no module is registered at the PEB image base
FACT_STATE_UNCAPTURED      = "uncaptured"       # no bytes were captured at the PEB image base
FACT_STATE_TRUNCATED       = "truncated"        # the capture there stops before the Machine field
FACT_STATE_INVALID         = "invalid"          # the bytes captured there are not a valid PE header
COMPARISON_FACT_STATES = (
    FACT_STATE_RECORDED, FACT_STATE_ABSENT, FACT_STATE_FAILED, FACT_STATE_UNSET,
    FACT_STATE_UNRECONSTRUCTED, FACT_STATE_BASE_UNKNOWN, FACT_STATE_UNMATCHED,
    FACT_STATE_UNCAPTURED, FACT_STATE_TRUNCATED, FACT_STATE_INVALID,
)
_STREAM_FACT_STATES = frozenset({FACT_STATE_RECORDED, FACT_STATE_ABSENT, FACT_STATE_FAILED,
                                 FACT_STATE_UNSET})
# The states each fact can take; a fact not listed takes _STREAM_FACT_STATES.
_FACT_STATES = {
    FACT_PEB_IMAGE_PATH: _STREAM_FACT_STATES | {FACT_STATE_UNRECONSTRUCTED},
    FACT_IMAGE_MACHINE: frozenset({FACT_STATE_RECORDED, FACT_STATE_FAILED,
                                   FACT_STATE_BASE_UNKNOWN, FACT_STATE_UNCAPTURED,
                                   FACT_STATE_TRUNCATED, FACT_STATE_INVALID}),
    **{fact: _STREAM_FACT_STATES | {FACT_STATE_BASE_UNKNOWN, FACT_STATE_UNMATCHED}
       for fact in (FACT_MODULE_IMAGE_PATH, FACT_MODULE_IMAGE_SIZE, FACT_MODULE_IMAGE_TIMESTAMP)},
}

FACT_RELATION_SAME      = "same"
FACT_RELATION_DIFFERENT = "different"
FACT_RELATION_UNKNOWN   = "unknown"
_FACT_RELATIONS = (FACT_RELATION_SAME, FACT_RELATION_DIFFERENT, FACT_RELATION_UNKNOWN)

PROCESS_INSTANCE_SAME      = "same"
PROCESS_INSTANCE_DIFFERENT = "different"
PROCESS_INSTANCE_UNKNOWN   = "unknown"
_PROCESS_INSTANCES = (PROCESS_INSTANCE_SAME, PROCESS_INSTANCE_DIFFERENT, PROCESS_INSTANCE_UNKNOWN)

CAPTURE_ORDER_BASELINE_FIRST = "baseline_first"
CAPTURE_ORDER_TARGET_FIRST   = "target_first"
CAPTURE_ORDER_SAME_SECOND    = "same_second"
CAPTURE_ORDER_UNKNOWN        = "unknown"
_CAPTURE_ORDERS = (CAPTURE_ORDER_BASELINE_FIRST, CAPTURE_ORDER_TARGET_FIRST,
                   CAPTURE_ORDER_SAME_SECOND, CAPTURE_ORDER_UNKNOWN)

COMPARISON_SIDE_BASELINE = "baseline"
COMPARISON_SIDE_TARGET   = "target"
_COMPARISON_SIDES = (COMPARISON_SIDE_BASELINE, COMPARISON_SIDE_TARGET)
_CAPTURE_DIAGNOSTIC_SEVERITIES = ("info", "warning")


def _fact_states(fact: str) -> frozenset:
    return _FACT_STATES.get(fact, _STREAM_FACT_STATES)


def _require_fact_value(fact: str, value, field_name: str) -> None:
    if value is None:
        return
    if fact in _INTEGER_FACTS:
        if (not isinstance(value, int) or isinstance(value, bool)
                or not 1 <= value <= _FACT_UINT32_MAX):
            raise ValueError(
                f"{field_name} for fact {fact!r} must be None or an int in 1..0xFFFFFFFF, "
                f"got {value!r}")
        return
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"{field_name} for fact {fact!r} must be None or a non-empty string, got {value!r}")
    if fact in _UTC_TIME_FACTS and not _UTC_TIME_RE.match(value):
        raise ValueError(
            f"{field_name} for fact {fact!r} must be a \"YYYY-MM-DD HH:MM:SS UTC\" string, "
            f"got {value!r}")


def _require_fact_state(fact: str, value, state, field_name: str) -> None:
    if state not in _fact_states(fact):
        raise ValueError(
            f"{field_name} for fact {fact!r} must be one of {sorted(_fact_states(fact))}, "
            f"got {state!r}")
    if (state == FACT_STATE_RECORDED) != (value is not None):
        raise ValueError(
            f"{field_name} for fact {fact!r} is {state!r}, so its value must "
            f"{'be set' if state == FACT_STATE_RECORDED else 'be None'}, got {value!r}")


@dataclass(frozen=True)
class ComparisonFactRecord:
    """One identity fact as each capture records it, from one stated source
    (see COMPARISON_FACTS).

    ``baseline_state``/``target_state`` say why each value is or is not
    present; a value is set exactly when its state is ``recorded``.
    ``relation`` is derived: ``unknown`` unless both sides are recorded,
    otherwise ``same`` or ``different`` by value (paths without regard to
    case). It relates two recorded values; it does not say anything
    changed between the captures.
    """
    fact:           str
    baseline:       "str | int | None"
    target:         "str | int | None"
    baseline_state: str
    target_state:   str
    relation:       str = field(init=False)

    def __post_init__(self):
        if self.fact not in COMPARISON_FACTS:
            raise ValueError(
                f"ComparisonFactRecord.fact must be one of {COMPARISON_FACTS}, got {self.fact!r}")
        _require_fact_value(self.fact, self.baseline, "ComparisonFactRecord.baseline")
        _require_fact_value(self.fact, self.target, "ComparisonFactRecord.target")
        _require_fact_state(self.fact, self.baseline, self.baseline_state,
                            "ComparisonFactRecord.baseline_state")
        _require_fact_state(self.fact, self.target, self.target_state,
                            "ComparisonFactRecord.target_state")
        if self.baseline is None or self.target is None:
            relation = FACT_RELATION_UNKNOWN
        elif self.fact in _CASE_INSENSITIVE_FACTS:
            relation = (FACT_RELATION_SAME if self.baseline.casefold() == self.target.casefold()
                        else FACT_RELATION_DIFFERENT)
        else:
            relation = (FACT_RELATION_SAME if self.baseline == self.target
                        else FACT_RELATION_DIFFERENT)
        object.__setattr__(self, "relation", relation)

    def to_dict(self) -> dict:
        return {
            "fact":           self.fact,
            "baseline":       self.baseline,
            "target":         self.target,
            "baseline_state": self.baseline_state,
            "target_state":   self.target_state,
            "relation":       self.relation,
        }


@dataclass(frozen=True)
class ComparisonCaptureDiagnostic:
    """A disagreement between two identity sources inside ONE capture --
    for example a PEB image path whose file name differs from the module
    registered at the PEB image base. ``code``/``severity``/``message``
    are those the shared process-identity snapshot (the one --process
    reports) raises for that capture, or the comparison's own
    PEB_MODULE_PATH_MISMATCH. A diagnostic is evidence, never a verdict.
    """
    side:     str
    code:     str
    severity: str
    message:  str

    def __post_init__(self):
        if self.side not in _COMPARISON_SIDES:
            raise ValueError(
                f"ComparisonCaptureDiagnostic.side must be one of {_COMPARISON_SIDES}, "
                f"got {self.side!r}")
        if self.severity not in _CAPTURE_DIAGNOSTIC_SEVERITIES:
            raise ValueError(
                f"ComparisonCaptureDiagnostic.severity must be one of "
                f"{_CAPTURE_DIAGNOSTIC_SEVERITIES}, got {self.severity!r}")
        for name in ("code", "message"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"ComparisonCaptureDiagnostic.{name} must be a non-empty string, "
                    f"got {value!r}")

    def to_dict(self) -> dict:
        return {
            "side":     self.side,
            "code":     self.code,
            "severity": self.severity,
            "message":  self.message,
        }


@dataclass(frozen=True)
class ComparisonPremiseRecord:
    """What the two captures of a comparison are known to share.

    ``scope`` is always ``inventory``: every comparison record relates two
    captured inventories. A record present on one side only, a different
    module base or a different region protection is a relation between
    those inventories, never an observed load, unload, rebase or
    protection change; nothing between the two captures was observed.

    ``facts`` holds one ComparisonFactRecord per COMPARISON_FACTS entry, in
    that order. ``capture_diagnostics`` holds the identity disagreements
    found inside each capture, baseline first. The other fields are
    derived from ``facts``:

    * ``process_instance`` rests on process ID and process creation time
      alone: ``different`` when either is recorded on both sides and
      differs, ``same`` when both are recorded and equal on both sides,
      ``unknown`` otherwise. Host identity is not established by either,
      and other identity facts are disclosed, never used to infer an
      instance.
    * ``capture_order`` orders the two capture times: ``baseline_first``,
      ``target_first``, ``same_second`` (equal at the format's one-second
      resolution) or ``unknown``.
    * ``known_differences`` and ``unknown_premises`` list, in fact order,
      the facts whose relation is ``different`` and ``unknown``.

    The premise qualifies how records are read; it never changes coverage
    or the exit code.
    """
    facts:               tuple
    capture_diagnostics: tuple
    scope:               str = field(init=False)
    process_instance:    str = field(init=False)
    capture_order:       str = field(init=False)
    known_differences:   tuple = field(init=False)
    unknown_premises:    tuple = field(init=False)

    def __post_init__(self):
        if (not isinstance(self.facts, tuple)
                or not all(isinstance(f, ComparisonFactRecord) for f in self.facts)):
            raise ValueError(
                "ComparisonPremiseRecord.facts must be a tuple of ComparisonFactRecord")
        names = tuple(f.fact for f in self.facts)
        if names != COMPARISON_FACTS:
            raise ValueError(
                f"ComparisonPremiseRecord.facts must hold exactly {COMPARISON_FACTS} in that "
                f"order, got {names}")
        if (not isinstance(self.capture_diagnostics, tuple)
                or not all(isinstance(d, ComparisonCaptureDiagnostic)
                           for d in self.capture_diagnostics)):
            raise ValueError(
                "ComparisonPremiseRecord.capture_diagnostics must be a tuple of "
                "ComparisonCaptureDiagnostic")
        sides = [d.side for d in self.capture_diagnostics]
        if sides != sorted(sides, key=_COMPARISON_SIDES.index):
            raise ValueError(
                "ComparisonPremiseRecord.capture_diagnostics must list baseline before target")
        by_fact = {f.fact: f for f in self.facts}

        identity = (by_fact[FACT_PROCESS_ID].relation,
                    by_fact[FACT_PROCESS_CREATE_TIME].relation)
        if FACT_RELATION_DIFFERENT in identity:
            process_instance = PROCESS_INSTANCE_DIFFERENT
        elif identity == (FACT_RELATION_SAME, FACT_RELATION_SAME):
            process_instance = PROCESS_INSTANCE_SAME
        else:
            process_instance = PROCESS_INSTANCE_UNKNOWN

        capture = by_fact[FACT_CAPTURE_TIME]
        if capture.relation == FACT_RELATION_UNKNOWN:
            capture_order = CAPTURE_ORDER_UNKNOWN
        elif capture.relation == FACT_RELATION_SAME:
            capture_order = CAPTURE_ORDER_SAME_SECOND
        elif capture.baseline < capture.target:
            capture_order = CAPTURE_ORDER_BASELINE_FIRST
        else:
            capture_order = CAPTURE_ORDER_TARGET_FIRST

        object.__setattr__(self, "scope", COMPARISON_SCOPE_INVENTORY)
        object.__setattr__(self, "process_instance", process_instance)
        object.__setattr__(self, "capture_order", capture_order)
        object.__setattr__(self, "known_differences", tuple(
            f.fact for f in self.facts if f.relation == FACT_RELATION_DIFFERENT))
        object.__setattr__(self, "unknown_premises", tuple(
            f.fact for f in self.facts if f.relation == FACT_RELATION_UNKNOWN))

    def to_dict(self) -> dict:
        return {
            "scope":               self.scope,
            "process_instance":    self.process_instance,
            "capture_order":       self.capture_order,
            "known_differences":   list(self.known_differences),
            "unknown_premises":    list(self.unknown_premises),
            "facts":               [f.to_dict() for f in self.facts],
            "capture_diagnostics": [d.to_dict() for d in self.capture_diagnostics],
        }
