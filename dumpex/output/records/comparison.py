"""`--diff` comparison records.

Tagged-union members for result.data.records (kind="comparison").
`entity_type` is the discriminator. Each `change_type` carries only the
before/after values that exist for that side of the comparison.

The field-shape validators all three apply (dumpex.output.records.common)
each mirror a constraint the v2.1 schema's own moduleDiffRecord/
threadDiffRecord/memoryDiffRecord $defs already enforce on the wire --
closing the gap where the Python model could construct (and freely
.to_dict()) a shape its own schema rejects.
"""
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
