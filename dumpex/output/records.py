"""Canonical v2 record types and their explicit wire projections.

Memory addresses and pointers are normalized lowercase hex strings;
other numeric values, including dump-file offsets and bitfields, remain
JSON integers. Missing values are ``None``, never an empty string.
Mutable fields are copied when projected so callers cannot mutate records
through a serialized result.
"""
import copy
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from dumpex.output.coverage import CoverageReport


def hex_address(n) -> "str | None":
    """Normalize an address-like int to a fixed-width (16 hex digit,
    zero-padded), lowercase "0x..." string, or None if `n` is None -- the
    one formatting helper every address-typed field goes through, so the
    normalized form never has to be re-derived ad hoc per command.
    Fixed-width rather than minimal-width so two addresses always compare
    equal-length as strings (matches the convention dumpex/commands/
    modules.py and threads.py's console output already used, e.g.
    `0x{m.baseaddress:016x}`, before this record type existed)."""
    return None if n is None else f"0x{n:016x}"


@dataclass
class MemoryRegionRecord:
    """One MinidumpMemoryInfo region, as reported by `--list`."""
    base_address: "str | None"
    size: "int | None"
    state:   "str | None"
    protect: "str | None"
    type:    "str | None"
    suspicious: bool   # True if `protect` is one of the always-suspicious
                        # page-protection combinations (see
                        # dumpex.rules_pkg.loader.SUSPICIOUS_PROTS) --
                        # replaces the RED-vs-plain console coloring test,
                        # which was previously never exposed as data.

    def to_dict(self) -> dict:
        return {
            "base_address": self.base_address,
            "size":         self.size,
            "state":        self.state,
            "protect":      self.protect,
            "type":         self.type,
            "suspicious":   self.suspicious,
        }


@dataclass
class ModuleRecord:
    """One loaded module, as reported by `--modules`."""
    name:          "str | None"
    full_path:     "str | None"
    base_address:  "str | None"
    end_address:   "str | None"
    size:          "int | None"
    compiled_utc:  "str | None"
    file_version:  "str | None"
    checksum:      "int | None"
    anomaly_flags: list = field(default_factory=list)   # list[str], e.g. ["NO_NAME"]

    def to_dict(self) -> dict:
        return {
            "name":          self.name,
            "full_path":     self.full_path,
            "base_address":  self.base_address,
            "end_address":   self.end_address,
            "size":          self.size,
            "compiled_utc":  self.compiled_utc,
            "file_version":  self.file_version,
            "checksum":      self.checksum,
            "anomaly_flags": list(self.anomaly_flags),
        }


MODULE_CONTEXT_RESOLVED     = "resolved"       # start_address falls inside a known module
MODULE_CONTEXT_UNREGISTERED = "unregistered"   # ModuleListStream available; confirmed NOT
                                                 # backed by any known module -- an actual
                                                 # signal (e.g. injection/hollowing indicator)
MODULE_CONTEXT_UNAVAILABLE  = "unavailable"     # ModuleListStream itself missing -- can't
                                                 # tell either way, NOT a confirmed anomaly


@dataclass
class ThreadRecord:
    """One thread, as reported by `--threads`."""
    tid:               "int | None"
    start_address:     "str | None"
    backing_module:    "str | None"
    # None only when start_address is itself None (module context is moot
    # with no address to resolve). Otherwise one of MODULE_CONTEXT_* --
    # see those constants' docstrings. Mirrors the same "confirmed vs
    # can't-tell" distinction dumpex.hunt._context.classify_memory_context
    # already makes for memory regions (UNREGISTERED vs UNKNOWN): a
    # missing ModuleListStream must never be indistinguishable from a
    # positively-confirmed "not in any module" finding, since the latter
    # is itself a DFIR signal this tool's own hunters treat as suspicious.
    module_context:    "str | None"
    create_time:       "str | None"
    exit_time:         "str | None"
    exit_status:       "int | None"
    kernel_time_100ns: "int | None"
    user_time_100ns:   "int | None"
    suspend_count:     "int | None"
    priority:          "int | None"
    teb:               "str | None"
    flags: list = field(default_factory=list)   # list[str], e.g. ["EXITED"]

    def to_dict(self) -> dict:
        return {
            "tid":               self.tid,
            "start_address":     self.start_address,
            "backing_module":    self.backing_module,
            "module_context":    self.module_context,
            "flags":             list(self.flags),
            "create_time":       self.create_time,
            "exit_time":         self.exit_time,
            "exit_status":       self.exit_status,
            "kernel_time_100ns": self.kernel_time_100ns,
            "user_time_100ns":   self.user_time_100ns,
            "suspend_count":     self.suspend_count,
            "priority":          self.priority,
            "teb":               self.teb,
        }


@dataclass
class SysInfoRecord:
    """The fixed ``--sysinfo`` record shape.

    Environment entries preserve source order and duplicate or ``=``-prefixed
    names. ``None`` means the block was unavailable; an empty tuple means it
    was observed and contained no entries.
    """
    dump_file:          "str | None" = None
    # The dump's own identity, reported together in the console's DUMP
    # section. size/sha256 come from re-reading the file (None together,
    # with SYSINFO_DUMP_FILE_UNREADABLE, when that read fails);
    # dump_time_utc is MinidumpHeader.TimeDateStamp, a UINT32 time_t whose
    # 0 means "the producer never set it" -> None, exactly like
    # MiscInfo.ProcessCreateTime.
    dump_file_size_bytes: "int | None" = None
    dump_sha256:        "str | None" = None
    dump_time_utc:      "str | None" = None
    hostname:           "str | None" = None
    username:           "str | None" = None
    os:                 "str | None" = None
    os_version:         "str | None" = None
    architecture:       "str | None" = None
    product_type:       "str | None" = None
    processors:         "int | None" = None
    cpu_vendor:         "str | None" = None
    cpu_current_mhz:    "int | None" = None
    cpu_max_mhz:        "int | None" = None
    thread_count:       "int | None" = None   # None if ThreadListStream itself is absent
    module_count:       "int | None" = None   # None if ModuleListStream itself is absent
    current_directory:  "str | None" = None
    # tuple[{"name": str, "value": str}] when the environment walk yielded
    # entries (or a verified-empty block: () ), None when the PEB/walk was
    # unavailable or unreadable -- §4.3.3. Never a dict: duplicate names,
    # `=`-prefixed names, and source order are real forensic evidence a
    # dict would silently destroy.
    environment_variables: "tuple | None" = None

    def to_dict(self) -> dict:
        return {
            "dump_file":               self.dump_file,
            "dump_file_size_bytes":    self.dump_file_size_bytes,
            "dump_sha256":             self.dump_sha256,
            "dump_time_utc":           self.dump_time_utc,
            "hostname":                self.hostname,
            "username":                self.username,
            "os":                      self.os,
            "os_version":              self.os_version,
            "architecture":            self.architecture,
            "product_type":            self.product_type,
            "processors":              self.processors,
            "cpu_vendor":              self.cpu_vendor,
            "cpu_current_mhz":         self.cpu_current_mhz,
            "cpu_max_mhz":             self.cpu_max_mhz,
            "thread_count":            self.thread_count,
            "module_count":            self.module_count,
            "current_directory":       self.current_directory,
            "environment_variables":   (None if self.environment_variables is None
                                         else [dict(e) for e in self.environment_variables]),
        }


# Historical schemas retain ``pidRecord`` and ``pebRecord`` definitions so
# output produced by older schema versions remains validatable.


# ── Extraction records ─────────────────────────────────────────────────
# Validators mirror the corresponding schema constraints: offsets and sizes
# are non-negative plain integers, encodings are closed vocabulary, and a
# read cannot exceed its request. `_HEX_ADDRESS_RE` and the
# `_require_optional_*` family below are resolved when __post_init__ runs,
# so their physical position later in this module (kept together
# with their other comparison-record callers) doesn't matter.

def _require_nonneg_int(value, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative plain int (not bool), got {value!r}")


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool, got {value!r}")


def _require_hex_address(value, field_name: str) -> None:
    if not isinstance(value, str) or not _HEX_ADDRESS_RE.match(value):
        raise ValueError(
            f"{field_name} must be a normalized hex address string (\"0x\" + 16 lowercase hex "
            f"digits, see hex_address()), got {value!r}")


_STRING_RECORD_ENCODINGS = ("ASCII", "UTF16")


@dataclass
class ExtractRecord:
    """`--extract`'s record -- the READ-side facts only. Write-side facts
    (the output path/size_bytes/sha256) live on the corresponding entry
    in result.artifacts instead (see Artifact below) -- not duplicated
    here, since the two describe different things (what was read from
    the dump vs. what was written to disk) that happen to usually agree
    in size but are conceptually distinct facts."""
    requested_address:      str          # hex_address(addr) -- never null: a
                                          # successful collect_extract() always
                                          # knows the address it read from
    requested_size:          int         # size actually passed to read_region
                                          # (post auto-size resolution -- see
                                          # dumpex.core.memory._resolve_size) --
                                          # never null for the same reason
    auto_sized:             bool         # True when --size wasn't given
    bytes_read:              int         # len(data) -- equal to requested_size
                                          # whenever the read didn't come up short
    mz_header_detected:      bool        # data[:2] == b"MZ"

    def __post_init__(self):
        # Both non-null: collect_extract() only ever constructs this record
        # after a successful read_region() call, which means it always
        # already knows the exact address/size it asked for -- allowing
        # None here would let a producer construct (and .to_dict()) a
        # shape the v2.2 schema's own required/non-nullable extractRecord
        # fields reject, the same gap StringRecord's own non-null
        # `address` field closed earlier.
        _require_hex_address(self.requested_address, "ExtractRecord.requested_address")
        _require_nonneg_int(self.requested_size, "ExtractRecord.requested_size")
        _require_bool(self.auto_sized, "ExtractRecord.auto_sized")
        _require_nonneg_int(self.bytes_read, "ExtractRecord.bytes_read")
        _require_bool(self.mz_header_detected, "ExtractRecord.mz_header_detected")
        if self.bytes_read > self.requested_size:
            raise ValueError(
                f"ExtractRecord.bytes_read ({self.bytes_read}) must not exceed "
                f"requested_size ({self.requested_size}) -- a read can come up short, never long")

    def to_dict(self) -> dict:
        return {
            "requested_address":  self.requested_address,
            "requested_size":     self.requested_size,
            "auto_sized":         self.auto_sized,
            "bytes_read":         self.bytes_read,
            "mz_header_detected": self.mz_header_detected,
        }


@dataclass
class StringRecord:
    """One extracted string -- `--strings`' record, also reused as-is by
    `--report`'s own "notable strings" section (see
    dumpex.commands.report). `offset` is a plain int (a byte offset
    relative to the read region's start, NOT a process address -- the
    hex_address()-only-for-real-addresses rule in this module's own
    docstring doesn't apply to it) while `address` is the absolute VA
    (the requested read's own base address + offset), a real memory
    address, so it goes through hex_address() like every other
    address-typed field -- and, unlike most other address-typed fields in
    this module, always non-null: a string was found at some real address,
    there is no "address unknown" case for it. `matched_grep` is a FLAG,
    not a filter: this record is emitted for every extracted string
    regardless of --grep, so the STRUCTURED records list (JSON) always
    shows every extracted string -- None when no --grep was given at all
    (the concept doesn't apply), True/False per record when it was. The
    CONSOLE rendering (render_strings_console) is a separate, narrower
    concern: it actually SKIPS any record with matched_grep is False
    (only highlighting True matches, never printing non-matches) -- do
    not conflate the two; a --grep run's console text shows the same
    count as its own JSON output only when every extracted string
    happens to match, and fewer whenever at least one doesn't."""
    offset:        int
    address:       str
    encoding:      str              # "ASCII" | "UTF16"
    text:          str
    matched_grep:  "bool | None"

    def __post_init__(self):
        _require_nonneg_int(self.offset, "StringRecord.offset")
        _require_hex_address(self.address, "StringRecord.address")
        if self.encoding not in _STRING_RECORD_ENCODINGS:
            raise ValueError(
                f"StringRecord.encoding must be one of {_STRING_RECORD_ENCODINGS}, "
                f"got {self.encoding!r}")
        if not isinstance(self.text, str):
            raise ValueError(f"StringRecord.text must be a str, got {self.text!r}")
        _require_optional_diff_bool(self.matched_grep, "StringRecord.matched_grep")

    def to_dict(self) -> dict:
        return {
            "offset":       self.offset,
            "address":      self.address,
            "encoding":     self.encoding,
            "text":         self.text,
            "matched_grep": self.matched_grep,
        }


# ── Comparison records ─────────────────────────────────────────────────
# Tagged-union members for result.data.records (kind="comparison").
# `entity_type` is the discriminator. Each `change_type` carries only the
# before/after values that exist for that side of the comparison.
#
# Field-shape validators shared by all three -- kept local to this
# section (not shared with, say, dumpex.output.coverage's own similarly-
# named helpers) since these two modules are otherwise fully decoupled by
# design. Each mirrors a constraint the v2.1 schema's own moduleDiffRecord/
# threadDiffRecord/memoryDiffRecord $defs already enforce on the wire --
# closing the gap where the Python model could construct (and freely
# .to_dict()) a shape its own schema rejects.

_HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{16}$")


def _require_optional_hex_address(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not _HEX_ADDRESS_RE.match(value)):
        raise ValueError(
            f"{field_name} must be None or a normalized hex address string (\"0x\" + 16 "
            f"lowercase hex digits, see hex_address()), got {value!r}")


def _require_optional_diff_str(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{field_name} must be None or a non-empty string, got {value!r}")


def _require_optional_diff_int(value, field_name: str) -> None:
    # bool is a subclass of int in Python -- explicitly excluded, since
    # the wire's JSON "integer" type rejects true/false (see hunt/coverage
    # modules' identical `isinstance(x, bool)` exclusion elsewhere).
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError(f"{field_name} must be None or a plain int (not bool), got {value!r}")


def _require_optional_diff_bool(value, field_name: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{field_name} must be None or a bool, got {value!r}")


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
_MODULE_CONTEXTS = (MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE)


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


SEVERITY_WARNING = "warning"
SEVERITY_ERROR   = "error"


@dataclass(frozen=True)
class Diagnostic:
    """One entry in the top-level diagnostics.warnings/.errors (a sibling
    of `result`, not nested under it) -- structured,
    not a bare string, so a consumer can filter/triage without parsing
    free text. Frozen: a plain (mutable) dataclass would let a caller
    construct a valid instance, then mutate a field past __post_init__'s
    own validation (e.g. `d.severity = "critical"`) before it reaches
    collector.py's set_command_result() -- CommandResult's isinstance
    check only confirms the TYPE at construction time, not that the
    fields are still valid by the time .to_dict() is actually called."""
    severity: str            # SEVERITY_WARNING / SEVERITY_ERROR
    message:  str
    code:     "str | None" = None

    def __post_init__(self):
        if self.severity not in (SEVERITY_WARNING, SEVERITY_ERROR):
            raise ValueError(
                f"Diagnostic.severity must be {SEVERITY_WARNING!r} or {SEVERITY_ERROR!r}, "
                f"got {self.severity!r}")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("Diagnostic.message must be a non-empty string")
        if self.code is not None and (not isinstance(self.code, str) or not self.code):
            raise ValueError("Diagnostic.code must be None or a non-empty string")

    def to_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "code": self.code}


@dataclass(frozen=True)
class Artifact:
    """One entry in the top-level `artifacts` array -- an output file the
    tool itself produced (e.g. an extracted memory region), distinct from
    meta.evidence (which describes the INPUT dump(s)). Field naming
    mirrors meta.evidence's own id/path/size_bytes/sha256 shape. Populated
    by --extract and by --report's own optional extract-to-file side
    effect (both via dumpex.commands.extract.build_extract_artifact(),
    which calls dumpex.core.safe_io.compute_bytes_summary() for the
    size_bytes/sha256 fields directly rather than parsing them back out
    of summarize_bytes()'s formatted string) -- report.py calls this
    helper directly rather than going through collect_extract()/
    cmd_extract(), passing kind="report_extracted_region" so
    artifacts[].kind still distinguishes the two producers. Constructing
    one is the ONLY
    way an entry reaches `artifacts` on the wire -- dumpex.output.collector.
    V2Output.set_command_result() calls .to_dict() unconditionally (no
    duck-typed dict passthrough), so a caller can't smuggle a shape this
    class doesn't validate. Frozen for the same reason as Diagnostic --
    otherwise a valid instance could be mutated past its own
    __post_init__ checks after CommandResult's isinstance check already
    passed."""
    id:          str
    kind:        str            # open vocabulary (e.g. "extracted_region") -- mirrors
                                  # dumpex.output.coverage's `source` staying open too
    path:        str
    size_bytes:  "int | None" = None
    sha256:      "str | None" = None
    description: "str | None" = None

    def __post_init__(self):
        for field_name in ("id", "kind", "path"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"Artifact.{field_name} must be a non-empty string")
        if self.size_bytes is not None and (
                not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool)
                or self.size_bytes < 0):
            raise ValueError(
                f"Artifact.size_bytes must be None or a non-negative int, got {self.size_bytes!r}")
        if self.sha256 is not None and (not isinstance(self.sha256, str) or not self.sha256):
            raise ValueError("Artifact.sha256 must be None or a non-empty string")
        if self.description is not None and not isinstance(self.description, str):
            raise ValueError("Artifact.description must be None or a string")

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "path": self.path,
                "size_bytes": self.size_bytes, "sha256": self.sha256,
                "description": self.description}


# ── Report records ─────────────────────────────────────────────────────
# One TriageCardRecord per triage card -- see dumpex.commands.report's own
# module docstring for why this is NOT a --diff-style tagged union of
# independent thread/region/string entities: a card's thread/region/
# strings/verdict are one coherent, MECE-scored narrative about one
# anchor, not independent things a consumer would count/filter
# separately. --report-string's N hits become N TriageCardRecords in one
# CommandResult.records list; tid/addr mode always produces exactly one.

TRIAGE_ANCHOR_TID        = "tid"
TRIAGE_ANCHOR_ADDRESS    = "address"
TRIAGE_ANCHOR_STRING_HIT = "string_hit"
_TRIAGE_ANCHOR_SOURCES = (TRIAGE_ANCHOR_TID, TRIAGE_ANCHOR_ADDRESS, TRIAGE_ANCHOR_STRING_HIT)

# Mirrors dumpex.core.memory.VERDICT_CLEAN/_SUSPICIOUS/_LIKELY_MALICIOUS/
# _HIGH_CONFIDENCE_MALICIOUS by convention (same four literal strings) --
# not imported from there, the same way ThreadRecord.module_context's own
# MODULE_CONTEXT_* vocabulary above is this module's own closed set
# rather than importing dumpex.hunt._context's. Keeps the dependency
# direction command/domain model -> output layer, never the reverse.
_TRIAGE_VERDICTS = ("CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS", "HIGH_CONFIDENCE_MALICIOUS")

# Mirrors dumpex.core.memory.INDICATOR_DIMS' own four keys by convention,
# for the same reason _TRIAGE_VERDICTS mirrors VERDICT_CLEAN/etc rather
# than importing them -- a TriageCardRecord.findings entry outside this
# set is rejected at construction time, not just left undocumented.
_TRIAGE_FINDING_KEYS = ("unbacked_thread", "rwx_private", "injected_pe", "ioc_strings")


@dataclass
class ReportThreadInfo:
    """One thread as seen by `--report` -- either the anchor thread
    (Section 1) or one of the other threads sharing the anchor's resolved
    region (Section 3). Deliberately narrower than ThreadRecord (no
    create_time/exit_time/exit_status/suspend_count/priority/teb/flags):
    report.py's own console output never surfaces those for either
    section, so this record does not either -- see ThreadRecord itself
    for the full `--threads` shape."""
    tid:               int
    start_address:     "str | None"
    backing_module:    "str | None"
    module_context:    "str | None"   # None only when start_address is itself
                                        # None -- see ThreadRecord's identical rule
    kernel_time_100ns: "int | None"
    user_time_100ns:   "int | None"
    backing_module_base: "str | None" = None   # only populated for report.py's own Section 1
    backing_module_end:  "str | None" = None   # anchor-thread print (which shows a module range);
                                                 # Section 3's "other threads sharing this region"
                                                 # entries never fetch/print a range, so these stay
                                                 # None there even when module_context == resolved

    def __post_init__(self):
        _require_nonneg_int(self.tid, "ReportThreadInfo.tid")
        _require_optional_hex_address(self.start_address, "ReportThreadInfo.start_address")
        _require_optional_diff_str(self.backing_module, "ReportThreadInfo.backing_module")
        if self.module_context is not None and self.module_context not in _MODULE_CONTEXTS:
            raise ValueError(
                f"ReportThreadInfo.module_context must be None or one of "
                f"{_MODULE_CONTEXTS}, got {self.module_context!r}")
        if self.start_address is None and self.module_context is not None:
            raise ValueError(
                "ReportThreadInfo.module_context must be None when start_address is None "
                "-- module resolution is never attempted with no address to resolve")
        _require_optional_diff_int(self.kernel_time_100ns, "ReportThreadInfo.kernel_time_100ns")
        _require_optional_diff_int(self.user_time_100ns, "ReportThreadInfo.user_time_100ns")
        _require_optional_hex_address(self.backing_module_base, "ReportThreadInfo.backing_module_base")
        _require_optional_hex_address(self.backing_module_end, "ReportThreadInfo.backing_module_end")
        if (self.backing_module_base is None) != (self.backing_module_end is None):
            raise ValueError(
                "ReportThreadInfo.backing_module_base and backing_module_end must both be "
                "None or both be set")
        if self.backing_module_base is not None and self.module_context != MODULE_CONTEXT_RESOLVED:
            raise ValueError(
                "ReportThreadInfo.backing_module_base/backing_module_end require "
                "module_context == 'resolved'")

    def to_dict(self) -> dict:
        return {
            "tid":                  self.tid,
            "start_address":        self.start_address,
            "backing_module":       self.backing_module,
            "module_context":       self.module_context,
            "kernel_time_100ns":    self.kernel_time_100ns,
            "user_time_100ns":      self.user_time_100ns,
            "backing_module_base":  self.backing_module_base,
            "backing_module_end":   self.backing_module_end,
        }


@dataclass
class ReportRegionInfo:
    """Resolved memory-region evidence for a triage-card target.

    file_offset is an integer dump offset, not a process address.
    module_context distinguishes resolved, confirmed unregistered, and unavailable
    module evidence. mz_header_detected is None when the header read failed.

    has_injected_pe is true only for a confirmed MZ header in a confirmed
    unregistered region; it is None whenever required header or module evidence
    is unavailable. This prevents missing module data from becoming a false
    positive and failed reads from becoming a false negative.
    """
    base_address:     str
    size:             int
    protect:          str
    type:             str
    module_owner:     "str | None"
    file_offset:      "int | None"
    is_rwx_private:   bool
    module_context:        str            # resolved / unregistered / unavailable -- never null
    mz_header_detected:    "bool | None"  # null iff the header-peek read itself failed
    has_injected_pe:       "bool | None"  # see class docstring for the tri-state derivation
    protection_suspicious: bool   # `protect` matches one of the runtime-configured
                                    # suspicious_protections rules (see
                                    # dumpex.rules_pkg.loader.get_rules()) -- independent
                                    # of is_rwx_private, which additionally requires
                                    # MEM_PRIVATE. Same semantics as MemoryRegionRecord.
                                    # suspicious above, kept as a separate field (not
                                    # reused) since ReportRegionInfo's own is_rwx_private
                                    # is already a distinct, MECE-dimension-specific bool.

    def __post_init__(self):
        _require_hex_address(self.base_address, "ReportRegionInfo.base_address")
        _require_nonneg_int(self.size, "ReportRegionInfo.size")
        if not isinstance(self.protect, str) or not self.protect:
            raise ValueError("ReportRegionInfo.protect must be a non-empty string")
        if not isinstance(self.type, str) or not self.type:
            raise ValueError("ReportRegionInfo.type must be a non-empty string")
        _require_optional_diff_str(self.module_owner, "ReportRegionInfo.module_owner")
        _require_optional_diff_int(self.file_offset, "ReportRegionInfo.file_offset")
        _require_bool(self.is_rwx_private, "ReportRegionInfo.is_rwx_private")
        if self.module_context not in _MODULE_CONTEXTS:
            raise ValueError(
                f"ReportRegionInfo.module_context must be one of {_MODULE_CONTEXTS}, "
                f"got {self.module_context!r}")
        if self.mz_header_detected is not None:
            _require_bool(self.mz_header_detected, "ReportRegionInfo.mz_header_detected")
        if self.has_injected_pe is not None:
            _require_bool(self.has_injected_pe, "ReportRegionInfo.has_injected_pe")
        _require_bool(self.protection_suspicious, "ReportRegionInfo.protection_suspicious")
        if self.is_rwx_private and not self.protection_suspicious:
            raise ValueError(
                "ReportRegionInfo.is_rwx_private requires protection_suspicious -- RWX+PRIVATE "
                "is itself a suspicious-protection match")
        if self.mz_header_detected is None and self.has_injected_pe is not None:
            raise ValueError(
                "ReportRegionInfo.has_injected_pe must be None when mz_header_detected is None "
                "-- the header read itself failed, so neither can be confirmed")
        if self.mz_header_detected is False and self.has_injected_pe is not False:
            raise ValueError(
                "ReportRegionInfo.has_injected_pe must be False when mz_header_detected is "
                "False -- no MZ header means no injected-PE finding is possible")
        if self.mz_header_detected is True:
            if self.module_context == MODULE_CONTEXT_UNREGISTERED and self.has_injected_pe is not True:
                raise ValueError(
                    "ReportRegionInfo.has_injected_pe must be True when an MZ header was found "
                    "in a confirmed-unregistered region")
            if self.module_context == MODULE_CONTEXT_RESOLVED and self.has_injected_pe is not False:
                raise ValueError(
                    "ReportRegionInfo.has_injected_pe must be False when an MZ header was found "
                    "in a module confirmed resolved -- a known module's own header is expected, "
                    "not suspicious")
            if self.module_context == MODULE_CONTEXT_UNAVAILABLE and self.has_injected_pe is not None:
                raise ValueError(
                    "ReportRegionInfo.has_injected_pe must be None when an MZ header was found "
                    "but module_context is unavailable -- cannot confirm whether it is actually "
                    "unregistered")

    def to_dict(self) -> dict:
        return {
            "base_address":          self.base_address,
            "size":                  self.size,
            "protect":               self.protect,
            "type":                  self.type,
            "module_owner":          self.module_owner,
            "file_offset":           self.file_offset,
            "is_rwx_private":        self.is_rwx_private,
            "module_context":        self.module_context,
            "mz_header_detected":    self.mz_header_detected,
            "has_injected_pe":       self.has_injected_pe,
            "protection_suspicious": self.protection_suspicious,
        }


@dataclass
class ReportIocString:
    """One IOC-pattern string hit in a triage card's Section 4 -- replaces
    the earlier loose dict shape (offset/address/encoding/text/matched_grep/
    is_network_pattern with no validation at all) with a typed record the
    same way every other structured fact in this module is typed.
    `context_hex`/`context_base_address`/`context_hit_offset` are only
    populated when `is_network_pattern` is True, and are computed ONCE at
    collect time (report.py already has the full region `data` in scope
    there) rather than deferred to render time -- the render layer must
    never re-read the dump to reproduce the ±128-byte hexdump context
    (see dumpex.commands.report.render_report_console's own docstring for
    why). `context_hex` is a lowercase hex string of that bounded byte
    window (never the full region -- at most 256 bytes), safe to embed in
    JSON; `context_base_address` is that window's own first-byte address;
    `context_hit_offset` is the hit's own offset WITHIN the window (not
    the region), i.e. dumpex.core.memory._hexdump_context's own `offset`
    parameter once fed this window instead of the full region."""
    offset:              int
    address:             str
    encoding:            str
    text:                str
    is_network_pattern:  bool
    context_hex:            "str | None" = None
    context_base_address:  "str | None" = None
    context_hit_offset:    "int | None" = None

    def __post_init__(self):
        _require_nonneg_int(self.offset, "ReportIocString.offset")
        _require_hex_address(self.address, "ReportIocString.address")
        if self.encoding not in _STRING_RECORD_ENCODINGS:
            raise ValueError(
                f"ReportIocString.encoding must be one of {_STRING_RECORD_ENCODINGS}, "
                f"got {self.encoding!r}")
        if not isinstance(self.text, str):
            raise ValueError(f"ReportIocString.text must be a str, got {self.text!r}")
        _require_bool(self.is_network_pattern, "ReportIocString.is_network_pattern")
        if not self.is_network_pattern:
            if (self.context_hex is not None or self.context_base_address is not None
                    or self.context_hit_offset is not None):
                raise ValueError(
                    "ReportIocString.context_hex/context_base_address/context_hit_offset "
                    "must all be None when is_network_pattern is False -- the hexdump context "
                    "is only ever computed for a network-pattern hit")
        else:
            if not isinstance(self.context_hex, str) or not self.context_hex:
                raise ValueError(
                    "ReportIocString.context_hex must be a non-empty hex string when "
                    "is_network_pattern is True")
            if len(self.context_hex) % 2 != 0 or any(
                    c not in "0123456789abcdef" for c in self.context_hex):
                raise ValueError(
                    f"ReportIocString.context_hex must be a lowercase hex string, "
                    f"got {self.context_hex!r}")
            # Bounded to <=256 bytes (512 hex chars) -- the whole point of
            # a "context window" is that it's small and bounded, matching
            # the +-128-byte window _collect_triage_card actually builds;
            # an unbounded context_hex would defeat that guarantee for any
            # caller that bypasses report.py and builds this record
            # directly (e.g. a future producer, or a hand-built test doc).
            if len(self.context_hex) > 512:
                raise ValueError(
                    "ReportIocString.context_hex must be at most 512 hex chars (256 bytes), "
                    f"got {len(self.context_hex)} chars")
            _require_hex_address(self.context_base_address, "ReportIocString.context_base_address")
            _require_nonneg_int(self.context_hit_offset, "ReportIocString.context_hit_offset")
            context_len_bytes = len(self.context_hex) // 2
            if self.context_hit_offset >= context_len_bytes:
                raise ValueError(
                    "ReportIocString.context_hit_offset must fall within context_hex's own "
                    f"{context_len_bytes}-byte window, got context_hit_offset="
                    f"{self.context_hit_offset!r}")

    def to_dict(self) -> dict:
        return {
            "offset":               self.offset,
            "address":              self.address,
            "encoding":             self.encoding,
            "text":                 self.text,
            "is_network_pattern":   self.is_network_pattern,
            "context_hex":          self.context_hex,
            "context_base_address": self.context_base_address,
            "context_hit_offset":   self.context_hit_offset,
        }


@dataclass
class TriageCardRecord:
    """One triage card -- see this section's own header comment for why
    this is one record per card, not a tagged union of its constituent
    thread/region/string facts. `anchor_source` says which of --report-tid/
    --report-addr/--report-string produced THIS card (string-hit mode
    produces N cards, one per private hit region, each with
    anchor_source="string_hit" and anchor_address set to that region's
    base -- report_tid is never forwarded into those, see
    dumpex.commands.report's own note on why). `notable_strings` reuses
    StringRecord as-is (matched_grep always None -- --report has no
    --grep concept). `ioc_strings` is a list of ReportIocString, NOT
    StringRecord -- see that class's own docstring for why (an extra
    is_network_pattern bool plus a bounded, collect-time-computed hexdump
    context that has no meaning for plain `--strings` output).
    `findings`/`finding_details` are today's `dims`
    dict, split into its ordered keys and their detail text -- `findings`
    entries are restricted to _TRIAGE_FINDING_KEYS, the same closed
    vocabulary as
    dumpex.core.memory.INDICATOR_DIMS' own keys (unbacked_thread/
    rwx_private/injected_pe/ioc_strings), mirrored locally rather than
    imported (see this section's own note on why records.py doesn't
    import from core.memory) -- an invented finding key is rejected here,
    not just left undocumented. `verdict` is verdict_for(dims)'s output --
    provably the same MECE rule the console's own colored text renders
    from (see core.memory._verdict); __post_init__ cross-checks verdict
    against len(findings) using the same four-tier rule, mirrored locally
    for the same reason. `artifact_id` correlates to this
    card's own entry in result.artifacts when --output was given for this
    card, else None.

    `string_scan`/`string_scan_error` capture Section 4's own scan
    metadata that neither notable_strings nor ioc_strings (both filtered
    subsets) can reconstruct: `requested_bytes` is how much this card
    asked read_region() for (post MAX_REGION_READ clamping -- `clamped`
    says whether that clamp actually reduced the ask below the region's
    own size); `bytes_read` is the real `len(data)` read_region() handed
    back (which can independently come up short of `requested_bytes` when
    the dump itself doesn't back that much of the region -- `truncated`
    flags exactly that, a genuine evidence-completeness gap distinct from
    `clamped`'s own self-imposed scan-budget policy). Both None (all
    string_scan fields, string_scan_error) when region is None (Section 4
    never ran); string_scan None with string_scan_error set to the
    exception text when region is not None but the read/extraction itself
    raised. `thread_region_correlation_excluded` is True
    exactly when this card's thread was confirmed unbacked but that fact
    was excluded from `findings`/verdict because it is not correlated
    with the independently-resolved region (see
    dumpex.commands.report._collect_triage_card's own reconciliation
    note) -- a fact with no other home in this record, since `findings`
    only lists dimensions that DID fire."""
    anchor_tid:               "int | None"
    anchor_address:           "str | None"
    anchor_source:            str          # TRIAGE_ANCHOR_TID / _ADDRESS / _STRING_HIT
    thread:                   "ReportThreadInfo | None"
    region:                   "ReportRegionInfo | None"
    string_hit:               "dict | None"   # {"offset", "address", "encoding"} -- the exact
                                                # location _search_string_in_memory found the
                                                # needle at, for anchor_source == string_hit cards
                                                # only; None otherwise. Kept separate from
                                                # notable_strings/ioc_strings (Section 4's own,
                                                # independently-run string extraction, which is
                                                # not guaranteed to re-find this exact substring
                                                # position, e.g. across a min_len boundary).
    other_threads_in_region:  list         # list[ReportThreadInfo]
    notable_strings:          list         # list[StringRecord]
    ioc_strings:              list         # list[ReportIocString]
    string_scan:              "dict | None"   # {"requested_bytes", "bytes_read", "clamped",
                                                # "truncated", "total", "ascii_count", "utf16_count"}
    string_scan_error:        "str | None"
    thread_region_correlation_excluded: bool
    findings:                 list         # list[str] -- _TRIAGE_FINDING_KEYS subset that fired
    finding_details:          dict         # {key: human detail string}
    verdict:                  str          # verdict_for()'s output
    artifact_id:              "str | None"
    extract_read_clamped:     "bool | None"   # None when no --output was given for this card
                                                # (extract never attempted); True/False once it
                                                # was, whether MAX_REGION_READ clamped the bytes
                                                # actually written below the region's own size
    extract_read_truncated:   "bool | None"   # None when no --output was given for this card;
                                                # True/False once it was, whether read_region()
                                                # itself came up short of whatever was requested
                                                # (post-clamp) -- a genuine evidence gap distinct
                                                # from extract_read_clamped's own self-imposed
                                                # policy cap (same clamped-vs-truncated split as
                                                # string_scan above). True here means the written
                                                # artifact is itself incomplete, not just smaller
                                                # than the region by policy.

    def __post_init__(self):
        if self.anchor_tid is not None:
            _require_nonneg_int(self.anchor_tid, "TriageCardRecord.anchor_tid")
        _require_optional_hex_address(self.anchor_address, "TriageCardRecord.anchor_address")
        if self.anchor_source not in _TRIAGE_ANCHOR_SOURCES:
            raise ValueError(
                f"TriageCardRecord.anchor_source must be one of {_TRIAGE_ANCHOR_SOURCES}, "
                f"got {self.anchor_source!r}")
        if self.thread is not None and not isinstance(self.thread, ReportThreadInfo):
            raise TypeError("TriageCardRecord.thread must be None or a ReportThreadInfo")
        if self.region is not None and not isinstance(self.region, ReportRegionInfo):
            raise TypeError("TriageCardRecord.region must be None or a ReportRegionInfo")
        if self.string_hit is not None:
            if not isinstance(self.string_hit, dict) or set(self.string_hit.keys()) != {
                    "offset", "address", "encoding"}:
                raise ValueError(
                    "TriageCardRecord.string_hit must be None or a dict with exactly "
                    "'offset'/'address'/'encoding' keys")
            _require_nonneg_int(self.string_hit["offset"], "TriageCardRecord.string_hit['offset']")
            _require_hex_address(self.string_hit["address"], "TriageCardRecord.string_hit['address']")
            if self.string_hit["encoding"] not in _STRING_RECORD_ENCODINGS:
                raise ValueError(
                    f"TriageCardRecord.string_hit['encoding'] must be one of "
                    f"{_STRING_RECORD_ENCODINGS}, got {self.string_hit['encoding']!r}")
        if self.anchor_source == TRIAGE_ANCHOR_STRING_HIT and self.string_hit is None:
            raise ValueError(
                "TriageCardRecord.string_hit is required when anchor_source == 'string_hit'")
        if self.anchor_source != TRIAGE_ANCHOR_STRING_HIT and self.string_hit is not None:
            raise ValueError(
                "TriageCardRecord.string_hit must be None when anchor_source != 'string_hit'")
        if not isinstance(self.other_threads_in_region, list) or any(
                not isinstance(t, ReportThreadInfo) for t in self.other_threads_in_region):
            raise TypeError(
                "TriageCardRecord.other_threads_in_region must be a list of ReportThreadInfo")
        if not isinstance(self.notable_strings, list) or any(
                not isinstance(s, StringRecord) for s in self.notable_strings):
            raise TypeError("TriageCardRecord.notable_strings must be a list of StringRecord")
        if not isinstance(self.ioc_strings, list) or any(
                not isinstance(s, ReportIocString) for s in self.ioc_strings):
            raise TypeError("TriageCardRecord.ioc_strings must be a list of ReportIocString")
        if self.string_scan is not None:
            if not isinstance(self.string_scan, dict):
                raise TypeError("TriageCardRecord.string_scan must be None or a dict")
            required = {"requested_bytes", "bytes_read", "clamped", "truncated",
                        "total", "ascii_count", "utf16_count"}
            if set(self.string_scan.keys()) != required:
                raise ValueError(
                    f"TriageCardRecord.string_scan must have exactly the keys {sorted(required)}, "
                    f"got {sorted(self.string_scan.keys())}")
            for key in ("clamped", "truncated"):
                _require_bool(self.string_scan[key], f"TriageCardRecord.string_scan[{key!r}]")
            for key in ("requested_bytes", "bytes_read", "total", "ascii_count", "utf16_count"):
                _require_nonneg_int(self.string_scan[key], f"TriageCardRecord.string_scan[{key!r}]")
            if self.string_scan["bytes_read"] > self.string_scan["requested_bytes"]:
                raise ValueError(
                    "TriageCardRecord.string_scan['bytes_read'] must not exceed "
                    "['requested_bytes'] -- a read can come up short, never long")
            if self.string_scan["truncated"] != (
                    self.string_scan["bytes_read"] < self.string_scan["requested_bytes"]):
                raise ValueError(
                    "TriageCardRecord.string_scan['truncated'] must equal "
                    "bytes_read < requested_bytes")
        _require_optional_diff_str(self.string_scan_error, "TriageCardRecord.string_scan_error")
        if self.string_scan is not None and self.string_scan_error is not None:
            raise ValueError(
                "TriageCardRecord.string_scan and string_scan_error are mutually exclusive -- "
                "a scan either produced counts or failed, never both")
        _require_bool(self.thread_region_correlation_excluded,
                      "TriageCardRecord.thread_region_correlation_excluded")
        if self.extract_read_clamped is not None:
            _require_bool(self.extract_read_clamped, "TriageCardRecord.extract_read_clamped")
        if self.extract_read_truncated is not None:
            _require_bool(self.extract_read_truncated, "TriageCardRecord.extract_read_truncated")
        if (self.extract_read_clamped is None) != (self.extract_read_truncated is None):
            raise ValueError(
                "TriageCardRecord.extract_read_clamped and extract_read_truncated must both be "
                "None (no --output attempted for this card) or both be set (once it was)")
        if not isinstance(self.findings, list) or any(
                f not in _TRIAGE_FINDING_KEYS for f in self.findings):
            raise ValueError(
                f"TriageCardRecord.findings entries must all be one of {_TRIAGE_FINDING_KEYS}, "
                f"got {self.findings!r}")
        if len(set(self.findings)) != len(self.findings):
            raise ValueError("TriageCardRecord.findings must not contain duplicate keys")
        if not isinstance(self.finding_details, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in self.finding_details.items()):
            raise TypeError(
                "TriageCardRecord.finding_details must be a dict of str -> str")
        if set(self.findings) != set(self.finding_details.keys()):
            raise ValueError(
                "TriageCardRecord.findings and finding_details must name the same keys, got "
                f"findings={self.findings!r} finding_details keys={list(self.finding_details)!r}")
        if self.verdict not in _TRIAGE_VERDICTS:
            raise ValueError(
                f"TriageCardRecord.verdict must be one of {_TRIAGE_VERDICTS}, got {self.verdict!r}")
        expected_verdict = _TRIAGE_VERDICTS[min(len(self.findings), 3)]
        if self.verdict != expected_verdict:
            raise ValueError(
                f"TriageCardRecord.verdict={self.verdict!r} does not match the four-tier rule "
                f"for {len(self.findings)} finding(s) (expected {expected_verdict!r}) -- mirrors "
                f"dumpex.core.memory.verdict_for()'s own len(dims) rule")
        _require_optional_diff_str(self.artifact_id, "TriageCardRecord.artifact_id")

    def to_dict(self) -> dict:
        return {
            "anchor_tid":              self.anchor_tid,
            "anchor_address":          self.anchor_address,
            "anchor_source":           self.anchor_source,
            "thread":                  self.thread.to_dict() if self.thread else None,
            "region":                  self.region.to_dict() if self.region else None,
            "string_hit":              dict(self.string_hit) if self.string_hit else None,
            "other_threads_in_region": [t.to_dict() for t in self.other_threads_in_region],
            "notable_strings":         [s.to_dict() for s in self.notable_strings],
            "ioc_strings":             [s.to_dict() for s in self.ioc_strings],
            "string_scan":             dict(self.string_scan) if self.string_scan else None,
            "string_scan_error":       self.string_scan_error,
            "thread_region_correlation_excluded": self.thread_region_correlation_excluded,
            "findings":                list(self.findings),
            "finding_details":         dict(self.finding_details),
            "verdict":                 self.verdict,
            "artifact_id":             self.artifact_id,
            "extract_read_clamped":    self.extract_read_clamped,
            "extract_read_truncated":  self.extract_read_truncated,
        }


# ── Hunt records ───────────────────────────────────────────────────────
# One HunterRecord per hunter -- `--hunt all` produces exactly 7, in a
# fixed order; a single `--hunt <ttp>` produces exactly 1. See
# docs/developer/hunt_architecture.md for the typed projection boundary
# this section implements. `hunter`/`status`/`score`/`max_score`/
# `verdict_level`/`confidence`/`lead_count`/`review_priority` are the 7
# common judgment fields (8 minus coverage_status, which is NOT a judgment
# field -- see that doc's legend); `coverage` is a real CoverageReport
# object (dumpex.output.coverage), never a bare status string alongside
# it, so there is exactly one place this fact lives; `findings` is the
# existing dumpex.hunt._finding.Finding.to_dict() shape, unchanged;
# `details` is one of the 7 *Details types below, discriminated by
# `hunter`.
#
# All seven detail types are produced by the hunt collection path.

HUNTERS = ("injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation")
_HUNT_STATUSES = ("DETECTED", "NOT_DETECTED_IN_SCANNED_SCOPE", "INCONCLUSIVE", "NOT_EVALUATED")
_HUNT_VERDICT_LEVELS = ("clean", "possible", "likely", "high", "inconclusive", "not_evaluated")
_HUNT_CONFIDENCES = ("none", "low", "medium", "high")
_HUNT_REVIEW_PRIORITIES = ("none", "low", "medium", "high")


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
    ThreadInfo/Thread objects it replaces."""
    tid:            int
    start_address:  "str | None" = None
    ip:             "str | None" = None
    ip_reg:         "str | None" = None

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

    def to_dict(self) -> dict:
        return {"tid": self.tid, "start_address": self.start_address,
                "ip": self.ip, "ip_reg": self.ip_reg}


@dataclass
class HuntThreadRegionHit:
    """A thread correlated with a specific region -- e.g. a thread's
    current RIP/EIP executing inside a flagged allocation, or its
    StartAddress falling inside one. Raw correlation.py output is a
    `(thread_ctx_or_info, region)` tuple; a bare `HuntThreadRef` alone
    would lose WHICH region/allocation the thread was actually correlated
    with, making it impossible for a consumer to re-verify a "full
    correlation" claim against `rwx`/`hidden_pe_validated` above."""
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
    this module's own top-of-file type rule); `image_base` (the PE
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


@dataclass
class InjectionDetails:
    """`--hunt injection`'s hunter-specific evidence. `pe_read_failed`/
    `pe_short_reads` deliberately do NOT appear here -- per the field
    matrix, those are coverage counts, not evidence, and instead inform
    this hunter's own CoverageReport limitations (PE_HEADER_READ_FAILED/
    PE_HEADER_SHORT_READ, see dumpex.output.coverage)."""
    rwx:                              list   # list[HuntRegionRef]
    hidden_pe_validated:              list   # list[HuntPeHeaderHit], valid=True
    hidden_pe_unvalidated:            list   # list[HuntPeHeaderHit], valid=False (MZ-prefix only)
    suspicious_validated_pe_hits:     list   # subset of hidden_pe_validated that's scoreable
    informational_validated_pe_hits: list   # the other (context-only) subset
    threads:                          list   # list[HuntThreadRef] -- unbacked StartAddress threads
    thread_contexts:                  list   # list[HuntThreadRef] -- every parsed thread context
    rwx_and_pe_alloc_bases:           list   # list[str] -- hex allocation bases
    rip_hits:                         list   # list[HuntThreadRegionHit] -- RIP inside a flagged region
    rip_full_correlation:             list   # subset of rip_hits with full (RWX+PE) correlation
    start_hits:                       list   # list[HuntThreadRegionHit] -- StartAddress-correlated

    def __post_init__(self):
        _require_list_of(self.rwx, HuntRegionRef, "InjectionDetails.rwx")
        _require_list_of(self.hidden_pe_validated, HuntPeHeaderHit,
                          "InjectionDetails.hidden_pe_validated")
        _require_list_of(self.hidden_pe_unvalidated, HuntPeHeaderHit,
                          "InjectionDetails.hidden_pe_unvalidated")
        _require_list_of(self.suspicious_validated_pe_hits, HuntPeHeaderHit,
                          "InjectionDetails.suspicious_validated_pe_hits")
        _require_list_of(self.informational_validated_pe_hits, HuntPeHeaderHit,
                          "InjectionDetails.informational_validated_pe_hits")
        _require_list_of(self.threads, HuntThreadRef, "InjectionDetails.threads")
        _require_list_of(self.thread_contexts, HuntThreadRef, "InjectionDetails.thread_contexts")
        if not isinstance(self.rwx_and_pe_alloc_bases, list) or any(
                not isinstance(a, str) for a in self.rwx_and_pe_alloc_bases):
            raise TypeError("InjectionDetails.rwx_and_pe_alloc_bases must be a list of str")
        for a in self.rwx_and_pe_alloc_bases:
            _require_hex_address(a, "InjectionDetails.rwx_and_pe_alloc_bases[]")
        _require_list_of(self.rip_hits, HuntThreadRegionHit, "InjectionDetails.rip_hits")
        _require_list_of(self.rip_full_correlation, HuntThreadRegionHit,
                          "InjectionDetails.rip_full_correlation")
        _require_list_of(self.start_hits, HuntThreadRegionHit, "InjectionDetails.start_hits")

    def to_dict(self) -> dict:
        return {
            "rwx":                              [r.to_dict() for r in self.rwx],
            "hidden_pe_validated":               [h.to_dict() for h in self.hidden_pe_validated],
            "hidden_pe_unvalidated":             [h.to_dict() for h in self.hidden_pe_unvalidated],
            "suspicious_validated_pe_hits":       [h.to_dict() for h in self.suspicious_validated_pe_hits],
            "informational_validated_pe_hits":    [h.to_dict() for h in self.informational_validated_pe_hits],
            "threads":                            [t.to_dict() for t in self.threads],
            "thread_contexts":                    [t.to_dict() for t in self.thread_contexts],
            "rwx_and_pe_alloc_bases":             list(self.rwx_and_pe_alloc_bases),
            "rip_hits":                            [t.to_dict() for t in self.rip_hits],
            "rip_full_correlation":                [t.to_dict() for t in self.rip_full_correlation],
            "start_hits":                          [t.to_dict() for t in self.start_hits],
        }


@dataclass
class HollowingDetails:
    """Image-base evidence for ``--hunt hollowing``.

    ``image_base`` is ``None`` when the PEB is unavailable. Each tri-state
    check is ``None`` when it could not run, not a clean ``False`` result.
    """
    image_base:           "str | None"
    mem_private_at_base:  "bool | None"   # None if the image-base region wasn't found at all
    mz_header_present:    "bool | None"   # None if the header read itself failed
    is_rwx_at_base:       "bool | None"   # None if the image-base region wasn't found at all
    peb_image_path:       "str | None"
    module_name:          "str | None"    # None if no module was found at image_base
    name_mismatch:        "bool | None"   # None if module list itself was unavailable

    def __post_init__(self):
        _require_optional_hex_address(self.image_base, "HollowingDetails.image_base")
        for f_name in ("mem_private_at_base", "mz_header_present", "is_rwx_at_base", "name_mismatch"):
            v = getattr(self, f_name)
            if v is not None:
                _require_bool(v, f"HollowingDetails.{f_name}")
        _require_optional_diff_str(self.peb_image_path, "HollowingDetails.peb_image_path")
        _require_optional_diff_str(self.module_name, "HollowingDetails.module_name")

    def to_dict(self) -> dict:
        return {
            "image_base":          self.image_base,
            "mem_private_at_base": self.mem_private_at_base,
            "mz_header_present":   self.mz_header_present,
            "is_rwx_at_base":      self.is_rwx_at_base,
            "peb_image_path":      self.peb_image_path,
            "module_name":         self.module_name,
            "name_mismatch":       self.name_mismatch,
        }


@dataclass
class StompingDetails:
    """Protection leads and verified changes for ``--hunt stomping``.

    ``targeted_scope`` is present only for a targeted (``--hunt-addr``)
    rescan; see :func:`_targeted_scope_dict`.
    """
    protection_leads: list   # list[dict]
    verified_changes: list   # list[dict]
    targeted_scope:   "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        for name in ("protection_leads", "verified_changes"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"StompingDetails.{name} must be a list of dict")
        _require_optional_targeted_scope(self.targeted_scope, "StompingDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {
            "protection_leads": [dict(x) for x in self.protection_leads],
            "verified_changes": [dict(x) for x in self.verified_changes],
            **_targeted_scope_dict(self),
        }


@dataclass
class PipeDetails:
    """`--hunt pipe`'s hunter-specific evidence.

    ``targeted_scope`` is present only for a targeted (``--hunt-addr``)
    rescan; see :func:`_targeted_scope_dict`.
    """
    handle_pipes:    list   # list[dict]
    private_pipes:   list   # list[dict]
    c2_context:      list   # list[dict]
    framework_pipes: list   # list[dict]
    unbacked_in_rgn: list   # list[dict]
    targeted_scope:  "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        for name in ("handle_pipes", "private_pipes", "c2_context", "framework_pipes",
                      "unbacked_in_rgn"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"PipeDetails.{name} must be a list of dict")
        _require_optional_targeted_scope(self.targeted_scope, "PipeDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {
            "handle_pipes":    [dict(x) for x in self.handle_pipes],
            "private_pipes":   [dict(x) for x in self.private_pipes],
            "c2_context":      [dict(x) for x in self.c2_context],
            "framework_pipes": [dict(x) for x in self.framework_pipes],
            "unbacked_in_rgn": [dict(x) for x in self.unbacked_in_rgn],
            **_targeted_scope_dict(self),
        }


@dataclass
class CsBeaconDetails:
    """Decoded configuration evidence for ``--hunt cs-beacon``.

    Process addresses use normalized hex strings in this typed shape;
    dump-file offsets remain integers. ``targeted_scope`` is present only for
    a targeted (``--hunt-addr``) rescan; see :func:`_targeted_scope_dict`.
    """
    configs:        list   # list[dict]
    config_count:   int
    targeted_scope: "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        if not isinstance(self.configs, list) or any(not isinstance(x, dict) for x in self.configs):
            raise TypeError("CsBeaconDetails.configs must be a list of dict")
        _require_nonneg_int(self.config_count, "CsBeaconDetails.config_count")
        if self.config_count != len(self.configs):
            raise ValueError(
                f"CsBeaconDetails.config_count ({self.config_count}) must equal "
                f"len(configs) ({len(self.configs)})")
        _require_optional_targeted_scope(self.targeted_scope, "CsBeaconDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {"configs": [dict(x) for x in self.configs], "config_count": self.config_count,
                **_targeted_scope_dict(self)}


@dataclass
class YaraDetails:
    """`--hunt yara`'s hunter-specific evidence. YARA deliberately stays
    off the shared Finding model -- see docs/developer/hunt_architecture.md
    for why `matches` must not be reclassified as `finding`."""
    matches:        list   # list[dict]
    rules_hit:      list   # list[str]
    targeted_scope: "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        if not isinstance(self.matches, list) or any(not isinstance(x, dict) for x in self.matches):
            raise TypeError("YaraDetails.matches must be a list of dict")
        if not isinstance(self.rules_hit, list) or any(not isinstance(x, str) for x in self.rules_hit):
            raise TypeError("YaraDetails.rules_hit must be a list of str")
        _require_optional_targeted_scope(self.targeted_scope, "YaraDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {"matches": [dict(x) for x in self.matches], "rules_hit": list(self.rules_hit),
                **_targeted_scope_dict(self)}


@dataclass
class ObfuscationDetails:
    """`--hunt obfuscation`'s hunter-specific evidence -- the seven decode
    layers' own hit lists."""
    sleep_mask:        list   # list[dict]
    entropy:           list   # list[dict]
    base64:            list   # list[dict]
    xor:               list   # list[dict]
    compressed:        list   # list[dict]
    hidden_pe:         list   # list[dict]
    hidden_shellcode:  list   # list[dict]
    targeted_scope:    "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        for name in ("sleep_mask", "entropy", "base64", "xor", "compressed", "hidden_pe",
                      "hidden_shellcode"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"ObfuscationDetails.{name} must be a list of dict")
        _require_optional_targeted_scope(self.targeted_scope, "ObfuscationDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {
            "sleep_mask":       [dict(x) for x in self.sleep_mask],
            "entropy":          [dict(x) for x in self.entropy],
            "base64":           [dict(x) for x in self.base64],
            "xor":              [dict(x) for x in self.xor],
            "compressed":       [dict(x) for x in self.compressed],
            "hidden_pe":        [dict(x) for x in self.hidden_pe],
            "hidden_shellcode": [dict(x) for x in self.hidden_shellcode],
            **_targeted_scope_dict(self),
        }


_HUNTER_DETAILS_TYPES = {
    "injection":  InjectionDetails,
    "hollowing":  HollowingDetails,
    "stomping":   StompingDetails,
    "pipe":       PipeDetails,
    "cs-beacon":  CsBeaconDetails,
    "yara":       YaraDetails,
    "obfuscation": ObfuscationDetails,
}


@dataclass
class HunterRecord:
    """One hunter result in ``result.data.records``.

    ``hunter`` discriminates the seven detail types. YARA has no shared
    max-score, confidence, lead-count, or review-priority semantics, so all
    four fields are ``None`` together. Coverage is a ``CoverageReport``,
    not a second bare status/reasons representation.
    """
    hunter:          str
    status:          str
    score:           int
    max_score:       "int | None"
    verdict_level:   str
    confidence:      "str | None"
    lead_count:      "int | None"
    review_priority: "str | None"
    coverage:        CoverageReport
    findings:        list   # list[dict] -- Finding.to_dict() shape, unchanged; [] for yara
    details:         object  # one of the 7 *Details types, matching `hunter`

    def __post_init__(self):
        if self.hunter not in HUNTERS:
            raise ValueError(f"HunterRecord.hunter must be one of {HUNTERS}, got {self.hunter!r}")
        if self.status not in _HUNT_STATUSES:
            raise ValueError(
                f"HunterRecord.status must be one of {_HUNT_STATUSES}, got {self.status!r}")
        _require_nonneg_int(self.score, "HunterRecord.score")
        if self.verdict_level not in _HUNT_VERDICT_LEVELS:
            raise ValueError(
                f"HunterRecord.verdict_level must be one of {_HUNT_VERDICT_LEVELS}, "
                f"got {self.verdict_level!r}")

        yara_only_fields = {
            "max_score": self.max_score, "confidence": self.confidence,
            "lead_count": self.lead_count, "review_priority": self.review_priority,
        }
        if self.hunter == "yara":
            set_fields = [name for name, v in yara_only_fields.items() if v is not None]
            if set_fields:
                raise ValueError(
                    f"HunterRecord.{set_fields[0]} must be None for hunter='yara' "
                    f"(max_score/confidence/lead_count/review_priority are all-or-nothing null)")
        else:
            unset_fields = [name for name, v in yara_only_fields.items() if v is None]
            if unset_fields:
                raise ValueError(
                    f"HunterRecord.{unset_fields[0]} must not be None for hunter={self.hunter!r} "
                    f"(only 'yara' allows these fields to be null)")
            _require_nonneg_int(self.max_score, "HunterRecord.max_score")
            if self.confidence not in _HUNT_CONFIDENCES:
                raise ValueError(
                    f"HunterRecord.confidence must be one of {_HUNT_CONFIDENCES}, "
                    f"got {self.confidence!r}")
            _require_nonneg_int(self.lead_count, "HunterRecord.lead_count")
            if self.review_priority not in _HUNT_REVIEW_PRIORITIES:
                raise ValueError(
                    f"HunterRecord.review_priority must be one of {_HUNT_REVIEW_PRIORITIES}, "
                    f"got {self.review_priority!r}")

        if not isinstance(self.coverage, CoverageReport):
            raise TypeError("HunterRecord.coverage must be a dumpex.output.coverage.CoverageReport")
        if not isinstance(self.findings, list) or any(not isinstance(f, dict) for f in self.findings):
            raise TypeError("HunterRecord.findings must be a list of dict")
        if self.hunter == "yara" and self.findings:
            raise ValueError(
                "HunterRecord.findings must be [] for hunter='yara' -- yara deliberately stays "
                "off the shared Finding model (see the field matrix's legend)")

        expected_details_type = _HUNTER_DETAILS_TYPES[self.hunter]
        if not isinstance(self.details, expected_details_type):
            raise TypeError(
                f"HunterRecord.details must be a {expected_details_type.__name__} for "
                f"hunter={self.hunter!r}, got {type(self.details).__name__}")

    def to_dict(self) -> dict:
        return {
            "hunter":          self.hunter,
            "status":          self.status,
            "score":           self.score,
            "max_score":       self.max_score,
            "verdict_level":   self.verdict_level,
            "confidence":      self.confidence,
            "lead_count":      self.lead_count,
            "review_priority": self.review_priority,
            "coverage": {
                "status":      self.coverage.status.value,
                "reasons":     self.coverage.reasons,
                "sources":     {name: obs.to_dict() for name, obs in self.coverage.sources.items()},
                "limitations": [lim.to_dict() for lim in self.coverage.limitations],
            },
            "findings": list(self.findings),
            "details":  self.details.to_dict(),
        }


# ── --process records (issue #40) ───────────────────────────────────────
# See docs/developer/recon_process_sysinfo_handles_contract.md §3.1/§3.4/§3.5 for the
# frozen JSON shape. identity_evidence's misc_info_claim/peb_claim/
# module_claim/main_image_pe sub-objects are built as plain dicts by
# dumpex.commands.process: a direct, fixed translation of
# dumpex.core.process_info's own frozen claim dataclasses (already
# validated at THAT boundary) into the wire's null/hex-address/UTC-string
# conventions, with no independent invariants of their own to enforce a
# second time. identity_evidence's own `diagnostics` entries, and every
# `iat.diagnostics` entry, are NOT plain dicts -- both go through
# ProcessDiagnosticRecord below (constructed, then .to_dict()'d) so a
# malformed diagnostic (an unknown severity, a non-positive
# affected_count, ...) is rejected at construction time regardless of
# which of the two arrays it ends up in, rather than only the IAT side
# being checked.

_IMPORT_BY_VALUES = ("name", "ordinal", "unavailable")
_PROCESS_DIAGNOSTIC_SEVERITIES = ("info", "warning")


def _require_optional_nonneg_int(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
        raise ValueError(f"{field_name} must be None or a non-negative plain int (not bool), "
                          f"got {value!r}")


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
    rather than an always-present dict with its own null members."""
    process_name:        "str | None"
    pid:                  "int | None"
    process_path:         "str | None"
    command_line:         "str | None"
    process_start_utc:    "str | None"
    image_base_address:   "str | None"
    iat:                  IatRecord
    identity_evidence:    dict
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
        }
        if self.peb_extended is not None:
            out["peb_extended"] = copy.deepcopy(self.peb_extended)
        return out


# ── --handles records (issue #42) ───────────────────────────────────────
# See docs/developer/recon_process_sysinfo_handles_contract.md §5.2 for the frozen
# JSON shape. One record per HandleDataStream descriptor whose Handle
# value is usable (§5.2.2 -- the ONE normalization failure that discards
# a descriptor); every other field degrades to null in place rather than
# costing the record.

HANDLE_NAME_STATUSES = ("ok", "unnamed", "unreadable")
# ^ §5.2.1's three-way discriminator, exported because both the record
# and its console renderer (dumpex.commands.handles) branch on it, and a
# fourth value invented at either end would silently mean "not ok".

# The console/summary labels for the two non-"ok" statuses. Frozen here,
# next to the vocabulary itself, so `by_type` bucketing and the console's
# Type/Object columns can never disagree about what an unnamed or
# unreadable name is called (§5.6 requires both to distinguish them, and
# the two must never merge into one bucket).
HANDLE_NAME_STATUS_LABELS = {
    "unnamed":    "(unnamed)",
    "unreadable": "(unreadable)",
}

# Those two labels are dumpex's own words, but a captured name is an
# arbitrary string from the dump and can be either of them verbatim.
# Every projection of a name to display text goes through
# handle_name_display() below, which reserves the labels for the null-name
# statuses and suffixes a captured name that collides -- so the labels
# always mean "the dump recorded no name" / "the name could not be read",
# in the summary and in the console table alike (§5.6).
HANDLE_RESERVED_NAME_LABELS = frozenset(HANDLE_NAME_STATUS_LABELS.values())
HANDLE_CAPTURED_NAME_SUFFIX = " [captured name]"


def handle_name_display(value: "str | None", status: str) -> str:
    """§5.6: a name is printed as itself when it read, and otherwise as
    the label for ITS OWN status -- never a shared placeholder that would
    tell a reader a handle is anonymous when its name was actually lost.
    Each of a record's two names goes through this independently.

    A captured name equal to one of the two reserved labels is suffixed
    rather than printed as-is: the labels are claims about EVIDENCE ("no
    name was recorded" / "the name could not be read"), and a dump must
    not be able to make dumpex state either one about a handle whose name
    read perfectly well. The record layer is unaffected -- `type_name`
    and `type_name_status` there are already unambiguous; this is purely
    the display projection, shared by the console table and
    `summary.by_type` so the two can never describe the same handle
    differently.

    A captured name that ALREADY ends with the suffix is suffixed too,
    which is what makes this projection injective: without it, a dump
    carrying both `(unnamed)` and `(unnamed) [captured name]` would map
    them to the same label, and the two call sites would then have to
    disambiguate separately -- which is exactly how they drifted apart
    once already (the summary appended a second suffix while the console
    table showed the two handles identically). Injective here means
    neither call site needs any cross-row state to stay consistent:

        f(x) = x + s   if x is a reserved label or x ends with s
        f(x) = x       otherwise

    f(x1) == f(x2) forces x1 == x2 -- x1 + s == x2 would require x2 to
    end with s, in which case f(x2) is x2 + s, not x2."""
    if status != "ok":
        return HANDLE_NAME_STATUS_LABELS[status]
    if value in HANDLE_RESERVED_NAME_LABELS or value.endswith(HANDLE_CAPTURED_NAME_SUFFIX):
        return value + HANDLE_CAPTURED_NAME_SUFFIX
    return value


@dataclass(frozen=True)
class HandleRecord:
    """One `--handles` record -- §5.2. `handle` is a fixed-width hex
    string (§1.3) and is never null: it is the record's only identity and
    §5.4's sort key, so a descriptor without a usable one is discarded by
    the collector instead of reaching this type. `attributes`/
    `granted_access` stay RAW, undecoded masks as plain integers on the
    wire (§5.2) -- console rendering formats granted_access as hex, which
    is a presentation choice, not this record's type.

    The two `*_status` fields are §5.2.1's independent discriminators:
    `null` alone cannot distinguish "this handle has no name" from "this
    handle's name could not be read", and the two fail independently
    (separate RVAs, separate bounded reads), so each name carries its
    own. All nine combinations are representable, and the pairing rule --
    a value is non-null if and only if its status is "ok" -- is enforced
    here rather than left to the collector's discipline, since a record
    claiming "ok" with a null value (or a decoded name filed as
    "unreadable") would make the console and every JSON consumer
    contradict the coverage limitations derived from the same statuses."""
    handle:              str
    type_name:           "str | None"
    type_name_status:    str
    object_name:         "str | None"
    object_name_status:  str
    attributes:          "int | None"
    granted_access:      "int | None"
    handle_count:        "int | None"
    pointer_count:       "int | None"

    def __post_init__(self):
        _require_hex_address(self.handle, "HandleRecord.handle")
        for field_name in ("type_name", "object_name"):
            value = getattr(self, field_name)
            status = getattr(self, f"{field_name}_status")
            if status not in HANDLE_NAME_STATUSES:
                raise ValueError(
                    f"HandleRecord.{field_name}_status must be one of {HANDLE_NAME_STATUSES}, "
                    f"got {status!r}")
            if status == "ok":
                # Non-empty specifically: §1.4 forbids "" on the wire, and
                # §5.2.1 files a successfully-read zero-length name as
                # "unnamed" (nothing was lost), never as "ok".
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"HandleRecord.{field_name} must be a non-empty string when "
                        f"{field_name}_status is 'ok', got {value!r}")
            elif value is not None:
                raise ValueError(
                    f"HandleRecord.{field_name} must be None when {field_name}_status is "
                    f"{status!r}, got {value!r}")
        # Non-negative rather than merely int: all four come from unsigned
        # fixed-width descriptor fields, so a negative value would mean a
        # signedness bug upstream, not evidence worth publishing.
        _require_optional_nonneg_int(self.attributes, "HandleRecord.attributes")
        _require_optional_nonneg_int(self.granted_access, "HandleRecord.granted_access")
        _require_optional_nonneg_int(self.handle_count, "HandleRecord.handle_count")
        _require_optional_nonneg_int(self.pointer_count, "HandleRecord.pointer_count")

    def to_dict(self) -> dict:
        return {
            "handle":              self.handle,
            "type_name":           self.type_name,
            "type_name_status":    self.type_name_status,
            "object_name":         self.object_name,
            "object_name_status":  self.object_name_status,
            "attributes":          self.attributes,
            "granted_access":      self.granted_access,
            "handle_count":        self.handle_count,
            "pointer_count":       self.pointer_count,
        }


# ── --profile records (issue #95) ───────────────────────────────────────
# See docs/developer/recon_profile_contract.md for the frozen shape. --profile is a
# capability MAP, never a verdict: nothing here may carry malicious/clean,
# confidence, ATT&CK, or hunter-score semantics (that is a hard non-goal
# of #95) -- every closed-vocabulary field below spells out an EVIDENCE
# fact ("this stream is present/absent/failed", "this capability's
# required evidence exists or doesn't"), never an interpretation of it.
# "Profile describes what evidence exists. Hunters interpret that
# evidence" (issue #95 / discussion #94).


class StreamParserState(str, Enum):
    PARSED        = "parsed"          # present; dumpex parsed it (a countable collection
                                        # with >=1 item, or a singular non-collection stream)
    PRESENT_EMPTY = "present_empty"   # present; dumpex parsed it, verified zero items
    UNPARSED      = "unparsed"        # present; dumpex has no parser registered for this
                                        # stream type (covers every recognized-but-
                                        # unimplemented MINIDUMP_STREAM_TYPE and every
                                        # unrecognized numeric type alike)
    FAILED        = "failed"          # present; dumpex attempted to parse it and it raised
    INDETERMINATE = "indeterminate"   # present; >=1 OTHER directory entry shares this same
                                        # stream type, and open_dump()'s own single
                                        # mf.<attr>/_dumpex_stream_failures pair cannot be
                                        # attributed back to any ONE of the duplicate
                                        # entries with confidence -- see
                                        # dumpex.commands.profile's own docstring on why


_STREAM_PARSER_STATES = tuple(s.value for s in StreamParserState)
# States for which record_count is REQUIRED to be exactly 0 (present_empty)
# or forbidden entirely (unparsed/indeterminate -- dumpex never counted
# anything for either). PARSED/FAILED are validated individually below:
# PARSED may carry a real count or None (a singular stream has none to
# carry); FAILED is always None (nothing was successfully counted).
_STREAM_STATE_FORBIDS_COUNT = (StreamParserState.UNPARSED.value, StreamParserState.INDETERMINATE.value,
                                StreamParserState.FAILED.value)


@dataclass(frozen=True)
class ProfileStreamEntry:
    """One row of the dump's own MINIDUMP_DIRECTORY table. Ordering across
    the whole `ProfileRecord.streams` tuple is directory order -- the
    order open_dump() itself read the entries in -- never sorted by type
    or name; a duplicate stream type or an unrecognized numeric type each
    still gets its own row rather than being merged, deduplicated, or
    dropped."""
    directory_index:   int            # 0-based position in the dump's own directory table
    stream_type_id:    int            # raw numeric MINIDUMP_STREAM_TYPE value -- always present,
                                        # even for a type this build's minidump library has never heard of
    stream_type_name:  "str | None"   # the enum member's own name, or None when stream_type_id
                                        # is not one of MINIDUMP_STREAM_TYPE's recognized values
    parser_state:      str            # StreamParserState
    record_count:      "int | None"   # items dumpex parsed for this entry, only when that count
                                        # is both meaningful (a collection stream) and unambiguous
                                        # (parser_state is parsed or present_empty)
    detail:            "str | None"   # FAILED's parser error text, INDETERMINATE's explanation of
                                        # which other directory_index(es) it conflicts with, or (only
                                        # for parsed) an explicit note that the stream declares more
                                        # items than dumpex actually read (e.g. HandleDataStream's own
                                        # NumberOfDescriptors exceeding len(handles)) -- optional even
                                        # for parsed, since most parsed streams have nothing to note;
                                        # always None for present_empty/unparsed, which have nothing a
                                        # detail could explain

    def __post_init__(self):
        _require_nonneg_int(self.directory_index, "ProfileStreamEntry.directory_index")
        _require_nonneg_int(self.stream_type_id, "ProfileStreamEntry.stream_type_id")
        if self.stream_type_name is not None and (
                not isinstance(self.stream_type_name, str) or not self.stream_type_name):
            raise ValueError(
                f"ProfileStreamEntry.stream_type_name must be None or a non-empty string, "
                f"got {self.stream_type_name!r}")
        if self.parser_state not in _STREAM_PARSER_STATES:
            raise ValueError(
                f"ProfileStreamEntry.parser_state must be one of {_STREAM_PARSER_STATES}, "
                f"got {self.parser_state!r}")
        _require_optional_nonneg_int(self.record_count, "ProfileStreamEntry.record_count")
        _require_optional_str(self.detail, "ProfileStreamEntry.detail")

        if self.parser_state == StreamParserState.PRESENT_EMPTY.value and self.record_count != 0:
            raise ValueError(
                "ProfileStreamEntry.record_count must be exactly 0 when parser_state is "
                f"present_empty, got {self.record_count!r}")
        if self.parser_state in _STREAM_STATE_FORBIDS_COUNT and self.record_count is not None:
            raise ValueError(
                f"ProfileStreamEntry.record_count must be None when parser_state is "
                f"{self.parser_state!r}, got {self.record_count!r}")
        if self.parser_state == StreamParserState.FAILED.value and not self.detail:
            raise ValueError("ProfileStreamEntry.detail is required when parser_state is failed")
        if self.parser_state == StreamParserState.INDETERMINATE.value and not self.detail:
            raise ValueError("ProfileStreamEntry.detail is required when parser_state is indeterminate")
        # present_empty/unparsed have nothing a detail could explain --
        # PARSED is the one additional state allowed to carry one
        # (optionally: most parsed streams have no note at all), for a
        # stream whose own declared item count exceeds what dumpex
        # actually read (e.g. a truncated HandleDataStream) -- a
        # genuine, if incomplete, parse is not FAILED or INDETERMINATE,
        # but the shortfall must still be sayable somewhere.
        if (self.parser_state in (StreamParserState.PRESENT_EMPTY.value, StreamParserState.UNPARSED.value)
                and self.detail is not None):
            raise ValueError(
                f"ProfileStreamEntry.detail must be None when parser_state is "
                f"{self.parser_state!r}, got {self.detail!r}")

    def to_dict(self) -> dict:
        return {
            "directory_index":  self.directory_index,
            "stream_type_id":   self.stream_type_id,
            "stream_type_name": self.stream_type_name,
            "parser_state":     self.parser_state,
            "record_count":     self.record_count,
            "detail":           self.detail,
        }


def _require_optional_str(value, field_name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field_name} must be None or a string, got {value!r}")


@dataclass(frozen=True)
class ProfileMemoryCapture:
    """Explicit memory-capture facts, kept independent per §5.3.2 of
    docs/developer/recon_profile_contract.md: "Do not infer MiniDumpWithFullMemory
    from Memory64ListStream alone. Report the raw flag and observed memory
    evidence independently." `full_memory_flag_set` is read ONLY from the
    header's own MINIDUMP_TYPE flags (None whenever `ProfileRecord.
    raw_flags` itself is None); `memory64_list_present`/`memory_list_present`
    and the two counts below are read ONLY from the dump's own directory
    table and parsed segment lists. Neither side is ever derived from the
    other, and a caller must not collapse them into one boolean."""
    full_memory_flag_set:    "bool | None"
    memory64_list_present:   bool
    memory_list_present:     bool
    captured_segment_count:  "int | None"   # len() of the preferred (Memory64-over-Memory)
                                              # segment table dumpex.core.memory.get_memory_segments()
                                              # returns; None iff neither stream parsed at all
    captured_bytes_total:    "int | None"   # sum of that same table's own segment sizes

    def __post_init__(self):
        if self.full_memory_flag_set is not None and not isinstance(self.full_memory_flag_set, bool):
            raise ValueError(
                f"ProfileMemoryCapture.full_memory_flag_set must be None or a bool, "
                f"got {self.full_memory_flag_set!r}")
        _require_bool(self.memory64_list_present, "ProfileMemoryCapture.memory64_list_present")
        _require_bool(self.memory_list_present, "ProfileMemoryCapture.memory_list_present")
        _require_optional_nonneg_int(self.captured_segment_count,
                                      "ProfileMemoryCapture.captured_segment_count")
        _require_optional_nonneg_int(self.captured_bytes_total,
                                      "ProfileMemoryCapture.captured_bytes_total")
        if (self.captured_segment_count is None) != (self.captured_bytes_total is None):
            raise ValueError(
                "ProfileMemoryCapture.captured_segment_count and captured_bytes_total must "
                f"both be None or both set together, got captured_segment_count="
                f"{self.captured_segment_count!r} captured_bytes_total={self.captured_bytes_total!r}")

    def to_dict(self) -> dict:
        return {
            "full_memory_flag_set":   self.full_memory_flag_set,
            "memory64_list_present":  self.memory64_list_present,
            "memory_list_present":    self.memory_list_present,
            "captured_segment_count": self.captured_segment_count,
            "captured_bytes_total":   self.captured_bytes_total,
        }


class CapabilityStatus(str, Enum):
    AVAILABLE   = "available"
    LIMITED     = "limited"
    UNAVAILABLE = "unavailable"


_CAPABILITY_STATUSES = tuple(s.value for s in CapabilityStatus)


@dataclass(frozen=True)
class CapabilityDefinition:
    """One row of the closed, frozen analysis-capability registry --
    the SINGLE source of truth both `ProfileCapabilityEntry.__post_init__`
    (construction-time validation, below) and dumpex.commands.profile's
    own collector logic read from, so a typo or a future capability edit
    made in only one place now fails loudly at record-construction time
    instead of silently producing a self-consistent-but-wrong record
    (e.g. a `handle_analysis` entry built with `required_source_groups=
    (("threads",),)` -- internally consistent by every OTHER rule this
    type enforces, but factually wrong for that capability id).

    `required_source_groups` is a tuple of OR-groups (see
    docs/developer/recon_profile_contract.md §4.2): each group is one or more
    alternative source names where at least one must be usable; a
    single-member group is an ordinary hard requirement. `label` is the
    console's own display name (dumpex.commands.profile.
    render_profile_console) -- kept here, not hand-duplicated in the
    renderer, for the same anti-drift reason as everything else in this
    registry."""
    capability_id:            str
    label:                      str
    required_source_groups:      tuple   # tuple[tuple[str, ...], ...]
    optional_sources:              tuple   # tuple[str]

    @property
    def required_sources(self) -> tuple:
        """The flattened, order-preserving, deduplicated union of every
        required group's members -- the same derivation
        ProfileCapabilityEntry.required_sources is validated to equal."""
        return tuple(dict.fromkeys(
            name for group in self.required_source_groups for name in group))


# The closed, frozen analysis-capability registry -- issue #95's own six
# first-release capability ids, in this fixed order. Chosen to match
# dumpex's ACTUAL current collectors/hunters, never a claim invented for
# --profile alone:
#
#   memory_region_analysis      -- dumpex.commands.list_cmd (--list):
#                                   MemoryInfoListStream alone.
#   module_analysis               -- dumpex.commands.modules (--modules):
#                                   ModuleListStream alone.
#   injection_artifact_analysis    -- dumpex.hunt.injection: its own
#                                   evaluation gate is evaluation_sources=
#                                   ("memory_info", "thread_info")
#                                   (dumpex.hunt.injection.report_facts.
#                                   project_coverage_report) -- an
#                                   OR-group, not "both required": the
#                                   hunter still RUNS (and reports real
#                                   PE_HEADER_READ_FAILED/_SHORT_READ
#                                   per-region facts) with EITHER
#                                   MemoryInfoListStream or
#                                   ThreadInfoListStream alone, and even
#                                   with zero captured memory bytes -- a
#                                   missing memory_content is a per-region
#                                   read failure the hunter reports, not a
#                                   reason to refuse to run at all.
#                                   ModuleListStream/ThreadListStream/
#                                   memory_content are therefore optional
#                                   enrichment here, matching the hunter's
#                                   own SourceRequirement-only (never
#                                   evaluation-group) treatment of them.
#   thread_analysis                 -- dumpex.commands.threads (--threads):
#                                   its own evaluation_sources=("threads",
#                                   "thread_info") is likewise an OR-group
#                                   (collect_threads() builds real records
#                                   from ThreadInfoListStream alone when
#                                   ThreadListStream is absent, reporting a
#                                   specific field-level limitation, not
#                                   not_evaluated) -- ModuleListStream
#                                   (start-address classification) is the
#                                   only true optional enrichment.
#   handle_analysis                  -- dumpex.commands.handles (--handles,
#                                   issue #42): HandleDataStream alone.
#   injector_handle_assessment         -- the SAME HandleDataStream evidence
#                                   handle_analysis uses, answering a DIFFERENT
#                                   analytical question (discussion #94's own
#                                   "handle-based assessment of potential
#                                   injector activity") that no dumpex hunter
#                                   implements yet (see #95's own non-goals:
#                                   "no automatic hunter integration ...
#                                   shared hunter consumption is follow-on
#                                   work") -- this capability id exists so a
#                                   dump's EVIDENCE BOUNDARY for that future
#                                   work is already visible today.
#                                   ThreadListStream is optional
#                                   cross-referencing context.
CAPABILITY_REGISTRY = (
    CapabilityDefinition("memory_region_analysis", "Memory-region analysis",
                          (("memory_info",),), ()),
    CapabilityDefinition("module_analysis", "Module analysis",
                          (("modules",),), ()),
    CapabilityDefinition("injection_artifact_analysis", "Injection-artifact analysis",
                          (("memory_info", "thread_info"),),
                          ("modules", "threads", "memory_content")),
    CapabilityDefinition("thread_analysis", "Thread analysis",
                          (("threads", "thread_info"),), ("modules",)),
    CapabilityDefinition("handle_analysis", "Handle analysis",
                          (("handles",),), ()),
    CapabilityDefinition("injector_handle_assessment", "Injector-handle assessment",
                          (("handles",),), ("threads",)),
)

# The frozen, ordered set of capability ids the first release covers --
# ProfileRecord.__post_init__ requires ProfileRecord.capabilities to
# carry EXACTLY these ids, in EXACTLY this order, every time: a closed
# matrix, not an open-ended list a future caller could silently add to or
# reorder. Derived from CAPABILITY_REGISTRY rather than hand-listed a
# second time, so the id set and its order can never drift from the
# registry that also defines each id's own source rules.
CAPABILITY_IDS = tuple(d.capability_id for d in CAPABILITY_REGISTRY)

CAPABILITY_BY_ID = MappingProxyType({d.capability_id: d for d in CAPABILITY_REGISTRY})


class CapabilityLimitationCode(str, Enum):
    REQUIRED_SOURCE_ABSENT = "REQUIRED_SOURCE_ABSENT"   # a source this capability REQUIRES
                                                          # is not present in the dump at all
    REQUIRED_SOURCE_FAILED = "REQUIRED_SOURCE_FAILED"    # a required source is present and
                                                          # dumpex genuinely attempted to parse
                                                          # it, and that attempt raised
    REQUIRED_SOURCE_INDETERMINATE = "REQUIRED_SOURCE_INDETERMINATE"
    # ^ a required source's own stream type has 2+ directory entries
    # (dumpex.output.records.StreamParserState.INDETERMINATE, §2.4 of
    # docs/developer/recon_profile_contract.md) -- open_dump() keeps only ONE
    # mf.<attr>/failure pair per stream TYPE, so whether that surviving
    # state reflects a clean parse or a failure cannot be attributed to
    # any one physical entry. Deliberately NOT REQUIRED_SOURCE_FAILED:
    # that code is a positive claim ("dumpex attempted to parse this and
    # it raised"), which is not always true here -- every duplicate entry
    # may in fact have parsed cleanly. Both still make the capability
    # unavailable (the evidence cannot be trusted either way), but the
    # WORDING must not assert a parse failure that may never have
    # happened.
    OPTIONAL_SOURCE_ABSENT = "OPTIONAL_SOURCE_ABSENT"    # a source that is PURELY optional
                                                          # (never a member of any required
                                                          # OR-group) is absent -- degrades to
                                                          # limited, never erases the required
                                                          # side's own available evidence
    OPTIONAL_SOURCE_FAILED = "OPTIONAL_SOURCE_FAILED"    # same, but present and could not be
                                                          # parsed
    OPTIONAL_SOURCE_INDETERMINATE = "OPTIONAL_SOURCE_INDETERMINATE"
    # ^ REQUIRED_SOURCE_INDETERMINATE's companion for a PURELY optional source.
    REQUIRED_GROUP_MEMBER_ABSENT = "REQUIRED_GROUP_MEMBER_ABSENT"
    # ^ This source IS a member of one of the capability's own required
    # OR-groups (§4.2 of docs/developer/recon_profile_contract.md -- e.g.
    # thread_analysis's ("threads", "thread_info") group), but a
    # DIFFERENT member of that SAME group already satisfies the
    # requirement, so the group as a whole is met and this member's own
    # absence only degrades the result to `limited`. Deliberately NOT
    # OPTIONAL_SOURCE_ABSENT: that code's fixed template says "optional
    # corroborating evidence", which is false for a source the registry
    # genuinely requires (just not THIS specific one, given a sibling
    # covered it) -- publishing "optional" for a required_sources member
    # is the same class of fabricated-detail problem
    # REQUIRED_SOURCE_INDETERMINATE exists to prevent, on a different
    # axis (source-vs-code contradiction rather than parse-outcome
    # wording).
    REQUIRED_GROUP_MEMBER_FAILED = "REQUIRED_GROUP_MEMBER_FAILED"
    # ^ REQUIRED_GROUP_MEMBER_ABSENT's companion: the unsatisfied sibling
    # is present but failed to parse, rather than merely absent.
    REQUIRED_GROUP_MEMBER_INDETERMINATE = "REQUIRED_GROUP_MEMBER_INDETERMINATE"
    # ^ REQUIRED_GROUP_MEMBER_ABSENT's companion: the unsatisfied sibling
    # is ambiguous (§2.4 -- duplicate directory entries), rather than
    # absent or genuinely failed.
    REQUIRED_SOURCE_TRUNCATED = "REQUIRED_SOURCE_TRUNCATED"
    # ^ A required-group member (satisfying its own group -- whether that
    # group has one member or several) is present, unambiguous, and
    # genuinely parsed -- but the underlying stream itself declares MORE
    # items than dumpex actually read (e.g. HandleDataStream's own
    # NumberOfDescriptors exceeding len(handles): issue #86's own
    # MAX_HANDLE_DESCRIPTORS cap, a DataSize too small for every declared
    # descriptor, or the file itself ending early). The group is still
    # satisfied -- real, examinable (if incomplete) data exists, so this
    # contributes to `limited`, never `unavailable` -- but the shortfall
    # must not stay silent (the same "real numbers are kept, but the fact
    # must not be silent" reasoning PROFILE_MEMORY_CONTENT_FALLBACK
    # already applies to a fallback stream, applied here to a single
    # stream's own incomplete parse instead). Distinct from
    # REQUIRED_GROUP_MEMBER_*, which describes an UNSATISFIED sibling --
    # a truncated source is the satisfying one (or the capability's only
    # option), just incompletely so.
    OPTIONAL_SOURCE_TRUNCATED = "OPTIONAL_SOURCE_TRUNCATED"
    # ^ REQUIRED_SOURCE_TRUNCATED's companion for a PURELY optional source.


_CAPABILITY_LIMITATION_CODES = tuple(c.value for c in CapabilityLimitationCode)
_REQUIRED_LIMITATION_CODES = (CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
                               CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value,
                               CapabilityLimitationCode.REQUIRED_SOURCE_INDETERMINATE.value)
_OPTIONAL_LIMITATION_CODES = (CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
                               CapabilityLimitationCode.OPTIONAL_SOURCE_FAILED.value,
                               CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value)
_REQUIRED_GROUP_MEMBER_LIMITATION_CODES = (
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value,
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_FAILED.value,
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_INDETERMINATE.value)
_TRUNCATED_LIMITATION_CODES = (CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value,
                                CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value)

# The human-facing minidump stream/source name for every source id the
# capability registry can name -- used ONLY by render_capability_limitation()
# below, never by a record's own `source` field (which always keeps the
# internal key, e.g. "handles", matching the same key CoverageReport.
# sources already uses elsewhere in this codebase).
CAPABILITY_SOURCE_DISPLAY_NAMES = {
    "memory_info":     "MemoryInfoListStream",
    "modules":         "ModuleListStream",
    "threads":         "ThreadListStream",
    "thread_info":     "ThreadInfoListStream",
    "handles":         "HandleDataStream",
    "sysinfo":         "SystemInfoStream",
    "memory_content":  "captured memory content (Memory64ListStream/MemoryListStream)",
}

_CAPABILITY_LIMITATION_TEMPLATES = {
    CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value:
        "{name} is not present in this dump",
    CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value:
        "{name} is present in this dump but could not be parsed",
    CapabilityLimitationCode.REQUIRED_SOURCE_INDETERMINATE.value:
        "{name} has duplicate directory entries; its parse outcome cannot be attributed to "
        "one entry with confidence",
    CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value:
        "{name} is not present in this dump (optional corroborating evidence)",
    CapabilityLimitationCode.OPTIONAL_SOURCE_FAILED.value:
        "{name} is present in this dump but could not be parsed (optional corroborating evidence)",
    CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value:
        "{name} has duplicate directory entries; its parse outcome cannot be attributed to "
        "one entry with confidence (optional corroborating evidence)",
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value:
        "{name} is not present in this dump, but a different required-group member for this "
        "capability already is -- treated as a degraded (not blocking) gap",
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_FAILED.value:
        "{name} is present in this dump but could not be parsed, but a different "
        "required-group member for this capability already is usable -- treated as a "
        "degraded (not blocking) gap",
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_INDETERMINATE.value:
        "{name} has duplicate directory entries; its parse outcome cannot be attributed to "
        "one entry with confidence, but a different required-group member for this "
        "capability already is usable -- treated as a degraded (not blocking) gap",
    CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value:
        "{name} is present and was parsed, but declares more items than dumpex actually "
        "read -- the shortfall was not read (and was not silently discarded)",
    CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value:
        "{name} is present and was parsed, but declares more items than dumpex actually "
        "read -- the shortfall was not read (and was not silently discarded) (optional "
        "corroborating evidence)",
}


def render_capability_limitation(code: str, source: str) -> str:
    """The ONE place a CapabilityLimitation becomes human text -- mirrors
    dumpex.output.coverage.render_limitation()'s "never composed ad hoc at
    the call site" rule, scoped to this closed, four-code vocabulary."""
    name = CAPABILITY_SOURCE_DISPLAY_NAMES.get(source, source)
    return _CAPABILITY_LIMITATION_TEMPLATES[code].format(name=name)


@dataclass(frozen=True)
class CapabilityLimitation:
    """One reason ONE capability is limited or unavailable -- never a
    command-level dumpex.output.coverage.CoverageLimitation (a different
    axis: this describes an ANALYSIS CAPABILITY's own evidence gap, not
    whether --profile itself completed). `detail` is derived, never
    caller-composed, from (code, source) via render_capability_limitation()
    -- see that function's own docstring."""
    code:   str   # CapabilityLimitationCode
    source: str   # one of the owning ProfileCapabilityEntry's own required_sources/optional_sources

    def __post_init__(self):
        if self.code not in _CAPABILITY_LIMITATION_CODES:
            raise ValueError(
                f"CapabilityLimitation.code must be one of {_CAPABILITY_LIMITATION_CODES}, "
                f"got {self.code!r}")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError(f"CapabilityLimitation.source must be a non-empty string, got {self.source!r}")

    def to_dict(self) -> dict:
        return {"code": self.code, "source": self.source,
                "detail": render_capability_limitation(self.code, self.source)}


@dataclass(frozen=True)
class ProfileCapabilityEntry:
    """One row of the closed analysis-capability matrix.
    `required_source_groups`/`optional_sources` are this capability's OWN
    frozen requirement rule (mirrors the real collector/hunter that
    capability describes -- see docs/developer/recon_profile_contract.md §4.2),
    carried on the record itself so a consumer never has to re-derive
    "why" from the registry module out of band.

    `required_source_groups` is a tuple of OR-**groups**: each group is
    one or more alternative source names where at least one must be
    usable for the capability to be anything but `unavailable` (a
    single-member group is an ordinary hard requirement). This is the
    actual rule §4.3 applies -- NOT flattened away, because a group
    member that goes unsatisfied while a SIBLING in the same group
    satisfies it is a materially different fact from a source that is
    purely optional: publishing the sibling's own gap as
    OPTIONAL_SOURCE_* (this type's own EARLIER shape) asserted "optional
    corroborating evidence" for a source the registry genuinely requires,
    which is exactly the kind of fabricated-detail problem
    REQUIRED_SOURCE_INDETERMINATE already exists to prevent on a
    different axis -- REQUIRED_GROUP_MEMBER_* is the dedicated,
    accurate code for it instead (§6.2).

    `required_sources` is kept alongside as the flattened, deduplicated,
    order-preserving union of every group's members -- for a consumer
    that only wants "which sources matter at all", and validated below
    to always equal exactly that derivation, so the two can never drift.

    `status` and `limitations` are cross-validated against each other and
    against required_source_groups/optional_sources below: a caller
    cannot construct e.g. status="available" while still attaching a
    REQUIRED_SOURCE_ABSENT limitation, status="unavailable" with none at
    all, or an OPTIONAL_SOURCE_* limitation naming a source that is
    actually a required-group member -- the exact "must be technically
    enforced, not caller discipline" rule this whole record family exists
    to satisfy."""
    capability_id:            str
    status:                    str      # CapabilityStatus
    required_source_groups:    tuple    # tuple[tuple[str, ...], ...]
    required_sources:            tuple    # tuple[str] -- flattened required_source_groups
    optional_sources:              tuple    # tuple[str]
    limitations:                    tuple    # tuple[CapabilityLimitation]

    def __post_init__(self):
        if self.capability_id not in CAPABILITY_IDS:
            raise ValueError(
                f"ProfileCapabilityEntry.capability_id must be one of {CAPABILITY_IDS}, "
                f"got {self.capability_id!r}")
        if self.status not in _CAPABILITY_STATUSES:
            raise ValueError(
                f"ProfileCapabilityEntry.status must be one of {_CAPABILITY_STATUSES}, "
                f"got {self.status!r}")

        if not isinstance(self.required_source_groups, tuple) or not self.required_source_groups:
            raise ValueError(
                "ProfileCapabilityEntry.required_source_groups must be a non-empty tuple of "
                f"groups -- a capability with no required evidence at all cannot be "
                f"meaningfully gated, got {self.required_source_groups!r}")
        flattened = []
        for group in self.required_source_groups:
            if not isinstance(group, tuple) or not group or any(
                    not isinstance(v, str) or not v for v in group):
                raise ValueError(
                    "ProfileCapabilityEntry.required_source_groups entries must each be a "
                    f"non-empty tuple of non-empty strings, got {group!r}")
            if len(set(group)) != len(group):
                raise ValueError(
                    f"ProfileCapabilityEntry.required_source_groups entry has duplicate "
                    f"members: {group!r}")
            flattened.extend(group)
        if len(set(flattened)) != len(flattened):
            raise ValueError(
                "ProfileCapabilityEntry.required_source_groups' members must not repeat "
                f"across groups, got {self.required_source_groups!r}")

        if not isinstance(self.optional_sources, tuple) or any(
                not isinstance(v, str) or not v for v in self.optional_sources):
            raise ValueError(
                "ProfileCapabilityEntry.optional_sources must be a tuple of non-empty "
                f"strings, got {self.optional_sources!r}")
        if set(flattened) & set(self.optional_sources):
            raise ValueError(
                "ProfileCapabilityEntry.required_source_groups and optional_sources must "
                f"not overlap, got required members={flattened!r} "
                f"optional_sources={self.optional_sources!r}")

        expected_required_sources = tuple(dict.fromkeys(flattened))
        if self.required_sources != expected_required_sources:
            raise ValueError(
                "ProfileCapabilityEntry.required_sources must equal the flattened, "
                f"order-preserving union of required_source_groups -- expected "
                f"{expected_required_sources!r}, got {self.required_sources!r}")

        # Cross-checked against CAPABILITY_REGISTRY -- the single source
        # of truth this capability_id's own source rule is defined
        # against -- not merely internally self-consistent. Without this,
        # a `handle_analysis` entry built with required_source_groups=
        # (("threads",),) would pass every check above (it is a
        # perfectly well-formed group, disjoint from optional_sources,
        # correctly flattened) while being factually wrong for that
        # capability id -- exactly the "must be technically enforced, not
        # caller discipline" rule this whole record family exists to
        # satisfy, applied to the registry's own frozen mapping, not just
        # this one instance's internal shape.
        definition = CAPABILITY_BY_ID[self.capability_id]
        if self.required_source_groups != definition.required_source_groups:
            raise ValueError(
                f"ProfileCapabilityEntry({self.capability_id!r}).required_source_groups "
                f"must equal the frozen registry's own {definition.required_source_groups!r}, "
                f"got {self.required_source_groups!r}")
        if self.optional_sources != definition.optional_sources:
            raise ValueError(
                f"ProfileCapabilityEntry({self.capability_id!r}).optional_sources must "
                f"equal the frozen registry's own {definition.optional_sources!r}, got "
                f"{self.optional_sources!r}")

        if not isinstance(self.limitations, tuple) or any(
                type(l) is not CapabilityLimitation for l in self.limitations):
            raise TypeError("ProfileCapabilityEntry.limitations must be a tuple of CapabilityLimitation instances")

        required_gaps = tuple(l for l in self.limitations if l.code in _REQUIRED_LIMITATION_CODES)
        group_member_gaps = tuple(l for l in self.limitations
                                    if l.code in _REQUIRED_GROUP_MEMBER_LIMITATION_CODES)
        optional_gaps = tuple(l for l in self.limitations if l.code in _OPTIONAL_LIMITATION_CODES)
        truncated_gaps = tuple(l for l in self.limitations if l.code in _TRUNCATED_LIMITATION_CODES)
        if (len(required_gaps) + len(group_member_gaps) + len(optional_gaps) + len(truncated_gaps)
                != len(self.limitations)):
            raise ValueError(
                "ProfileCapabilityEntry.limitations contains a code outside the closed "
                f"REQUIRED_SOURCE_*/REQUIRED_GROUP_MEMBER_*/OPTIONAL_SOURCE_*/*_TRUNCATED "
                f"vocabulary: {self.limitations!r}")
        required_truncated = tuple(
            l for l in truncated_gaps
            if l.code == CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value)
        optional_truncated = tuple(
            l for l in truncated_gaps
            if l.code == CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value)

        # No source may carry more than one limitation -- two limitations
        # for the same source would be either a duplicate (redundant) or
        # a contradiction (e.g. REQUIRED_SOURCE_ABSENT and
        # OPTIONAL_SOURCE_ABSENT both naming "threads"), neither of which
        # a well-formed record can represent.
        limitation_sources = [l.source for l in self.limitations]
        if len(set(limitation_sources)) != len(limitation_sources):
            raise ValueError(
                "ProfileCapabilityEntry.limitations names the same source more than once: "
                f"{limitation_sources!r}")

        # Each code family is matched to exactly the sources it is
        # allowed to describe -- REQUIRED_SOURCE_*/REQUIRED_GROUP_MEMBER_*/
        # REQUIRED_SOURCE_TRUNCATED only for a member of one of this
        # capability's own required groups (all three describe a
        # required-group member; which one is chosen is a fact about
        # ABSENT/FAILED/INDETERMINATE vs. an unsatisfied sibling vs. an
        # incomplete parse, not about which set the source lives in),
        # OPTIONAL_SOURCE_*/OPTIONAL_SOURCE_TRUNCATED only for a source
        # that is PURELY optional -- never for a required-group member,
        # which is exactly the "optional corroborating evidence"
        # fabrication this type's own docstring describes.
        required_set = set(flattened)
        for l in required_gaps + group_member_gaps + required_truncated:
            if l.source not in required_set:
                raise ValueError(
                    f"ProfileCapabilityEntry: a {l.code!r} limitation's source {l.source!r} "
                    f"must be a member of one of this capability's own "
                    f"required_source_groups {self.required_source_groups!r}")
        for l in optional_gaps + optional_truncated:
            if l.source not in self.optional_sources:
                raise ValueError(
                    f"ProfileCapabilityEntry: an OPTIONAL_SOURCE_*/OPTIONAL_SOURCE_TRUNCATED "
                    f"limitation's source {l.source!r} must be one of this capability's own "
                    f"optional_sources {self.optional_sources!r} -- a required-group member's "
                    f"own gap must use REQUIRED_SOURCE_*/REQUIRED_GROUP_MEMBER_*/"
                    f"REQUIRED_SOURCE_TRUNCATED instead, never OPTIONAL_SOURCE_*")

        # REQUIRED_GROUP_MEMBER_* asserts "a DIFFERENT member of this
        # SAME group already satisfies it" -- meaningless (and therefore
        # forbidden) for a single-member group, which has no sibling to
        # make that claim about.
        group_by_member = {name: group for group in self.required_source_groups for name in group}
        for l in group_member_gaps:
            group = group_by_member[l.source]
            if len(group) == 1:
                raise ValueError(
                    f"ProfileCapabilityEntry: a REQUIRED_GROUP_MEMBER_* limitation's source "
                    f"{l.source!r} belongs to the single-member group {group!r}, which has no "
                    f"sibling to have satisfied it -- use REQUIRED_SOURCE_* instead")

        # Every required group is either FULLY blocked (every one of its
        # members carries a required_gap) or FULLY unblocked (none of
        # them do) -- a group with only SOME members blocked would be an
        # incomplete/inconsistent construction (the collector's own
        # algorithm always resolves a failed group's every member at
        # once; nothing may reach this type any other way).
        required_gap_sources = {l.source for l in required_gaps}
        for group in self.required_source_groups:
            blocked_count = sum(1 for name in group if name in required_gap_sources)
            if blocked_count not in (0, len(group)):
                raise ValueError(
                    f"ProfileCapabilityEntry: required group {group!r} has only "
                    f"{blocked_count}/{len(group)} member(s) carrying a REQUIRED_SOURCE_* "
                    f"limitation -- a group must be either fully blocked or fully unblocked, "
                    f"never partially")

        if self.status == CapabilityStatus.UNAVAILABLE.value:
            if not required_gaps:
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'unavailable' but carries no "
                    "REQUIRED_SOURCE_* limitation explaining why")
            if not any(all(name in required_gap_sources for name in group)
                       for group in self.required_source_groups):
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'unavailable' but no required group is "
                    "fully blocked -- §4.3 makes a capability unavailable only when at least "
                    "one whole required OR-group has no usable member")
        elif self.status == CapabilityStatus.LIMITED.value:
            if required_gaps:
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'limited' but carries a "
                    "REQUIRED_SOURCE_* limitation -- missing required evidence must be "
                    "'unavailable', never 'limited'")
            if not (group_member_gaps or optional_gaps or truncated_gaps):
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'limited' but carries no "
                    "REQUIRED_GROUP_MEMBER_*/OPTIONAL_SOURCE_*/*_TRUNCATED limitation "
                    "explaining why")
        else:   # available
            if self.limitations:
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'available' but carries limitations -- "
                    "'available' means no evidence gap at all")

    def to_dict(self) -> dict:
        return {
            "capability_id":            self.capability_id,
            "status":                   self.status,
            "required_source_groups":   [list(group) for group in self.required_source_groups],
            "required_sources":         list(self.required_sources),
            "optional_sources":         list(self.optional_sources),
            "limitations":              [l.to_dict() for l in self.limitations],
        }


@dataclass(frozen=True)
class ProfileRecord:
    """`--profile`'s record -- issue #95. Exactly one per result, same as
    ProcessRecord: a dump either has a directory table dumpex could read
    (in which case there is exactly one profile to report, however
    limited its contents) or it doesn't (collect_profile() then returns
    ZERO records, coverage.status="not_evaluated", exit 4 -- see
    dumpex.commands.profile). `capabilities` never carries verdict,
    confidence, ATT&CK, or hunter-score semantics -- see this section's
    own module-level comment."""
    architecture:            "str | None"   # mf.sysinfo.ProcessorArchitecture.name, e.g. "AMD64";
                                              # None when SystemInfoStream is absent
    raw_flags:                "int | None"   # the header's own 64-bit MINIDUMP_TYPE union value,
                                              # verbatim; None only when the header's own trailing
                                              # bytes were themselves truncated (see
                                              # dumpex.core.memory._correct_header_union)
    recognized_flags:          tuple          # tuple[str]: MINIDUMP_TYPE member names whose bit is
                                              # set in raw_flags, in MINIDUMP_TYPE's own declaration
                                              # order (not alphabetical) -- always () when raw_flags is None
    unrecognized_flag_bits:     "int | None"  # bits set in raw_flags that no known MINIDUMP_TYPE
                                              # member covers; 0 when every set bit is recognized;
                                              # None iff raw_flags is None
    memory_capture:              ProfileMemoryCapture
    streams:                      tuple       # tuple[ProfileStreamEntry], directory order
    capabilities:                  tuple       # tuple[ProfileCapabilityEntry], CAPABILITY_IDS order

    def __post_init__(self):
        if self.architecture is not None and (
                not isinstance(self.architecture, str) or not self.architecture):
            raise ValueError(
                f"ProfileRecord.architecture must be None or a non-empty string, "
                f"got {self.architecture!r}")
        _require_optional_nonneg_int(self.raw_flags, "ProfileRecord.raw_flags")
        _require_optional_nonneg_int(self.unrecognized_flag_bits, "ProfileRecord.unrecognized_flag_bits")
        if (self.raw_flags is None) != (self.unrecognized_flag_bits is None):
            raise ValueError(
                "ProfileRecord.raw_flags and unrecognized_flag_bits must both be None or "
                f"both set together, got raw_flags={self.raw_flags!r} "
                f"unrecognized_flag_bits={self.unrecognized_flag_bits!r}")
        if not isinstance(self.recognized_flags, tuple) or any(
                not isinstance(v, str) or not v for v in self.recognized_flags):
            raise ValueError(
                f"ProfileRecord.recognized_flags must be a tuple of non-empty strings, "
                f"got {self.recognized_flags!r}")
        if self.raw_flags is None and self.recognized_flags:
            raise ValueError(
                "ProfileRecord.recognized_flags must be empty when raw_flags is None -- "
                "nothing can be recognized in a flags value that was never read")

        if not isinstance(self.memory_capture, ProfileMemoryCapture):
            raise TypeError("ProfileRecord.memory_capture must be a ProfileMemoryCapture")

        if not isinstance(self.streams, tuple) or any(
                type(s) is not ProfileStreamEntry for s in self.streams):
            raise TypeError("ProfileRecord.streams must be a tuple of ProfileStreamEntry instances")
        for i, entry in enumerate(self.streams):
            if entry.directory_index != i:
                raise ValueError(
                    "ProfileRecord.streams must be in directory order with directory_index "
                    f"== position -- entry at position {i} has directory_index "
                    f"{entry.directory_index!r}")

        if not isinstance(self.capabilities, tuple) or any(
                type(c) is not ProfileCapabilityEntry for c in self.capabilities):
            raise TypeError("ProfileRecord.capabilities must be a tuple of ProfileCapabilityEntry instances")
        seen_ids = tuple(c.capability_id for c in self.capabilities)
        if seen_ids != CAPABILITY_IDS:
            raise ValueError(
                f"ProfileRecord.capabilities must contain exactly the frozen registry ids "
                f"in order {CAPABILITY_IDS}, got {seen_ids!r}")

    def to_dict(self) -> dict:
        return {
            "architecture":            self.architecture,
            "raw_flags":               self.raw_flags,
            "recognized_flags":        list(self.recognized_flags),
            "unrecognized_flag_bits":  self.unrecognized_flag_bits,
            "memory_capture":          self.memory_capture.to_dict(),
            "streams":                 [s.to_dict() for s in self.streams],
            "capabilities":            [c.to_dict() for c in self.capabilities],
        }
