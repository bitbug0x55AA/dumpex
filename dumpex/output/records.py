"""Canonical v2 record types.

Same house style as dumpex.hunt._finding.Finding: plain dataclasses, an
explicit to_dict() (never dataclasses.asdict()/str() fallback), defensive
list(...) copies for mutable fields, snake_case fields throughout.

Type rule (resolves "addresses as hex, numbers as int, missing as null"
into one consistent policy applied to every record below): a field is a
normalized lowercase hex string (`f"0x{n:x}"`) ONLY when it is a real
memory address or pointer -- base_address, end_address, teb,
peb_address, image_base_address, and the three PEB standard-handle
fields. Every other numeric field -- pid, tid, exc_tid, size, checksum,
durations, counts, exit_status, suspend_count, priority -- is a plain
JSON integer, never a hex string. Missing values are always None, never
"". Console rendering (dumpex/commands/*.py's render_*_console functions)
is free to format any of these ints as hex text for display -- that is a
presentation choice independent of the record's own field type.

StringRecord is now populated by --strings (Phase E) -- a future --report
migration is expected to reuse it for its own "notable strings" section.
Artifact is populated by --extract (Phase E) -- a future --report
migration is expected to reuse it too, for its own optional
extract-to-file side effect.
"""
import re
from dataclasses import dataclass, field


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
    """`--sysinfo`'s record. Split out from a single shared "process info"
    record (an earlier iteration bundled sysinfo/pid/peb into one type
    with dozens of nulled-out fields per command) so each kind's schema
    can be fully and tightly typed -- see PidRecord/PebRecord below."""
    dump_file:          "str | None" = None
    hostname:           "str | None" = None
    username:           "str | None" = None
    os:                 "str | None" = None
    os_version:         "str | None" = None
    architecture:       "str | None" = None
    product_type:       "str | None" = None
    pid:                "int | None" = None
    process_start_utc:  "str | None" = None
    image_path:         "str | None" = None
    command_line:       "str | None" = None
    current_directory:  "str | None" = None
    processors:         "int | None" = None
    cpu_vendor:         "str | None" = None
    cpu_current_mhz:    "int | None" = None
    cpu_max_mhz:        "int | None" = None
    process_user_time_seconds:   "int | float | None" = None
    process_kernel_time_seconds: "int | float | None" = None
    thread_count:       "int | None" = None   # None if ThreadListStream itself is absent
    module_count:       "int | None" = None   # None if ModuleListStream itself is absent

    def to_dict(self) -> dict:
        return {
            "dump_file":                    self.dump_file,
            "hostname":                     self.hostname,
            "username":                     self.username,
            "os":                           self.os,
            "os_version":                   self.os_version,
            "architecture":                 self.architecture,
            "product_type":                 self.product_type,
            "pid":                          self.pid,
            "process_start_utc":            self.process_start_utc,
            "image_path":                   self.image_path,
            "command_line":                 self.command_line,
            "current_directory":            self.current_directory,
            "processors":                   self.processors,
            "cpu_vendor":                   self.cpu_vendor,
            "cpu_current_mhz":              self.cpu_current_mhz,
            "cpu_max_mhz":                  self.cpu_max_mhz,
            "process_user_time_seconds":    self.process_user_time_seconds,
            "process_kernel_time_seconds":  self.process_kernel_time_seconds,
            "thread_count":                 self.thread_count,
            "module_count":                 self.module_count,
        }


@dataclass
class PidRecord:
    """`--pid`'s record."""
    pid:          "int | None" = None
    source:       "str | None" = None   # which stream determined pid
    thread_count: "int | None" = None
    exc_tid:      "int | None" = None   # exception-stream TID (last resort, not a PID)

    def to_dict(self) -> dict:
        return {
            "pid":          self.pid,
            "source":       self.source,
            "thread_count": self.thread_count,
            "exc_tid":      self.exc_tid,
        }


@dataclass
class PebRecord:
    """`--peb`'s record."""
    peb_address:        "str | None" = None
    image_base_address: "str | None" = None
    being_debugged:     "bool | None" = None
    image_path:         "str | None" = None
    command_line:       "str | None" = None
    window_title:       "str | None" = None
    dll_path:           "str | None" = None
    current_directory:  "str | None" = None
    standard_input:     "str | None" = None   # handle value, hex
    standard_output:    "str | None" = None   # handle value, hex
    standard_error:     "str | None" = None   # handle value, hex
    environment_variables: "list | None" = None   # list[{"name","value"}]

    def to_dict(self) -> dict:
        return {
            "peb_address":           self.peb_address,
            "image_base_address":    self.image_base_address,
            "being_debugged":        self.being_debugged,
            "image_path":            self.image_path,
            "command_line":          self.command_line,
            "window_title":          self.window_title,
            "dll_path":              self.dll_path,
            "current_directory":     self.current_directory,
            "standard_input":        self.standard_input,
            "standard_output":       self.standard_output,
            "standard_error":        self.standard_error,
            "environment_variables": (list(self.environment_variables)
                                       if self.environment_variables is not None else None),
        }


# ── Extraction records (Phase E) ────────────────────────────────────────
# Validators below mirror v2.2's extractRecord/stringRecord $defs (P2-1
# remediation) -- before this, neither record had a __post_init__ at all,
# so Python happily constructed (and .to_dict()'d) shapes the schema
# itself rejects (negative offsets, a bogus `encoding`, bytes_read >
# requested_size, bool-typed ints, ...). `_HEX_ADDRESS_RE` and the
# `_require_optional_*` family a little further below (shared with the
# comparison records) are referenced here by name -- plain top-level
# functions looked up at __post_init__ CALL time, not at class-definition
# time, so their physical position later in this module (kept together
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
    a future --report migration's own "notable strings" section (see
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
    regardless of --grep, so the STRUCTURED records list (JSON/CSV) always
    shows every extracted string -- None when no --grep was given at all
    (the concept doesn't apply), True/False per record when it was. The
    CONSOLE rendering (render_strings_console) is a separate, narrower
    concern: it actually SKIPS any record with matched_grep is False
    (only highlighting True matches, never printing non-matches) -- do
    not conflate the two; a --grep run's console text and its JSON/CSV
    output deliberately show different amounts of data."""
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


# ── Comparison records (Phase C) ────────────────────────────────────────
# Three tagged-union members for a future comparison command's
# result.data.records array (kind="comparison") -- entity_type is the
# discriminator. Fields are grounded directly in dumpex.commands.diff's
# existing (console-only) diff_modules/diff_threads/diff_memory business
# logic, not invented: each change_type only carries the before/after
# values that function's own set-difference logic actually produces for
# it (e.g. an "added" module has no full_path_before -- there is no
# baseline-side module to report one from). No command constructs these
# yet; see dumpex/commands/comparison.py.
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
    """One added/removed/rebased module between two dumps -- ported from
    diff_modules' own module-name-keyed added/removed/rebased set logic
    (see dumpex.commands.comparison._module_match_key for how the actual
    match key differs from `name` for an anonymous module). Frozen, with
    __post_init__ enforcing the same before/after null-pairing per
    change_type the v2.1 schema's moduleDiffRecord allOf already
    enforces on the wire -- catches a construction bug at the Python
    layer instead of only at schema-validation time, and stops a valid
    instance from being mutated into an invalid one after the fact."""
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
    """One added/removed thread between two dumps -- ported from
    diff_threads' own TID-keyed added/removed set logic. diff_threads has
    no "changed" category (a TID either exists in both, one, or the
    other), so change_type is added/removed only. backing_module_after/
    backing_module_context are populated for "added" only, resolved
    against the TARGET's module list exactly like diff_threads' own
    addr_to_module(sa, modules_b) call -- diff_threads never attempts
    baseline-side module resolution for a removed thread, so there is no
    backing_module_before field. backing_module_context reuses
    ThreadRecord's own MODULE_CONTEXT_RESOLVED/_UNREGISTERED/_UNAVAILABLE
    vocabulary (see above) so a comparison result distinguishes
    "confirmed not backed by any module" (a real signal) from "target's
    ModuleListStream itself wasn't available to check against" (not a
    confirmed anomaly), the same way --threads already does. Frozen, with
    __post_init__ enforcing the same invariants the v2.1 schema's
    threadDiffRecord allOf already enforces on the wire."""
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
    """One added/removed/protection-changed memory region between two
    dumps -- ported from diff_memory's own BaseAddress-keyed added/
    removed/changed set logic. suspicious_before/_after reuse
    MemoryRegionRecord.suspicious's own precedent (True iff `protect` is
    one of dumpex.rules_pkg.loader.SUSPICIOUS_PROTS) rather than
    diff_memory's own 4-tier rwx/exec/notable/noise console
    categorization, which stays a future console-renderer concern -- the
    same line MemoryRegionRecord.suspicious already draws between
    structured data and presentation. Frozen, with __post_init__
    enforcing the same invariants the v2.1 schema's memoryDiffRecord
    allOf already enforces on the wire."""
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
    by --extract (Phase E, via dumpex.commands.extract.build_extract_
    artifact(), which calls dumpex.core.safe_io.compute_bytes_summary()
    for the size_bytes/sha256 fields directly rather than parsing them
    back out of summarize_bytes()'s formatted string) -- a future
    --report migration is expected to reuse the same helper for its own
    optional extract-to-file side effect. Constructing one is the ONLY
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
