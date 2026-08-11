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

StringRecord is populated by --strings and reused as-is by --report's own
"notable strings" section (see TriageCardRecord below). Artifact is
populated by --extract and by --report's own optional extract-to-file
side effect (under a different `kind` string -- see Artifact's own
docstring).
"""
import re
from dataclasses import dataclass, field

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


# ── Report records (Phase E, PR3) ───────────────────────────────────────
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
    """The memory region resolved at a triage card's target address
    (report.py's Section 2). `file_offset` is a plain int -- a byte
    offset inside the .dmp file, not a process address -- so it does NOT
    go through hex_address() despite the name similarity to this module's
    other `*_address` fields (see this module's own docstring's hex-vs-int
    type rule). `is_rwx_private` is a MECE dimension report.py can always
    determine from the region's own protection bits alone, independent of
    module evidence.

    `module_context`/`mz_header_detected`/`has_injected_pe` together
    replace what used to be a single boolean `has_injected_pe` computed as
    `header[:2] == b'MZ' and not rmod` -- that conflated "confirmed not
    backed by any module" with "ModuleListStream itself was absent, so we
    simply could not check," producing a false-positive injected-PE
    finding whenever modules were unavailable (rmod is unconditionally
    None/falsy in that case too). `module_context` mirrors ReportThreadInfo's
    own resolved/unregistered/unavailable vocabulary but is never null here
    (unlike the thread field): a target region, once resolved at all,
    always has SOME module-context answer, whereas a thread's own
    module_context is null only when start_address itself is unknown.
    `mz_header_detected` is null when the small header-peek read itself
    failed (a distinct, rare failure from the main Section 4 content
    read) -- an unconfirmed header must not silently read as "no PE
    header found" (false negative) any more than a missing module list
    should silently read as "confirmed unregistered" (false positive).
    `has_injected_pe` is the MECE-dimension-ready derived fact: True only
    when an MZ header WAS found AND module_context is confirmed
    'unregistered'; False when no MZ header was found, or one was found
    in a module confirmed 'resolved' (known, expected); null whenever the
    evidence needed to decide either way is itself missing (mz_header_
    detected is null, or an MZ header was found but module_context is
    'unavailable' -- found something suspicious-shaped but can't confirm
    it actually is). TriageCardRecord.findings may only ever contain
    'injected_pe' when this is True -- never on a null (unconfirmed) or
    False value."""
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


# ── Hunt records (v2.4 migration, PR2a -- injection only) ───────────────
# One HunterRecord per hunter -- `--hunt all` produces exactly 7, in a
# fixed order; a single `--hunt <ttp>` produces exactly 1. See
# docs/hunt_migration_field_matrix.md for the full field-by-field audit
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
# All 7 *Details classes below are fully wired to a real collect_*()
# (dumpex.hunt.injection.collect.collect_injection_record() first, PR2a;
# the other 6 -- hollowing/stomping/pipe/cs-beacon/yara/obfuscation --
# followed in PR2b, each fixing the same confirmed non-reproducible
# str(obj) defect InjectionDetails was built to fix; see each hunter's
# own collect.py module), and every one of them is reachable from the
# CLI as of PR4 via `dumpex.hunt.collect_hunt()`/`dumpex.hunt.cmd_hunt(
# ..., collect_records=True)`.

HUNTERS = ("injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation")
_HUNT_STATUSES = ("DETECTED", "NOT_DETECTED_IN_SCANNED_SCOPE", "INCONCLUSIVE", "NOT_EVALUATED")
_HUNT_VERDICT_LEVELS = ("clean", "possible", "likely", "high", "inconclusive", "not_evaluated")
_HUNT_CONFIDENCES = ("none", "low", "medium", "high")
_HUNT_REVIEW_PRIORITIES = ("none", "low", "medium", "high")


def _require_list_of(value, cls, field_name: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, cls) for item in value):
        raise TypeError(f"{field_name} must be a list of {cls.__name__}")


@dataclass
class HuntRegionRef:
    """A memory region reference inside a hunter's `details` -- replaces
    every raw Region object a hunter's aggregate.py builds today, which
    (per docs/hunt_migration_field_matrix.md's cross-cutting finding #1)
    reaches JSON via dumpex.ui.structured._json_safe()'s str(obj) fallback
    and embeds the interpreter's own live heap address, non-reproducible
    across runs."""
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
    """One MZ-prefixed region examined for a hidden PE header (injection's
    hidden_pe_validated/hidden_pe_unvalidated) -- the region plus the
    structural-validation outcome. `entry_point_rva` stays a plain int
    (an RVA is relative to a not-yet-established image base, not itself a
    memory address -- see this module's own top-of-file type rule);
    `image_base` (the PE header's OWN declared base) is a real address,
    hex-formatted."""
    region:              HuntRegionRef
    valid:               bool
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


# The remaining 6 *Details classes below are SHAPE ONLY (field names/types
# straight from docs/hunt_migration_field_matrix.md's own per-hunter
# tables, empirically verified there against running code) -- no
# collect_*() function constructs any of these yet, and their fields are
# NOT guaranteed free of the raw-object str(obj) non-reproducibility
# defect InjectionDetails above was built specifically to fix. Real
# per-hunter collect_*() wiring (the same treatment injection got) is
# explicit follow-up work.

@dataclass
class HollowingDetails:
    """New JSON surface for `--hunt hollowing` (today's v1.1 output has NO
    detail fields at all -- see the field matrix's hollowing section for
    why). Mirrors the four checks the hollowing hunter already computes
    but never persisted: memory type / MZ header / RWX protection at the
    image base, and the PEB-vs-module-list name compare.
    `image_base` is `None` exactly when the PEB itself is missing (the
    hunter's own NOT_EVALUATED case, confirmed by
    dumpex.hunt.hollowing._build_hollowing_report()'s early return, and
    structurally guaranteed since the canonical-Report migration by
    dumpex.hunt.hollowing.domain.HollowingReport's own context/peb_present
    invariant) --
    there is no image base to report at all in that case, unlike every
    other hunter's `HunterRecord`, which always has SOME evidence to
    convert even when coverage is incomplete."""
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
    """`--hunt stomping`'s hunter-specific evidence. `verified_changes[*]`
    is already close to this final shape in today's v1.1 output (a flat
    dict, not a raw object) -- see the field matrix's stomping section."""
    protection_leads: list   # list[dict]
    verified_changes: list   # list[dict]

    def __post_init__(self):
        for name in ("protection_leads", "verified_changes"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"StompingDetails.{name} must be a list of dict")

    def to_dict(self) -> dict:
        return {
            "protection_leads": [dict(x) for x in self.protection_leads],
            "verified_changes": [dict(x) for x in self.verified_changes],
        }


@dataclass
class PipeDetails:
    """`--hunt pipe`'s hunter-specific evidence."""
    handle_pipes:    list   # list[dict]
    private_pipes:   list   # list[dict]
    c2_context:      list   # list[dict]
    framework_pipes: list   # list[dict]
    unbacked_in_rgn: list   # list[dict]

    def __post_init__(self):
        for name in ("handle_pipes", "private_pipes", "c2_context", "framework_pipes",
                      "unbacked_in_rgn"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"PipeDetails.{name} must be a list of dict")

    def to_dict(self) -> dict:
        return {
            "handle_pipes":    [dict(x) for x in self.handle_pipes],
            "private_pipes":   [dict(x) for x in self.private_pipes],
            "c2_context":      [dict(x) for x in self.c2_context],
            "framework_pipes": [dict(x) for x in self.framework_pipes],
            "unbacked_in_rgn": [dict(x) for x in self.unbacked_in_rgn],
        }


@dataclass
class CsBeaconDetails:
    """`--hunt cs-beacon`'s hunter-specific evidence. `configs[*]`'s
    `va`/`file_offset`/`region_base` are plain JSON ints in today's v1.1
    output -- confirmed by the field matrix as a real shape change (not
    just a container move) once this hunter's collect_*() is wired."""
    configs:      list   # list[dict]
    config_count: int

    def __post_init__(self):
        if not isinstance(self.configs, list) or any(not isinstance(x, dict) for x in self.configs):
            raise TypeError("CsBeaconDetails.configs must be a list of dict")
        _require_nonneg_int(self.config_count, "CsBeaconDetails.config_count")
        if self.config_count != len(self.configs):
            raise ValueError(
                f"CsBeaconDetails.config_count ({self.config_count}) must equal "
                f"len(configs) ({len(self.configs)})")

    def to_dict(self) -> dict:
        return {"configs": [dict(x) for x in self.configs], "config_count": self.config_count}


@dataclass
class YaraDetails:
    """`--hunt yara`'s hunter-specific evidence. YARA deliberately stays
    off the shared Finding model -- see docs/hunt_migration_field_matrix.md's
    legend for why `matches` must not be reclassified as `finding`."""
    matches:    list   # list[dict]
    rules_hit:  list   # list[str]

    def __post_init__(self):
        if not isinstance(self.matches, list) or any(not isinstance(x, dict) for x in self.matches):
            raise TypeError("YaraDetails.matches must be a list of dict")
        if not isinstance(self.rules_hit, list) or any(not isinstance(x, str) for x in self.rules_hit):
            raise TypeError("YaraDetails.rules_hit must be a list of str")

    def to_dict(self) -> dict:
        return {"matches": [dict(x) for x in self.matches], "rules_hit": list(self.rules_hit)}


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

    def __post_init__(self):
        for name in ("sleep_mask", "entropy", "base64", "xor", "compressed", "hidden_pe",
                      "hidden_shellcode"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"ObfuscationDetails.{name} must be a list of dict")

    def to_dict(self) -> dict:
        return {
            "sleep_mask":       [dict(x) for x in self.sleep_mask],
            "entropy":          [dict(x) for x in self.entropy],
            "base64":           [dict(x) for x in self.base64],
            "xor":              [dict(x) for x in self.xor],
            "compressed":       [dict(x) for x in self.compressed],
            "hidden_pe":        [dict(x) for x in self.hidden_pe],
            "hidden_shellcode": [dict(x) for x in self.hidden_shellcode],
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
    """One hunter's complete v2.4 result -- `result.data.records[*]` for
    `result.kind == "hunt"`. `hunter` discriminates which of the 7
    `*Details` types `details` must be. `max_score`/`confidence`/
    `lead_count`/`review_priority` are `None` for every hunter except
    `hunter == "yara"`, where they must ALL be `None` (yara has none of
    these today -- see the field matrix) -- never a mix of some set, some
    not. `coverage` is a real CoverageReport, not a bare status string:
    this hunter's coverage_status/coverage_reasons/coverage dict from
    today's v1.1 output are migration SOURCES the reducer that built this
    CoverageReport consumed, never carried forward as a second field
    alongside it (see the field matrix's own cross-cutting finding #2)."""
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
