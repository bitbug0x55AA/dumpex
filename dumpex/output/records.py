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

StringRecord (extraction, for a future --strings migration) is
intentionally not defined yet. Artifact (below) IS defined -- its wire
shape needed locking in ahead of a future --extract/--report migration --
but isn't populated by any command yet.
"""
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


SEVERITY_WARNING = "warning"
SEVERITY_ERROR   = "error"


@dataclass
class Diagnostic:
    """One entry in result.diagnostics.warnings/.errors -- structured,
    not a bare string, so a consumer can filter/triage without parsing
    free text."""
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


@dataclass
class Artifact:
    """One entry in the top-level `artifacts` array -- an output file the
    tool itself produced (e.g. an extracted memory region), distinct from
    meta.evidence (which describes the INPUT dump(s)). Field naming
    mirrors meta.evidence's own id/path/size_bytes/sha256 shape. Not yet
    populated by any of the six v2-routed recon commands -- extract.py/
    report.py (the eventual producers) are still v1.1 console-only today
    and only ever concatenate size+hash into a print string via
    dumpex.core.safe_io.summarize_bytes(), with no structured shape at
    all -- this type exists so a future migration has something typed to
    build instead of a bare dict. Constructing one is the ONLY way an
    entry reaches `artifacts` on the wire -- dumpex.output.collector.
    V2Output.set_command_result() calls .to_dict() unconditionally (no
    duck-typed dict passthrough), so a caller can't smuggle a shape this
    class doesn't validate."""
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
