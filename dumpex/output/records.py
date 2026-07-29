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

StringRecord/ArtifactRecord (extraction) are intentionally not defined
yet -- see dumpex/output/__init__.py's docstring; they are PR3 scope.
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


@dataclass
class ThreadRecord:
    """One thread, as reported by `--threads`."""
    tid:               "int | None"
    start_address:     "str | None"
    backing_module:    "str | None"
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
class ProcessInfoRecord:
    """
    Shared "process-centric" record for `--sysinfo`, `--pid`, and `--peb`
    -- one record type per the requested canonical-record list, rather
    than three narrower ones, differentiated by result.kind
    ("sysinfo"/"pid"/"peb"). Each command only populates its own subset
    of fields; the rest stay None. See the v2 migration plan for why this
    tradeoff was made (bundling vs. three separate record types).
    """
    pid:                "int | None" = None
    source:             "str | None" = None   # pid only: which stream determined pid
    dump_file:          "str | None" = None   # sysinfo only
    hostname:           "str | None" = None   # sysinfo only
    username:           "str | None" = None   # sysinfo only
    os:                 "str | None" = None   # sysinfo only
    os_version:         "str | None" = None   # sysinfo only
    architecture:       "str | None" = None   # sysinfo only
    product_type:       "str | None" = None   # sysinfo only
    process_start_utc:  "str | None" = None   # sysinfo only
    image_path:         "str | None" = None   # sysinfo, peb
    command_line:       "str | None" = None   # sysinfo, peb
    current_directory:  "str | None" = None   # sysinfo (working dir), peb
    processors:         "int | None" = None   # sysinfo only
    cpu_vendor:              "str | None" = None   # sysinfo only
    cpu_current_mhz:         "int | None" = None   # sysinfo only
    cpu_max_mhz:             "int | None" = None   # sysinfo only
    process_user_time_seconds:   "int | float | None" = None   # sysinfo only
    process_kernel_time_seconds: "int | float | None" = None   # sysinfo only
    thread_count:       "int | None" = None   # sysinfo (was threads_in_dump), pid
    module_count:       "int | None" = None   # sysinfo only (was modules_in_dump)
    exc_tid:            "int | None" = None   # pid only -- exception-stream TID (last resort)
    peb_address:        "str | None" = None   # peb only
    image_base_address: "str | None" = None   # peb only
    being_debugged:     "bool | None" = None  # peb only
    window_title:       "str | None" = None   # peb only
    dll_path:           "str | None" = None   # peb only
    standard_input:     "str | None" = None   # peb only (handle value, hex)
    standard_output:    "str | None" = None   # peb only (handle value, hex)
    standard_error:     "str | None" = None   # peb only (handle value, hex)
    environment_variables: "list | None" = None   # peb only: list[{"name","value"}]

    def to_dict(self) -> dict:
        return {
            "pid":                          self.pid,
            "source":                       self.source,
            "dump_file":                    self.dump_file,
            "hostname":                     self.hostname,
            "username":                     self.username,
            "os":                           self.os,
            "os_version":                   self.os_version,
            "architecture":                 self.architecture,
            "product_type":                 self.product_type,
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
            "exc_tid":                      self.exc_tid,
            "peb_address":                  self.peb_address,
            "image_base_address":           self.image_base_address,
            "being_debugged":               self.being_debugged,
            "window_title":                 self.window_title,
            "dll_path":                     self.dll_path,
            "standard_input":               self.standard_input,
            "standard_output":              self.standard_output,
            "standard_error":               self.standard_error,
            "environment_variables":        (list(self.environment_variables)
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

    def to_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "code": self.code}
