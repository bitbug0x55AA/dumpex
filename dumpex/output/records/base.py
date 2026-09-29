"""The dump's own inventory records: memory regions, modules, threads and
the system summary (`--list`, `--modules`, `--threads`, `--sysinfo`), and
the module-context and thread-evidence vocabularies other domains reuse.
"""
from dataclasses import dataclass, field

from dumpex.output.records.common import _require_optional_hex_address


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
_MODULE_CONTEXTS = (MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE)


# What standing a thread's `start_address` has, and whether its record's
# DumpFlags could be read at all. Mirrors dumpex.core.memory's own
# START_ADDRESS_*/DUMP_FLAGS_* by convention (same literal strings), the
# same way report_card's _TRIAGE_VERDICTS mirrors that module's verdict
# constants rather than importing them -- the dependency direction stays
# command/domain model -> output layer, never the reverse.
START_ADDRESS_RECORDED   = "recorded"     # the record stands behind this address
START_ADDRESS_INVALID    = "invalid"      # its own DumpFlags disown every field but
                                            # ThreadId; start_address is null
START_ADDRESS_UNVERIFIED = "unverified"   # address present, DumpFlags unreadable, so
                                            # nothing establishes it as evidence
START_ADDRESS_ABSENT     = "absent"       # no address was recorded for this thread at
                                            # all; start_address is null
_START_ADDRESS_STATES = (START_ADDRESS_RECORDED, START_ADDRESS_INVALID,
                          START_ADDRESS_UNVERIFIED, START_ADDRESS_ABSENT)

DUMP_FLAGS_RESOLVED   = "resolved"     # value known; an empty `flags` means no flag set
DUMP_FLAGS_UNRESOLVED = "unresolved"   # record present, value unreadable; an empty
                                        # `flags` means nothing is known
DUMP_FLAGS_ABSENT     = "absent"       # no ThreadInfoListStream record at all
_DUMP_FLAGS_STATES = (DUMP_FLAGS_RESOLVED, DUMP_FLAGS_UNRESOLVED, DUMP_FLAGS_ABSENT)

# The `dump_flags_state` each start-address state requires, for the three
# states that are decided BY the flags. `absent` is deliberately absent
# from this table: whether an address was captured at all is independent
# of whether the flags were readable, so a record with perfectly readable
# flags can still have stopped short of its own StartAddress field.
_START_ADDRESS_STATE_FLAGS_STATE = {
    START_ADDRESS_RECORDED:   DUMP_FLAGS_RESOLVED,
    START_ADDRESS_INVALID:    DUMP_FLAGS_RESOLVED,
    START_ADDRESS_UNVERIFIED: DUMP_FLAGS_UNRESOLVED,
}

# The states that describe an address this record actually carries, and
# the states that describe the absence of one. Enforced against
# `start_address` itself, so a null can never be published as an address
# the record stood behind, nor an address as one it never held.
_START_ADDRESS_STATES_WITH_ADDRESS = (START_ADDRESS_RECORDED, START_ADDRESS_UNVERIFIED)
_START_ADDRESS_STATES_WITHOUT_ADDRESS = (START_ADDRESS_INVALID, START_ADDRESS_ABSENT)


def _require_thread_info_states(start_address, start_address_state, dump_flags_state, where):
    """Shared validation of the two thread-record fields that say what a
    `start_address` is worth. Used by every record carrying them, so the
    rules cannot drift between `--threads` and `--report`."""
    if start_address_state not in _START_ADDRESS_STATES:
        raise ValueError(
            f"{where}.start_address_state must be one of {_START_ADDRESS_STATES}, "
            f"got {start_address_state!r}")
    if dump_flags_state not in _DUMP_FLAGS_STATES:
        raise ValueError(
            f"{where}.dump_flags_state must be one of {_DUMP_FLAGS_STATES}, "
            f"got {dump_flags_state!r}")
    expected = _START_ADDRESS_STATE_FLAGS_STATE.get(start_address_state)
    if expected is not None and dump_flags_state != expected:
        raise ValueError(
            f"{where}.start_address_state {start_address_state!r} requires "
            f"dump_flags_state {expected!r}, got {dump_flags_state!r}")
    if dump_flags_state == DUMP_FLAGS_ABSENT and start_address_state != START_ADDRESS_ABSENT:
        raise ValueError(
            f"{where}.start_address_state must be {START_ADDRESS_ABSENT!r} when "
            f"dump_flags_state is {DUMP_FLAGS_ABSENT!r} -- a thread with no "
            f"ThreadInfoListStream record has no recorded start address either")
    if start_address is None and start_address_state in _START_ADDRESS_STATES_WITH_ADDRESS:
        raise ValueError(
            f"{where}.start_address_state {start_address_state!r} describes an address this "
            f"record carries, but start_address is None")
    if start_address is not None and start_address_state in _START_ADDRESS_STATES_WITHOUT_ADDRESS:
        raise ValueError(
            f"{where}.start_address must be None when start_address_state is "
            f"{start_address_state!r} -- no address was established for this thread")


@dataclass
class ThreadRecord:
    """One thread, as reported by `--threads`.

    `start_address` (where the thread BEGAN, from ThreadInfoListStream) and
    `ip`/`ip_reg` (where it IS RIGHT NOW, the live RIP/EIP captured in this
    thread's own CONTEXT at dump time) are independent facts from
    independent sources -- a thread whose current `ip` differs from its
    `start_address` is not reducible to either address alone, and one is
    never substituted for the other. `ip` is None whenever this thread's
    CONTEXT was not captured/parsed (see dumpex.core.memory.
    get_thread_contexts's own "not in this list" contract) -- never
    defaulted to `start_address` or to 0.

    `ip_context_conflict` is a tri-state join against this TID's own
    ThreadInfoListStream record, computed by dumpex.core.memory.
    ip_context_conflict_for (the single derivation `--threads` and
    `--report` both consume): True when `ip` is set (the base
    ThreadListStream's own CONTEXT parsed a value) AND that record
    independently flags this same context as invalid (the same [NO_CTX]
    tag `flags` already carries); False when `ip` is set and that record
    is real and clean, OR whenever `ip` itself is None (nothing to
    dispute, regardless of ThreadInfoListStream coverage); None when `ip`
    is set but no DumpFlags value could be established to check it
    against -- no ThreadInfoListStream record for this TID at all (see
    RawThreadInfo), or one whose flags could not be read (see
    `dump_flags_state`). The dispute is then undeterminable, never a
    confirmed False the way genuinely clean, readable DumpFlags are.
    `ip` keeps the real, parsed value in every case.

    `start_address_state` says what `start_address` is worth, and
    `dump_flags_state` whether this thread's DumpFlags could be read at
    all -- see those constants' own comments. A `start_address` of None
    is `absent` (ThreadInfoListStream never covered this TID) or
    `invalid` (it did, and its own DumpFlags disown every field but
    ThreadId); neither is an address 0x0, and neither is evidence that
    this thread starts outside every module. `flags` carries one tag per
    DumpFlags bit actually set, so a combined value is reported in full;
    an empty `flags` means "no flag set" only when `dump_flags_state` is
    `resolved`."""
    tid:               "int | None"
    start_address:     "str | None"
    ip:                "str | None"   # live RIP/EIP from this thread's own CONTEXT;
                                        # None means no CONTEXT was captured/parsed for
                                        # this thread -- an unknown current IP, never
                                        # start_address wearing a different name
    ip_reg:            "str | None"   # "RIP" or "EIP"; both-or-neither with `ip`
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
    flags: list = field(default_factory=list)   # list[str], one per DumpFlags bit
                                                   # actually set, e.g. ["EXITED"]
    ip_context_conflict: "bool | None" = False   # None: undeterminable -- see this
                                                    # class's own docstring
    start_address_state: str = START_ADDRESS_RECORDED   # see this class's own docstring
    dump_flags_state:    str = DUMP_FLAGS_RESOLVED      # and the constants themselves

    def __post_init__(self):
        _require_optional_hex_address(self.ip, "ThreadRecord.ip")
        _require_thread_info_states(self.start_address, self.start_address_state,
                                     self.dump_flags_state, "ThreadRecord")
        if self.ip_reg is not None and not isinstance(self.ip_reg, str):
            raise ValueError("ThreadRecord.ip_reg must be None or a string")
        if self.ip is not None and self.ip_reg is None:
            raise ValueError("ThreadRecord.ip_reg is required when ip is set")
        if self.ip is None and self.ip_reg is not None:
            raise ValueError("ThreadRecord.ip_reg must be None when ip is None")
        if self.ip_context_conflict is not None and not isinstance(self.ip_context_conflict, bool):
            raise ValueError("ThreadRecord.ip_context_conflict must be None or a bool")
        if self.ip is None and self.ip_context_conflict is not False:
            raise ValueError(
                "ThreadRecord.ip_context_conflict must be False when ip is None -- there is "
                "no captured value to dispute regardless of ThreadInfoListStream coverage")

    def to_dict(self) -> dict:
        return {
            "tid":               self.tid,
            "start_address":     self.start_address,
            "ip":                self.ip,
            "ip_reg":            self.ip_reg,
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
            "ip_context_conflict": self.ip_context_conflict,
            "start_address_state": self.start_address_state,
            "dump_flags_state":    self.dump_flags_state,
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
