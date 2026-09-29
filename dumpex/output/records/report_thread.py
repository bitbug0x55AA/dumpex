"""`--report` thread, region and IOC-string records: the evidence a triage
card's verdict is scored from.
"""
from dataclasses import dataclass

from dumpex.core.pe_utils import has_executable_protection, is_private_memory_type
from dumpex.output.records.base import (
    DUMP_FLAGS_RESOLVED,
    MODULE_CONTEXT_RESOLVED,
    MODULE_CONTEXT_UNAVAILABLE,
    MODULE_CONTEXT_UNREGISTERED,
    START_ADDRESS_RECORDED,
    _MODULE_CONTEXTS,
    _require_thread_info_states,
)
from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
)
from dumpex.output.records.extraction import _PE_HEADER_STATES, _STRING_RECORD_ENCODINGS


REGION_MEMBERSHIP_START           = "start"           # StartAddress falls inside the region
REGION_MEMBERSHIP_CURRENT         = "current"         # only the captured current IP falls inside it
REGION_MEMBERSHIP_START_AND_CURRENT = "start_and_current"
_REGION_MEMBERSHIP_REASONS = (
    REGION_MEMBERSHIP_START, REGION_MEMBERSHIP_CURRENT, REGION_MEMBERSHIP_START_AND_CURRENT)


@dataclass
class ReportThreadInfo:
    """One thread as seen by `--report` -- either the anchor thread
    (Section 1) or one of the other threads sharing the anchor's resolved
    region (Section 3). Deliberately narrower than ThreadRecord (no
    create_time/exit_time/exit_status/suspend_count/priority/teb/flags):
    report.py's own console output never surfaces those for either
    section, so this record does not either -- see ThreadRecord itself
    for the full `--threads` shape.

    `start_address` (where this thread BEGAN) and `ip`/`ip_reg` (its live
    RIP/EIP, from this thread's own captured CONTEXT) are independent --
    see ThreadRecord's own docstring for why one is never substituted for
    the other. `ip` is None when this thread's CONTEXT was not captured/
    parsed, never defaulted to `start_address`.

    `ip_context_conflict` is a tri-state join against this TID's own
    ThreadInfoListStream record, computed by dumpex.core.memory.
    ip_context_conflict_for (the same derivation ThreadRecord's identical
    field uses, so `--threads` and `--report` cannot disagree about the
    same TID): True exactly when `ip` is set (the base ThreadListStream's
    own CONTEXT parsed a value) AND that record independently flags this
    same context as invalid (DumpFlags == MINIDUMP_THREAD_INFO_INVALID_
    CONTEXT, the same tag --threads renders as `[NO_CTX]`) -- a genuine
    disagreement between the dump's two thread sources about one fact.
    `ip` keeps the real, parsed value either way (it is not discarded or
    nulled out just because a second source disputes it), but the
    conflict travels with it on the wire so a consumer is never left
    treating a disputed value as a confirmed one.

    False when `ip` is set and that record is real and clean, OR
    whenever `ip` itself is None: there is nothing to conflict about when
    no value was parsed at all, regardless of ThreadInfoListStream
    coverage. None when `ip` is set but no DumpFlags value could be
    established to join it against -- this TID has no ThreadInfoListStream
    record at all (a RawThreadInfo placeholder, or a base-only TID whose
    current IP became the card's own anchor), or it has one whose flags
    could not be read (see `dump_flags_state`). The join cannot be
    performed either way, so the dispute is undeterminable and must never
    render the same as a confirmed False: a MODULE_CONTEXT_UNREGISTERED-
    vs-MODULE_CONTEXT_UNAVAILABLE distinction applied to this field.

    `backing_module`/`module_context` always describe `start_address`
    specifically, never `ip` -- there is no current-IP module lookup on
    this record at all. `region_membership` (Section 3 only; always None
    for Section 1's own anchor-thread entry, which is not "in" a region
    the way a Section 3 member is -- enforced by the schema's own
    triageCardRecord.thread/other_threads_in_region constraints, not just
    this docstring) says which address actually placed this entry in
    Section 3's list: `start` (StartAddress falls inside the region),
    `current` (only the captured current IP falls inside it --
    backing_module/module_context still describe StartAddress, which may
    be unrelated to or entirely outside this region), or
    `start_and_current` (both do). `region_membership` says WHICH address
    admitted this entry, never whether that address is trustworthy: a
    `current`-only or `start_and_current` entry can still be admitted by a
    disputed value -- a consumer that needs to know whether the admitting
    current IP is disputed must separately check `ip_context_conflict`
    (ANDing the two fields); `region_membership` itself has no disputed
    variant.

    `start_address_state`/`dump_flags_state` carry the same facts, with
    the same vocabulary and the same rules, as ThreadRecord's identical
    pair. They also decide what a `start` or `start_and_current`
    `region_membership` can rest on: only a `recorded` start address is
    established evidence that this thread begins inside the region."""
    tid:               int
    start_address:     "str | None"
    ip:                "str | None"   # live RIP/EIP; None means no CONTEXT
                                        # was captured/parsed for this thread
    ip_reg:            "str | None"   # "RIP" or "EIP"; both-or-neither with `ip`
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
    region_membership: "str | None" = None   # Section 3 only -- see this class's own docstring
    ip_context_conflict: "bool | None" = False   # None: undeterminable -- see this
                                                    # class's own docstring
    start_address_state: str = START_ADDRESS_RECORDED   # ThreadRecord's identical pair,
    dump_flags_state:    str = DUMP_FLAGS_RESOLVED      # same constants, same rules

    def __post_init__(self):
        _require_nonneg_int(self.tid, "ReportThreadInfo.tid")
        _require_optional_hex_address(self.start_address, "ReportThreadInfo.start_address")
        _require_thread_info_states(self.start_address, self.start_address_state,
                                     self.dump_flags_state, "ReportThreadInfo")
        _require_optional_hex_address(self.ip, "ReportThreadInfo.ip")
        if self.ip_reg is not None and not isinstance(self.ip_reg, str):
            raise ValueError("ReportThreadInfo.ip_reg must be None or a string")
        if self.ip is not None and self.ip_reg is None:
            raise ValueError("ReportThreadInfo.ip_reg is required when ip is set")
        if self.ip is None and self.ip_reg is not None:
            raise ValueError("ReportThreadInfo.ip_reg must be None when ip is None")
        if self.ip_context_conflict is not None and not isinstance(self.ip_context_conflict, bool):
            raise ValueError("ReportThreadInfo.ip_context_conflict must be None or a bool")
        if self.ip is None and self.ip_context_conflict is not False:
            raise ValueError(
                "ReportThreadInfo.ip_context_conflict must be False when ip is None "
                "-- there is nothing to conflict about when no value was parsed at all")
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
        if (self.region_membership is not None
                and self.region_membership not in _REGION_MEMBERSHIP_REASONS):
            raise ValueError(
                f"ReportThreadInfo.region_membership must be None or one of "
                f"{_REGION_MEMBERSHIP_REASONS}, got {self.region_membership!r}")

    def to_dict(self) -> dict:
        return {
            "tid":                  self.tid,
            "start_address":        self.start_address,
            "ip":                   self.ip,
            "ip_reg":               self.ip_reg,
            "backing_module":       self.backing_module,
            "module_context":       self.module_context,
            "kernel_time_100ns":    self.kernel_time_100ns,
            "user_time_100ns":      self.user_time_100ns,
            "backing_module_base":  self.backing_module_base,
            "backing_module_end":   self.backing_module_end,
            "region_membership":    self.region_membership,
            "ip_context_conflict":  self.ip_context_conflict,
            "start_address_state":  self.start_address_state,
            "dump_flags_state":     self.dump_flags_state,
        }


@dataclass
class ReportRegionInfo:
    """Resolved memory-region evidence for a triage-card target.

    file_offset is an integer dump offset, not a process address.
    module_context distinguishes resolved, confirmed unregistered, and unavailable
    module evidence. mz_header_detected is None when the header read failed.

    has_injected_pe is true only for a STRUCTURALLY VALID PE header (not a bare
    'MZ' prefix) in a confirmed-unregistered region that is also MEM_PRIVATE or
    executable; it is False for a confirmed-unregistered region carrying a valid
    but read-only, non-executable, non-private mapping (a resource-only PE
    legitimately has no module-list entry) and for a header that fails strict
    validation outright; it is None whenever required header or module evidence
    is unavailable, or a partial capture leaves structural validity itself
    undetermined. Registration (module_context) and memory type (type/protect)
    are independent facts here -- an unregistered address is never, by itself,
    private memory.

    pe_header_state (v2.20) is the structural-validity fact has_injected_pe's
    own tri-state derivation rests on, made independently inspectable rather
    than staying implicit in a producer's control flow: "ok" / "pe_invalid" /
    "short_read" (the same vocabulary dumpex.commands.process._classify_main_
    image_state uses), set exactly when mz_header_detected is True AND
    module_context is confirmed unregistered -- the only case a structural PE
    parse is ever attempted here -- and None otherwise. __post_init__ enforces
    it bidirectionally against has_injected_pe: "ok" forces has_injected_pe to
    equal (MEM_PRIVATE or executable), never leaving a dropped finding
    (has_injected_pe=False for a validated private/executable region)
    representable, and "short_read" forces has_injected_pe to None.
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
                                    # suspicious (base), kept as a separate field (not
                                    # reused) since ReportRegionInfo's own is_rwx_private
                                    # is already a distinct, MECE-dimension-specific bool.
    pe_header_state:       "str | None" = None   # "ok" / "pe_invalid" / "short_read", or None
                                                  # when no structural PE parse was attempted --
                                                  # see class docstring

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
            if self.module_context == MODULE_CONTEXT_UNREGISTERED:
                # A structural PE parse always runs here -- pe_header_state
                # is the record of what it found, and has_injected_pe is
                # enforced BIDIRECTIONALLY against it: a producer bug that
                # dropped a genuine finding (has_injected_pe=False for a
                # validated private/executable region) is exactly as
                # invalid as one that invented one, never just the latter.
                if self.pe_header_state not in _PE_HEADER_STATES:
                    raise ValueError(
                        f"ReportRegionInfo.pe_header_state must be one of {_PE_HEADER_STATES} "
                        "when an MZ header was found in a confirmed-unregistered region -- a "
                        f"structural PE parse always runs there, got {self.pe_header_state!r}")
                if self.pe_header_state == "short_read":
                    if self.has_injected_pe is not None:
                        raise ValueError(
                            "ReportRegionInfo.has_injected_pe must be None when "
                            "pe_header_state is 'short_read' -- a capture-length gap leaves "
                            "structural validity genuinely undetermined")
                else:
                    # "ok" or "pe_invalid": structural validity IS settled,
                    # so has_injected_pe must exactly equal "ok" AND
                    # (MEM_PRIVATE or executable) -- the same predicates
                    # the producer (_scan_content_range) uses, so this gate
                    # can never be looser than what it enforces in either
                    # direction.
                    expected = (self.pe_header_state == "ok"
                               and (is_private_memory_type(self.type)
                                    or has_executable_protection(self.protect)))
                    if self.has_injected_pe is not expected:
                        raise ValueError(
                            "ReportRegionInfo.has_injected_pe must be True exactly when "
                            "pe_header_state is 'ok' and the region is MEM_PRIVATE or "
                            f"executable -- got has_injected_pe={self.has_injected_pe!r} with "
                            f"pe_header_state={self.pe_header_state!r}, type={self.type!r}, "
                            f"protect={self.protect!r}")
            elif self.pe_header_state is not None:
                raise ValueError(
                    "ReportRegionInfo.pe_header_state must be None when module_context is not "
                    "confirmed unregistered -- no structural PE parse is ever attempted "
                    "otherwise")
        elif self.pe_header_state is not None:
            raise ValueError(
                "ReportRegionInfo.pe_header_state must be None when mz_header_detected is not "
                "True -- no structural PE parse is ever attempted without a confirmed MZ "
                "prefix")

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
            "pe_header_state":       self.pe_header_state,
        }


@dataclass
class ReportIocString:
    """One IOC-pattern string hit in a triage card's Section 4 -- replaces
    the earlier loose dict shape (offset/address/encoding/text/matched_grep/
    is_network_pattern with no validation at all) with a typed record the
    same way every other structured fact in these records is typed.
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
