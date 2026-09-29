"""`--profile` records: the stream inventory, the memory-capture summary,
and ProfileRecord.

See docs/developer/recon_profile_contract.md for the frozen shape.
--profile is a capability MAP, never a verdict: nothing here may carry
malicious/clean, confidence, ATT&CK, or hunter-score semantics -- every
closed-vocabulary field spells out an EVIDENCE fact ("this stream is
present/absent/failed", "this capability's required evidence exists or
doesn't"), never an interpretation of it. "Profile describes what
evidence exists. Hunters interpret that evidence."
"""
from dataclasses import dataclass

from dumpex.output.records.capabilities import CAPABILITY_IDS, ProfileCapabilityEntry
from dumpex.output.records.common import (
    _require_bool,
    _require_nonneg_int,
    _require_optional_nonneg_int,
)
from dumpex.output.records.stream_state import StreamParserState, _STREAM_PARSER_STATES


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


@dataclass(frozen=True)
class ProfileRecord:
    """`--profile`'s record -- issue #95. Exactly one per result, same as
    ProcessRecord: a dump either has a directory table dumpex could read
    (in which case there is exactly one profile to report, however
    limited its contents) or it doesn't (collect_profile() then returns
    ZERO records, coverage.status="not_evaluated", exit 4 -- see
    dumpex.commands.profile). `capabilities` never carries verdict,
    confidence, ATT&CK, or hunter-score semantics -- see this module's
    own docstring."""
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
