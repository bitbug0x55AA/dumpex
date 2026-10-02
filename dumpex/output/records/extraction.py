"""`--extract` and `--strings` records.

Validators mirror the corresponding schema constraints: offsets and sizes
are non-negative plain integers, encodings are closed vocabulary, and a
read cannot exceed its request.
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_bool,
)


_STRING_RECORD_ENCODINGS = ("ASCII", "UTF16")


# The same vocabulary dumpex.core.process_info.classify_main_image_state
# uses for the analogous main-image question -- "read_failed" has no
# counterpart here because ReportRegionInfo already represents that case
# as mz_header_detected=None, one level up.
_PE_HEADER_STATES = ("ok", "pe_invalid", "short_read")


@dataclass
class ExtractRecord:
    """`--extract`'s record -- the READ-side facts only. Write-side facts
    (the output path/size_bytes/sha256) live on the corresponding entry
    in result.artifacts instead (see diagnostics.Artifact) -- not duplicated
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
    pe_header_state:  "str | None" = None   # "ok"/"pe_invalid"/"short_read" (v2.20, same
                                             # vocabulary as ReportRegionInfo.pe_header_state);
                                             # set exactly when a structural PE parse was
                                             # attempted -- mz_header_detected True AND the
                                             # extracted address is confirmed unregistered with
                                             # a covering MemoryInfo region -- None otherwise

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
        if self.pe_header_state is not None:
            if not self.mz_header_detected:
                raise ValueError(
                    "ExtractRecord.pe_header_state must be None when mz_header_detected is "
                    "False -- no structural PE parse is ever attempted without a confirmed MZ "
                    "prefix")
            if self.pe_header_state not in _PE_HEADER_STATES:
                raise ValueError(
                    f"ExtractRecord.pe_header_state must be None or one of {_PE_HEADER_STATES}, "
                    f"got {self.pe_header_state!r}")

    def to_dict(self) -> dict:
        return {
            "requested_address":  self.requested_address,
            "requested_size":     self.requested_size,
            "auto_sized":         self.auto_sized,
            "bytes_read":         self.bytes_read,
            "mz_header_detected": self.mz_header_detected,
            "pe_header_state":    self.pe_header_state,
        }


@dataclass
class StringRecord:
    """One extracted string -- `--strings`' record, also reused as-is by
    `--report`'s own "notable strings" section (see
    dumpex.commands.report). `offset` is a plain int (a byte offset
    relative to the read region's start, NOT a process address -- the
    hex_address()-only-for-real-addresses rule in
    dumpex.output.records.common's docstring doesn't apply to it) while `address` is the absolute VA
    (the requested read's own base address + offset), a real memory
    address, so it goes through hex_address() like every other
    address-typed field -- and, unlike most other address-typed fields in
    these records, always non-null: a string was found at some real address,
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
