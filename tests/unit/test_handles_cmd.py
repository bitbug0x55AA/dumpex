"""Unit tests for dumpex.commands.handles -- issue #42's collect/render/
command vertical slice over docs/recon_process_sysinfo_handles_contract.md
§5.

Most cases go through the REAL parser
(dumpex.core.memory.parse_handle_stream) over real HandleDataStream
bytes, so the record builder is exercised against exactly the object
`open_dump()` puts on `mf.handles` -- not a hand-shaped stand-in that
could drift from it. The few shapes that parser cannot produce (a
non-integer/out-of-range `Handle`, a descriptor missing an attribute
entirely) are built directly, since §5.2.2's discard rule has to hold for
them too.
"""
import io
import types
import re
import struct
import contextlib

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

from tests.fixtures.fakes import FakeMF

from dumpex.core.memory import parse_handle_stream, ParsedHandleDescriptor, ParsedHandleDataStream
from dumpex.commands.handles import (
    collect_handles, cmd_handles, render_handles_console, summarize_handles_by_type,
)
from dumpex.ui.console_layout import resolve_width, strip_ansi
from dumpex.output.coverage import (
    CoverageStatus, LimitationCode, SourceState, exit_code_for, render_limitation,
)


HANDLE_STREAM = MINIDUMP_STREAM_TYPE.HandleDataStream

# A name spec of BAD_RVA gets a non-zero RVA pointing past the end of the
# file: the bounded read comes back short, so _read_handle_string()
# returns None -- §5.2.1's "unreadable", which is a different fact from
# both "no name" (RVA 0) and "" (a successful zero-length read).
BAD_RVA = object()


# ── Stream builders ──────────────────────────────────────────────────────

class _Location:
    def __init__(self, rva, data_size):
        self.Rva = rva
        self.DataSize = data_size


class _Directory:
    def __init__(self, rva, data_size, stream_type=HANDLE_STREAM):
        self.Location = _Location(rva, data_size)
        self.StreamType = stream_type


def _minidump_string_bytes(s: str) -> bytes:
    encoded = s.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded


def _build_handle_stream(descriptors, *, size_of_descriptor=32, number_of_descriptors=None,
                          declared_data_size=None):
    """Raw HandleDataStream bytes (16-byte header + fixed-size descriptor
    array + a trailing string area) plus the (rva=0, data_size) framing.
    Mirrors tests/unit/test_handle_stream_parse.py's own builder, with
    per-name RVA control (a real string, no name at all, or BAD_RVA)."""
    n = number_of_descriptors if number_of_descriptors is not None else len(descriptors)
    header = struct.pack("<IIII", 16, size_of_descriptor, n, 0)

    desc_area_size = 16 + len(descriptors) * size_of_descriptor
    strings_blob = bytearray()
    desc_bytes = bytearray()
    unreachable_rva = 0xF000_0000   # far past the end of every fixture body
    for d in descriptors:
        rvas = []
        for key in ("type_name", "object_name"):
            name = d.get(key)
            if name is None:
                rvas.append(0)
            elif name is BAD_RVA:
                rvas.append(unreachable_rva)
            else:
                rvas.append(desc_area_size + len(strings_blob))
                strings_blob += _minidump_string_bytes(name)
        fixed = struct.pack("<QIIIIII", d["handle"], rvas[0], rvas[1],
                             d.get("attributes", 0), d.get("granted_access", 0),
                             d.get("handle_count", 1), d.get("pointer_count", 1))
        if size_of_descriptor == 40:
            fixed += struct.pack("<II", 0, 0)   # ObjectInfoRva/Reserved0 -- never walked
        desc_bytes += fixed

    body = header + bytes(desc_bytes) + bytes(strings_blob)
    data_size = declared_data_size if declared_data_size is not None else desc_area_size
    return body, data_size


def _parsed(descriptors, **kwargs):
    body, data_size = _build_handle_stream(descriptors, **kwargs)
    return parse_handle_stream(_Directory(rva=0, data_size=data_size), io.BytesIO(body))


def _mf(*, parsed=None, failure=None, has_directory=None):
    """A FakeMF in one of §5.5's stream states. `has_directory` defaults
    to "the dump declares the stream whenever there is anything to
    declare", which is what open_dump() always produces."""
    mf = FakeMF()
    mf.handles = parsed
    mf._dumpex_stream_failures = {HANDLE_STREAM: failure} if failure else {}
    if has_directory is None:
        has_directory = parsed is not None or failure is not None
    mf.directories = [_Directory(0, 16)] if has_directory else []
    return mf


def _mf_with(descriptors, **kwargs):
    return _mf(parsed=_parsed(descriptors, **kwargs))


def _codes(coverage):
    return [l.code for l in coverage.limitations]


def _limitation(coverage, code):
    return next((l for l in coverage.limitations if l.code == code), None)


def _console_via_cmd(mf, *, verbose=False) -> str:
    """The console for a whole dump, through cmd_handles() -- the path
    that reads the dump's OS version. `_console()` renders already
    collected records and cannot see it."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cmd_handles(mf, verbose=verbose)
    return buffer.getvalue()


def _console(result, *, verbose=False) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render_handles_console(result.records, result.coverage, verbose=verbose)
    return buffer.getvalue()


def _rows(text: str) -> list:
    """The table rows only -- every one starts with a fixed-width handle
    value, which no other line in the block does."""
    return [line for line in text.splitlines()
            if line.strip().startswith("0x") and "  " in line.strip()]


# ── §5.5 case 1: no HandleDataStream at all ─────────────────────────────

def test_absent_stream_is_not_evaluated_with_an_actionable_reason():
    result = collect_handles(_mf())

    assert result.kind == "handles"
    assert result.records == []
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status) == 4
    assert _codes(result.coverage) == [LimitationCode.HANDLES_UNAVAILABLE]
    assert result.coverage.reasons == [
        "HandleDataStream not present in this dump (not captured with handle data)"]
    assert result.coverage.sources["handles"].state == SourceState.ABSENT
    assert result.coverage.sources["handle_records"].state == SourceState.ABSENT
    assert result.summary == {"count": 0, "by_type": {}}


# ── §5.5 case 2: present but unparseable ────────────────────────────────

def test_parse_failure_is_never_a_clean_zero_handle_result():
    detail = "HandleStreamFramingError: HandleDataStream SizeOfDescriptor 33 is neither 32 nor 40"
    result = collect_handles(_mf(failure=detail))

    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status) == 4
    # Both limitations, in the frozen order: the group's own code, then
    # the SOURCE_FAILED carrying the parser's error text (the group code
    # cannot carry a detail of its own).
    assert _codes(result.coverage) == [
        LimitationCode.HANDLES_PARSE_FAILED, LimitationCode.SOURCE_FAILED]
    assert result.coverage.sources["handles"].state == SourceState.FAILED
    assert result.coverage.sources["handles"].detail == detail
    assert detail in result.coverage.reasons[1]
    assert "HandleDataStream present but could not be read" in result.coverage.reasons[1]


def test_parse_failed_and_unavailable_are_never_the_same_reason():
    """§5.5: "not captured with handle data" and "captured, but the
    handle data will not parse" send an analyst to different next steps,
    and both map to exit 4 without becoming the same string."""
    absent = collect_handles(_mf())
    failed = collect_handles(_mf(failure="HandleDescriptorLayoutError: layout drift"))

    assert exit_code_for(absent.coverage.status) == exit_code_for(failed.coverage.status) == 4
    assert _codes(absent.coverage)[0] != _codes(failed.coverage)[0]
    assert absent.coverage.reasons[0] != failed.coverage.reasons[0]


def test_library_layout_drift_detail_survives_into_coverage():
    """A HandleDescriptorLayoutError means the installed minidump library
    drifted from the on-disk layout -- the dump is probably fine. That
    distinction only reaches the analyst through the SOURCE_FAILED
    detail, so it must not be collapsed into a generic "parse failed"."""
    detail = ("HandleDescriptorLayoutError: minidump.streams.HandleDataStream."
              "MINIDUMP_HANDLE_DESCRIPTOR now reports 36 bytes")
    result = collect_handles(_mf(failure=detail))
    assert result.coverage.sources["handles"].detail == detail
    assert "MINIDUMP_HANDLE_DESCRIPTOR now reports 36 bytes" in " ".join(result.coverage.reasons)


def test_declared_stream_with_no_parsed_object_fails_closed_as_failed_evidence():
    """A directory entry with neither a parsed stream nor a recorded
    failure is not reachable through today's open_dump() -- but if it
    ever is, reporting "this dump was not captured with handle data"
    would be a false claim about the evidence. It fails closed to case 2
    instead."""
    result = collect_handles(_mf(parsed=None, failure=None, has_directory=True))

    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert _codes(result.coverage) == [
        LimitationCode.HANDLES_PARSE_FAILED, LimitationCode.SOURCE_FAILED]
    assert result.coverage.sources["handles"].state == SourceState.FAILED


# ── §5.5 case 4: present-empty ──────────────────────────────────────────

def test_present_empty_stream_is_complete_with_zero_records():
    result = collect_handles(_mf_with([]))

    assert result.records == []
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status) == 0
    assert result.coverage.limitations == []
    assert result.coverage.sources["handles"].state == SourceState.PRESENT_EMPTY
    assert result.coverage.sources["handles"].record_count == 0
    assert result.coverage.sources["handle_records"].state == SourceState.PRESENT_EMPTY
    assert result.summary == {"count": 0, "by_type": {}}


# ── §5.5 case 5 / §5.2: a populated stream ──────────────────────────────

_POPULATED = [
    {"handle": 0x234, "type_name": "File", "object_name": "\\Device\\NamedPipe\\mypipe",
     "attributes": 0, "granted_access": 0x0012019F, "handle_count": 1, "pointer_count": 32},
    {"handle": 0x238, "type_name": "Key", "object_name": None,
     "attributes": 2, "granted_access": 0x00020019, "handle_count": 1, "pointer_count": 3},
]


def test_populated_stream_is_complete_and_lossless():
    result = collect_handles(_mf_with(_POPULATED))

    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status) == 0
    assert result.coverage.limitations == []
    assert result.coverage.sources["handles"].record_count == 2
    assert result.coverage.sources["handle_records"].state == SourceState.PRESENT
    assert result.coverage.sources["handle_records"].record_count == 2

    assert result.records[0].to_dict() == {
        "handle": "0x0000000000000234",
        "type_name": "File", "type_name_status": "ok",
        "object_name": "\\Device\\NamedPipe\\mypipe", "object_name_status": "ok",
        "attributes": 0, "granted_access": 0x0012019F,
        "handle_count": 1, "pointer_count": 32,
    }
    # Masks stay RAW integers on the wire (§1.3/§5.2) -- undecoded, and
    # not hex strings.
    assert isinstance(result.records[0].granted_access, int)
    assert result.records[1].to_dict()["object_name"] is None
    assert result.records[1].to_dict()["object_name_status"] == "unnamed"


@pytest.mark.parametrize("size_of_descriptor", [32, 40])
def test_v1_and_v2_descriptors_produce_identical_records(size_of_descriptor):
    """The v2 descriptor adds only ObjectInfoRva/Reserved0, which §5.3
    never exposes -- so the seven reported fields must be byte-identical
    between the two layouts. A stride/parser mismatch (issue #86) would
    show up here as shifted field values, not as an exception."""
    result = collect_handles(_mf_with(_POPULATED, size_of_descriptor=size_of_descriptor))
    assert [r.to_dict() for r in result.records] == [
        {"handle": "0x0000000000000234", "type_name": "File", "type_name_status": "ok",
         "object_name": "\\Device\\NamedPipe\\mypipe", "object_name_status": "ok",
         "attributes": 0, "granted_access": 0x0012019F, "handle_count": 1, "pointer_count": 32},
        {"handle": "0x0000000000000238", "type_name": "Key", "type_name_status": "ok",
         "object_name": None, "object_name_status": "unnamed",
         "attributes": 2, "granted_access": 0x00020019, "handle_count": 1, "pointer_count": 3},
    ]


def test_maximum_width_values_and_zero_counters_survive_intact():
    result = collect_handles(_mf_with([
        {"handle": 0xFFFF_FFFF_FFFF_FFFF, "type_name": "Event", "object_name": None,
         "attributes": 0xFFFF_FFFF, "granted_access": 0xFFFF_FFFF,
         "handle_count": 0xFFFF_FFFF, "pointer_count": 0},
        {"handle": 0, "type_name": None, "object_name": None,
         "attributes": 0, "granted_access": 0, "handle_count": 0, "pointer_count": 0},
    ]))

    biggest = result.records[-1]
    assert biggest.handle == "0xffffffffffffffff"
    assert biggest.granted_access == 0xFFFF_FFFF
    assert biggest.attributes == 0xFFFF_FFFF
    assert biggest.handle_count == 0xFFFF_FFFF
    # 0 is a captured value, never null -- "zero pointers" and "pointer
    # count unavailable" are different facts.
    assert biggest.pointer_count == 0
    zero_handle = result.records[0]
    assert zero_handle.handle == "0x0000000000000000"
    assert zero_handle.handle_count == 0 and zero_handle.pointer_count == 0
    assert result.coverage.status == CoverageStatus.COMPLETE


# ── §5.4 ordering ───────────────────────────────────────────────────────

def test_records_sort_numerically_ascending_by_handle_value():
    result = collect_handles(_mf_with([
        {"handle": 0x1000, "type_name": "File", "object_name": None},
        {"handle": 0x8, "type_name": "File", "object_name": None},
        {"handle": 0xFFFF_FFFF_FFFF_FFFF, "type_name": "File", "object_name": None},
        {"handle": 0x100, "type_name": "File", "object_name": None},
    ]))
    assert [r.handle for r in result.records] == [
        "0x0000000000000008", "0x0000000000000100", "0x0000000000001000",
        "0xffffffffffffffff",
    ]


def test_duplicate_handle_values_keep_the_streams_own_order():
    """§5.4: equal values (which only a malformed dump produces) keep
    source order -- a stable sort, never a re-shuffle."""
    result = collect_handles(_mf_with([
        {"handle": 0x40, "type_name": "File", "object_name": "second-in-value-order"},
        {"handle": 0x10, "type_name": "File", "object_name": "first"},
        {"handle": 0x40, "type_name": "File", "object_name": "third"},
        {"handle": 0x40, "type_name": "File", "object_name": "fourth"},
    ]))
    assert [r.object_name for r in result.records] == [
        "first", "second-in-value-order", "third", "fourth"]


# ── §5.2.1 name statuses ────────────────────────────────────────────────

def test_unreadable_name_keeps_the_record_and_drives_partial():
    """§8.3 item 5b, all four shapes in one run."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": None, "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": "\\BaseNamedObjects\\thing"},
        {"handle": 0x30, "type_name": "File", "object_name": BAD_RVA},
        {"handle": 0x40, "type_name": BAD_RVA, "object_name": BAD_RVA},
    ]))

    statuses = [(r.type_name_status, r.object_name_status) for r in result.records]
    assert statuses == [
        ("unnamed", "unnamed"), ("unnamed", "ok"), ("ok", "unreadable"),
        ("unreadable", "unreadable"),
    ]
    # No descriptor is ever dropped for a name failure.
    assert len(result.records) == 4
    assert all(r.type_name is None or r.type_name_status == "ok" for r in result.records)
    assert result.records[2].object_name is None
    assert result.records[2].handle_count is not None   # every other field intact

    assert result.coverage.status == CoverageStatus.PARTIAL
    assert exit_code_for(result.coverage.status) == 3
    limitation = _limitation(result.coverage, LimitationCode.HANDLE_STRING_READ_FAILED)
    # Descriptors, not fields: the handle that lost BOTH names counts once.
    assert limitation.affected_count == 2
    assert render_limitation(limitation) == (
        "2 handle(s) have a type or object name that could not be read or decoded")


def test_unnamed_only_stream_stays_complete():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": None, "object_name": None},
        {"handle": 0x20, "type_name": "Key", "object_name": None},
    ]))
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status) == 0
    assert result.coverage.limitations == []


@pytest.mark.parametrize("field", ["type_name", "object_name"])
def test_present_but_empty_name_is_unnamed_not_a_read_failure(field):
    """§8.3 item 6c: a non-zero RVA whose MINIDUMP_STRING.Length is 0
    read successfully -- nothing was lost, so it is "unnamed" with a null
    value, no HANDLE_STRING_READ_FAILED, and exit 0."""
    descriptor = {"handle": 0x10, "type_name": "File", "object_name": "\\Device\\X"}
    descriptor[field] = ""
    result = collect_handles(_mf_with([descriptor]))

    record = result.records[0]
    assert getattr(record, field) is None
    assert getattr(record, f"{field}_status") == "unnamed"
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status) == 0
    assert LimitationCode.HANDLE_STRING_READ_FAILED not in _codes(result.coverage)


def test_placeholder_decode_string_never_reaches_a_record():
    """§5.1 item 3: the library's own '<STRING_DECODE_FAILED>' must never
    be emitted as a name -- a failed decode is null + "unreadable"."""
    result = collect_handles(_mf_with([{"handle": 0x10, "type_name": BAD_RVA,
                                         "object_name": BAD_RVA}]))
    serialized = str(result.records[0].to_dict())
    assert "STRING_DECODE_FAILED" not in serialized


# ── §5.2.2 / §5.5 case 3: descriptor normalization ──────────────────────

def _descriptor(handle, **kwargs):
    """A ParsedHandleDescriptor built directly -- for the Handle values
    the real parser cannot produce (it reads a `<Q`, so it can only ever
    hand back an in-range int)."""
    return ParsedHandleDescriptor(
        handle=handle, type_name=kwargs.get("type_name"), object_name=kwargs.get("object_name"),
        attributes=kwargs.get("attributes", 0), granted_access=kwargs.get("granted_access", 1),
        handle_count=kwargs.get("handle_count", 1), pointer_count=kwargs.get("pointer_count", 1),
        type_name_rva=kwargs.get("type_name_rva", 0),
        object_name_rva=kwargs.get("object_name_rva", 0))


class _Header:
    def __init__(self, number_of_descriptors):
        self.NumberOfDescriptors = number_of_descriptors


def _mf_from_descriptors(descriptors, *, declared=None):
    parsed = ParsedHandleDataStream(
        header=_Header(len(descriptors) if declared is None else declared),
        handles=list(descriptors))
    return _mf(parsed=parsed)


@pytest.mark.parametrize("bad_handle", [None, "0x10", 1.5, True, -1, 1 << 64])
def test_unusable_handle_values_discard_only_that_descriptor(bad_handle):
    result = collect_handles(_mf_from_descriptors([
        _descriptor(bad_handle), _descriptor(0x50, type_name="File", type_name_rva=8),
    ]))

    assert [r.handle for r in result.records] == ["0x0000000000000050"]
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert exit_code_for(result.coverage.status) == 3
    limitation = _limitation(result.coverage, LimitationCode.HANDLE_DESCRIPTOR_INVALID)
    assert limitation.affected_count == 1
    assert render_limitation(limitation) == "1 handle descriptor(s) could not be normalized"
    # The surviving record is fully reported -- partial loss never
    # discards what normalized.
    assert result.records[0].type_name == "File"


def test_all_descriptors_invalid_is_not_evaluated_and_keeps_the_descriptor_count():
    result = collect_handles(_mf_from_descriptors([_descriptor(None), _descriptor("nope")]))

    assert result.records == []
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status) == 4
    assert _codes(result.coverage) == [LimitationCode.HANDLES_ALL_DESCRIPTORS_INVALID]
    # §6.1: the descriptor count lives on the stream source, so the
    # aggregate code needs no field of its own.
    assert result.coverage.sources["handles"].state == SourceState.PRESENT
    assert result.coverage.sources["handles"].record_count == 2
    assert result.coverage.sources["handle_records"].state == SourceState.ABSENT
    # Never HANDLE_DESCRIPTOR_INVALID as well: one fact, one limitation.
    assert LimitationCode.HANDLE_DESCRIPTOR_INVALID not in _codes(result.coverage)


def test_all_invalid_is_distinguishable_from_present_empty():
    """Both report zero records; only one of them is a complete answer."""
    empty = collect_handles(_mf_with([]))
    all_invalid = collect_handles(_mf_from_descriptors([_descriptor(None)]))

    assert empty.coverage.status == CoverageStatus.COMPLETE
    assert all_invalid.coverage.status == CoverageStatus.NOT_EVALUATED
    assert empty.coverage.sources["handles"].state == SourceState.PRESENT_EMPTY
    assert all_invalid.coverage.sources["handles"].state == SourceState.PRESENT


@pytest.mark.parametrize("value", [b"File", 42, ["File"]])
def test_a_non_string_name_is_a_read_failure_not_a_crash(value):
    """Every other descriptor field this module reads is type-checked
    before it reaches the record (an unusable Handle discards the
    descriptor, an unusable counter becomes null). A name skipping that
    check would raise out of HandleRecord's own validation and abort the
    command -- a traceback where every other unusable-evidence path
    produces exit 4 with a readable reason."""
    result = collect_handles(_mf_from_descriptors([
        _descriptor(0x10, type_name=value, type_name_rva=8),
    ]))

    record = result.records[0]
    assert record.type_name is None
    assert record.type_name_status == "unreadable"
    assert record.handle == "0x0000000000000010"   # the record is kept
    assert _limitation(result.coverage, LimitationCode.HANDLE_STRING_READ_FAILED).affected_count == 1
    assert exit_code_for(result.coverage.status) == 3


def test_unreadable_numeric_field_nulls_the_field_and_keeps_the_record():
    """§5.2.2: only the Handle discards a descriptor. Every other field
    degrades to null in place."""
    result = collect_handles(_mf_from_descriptors([
        _descriptor(0x10, granted_access=None, attributes="?", handle_count=-4,
                     pointer_count=True),
    ]))
    record = result.records[0]
    assert record.handle == "0x0000000000000010"
    assert (record.granted_access, record.attributes, record.handle_count,
            record.pointer_count) == (None, None, None, None)
    assert result.coverage.status == CoverageStatus.COMPLETE


# ── §5.1.1 rules 4-5: truncation ────────────────────────────────────────

def test_truncated_stream_reports_the_unread_tail_and_keeps_the_head():
    """The stream declares 5 descriptors but its own DataSize only covers
    2. `affected_count` is header.NumberOfDescriptors - len(handles) --
    read off the parser's object, never recomputed."""
    result = collect_handles(_mf_with(
        [{"handle": 0x10 * (i + 1), "type_name": "File", "object_name": None} for i in range(2)],
        number_of_descriptors=5))

    assert len(result.records) == 2   # a truncated tail never discards a readable head
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert exit_code_for(result.coverage.status) == 3
    limitation = _limitation(result.coverage, LimitationCode.HANDLE_STREAM_TRUNCATED)
    assert limitation.affected_count == 3
    assert render_limitation(limitation) == (
        "HandleDataStream declares more descriptors than dumpex will parse; "
        "3 descriptor(s) were not read")


def test_truncation_is_read_off_the_header_not_recomputed_from_the_framing():
    """§5.1.1 rule 5's MUST, in the only shape that can falsify it: the
    stream's own framing (DataSize) has room for 5 descriptors, but the
    FILE ends after 2. Reading `header.NumberOfDescriptors -
    len(handles)` off the returned object gives the true 3; recomputing
    from rule 4's three-term formula gives
    `5 - min(5, MAX_HANDLE_DESCRIPTORS, (176-16)//32)` == 0 -- i.e. no
    truncation reported at all, and a silent `complete`/exit 0 on a dump
    that lost handles. Every other truncation fixture stops at the
    DataSize bound, where both answers agree."""
    mf = _mf_with([{"handle": 0x10 * (i + 1)} for i in range(2)],
                   number_of_descriptors=5, declared_data_size=16 + 5 * 32)
    # The framing really does claim room the file does not have.
    assert mf.handles.header.NumberOfDescriptors == 5
    assert len(mf.handles.handles) == 2

    result = collect_handles(mf)
    assert _limitation(result.coverage, LimitationCode.HANDLE_STREAM_TRUNCATED).affected_count == 3
    assert len(result.records) == 2
    assert exit_code_for(result.coverage.status) == 3
    # #86 regression guard: the missing descriptors must not come back as
    # all-zero records read from an empty buffer.
    assert "0x0000000000000000" not in [r.handle for r in result.records]


def test_truncation_to_zero_descriptors_is_not_a_complete_empty_result():
    """The dangerous shape: a stream claiming handles whose descriptor
    array was cut off entirely must never look like case 4's clean
    present-empty answer."""
    result = collect_handles(_mf_with([], number_of_descriptors=7))

    assert result.records == []
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert exit_code_for(result.coverage.status) == 3
    assert _limitation(result.coverage, LimitationCode.HANDLE_STREAM_TRUNCATED).affected_count == 7


def test_truncation_and_string_failures_survive_a_not_evaluated_result():
    """§5.5's retention rule: in case 3's total loss the exit-4 result
    must still say what went wrong with the descriptors the aggregate
    code only counts."""
    result = collect_handles(_mf_from_descriptors(
        [_descriptor(None), _descriptor("bad", type_name_rva=0x40)], declared=6))

    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status) == 4
    assert _codes(result.coverage) == [
        LimitationCode.HANDLES_ALL_DESCRIPTORS_INVALID, LimitationCode.HANDLE_STREAM_TRUNCATED]


def test_limitation_order_is_stream_then_descriptors_then_names():
    result = collect_handles(_mf_with(
        [{"handle": 0x10, "type_name": BAD_RVA, "object_name": None},
         {"handle": 0x20, "type_name": "File", "object_name": None}],
        number_of_descriptors=4))
    assert _codes(result.coverage) == [
        LimitationCode.HANDLE_STREAM_TRUNCATED, LimitationCode.HANDLE_STRING_READ_FAILED]

    mixed = collect_handles(_mf_from_descriptors(
        [_descriptor(None), _descriptor(0x10, type_name_rva=0x99)], declared=3))
    assert _codes(mixed.coverage) == [
        LimitationCode.HANDLE_STREAM_TRUNCATED, LimitationCode.HANDLE_DESCRIPTOR_INVALID,
        LimitationCode.HANDLE_STRING_READ_FAILED]


def test_discarded_descriptors_are_not_double_counted_as_name_failures():
    """A descriptor discarded for its Handle is counted once, by
    HANDLE_DESCRIPTOR_INVALID -- its unread names must not also inflate
    HANDLE_STRING_READ_FAILED."""
    result = collect_handles(_mf_from_descriptors([
        _descriptor(None, type_name_rva=0x99, object_name_rva=0x99),
        _descriptor(0x10, type_name="File", type_name_rva=8),
    ]))
    assert _limitation(result.coverage, LimitationCode.HANDLE_DESCRIPTOR_INVALID).affected_count == 1
    assert _limitation(result.coverage, LimitationCode.HANDLE_STRING_READ_FAILED) is None


def test_missing_descriptor_count_never_invents_a_truncation():
    """A header without a usable NumberOfDescriptors cannot support a
    truncation claim -- reporting one would put a fabricated count in
    front of an analyst."""
    class _NoCount:
        NumberOfDescriptors = None

    parsed = ParsedHandleDataStream(header=_NoCount(), handles=[_descriptor(0x10)])
    result = collect_handles(_mf(parsed=parsed))
    assert LimitationCode.HANDLE_STREAM_TRUNCATED not in _codes(result.coverage)
    assert result.coverage.status == CoverageStatus.COMPLETE


def test_console_marks_an_unavailable_access_mask_without_faking_a_value():
    # A retained type, so the row survives the default projection -- a
    # descriptor with no type and no object name is the exact shape the
    # fold collapses (#98), and this case is about the Access column.
    result = collect_handles(_mf_from_descriptors(
        [_descriptor(0x10, granted_access=None, type_name="Process", type_name_rva=8)]))
    row = next(l for l in _console(result).splitlines() if "0x0000000000000010" in l)
    # The Access column says the mask is unavailable -- never a
    # fabricated 0x00000000, which reads as a real, zero-rights mask.
    assert "(unknown)" in row
    assert "0x00000000 " not in row.split("0x0000000000000010", 1)[1]


# ── §5.6 summary ────────────────────────────────────────────────────────

def test_summary_by_type_is_ordered_count_desc_then_name_asc():
    result = collect_handles(_mf_with(
        [{"handle": 0x10 + i, "type_name": "File", "object_name": None} for i in range(3)]
        + [{"handle": 0x100 + i, "type_name": "Event", "object_name": None} for i in range(3)]
        + [{"handle": 0x200, "type_name": "Key", "object_name": None}]))

    assert result.summary["count"] == 7
    assert list(result.summary["by_type"].items()) == [("Event", 3), ("File", 3), ("Key", 1)]


def test_summary_never_merges_unnamed_and_unreadable_types():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": None, "object_name": None},
        {"handle": 0x20, "type_name": BAD_RVA, "object_name": None},
        {"handle": 0x30, "type_name": "File", "object_name": BAD_RVA},
    ]))
    # object_name_status never affects bucketing -- the File handle with
    # an unreadable OBJECT name still counts under "File".
    assert result.summary["by_type"] == {"(unnamed)": 1, "(unreadable)": 1, "File": 1}


def test_a_captured_type_name_never_merges_into_a_placeholder_bucket():
    """§5.6's two labels share a string space with captured type names.
    A dump carrying a type literally named "(unnamed)" must not be summed
    into the null-name bucket -- that would inflate the one bucket an
    analyst is least likely to look through, and make the summary
    contradict the record layer, which keeps the two apart via
    type_name_status."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": None},
        {"handle": 0x30, "type_name": "(unreadable)", "object_name": None},
        {"handle": 0x40, "type_name": BAD_RVA, "object_name": None},
    ]))

    by_type = result.summary["by_type"]
    assert len(by_type) == 4 and set(by_type.values()) == {1}
    # The reserved labels keep meaning exactly what §5.6 says they mean...
    assert by_type["(unnamed)"] == 1
    assert by_type["(unreadable)"] == 1
    # ... and the captured names still get their own keys rather than
    # being dropped or silently folded in.
    assert by_type["(unnamed) [captured name]"] == 1
    assert by_type["(unreadable) [captured name]"] == 1
    assert sum(by_type.values()) == result.summary["count"] == 4

    # The console reads the same buckets, so it cannot disagree.
    listed = next(l for l in _console(result).splitlines() if "By type:" in l)
    assert listed.count("(unnamed)") == 2 and listed.count("(unreadable)") == 2


def test_placeholder_collision_disambiguation_is_deterministic():
    """Record order must not decide which bucket keeps the clean label."""
    forward = [
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": None},
    ]
    reverse = [
        {"handle": 0x10, "type_name": None, "object_name": None},
        {"handle": 0x20, "type_name": "(unnamed)", "object_name": None},
    ]
    assert (collect_handles(_mf_with(forward)).summary["by_type"]
            == collect_handles(_mf_with(reverse)).summary["by_type"]
            == {"(unnamed)": 1, "(unnamed) [captured name]": 1})


def test_a_captured_name_colliding_with_the_disambiguated_key_also_separates():
    """The suffix is applied until the key is free, so an adversarial
    dump cannot force two buckets into one by pre-claiming it."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": "(unnamed) [captured name]", "object_name": None},
        {"handle": 0x30, "type_name": None, "object_name": None},
    ]))
    assert len(result.summary["by_type"]) == 3
    assert sum(result.summary["by_type"].values()) == 3


def test_by_type_keys_are_ordered_on_the_final_labels():
    """§1.5 orders by name ascending -- which has to hold for the keys
    actually emitted, not for the pre-disambiguation names they were
    derived from. Sorting before projection put
    "(unnamed) [captured name]" ahead of "(unnamed) A" (space < "A" only
    before the suffix is applied; "A" < "[" after)."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": None},
        {"handle": 0x30, "type_name": "(unnamed) A", "object_name": None},
    ]))
    by_type = result.summary["by_type"]
    assert list(by_type) == sorted(by_type, key=lambda key: (-by_type[key], key))
    assert list(by_type) == ["(unnamed)", "(unnamed) A", "(unnamed) [captured name]"]


def test_the_console_table_and_the_summary_project_names_the_same_way():
    """The buckets being right is worth nothing if the table an analyst
    actually reads still shows both as "(unnamed)": they would go looking
    for the row the summary promised and find two identical ones. The
    projection is shared, so the labels in the Type column and the keys
    of by_type are the same set."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": None},
    ]))
    # Rendered verbose: both rows are anonymous, so the DEFAULT console
    # folds BOTH (#98). The claim under test is that the Type column and
    # by_type project a name the same way, which is a property of the
    # projection, not of which rows a view chose to print.
    rows = [l for l in _console(result, verbose=True).splitlines() if "0x00000000000000" in l]
    types = [l.split("  ")[2].strip() for l in rows]

    assert types[0] != types[1]                       # the two rows are distinguishable
    assert set(types) == set(result.summary["by_type"])
    assert "(unnamed) [captured name]" in types       # the captured name ...
    assert "(unnamed)" in types                       # ... and the null one


def test_a_captured_object_name_cannot_claim_the_reserved_labels_either():
    """The Object column has no summary to cross-check it, so a captured
    object name literally called "(unreadable)" would be the analyst's
    only signal -- and it would be a false one: it says dumpex lost the
    name, when the dump recorded exactly that string."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "(unreadable)"},
        {"handle": 0x20, "type_name": "File", "object_name": BAD_RVA},
    ]))
    captured, lost = result.records
    assert captured.object_name == "(unreadable)" and captured.object_name_status == "ok"
    assert lost.object_name is None and lost.object_name_status == "unreadable"

    rows = [l for l in _console(result).splitlines() if "0x00000000000000" in l]
    assert rows[0].endswith("(unreadable) [captured name]")
    assert rows[1].endswith("(unreadable)")


def test_a_name_already_carrying_the_suffix_stays_distinct_everywhere():
    """The disambiguation must be injective, not merely applied: a dump
    carrying BOTH "(unnamed)" and "(unnamed) [captured name]" used to
    collapse them into one label in the console table while the summary
    told them apart -- the two call sites disagreeing about the same two
    handles."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": "(unnamed) [captured name]", "object_name": None},
    ]))

    # Verbose for the same reason as the case above: both rows are
    # anonymous and the default view folds them.
    rows = [l for l in _console(result, verbose=True).splitlines() if "0x00000000000000" in l]
    types = [l.split("  ")[2].strip() for l in rows]
    assert types[0] != types[1]
    assert set(types) == set(result.summary["by_type"])
    assert len(result.summary["by_type"]) == 2


def test_by_type_is_empty_when_there_are_no_records():
    assert collect_handles(_mf_with([])).summary["by_type"] == {}
    assert summarize_handles_by_type([]) == {}


# ── §5.6 console ────────────────────────────────────────────────────────

def test_console_table_prints_each_null_name_by_its_own_status():
    result = collect_handles(_mf_with([
        {"handle": 0x234, "type_name": "File", "object_name": "\\Device\\NamedPipe\\mypipe",
         "granted_access": 0x0012019F, "handle_count": 1, "pointer_count": 32},
        {"handle": 0x238, "type_name": "Key", "object_name": None,
         "granted_access": 0x00020019, "handle_count": 1, "pointer_count": 3},
        {"handle": 0x23C, "type_name": BAD_RVA, "object_name": BAD_RVA,
         "granted_access": 1, "handle_count": 1, "pointer_count": 2},
    ]))
    # Verbose: the anonymous Key row is folded out of the default view
    # (#98), and this case is about how each null name PRINTS, not about
    # which rows a view selects. The widths are unchanged either way --
    # "(unreadable)" (12) is still narrower than the Type column's
    # minimum, so §5.6's sample rows stay byte-identical.
    text = _console(result, verbose=True)

    assert "0x0000000000000234  File            0x0012019f    1   32  \\Device\\NamedPipe\\mypipe" in text
    assert "0x0000000000000238  Key             0x00020019    1    3  (unnamed)" in text
    assert "0x000000000000023c  (unreadable)    0x00000001    1    2  (unreadable)" in text
    assert "3 handle(s) captured" in text
    assert "By type: (unreadable) 1, File 1, Key 1" in text


@pytest.mark.parametrize("type_name", [
    "WaitCompletionPacket",   # 20 -- real Windows kernel object types
    "FilterConnectionPort",   # 20
    "IoCompletionReserve",    # 19
    "DxgkSharedResource",     # 18
    "ActivityReference",      # 17
    "ActivationObject",       # 16 -- the exact width of the old column
    "PowerRequestType",       # 16
    "WmiGuidQwerty1",         # 14 -- the new column width
    "WmiGuidQwert1",          # 13
])
def test_a_long_type_name_never_collides_with_the_access_mask(type_name):
    """`{name:<16}` was a MINIMUM width, not a truncation: a 16-character
    type name left no separator at all, rendering "ActivationObject
    0x00000002" as one unsplittable token exactly where an analyst reads
    the granted-access mask (and breaking any column-wise awk/copy-paste
    of the table). The name is never truncated -- that would drop
    evidence -- so the columns shift instead."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": type_name, "object_name": "X", "granted_access": 1},
    ]))
    row = next(l for l in _console(result).splitlines() if "0x0000000000000010" in l)

    assert type_name in row                      # never truncated
    assert f"{type_name}0x" not in row           # never fused to the mask
    tokens = row.split()
    assert tokens[1] == type_name                # Type and Access are two
    assert tokens[2] == "0x00000001"             # independent tokens


def test_the_type_column_separator_matches_every_other_column():
    """Handle -> Type, Cnt -> Ptr and Ptr -> Object are all separated by
    two spaces; Type -> Access must not be the one exception."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": BAD_RVA, "granted_access": 1},
    ]))
    lines = _console(result).splitlines()
    header = next(l for l in lines if "Handle" in l and "Access" in l)
    row = next(l for l in lines if "0x0000000000000010" in l)

    assert "  Access" in header
    assert "File" in row and "  0x00000001" in row
    # "(unreadable)" (12 chars) is the longest name in §5.6's own sample
    # rows -- it must still sit in the same columns as before.
    unreadable = collect_handles(_mf_with([
        {"handle": 0x23C, "type_name": BAD_RVA, "object_name": BAD_RVA, "granted_access": 1,
         "handle_count": 1, "pointer_count": 2},
    ]))
    assert ("0x000000000000023c  (unreadable)    0x00000001    1    2  (unreadable)"
            in _console(unreadable))


def _assert_columns_stay_separated(row: str, cells: list) -> None:
    """Every adjacent pair of rendered cells must keep whitespace between
    them -- the property the two literal spaces after each column exist
    to guarantee, checked on the row rather than on the format string."""
    for left, right in zip(cells, cells[1:]):
        assert re.search(re.escape(left) + r"\s+" + re.escape(right), row), (
            f"{left!r} and {right!r} are not separated in {row!r}")


@pytest.mark.parametrize("access_text", [
    "0x0012019f",        # today: a raw 32-bit mask, the only shape §5.2 allows
    "FILE_ALL_ACCESS",   # §5.2's deferred type-specific decoding, 15 chars
    "KEY_READ|KEY_WRITE|KEY_NOTIFY",
])
def test_no_column_fuses_into_the_next_however_wide_its_value(monkeypatch, access_text):
    """The Type column's fusion bug is not specific to Type: any column
    whose separation comes from a width alone reproduces it as soon as a
    value reaches that width. Access is the next one to grow -- §5.2
    defers type-specific permission decoding to a later feature, and a
    decoded name beside a 3-digit handle count is exactly the shape that
    used to render as "FILE_ALL_ACCESS100". This pins the invariant for
    that feature ahead of time, on every column at once."""
    import dumpex.commands.handles as handles_module
    monkeypatch.setattr(handles_module, "_access_display", lambda record: access_text)

    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "WaitCompletionPacket", "object_name": "X",
         "handle_count": 100, "pointer_count": 999},
    ]))
    row = next(l for l in _console(result).splitlines() if "0x0000000000000010" in l)
    _assert_columns_stay_separated(
        row, ["0x0000000000000010", "WaitCompletionPacket", access_text, "100", "999", "X"])


def test_every_header_column_is_separated_the_same_way():
    result = collect_handles(_mf_with([{"handle": 0x10, "type_name": "File",
                                         "object_name": "X"}]))
    header = next(l for l in _console(result).splitlines() if "Handle" in l and "Access" in l)
    _assert_columns_stay_separated(
        header, ["Handle", "Type", "Access", "Cnt", "Ptr", "Object"])


def test_console_headline_distinguishes_every_state():
    assert "HandleDataStream not present in this dump" in _console(collect_handles(_mf()))

    failed = _console(collect_handles(_mf(failure="HandleStreamFramingError: boom")))
    assert "HandleDataStream is present in this dump but could not be parsed" in failed
    assert "boom" in failed   # the parser's own text, via the [~] lines

    empty = _console(collect_handles(_mf_with([])))
    assert "0 handle(s) captured" in empty
    assert "By type:" not in empty

    total_loss = _console(collect_handles(_mf_from_descriptors([_descriptor(None),
                                                                 _descriptor("bad")])))
    assert "0 handles usable -- 2 descriptor(s) failed to normalize" in total_loss

    partial_loss = _console(collect_handles(_mf_from_descriptors(
        [_descriptor(None), _descriptor(0x10)])))
    assert "1 handle(s) captured" in partial_loss
    assert "1 descriptor(s) could not be normalized -- see coverage.limitations" in partial_loss


# ── §5.7 / console safety: names are attacker-controlled ────────────────
# TypeName/ObjectName are decoded straight out of the dump. Printed raw
# they are not data on a line, they are input to the terminal's parser.

_FORGED_REASON = "Evil\n  [~] HandleDataStream fully parsed, 0 limitations"


def test_a_name_cannot_forge_a_coverage_reason_line():
    """A newline in a type name used to print an extra line that an
    analyst could not tell from a real "[~]" coverage reason -- i.e. a
    dump could state its own coverage verdict."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": _FORGED_REASON, "object_name": None},
    ]))
    text = _console(result)

    assert not any(line.strip().startswith("[~] HandleDataStream fully parsed")
                   for line in text.splitlines())
    assert "\\x0a" in text          # the newline is still VISIBLE, not dropped
    assert "Evil" in text           # ... and so is the rest of the name
    # The record itself keeps the exact decoded value: JSON is the place
    # to read evidence byte-for-byte, and json.dumps escapes it safely.
    assert result.records[0].type_name == _FORGED_REASON


@pytest.mark.parametrize("hostile,escaped", [
    ("\x1b[2J\x1b[HCLEARED", "\\x1b"),        # ANSI: clear screen / home cursor
    ("\x07bell", "\\x07"),                    # BEL
    ("a\rb", "\\x0d"),                        # CR alone repaints the line
    ("user\u202egnp.exe", "\\u202e"),          # bidi override: reads as "userexe.png"
    ("x\u2028y", "\\u2028"),                  # line separator
])
def test_terminal_control_characters_in_a_name_are_escaped(hostile, escaped):
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": hostile},
    ]))
    text = _console(result)

    assert hostile not in text      # never reaches the terminal verbatim
    assert escaped in text          # rendered visibly instead
    assert result.records[0].object_name == hostile   # JSON keeps it exact


def test_escaping_leaves_ordinary_names_alone():
    """Windows paths and non-ASCII names are the normal case -- they must
    not be mangled by the escaping (backslashes are deliberately not
    doubled; see console_safe()'s own docstring)."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "\\Device\\NamedPipe\\mypipe"},
        {"handle": 0x20, "type_name": "Key", "object_name": "\\REGISTRY\\MACHINE\u30c6\u30b9\u30c8"},
    ]))
    text = _console(result)
    assert "\\Device\\NamedPipe\\mypipe" in text
    assert "\\REGISTRY\\MACHINE\u30c6\u30b9\u30c8" in text
    assert "\\x" not in text


def test_the_by_type_line_escapes_names_too():
    """by_type's keys come from type names, so the summary line is the
    same attack surface as the table."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "A\x1b[31mB", "object_name": None},
    ]))
    listed = next(l for l in _console(result).splitlines() if "By type:" in l)
    assert "\\x1b" in listed
    assert "\x1b[31m" not in listed
    # The wire value stays raw for a JSON consumer.
    assert "A\x1b[31mB" in result.summary["by_type"]


def test_console_never_implies_live_process_state():
    """§5.7: every user-facing string describes CAPTURED evidence."""
    result = collect_handles(_mf_with(_POPULATED))
    text = _console(result).lower()
    for forbidden in ("current", "live", "open process", "running process", "now holds",
                      "pid "):
        assert forbidden not in text


def test_renderer_projects_records_only():
    """The renderer takes no `mf` and must not re-read the stream: a
    result rendered after the dump object is gutted is byte-identical."""
    import inspect
    assert "mf" not in inspect.signature(render_handles_console).parameters

    mf = _mf_with(_POPULATED)
    result = collect_handles(mf)
    before = _console(result)
    mf.handles = None
    mf._dumpex_stream_failures = {HANDLE_STREAM: "vanished"}
    assert _console(result) == before


def test_cmd_handles_renders_and_returns_the_same_result():
    mf = _mf_with(_POPULATED)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = cmd_handles(mf)
    assert result.kind == "handles"
    assert [r.to_dict() for r in result.records] == [
        r.to_dict() for r in collect_handles(mf).records]
    assert "2 handle(s) captured" in buffer.getvalue()


# ── The collector must not go through get_handles()'s narrow view ───────

def test_collect_handles_never_routes_through_the_narrow_get_handles_view(monkeypatch):
    """get_handles() returns only mf.handles.handles -- it discards the
    header, and with it NumberOfDescriptors, so a builder written against
    it could not emit HANDLE_STREAM_TRUNCATED at all. The truncation
    tests above prove the header IS read; this pins the reason.

    Enforced by arming every route to that view with a tripwire rather
    than by scanning the module text for the name. The tripwire sits on
    the CALLEE, so it fires no matter how the caller reaches it -- a
    local alias, `getattr(memory, "get_" + "handles")`, an
    `importlib.import_module()` lookup, or a renamed wrapper -- none of
    which a source-text assertion can see. The fixture is the
    header-only truncation shape, so an implementation that quietly
    swapped in the narrow view would fail the coverage assertion below
    even with the tripwire removed.
    """
    def _tripwire(*args, **kwargs):
        raise AssertionError(
            "collect_handles() routed through get_handles()'s header-less view")

    import dumpex.core.memory as memory_module
    import dumpex.commands.handles as handles_module

    monkeypatch.setattr(memory_module, "get_handles", _tripwire)
    # A module-level `from dumpex.core.memory import get_handles` would bind
    # its own reference that patching core.memory cannot reach.
    monkeypatch.setattr(handles_module, "get_handles", _tripwire, raising=False)

    # DataSize claims room for 5 descriptors but the file ends after 2, so
    # only `header.NumberOfDescriptors` can yield the true count of 3.
    mf = _mf_with([{"handle": 0x10 * (i + 1)} for i in range(2)],
                   number_of_descriptors=5, declared_data_size=16 + 5 * 32)
    mf.get_handles = _tripwire   # minidump's own method, the same narrow view

    result = collect_handles(mf)

    assert len(result.records) == 2
    assert _limitation(result.coverage,
                        LimitationCode.HANDLE_STREAM_TRUNCATED).affected_count == 3


# ── #98: console folding is a projection, never a filter ────────────────
# Every case here asserts the same underlying invariant from a different
# side: the records, the summary and by_type are what collect_handles()
# produced, whatever the console chose to print.

# Anonymous rows of two ordinary types (folded), the five
# investigation-relevant types that must survive folding whatever their
# count, and one named row.
_FOLDING_FIXTURE = (
    [{"handle": 0x10 + i, "type_name": "Event", "object_name": None} for i in range(5)]
    + [{"handle": 0x30 + i, "type_name": "Mutant", "object_name": None} for i in range(2)]
    + [{"handle": 0x100, "type_name": "Process", "object_name": None},
       {"handle": 0x110, "type_name": "Thread", "object_name": None},
       {"handle": 0x120, "type_name": "Token", "object_name": None},
       {"handle": 0x130, "type_name": "Section", "object_name": None},
       {"handle": 0x140, "type_name": "Job", "object_name": None},
       {"handle": 0x200, "type_name": "File", "object_name": "\\Device\\HarddiskVolume1\\a.txt"}]
)


def test_default_console_folds_anonymous_rows_but_retains_the_approved_types():
    result = collect_handles(_mf_with(_FOLDING_FIXTURE))
    text = _console(result)
    shown = "\n".join(_rows(text))

    # Folded: anonymous rows of any type not on the retain list.
    assert "Event" not in shown and "Mutant" not in shown
    # Never folded: the anonymous types an investigation turns on.
    for kept in ("Process", "Thread", "Token", "Section", "Job"):
        assert kept in shown, f"{kept} was folded but must stay visible"
    assert "\\Device\\HarddiskVolume1\\a.txt" in shown


def test_default_console_reports_the_exact_folded_count_per_type():
    text = _console(collect_handles(_mf_with(_FOLDING_FIXTURE)))
    line = next(l for l in text.splitlines() if "not shown" in l)

    assert "7 anonymous handle(s) not shown" in line   # 5 Event + 2 Mutant
    assert "Event 5" in line and "Mutant 2" in line
    assert "use --verbose to show all" in text


def test_folded_counts_are_ordered_count_desc_then_name_asc():
    """§1.5's frozen order, applied to the fold line so two runs over the
    same dump print the same text."""
    descriptors = (
        [{"handle": 0x10 + i, "type_name": "Mutant", "object_name": None} for i in range(3)]
        + [{"handle": 0x40 + i, "type_name": "Event", "object_name": None} for i in range(3)]
        + [{"handle": 0x80, "type_name": "Semaphore", "object_name": None}])
    line = next(l for l in _console(collect_handles(_mf_with(descriptors))).splitlines()
                if "not shown" in l)
    listed = line.split("recorded):")[1]

    assert listed.index("Event 3") < listed.index("Mutant 3") < listed.index("Semaphore 1")


def test_verbose_console_shows_every_record_and_folds_nothing():
    result = collect_handles(_mf_with(_FOLDING_FIXTURE))
    text = _console(result, verbose=True)

    assert len(_rows(text)) == len(result.records)
    assert "not shown" not in text
    assert "use --verbose to show all" not in text


def test_verbosity_never_changes_the_records_the_summary_or_by_type():
    """The console is a projection. Whatever it folds, the CommandResult
    an analyst reads in --json is the same object either way."""
    mf = _mf_with(_FOLDING_FIXTURE)
    result = collect_handles(mf)
    before = [r.to_dict() for r in result.records]
    summary_before = dict(result.summary)

    default_text = _console(result)
    verbose_text = _console(result, verbose=True)

    assert [r.to_dict() for r in result.records] == before
    assert dict(result.summary) == summary_before
    assert result.summary["count"] == len(_FOLDING_FIXTURE)
    # The headline and the by_type line count the COMPLETE inventory in
    # both projections -- a folded row is still captured evidence.
    assert f"{len(_FOLDING_FIXTURE)} handle(s) captured" in default_text
    assert f"{len(_FOLDING_FIXTURE)} handle(s) captured" in verbose_text
    for text in (default_text, verbose_text):
        by_type_line = next(l for l in text.splitlines() if "By type:" in l)
        assert "Event 5" in by_type_line and "Mutant 2" in by_type_line


def test_folding_never_hides_an_unreadable_name():
    """"unnamed" and "unreadable" are different facts (§5.2.1): the
    second is evidence LOSS, and folding it would hide the row an analyst
    needs in order to know something was lost."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Event", "object_name": None},
        {"handle": 0x20, "type_name": "Event", "object_name": BAD_RVA},
        {"handle": 0x30, "type_name": BAD_RVA, "object_name": None},
    ]))
    shown = "\n".join(_rows(_console(result)))

    assert "0x0000000000000020" in shown      # unreadable object name: kept
    assert "0x0000000000000030" in shown      # unreadable TYPE name: kept
    assert "0x0000000000000010" not in shown  # genuinely anonymous Event: folded


def test_a_named_handle_of_a_foldable_type_is_never_folded():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Event", "object_name": "\\BaseNamedObjects\\evil"},
        {"handle": 0x20, "type_name": "Event", "object_name": None},
    ]))
    shown = "\n".join(_rows(_console(result)))
    assert "\\BaseNamedObjects\\evil" in shown
    assert "0x0000000000000020" not in shown


def test_an_unclassified_anonymous_type_is_folded_but_never_lost():
    """The type list is a RETAIN list, so an unclassified type -- a new
    Windows object type, or one a dump invents -- folds like any other
    anonymous row. It must still be NAMED and COUNTED, in the fold line
    and in by_type, and reachable with --verbose."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "SomeFutureObjectType", "object_name": None},
    ]))
    text = _console(result)

    assert _rows(text) == []                                  # folded out of the table
    assert "1 anonymous handle(s) not shown" in text
    assert "SomeFutureObjectType 1" in text                   # named and counted
    assert result.summary["by_type"] == {"SomeFutureObjectType": 1}
    assert len(_rows(_console(result, verbose=True))) == 1     # reachable


def test_a_descriptor_with_no_type_name_at_all_is_folded():
    """The shape that made the shipped fold a no-op on real dumps.

    A dump writer that leaves `TypeNameRva` 0 produces descriptors with
    NO type name -- status "unnamed", which is not a read failure -- and
    typically no object name either. That is the lowest-context row the
    table can hold, and whole handle streams are written that way. The
    first cut of the predicate required `type_name_status == "ok"`, so
    every one of those rows stayed pinned on screen and the fold did
    nothing on exactly the dumps that need it; every fixture in this file
    happened to carry a type name, so nothing caught it."""
    result = collect_handles(_mf_with(
        [{"handle": 0x10 + i, "type_name": None, "object_name": None} for i in range(8)]))
    text = _console(result)

    assert _rows(text) == []
    assert "8 anonymous handle(s) not shown" in text
    # Bucketed and labelled exactly as `By type:` labels it, so the two
    # lines describe the same handles the same way.
    assert "(unnamed) 8" in text
    assert result.summary["by_type"] == {"(unnamed)": 8}
    assert len(_rows(_console(result, verbose=True))) == 8


def test_a_typeless_row_still_shows_when_it_has_an_object_name():
    """Only the OBJECT name decides whether a row is anonymous. A
    descriptor with no type name but a captured object name is evidence
    an analyst reads, and it must survive the default projection."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": None, "object_name": r"\\Device\\HarddiskVolume1\\a.txt"},
        {"handle": 0x20, "type_name": None, "object_name": None},
    ]))
    text = _console(result)
    assert len(_rows(text)) == 1
    assert "a.txt" in text
    assert "1 anonymous handle(s) not shown" in text


def test_an_unreadable_type_name_blocks_folding_even_when_anonymous():
    """"unnamed" and "unreadable" stay different facts in the TYPE field
    too: a type that should have been there and could not be read is
    evidence loss, and the row that says so is never folded."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": BAD_RVA, "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": None},
    ]))
    text = _console(result)
    rows = _rows(text)

    assert len(rows) == 1
    assert "0x0000000000000010" in rows[0]        # the lost type name: kept
    assert "(unreadable)" in rows[0]
    assert "1 anonymous handle(s) not shown" in text


def test_the_fold_line_and_by_type_never_describe_a_handle_differently():
    """Both lines go through handle_name_display(), so a dump carrying a
    type literally named "(unnamed)" cannot make the fold line claim a
    handle is typeless -- nor merge into the null-type bucket."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "(unnamed)", "object_name": None},
        {"handle": 0x20, "type_name": None, "object_name": None},
    ]))
    fold_line = next(l for l in _console(result).splitlines() if "not shown" in l)

    assert "(unnamed) 1" in fold_line
    assert "(unnamed) [captured name] 1" in fold_line
    for label in result.summary["by_type"]:
        assert label in fold_line


@pytest.mark.parametrize("type_name", ["Process", "Thread", "Token", "Section", "Job"])
def test_the_retained_anonymous_types_are_never_folded(type_name):
    """#98 forbids `object_name_status == "unnamed"` as the SOLE
    suppression rule: an anonymous handle to one of these five is exactly
    the evidence a cross-process-access question turns on."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": type_name, "object_name": None},
    ]))
    text = _console(result)
    assert len(_rows(text)) == 1
    assert "not shown" not in text


def test_nothing_is_folded_when_no_row_qualifies():
    """Every row carries a captured object name, so none is a fold
    candidate and the fold line must not appear at all."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "\\Device\\X"},
        {"handle": 0x20, "type_name": "Event", "object_name": "\\BaseNamedObjects\\e"},
    ]))
    text = _console(result)
    assert "not shown" not in text
    assert len(_rows(text)) == 2


def test_the_name_status_legend_explains_unnamed_versus_unreadable():
    # A retained type, so the row survives the default projection and the
    # legend describes a label that is actually on screen.
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Token", "object_name": None},
    ]))
    text = _console(result)
    assert "(unnamed) = the descriptor records no name" in text
    assert "(unreadable) = a name was recorded but the bounded read failed" in text


def test_the_legend_is_absent_when_every_name_read():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "\\Device\\X"},
    ]))
    assert "the descriptor records no name" not in _console(result)


# ── #98: NT namespace object names are explained, never expanded ────────

def test_known_dlls_is_explained_as_an_nt_object_manager_directory():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Directory", "object_name": "\\KnownDlls"},
    ]))
    text = _console(result)

    assert "NT Object Manager directory" in text
    assert "\\KnownDlls (Directory)" in text
    # The note must not claim the directory's contents were captured, and
    # nothing may be enumerated from the analysis host.
    assert "not captured" in text
    for forbidden in ("contains:", "entries:", "ntdll.dll", "kernel32.dll"):
        assert forbidden not in text


def test_a_directory_note_is_not_attached_to_a_handle_of_another_type():
    """A dump can name a File handle "\\KnownDlls". Attaching the
    directory note to it would be dumpex asserting something the
    descriptor does not say."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "\\KnownDlls"},
    ]))
    text = _console(result)
    assert "\\KnownDlls" in text                            # the name is still shown
    assert "pre-mapped system DLL sections" not in text     # the note is not


def test_an_unlisted_directory_gets_one_generic_note_however_many_there_are():
    """Bounded output: the notes block can never grow with the dump."""
    descriptors = [{"handle": 0x10 + i, "type_name": "Directory",
                    "object_name": f"\\Sessions\\{i}\\BaseNamedObjects"} for i in range(50)]
    text = _console(collect_handles(_mf_with(descriptors)))
    generic = [l for l in text.splitlines()
               if "Directory handles name an NT Object Manager namespace directory" in l]
    assert len(generic) == 1


def test_a_note_survives_its_row_being_folded():
    """A folded row is still captured evidence, so a note derived from it
    must not disappear with the row. (Directory is not foldable today;
    the notes are built from the COLLECTED records so this holds however
    the fold list changes.)"""
    import dumpex.commands.handles as handles_module
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Directory", "object_name": "\\KnownDlls"},
    ]))
    text = _console(result)
    assert "NT Object Manager directory" in text

    # Forced through the predicate rather than through the type list, so
    # the case keeps holding whatever the fold RULE becomes.
    original = handles_module._is_foldable
    try:
        handles_module._is_foldable = lambda record: True
        folded_text = _console(result)
        assert _rows(folded_text) == []                    # the row is gone ...
        assert "NT Object Manager directory" in folded_text  # ... the note is not
    finally:
        handles_module._is_foldable = original


def test_the_notes_block_escapes_its_own_labels():
    """The label carries a dump-derived object name, so it is the same
    attack surface as the table."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Directory", "object_name": "A\x1b[31mB"},
    ]))
    text = _console(result)
    assert "\x1b[31m" not in text


def test_folding_and_notes_never_imply_live_state():
    result = collect_handles(_mf_with(_FOLDING_FIXTURE + [
        {"handle": 0x500, "type_name": "Directory", "object_name": "\\KnownDlls"}]))
    for text in (_console(result), _console(result, verbose=True)):
        lowered = text.lower()
        for forbidden in ("current", "live", "open process", "running process", "now holds"):
            assert forbidden not in lowered


def test_cmd_handles_forwards_verbose_to_the_renderer_only():
    """--verbose reaches the renderer; the collector has no verbosity
    parameter at all, which is what makes "console filtering never
    removes a record from --json" structural."""
    import inspect
    assert "verbose" not in inspect.signature(collect_handles).parameters

    mf = _mf_with(_FOLDING_FIXTURE)
    default_buf, verbose_buf = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(default_buf):
        default_result = cmd_handles(mf)
    with contextlib.redirect_stdout(verbose_buf):
        verbose_result = cmd_handles(mf, verbose=True)

    assert ([r.to_dict() for r in default_result.records]
            == [r.to_dict() for r in verbose_result.records])
    assert default_result.summary == verbose_result.summary
    assert default_result.coverage.status == verbose_result.coverage.status
    assert len(_rows(verbose_buf.getvalue())) > len(_rows(default_buf.getvalue()))


def _table_block(text: str) -> list:
    """The header line plus every row, as printed."""
    lines = text.splitlines()
    header_index = next(i for i, l in enumerate(lines)
                        if "Handle" in l and "Access" in l and "Object" in l)
    return [lines[header_index]] + _rows(text)


# The table's left-aligned columns, and the right-aligned counters. A
# left-aligned column is aligned when every row's value STARTS at the
# header label's own offset; a right-aligned one when every row's value
# ENDS at the header label's end. Checked against the header rather than
# row-against-row, so a table that is internally consistent but shifted
# out from under its own header still fails.
_LEFT_ALIGNED_COLUMNS = ("Type", "Access", "Object")
_RIGHT_ALIGNED_COLUMNS = ("Cnt", "Ptr")


def _assert_columns_line_up(text: str) -> list:
    block = _table_block(text)
    header = block[0]
    for row in block[1:]:
        for label in _LEFT_ALIGNED_COLUMNS:
            at = header.index(label)
            assert row[at] != " " and row[at - 1] == " ", (
                f"{label!r} does not start at column {at} in {row!r}")
        for label in _RIGHT_ALIGNED_COLUMNS:
            end = header.index(label) + len(label)
            assert row[end - 1] != " " and row[end] == " ", (
                f"{label!r} does not end at column {end} in {row!r}")
    return block


def test_every_row_lines_its_columns_up_with_the_header():
    """A per-column MINIMUM width separates a table without aligning it:
    one 20-character type name used to push that ONE row's Access/Cnt/
    Ptr/Object right while every other row stayed put, leaving the table
    ragged under its own header. Columns are now sized to the widest
    value actually present, so every row lines up with the header and
    with every other row."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 1},
        # Real Windows type names, far wider than the column minimum.
        {"handle": 0x20, "type_name": "WaitCompletionPacket", "object_name": "B",
         "granted_access": 0x0012019F, "handle_count": 100, "pointer_count": 999},
        {"handle": 0x30, "type_name": "IoCompletionReserve", "object_name": "C",
         "granted_access": 2},
    ]))
    assert len(_assert_columns_line_up(_console(result))) == 4


def test_a_short_table_still_lines_up():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "\\Device\\X"},
        {"handle": 0x20, "type_name": "Key", "object_name": BAD_RVA},
    ]))
    _assert_columns_line_up(_console(result))


def test_the_widest_value_sets_the_column_for_every_row():
    """The same record renders wider once a wider type shares the table
    -- the column grows, the value does not change."""
    narrow = _console(collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A"}])))
    wide = _console(collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A"},
        {"handle": 0x20, "type_name": "WaitCompletionPacket", "object_name": "B"}])))

    narrow_header = _table_block(narrow)[0]
    wide_header = _table_block(wide)[0]
    assert wide_header.index("Access") > narrow_header.index("Access")
    # ... and the File row still reads exactly the same value.
    assert _rows(narrow)[0].split()[1] == _rows(wide)[0].split()[1] == "File"
    _assert_columns_line_up(wide)


def test_a_hostile_type_name_cannot_set_the_layout_for_every_row():
    """Type names are attacker-controlled. Without a ceiling, one absurd
    name would pad EVERY row to its width and destroy the table for the
    other handles -- so the column stops growing at the cap and only that
    row overflows. Nothing is truncated."""
    import dumpex.commands.handles as handles_module
    over_cap = "T" * (handles_module._TYPE_COLUMN_MAX_WIDTH * 2)
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A"},
        {"handle": 0x20, "type_name": over_cap, "object_name": "B"},
    ]))
    text = _console(result)

    assert over_cap in text          # the value itself is never truncated
    ordinary = next(l for l in _rows(text) if " File " in l)
    hostile = next(l for l in _rows(text) if over_cap in l)
    # The ordinary row is unaffected by its neighbour ...
    assert len(ordinary) < handles_module._TYPE_COLUMN_MAX_WIDTH + 60
    # ... both rows still start the Type column together ...
    assert hostile.index(over_cap) == ordinary.index("File")
    # ... and only the over-cap row runs past it.
    assert len(hostile) > len(ordinary)


def test_column_widths_are_measured_on_the_escaped_text():
    """console_safe() EXPANDS a name (one control character becomes four
    visible characters), so a column sized on the raw value would be too
    narrow for its own row."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "A\x1bB", "object_name": "X", "granted_access": 1},
        {"handle": 0x20, "type_name": "File", "object_name": "Y", "granted_access": 2},
    ]))
    text = _console(result)
    assert "\\x1b" in text
    _assert_columns_line_up(text)


# ── #102 §5.6.4: the per-row rights lines ───────────────────────────────

# `  ` (the table's own indent) + the row indent + the branch, then the
# label column; a wrapped line aligns under the names.
_RIGHTS_HEAD_RE = re.compile(r"^ {6}(?:└─ |   )(Rights|Type|Standard) +(\S.*)$")
_RIGHTS_CONT = " " * 18


def _rights_groups(text: str) -> list:
    """-> [(label, text), ...] for every rights group printed, in order,
    with each group's wrapped continuations rejoined (a continued line
    ends in ` ·`, so a single space puts it back together).

    A continuation only counts while it immediately follows its own
    group: the `Aliases used` block further down is indented past the
    same column, and a rule that read any deep indent as a continuation
    would splice that block onto the last row's rights."""
    groups = []
    open_group = None
    for line in text.splitlines():
        head = _RIGHTS_HEAD_RE.match(line)
        if head:
            groups.append([head.group(1), head.group(2)])
            open_group = groups[-1]
        elif open_group is not None and line.startswith(_RIGHTS_CONT) and line.strip():
            open_group[1] += " " + line.strip()
        else:
            open_group = None
    return [(label, body) for label, body in groups]


def _rights_texts(text: str) -> list:
    """Just the decoded text of each group, in order."""
    return [body for _label, body in _rights_groups(text)]


def _row_and_rights_pairs(text: str) -> list:
    """-> [(table row, [(label, text), ...]), ...] -- the pairing an
    investigator actually reads, taken off the rendered output rather
    than off the records."""
    pairs = []
    open_group = None
    for line in text.splitlines():
        stripped = line.strip()
        head = _RIGHTS_HEAD_RE.match(line)
        if head and pairs:
            pairs[-1][1].append([head.group(1), head.group(2)])
            open_group = pairs[-1][1][-1]
        elif open_group is not None and line.startswith(_RIGHTS_CONT) and stripped:
            open_group[1] += " " + stripped
        elif stripped.startswith("0x") and "  " in stripped:
            pairs.append([line, []])
            open_group = None
        else:
            open_group = None
    return [(row, [(label, body) for label, body in groups]) for row, groups in pairs]


def test_every_printed_row_carries_its_own_decoded_rights():
    """The whole point of #102: no investigator should have to hold a
    `type + mask` in their head and go looking for it somewhere else on
    the screen."""
    result = collect_handles(_mf_with([
        {"handle": 0x5C, "type_name": "Key", "object_name": r"\REGISTRY\MACHINE\SOFTWARE",
         "granted_access": 0x00020019, "handle_count": 2, "pointer_count": 65536},
        {"handle": 0x1DC, "type_name": "Thread", "object_name": "T",
         "granted_access": 0x001FFFFF},
    ]))
    pairs = _row_and_rights_pairs(_console(result))

    assert len(pairs) == 2
    assert "Key" in pairs[0][0] and "0x00020019" in pairs[0][0]
    assert pairs[0][1] == [("Rights", "KeyRead")]
    assert "Thread" in pairs[1][0] and "0x001fffff" in pairs[1][0]
    assert pairs[1][1] == [("Rights", "AllAccess")]


def test_the_rights_lines_follow_the_table_s_own_order():
    """§5.4 orders rows by handle value, and an investigation walks them
    in that order. The rights are attached to the rows, so they cannot
    drift into an order of their own."""
    result = collect_handles(_mf_with([
        {"handle": 0x30, "type_name": "Key", "object_name": "C", "granted_access": 0x20019},
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 1},
        {"handle": 0x20, "type_name": "Process", "object_name": "B", "granted_access": 1},
    ]))
    pairs = _row_and_rights_pairs(_console(result))

    assert [row.split()[0] for row, _ in pairs] == [
        "0x0000000000000010", "0x0000000000000020", "0x0000000000000030"]
    assert [groups[0][1] for _row, groups in pairs] == ["ReadData", "Terminate", "KeyRead"]


def test_the_rights_are_drawn_as_belonging_to_the_row_above_them():
    """A branch, so a glance tells "this continues the handle above" from
    "this is another handle" without reading either line."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "A", "granted_access": 0x20019},
    ]))
    lines = _console(result).splitlines()
    row = next(i for i, line in enumerate(lines) if "0x0000000000000010" in line)

    assert lines[row + 1] == "      └─ Rights   KeyRead"


def test_the_access_column_still_carries_the_exact_raw_mask():
    """#102 decodes the mask; it never replaces it. The captured value is
    what a reader compares against a reference, and an unknown or future
    bit is only auditable against the number."""
    result = collect_handles(_mf_with([
        {"handle": 0x234, "type_name": "File", "object_name": "A",
         "granted_access": 0x0012019F, "handle_count": 1, "pointer_count": 32},
    ]))
    text = _console(result)

    assert ("0x0000000000000234  File            0x0012019f    1   32  A") in text
    assert result.records[0].granted_access == 0x0012019F   # ... and the record is raw
    # ... and the column is the ONLY place that value is printed: the
    # rights beneath it carry the reading, not a second copy.
    assert text.count("0x0012019f") == 1
    assert "0x" not in _rights_texts(text)[0]


def test_the_same_low_order_bit_decodes_by_each_row_s_recorded_type():
    """The cross-type case the raw-mask contract could not express: bit
    0x0001 is FILE_READ_DATA on a File, PROCESS_TERMINATE on a Process
    and TOKEN_ASSIGN_PRIMARY on a Token, on three adjacent rows."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 1},
        {"handle": 0x20, "type_name": "Process", "object_name": "B", "granted_access": 1},
        {"handle": 0x30, "type_name": "Token", "object_name": "C", "granted_access": 1},
    ]))

    assert _rights_texts(_console(result)) == ["ReadData", "Terminate", "AssignPrimary"]


def test_a_composite_alias_collapses_the_masks_a_dump_repeats():
    """`0x00020019` is `KEY_READ`, and a dump carries it on every Key
    handle it has. Printing its four components on each of those rows
    fills the console with a run an analyst already recognises by name --
    which is what a composite alias is for."""
    result = collect_handles(_mf_with(
        [{"handle": 0x10 + i, "type_name": "Key", "object_name": f"K{i}",
          "granted_access": 0x00020019} for i in range(20)]
        + [{"handle": 0x100, "type_name": "File", "object_name": "F",
            "granted_access": 0x0012019F}]))
    texts = _rights_texts(_console(result))

    assert texts[:20] == ["KeyRead"] * 20
    assert texts[20] == "FileGenericRead · FileGenericWrite"


def test_a_zero_mask_reads_as_no_rights_rather_than_missing_evidence():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Section", "object_name": "A", "granted_access": 0},
    ]))
    text = _console(result)

    assert _rights_groups(text) == [("Rights", "(no rights)")]
    # The column carries the captured zero, the line says what it means,
    # and neither reads like the absent-mask case.
    assert "0x00000000" in text
    assert "(unknown)" not in text


def test_an_absent_mask_is_never_decoded_at_all():
    """§5.2.2's null `granted_access` is absent evidence. `(unknown)`
    stays the Access column's word alone and the row gets no rights line
    -- a line saying "(no rights)" would turn a missing value into a
    captured one."""
    result = collect_handles(_mf_from_descriptors(
        [_descriptor(0x10, granted_access=None, type_name="Process", type_name_rva=8)]))
    text = _console(result)

    assert "(unknown)" in text
    assert _rights_groups(text) == []
    assert "Rights" not in text


def test_an_unsupported_type_keeps_the_mask_and_says_what_is_undecoded():
    """A type dumpex has no table for still decodes the type-INDEPENDENT
    half of the mask; the type-specific half is named as unavailable and
    shown exactly as captured, never read against some other type's
    rights."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "TpWorkerFactory", "object_name": "A",
         "granted_access": 0x0012019F},
    ]))

    assert _rights_groups(_console(result)) == [
        ("Rights", "TypeSpecificUnavailable(0x0000019f) · ReadControl · Synchronize")]


def test_the_station_and_desktop_types_a_real_dump_is_full_of_are_decoded():
    """The types that made the first cut of this feature useless on a
    real sample: both used to render as unknown bits alone."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "WindowStation", "object_name": r"\Windows\WinSta0",
         "granted_access": 0x00000024},
        {"handle": 0x20, "type_name": "Desktop", "object_name": r"\Default",
         "granted_access": 0x00000102},
    ]))

    assert _rights_texts(_console(result)) == [
        "AccessClipboard · AccessGlobalAtoms",
        "CreateWindow · SwitchDesktop",
    ]


def test_a_long_decode_splits_into_the_type_s_own_rights_and_the_shared_ones():
    """A wrapped run of thirteen names mixes rights that mean something
    only for THIS object type with rights that mean the same thing for
    every type, and the reader cannot see where one ends and the other
    begins. `WINSTA_ALL_ACCESS` plus the standard rights is exactly that
    case."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "WindowStation", "object_name": "W",
         "granted_access": 0x000F037F},
    ]))
    text = _console(result)

    assert _rights_groups(text) == [
        ("Type", "EnumDesktops · ReadAttributes · AccessClipboard · CreateDesktop · "
                  "WriteAttributes · AccessGlobalAtoms · ExitWindows · Enumerate · ReadScreen"),
        ("Standard", "Delete · ReadControl · WriteDac · WriteOwner"),
    ]
    # The second group belongs to the same handle, so it carries no
    # branch of its own -- the branch marks a handle, not a line.
    heads = [line for line in text.splitlines() if _RIGHTS_HEAD_RE.match(line)]
    assert heads[0].startswith("      └─ Type     ")
    assert heads[1].startswith("         Standard ")


def test_a_short_decode_stays_one_labelled_line():
    """The split is taken only when the whole decode does not fit and
    both halves exist -- a `Rights` line that fits must not be broken up
    into two."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "A", "granted_access": 0x0002001F},
    ]))

    assert _rights_groups(_console(result)) == [("Rights", "KeyRead · KeyWrite")]


def test_a_row_with_no_readable_type_is_decoded_the_same_way():
    """`(unnamed)`/`(unreadable)` are §5.2.1 facts about the NAME, and
    neither is a type to decode against -- but the standard rights are
    still the standard rights."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": BAD_RVA, "object_name": "A", "granted_access": 0x00100001},
    ]))

    assert _rights_groups(_console(result)) == [
        ("Rights", "TypeSpecificUnavailable(0x00000001) · Synchronize")]


def test_bits_with_no_documented_right_stay_visible_at_their_raw_value():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x00008001},
    ]))

    assert _rights_texts(_console(result)) == ["ReadData · UnknownBits(0x00008000)"]


def test_generic_bits_are_reported_as_captured_and_never_expanded():
    """Expanding a GENERIC_* bit needs the kernel object type's own
    GENERIC_MAPPING, which the dump does not record. The captured bit is
    the fact."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x80000000},
    ]))

    assert _rights_texts(_console(result)) == ["GenericRead"]


def test_long_rights_wrap_under_the_row_without_losing_a_name():
    """§5.6.4 must not truncate: a decode wider than the console wraps
    under its own row -- every name survives and the continuation is
    indented under the names, so it cannot read as a new row."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Thread", "object_name": "A", "granted_access": 0x0000143A},
    ]))
    text = _console(result)

    assert _rights_texts(text) == [
        "SuspendResume · GetContext · SetContext · SetInformation · "
        "SetLimitedInformation · Resume"]
    printed = [line for line in text.splitlines()
                if _RIGHTS_HEAD_RE.match(line) or line.startswith(_RIGHTS_CONT)]
    assert len(printed) > 1
    assert all(len(line) <= resolve_width() for line in printed)
    # A continued line says so, so a reader never takes a wrapped list
    # for a finished one.
    assert printed[0].endswith(" ·")


def test_the_rights_lines_are_an_observation_and_never_a_verdict():
    """§1.6: a powerful permission is evidence worth reading, not a
    finding. Nothing here may score, rank, or accuse."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Process", "object_name": "A",
         "granted_access": 0x001FFFFF},
    ]))
    text = _console(result)

    assert "Rights decode each row's own Access mask against its recorded object type" in text
    assert "never" in text and "evidence that it was used" in text
    lowered = text.lower()
    for word in ("suspicious", "malicious", "injection", "detected", "score",
                  "confidence", "threat"):
        assert word not in lowered


def test_the_shared_caption_is_printed_once_and_only_with_the_lines():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 1},
        {"handle": 0x20, "type_name": "File", "object_name": "B", "granted_access": 2},
    ]))
    text = _console(result)

    assert text.count("Rights decode each row's own Access mask") == 1
    # ... and it explains the two labels a split row uses. Read off the
    # rejoined caption, which wraps to the console width like any other
    # prose block.
    caption = " ".join(line.strip() for line in text.splitlines())
    assert "Type (rights that object type defines)" in caption
    assert "Standard (the rights every type shares)" in caption
    # Nothing decoded at all -> no caption, because there is nothing for
    # it to explain.
    empty = _console(collect_handles(_mf_with([])))
    assert "Rights decode each row's own Access mask" not in empty


# ── #102 §5.6.4: the `Aliases used` expansion block ─────────────────────

_ALIAS_ENTRY_RE = re.compile(r"^ {6}(\S.*?) +(\S+) += (\S.*)$")


def _alias_entries(text: str) -> list:
    """-> [(type label, alias, expansion), ...] from the `Aliases used`
    block, with each entry's wrapped continuations rejoined."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines)
                   if line.strip() == "Aliases used"), None)
    if start is None:
        return []
    entries = []
    for line in lines[start + 1:]:
        if not line.strip():
            break
        matched = _ALIAS_ENTRY_RE.match(line)
        if matched:
            entries.append([matched.group(1), matched.group(2), matched.group(3)])
        elif entries and line.startswith(" " * 8) and line.strip():
            # An expansion continuation is indented past the entry
            # labels; the block's own notes sit to their left.
            entries[-1][2] += " " + line.strip()
    return [(type_label, alias, expansion) for type_label, alias, expansion in entries]


def test_a_composite_says_once_what_it_stands_for():
    """A composite is short and recognisable, which is what makes it
    worth printing on every row -- but the capabilities inside it stop
    being visible, and `TOKEN_WRITE` contains `AdjustPrivileges`. An
    investigator scanning the transcript for that word has to be able to
    find it."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Token", "object_name": "T",
         "granted_access": 0x000200E0},
    ]))
    text = _console(result)

    assert _rights_texts(text) == ["TokenWrite"]
    assert _alias_entries(text) == [
        ("Token", "TokenWrite",
         "AdjustPrivileges · AdjustGroups · AdjustDefault · ReadControl")]
    assert "AdjustPrivileges" in text


def test_the_expansion_is_printed_once_however_many_rows_use_it():
    """Repeating five component names on every row is the wall the
    composites exist to collapse."""
    result = collect_handles(_mf_with(
        [{"handle": 0x10 + i, "type_name": "Key", "object_name": f"K{i}",
          "granted_access": 0x00020019} for i in range(20)]))
    text = _console(result)

    assert _rights_texts(text) == ["KeyRead"] * 20
    assert _alias_entries(text) == [
        ("Key", "KeyRead", "QueryValue · EnumerateSubKeys · Notify · ReadControl")]


def test_all_access_is_expanded_per_object_type_and_never_once_for_all():
    """`AllAccess` names the recorded type's own `*_ALL_ACCESS` constant,
    and what that contains is entirely type-dependent: terminating and
    writing the memory of a Process, setting an Event. Reading the two as
    the same capability is the cross-type mistake this whole decoder
    exists to prevent, so the block labels every expansion with its
    type."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Process", "object_name": "P",
         "granted_access": 0x001FFFFF},
        {"handle": 0x20, "type_name": "Event", "object_name": "E",
         "granted_access": 0x001F0003},
    ]))
    entries = _alias_entries(_console(result))

    assert [(type_label, alias) for type_label, alias, _ in entries] == [
        ("Event", "AllAccess"), ("Process", "AllAccess")]
    event = next(e for e in entries if e[0] == "Event")[2]
    process = next(e for e in entries if e[0] == "Process")[2]
    assert event == ("QueryState · ModifyState · Delete · ReadControl · WriteDac · "
                      "WriteOwner · Synchronize")
    assert "Terminate · CreateThread" in process
    assert "VmWrite" in process and "VmWrite" not in event


def test_an_expansion_names_the_bits_its_constant_covers_without_a_right():
    """A `Process`'s own `*_ALL_ACCESS` is defined over the whole specific
    range, two bits of which Windows documents no right for. The
    expansion says so rather than quietly listing fourteen names for a
    constant that covers sixteen bits -- and it says what that means
    HERE, which is not what the same token means on a rights line: the
    bits are not undecodable, they are covered by the constant and have
    no documented name of their own."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Process", "object_name": "P",
         "granted_access": 0x001FFFFF},
    ]))
    text = _console(result)
    caption = " ".join(line.strip() for line in text.splitlines())

    assert _alias_entries(text)[0][2].endswith("UnknownBits(0x0000c000)")
    assert ("UnknownBits in an alias expansion are included by that Windows constant "
            "but have no individually documented right name in this definition set."
            ) in caption


def test_the_unknown_bits_caveat_is_printed_only_when_an_expansion_has_one():
    """Every composite whose constant covers only documented rights
    expands cleanly, and the caveat would then explain something that is
    not on screen."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "K",
         "granted_access": 0x00020019},
    ]))
    text = _console(result)

    assert _alias_entries(text) == [
        ("Key", "KeyRead", "QueryValue · EnumerateSubKeys · Notify · ReadControl")]
    assert "UnknownBits in an alias expansion" not in text


# ── The Vista widening, end to end ──────────────────────────────────────
# access_rights decides which `*_ALL_ACCESS` a Process or Thread mask is
# read against; these check that the dump's own major version is what
# reaches it, and that nothing else moves.

def _mf_with_os_major(descriptors, major):
    """A fake dump whose SYSTEM_INFO stream reports `major`, or that has
    no usable one when `major` is None."""
    mf = _mf_with(descriptors)
    mf.sysinfo = types.SimpleNamespace(MajorVersion=major)
    return mf


_FULL_PROCESS_XP = [{"handle": 0x10, "type_name": "Process",
                      "object_name": "P", "granted_access": 0x001F0FFF}]


def test_a_pre_vista_dump_reads_its_full_process_handle_as_all_access():
    """0x001f0fff IS `PROCESS_ALL_ACCESS` on XP and Server 2003 -- winnt.h
    defines the constant that way under `#else` -- so the row should say
    so instead of spelling out twelve rights."""
    mf = _mf_with_os_major(_FULL_PROCESS_XP, 5)
    text = _console_via_cmd(mf)

    assert "Rights   AllAccess" in text


def test_a_modern_dump_does_not_call_the_narrower_mask_all_access():
    """The same mask on Vista and later is a PARTIAL handle -- the two
    `*_LIMITED_INFORMATION` rights are absent -- and naming it
    `AllAccess` would claim a capability the handle does not have."""
    text = _console_via_cmd(_mf_with_os_major(_FULL_PROCESS_XP, 10))

    assert "AllAccess" not in text
    assert "Terminate" in text and "SuspendResume" in text


def test_a_dump_with_no_readable_version_uses_the_modern_constants():
    """The safe direction. Treating "version unknown" as "old" would
    print `AllAccess` for genuinely partial masks on every dump whose
    SYSTEM_INFO stream is missing or unparsable."""
    for major in (None, "6", -1, True):
        text = _console_via_cmd(_mf_with_os_major(_FULL_PROCESS_XP, major))
        assert "AllAccess" not in text, f"major={major!r} selected the old value"


def test_the_version_never_reaches_the_records_or_the_json():
    """`granted_access` is the same integer whatever the dump's version
    is: the version selects a display NAME and nothing else, which is
    what keeps the v2.13 schema out of this entirely."""
    old = collect_handles(_mf_with_os_major(_FULL_PROCESS_XP, 5))
    new = collect_handles(_mf_with_os_major(_FULL_PROCESS_XP, 10))

    assert [r.granted_access for r in old.records] == [0x001F0FFF]
    assert ([r.to_dict() for r in old.records]
            == [r.to_dict() for r in new.records])


def test_the_alias_expansion_follows_the_version_the_row_was_decoded_with():
    """The `Aliases used` block must expand the same constant the row
    used, or it would list rights the handle never had."""
    text = _console_via_cmd(_mf_with_os_major(_FULL_PROCESS_XP, 5))
    entries = dict((alias, expansion)
                   for _type, alias, expansion in _alias_entries(text))

    assert "Terminate" in entries["AllAccess"]
    assert "QueryLimitedInformation" not in entries["AllAccess"]


def test_the_block_says_a_display_name_maps_to_a_constant_not_that_it_is_one():
    """`AllAccess` and `KeyRead` are dumpex's display forms; no header
    defines either spelling. Telling a reader they are "the SDK's own
    name" sends them looking for a symbol that does not exist.

    The caption also stops short of calling every constant "documented".
    It once said "one documented Windows constant", which an investigator
    reads as "I can go and check this" -- true of `KEY_READ`, false of
    `SYMBOLIC_LINK_ALL_ACCESS`, for which no Microsoft header or
    reference page could be found. The wording now spans the three kinds
    the registry actually holds, and the unconfirmed ones are marked
    individually on their own lines."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "K",
         "granted_access": 0x00020019},
    ]))
    caption = " ".join(line.strip() for line in _console(result).splitlines())

    assert ("Each display name maps to one Windows SDK, WDK or native constant"
            in caption)
    assert "the Windows SDK's own name" not in caption
    assert "documented Windows constant" not in caption

    # A confirmed composite carries no caveat of its own.
    assert "[source unconfirmed]" not in caption


def test_an_unconfirmed_composite_is_marked_and_a_confirmed_one_is_not():
    """The P1 the caption change exists for. `SYMBOLIC_LINK_ALL_ACCESS`
    has no confirmed Microsoft source; `KEY_READ` does. Printing both
    with identical confidence tells the reader the first is checkable
    when it is not, and the difference has to be visible on the line
    rather than in a header the reader would have to go and fail to
    find."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "K",
         "granted_access": 0x00020019},
        {"handle": 0x20, "type_name": "SymbolicLink", "object_name": "L",
         "granted_access": 0x000F0001},
    ]))
    text = _console(result)
    entries = dict((alias, expansion)
                   for _type, alias, expansion in _alias_entries(text))

    assert "[source unconfirmed]" in entries["AllAccess"]
    assert "[source unconfirmed]" not in entries["KeyRead"]

    # And the caveat is explained once, underneath.
    caption = " ".join(line.strip() for line in text.splitlines())
    assert ("Names marked [source unconfirmed] map to a constant no Microsoft "
            "header or reference page could be found for") in caption


def test_the_unconfirmed_caveat_is_absent_when_nothing_on_screen_is_marked():
    """Same rule the UnknownBits note follows: a caveat never explains
    something that is not there."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "K",
         "granted_access": 0x00020019},
    ]))
    caption = " ".join(line.strip() for line in _console(result).splitlines())

    assert "Names marked [source unconfirmed]" not in caption


def test_a_directory_composite_is_confirmed_and_a_symbolic_link_one_is_not():
    """The two look like one family and are not: Microsoft's
    ZwOpenDirectoryObject page names `DIRECTORY_ALL_ACCESS` outright,
    while no page names `SYMBOLIC_LINK_ALL_ACCESS`. Marking them
    identically -- in either direction -- would be wrong about one."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Directory", "object_name": "D",
         "granted_access": 0x000F000F},
        {"handle": 0x20, "type_name": "SymbolicLink", "object_name": "L",
         "granted_access": 0x000F0001},
    ]))
    marked = {type_display: "[source unconfirmed]" in expansion
              for type_display, _alias, expansion
              in _alias_entries(_console(result))}

    assert marked == {"Directory": False, "SymbolicLink": True}


# ── The Aliases-used block survives a hostile or malformed Type field ───
# access_rights normalizes a type name case- and whitespace-insensitively
# before looking it up, so `"Process"`, `"  process  "` and a
# thousands-of-bytes-of-whitespace variant of it are ONE registry entry.
# The block used to key its dedup on the RAW text instead, so each
# spelling produced its own (redundant) expansion line, and it labelled
# that line with the raw text too, so a single crafted or corrupted
# `type_name` inflated the shared type column for every OTHER entry in
# the block as well.

def test_case_and_whitespace_variants_of_one_type_produce_one_alias_entry():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Process", "object_name": "A",
         "granted_access": 0x001FFFFF},
        {"handle": 0x20, "type_name": "  process  ", "object_name": "B",
         "granted_access": 0x001FFFFF},
        {"handle": 0x30, "type_name": "PROCESS", "object_name": "C",
         "granted_access": 0x001FFFFF},
    ]))
    entries = _alias_entries(_console(result))

    assert entries == [("Process", "AllAccess",
                         "Terminate · CreateThread · SetSessionId · "
                         "VmOperation · VmRead · VmWrite · DupHandle · "
                         "CreateProcess · SetQuota · SetInformation · "
                         "QueryInformation · SuspendResume · "
                         "QueryLimitedInformation · SetLimitedInformation · "
                         "Delete · ReadControl · WriteDac · WriteOwner · "
                         "Synchronize · UnknownBits(0x0000c000)")]


def test_a_wildly_padded_type_field_cannot_widen_the_aliases_block():
    """The actual reported failure mode: a 400-character (or, in a real
    dump, up to MAX_HANDLE_STRING_BYTES -- 4096 bytes, attacker-controlled
    and read verbatim by the parser) `type_name` must not blow the shared
    type column out for every entry in the block, including a perfectly
    ordinary one on a different row."""
    hostile = " " * 200 + "Process" + " " * 200
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": hostile, "object_name": "A",
         "granted_access": 0x001FFFFF},
        {"handle": 0x20, "type_name": "Key", "object_name": "B",
         "granted_access": 0x00020019},
    ]))
    text = _console(result)
    alias_block = text[text.index("Aliases used"):]

    # Bounded, not merely shorter than the 462-char raw text would
    # have produced: every line in this block wraps to the console
    # width regardless of what the dump's Type field contained.
    assert max(len(line) for line in alias_block.splitlines()) <= 100
    assert "Process" in alias_block
    # The point being tested is the ORIGINAL padded text, not its
    # trimmed form (which is just "Process" and is supposed to appear).
    assert hostile not in alias_block
    entries = _alias_entries(text)
    assert [type_label for type_label, _alias, _expansion in entries] == ["Key", "Process"]


def test_the_aliases_block_label_is_the_registries_own_spelling():
    """Not merely "not garbled" -- specifically the canonical spelling,
    so the label matches what SUPPORTED_OBJECT_TYPES and every other
    corner of this feature call the type, regardless of how the dump
    happened to spell it."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "sYmBoLiClInK", "object_name": "A",
         "granted_access": 0x000F0001},
    ]))
    entries = _alias_entries(_console(result))
    assert entries[0][0] == "SymbolicLink"


# ── Unconfirmed single-bit right names are marked on the Rights line ────
# The provenance model already distinguished confirmed from unconfirmed
# constants, but that distinction only reached composite aliases. A bare
# single-bit name -- `QueryState` on a `Semaphore`, `Alert` on a `Thread`,
# `Query`/`Set` on a `SymbolicLink` -- decoded and printed exactly like a
# `winnt.h`-confirmed one, with nothing on the line to tell them apart.

@pytest.mark.parametrize("type_name,mask,unconfirmed_name", [
    ("Thread", 0x0004, "Alert"),
    ("SymbolicLink", 0x0001, "Query"),
    ("SymbolicLink", 0x0002, "Set"),
    ("Semaphore", 0x0001, "QueryState"),
    ("IoCompletion", 0x0001, "QueryState"),
])
def test_each_unconfirmed_single_bit_name_is_marked_on_its_own(type_name, mask,
                                                                unconfirmed_name):
    """Every constant this review named, checked individually rather than
    only through SYMBOLIC_LINK_ALL_ACCESS."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": type_name, "object_name": "A",
         "granted_access": mask},
    ]))
    text = _console(result)

    assert f"{unconfirmed_name} [?]" in text
    assert "Names marked [?] map to a constant no Microsoft header or reference "  \
           "page could be found for" in " ".join(line.strip()
                                                   for line in text.splitlines())


# ── The same split, one level down: components INSIDE a composite ──────
# An alias's own confirmation status (checked above) and the confirmation
# status of the individual rights its expansion NAMES are two different
# questions, and they disagree for four of this registry's aliases:
# `IoCompletion`/`Thread`/`Semaphore AllAccess` are themselves confirmed
# `winnt.h` constants, so their `Rights` line correctly prints a bare
# `AllAccess` -- but expanding any of them lists a component
# (`QueryState`, `Alert`) whose OWN constant has no confirmed source, and
# that fact was invisible in the expansion until now. `SymbolicLink` is
# the case where BOTH the alias and one of its components are
# unconfirmed, and both marks must appear together rather than one
# standing in for the other.

@pytest.mark.parametrize("type_name,mask,alias,unconfirmed_component", [
    ("IoCompletion", 0x001F0003, "AllAccess", "QueryState"),
    ("Thread", 0x001FFFFF, "AllAccess", "Alert"),
    ("Semaphore", 0x001F0003, "AllAccess", "QueryState"),
    ("SymbolicLink", 0x000F0001, "AllAccess", "Query"),
])
def test_an_unconfirmed_component_is_marked_inside_a_confirmed_or_unconfirmed_alias(
        type_name, mask, alias, unconfirmed_component):
    """Every type this review named. The alias LABEL on the `Rights` line
    is never touched by this -- only the expansion underneath it."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": type_name, "object_name": "A",
         "granted_access": mask},
    ]))
    text = _console(result)
    entries = _alias_entries(text)

    [(_type, found_alias, expansion)] = entries
    assert found_alias == alias
    assert f"{unconfirmed_component} [?]" in expansion


@pytest.mark.parametrize("type_name,mask,alias", [
    ("IoCompletion", 0x001F0003, "AllAccess"),
    ("Thread", 0x001FFFFF, "AllAccess"),
])
def test_the_alias_label_itself_stays_unmarked_when_only_a_component_is_unconfirmed(
        type_name, mask, alias):
    """The other half of the same fact: `IO_COMPLETION_ALL_ACCESS` and
    `THREAD_ALL_ACCESS` are themselves confirmed winnt.h constants, so
    neither the `Rights` line's `AllAccess` nor the alias LABEL in the
    `Aliases used` block may carry a mark just because one of the rights
    it expands to does."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": type_name, "object_name": "A",
         "granted_access": mask},
    ]))
    text = _console(result)
    rights_line = next(l for l in text.splitlines() if "Rights" in l)
    assert "[?]" not in rights_line

    entries = _alias_entries(text)
    [(_type, found_alias, _expansion)] = entries
    assert found_alias == alias        # the label carries no "[?]" suffix


def test_symbolic_link_all_access_marks_both_the_alias_and_its_component():
    """The one case where two independent facts are both true at once:
    `SYMBOLIC_LINK_ALL_ACCESS` has no confirmed header (marked
    `[source unconfirmed]`, per the earlier round), AND its `Query`
    component -- `SYMBOLIC_LINK_QUERY` -- has no confirmed header either
    (marked `[?]`). Neither mark substitutes for the other."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "SymbolicLink", "object_name": "A",
         "granted_access": 0x000F0001},
    ]))
    entries = _alias_entries(_console(result))

    [(_type, alias, expansion)] = entries
    assert alias == "AllAccess"
    assert "Query [?]" in expansion
    assert "[source unconfirmed]" in expansion


@pytest.mark.parametrize("type_name,mask,alias,confirmed_component", [
    ("Event", 0x001F0003, "AllAccess", "QueryState"),   # ntifs.h-confirmed
    ("Timer", 0x001F0003, "AllAccess", "QueryState"),   # winnt.h, not mixed
])
def test_a_confirmed_component_inside_a_confirmed_alias_carries_no_mark(
        type_name, mask, alias, confirmed_component):
    """The contrast case the parametrized test above needs: `Event` and
    `Timer` look exactly like `Semaphore`/`IoCompletion` from the
    outside -- same bit, same display name, same alias shape -- and
    neither is mixed. Marking their `QueryState` here would be the same
    over-eager mistake `EVENT_QUERY_STATE` was once filed under before
    Microsoft's own reference page was checked."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": type_name, "object_name": "A",
         "granted_access": mask},
    ]))
    entries = _alias_entries(_console(result))

    [(_type, found_alias, expansion)] = entries
    assert found_alias == alias
    assert f"{confirmed_component} [?]" not in expansion
    assert "[?]" not in expansion


def test_a_confirmed_single_bit_name_is_never_marked():
    """The contrast case in the same family: TIMER_QUERY_STATE IS a
    winnt.h constant, unlike the SEMAPHORE/IO_COMPLETION lookalikes."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Timer", "object_name": "A",
         "granted_access": 0x0001},
    ]))
    text = _console(result)

    assert "QueryState [?]" not in text
    assert "[?]" not in text


def test_a_confirmed_and_an_unconfirmed_bit_on_one_row_are_told_apart():
    """The clearest single demonstration: one Semaphore mask carrying
    both bits must mark exactly one of the two names on the same line."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Semaphore", "object_name": "A",
         "granted_access": 0x0003},
    ]))
    text = _console(result)

    assert "QueryState [?] · ModifyState" in text
    assert "ModifyState [?]" not in text


def test_an_ioc_completion_all_access_row_is_not_marked_even_though_the_type_is_mixed():
    """`IoCompletion` is mixed-source, but `AllAccess` itself is
    `IO_COMPLETION_ALL_ACCESS` -- a confirmed winnt.h constant. The
    `Rights` line must not inherit a mark that belongs to the type's
    OTHER, unrelated bit.

    That bit is not swept under the rug, though: `AllAccess` still
    EXPANDS to `QueryState`, which comes from the unconfirmed
    `IO_COMPLETION_QUERY_STATE`, and the `Aliases used` block marks that
    one component on its own -- a fact this test pins alongside the
    Rights line staying clean, rather than asserting `[?]` is absent from
    the WHOLE output (which would have frozen the very gap this test
    exists to close)."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "IoCompletion", "object_name": "A",
         "granted_access": 0x001F0003},
    ]))
    text = _console(result)
    rights_line = next(l for l in text.splitlines() if "Rights" in l)

    assert "Rights   AllAccess" in rights_line
    assert "[?]" not in rights_line

    entries = _alias_entries(text)
    assert entries == [("IoCompletion", "AllAccess",
                         "QueryState [?] · ModifyState · Delete · ReadControl · "
                         "WriteDac · WriteOwner · Synchronize")]


def test_the_unconfirmed_rights_caveat_is_absent_when_nothing_is_marked():
    """Same rule every other on-demand caveat in this block follows."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key", "object_name": "A",
         "granted_access": 0x00020019},
    ]))
    text = _console(result)
    assert "[?]" not in text
    assert "Names marked [?]" not in text


def test_an_unconfirmed_mark_is_never_split_across_a_wrapped_line():
    """The mark is part of the piece wrap_rights() sees, so it can never
    be separated from its name -- the same guarantee every right name
    already has."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "SymbolicLink", "object_name": "A",
         "granted_access": 0x0003},
    ]))
    text = _console(result)
    for line in text.splitlines():
        if "Query" in line and "[?" in line and "]" not in line:
            pytest.fail(f"mark split across a wrap boundary: {line!r}")


def test_the_block_lists_only_the_composites_actually_on_screen():
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A",
         "granted_access": 0x00120089},
    ]))
    entries = _alias_entries(_console(result))

    assert [alias for _type, alias, _expansion in entries] == ["FileGenericRead"]
    # A row that used no composite contributes none.
    plain = _console(collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 1}])))
    assert _alias_entries(plain) == []
    assert "Aliases used" not in plain


def test_a_folded_row_takes_its_alias_expansion_with_it():
    """The block explains names that are on screen, so it follows the
    same rows the rights lines do."""
    descriptors = [
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x120089},
        {"handle": 0x20, "type_name": "Event", "object_name": None, "granted_access": 0x1F0003},
    ]
    default = _alias_entries(_console(collect_handles(_mf_with(descriptors))))
    verbose = _alias_entries(_console(collect_handles(_mf_with(descriptors)), verbose=True))

    assert [alias for _t, alias, _e in default] == ["FileGenericRead"]
    assert [alias for _t, alias, _e in verbose] == ["AllAccess", "FileGenericRead"]


def test_the_expansion_block_escapes_a_dump_derived_type_name():
    """The alias name and its rights are dumpex's own vocabulary, but the
    label carries the recorded TYPE, which is attacker-controlled."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "Key\x1bX", "object_name": "A",
         "granted_access": 0x00020019},
    ]))
    text = _console(result)

    # Not a type this registry carries once the escape is part of the
    # name -- so no composite, and nothing to expand.
    assert _alias_entries(text) == []
    assert "Key\\x1bX" in text
    assert "\x1b[" not in text.replace("\x1b[0m", "")


# ── #102: colour is a projection of the same text ───────────────────────

def test_colour_separates_the_names_from_the_scaffolding(monkeypatch):
    """On a terminal the names are what the eye should land on, so the
    branch, the label and the separators are dimmed and a remainder --
    the one piece saying something was NOT read -- is yellow. The text
    itself is identical either way."""
    import dumpex.ui.colors as colors
    monkeypatch.setattr(colors, "USE_COLOR", True)

    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x00008001},
    ]))
    line = next(l for l in _console(result).splitlines() if "UnknownBits" in l)

    assert "\x1b[2m└─ \x1b[0m" in line                     # branch, dimmed
    assert "\x1b[2mRights  \x1b[0m" in line                # label, dimmed
    assert "\x1b[2m · \x1b[0m" in line                     # separator, dimmed
    assert "\x1b[93mUnknownBits(0x00008000)\x1b[0m" in line  # remainder, yellow
    assert "\x1b[" not in "ReadData"                       # ... but not the names
    assert strip_ansi(line).strip() == "└─ Rights   ReadData · UnknownBits(0x00008000)"


def test_widths_are_measured_on_the_text_and_not_on_the_escape_codes(monkeypatch):
    """Colouring before wrapping would spend the line's width budget on
    escape sequences and wrap the rights early. The wrap is identical
    with colour on and off."""
    import dumpex.ui.colors as colors
    descriptors = [{"handle": 0x10, "type_name": "Thread", "object_name": "A",
                     "granted_access": 0x0000143A}]

    monkeypatch.setattr(colors, "USE_COLOR", False)
    plain = _console(collect_handles(_mf_with(descriptors)))
    monkeypatch.setattr(colors, "USE_COLOR", True)
    coloured = _console(collect_handles(_mf_with(descriptors)))

    assert _rights_texts(plain) == _rights_texts(
        "\n".join(strip_ansi(line) for line in coloured.splitlines()))


# ── #102 x #98: decoding changes nothing about which rows exist ─────────

def test_decoding_does_not_change_folding_retention_or_coverage():
    descriptors = [
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x120089},
        {"handle": 0x20, "type_name": "Event", "object_name": None, "granted_access": 0x1F0003},
        {"handle": 0x30, "type_name": "Process", "object_name": None, "granted_access": 0x1FFFFF},
    ]
    default = collect_handles(_mf_with(descriptors))
    verbose = collect_handles(_mf_with(descriptors))

    # Same records, summary, coverage and exit code either way -- the
    # decode is a projection of the records, not an input to them.
    assert [r.to_dict() for r in default.records] == [r.to_dict() for r in verbose.records]
    assert default.summary == verbose.summary == {
        "count": 3, "by_type": {"Event": 1, "File": 1, "Process": 1}}
    assert exit_code_for(default.coverage.status) == 0

    default_text = _console(default)
    verbose_text = _console(verbose, verbose=True)
    # #98's fold is untouched: the anonymous Event row is still folded,
    # the anonymous Process row is still retained.
    assert "1 anonymous handle(s) not shown (no object name recorded): Event 1" in default_text
    assert len(_rows(default_text)) == 2
    assert len(_rows(verbose_text)) == 3


def test_a_folded_row_takes_its_rights_line_with_it():
    """The line belongs to a row, so a view that does not print the row
    does not print the line -- and `--verbose` gets both back
    together."""
    descriptors = [
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x120089},
        {"handle": 0x20, "type_name": "Event", "object_name": None, "granted_access": 0x1F0003},
    ]
    default = _rights_texts(_console(collect_handles(_mf_with(descriptors))))
    verbose = _rights_texts(_console(collect_handles(_mf_with(descriptors)), verbose=True))

    assert default == ["FileGenericRead"]
    assert verbose == default + ["AllAccess"]


def test_the_rights_always_belong_to_the_row_above_them():
    """The pairing is what the whole redesign rests on: the line under a
    row decodes THAT row's mask against THAT row's type."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A", "granted_access": 0x00000002},
        {"handle": 0x20, "type_name": "Thread", "object_name": "B", "granted_access": 0x00000002},
    ]))

    for row, groups in _row_and_rights_pairs(_console(result)):
        expected = "WriteData" if " File " in row else "SuspendResume"
        assert groups == [("Rights", expected)]


def test_a_hostile_type_name_cannot_forge_output_through_the_rights_line():
    """The rights line is dumpex's own vocabulary plus numbers -- no
    dump-derived string reaches it, so a hostile type name has nothing to
    ride in on. The Type column escapes it as before."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "A\x1bB\nHandle", "object_name": "X",
         "granted_access": 1},
    ]))
    text = _console(result)

    assert "A\\x1bB\\x0aHandle" in text
    assert _rights_texts(text) == ["TypeSpecificUnavailable(0x00000001)"]
    assert "\x1b[" not in text.replace("\x1b[0m", "")


def test_no_decoded_right_ever_reaches_the_record():
    """#102 is a console projection. The record keeps the captured
    integer and gains no field: v2.13's schema is frozen, and a consumer
    that needs a stable machine value reads `granted_access`."""
    result = collect_handles(_mf_with([
        {"handle": 0x10, "type_name": "File", "object_name": "A",
         "granted_access": 0x0012019F},
    ]))
    serialized = result.records[0].to_dict()

    assert serialized["granted_access"] == 0x0012019F
    assert isinstance(serialized["granted_access"], int)
    assert set(serialized) == {
        "handle", "type_name", "type_name_status", "object_name",
        "object_name_status", "attributes", "granted_access",
        "handle_count", "pointer_count"}
    assert "ReadData" not in str(serialized)
