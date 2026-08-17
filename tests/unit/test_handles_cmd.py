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


def _console(result) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render_handles_console(result.records, result.coverage)
    return buffer.getvalue()


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
    result = collect_handles(_mf_from_descriptors([_descriptor(0x10, granted_access=None)]))
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
    rows = [l for l in _console(result).splitlines() if "0x00000000000000" in l]
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

    rows = [l for l in _console(result).splitlines() if "0x00000000000000" in l]
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
    text = _console(result)

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
