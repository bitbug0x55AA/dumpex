"""
Characterization baseline for `dumpex.core.memory`'s loader and
captured-range readers, driven through real synthetic `.dmp` bytes.

Every case here opens a file written by `tests.fixtures.minidump_bytes`
through the real `open_dump()`, so the header/directory walk, per-stream
parser isolation, thread-context parsing and the installed `minidump`
library's buffered reader all run exactly as a CLI invocation runs them.

The expectations are the CURRENT outcomes, including ones that are known
to be weak evidence handling (a region spanning two adjacent segments is
skipped by the string search; a short-backed segment is still reported as
fully captured by the structural capture count; a thread whose context
location is empty still gets a context parsed from file offset 0). They
prove that relocating this code preserves behaviour, not that the
behaviour is correct: a deliberate fix updates the affected expectation in
its own reviewed change. See docs/developer/decomposition_baseline.md.
"""
import struct

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE

import dumpex.core.memory as memory
from dumpex.output.coverage import SourceState
from tests.fixtures.minidump_bytes import (
    ARCH_INTEL, HANDLE_DATA, MEM_RESERVE, PAGE_EXECUTE_READWRITE, THREAD_INFO_LIST,
    MEMORY_INFO_LIST, MISC_INFO, DumpSpec, HandleSpec, ModuleSpec, RawStreamSpec, RegionSpec,
    SegmentSpec, ThreadInfoSpec, ThreadSpec, build_minidump, write_minidump,
)

_MODULES = (ModuleSpec(0x400000, 0x1000, r"C:\Program Files\App\app.exe"),)

# Two adjacent segments, a hole, a small isolated segment and a trailing
# segment whose backing bytes are cut short by file truncation.
def _pattern(seed: int, size: int) -> bytes:
    """Position-dependent content: every offset of every segment holds a
    different byte sequence, so a read from the wrong offset or segment, a
    dropped or repeated chunk, or a zero-filled stretch cannot compare equal
    to the expected slice."""
    return bytes((seed * 0x40 + i * 7 + (i >> 8) * 13) & 0xFF for i in range(size))


_SEG_A = SegmentSpec(0x10000, _pattern(1, 0x1000))
_SEG_B = SegmentSpec(0x11000, _pattern(2, 0x1000))
_SEG_C = SegmentSpec(0x20000, _pattern(3, 0x100))
_SEG_D = SegmentSpec(0x30000, _pattern(4, 0x1000))
_A, _B, _C, _D = (s.data for s in (_SEG_A, _SEG_B, _SEG_C, _SEG_D))
_SHORT_BACKED_BYTES = 0x80


def _open(tmp_path, spec, name="sample.dmp"):
    return memory.open_dump(write_minidump(tmp_path / name, spec))


def _gapped_spec(**overrides):
    fields = dict(modules=_MODULES, memory64=(_SEG_A, _SEG_B, _SEG_C, _SEG_D))
    fields.update(overrides)
    spec = DumpSpec(**fields)
    full = len(build_minidump(spec))
    spec.truncate_to = full - len(_SEG_D.data) + _SHORT_BACKED_BYTES
    return spec


@pytest.fixture
def gapped(tmp_path):
    mf = _open(tmp_path, _gapped_spec())
    yield mf
    mf.file_handle.close()


def _outcome(fn, *args):
    try:
        result = fn(*args)
    except Exception as exc:   # noqa: BLE001 -- the exception IS the characterized outcome
        return ("raises", type(exc).__name__, str(exc))
    if isinstance(result, (bytes, bytearray)):
        return ("bytes", bytes(result))
    return ("value", result)


# ── Header and directory walk ───────────────────────────────────────────


def test_missing_file_exits_1_and_reports_on_stdout(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        memory.open_dump(str(tmp_path / "absent.dmp"))
    assert exc.value.code == 1
    out, err = capsys.readouterr()
    assert out == f"[!] File not found: {tmp_path / 'absent.dmp'}\n"
    assert err == ""


def test_non_minidump_file_exits_1_with_the_parse_error_on_stdout(tmp_path, capsys):
    path = tmp_path / "junk.dmp"
    path.write_bytes(b"not a minidump at all")
    with pytest.raises(SystemExit) as exc:
        memory.open_dump(str(path))
    assert exc.value.code == 1
    out, err = capsys.readouterr()
    assert out.splitlines() == [
        f"[!] Could not parse {path} as a minidump file: "
        f"MinidumpHeaderSignatureMismatchException:  ton",
        "    The file may be corrupted, truncated, or not a Windows minidump (.dmp) at all.",
    ]
    assert err == ""


def test_header_union_and_flags_are_read_at_their_real_offsets(gapped):
    assert gapped.header.TimeDateStamp == 0x5F5E1000
    assert gapped.header.Reserved == 0x5F5E1000
    assert gapped.header.Flags == MINIDUMP_TYPE(0x2)


def test_high_flag_bits_are_kept_at_full_64_bit_width(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, flags=0x8000_0000_0000_0002))
    assert int(mf.header.Flags) == 0x8000_0000_0000_0002


def test_directory_walk_is_bounded_by_file_size_not_the_declared_count(tmp_path):
    spec = DumpSpec(modules=_MODULES, memory64=(_SEG_C,), declared_stream_count=50)
    mf = _open(tmp_path, spec)
    readable = (len(build_minidump(spec)) - 32) // 12
    assert mf.header.NumberOfStreams == 50
    assert len(mf.directories) == readable
    assert memory.directory_truncated_count(mf) == 50 - readable
    # The walk reads whatever bytes follow the real table as further
    # entries; the five real entries still come first.
    assert [d.StreamType for d in mf.directories[:5]] == [
        MINIDUMP_STREAM_TYPE.SystemInfoStream, MINIDUMP_STREAM_TYPE.ModuleListStream,
        MINIDUMP_STREAM_TYPE.ThreadListStream, MINIDUMP_STREAM_TYPE.MemoryInfoListStream,
        MINIDUMP_STREAM_TYPE.Memory64ListStream]


def test_unrecognized_stream_ids_stay_raw_integers_and_are_not_dispatched(tmp_path):
    raws = (RawStreamSpec(0x4000, b"xyz"), RawStreamSpec(0x10001, b"user"))
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, raw_streams=raws))
    types = [d.StreamType for d in mf.directories]
    assert 0x4000 in types and 0x10001 in types
    assert not isinstance(types[types.index(0x4000)], MINIDUMP_STREAM_TYPE)
    assert mf._dumpex_stream_failures == {}


def test_open_dump_leaves_the_dump_file_open_on_the_returned_object(gapped):
    assert gapped.file_handle.closed is False
    assert gapped.filename.endswith("sample.dmp")


# ── Per-stream parse isolation and stream states ────────────────────────


@pytest.mark.parametrize("stream_type, body, failed_type, detail", [
    (HANDLE_DATA, struct.pack("<IIII", 16, 7, 1, 0), MINIDUMP_STREAM_TYPE.HandleDataStream,
     "HandleStreamFramingError: HandleDataStream SizeOfDescriptor 7 is neither 32 "
     "(MINIDUMP_HANDLE_DESCRIPTOR) nor 40 (MINIDUMP_HANDLE_DESCRIPTOR_2)"),
    (HANDLE_DATA, b"\x10\x00", MINIDUMP_STREAM_TYPE.HandleDataStream,
     "HandleStreamFramingError: HandleDataStream is 2 byte(s), too small to contain its own "
     "16-byte header"),
    (THREAD_INFO_LIST, struct.pack("<III", 4, 64, 1), MINIDUMP_STREAM_TYPE.ThreadInfoListStream,
     "ThreadInfoStreamFramingError: ThreadInfoListStream SizeOfHeader 4 is out of bounds for a "
     "12-byte stream"),
    (THREAD_INFO_LIST, b"\x0c", MINIDUMP_STREAM_TYPE.ThreadInfoListStream,
     "ThreadInfoStreamFramingError: ThreadInfoListStream is 1 byte(s), too small to contain its "
     "own 12-byte header"),
])
def test_one_malformed_stream_is_recorded_and_isolated(tmp_path, stream_type, body,
                                                       failed_type, detail):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, memory64=(_SEG_C,),
                                  raw_streams=(RawStreamSpec(stream_type, body),)))
    assert mf._dumpex_stream_failures == {failed_type: detail}
    assert memory.stream_failure(mf, failed_type) == detail
    assert memory.has_stream_directory(mf, failed_type) is True
    assert memory.get_modules(mf)[0].name == r"C:\Program Files\App\app.exe"
    assert memory.read_region(mf, 0x20000, 4) == _C[:4]
    observed = memory.observe_stream(mf, "x", failed_type, None, [])
    assert (observed.state, observed.record_count, observed.detail) == (SourceState.FAILED, None, detail)


def test_handle_stream_evidence_distinguishes_absent_parsed_and_failed(tmp_path):
    absent = _open(tmp_path, DumpSpec(modules=_MODULES), "absent.dmp")
    parsed = _open(tmp_path, DumpSpec(modules=_MODULES, handles=(
        HandleSpec(0x4, "File", r"\Device\HarddiskVolume1\x"), HandleSpec(0x8, "Event", None))),
        "parsed.dmp")
    failed = _open(tmp_path, DumpSpec(modules=_MODULES, raw_streams=(
        RawStreamSpec(HANDLE_DATA, b"\x10\x00"),)), "failed.dmp")
    assert memory.handle_stream_evidence(absent) == ("absent", None, None)
    state, stream, detail = memory.handle_stream_evidence(parsed)
    assert (state, detail) == ("parsed", None)
    assert [(h.Handle, h.TypeName, h.ObjectName) for h in memory.get_handles(parsed)] == [
        (0x4, "File", r"\Device\HarddiskVolume1\x"), (0x8, "Event", None)]
    assert memory.declared_descriptor_count(stream) == 2
    assert memory.truncated_descriptor_count(stream) == 0
    assert memory.handle_stream_evidence(failed)[0] == "failed"


def test_unparseable_optional_values_are_kept_as_parsed_not_failed(tmp_path):
    region_body = (struct.pack("<IIQ", 16, 48, 1)
                   + struct.pack("<QQIIQIIII", 0x10000, 0x10000, 4, 0, 0x1000, 0x7777, 4, 0x20000, 0))
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, regions=None, raw_streams=(
        RawStreamSpec(MEMORY_INFO_LIST, region_body), RawStreamSpec(MISC_INFO, b"\x01"))))
    assert mf._dumpex_stream_failures == {}
    [region] = memory.get_memory_regions(mf)
    assert (region.BaseAddress, region.State, memory.prot_str(region.State)) == (0x10000, None, "None")


def test_observe_stream_absent_present_empty_and_present(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES))
    absent = memory.observe_stream(mf, "handles", MINIDUMP_STREAM_TYPE.HandleDataStream, None, None)
    empty = memory.observe_stream(mf, "threads", MINIDUMP_STREAM_TYPE.ThreadListStream,
                                  mf.threads, mf.threads.threads)
    present = memory.observe_stream(mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream,
                                    mf.modules, memory.get_modules(mf))
    assert (absent.state, absent.record_count) == (SourceState.ABSENT, None)
    assert (empty.state, empty.record_count) == (SourceState.PRESENT_EMPTY, 0)
    assert (present.state, present.record_count) == (SourceState.PRESENT, 1)


# ── Thread contexts, thread info and the start/current-IP join ──────────


_THREADS = (ThreadSpec(0x100, ip=0x401010), ThreadSpec(0x104, ip=0x402000),
            ThreadSpec(0x108, ip=0x403000), ThreadSpec(0x10C, ip=0x404000))
_THREAD_INFOS = (
    ThreadInfoSpec(0x100, start_address=0x401000),
    ThreadInfoSpec(0x104, dump_flags=memory.DUMP_FLAG_INVALID_INFO, start_address=0x402000),
    ThreadInfoSpec(0x108, dump_flags=memory.DUMP_FLAG_INVALID_CONTEXT | memory.DUMP_FLAG_EXITED_THREAD,
                   start_address=0x403000),
    ThreadInfoSpec(0x100, start_address=0x401100),
)


def test_enriched_thread_contexts_join_every_start_and_conflict_state(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, threads=_THREADS, thread_infos=_THREAD_INFOS))
    base = {"ip_reg": "RIP", "is_wow64": False}
    assert memory.enriched_thread_contexts(mf) == [
        # A TID recorded twice resolves to its LAST ThreadInfoListStream entry.
        {"ThreadId": 0x100, "ip": 0x401010, **base, "start_address": 0x401100,
         "start_address_state": "recorded", "ip_context_conflict": False},
        {"ThreadId": 0x104, "ip": 0x402000, **base, "start_address": None,
         "start_address_state": "invalid", "ip_context_conflict": False},
        {"ThreadId": 0x108, "ip": 0x403000, **base, "start_address": 0x403000,
         "start_address_state": "recorded", "ip_context_conflict": True},
        {"ThreadId": 0x10C, "ip": 0x404000, **base, "start_address": None,
         "start_address_state": "absent", "ip_context_conflict": None},
    ]


def test_thread_info_flag_states_and_tags(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, threads=_THREADS, thread_infos=_THREAD_INFOS))
    rows = [(i.ThreadId, memory.dump_flags_value(i), memory.dump_flags_state(i),
             memory.dump_flags_tags(i), memory.recorded_start_address(i))
            for i in memory.get_thread_infos(mf)]
    assert rows == [
        (0x100, 0, "resolved", [], (0x401000, "recorded")),
        (0x104, 8, "resolved", ["NO_INFO"], (None, "invalid")),
        (0x108, 20, "resolved", ["EXITED", "NO_CTX"], (0x403000, "recorded")),
        (0x100, 0, "resolved", [], (0x401100, "recorded")),
    ]
    placeholder = memory.RawThreadInfo(0x10C)
    assert memory.recorded_start_address(placeholder) == (None, "absent")
    assert memory.dump_flags_state(placeholder) == "absent"
    assert memory.recorded_start_address(None) == (None, "absent")
    assert memory.ip_context_conflict_for(None, placeholder) is False
    assert memory.ip_context_conflict_for(0x1, placeholder) is None


def test_thread_info_entries_too_short_for_dump_flags_are_unresolved(tmp_path):
    body = struct.pack("<III", 12, 4, 2) + struct.pack("<II", 0x100, 0x104)
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, threads=_THREADS[:2],
                                  raw_streams=(RawStreamSpec(THREAD_INFO_LIST, body),)))
    assert [(i.ThreadId, memory.dump_flags_value(i), memory.dump_flags_state(i),
             memory.recorded_start_address(i)) for i in memory.get_thread_infos(mf)] == [
        (0x100, None, "unresolved", (None, "absent")),
        (0x104, None, "unresolved", (None, "absent")),
    ]
    assert [c["ip_context_conflict"] for c in memory.enriched_thread_contexts(mf)] == [None, None]


def test_thread_info_stream_declaring_more_entries_than_it_holds(tmp_path):
    body = (struct.pack("<III", 12, 64, 3)
            + struct.pack("<IIIIQQQQQQ", 0x100, 0, 0, 0, 0, 0, 0, 0, 0x401000, 0))
    mf = _open(tmp_path, DumpSpec(modules=_MODULES,
                                  raw_streams=(RawStreamSpec(THREAD_INFO_LIST, body),)))
    assert mf._dumpex_stream_failures == {}
    assert memory.declared_thread_info_count(mf.thread_info) == 3
    assert memory.truncated_thread_info_count(mf.thread_info) == 2
    assert [i.ThreadId for i in memory.get_thread_infos(mf)] == [0x100]


def test_wow64_context_reports_eip(tmp_path):
    mf = _open(tmp_path, DumpSpec(architecture=ARCH_INTEL, modules=_MODULES,
                                  threads=(ThreadSpec(0x200, ip=0x401234),)))
    assert memory.get_thread_contexts(mf) == [
        {"ThreadId": 0x200, "ip": 0x401234, "ip_reg": "EIP", "is_wow64": True}]


def test_no_system_info_means_no_thread_contexts_and_no_peb(tmp_path):
    mf = _open(tmp_path, DumpSpec(architecture=None, modules=_MODULES,
                                  threads=(ThreadSpec(0x200, ip=0x401234),)))
    assert memory.get_thread_contexts(mf) == []
    assert mf.peb is None


def test_thread_with_an_empty_context_location_is_parsed_from_file_offset_zero(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, threads=(ThreadSpec(0x300, ip=None),)))
    with open(mf.filename, "rb") as fh:
        fh.seek(0xF8)
        rip_at_offset_zero_context = int.from_bytes(fh.read(8), "little")
    assert memory.get_thread_contexts(mf) == [
        {"ThreadId": 0x300, "ip": rip_at_offset_zero_context, "ip_reg": "RIP", "is_wow64": False}]


# ── Segment table, VA mapping and structural capture ────────────────────


def test_segment_table_order_and_file_offsets(gapped):
    segments = memory.get_memory_segments(gapped)
    assert [(s.start_virtual_address, s.size) for s in segments] == [
        (0x10000, 0x1000), (0x11000, 0x1000), (0x20000, 0x100), (0x30000, 0x1000)]
    assert segments[1].start_file_address == segments[0].start_file_address + 0x1000
    assert memory.get_memory_segments(gapped) is memory._memory_segments(gapped)


def test_va_to_file_offset_is_half_open_and_rejects_zero(gapped):
    first = memory.get_memory_segments(gapped)[0].start_file_address
    assert memory.va_to_file_offset(gapped, 0x10000) == first
    assert memory.va_to_file_offset(gapped, 0x11FFF) == first + 0x1FFF
    assert memory.va_to_file_offset(gapped, 0x12000) is None
    assert memory.va_to_file_offset(gapped, 0) is None


@pytest.mark.parametrize("va, size, expected", [
    (0x10000, 0x10, 0x10),
    (0x10FF0, 0x20, 0x20),          # adjacent segments form one contiguous run
    (0x10000, 0x3000, 0x2000),      # the run stops at the first hole
    (0x12000, 0x10, 0),             # inside the hole
    (0x30000, 0x1000, 0x1000),      # short-backed segment still counts as captured
    (0, 0x10, 0),
    (0x10000, 0, 0),
    (0x10000, -1, 0),
])
def test_va_range_captured_bytes(gapped, va, size, expected):
    assert memory.va_range_captured_bytes(gapped, va, size) == expected


def test_segment_index_is_memoized_on_the_dump_and_rebuilt_for_a_new_table(gapped):
    memory.va_range_captured_bytes(gapped, 0x10000, 1)
    raw, ordered, max_ends = gapped._dumpex_segments_by_va
    assert raw is memory._memory_segments(gapped)
    assert max_ends == [0x11000, 0x12000, 0x20100, 0x31000]
    memory.va_range_captured_bytes(gapped, 0x20000, 1)
    assert gapped._dumpex_segments_by_va[1] is ordered
    gapped.memory_segments_64.memory_segments = list(raw[:1])
    assert memory.va_range_captured_bytes(gapped, 0x10000, 0x2000) == 0x1000
    assert gapped._dumpex_segments_by_va[0] is gapped.memory_segments_64.memory_segments


# ── Checked, clamped and spanning reads ─────────────────────────────────


def _bytes(data):
    return ("bytes", data)


_BOUNDARY_ERROR = ("raises", "Exception", "Would read over segment boundaries!")

# (va, size, read_region, read_region_clamped, read_region_spanning) -- every
# successful read is compared in full against the exact slice it must return.
READ_CASES = {
    "segment_start": (0x10000, 0x10, _bytes(_A[:0x10]), _bytes(_A[:0x10]), _bytes(_A[:0x10])),
    "segment_end_boundary": (0x10FF0, 0x10, _bytes(_A[0xFF0:]), _bytes(_A[0xFF0:]),
                             _bytes(_A[0xFF0:])),
    "into_adjacent_segment": (0x10FF0, 0x20, _BOUNDARY_ERROR, _bytes(_A[0xFF0:]),
                              _bytes(_A[0xFF0:] + _B[:0x10])),
    "whole_adjacent_run": (0x10000, 0x2000, _BOUNDARY_ERROR, _bytes(_A), _bytes(_A + _B)),
    "into_hole": (0x11FF0, 0x20, _BOUNDARY_ERROR, _bytes(_B[0xFF0:]), _bytes(_B[0xFF0:])),
    "inside_hole": (0x12000, 0x4,
                    ("raises", "Exception", "Memory address 0x00012000 is not in process memory space"),
                    _bytes(b""), _bytes(b"")),
    # the file ends before the segment's declared data does
    "short_backed_segment": (0x30000, 0x100, _bytes(_D[:_SHORT_BACKED_BYTES]),
                             _bytes(_D[:_SHORT_BACKED_BYTES]), _bytes(_D[:_SHORT_BACKED_BYTES])),
    "zero_length": (0x10000, 0, _BOUNDARY_ERROR, _bytes(b""), _bytes(b"")),
}


@pytest.mark.parametrize("va, size, region, clamped, spanning", list(READ_CASES.values()),
                         ids=list(READ_CASES))
def test_read_primitives(gapped, va, size, region, clamped, spanning):
    assert _outcome(memory.read_region, gapped, va, size) == region
    assert _outcome(memory.read_region_clamped, gapped, va, size) == clamped
    assert _outcome(memory.read_region_spanning, gapped, va, size) == spanning


def test_clamped_reader_builds_one_reader_and_read_region_builds_one_per_call(gapped):
    calls = []
    real = gapped.get_reader

    def counting():
        calls.append(1)
        return real()

    gapped.get_reader = counting
    read = memory.clamped_reader(gapped)
    assert (read(0x10000, 4), read(0x20000, 4), read(0x12000, 4)) == (_A[:4], _C[:4], b"")
    assert len(calls) == 1
    memory.read_region(gapped, 0x10000, 4)
    memory.read_region(gapped, 0x20000, 4)
    assert len(calls) == 3


@pytest.mark.parametrize("spec_overrides, error", [
    ({"architecture": None}, "'NoneType' object has no attribute 'ProcessorArchitecture'"),
    ({"modules": None}, "'NoneType' object has no attribute 'modules'"),
    ({"memory64": None}, "'NoneType' object has no attribute 'memory_segments'"),
])
def test_reader_construction_failures(tmp_path, spec_overrides, error):
    fields = dict(modules=_MODULES, memory64=(_SEG_C,))
    fields.update(spec_overrides)
    mf = _open(tmp_path, DumpSpec(**fields))
    assert _outcome(memory.read_region, mf, 0x20000, 4) == ("raises", "AttributeError", error)
    assert memory.read_region_clamped(mf, 0x20000, 4) == b""
    assert memory.read_region_spanning(mf, 0x20000, 4) == b""


def test_memory64_list_takes_precedence_over_memory_list(tmp_path):
    mf = _open(tmp_path, DumpSpec(
        modules=_MODULES,
        memory64=(SegmentSpec(0x10000, b"6" * 0x100),),
        memory32=(SegmentSpec(0x10000, b"3" * 0x100), SegmentSpec(0x50000, b"x" * 0x10))))
    assert [(s.start_virtual_address, s.size) for s in memory.get_memory_segments(mf)] == [
        (0x10000, 0x100)]
    assert memory.read_region(mf, 0x10000, 4) == b"6666"
    assert memory.va_to_file_offset(mf, 0x50000) is None
    assert memory.read_region_clamped(mf, 0x50000, 4) == b""


def test_memory_list_is_used_when_memory64_list_is_absent(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, memory64=None,
                                  memory32=(SegmentSpec(0x10000, b"3" * 0x100),)))
    assert [(s.start_virtual_address, s.size) for s in memory.get_memory_segments(mf)] == [
        (0x10000, 0x100)]
    assert memory.read_region(mf, 0x10000, 4) == b"3333"


def test_overlapping_segments_resolve_to_the_first_listed(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, memory64=(
        SegmentSpec(0x10000, b"L" * 0x200), SegmentSpec(0x10100, b"S" * 0x40))))
    first = memory.get_memory_segments(mf)[0].start_file_address
    assert memory.read_region(mf, 0x10100, 4) == b"LLLL"
    assert memory.va_to_file_offset(mf, 0x10100) == first + 0x100
    assert memory.va_range_captured_bytes(mf, 0x10100, 0x100) == 0x100
    assert memory.read_region_spanning(mf, 0x10180, 0x100) == b"L" * 0x80


def test_unsorted_adjacent_segments_still_form_one_run(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, memory64=(
        SegmentSpec(0x11000, b"B" * 0x10), SegmentSpec(0x10000, b"A" * 0x1000))))
    assert memory.va_range_captured_bytes(mf, 0x10FF0, 0x20) == 0x20
    assert memory.read_region_spanning(mf, 0x10FF0, 0x20) == b"A" * 0x10 + b"B" * 0x10


# ── Size resolution, string search and address labels ───────────────────


_SEARCH_SEGMENTS = (
    SegmentSpec(0x10000, b"A" * 0xFF0 + b"NEEDLE" + b"A" * 0xA),
    SegmentSpec(0x11000, b"B" * 0x1000),
    SegmentSpec(0x20000, b"x" * 0x10 + "NEEDLE".encode("utf-16-le") + b"x" * 0xE4),
    SegmentSpec(0x30000, b"D" * 0x1000),
)
_SEARCH_REGIONS = (
    RegionSpec(0x10000, 0x2000),                         # spans two adjacent segments
    RegionSpec(0x20000, 0x100, protect=PAGE_EXECUTE_READWRITE),
    RegionSpec(0x30000, 0x1000),                         # short-backed
    RegionSpec(0x40000, 0x1000, state=MEM_RESERVE),      # not committed
    RegionSpec(0x50000, 0x1000),                         # committed, never captured
)


@pytest.fixture
def searchable(tmp_path):
    spec = DumpSpec(modules=_MODULES, regions=_SEARCH_REGIONS, memory64=_SEARCH_SEGMENTS)
    spec.truncate_to = len(build_minidump(spec)) - 0x1000 + _SHORT_BACKED_BYTES
    mf = _open(tmp_path, spec)
    yield mf
    mf.file_handle.close()


def test_string_search_hits_and_telemetry(searchable):
    hits, stats = memory._search_string_in_memory(searchable, "NEEDLE")
    # The ASCII needle inside the region that spans two adjacent segments
    # is not found: that region's single read raises and is counted as
    # skipped, together with the never-captured committed region.
    assert [(r.BaseAddress, off, enc) for r, off, enc in hits] == [(0x20000, 0x10, "UTF16")]
    assert stats == memory.StringSearchStats(skipped=2, clamped=0, truncated=1)
    hits, stats = memory._search_string_in_memory(searchable, "DDDD")
    assert [(r.BaseAddress, off, enc) for r, off, enc in hits] == [(0x30000, 0, "ASCII")]
    assert stats == memory.StringSearchStats(skipped=2, clamped=0, truncated=1)


def test_string_search_reports_one_hit_per_region_and_ignores_modules(monkeypatch):
    """The search reports the first ASCII occurrence per committed region,
    or the first UTF-16LE one only when the ASCII form is absent; further
    occurrences in the same region are not reported. A hit in a MEM_IMAGE
    region covered by a loaded module is reported like any other: setting
    registered-image hits aside is collect_report's decision."""
    from tests.fixtures.fakes import FakeMF, FakeStream, Module, Region
    wide = "NEEDLE".encode("utf-16-le")
    contents = {
        0x10000: b"..NEEDLE..NEEDLE.." + wide,
        0x20000: b"...." + wide + b".." + wide,
        0x30000: b"NEEDLE",
    }
    mf = FakeMF()
    mf.memory_info = FakeStream([
        Region(0x10000, 0x10000, 0x40, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
        Region(0x20000, 0x20000, 0x40, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(0x30000, 0x30000, 0x40, "MEM_RESERVE", "PAGE_NOACCESS", "MEM_PRIVATE"),
    ], "infos")
    mf.modules = FakeStream([Module(0x10000, 0x1000, "C:\\Windows\\System32\\image.dll")], "modules")
    monkeypatch.setattr(memory, "read_region",
                        lambda mf_, addr, size: contents[addr].ljust(size, b"\x00"))
    hits, stats = memory._search_string_in_memory(mf, "NEEDLE")
    assert [(r.BaseAddress, off, enc) for r, off, enc in hits] == [
        (0x10000, 2, "ASCII"),
        (0x20000, 4, "UTF16"),
    ]
    assert stats == memory.StringSearchStats(skipped=0, clamped=0, truncated=0)


def test_resolve_size(searchable):
    assert memory._resolve_size(searchable, 0x10010, None) == 0x2000 - 0x10
    assert memory._resolve_size(searchable, 0x10010, 5) == 5
    assert memory._resolve_size(searchable, 0x90000, None) == 0x10000


def test_addr_label(searchable):
    offset = memory.va_to_file_offset(searchable, 0x10010)
    assert memory.addr_label(searchable, 0x10010, region_base=0x10000).splitlines() == [
        "  VA (process)     0x0000000000010010",
        f"  File offset (.dmp)   0x{offset:016x}",
        "  Region base (VA)     0x0000000000010000",
    ]
    assert memory.addr_label(searchable, 0x90000).splitlines() == [
        "  VA (process)     0x0000000000090000",
        "  File offset (.dmp)   (VA not captured in dump)",
    ]


def test_handle_string_reads_restore_the_file_cursor(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, handles=(HandleSpec(0x4, "File", "n"),)))
    fh = mf.file_handle
    with open(mf.filename, "rb") as raw:
        name_rva = raw.read().find(struct.pack("<I", 8) + "File".encode("utf-16-le"))
    fh.seek(7)
    assert memory._read_handle_string(name_rva, fh) == "File"
    assert fh.tell() == 7
    assert memory._read_handle_string(10 ** 9, fh) is None
    assert fh.tell() == 7


# ── Wrap-around at the top of the address space ─────────────────────────

_TOP = 0xFFFF_FFFF_FFFF_F000
_TOP_DATA = bytes(range(256)) * 16


@pytest.fixture
def top_of_space(tmp_path):
    mf = _open(tmp_path, DumpSpec(modules=_MODULES, memory64=(SegmentSpec(_TOP, _TOP_DATA),)))
    yield mf
    mf.file_handle.close()


@pytest.mark.parametrize("va, size, region, clamped_and_spanning, captured", [
    (_TOP, 0x1000, _bytes(_TOP_DATA), _bytes(_TOP_DATA), 0x1000),
    # va + size runs past 2**64
    (_TOP + 0xFF0, 0x20, _BOUNDARY_ERROR, _bytes(_TOP_DATA[0xFF0:]), 0x10),
    (0xFFFF_FFFF_FFFF_FFFF, 2, _BOUNDARY_ERROR, _bytes(_TOP_DATA[-1:]), 1),
    (0xFFFF_FFFF_FFFF_FFFF, 1, _bytes(_TOP_DATA[-1:]), _bytes(_TOP_DATA[-1:]), 1),
])
def test_reads_that_reach_or_wrap_past_the_top_of_the_address_space(
        top_of_space, va, size, region, clamped_and_spanning, captured):
    assert _outcome(memory.read_region, top_of_space, va, size) == region
    assert _outcome(memory.read_region_clamped, top_of_space, va, size) == clamped_and_spanning
    assert _outcome(memory.read_region_spanning, top_of_space, va, size) == clamped_and_spanning
    assert memory.va_range_captured_bytes(top_of_space, va, size) == captured
    first = memory.get_memory_segments(top_of_space)[0].start_file_address
    assert memory.va_to_file_offset(top_of_space, va) == first + (va - _TOP)


# ── Size caps ────────────────────────────────────────────────────────────


def test_thread_info_entries_past_the_entry_cap_are_counted_as_truncated(tmp_path, monkeypatch):
    body = struct.pack("<III", 12, 64, 3) + b"".join(
        struct.pack("<IIIIQQQQQQ", 0x100 + i * 4, 0, 0, 0, 0, 0, 0, 0, 0x401000 + i, 0)
        for i in range(3))
    monkeypatch.setattr(memory, "MAX_THREAD_INFO_ENTRIES", 2)
    mf = _open(tmp_path, DumpSpec(modules=_MODULES,
                                  raw_streams=(RawStreamSpec(THREAD_INFO_LIST, body),)))
    assert mf._dumpex_stream_failures == {}
    assert memory.declared_thread_info_count(mf.thread_info) == 3
    assert memory.truncated_thread_info_count(mf.thread_info) == 1
    assert [i.ThreadId for i in memory.get_thread_infos(mf)] == [0x100, 0x104]


# ── Verdict, IOC extraction and hexdump presentation ─────────────────────


@pytest.mark.parametrize("count, tier, text", [
    (0, "CLEAN", "CLEAN — no suspicious indicators found"),
    (1, "SUSPICIOUS", "SUSPICIOUS — 1 independent indicator"),
    (2, "LIKELY_MALICIOUS", "LIKELY MALICIOUS — 2 independent indicators"),
    (3, "HIGH_CONFIDENCE_MALICIOUS", "HIGH CONFIDENCE MALICIOUS — 3 independent indicators"),
    (4, "HIGH_CONFIDENCE_MALICIOUS", "HIGH CONFIDENCE MALICIOUS — 4 independent indicators"),
])
def test_verdict_tiers(monkeypatch, count, tier, text):
    import dumpex.ui.colors as colors
    monkeypatch.setattr(colors, "USE_COLOR", False)
    dims = {name: True for name in list(memory.INDICATOR_DIMS)[:count]}
    assert memory.verdict_for(dims) == tier
    assert memory._verdict(dims) == text


def test_ioc_string_extraction_encodings_and_url_extension():
    blob = (b"\x00junk\x00" + b"http://c2.example.test/a\x01b" + b"\x00" * 4
            + b"GET https://x.example.test/p HTTP\x00"
            + b"plain ascii text here\x00" + "wide string here".encode("utf-16-le") + b"\x00\x00"
            + b"https://x.io/\xff" + b"\x00")
    # The UTF-16 pattern starts on the last ASCII character before the wide
    # string, whose zero terminator reads as its high byte.
    assert memory._extract_ioc_strings(blob, 0x5000) == [
        (6, "ASCII", "http://c2.example.test/a"),
        (36, "ASCII", "GET https://x.example.test/p HTTP"),
        (40, "ASCII-URL", "https://x.example.test/p HTTP"),
        (70, "ASCII", "plain ascii text here"),
        (90, "UTF16", "ewide string here"),
        (126, "ASCII", "https://x.io/"),
    ]
    assert memory.IOC_STRING_ENCODING_WIDTHS == {"ASCII": 1, "ASCII-URL": 1, "UTF16": 2}


def test_hexdump_context_rows_and_hit_highlight(monkeypatch):
    import dumpex.ui.colors as colors
    data = bytes(range(0x40))
    monkeypatch.setattr(colors, "USE_COLOR", False)
    assert memory._hexdump_context(data, 0x12, 0x1000, before=0x10, after=0x10).splitlines() == [
        "    0x0000000000001002  02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11   ................",
        "    0x0000000000001012  12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21   .............. !",
    ]
    monkeypatch.setattr(colors, "USE_COLOR", True)
    lines = memory._hexdump_context(data, 0x12, 0x1000, before=0x10, after=0x10).splitlines()
    assert lines[0].startswith("    \x1b[2m0x0000000000001002\x1b[0m  02 03")
    assert lines[1].startswith("    \x1b[93m0x0000000000001012\x1b[0m  \x1b[93m12 13")
