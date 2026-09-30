"""
Behavioural checks for the module-level replacement seams of
`dumpex.core.memory`.

Tests (and the conftest reset fixture) replace readers, parsers, caps,
caches and thread interpretations by assigning to
`dumpex.core.memory.<name>`. That only works while
the function that consumes `<name>` resolves it from the
`dumpex.core.memory` namespace at call time. Moving the consumer into
another module silently breaks the seam -- a re-export keeps the name
importable, but the moved function would read its NEW module's globals --
unless the move delegates explicitly.

Each `check_*` function patches legacy names on whatever module is
installed under `dumpex.core.memory` when it runs -- the real module, or a
facade over relocated code -- and asserts the consumer, called through that
same path, observes the patch. They take a pytest `MonkeyPatch` and are
shared by `tests/unit/test_memory_patch_seams.py` (which runs them against
the current tree) and the mutation controls (which run them against a
simulated relocation that does not delegate, and expect them to fail).
"""
import importlib
import io
import struct

from minidump.constants import MINIDUMP_STREAM_TYPE

from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment


def _legacy():
    """The module currently installed under the legacy path."""
    return importlib.import_module("dumpex.core.memory")


def _patch(monkeypatch, memory, name, value):
    # A name the legacy path does not have is added rather than refused:
    # the check then reports that the consumer does not see it.
    monkeypatch.setattr(memory, name, value, raising=False)


class _Marker(Exception):
    """Raised by a patched seam so a check can prove the patch was reached."""


def _raise_marker(*args, **kwargs):
    raise _Marker()


def _reached(fn, *args) -> bool:
    """True when calling `fn` raised the marker, directly or as the cause
    of the exception the consumer wraps it in."""
    try:
        fn(*args)
    except Exception as exc:   # noqa: BLE001 -- inspected below
        while exc is not None:
            if isinstance(exc, _Marker):
                return True
            exc = exc.__cause__
    return False


def _thread_mf():
    mf = FakeMF()
    mf.threads = FakeStream([], "threads")
    return mf


def check_read_region_reaches_string_search(monkeypatch):
    memory = _legacy()
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x10, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    _patch(monkeypatch, memory, "read_region", lambda mf_, addr, size: b"..needle..".ljust(size))
    hits, _ = memory._search_string_in_memory(mf, "needle")
    assert [(r.BaseAddress, off, enc) for r, off, enc in hits] == [(0x1000, 2, "ASCII")], \
        "_search_string_in_memory does not read through dumpex.core.memory.read_region"


def check_max_region_read_reaches_size_resolution(monkeypatch):
    memory = _legacy()
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    _patch(monkeypatch, memory, "MAX_REGION_READ", 0x10)
    assert memory._resolve_size(mf, 0x1000, None) == 0x10, \
        "_resolve_size does not read dumpex.core.memory.MAX_REGION_READ"
    _patch(monkeypatch, memory, "read_region", lambda mf_, addr, size: b"\x00" * size)
    _, stats = memory._search_string_in_memory(mf, "x")
    assert stats.clamped == 1, \
        "_search_string_in_memory does not read dumpex.core.memory.MAX_REGION_READ"


def check_thread_readers_reach_enriched_contexts(monkeypatch):
    memory = _legacy()
    mf = _thread_mf()
    _patch(monkeypatch, memory, "get_thread_contexts",
           lambda mf_: [{"ThreadId": 7, "ip": 0x10, "ip_reg": "RIP", "is_wow64": False}])
    _patch(monkeypatch, memory, "get_thread_infos", lambda mf_: [])
    assert [c["ThreadId"] for c in memory.enriched_thread_contexts(mf)] == [7], \
        "enriched_thread_contexts does not read dumpex.core.memory.get_thread_contexts"
    _patch(monkeypatch, memory, "get_thread_infos", _raise_marker)
    assert _reached(memory.enriched_thread_contexts, mf), \
        "enriched_thread_contexts does not read dumpex.core.memory.get_thread_infos"
    _patch(monkeypatch, memory, "get_thread_infos", lambda mf_: [])
    _patch(monkeypatch, memory, "recorded_start_address", _raise_marker)
    assert _reached(memory.enriched_thread_contexts, mf), \
        "enriched_thread_contexts does not read dumpex.core.memory.recorded_start_address"


def check_dump_flags_reach_conflict_join(monkeypatch):
    memory = _legacy()
    info = type("Info", (), {"ThreadId": 1, "DumpFlags": 0, "RawDumpFlags": 0})()
    _patch(monkeypatch, memory, "dump_flags_value", lambda ti: memory.DUMP_FLAG_INVALID_CONTEXT)
    _patch(monkeypatch, memory, "_is_real_thread_info", lambda ti: True)
    assert memory.ip_context_conflict_for(0x10, info) is True, \
        "ip_context_conflict_for does not read dumpex.core.memory.dump_flags_value"


def check_flag_readers_reach_thread_interpretations(monkeypatch):
    memory = _legacy()
    info = type("Info", (), {"ThreadId": 1, "StartAddress": 0x401000,
                             "DumpFlags": 0, "RawDumpFlags": 0})()
    _patch(monkeypatch, memory, "_is_real_thread_info", lambda ti: False)
    assert memory.dump_flags_state(info) == memory.DUMP_FLAGS_ABSENT, \
        "dump_flags_state does not read dumpex.core.memory._is_real_thread_info"
    assert memory.recorded_start_address(info) == (None, memory.START_ADDRESS_ABSENT), \
        "recorded_start_address does not read dumpex.core.memory._is_real_thread_info"
    _patch(monkeypatch, memory, "_is_real_thread_info", lambda ti: True)
    _patch(monkeypatch, memory, "dump_flags_value", lambda ti: None)
    assert memory.dump_flags_state(info) == memory.DUMP_FLAGS_UNRESOLVED, \
        "dump_flags_state does not read dumpex.core.memory.dump_flags_value"
    assert memory.recorded_start_address(info) == (0x401000, memory.START_ADDRESS_UNVERIFIED), \
        "recorded_start_address does not read dumpex.core.memory.dump_flags_value"
    _patch(monkeypatch, memory, "dump_flags_value", lambda ti: memory.DUMP_FLAG_EXITED_THREAD)
    assert memory.dump_flags_tags(info) == ["EXITED"], \
        "dump_flags_tags does not read dumpex.core.memory.dump_flags_value"


def check_clamped_reader_reaches_one_shot_read(monkeypatch):
    memory = _legacy()
    _patch(monkeypatch, memory, "clamped_reader", lambda mf_: (lambda addr, size: b"patched"))
    assert memory.read_region_clamped(FakeMF(), 0x1000, 4) == b"patched", \
        "read_region_clamped does not build its reader through dumpex.core.memory.clamped_reader"


def check_segment_table_reaches_address_mapping(monkeypatch):
    memory = _legacy()
    segments = [Segment(0x1000, 0x400, 0x100)]
    _patch(monkeypatch, memory, "_memory_segments", lambda mf_: segments)
    mf = FakeMF()
    assert memory.va_to_file_offset(mf, 0x1010) == 0x410, \
        "va_to_file_offset does not read dumpex.core.memory._memory_segments"
    assert memory.va_range_captured_bytes(mf, 0x1000, 0x200) == 0x100, \
        "va_range_captured_bytes does not read dumpex.core.memory._memory_segments"
    assert memory.get_memory_segments(mf) is segments, \
        "get_memory_segments does not read dumpex.core.memory._memory_segments"
    _patch(monkeypatch, memory, "va_to_file_offset", lambda mf_, va: 0xABC)
    assert "0x0000000000000abc" in memory.addr_label(mf, 0x1010), \
        "addr_label does not read dumpex.core.memory.va_to_file_offset"


def check_stream_failure_reaches_observers(monkeypatch):
    memory = _legacy()
    _patch(monkeypatch, memory, "stream_failure", lambda mf_, st: "patched failure")
    observed = memory.observe_stream(FakeMF(), "x", MINIDUMP_STREAM_TYPE.HandleDataStream, None, [])
    assert observed.detail == "patched failure", \
        "observe_stream does not read dumpex.core.memory.stream_failure"
    assert memory.handle_stream_evidence(FakeMF()) == ("failed", None, "patched failure"), \
        "handle_stream_evidence does not read dumpex.core.memory.stream_failure"


def check_handle_layout_seams_reach_the_parser(monkeypatch):
    memory = _legacy()
    header = struct.pack("<IIII", 16, 32, 3, 0)
    body = header + b"\x00" * (32 * 3)

    class _Directory:
        class Location:
            Rva = 0
            DataSize = len(body)

    _patch(monkeypatch, memory, "MAX_HANDLE_DESCRIPTORS", 2)
    parsed = memory.parse_handle_stream(_Directory, io.BytesIO(body))
    assert len(parsed.handles) == 2, \
        "parse_handle_stream does not read dumpex.core.memory.MAX_HANDLE_DESCRIPTORS"
    _patch(monkeypatch, memory, "_handle_descriptor_layout", _raise_marker)
    assert _reached(memory.parse_handle_stream, _Directory, io.BytesIO(body)), \
        "parse_handle_stream does not read dumpex.core.memory._handle_descriptor_layout"
    monkeypatch.undo()
    _patch(monkeypatch, memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", (1, 2))
    assert memory._handle_descriptor_layout() == (1, 2), \
        "_handle_descriptor_layout does not read dumpex.core.memory._HANDLE_DESCRIPTOR_LAYOUT_CACHE"
    _patch(monkeypatch, memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)
    _patch(monkeypatch, memory, "_descriptor_class_size", _raise_marker)
    assert _reached(memory._handle_descriptor_layout), \
        "_handle_descriptor_layout does not read dumpex.core.memory._descriptor_class_size"


def check_loader_seams_reach_open_dump(monkeypatch, dump_path):
    """`dump_path` names a real synthetic dump with SystemInfo, a thread with
    a captured context, and a ModuleListStream."""
    memory = _legacy()
    calls = []
    real_parse = memory._STREAM_DISPATCH[MINIDUMP_STREAM_TYPE.ModuleListStream][1]

    def recording_parse(directory, fh):
        calls.append("modules")
        return real_parse(directory, fh)

    monkeypatch.setitem(memory._STREAM_DISPATCH, MINIDUMP_STREAM_TYPE.ModuleListStream,
                        ("modules", recording_parse))
    _patch(monkeypatch, memory, "CONTEXT",
           type("PatchedContext", (), {"parse": staticmethod(lambda fh: "ctx")}))
    monkeypatch.setattr(memory.PEB, "from_minidump", staticmethod(lambda mf_: "peb"))
    mf = memory.open_dump(dump_path)
    try:
        assert calls == ["modules"], "open_dump does not dispatch through _STREAM_DISPATCH"
        assert [t.ContextObject for t in mf.threads.threads] == ["ctx"], \
            "open_dump does not parse contexts through dumpex.core.memory.CONTEXT"
        assert mf.peb == "peb", "open_dump does not build the PEB through dumpex.core.memory.PEB"
    finally:
        mf.file_handle.close()


CHECKS = (
    check_read_region_reaches_string_search,
    check_max_region_read_reaches_size_resolution,
    check_thread_readers_reach_enriched_contexts,
    check_dump_flags_reach_conflict_join,
    check_flag_readers_reach_thread_interpretations,
    check_clamped_reader_reaches_one_shot_read,
    check_segment_table_reaches_address_mapping,
    check_stream_failure_reaches_observers,
    check_handle_layout_seams_reach_the_parser,
)
