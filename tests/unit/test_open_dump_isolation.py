"""Unit tests for dumpex.core.memory.open_dump()'s per-stream isolation
(issue #37 §2), stream_failure(), and observe_stream().

Builds a small, structurally-real minidump file (a real MinidumpHeader +
a real MINIDUMP_DIRECTORY table -- Phase 1 parses these for real, exactly
as before this change) naming whichever stream types a test needs, then
drives Phase 2/3 through dumpex.core.memory._STREAM_DISPATCH entries
monkeypatched to test doubles. What bytes actually sit at each stream's
own Rva is irrelevant here: the doubles never read them -- this targets
open_dump()'s OWN isolation/ordering logic (the actual production code
path), not the installed minidump library's binary parsers, which is a
separate, much larger byte-format surface (tests/unit/test_open_dump.py
already covers the unchanged file-not-found/corrupted-file paths that
don't go through per-stream dispatch at all).
"""
import io
import struct

import pytest

import dumpex.core.memory as memory
from dumpex.core.memory import open_dump, stream_failure, observe_stream
from dumpex.output.coverage import SourceState

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE


def _build_minidump_bytes(stream_types) -> bytes:
    """A real, parseable MinidumpHeader + MINIDUMP_DIRECTORY table naming
    `stream_types` in order, each pointing at a 4-byte placeholder
    payload region nothing in these tests ever reads."""
    n = len(stream_types)
    stream_dir_rva = 32
    dir_entry_size = 12
    payload_rva = stream_dir_rva + n * dir_entry_size

    header = (b"MDMP" + struct.pack("<H", 42899) + struct.pack("<H", 0)
              + struct.pack("<I", n) + struct.pack("<I", stream_dir_rva)
              + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", 0)
              + struct.pack("<I", 0))   # Flags = MiniDumpNormal = 0

    directory = bytearray()
    for st in stream_types:
        directory += struct.pack("<III", st.value, 4, payload_rva)
        payload_rva += 4

    payloads = b"\x00" * (n * 4)
    return header + bytes(directory) + payloads


def _write(tmp_path, stream_types):
    path = tmp_path / "fake.dmp"
    path.write_bytes(_build_minidump_bytes(stream_types))
    return str(path)


class _StreamList:
    """Stand-in for a MinidumpXxxList wrapper (`.modules`/`.threads`/...)."""
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)


class _FakeThread:
    def __init__(self, teb, context_rva=0):
        self.Teb = teb
        self.ThreadContext = _StreamList(Rva=context_rva)
        # No ContextObject attribute at all until phase 3a sets one --
        # matches a real MINIDUMP_THREAD, which never predefines it.


class _FakeContext:
    def __init__(self, rip):
        self.Rip = rip


@pytest.fixture
def dispatch_patch(monkeypatch):
    """Patch ONE _STREAM_DISPATCH entry's parser to `fn` for the
    duration of a test, leaving every other entry (including the real
    parse_handle_stream) untouched."""
    def _patch(stream_type, fn):
        name, _ = memory._STREAM_DISPATCH[stream_type]
        monkeypatch.setitem(memory._STREAM_DISPATCH, stream_type, (name, fn))
    return _patch


# ── Phase 2: per-stream isolation ─────────────────────────────────────────

def test_isolates_one_malformed_stream_others_still_populate(tmp_path, dispatch_patch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream,
                              MINIDUMP_STREAM_TYPE.ModuleListStream])
    sysinfo_obj = _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64)
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream, lambda d, fh: sysinfo_obj)
    dispatch_patch(MINIDUMP_STREAM_TYPE.ModuleListStream,
                    lambda d, fh: (_ for _ in ()).throw(ValueError("corrupt module list")))

    mf = open_dump(path)   # must not raise / SystemExit

    assert mf.sysinfo is sysinfo_obj
    assert mf.modules is None
    detail = stream_failure(mf, MINIDUMP_STREAM_TYPE.ModuleListStream)
    assert detail is not None
    assert "corrupt module list" in detail
    assert stream_failure(mf, MINIDUMP_STREAM_TYPE.SystemInfoStream) is None
    assert mf._dumpex_stream_failures == {MINIDUMP_STREAM_TYPE.ModuleListStream: detail}


def test_stream_failures_empty_when_nothing_fails(tmp_path, dispatch_patch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream,
                    lambda d, fh: _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64))

    mf = open_dump(path)

    assert mf._dumpex_stream_failures == {}


def test_unrecognized_stream_type_is_silently_skipped(tmp_path):
    # TokenStream is a real, library-recognized MINIDUMP_STREAM_TYPE but
    # is not in dumpex's own _STREAM_DISPATCH -- same silent skip an
    # unimplemented branch of the library's own __parse_directories()
    # takes, not a failure.
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.TokenStream])
    mf = open_dump(path)   # must not raise
    assert mf._dumpex_stream_failures == {}


def test_multiple_failed_streams_are_all_recorded(tmp_path, dispatch_patch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.ModuleListStream,
                              MINIDUMP_STREAM_TYPE.MiscInfoStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.ModuleListStream,
                    lambda d, fh: (_ for _ in ()).throw(RuntimeError("bad modules")))
    dispatch_patch(MINIDUMP_STREAM_TYPE.MiscInfoStream,
                    lambda d, fh: (_ for _ in ()).throw(RuntimeError("bad misc")))

    mf = open_dump(path)

    assert set(mf._dumpex_stream_failures) == {
        MINIDUMP_STREAM_TYPE.ModuleListStream, MINIDUMP_STREAM_TYPE.MiscInfoStream}


# ── stream_failure() ──────────────────────────────────────────────────────

def test_stream_failure_none_for_never_failed():
    class _MF:
        _dumpex_stream_failures = {}
    assert stream_failure(_MF(), MINIDUMP_STREAM_TYPE.ModuleListStream) is None


def test_stream_failure_treats_missing_attribute_as_no_failures():
    # An mf built by a test/fixture that never went through open_dump()
    # has no _dumpex_stream_failures attribute at all -- must not raise.
    class _MF:
        pass
    assert stream_failure(_MF(), MINIDUMP_STREAM_TYPE.ModuleListStream) is None


def test_stream_failure_returns_the_recorded_detail():
    class _MF:
        _dumpex_stream_failures = {MINIDUMP_STREAM_TYPE.HandleDataStream: "ValueError: boom"}
    assert stream_failure(_MF(), MINIDUMP_STREAM_TYPE.HandleDataStream) == "ValueError: boom"


# ── observe_stream() ───────────────────────────────────────────────────────

class _FailMF:
    def __init__(self, failures):
        self._dumpex_stream_failures = failures


def test_observe_stream_failed_when_stream_type_in_failures():
    mf = _FailMF({MINIDUMP_STREAM_TYPE.ModuleListStream: "boom"})
    obs = observe_stream(mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream, obj=None, items=[])
    assert obs.state == SourceState.FAILED
    assert obs.detail == "boom"
    assert obs.record_count is None


def test_observe_stream_absent_when_object_falsy_and_not_failed():
    mf = _FailMF({})
    obs = observe_stream(mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream, obj=None, items=[])
    assert obs.state == SourceState.ABSENT


def test_observe_stream_present_empty():
    mf = _FailMF({})
    obs = observe_stream(mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream,
                          obj=_StreamList(modules=[]), items=[])
    assert obs.state == SourceState.PRESENT_EMPTY
    assert obs.record_count == 0


def test_observe_stream_present_with_items():
    mf = _FailMF({})
    items = [object(), object()]
    obs = observe_stream(mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream,
                          obj=_StreamList(modules=items), items=items)
    assert obs.state == SourceState.PRESENT
    assert obs.record_count == 2


def test_observe_stream_failed_takes_priority_over_object_state():
    # Even if the caller (incorrectly) also passes a truthy obj/items, a
    # recorded stream failure must win -- a stream that raised while
    # parsing never left a usable object behind.
    mf = _FailMF({MINIDUMP_STREAM_TYPE.ModuleListStream: "boom"})
    obs = observe_stream(mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream,
                          obj=_StreamList(modules=[object()]), items=[object()])
    assert obs.state == SourceState.FAILED


# ── Phase 3a: thread contexts (preserved, including its partial guard) ───

def test_thread_contexts_populated_when_sysinfo_and_threads_present(tmp_path, dispatch_patch, monkeypatch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream,
                              MINIDUMP_STREAM_TYPE.ThreadListStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream,
                    lambda d, fh: _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64))
    thread = _FakeThread(teb=0x1000, context_rva=0)
    dispatch_patch(MINIDUMP_STREAM_TYPE.ThreadListStream, lambda d, fh: _StreamList(threads=[thread]))
    monkeypatch.setattr(memory, "CONTEXT",
                         type("FakeCtx", (), {"parse": staticmethod(lambda fh: _FakeContext(rip=0xdead))}))

    mf = open_dump(path)

    assert mf.threads.threads[0].ContextObject.Rip == 0xdead


def test_thread_context_partial_failure_keeps_earlier_results(tmp_path, dispatch_patch, monkeypatch):
    # Reproduces MinidumpFile.__parse_thread_context()'s own partial-
    # failure guard: the loop is inside ONE try/except, so a later
    # thread's failure must not undo an earlier thread's already-assigned
    # ContextObject.
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream,
                              MINIDUMP_STREAM_TYPE.ThreadListStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream,
                    lambda d, fh: _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64))
    threads = [_FakeThread(teb=0x1000), _FakeThread(teb=0x2000)]
    dispatch_patch(MINIDUMP_STREAM_TYPE.ThreadListStream, lambda d, fh: _StreamList(threads=threads))

    calls = {"n": 0}

    def fake_parse(fh):
        calls["n"] += 1
        if calls["n"] == 2:
            raise Exception("bad context rva")
        return _FakeContext(rip=0x1111)

    monkeypatch.setattr(memory, "CONTEXT", type("FakeCtx", (), {"parse": staticmethod(fake_parse)}))

    mf = open_dump(path)   # must not raise

    assert mf.threads.threads[0].ContextObject.Rip == 0x1111
    assert getattr(mf.threads.threads[1], "ContextObject", None) is None


def test_thread_contexts_skipped_when_sysinfo_absent(tmp_path, dispatch_patch, monkeypatch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.ThreadListStream])
    thread = _FakeThread(teb=0x1000)
    dispatch_patch(MINIDUMP_STREAM_TYPE.ThreadListStream, lambda d, fh: _StreamList(threads=[thread]))
    parse_called = {"called": False}

    def fake_parse(fh):
        parse_called["called"] = True
        return _FakeContext(rip=1)

    monkeypatch.setattr(memory, "CONTEXT", type("FakeCtx", (), {"parse": staticmethod(fake_parse)}))

    mf = open_dump(path)

    assert mf.sysinfo is None
    assert parse_called["called"] is False
    assert getattr(mf.threads.threads[0], "ContextObject", None) is None


# ── Phase 3b: PEB (same precondition, same swallow) ───────────────────────

def test_peb_populated_when_sysinfo_and_threads_present(tmp_path, dispatch_patch, monkeypatch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream,
                              MINIDUMP_STREAM_TYPE.ThreadListStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream,
                    lambda d, fh: _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64))
    dispatch_patch(MINIDUMP_STREAM_TYPE.ThreadListStream,
                    lambda d, fh: _StreamList(threads=[_FakeThread(teb=0x1000)]))

    fake_peb = object()
    monkeypatch.setattr(memory.PEB, "from_minidump", staticmethod(lambda mf: fake_peb))

    mf = open_dump(path)

    assert mf.peb is fake_peb


def test_peb_exception_is_swallowed_leaving_peb_none(tmp_path, dispatch_patch, monkeypatch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream,
                              MINIDUMP_STREAM_TYPE.ThreadListStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream,
                    lambda d, fh: _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64))
    dispatch_patch(MINIDUMP_STREAM_TYPE.ThreadListStream,
                    lambda d, fh: _StreamList(threads=[_FakeThread(teb=0x1000)]))

    def boom(mf):
        raise Exception("malformed environment block")

    monkeypatch.setattr(memory.PEB, "from_minidump", staticmethod(boom))

    mf = open_dump(path)   # must not raise

    assert mf.peb is None


def test_peb_not_attempted_when_threads_absent(tmp_path, dispatch_patch, monkeypatch):
    path = _write(tmp_path, [MINIDUMP_STREAM_TYPE.SystemInfoStream])
    dispatch_patch(MINIDUMP_STREAM_TYPE.SystemInfoStream,
                    lambda d, fh: _StreamList(ProcessorArchitecture=PROCESSOR_ARCHITECTURE.AMD64))
    called = {"n": 0}

    def track(mf):
        called["n"] += 1
        return object()

    monkeypatch.setattr(memory.PEB, "from_minidump", staticmethod(track))

    mf = open_dump(path)

    assert mf.peb is None
    assert called["n"] == 0
