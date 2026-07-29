"""Unit tests for dumpex.commands.threads's collect/render split."""
from tests.fixtures.fakes import ThreadInfo, Thread, Ctx, Module, FakeStream, FakeMF

from dumpex.commands.threads import collect_threads, render_threads_console, cmd_threads
from dumpex.output.records import (
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)


def test_collect_threads_normal_with_thread_info():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
    records, status, reasons, degraded, has_times = collect_threads(mf)
    assert status == "complete"
    assert reasons == []
    assert degraded is False
    assert len(records) == 1
    rec = records[0]
    assert rec.tid == 1
    assert isinstance(rec.tid, int)
    assert rec.start_address == "0x000000007ffe0000"
    assert rec.module_context == MODULE_CONTEXT_RESOLVED
    assert rec.backing_module == "legit.dll"


def test_collect_threads_module_list_missing_is_unavailable_not_unregistered():
    # The false-signal bug this fixes: a missing ModuleListStream must
    # never render as a confirmed "not in any module" finding.
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    # no mf.modules at all
    records, status, reasons, degraded, has_times = collect_threads(mf)
    assert status == "partial"
    assert records[0].module_context == MODULE_CONTEXT_UNAVAILABLE
    assert records[0].backing_module is None
    assert any("ModuleListStream" in r for r in reasons)


def test_collect_threads_confirmed_not_in_any_module_is_unregistered():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x140000000, 0x1000, "other.dll")], "modules")  # doesn't cover 0x7ffe0000
    records, status, reasons, degraded, has_times = collect_threads(mf)
    assert status == "complete"   # ModuleListStream WAS available; this is a confirmed answer
    assert records[0].module_context == MODULE_CONTEXT_UNREGISTERED
    assert records[0].backing_module is None


def test_collect_threads_degraded_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info stream
    records, status, reasons, degraded, has_times = collect_threads(mf)
    assert status == "partial"
    assert degraded is True
    assert reasons and "ThreadInfoListStream" in reasons[0]
    assert len(records) == 1
    rec = records[0]
    assert rec.tid == 1
    assert rec.start_address is None
    assert rec.backing_module is None
    assert rec.create_time is None
    assert rec.suspend_count is None   # base ThreadListStream fixture has none set


def test_collect_threads_present_but_empty_streams_is_complete():
    mf = FakeMF()
    mf.threads = FakeStream([], "threads")
    mf.thread_info = FakeStream([], "infos")
    mf.modules = FakeStream([], "modules")
    records, status, reasons, degraded, has_times = collect_threads(mf)
    assert records == []
    assert status == "complete"
    assert degraded is False


def test_collect_threads_neither_stream_present_is_not_evaluated():
    # Neither ThreadListStream nor ThreadInfoListStream present at all --
    # must not be indistinguishable from "complete, zero threads."
    records, status, reasons, degraded, has_times = collect_threads(FakeMF())
    assert records == []
    assert status == "not_evaluated"
    assert reasons == ["Neither ThreadListStream nor ThreadInfoListStream present in this dump"]


def test_render_threads_console_normal_does_not_crash(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    records, status, reasons, degraded, has_times = collect_threads(mf)
    render_threads_console(records, degraded, has_times)
    out = capsys.readouterr().out
    assert "0x1" in out
    assert "1 thread(s)" in out


def test_render_threads_console_degraded_prints_warning_banner(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    records, status, reasons, degraded, has_times = collect_threads(mf)
    render_threads_console(records, degraded, has_times)
    out = capsys.readouterr().out
    assert "ThreadInfoListStream not present" in out
    assert "unavailable" in out


def test_cmd_threads_returns_three_tuple_matching_cli_contract(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    records, status, reasons = cmd_threads(mf)
    assert len(records) == 1
    assert status == "partial"
    capsys.readouterr()
