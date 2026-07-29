"""Unit tests for dumpex.commands.threads's collect/render split."""
from tests.fixtures.fakes import ThreadInfo, Thread, Ctx, FakeStream, FakeMF

from dumpex.commands.threads import collect_threads, render_threads_console, cmd_threads


def test_collect_threads_normal_with_thread_info():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    records, status, reasons, degraded, has_times = collect_threads(mf)
    assert status == "complete"
    assert reasons == []
    assert degraded is False
    assert len(records) == 1
    rec = records[0]
    assert rec.tid == 1
    assert isinstance(rec.tid, int)
    assert rec.start_address == "0x000000007ffe0000"


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


def test_collect_threads_empty():
    records, status, reasons, degraded, has_times = collect_threads(FakeMF())
    assert records == []
    assert status == "complete"
    assert degraded is False


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
