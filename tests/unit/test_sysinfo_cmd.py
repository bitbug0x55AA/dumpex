"""Unit tests for dumpex.commands.sysinfo's collect/render split
(cmd_sysinfo and cmd_pid)."""
from tests.fixtures.fakes import (
    SysInfo, MiscInfo, ExceptionStream, Peb, Thread, Ctx, Module,
    FakeStream, FakeMF,
)

from dumpex.commands.sysinfo import (
    collect_sysinfo, render_sysinfo_console, cmd_sysinfo,
    collect_pid, render_pid_console, cmd_pid,
)
from dumpex.output.coverage import LimitationCode


# ── --sysinfo ────────────────────────────────────────────────────────────

def test_collect_sysinfo_normal_is_complete():
    mf = FakeMF()
    mf.sysinfo = SysInfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    records, status, reasons, peb_present, threads_present, modules_present = collect_sysinfo(mf)
    assert status == "complete"
    assert reasons == []
    assert peb_present is True
    rec = records[0]
    assert rec.pid == 1234
    assert isinstance(rec.pid, int)
    assert rec.os == "Windows 10"
    assert rec.thread_count == 1
    assert rec.module_count == 1


def test_collect_sysinfo_missing_streams_is_partial():
    records, status, reasons, peb_present, threads_present, modules_present = \
        collect_sysinfo(FakeMF())
    assert status == "partial"
    # sysinfo, misc_info, peb, threads, modules all missing
    assert len(reasons) == 5
    assert peb_present is False
    rec = records[0]
    assert rec.pid is None
    assert rec.os is None
    assert rec.hostname is None   # never "" or "(unknown)"
    assert rec.thread_count is None   # never 0 when the stream itself is absent
    assert rec.module_count is None


def test_collect_sysinfo_windows_11_misdetection_fix():
    mf = FakeMF()
    mf.sysinfo = SysInfo(build_number=22631, operating_system="Windows 10")
    records, *_ = collect_sysinfo(mf)
    assert records[0].os == "Windows 11"


def test_render_sysinfo_console_does_not_crash(capsys):
    mf = FakeMF()
    mf.sysinfo = SysInfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    records, status, reasons, peb_present, threads_present, modules_present = collect_sysinfo(mf)
    render_sysinfo_console(records[0], peb_present, threads_present, modules_present)
    out = capsys.readouterr().out
    assert "SYSTEM INFO" in out
    assert "1234" in out
    assert "Threads in dump" in out


def test_cmd_sysinfo_returns_three_tuple(capsys):
    records, status, reasons = cmd_sysinfo(FakeMF())
    assert len(records) == 1
    assert status == "partial"
    capsys.readouterr()


# ── --pid ──────────────────────────────────────────────────────────────
# collect_pid() returns a dumpex.output.command_result.CommandResult
# (migrated onto the shared coverage core in dumpex.output.coverage);
# accessed via attributes, never unpacked as a tuple.

def test_collect_pid_via_misc_info_is_complete():
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=4321)
    result = collect_pid(mf)
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []
    rec = result.records[0]
    assert rec.pid == 4321
    assert rec.source == "MINIDUMP_MISC_INFO (ProcessId field)"


def test_collect_pid_fallback_to_thread_list_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0)), Thread(10, Ctx(0))], "threads")
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    assert result.coverage.reasons
    assert "thread list" in result.coverage.reasons[0]
    rec = result.records[0]
    assert rec.pid is None
    assert rec.thread_count == 2

    # Structured: the reducer never inferred this -- it's business logic
    # collect_pid itself decided, so it must be a hand-built
    # PID_THREAD_LIST_FALLBACK carrying the raw TIDs, not a free-text blob.
    limitation = result.coverage.limitations[0]
    assert limitation.code == LimitationCode.PID_THREAD_LIST_FALLBACK
    assert limitation.source == "misc_info"
    assert limitation.counterpart_source == "threads"
    assert limitation.related_tids == (9, 10)


def test_collect_pid_fallback_to_exception_stream():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
    mf.exception = ExceptionStream(9)
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    assert len(result.coverage.reasons) == 2   # thread-list warning + exception-stream warning
    assert result.records[0].exc_tid == 9
    assert isinstance(result.records[0].exc_tid, int)

    codes = [l.code for l in result.coverage.limitations]
    assert codes == [LimitationCode.PID_THREAD_LIST_FALLBACK, LimitationCode.PID_EXCEPTION_TID_FALLBACK]
    exc_limitation = result.coverage.limitations[1]
    assert exc_limitation.source == "exception"
    assert exc_limitation.thread_id == 9


def test_collect_pid_nothing_available():
    # None of MiscInfo/thread list/exception stream present at all --
    # nothing to even attempt a fallback with.
    result = collect_pid(FakeMF())
    assert result.coverage.status == "not_evaluated"
    assert result.coverage.reasons and "could not be evaluated" in result.coverage.reasons[0]
    rec = result.records[0]
    assert rec.pid is None
    assert rec.thread_count is None   # never 0 when ThreadListStream itself is absent

    limitation = result.coverage.limitations[0]
    assert limitation.code == LimitationCode.PID_SOURCES_ABSENT


def test_collect_pid_partial_status_never_has_empty_reasons():
    # mf.threads is present as a stream object but reports zero threads,
    # and there's no exception stream -- neither fallback branch appends
    # a warning on its own, so this exercises the safety-net reason.
    mf = FakeMF()
    mf.threads = FakeStream([], "threads")
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    assert result.coverage.reasons   # must never be empty for a non-complete status
    assert result.coverage.limitations[0].code == LimitationCode.PID_NO_USABLE_FALLBACK


def test_collect_pid_threads_present_but_misc_info_absent_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    result = collect_pid(mf)
    assert result.coverage.status == "partial"   # a real (if weaker) source was available
    assert result.records[0].thread_count == 1


def test_render_pid_console_not_evaluated_prints_the_stable_reason(capsys):
    result = collect_pid(FakeMF())
    render_pid_console(result.records[0], result.coverage.reasons)
    out = capsys.readouterr().out
    assert "ProcessId not found" in out
    assert "could not be evaluated" in out


def test_cmd_pid_returns_command_result(capsys):
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=100)
    result = cmd_pid(mf)
    assert result.records[0].pid == 100
    assert result.coverage.status == "complete"
    capsys.readouterr()
