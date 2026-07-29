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

def test_collect_pid_via_misc_info_is_complete():
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=4321)
    records, status, reasons = collect_pid(mf)
    assert status == "complete"
    assert reasons == []
    rec = records[0]
    assert rec.pid == 4321
    assert rec.source == "MINIDUMP_MISC_INFO (ProcessId field)"


def test_collect_pid_fallback_to_thread_list_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0)), Thread(10, Ctx(0))], "threads")
    records, status, reasons = collect_pid(mf)
    assert status == "partial"
    assert reasons
    assert "thread list" in reasons[0]
    rec = records[0]
    assert rec.pid is None
    assert rec.thread_count == 2


def test_collect_pid_fallback_to_exception_stream():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
    mf.exception = ExceptionStream(9)
    records, status, reasons = collect_pid(mf)
    assert status == "partial"
    assert len(reasons) == 2   # thread-list warning + exception-stream warning
    assert records[0].exc_tid == 9
    assert isinstance(records[0].exc_tid, int)


def test_collect_pid_nothing_available():
    records, status, reasons = collect_pid(FakeMF())
    assert status == "partial"
    assert reasons == []
    rec = records[0]
    assert rec.pid is None
    assert rec.thread_count == 0


def test_render_pid_console_no_pid_no_warnings(capsys):
    records, status, reasons = collect_pid(FakeMF())
    render_pid_console(records[0], reasons)
    out = capsys.readouterr().out
    assert "Could not determine PID" in out


def test_cmd_pid_returns_three_tuple(capsys):
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=100)
    records, status, reasons = cmd_pid(mf)
    assert records[0].pid == 100
    assert status == "complete"
    capsys.readouterr()
