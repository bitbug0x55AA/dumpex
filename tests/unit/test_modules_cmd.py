"""Unit tests for dumpex.commands.modules's collect/render split."""
from tests.fixtures.fakes import Module, FakeStream, FakeMF

from dumpex.commands.modules import collect_modules, render_modules_console, cmd_modules


def test_collect_modules_normal():
    mf = FakeMF()
    mf.modules = FakeStream(
        [Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")], "modules")
    records, status, reasons = collect_modules(mf)
    assert status == "complete"
    assert reasons == []
    assert len(records) == 1
    rec = records[0]
    assert rec.name == "ntdll.dll"
    assert rec.full_path == r"C:\Windows\System32\ntdll.dll"
    assert rec.base_address == "0x0000000140000000"
    assert rec.end_address == "0x0000000140005000"
    assert rec.size == 0x5000
    assert isinstance(rec.size, int)
    assert rec.checksum is None   # Module fixture doesn't set a checksum
    assert rec.anomaly_flags == []


def test_collect_modules_empty():
    records, status, reasons = collect_modules(FakeMF())
    assert records == []
    assert status == "complete"


def test_collect_modules_no_name_flagged_as_anomaly():
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x140000000, 0x1000, "")], "modules")
    records, status, reasons = collect_modules(mf)
    assert records[0].anomaly_flags == ["NO_NAME"]
    assert records[0].full_path is None


def test_collect_modules_sorted_by_base_address():
    mf = FakeMF()
    mf.modules = FakeStream([
        Module(0x150000000, 0x1000, "b.dll"),
        Module(0x140000000, 0x1000, "a.dll"),
    ], "modules")
    records, _, _ = collect_modules(mf)
    assert [r.name for r in records] == ["a.dll", "b.dll"]


def test_render_modules_console_does_not_crash(capsys):
    mf = FakeMF()
    mf.modules = FakeStream(
        [Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")], "modules")
    records, _, _ = collect_modules(mf)
    render_modules_console(records)
    out = capsys.readouterr().out
    assert "ntdll.dll" in out
    assert "1 module(s)" in out


def test_cmd_modules_returns_records_status_reasons(capsys):
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    records, status, reasons = cmd_modules(mf)
    assert len(records) == 1
    assert status == "complete"
    capsys.readouterr()
