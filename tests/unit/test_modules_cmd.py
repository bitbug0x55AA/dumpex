"""Unit tests for dumpex.commands.modules's collect/render split.

collect_modules() returns a dumpex.output.command_result.CommandResult
(migrated onto the shared coverage core in dumpex.output.coverage --
see that module and dumpex.output.command_result); accessed via
attributes, never unpacked as a tuple.
"""
from tests.fixtures.fakes import Module, FakeStream, FakeMF

from dumpex.commands.modules import collect_modules, render_modules_console, cmd_modules


def test_collect_modules_normal():
    mf = FakeMF()
    mf.modules = FakeStream(
        [Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")], "modules")
    result = collect_modules(mf)
    assert result.kind == "modules"
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.name == "ntdll.dll"
    assert rec.full_path == r"C:\Windows\System32\ntdll.dll"
    assert rec.base_address == "0x0000000140000000"
    assert rec.end_address == "0x0000000140005000"
    assert rec.size == 0x5000
    assert isinstance(rec.size, int)
    assert rec.checksum is None   # Module fixture doesn't set a checksum
    assert rec.anomaly_flags == []
    assert result.summary == {"count": 1}


def test_collect_modules_present_but_empty_stream_is_complete():
    mf = FakeMF()
    mf.modules = FakeStream([], "modules")   # stream present, genuinely zero modules
    result = collect_modules(mf)
    assert result.records == []
    assert result.coverage.status == "complete"


def test_collect_modules_missing_stream_is_not_evaluated():
    # ModuleListStream entirely absent must not be indistinguishable from
    # "present, zero modules" -- see the P1 review fix.
    result = collect_modules(FakeMF())
    assert result.records == []
    assert result.coverage.status == "not_evaluated"
    assert result.coverage.reasons == ["ModuleListStream not present in this dump"]
    assert result.coverage.sources["modules"].state == "absent"


def test_collect_modules_no_name_flagged_as_anomaly():
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x140000000, 0x1000, "")], "modules")
    result = collect_modules(mf)
    assert result.records[0].anomaly_flags == ["NO_NAME"]
    assert result.records[0].full_path is None


def test_collect_modules_sorted_by_base_address():
    mf = FakeMF()
    mf.modules = FakeStream([
        Module(0x150000000, 0x1000, "b.dll"),
        Module(0x140000000, 0x1000, "a.dll"),
    ], "modules")
    result = collect_modules(mf)
    assert [r.name for r in result.records] == ["a.dll", "b.dll"]


def test_render_modules_console_does_not_crash(capsys):
    mf = FakeMF()
    mf.modules = FakeStream(
        [Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")], "modules")
    result = collect_modules(mf)
    render_modules_console(result.records)
    out = capsys.readouterr().out
    assert "ntdll.dll" in out
    assert "1 module(s)" in out


def test_render_modules_console_present_empty_does_not_crash(capsys):
    mf = FakeMF()
    mf.modules = FakeStream([], "modules")   # stream present, genuinely zero modules
    result = collect_modules(mf)
    render_modules_console(result.records)
    out = capsys.readouterr().out
    assert "0 module(s)" in out


def test_cmd_modules_returns_command_result(capsys):
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    result = cmd_modules(mf)
    assert len(result.records) == 1
    assert result.coverage.status == "complete"
    capsys.readouterr()
