"""Unit tests for dumpex.commands.peb's collect/render split."""
from tests.fixtures.fakes import Peb, FakeMF

from dumpex.commands.peb import collect_peb, render_peb_console, cmd_peb


def test_collect_peb_normal_is_complete():
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe", address=0x7ffd0000, being_debugged=False,
                 command_line="test.exe", window_title="Test", dll_path=r"C:\dlls",
                 current_directory=r"C:\\", standard_input=3, standard_output=7,
                 standard_error=11,
                 environment_variables=[{"name": "PATH", "value": r"C:\Windows"}])
    records, status, reasons, present = collect_peb(mf)
    assert status == "complete"
    assert present is True
    rec = records[0]
    assert rec.peb_address == "0x000000007ffd0000"
    assert rec.image_base_address == "0x0000000140000000"
    assert rec.being_debugged is False
    assert rec.standard_input == "0x0000000000000003"
    assert rec.environment_variables == [{"name": "PATH", "value": r"C:\Windows"}]


def test_collect_peb_missing_is_not_evaluated_all_fields_none():
    # --peb has exactly one data source; when it's absent there is
    # nothing to report at all, not merely an incomplete subset.
    records, status, reasons, present = collect_peb(FakeMF())
    assert status == "not_evaluated"
    assert present is False
    assert reasons == ["PEB could not be parsed (missing sysinfo or thread list in dump)"]
    rec = records[0]
    for value in rec.to_dict().values():
        assert value is None


def test_collect_peb_no_environment_variables_stays_none():
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    records, status, reasons, present = collect_peb(mf)
    assert records[0].environment_variables is None


def test_render_peb_console_normal_does_not_crash(capsys):
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe",
                 environment_variables=[{"name": "PATH", "value": "C:\\"}])
    records, status, reasons, present = collect_peb(mf)
    render_peb_console(records[0], present)
    out = capsys.readouterr().out
    assert "PEB" in out
    assert "PATH=C:\\" in out


def test_render_peb_console_missing_prints_error_line(capsys):
    records, status, reasons, present = collect_peb(FakeMF())
    render_peb_console(records[0], present)
    out = capsys.readouterr().out
    assert "PEB could not be parsed" in out


def test_cmd_peb_returns_three_tuple(capsys):
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    records, status, reasons = cmd_peb(mf)
    assert len(records) == 1
    assert status == "complete"
    capsys.readouterr()
