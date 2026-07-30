"""Unit tests for dumpex.commands.peb's collect/render split.

collect_peb() returns a dumpex.output.command_result.CommandResult
(migrated onto the shared coverage core in dumpex.output.coverage --
see that module and dumpex.output.command_result); accessed via
attributes, never unpacked as a tuple. peb_present -- extra rendering
context this command needs -- is derived via peb_is_present() rather
than returned separately."""
from tests.fixtures.fakes import Peb, FakeMF

from dumpex.commands.peb import collect_peb, render_peb_console, cmd_peb, peb_is_present
from dumpex.output.coverage import LimitationCode


def test_collect_peb_normal_is_complete():
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe", address=0x7ffd0000, being_debugged=False,
                 command_line="test.exe", window_title="Test", dll_path=r"C:\dlls",
                 current_directory=r"C:\\", standard_input=3, standard_output=7,
                 standard_error=11,
                 environment_variables=[{"name": "PATH", "value": r"C:\Windows"}])
    result = collect_peb(mf)
    assert result.coverage.status == "complete"
    assert peb_is_present(result.coverage) is True
    rec = result.records[0]
    assert rec.peb_address == "0x000000007ffd0000"
    assert rec.image_base_address == "0x0000000140000000"
    assert rec.being_debugged is False
    assert rec.standard_input == "0x0000000000000003"
    assert rec.environment_variables == [{"name": "PATH", "value": r"C:\Windows"}]
    assert result.summary == {"count": 1}


def test_collect_peb_missing_is_not_evaluated_all_fields_none():
    # --peb has exactly one data source; when it's absent there is
    # nothing to report at all, not merely an incomplete subset.
    result = collect_peb(FakeMF())
    assert result.coverage.status == "not_evaluated"
    assert peb_is_present(result.coverage) is False
    assert result.coverage.reasons == [
        "PEB could not be parsed (missing sysinfo or thread list in dump)"]
    rec = result.records[0]
    for value in rec.to_dict().values():
        assert value is None

    # Dedicated code, not the generic single-source SOURCE_ABSENT default
    # -- PEB's existing wording doesn't fit "PEB not present in this dump".
    limitation = result.coverage.limitations[0]
    assert limitation.code == LimitationCode.PEB_UNAVAILABLE
    assert limitation.source == "peb"


def test_collect_peb_no_environment_variables_stays_none():
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    result = collect_peb(mf)
    assert result.records[0].environment_variables is None


def test_render_peb_console_normal_does_not_crash(capsys):
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe",
                 environment_variables=[{"name": "PATH", "value": "C:\\"}])
    result = collect_peb(mf)
    render_peb_console(result.records[0], peb_is_present(result.coverage))
    out = capsys.readouterr().out
    assert "PEB" in out
    assert "PATH=C:\\" in out


def test_render_peb_console_missing_prints_error_line(capsys):
    result = collect_peb(FakeMF())
    render_peb_console(result.records[0], peb_is_present(result.coverage))
    out = capsys.readouterr().out
    assert "PEB could not be parsed" in out


def test_cmd_peb_returns_command_result(capsys):
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    result = cmd_peb(mf)
    assert len(result.records) == 1
    assert result.coverage.status == "complete"
    capsys.readouterr()
