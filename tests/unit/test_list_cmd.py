"""Unit tests for dumpex.commands.list_cmd's collect/render split.

collect_regions() returns a dumpex.output.command_result.CommandResult
(migrated onto the shared coverage core in dumpex.output.coverage --
see that module and dumpex.output.command_result); accessed via
attributes (result.records / result.coverage.status /
result.coverage.reasons), never unpacked as a tuple.
"""
from tests.fixtures.fakes import Region, FakeStream, FakeMF

from dumpex.commands.list_cmd import collect_regions, render_regions_console, cmd_list


def test_collect_regions_normal():
    mf = FakeMF()
    mf.memory_info = FakeStream([
        Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED"),
    ], "infos")
    result = collect_regions(mf)
    assert result.kind == "memory_regions"
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []
    assert len(result.records) == 2
    assert result.records[0].base_address == "0x0000000000001000"
    assert result.records[0].size == 0x2000
    assert result.records[0].suspicious is True    # PAGE_EXECUTE_READWRITE
    assert result.records[1].suspicious is False   # PAGE_READONLY
    assert result.summary == {"count": 2}


def test_collect_regions_present_but_empty_stream_is_complete():
    mf = FakeMF()
    mf.memory_info = FakeStream([], "infos")   # stream present, genuinely zero regions
    result = collect_regions(mf)
    assert result.records == []
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []


def test_collect_regions_missing_stream_is_not_evaluated():
    # MemoryInfoListStream entirely absent must not be indistinguishable
    # from "present, zero regions" -- see the P1 review fix.
    result = collect_regions(FakeMF())
    assert result.records == []
    assert result.coverage.status == "not_evaluated"
    assert result.coverage.reasons == ["MemoryInfoListStream not present in this dump"]
    assert result.coverage.sources["memory_info"].state == "absent"


def test_collect_regions_filter_by_protection():
    mf = FakeMF()
    mf.memory_info = FakeStream([
        Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED"),
    ], "infos")
    result = collect_regions(mf, filter_prot="READONLY")
    assert len(result.records) == 1
    assert result.records[0].protect == "PAGE_READONLY"
    # filtering narrows records but is not itself a coverage gap
    assert result.coverage.status == "complete"


def test_render_regions_console_does_not_crash(capsys):
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    result = collect_regions(mf)
    render_regions_console(result.records)
    out = capsys.readouterr().out
    assert "0x0000000000001000" in out
    assert "1 region(s) shown" in out


def test_render_regions_console_present_empty_does_not_crash(capsys):
    mf = FakeMF()
    mf.memory_info = FakeStream([], "infos")   # stream present, genuinely zero regions
    result = collect_regions(mf)
    render_regions_console(result.records)
    out = capsys.readouterr().out
    assert "0 region(s) shown" in out


def test_cmd_list_returns_command_result(capsys):
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    result = cmd_list(mf)
    assert len(result.records) == 1
    assert result.coverage.status == "complete"
    capsys.readouterr()   # drain console output, not asserted here
