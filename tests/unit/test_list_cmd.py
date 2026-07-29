"""Unit tests for dumpex.commands.list_cmd's collect/render split."""
from tests.fixtures.fakes import Region, FakeStream, FakeMF

from dumpex.commands.list_cmd import collect_regions, render_regions_console, cmd_list


def test_collect_regions_normal():
    mf = FakeMF()
    mf.memory_info = FakeStream([
        Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED"),
    ], "infos")
    records, status, reasons = collect_regions(mf)
    assert status == "complete"
    assert reasons == []
    assert len(records) == 2
    assert records[0].base_address == "0x0000000000001000"
    assert records[0].size == 0x2000
    assert records[0].suspicious is True    # PAGE_EXECUTE_READWRITE
    assert records[1].suspicious is False   # PAGE_READONLY


def test_collect_regions_present_but_empty_stream_is_complete():
    mf = FakeMF()
    mf.memory_info = FakeStream([], "infos")   # stream present, genuinely zero regions
    records, status, reasons = collect_regions(mf)
    assert records == []
    assert status == "complete"
    assert reasons == []


def test_collect_regions_missing_stream_is_not_evaluated():
    # MemoryInfoListStream entirely absent must not be indistinguishable
    # from "present, zero regions" -- see the P1 review fix.
    records, status, reasons = collect_regions(FakeMF())
    assert records == []
    assert status == "not_evaluated"
    assert reasons == ["MemoryInfoListStream not present in this dump"]


def test_collect_regions_filter_by_protection():
    mf = FakeMF()
    mf.memory_info = FakeStream([
        Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED"),
    ], "infos")
    records, status, reasons = collect_regions(mf, filter_prot="READONLY")
    assert len(records) == 1
    assert records[0].protect == "PAGE_READONLY"


def test_render_regions_console_does_not_crash(capsys):
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    records, _, _ = collect_regions(mf)
    render_regions_console(records)
    out = capsys.readouterr().out
    assert "0x0000000000001000" in out
    assert "1 region(s) shown" in out


def test_cmd_list_returns_same_tuple_as_collect(capsys):
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    records, status, reasons = cmd_list(mf)
    assert len(records) == 1
    assert status == "complete"
    capsys.readouterr()   # drain console output, not asserted here
