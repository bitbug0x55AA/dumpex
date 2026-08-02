"""Unit tests for dumpex.commands.report's --report collect/render split
(Phase E, PR3). collect_report() returns a dumpex.output.command_result.
CommandResult -- accessed via attributes, never unpacked as a tuple.

Patches read_region in BOTH dumpex.commands.report AND dumpex.core.memory:
_search_string_in_memory (used by string-search mode) lives in core.memory
and calls its own module-global read_region, which a patch on report_mod
alone would not reach.
"""
import pytest

from tests.fixtures.fakes import FakeMF, FakeStream, Module, Region, ThreadInfo, mem_reader

import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
from dumpex.commands.report import collect_report, cmd_report
from dumpex.output.coverage import SourceState, CoverageStatus, combine_coverage_reports
from dumpex.output.records import (
    TriageCardRecord, ReportThreadInfo, ReportRegionInfo, Diagnostic,
    TRIAGE_ANCHOR_TID, TRIAGE_ANCHOR_ADDRESS, TRIAGE_ANCHOR_STRING_HIT,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)
from dumpex.core.memory import (
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_LIKELY_MALICIOUS, VERDICT_HIGH_CONFIDENCE_MALICIOUS,
)


def _mk_mf(monkeypatch, *, modules=None, threads=None, regions=None, read_map=None,
           filename="test.dmp"):
    mf = FakeMF()
    mf.filename = filename
    if modules is not None:
        mf.modules = FakeStream(modules, "modules")
    if threads is not None:
        mf.thread_info = FakeStream(threads, "infos")
    if regions is not None:
        mf.memory_info = FakeStream(regions, "infos")
    if read_map is not None:
        reader = mem_reader(read_map)
        monkeypatch.setattr(report_mod, "read_region", reader)
        monkeypatch.setattr(core_memory_mod, "read_region", reader)
    return mf


# ── tid/addr mode: happy paths ────────────────────────────────────────────

def test_collect_report_addr_mode_clean_region(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[Module(0x5000, 0x1000, r"C:\ntdll.dll")],
                regions=[Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")],
                read_map={0x5000: b"boring data here nothing to see"})
    result = collect_report(mf, report_addr="0x5000")
    assert result.kind == "report"
    assert len(result.records) == 1
    card = result.records[0]
    assert isinstance(card, TriageCardRecord)
    assert card.anchor_source == TRIAGE_ANCHOR_ADDRESS
    assert card.anchor_address == "0x0000000000005000"
    assert card.thread is None
    assert card.region.module_owner == r"C:\ntdll.dll"
    assert card.region.is_rwx_private is False
    assert card.findings == []
    assert card.verdict == VERDICT_CLEAN
    assert result.coverage.status == CoverageStatus.PARTIAL   # modules/thread_info absent here


def test_collect_report_tid_not_found_produces_diagnostic(monkeypatch):
    mf = _mk_mf(monkeypatch, threads=[ThreadInfo(1, 0x1000)])
    result = collect_report(mf, report_tid="5")
    card = result.records[0]
    assert card.anchor_tid == 5
    assert card.thread is None
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_TID_NOT_FOUND" in codes


def test_collect_report_addr_not_found_produces_diagnostic(monkeypatch):
    mf = _mk_mf(monkeypatch, regions=[])
    result = collect_report(mf, report_addr="0x9999000")
    card = result.records[0]
    assert card.region is None
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_REGION_NOT_FOUND" in codes


# ── MECE dimensions, individually and combined ────────────────────────────

def test_rwx_private_dimension_fires_suspicious(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x6000, 0x6000, 0x1000, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
                read_map={0x6000: b"x" * 32})
    result = collect_report(mf, report_addr="0x6000")
    card = result.records[0]
    assert card.findings == ["rwx_private"]
    assert card.region.is_rwx_private is True
    assert card.region.protection_suspicious is True
    assert card.verdict == VERDICT_SUSPICIOUS


def test_rwx_private_and_injected_pe_dimensions_combine_to_likely_malicious(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7000, 0x7000, 0x1000, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
                read_map={0x7000: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7000")
    card = result.records[0]
    assert set(card.findings) == {"rwx_private", "injected_pe"}
    assert card.region.has_injected_pe is True
    assert card.verdict == VERDICT_LIKELY_MALICIOUS


def test_all_three_region_and_string_dims_combine_to_high_confidence(monkeypatch):
    ioc_data = b"MZ" + b"\x90" * 62 + b"cmd.exe /c powershell -enc ZZZZZZZZZZZZZZZZZZ" + b"\x00" * 20
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x8000, 0x8000, 0x1000, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
                read_map={0x8000: ioc_data})
    result = collect_report(mf, report_addr="0x8000")
    card = result.records[0]
    assert set(card.findings) == {"rwx_private", "injected_pe", "ioc_strings"}
    assert card.verdict == VERDICT_HIGH_CONFIDENCE_MALICIOUS
    assert len(card.ioc_strings) == 1
    assert card.ioc_strings[0]["is_network_pattern"] is False


def test_unbacked_thread_correlated_with_own_start_address(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[], threads=[ThreadInfo(7, 0x2000)],
                regions=[Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x2000: b"\x00" * 64})
    result = collect_report(mf, report_tid="7")
    card = result.records[0]
    assert card.findings == ["unbacked_thread"]
    assert card.thread_region_correlation_excluded is False
    assert card.verdict == VERDICT_SUSPICIOUS


def test_unbacked_thread_not_correlated_with_independent_addr_excluded(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[], threads=[ThreadInfo(7, 0x2000)],
                regions=[Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x5000: b"\x00" * 64})
    result = collect_report(mf, report_tid="7", report_addr="0x5000")
    card = result.records[0]
    assert card.findings == []
    assert card.thread_region_correlation_excluded is True
    assert card.verdict == VERDICT_CLEAN
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_THREAD_NOT_CORRELATED_WITH_REGION" in codes


# ── string-search mode ────────────────────────────────────────────────────

def test_string_mode_zero_hits_produces_no_cards(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x9000, 0x9000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x9000: b"nothing interesting at all here"})
    result = collect_report(mf, report_string="TOTALLYABSENTNEEDLE")
    assert result.records == []
    assert result.summary["card_count"] == 0
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_STRING_NOT_FOUND" in codes


def test_string_mode_one_private_hit_produces_one_card(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0xa000, 0xa000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xa000: b"header MYSECRETNEEDLE12 trailer" + b"\x00" * 20})
    result = collect_report(mf, report_string="MYSECRETNEEDLE12")
    assert len(result.records) == 1
    card = result.records[0]
    assert card.anchor_source == TRIAGE_ANCHOR_STRING_HIT
    assert card.anchor_tid is None
    assert card.string_hit["offset"] == 7
    assert card.string_hit["encoding"] == "ASCII"
    assert result.summary["hits_private"] == 1
    assert result.summary["hits_image"] == 0


def test_string_mode_mixed_image_and_private_hits_only_triages_private(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[Module(0xb000, 0x1000, r"C:\Windows\System32\kernel32.dll")],
                regions=[
                    Region(0xb000, 0xb000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
                    Region(0xc000, 0xc000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ],
                read_map={0xb000: b"header SHAREDNEEDLE9999 trailer" + b"\x00" * 20,
                          0xc000: b"header SHAREDNEEDLE9999 trailer" + b"\x00" * 20})
    result = collect_report(mf, report_string="SHAREDNEEDLE9999")
    assert len(result.records) == 1
    assert result.records[0].anchor_address == "0x000000000000c000"
    assert result.summary["hits_image"] == 1
    assert result.summary["image_hit_modules"] == ["kernel32.dll"]


def test_string_mode_with_report_tid_also_given_is_not_forwarded(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0xa000, 0xa000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xa000: b"header MYSECRETNEEDLE12 trailer" + b"\x00" * 20})
    result = collect_report(mf, report_string="MYSECRETNEEDLE12", report_tid="99")
    card = result.records[0]
    assert card.anchor_tid is None   # never forwarded into string-hit cards
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_TID_NOT_CORRELATED_WITH_STRING_HITS" in codes


def test_string_mode_skipped_unreadable_region_surfaces_diagnostic(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[
                    Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                    Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ])

    def _reader(mf_, addr, size):
        if addr == 0x1000:
            raise RuntimeError("boom")
        return b"header MYSECRETNEEDLE12 trailer" + b"\x00" * 20
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_string="MYSECRETNEEDLE12")
    assert len(result.records) == 1
    assert result.summary["skipped_unreadable_regions"] == 1
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_STRING_SCAN_REGIONS_SKIPPED" in codes


def test_string_mode_multi_hit_extract_disambiguates_filenames(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[
                    Region(0xe000, 0xe000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                    Region(0xf000, 0xf000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ],
                read_map={0xe000: b"header MULTIHITNEEDLE77 trailer" + b"\x00" * 20,
                          0xf000: b"header MULTIHITNEEDLE77 trailer" + b"\x00" * 20})
    out_path = str(tmp_path / "out.bin")
    result = collect_report(mf, report_string="MULTIHITNEEDLE77", extract_to=out_path, force=True)
    assert len(result.records) == 2
    assert len(result.artifacts) == 2
    paths = sorted(a.path for a in result.artifacts)
    assert paths == sorted([
        str(tmp_path / "out_0xe000.bin"), str(tmp_path / "out_0xf000.bin")])
    for p in paths:
        assert __import__("pathlib").Path(p).exists()


# ── coverage: combine_coverage_reports across N cards ────────────────────

def test_string_mode_combines_coverage_across_cards_without_conflict(monkeypatch):
    # Every card reads the SAME mf, so repeated identical SourceObservations
    # across cards must never trigger combine_coverage_reports' conflict
    # rejection (unlike comparison.py's genuinely-independent baseline/target).
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[
                    Region(0xe000, 0xe000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                    Region(0xf000, 0xf000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ],
                read_map={0xe000: b"header MULTIHITNEEDLE77 trailer" + b"\x00" * 20,
                          0xf000: b"header MULTIHITNEEDLE77 trailer" + b"\x00" * 20})
    result = collect_report(mf, report_string="MULTIHITNEEDLE77")
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert "modules" in result.coverage.sources
    assert "memory_info" in result.coverage.sources
    assert "thread_info" in result.coverage.sources


def test_all_three_sources_absent_is_not_evaluated(monkeypatch):
    # No modules=/threads=/regions= given at all -- FakeMF defaults every
    # stream attribute to None, i.e. genuinely ABSENT, not an empty list
    # (which would be PRESENT_EMPTY and stay "partial", not "not_evaluated").
    mf = _mk_mf(monkeypatch)
    result = collect_report(mf, report_addr="0x1234")
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED


# ── module_context vocabulary (resolved/unregistered/unavailable) ────────

def test_module_context_unavailable_when_modules_stream_itself_absent(monkeypatch):
    mf = _mk_mf(monkeypatch, threads=[ThreadInfo(7, 0x2000)])   # no modules= given -> absent stream
    result = collect_report(mf, report_tid="7")
    card = result.records[0]
    assert card.thread.module_context == MODULE_CONTEXT_UNAVAILABLE
    # An unconfirmed absence must never fold into the MECE verdict as if
    # it were a confirmed "not in any module" signal.
    assert card.findings == []


def test_module_context_unregistered_when_modules_present_but_no_match(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[], threads=[ThreadInfo(7, 0x2000)])
    result = collect_report(mf, report_tid="7")
    card = result.records[0]
    assert card.thread.module_context == MODULE_CONTEXT_UNREGISTERED
    assert card.findings == ["unbacked_thread"]


def test_module_context_resolved_carries_module_range(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[Module(0x2000, 0x1000, r"C:\ntdll.dll")],
                threads=[ThreadInfo(7, 0x2000)])
    result = collect_report(mf, report_tid="7")
    card = result.records[0]
    assert card.thread.module_context == MODULE_CONTEXT_RESOLVED
    assert card.thread.backing_module_base == "0x0000000000002000"
    assert card.thread.backing_module_end == "0x0000000000003000"


# ── cmd_report thin wrapper ────────────────────────────────────────────────

def test_cmd_report_returns_command_result_and_prints(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, regions=[])
    result = cmd_report(mf, report_addr="0x1234")
    assert result.kind == "report"
    out = capsys.readouterr().out
    assert "TRIAGE REPORT" in out
    assert "No committed region found" in out
