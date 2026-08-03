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
from dumpex.commands.report import collect_report, cmd_report, render_report_console
from dumpex.output.coverage import (
    SourceState, CoverageStatus, combine_coverage_reports, EXECUTION_COMPLETED, EXECUTION_PARTIAL,
)
from dumpex.output.records import (
    TriageCardRecord, ReportThreadInfo, ReportRegionInfo, ReportIocString, Diagnostic,
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
    assert card.ioc_strings[0].is_network_pattern is False
    assert card.ioc_strings[0].context_hex is None


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


def test_string_mode_skipped_unreadable_region_lowers_coverage(monkeypatch):
    # P1-3 review fix: a skipped-during-search region must show up in
    # coverage.status/reasons (a genuine evidence-completeness gap), not
    # merely as an easy-to-miss diagnostic with no effect on coverage.
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
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert any("skipped 1 region" in r for r in result.coverage.reasons)


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


# ── P1-2: injected_pe false positive when modules absent ─────────────────

def test_mz_header_in_unavailable_module_context_is_not_a_false_positive(monkeypatch):
    # The bug: header[:2] == b'MZ' and not rmod treated "ModuleListStream
    # absent" (rmod always falsy then too) as "confirmed unregistered."
    # No modules= given at all -> modules stream itself absent.
    mf = _mk_mf(monkeypatch,
                regions=[Region(0x7000, 0x7000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x7000: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7000")
    card = result.records[0]
    assert card.region.mz_header_detected is True
    assert card.region.module_context == MODULE_CONTEXT_UNAVAILABLE
    assert card.region.has_injected_pe is None
    assert card.findings == []
    assert card.verdict == VERDICT_CLEAN


def test_mz_header_in_confirmed_unregistered_region_is_injected_pe(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],   # modules PRESENT (empty) -> confirmed unregistered
                regions=[Region(0x7100, 0x7100, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x7100: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7100")
    card = result.records[0]
    assert card.region.module_context == MODULE_CONTEXT_UNREGISTERED
    assert card.region.has_injected_pe is True
    assert card.findings == ["injected_pe"]


def test_mz_header_in_resolved_module_is_not_injected_pe(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[Module(0x7200, 0x1000, r"C:\legit.dll")],
                regions=[Region(0x7200, 0x7200, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")],
                read_map={0x7200: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7200")
    card = result.records[0]
    assert card.region.module_context == MODULE_CONTEXT_RESOLVED
    assert card.region.has_injected_pe is False
    assert card.findings == []


def test_header_read_failure_yields_null_mz_header_detected(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7300, 0x7300, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])

    def _reader(mf_, addr, size):
        raise RuntimeError("region unreadable")
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_addr="0x7300")
    card = result.records[0]
    assert card.region.mz_header_detected is None
    assert card.region.has_injected_pe is None
    assert card.findings == []
    # Section 4's own read fails too (same reader) -- see the P1-3 tests
    # below for the coverage-side consequence of that.
    assert card.string_scan is None
    assert card.string_scan_error == "region unreadable"


def test_other_thread_unbacked_in_region_requires_modules_available(monkeypatch):
    # Section 3's own instance of the same bug class: an other-thread in
    # the resolved region must not be flagged unbacked_thread when
    # modules are simply unavailable, only when confirmed unregistered.
    mf = _mk_mf(monkeypatch, threads=[ThreadInfo(1, 0x8050), ThreadInfo(2, 0x8060)],
                regions=[Region(0x8000, 0x8000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x8000: b"\x00" * 64})
    result = collect_report(mf, report_tid="1")
    card = result.records[0]
    assert card.findings == []
    assert all(t.module_context == MODULE_CONTEXT_UNAVAILABLE for t in card.other_threads_in_region)


# ── P1-3: coverage/execution status matrix ────────────────────────────────

def test_region_read_failure_lowers_coverage_via_aggregate_source_failed(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[], threads=[], regions=[
        Region(0x9100, 0x9100, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])

    def _reader(mf_, addr, size):
        raise RuntimeError("boom")
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_addr="0x9100")
    assert result.records[0].string_scan_error == "boom"
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert any("could not be read" in r for r in result.coverage.reasons)


def test_short_read_sets_truncated_and_lowers_coverage(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[], threads=[], regions=[
        Region(0x9200, 0x9200, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])

    def _reader(mf_, addr, size):
        return b"short"   # far less than the requested 0x1000
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_addr="0x9200")
    card = result.records[0]
    assert card.string_scan["requested_bytes"] == 0x1000
    assert card.string_scan["bytes_read"] == 5
    assert card.string_scan["truncated"] is True
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert any("partially read" in r for r in result.coverage.reasons)


def test_full_read_is_not_truncated_or_clamped(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0xa100, 0xa100, 16, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xa100: b"x" * 16})
    result = collect_report(mf, report_addr="0xa100")
    card = result.records[0]
    assert card.string_scan["clamped"] is False
    assert card.string_scan["truncated"] is False
    assert result.execution_status == EXECUTION_COMPLETED


def test_max_region_read_clamp_sets_execution_partial(monkeypatch):
    monkeypatch.setattr(report_mod, "MAX_REGION_READ", 16)
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0xa200, 0xa200, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xa200: b"x" * 4096})
    result = collect_report(mf, report_addr="0xa200")
    card = result.records[0]
    assert card.string_scan["clamped"] is True
    assert card.string_scan["requested_bytes"] == 16
    assert result.execution_status == EXECUTION_PARTIAL


def test_extract_write_failure_diagnostic_sets_execution_partial(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0xa300, 0xa300, 16, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xa300: b"x" * 16})

    def _raise_write(*a, **kw):
        raise PermissionError("disk full")
    monkeypatch.setattr(report_mod, "write_output_bytes", _raise_write)

    bad_path = str(tmp_path / "out.bin")
    result = collect_report(mf, report_addr="0xa300", extract_to=bad_path)
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_EXTRACT_FAILED" in codes
    assert result.execution_status == EXECUTION_PARTIAL
    assert result.records[0].artifact_id is None


def test_string_mode_aggregates_truncation_across_cards(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[
                    Region(0xb100, 0xb100, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                    Region(0xb200, 0xb200, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ])

    def _reader(mf_, addr, size):
        if addr == 0xb100:
            return b"header MULTINEEDLE55 trailer" + b"\x00" * 20   # full read, has the needle
        return b"x"   # region 2's own Section-4 content read comes up short
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_string="MULTINEEDLE55")
    assert len(result.records) == 1   # only region 1 contains the needle
    assert result.coverage.status == CoverageStatus.PARTIAL


# ── P2-1: renderer must not re-read the dump ──────────────────────────────

def test_renderer_never_calls_read_region_for_network_pattern_context(monkeypatch, capsys):
    net_data = (b"MZ" + b"\x90" * 62
                + b"http://evil.example.com/beacon" + b"\x00" * 20)
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0xc000, 0xc000, 0x1000, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
                read_map={0xc000: net_data})
    result = collect_report(mf, report_addr="0xc000")
    card = result.records[0]
    net_hits = [s for s in card.ioc_strings if s.is_network_pattern]
    assert len(net_hits) == 1
    assert net_hits[0].context_hex is not None

    def _boom(mf_, addr, size):
        raise AssertionError("render must not re-read the dump")
    monkeypatch.setattr(report_mod, "read_region", _boom)
    monkeypatch.setattr(core_memory_mod, "read_region", _boom)

    render_report_console(result.records, result.coverage, result.diagnostics,
                           result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "Network pattern" in out


# ── Console rendering branches (P2-1 purification follow-through) ────────

def test_other_thread_confirmed_unregistered_via_section3_sets_finding(monkeypatch):
    # Positive counterpart to test_other_thread_unbacked_in_region_requires_
    # modules_available: the ANCHOR thread (TID 1, start 0x8000) is itself
    # resolved (backed by a tiny module covering only 0x8000-0x800f), so
    # Section 1 does NOT set unbacked_thread -- the second thread (TID 2,
    # start 0x8060, inside the same memory region but outside the module's
    # own range) is the one Section 3's own branch (line 234, not Section
    # 1's identical-looking one) must catch on its own.
    mf = _mk_mf(monkeypatch, modules=[Module(0x8000, 0x10, r"C:\tiny.dll")],
                threads=[ThreadInfo(1, 0x8000), ThreadInfo(2, 0x8060)],
                regions=[Region(0x8000, 0x8000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x8000: b"\x00" * 64})
    result = collect_report(mf, report_tid="1")
    card = result.records[0]
    assert card.thread.module_context == MODULE_CONTEXT_RESOLVED
    assert card.findings == ["unbacked_thread"]
    other = next(t for t in card.other_threads_in_region if t.tid == 2)
    assert other.module_context == MODULE_CONTEXT_UNREGISTERED


def test_string_mode_read_failure_prints_could_not_read_region(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0xd000, 0xd000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])

    # First read is the memory-wide search itself (must succeed to find the
    # hit and produce a card); the second is that card's own Section 4
    # content read (must fail, to exercise the string_scan_error console
    # branch) -- both request the same size, so a call counter is the only
    # way to tell them apart.
    calls = {"n": 0}
    def _reader(mf_, addr, size):
        calls["n"] += 1
        if calls["n"] == 1:
            return b"header MYSECRETNEEDLE12 trailer" + b"\x00" * 20
        raise RuntimeError("section 4 read failed")
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_string="MYSECRETNEEDLE12")
    render_report_console(result.records, result.coverage, result.diagnostics,
                           result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "Could not read region: section 4 read failed" in out


def test_string_mode_all_hits_image_prints_skip_notice_and_zero_cards(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, modules=[Module(0xb000, 0x1000, r"C:\Windows\System32\kernel32.dll")],
                regions=[Region(0xb000, 0xb000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")],
                read_map={0xb000: b"header SHAREDNEEDLE9999 trailer" + b"\x00" * 20})
    result = collect_report(mf, report_string="SHAREDNEEDLE9999")
    assert result.summary["card_count"] == 0
    render_report_console(result.records, result.coverage, result.diagnostics,
                           result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "hit(s) in known MEM_IMAGE modules (kernel32.dll)" in out
    assert "All hits are in known system modules" in out


def test_string_mode_multi_hit_banner_and_tid_not_carried_notice(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[
                    Region(0xe000, 0xe000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                    Region(0xf000, 0xf000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ],
                read_map={0xe000: b"header MULTIHITNEEDLE77 trailer" + b"\x00" * 20,
                          0xf000: b"header MULTIHITNEEDLE77 trailer" + b"\x00" * 20})
    result = collect_report(mf, report_string="MULTIHITNEEDLE77", report_tid="99")
    render_report_console(result.records, result.coverage, result.diagnostics,
                           result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "Triaging hit 1/2" in out and "Triaging hit 2/2" in out
    assert "--report-tid 0x99 was also given" in out


def test_extract_success_prints_artifact_summary(monkeypatch, capsys, tmp_path):
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0xa400, 0xa400, 16, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xa400: b"x" * 16})
    out_path = str(tmp_path / "out.bin")
    result = cmd_report(mf, report_addr="0xa400", extract_to=out_path, force=True)
    out = capsys.readouterr().out
    assert "Region extracted" in out
    assert result.records[0].artifact_id is not None


# ── cmd_report thin wrapper ────────────────────────────────────────────────

def test_cmd_report_returns_command_result_and_prints(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, regions=[])
    result = cmd_report(mf, report_addr="0x1234")
    assert result.kind == "report"
    out = capsys.readouterr().out
    assert "TRIAGE REPORT" in out
    assert "No committed region found" in out
