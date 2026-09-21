"""Unit tests for dumpex.commands.report's --report collect/render split
(Phase E, PR3). collect_report() returns a dumpex.output.command_result.
CommandResult -- accessed via attributes, never unpacked as a tuple.

Patches read_region in BOTH dumpex.commands.report AND dumpex.core.memory:
_search_string_in_memory (used by string-search mode) lives in core.memory
and calls its own module-global read_region, which a patch on report_mod
alone would not reach.
"""
import pytest

from tests.fixtures.fakes import (
    FakeMF, FakeStream, Module, Region, ThreadInfo, mem_reader, build_pe_header,
    TEXT_SECTION_RX,
)

# A minimal, structurally-valid PE32+ header (one executable .text section)
# for tests that need parse_pe_header() to actually confirm a candidate --
# a bare 'MZ' prefix (the pre-fix behavior this replaces) is no longer
# enough to assert has_injected_pe=True; see
# test_mz_bytes_alone_without_a_structurally_valid_pe_is_not_injected_pe.
_VALID_PE_BYTES = build_pe_header([TEXT_SECTION_RX])

# The same header, but with its one section declared read-only (no
# IMAGE_SCN_MEM_EXECUTE) -- a resource-only PE has no executable section at
# all.
_RESOURCE_ONLY_PE_BYTES = build_pe_header([{
    "name": b".rsrc", "vaddr": 0x1000, "vsize": 0x2000,
    "rawptr": 0x400, "rawsize": 0x2000, "chars": 0x40000000,  # READ only
}])

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
                read_map={0x7000: _VALID_PE_BYTES})
    result = collect_report(mf, report_addr="0x7000")
    card = result.records[0]
    assert set(card.findings) == {"rwx_private", "injected_pe"}
    assert card.region.has_injected_pe is True
    assert card.verdict == VERDICT_LIKELY_MALICIOUS


def test_all_three_region_and_string_dims_combine_to_high_confidence(monkeypatch):
    ioc_data = _VALID_PE_BYTES + b"cmd.exe /c powershell -enc ZZZZZZZZZZZZZZZZZZ" + b"\x00" * 20
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
    assert result.summary["hits_mapped"] == 0
    assert result.summary["hits_unregistered_image"] == 0
    assert result.summary["hits_image_registration_unavailable"] == 0
    assert result.summary["hits_region_type_unavailable"] == 0
    assert result.summary["hits_image"] == 0


def test_string_mode_summary_breaks_hits_private_down_by_actual_region_type(monkeypatch):
    # hits_private is grouping/actionability shorthand ("no resolved image
    # module owns this hit"), not a memory-type claim -- it lumps together
    # genuine MEM_PRIVATE hits, MEM_MAPPED hits, and MEM_IMAGE hits no
    # module covers. A consumer reading only the summary (not each card)
    # must still be able to tell those apart, and every hit that gets
    # grouped in must still get its own card regardless of its actual type.
    needle = "MULTITYPEHIT2024"
    mf = _mk_mf(monkeypatch,
                modules=[Module(0xb000, 0x1000, r"C:\Windows\System32\kernel32.dll")],
                regions=[
                    Region(0xb000, 0xb000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
                    Region(0xc000, 0xc000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
                    Region(0xd000, 0xd000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED"),
                    Region(0xe000, 0xe000, 0x1000, "MEM_COMMIT",
                           "PAGE_EXECUTE_READWRITE", "MEM_IMAGE"),
                ],
                read_map={addr: f"header {needle} trailer".encode() + b"\x00" * 20
                          for addr in (0xb000, 0xc000, 0xd000, 0xe000)})
    result = collect_report(mf, report_string=needle)

    assert result.summary["total_hits"] == 4
    assert result.summary["hits_image"] == 1
    assert result.summary["hits_private"] == 3
    assert result.summary["hits_mapped"] == 1
    assert result.summary["hits_unregistered_image"] == 1
    assert result.summary["hits_image_registration_unavailable"] == 0
    assert result.summary["hits_region_type_unavailable"] == 0
    # hits_private minus all four breakdown fields is the genuine
    # MEM_PRIVATE remainder -- exactly 1 here (the 0xc000 hit).
    assert (result.summary["hits_private"] - result.summary["hits_mapped"]
            - result.summary["hits_unregistered_image"]
            - result.summary["hits_image_registration_unavailable"]
            - result.summary["hits_region_type_unavailable"]) == 1

    # Every non-image hit still gets its own card -- the breakdown is
    # purely additional classification, never a filter.
    assert result.summary["card_count"] == 3
    region_types = sorted(card.region.type for card in result.records)
    assert region_types == ["MEM_IMAGE", "MEM_MAPPED", "MEM_PRIVATE"]
    mapped_card = next(c for c in result.records if c.region.type == "MEM_MAPPED")
    assert mapped_card.anchor_pe_context.classification == "mapped"
    unregistered_image_card = next(c for c in result.records if c.region.type == "MEM_IMAGE")
    assert unregistered_image_card.anchor_pe_context.classification == "unregistered_image"


def test_string_mode_unresolved_region_type_is_not_counted_as_confirmed_private(monkeypatch):
    # A committed region whose own Type could not be parsed (the minidump
    # dependency leaves it None on an unrecognized value) must not be
    # silently folded into "confirmed MEM_PRIVATE" just because it is
    # neither MEM_MAPPED nor MEM_IMAGE -- hits_region_type_unavailable
    # names the gap explicitly, so hits_private minus every breakdown
    # field stays an honest count of ACTUALLY-confirmed MEM_PRIVATE hits.
    needle = "UNKNOWNTYPEHIT2024"
    addr = 0xf000
    region = Region(addr, addr, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
    region.Type = None   # simulates an unparseable/unrecognized Type value
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[region],
                read_map={addr: f"header {needle} trailer".encode() + b"\x00" * 20})
    result = collect_report(mf, report_string=needle)

    assert result.summary["total_hits"] == 1
    assert result.summary["hits_private"] == 1
    assert result.summary["hits_mapped"] == 0
    assert result.summary["hits_unregistered_image"] == 0
    assert result.summary["hits_region_type_unavailable"] == 1
    # Nothing here is confirmed MEM_PRIVATE -- the remainder must be 0.
    assert (result.summary["hits_private"] - result.summary["hits_mapped"]
            - result.summary["hits_unregistered_image"]
            - result.summary["hits_image_registration_unavailable"]
            - result.summary["hits_region_type_unavailable"]) == 0
    # The card itself is still produced -- the fix corrects the summary
    # count, not the card retention.
    assert result.summary["card_count"] == 1
    assert result.records[0].region.type == "None"
    assert result.records[0].anchor_pe_context.classification == "region_type_unavailable"


def test_string_mode_image_hit_registration_state_matches_across_summary_and_card(monkeypatch):
    # The four module-list states a MEM_IMAGE string hit can land in --
    # entirely absent, present-but-empty, present-but-non-covering, and
    # present-with-a-covering-module -- must agree between the per-card
    # anchor_pe_context.classification/registration and the summary-only
    # hits_unregistered_image/hits_image_registration_unavailable
    # counters. A summary consumer reading hits_unregistered_image alone
    # must never see the stronger "confirmed unregistered" claim for a run
    # that never actually checked (module list absent).
    needle = "IMGREGSTATE2024"
    addr = 0xf100

    def _run(modules):
        mf = _mk_mf(monkeypatch, modules=modules,
                    regions=[Region(addr, addr, 0x1000, "MEM_COMMIT",
                                    "PAGE_EXECUTE_READWRITE", "MEM_IMAGE")],
                    read_map={addr: f"header {needle} trailer".encode() + b"\x00" * 20})
        return collect_report(mf, report_string=needle)

    # ModuleListStream entirely absent -- registration never checked.
    result = _run(modules=None)
    assert result.summary["hits_unregistered_image"] == 0
    assert result.summary["hits_image_registration_unavailable"] == 1
    card = result.records[0]
    assert card.anchor_pe_context.classification == "image_registration_unavailable"
    assert card.anchor_pe_context.registration == "unavailable"

    # ModuleListStream present but empty -- a CHECKED negative.
    result = _run(modules=[])
    assert result.summary["hits_unregistered_image"] == 1
    assert result.summary["hits_image_registration_unavailable"] == 0
    card = result.records[0]
    assert card.anchor_pe_context.classification == "unregistered_image"
    assert card.anchor_pe_context.registration == "unregistered"

    # ModuleListStream present, non-empty, but does not cover this address.
    result = _run(modules=[Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")])
    assert result.summary["hits_unregistered_image"] == 1
    assert result.summary["hits_image_registration_unavailable"] == 0
    card = result.records[0]
    assert card.anchor_pe_context.classification == "unregistered_image"
    assert card.anchor_pe_context.registration == "unregistered"

    # ModuleListStream present and covers this exact address -- a real
    # image hit, not a "no module owns this" case at all.
    result = _run(modules=[Module(addr, 0x1000, r"C:\Windows\System32\kernel32.dll")])
    assert result.summary["hits_image"] == 1
    assert result.summary["hits_private"] == 0
    assert result.records == []


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
                read_map={0x7100: _VALID_PE_BYTES})
    result = collect_report(mf, report_addr="0x7100")
    card = result.records[0]
    assert card.region.module_context == MODULE_CONTEXT_UNREGISTERED
    assert card.region.has_injected_pe is True
    assert card.region.pe_header_state == "ok"
    assert card.findings == ["injected_pe"]


# ── domain correction: registration alone never implies private memory ───

def test_scan_content_range_requires_region_type_and_protect(monkeypatch):
    # A caller that omits the region's own type/protection facts must be
    # refused outright -- not silently produce a wrong has_injected_pe=False,
    # which is exactly the false-negative shape an omitted keyword would
    # otherwise create.
    mf = _mk_mf(monkeypatch, read_map={0x1000: _VALID_PE_BYTES})
    with pytest.raises(TypeError):
        report_mod._scan_content_range(
            mf, base_address=0x1000, requested_size=0x1000, min_len=4,
            module_context=MODULE_CONTEXT_UNREGISTERED)


def test_mz_bytes_alone_without_a_structurally_valid_pe_is_not_injected_pe(monkeypatch):
    # A bare 'MZ' prefix with no real PE structure behind it (e_lfanew
    # doesn't even point at a "PE\0\0" signature) is at most a coincidence,
    # not a confirmed PE -- confirmed-unregistered registration alone must
    # not promote it to a finding.
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7150, 0x7150, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x7150: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7150")
    card = result.records[0]
    assert card.region.module_context == MODULE_CONTEXT_UNREGISTERED
    assert card.region.mz_header_detected is True
    assert card.region.has_injected_pe is False
    assert card.region.pe_header_state == "pe_invalid"
    assert card.findings == []


def test_mz_that_fails_validation_in_unregistered_memory_is_not_silent_on_console(monkeypatch, capsys):
    # has_injected_pe=False here is NOT the same as "nothing to report": an
    # MZ prefix that fails strict validation, in confirmed-unregistered
    # memory, must still surface on the console rather than vanishing
    # while the JSON record still carries mz_header_detected=true.
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7155, 0x7155, 0x1000, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
                read_map={0x7155: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7155")
    assert result.records[0].region.pe_header_state == "pe_invalid"
    render_report_console(result.records, result.coverage, result.diagnostics,
                          result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "failed structural PE validation" in out
    assert "not confirmed as an injected PE" in out
    # Distinct from the "valid but benign mapping" sentence -- see
    # test_valid_resource_only_pe_console_names_the_mapping_not_validation.
    assert "non-private, non-executable mapping" not in out


def test_valid_resource_only_pe_console_names_the_mapping_not_validation(monkeypatch, capsys):
    # pe_header_state == "ok" here -- the header genuinely validated, so
    # the console must say it sits in a benign mapping, never that
    # validation itself failed (the opposite sentence, pinned by
    # test_mz_that_fails_validation_in_unregistered_memory_is_not_silent_on_console).
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7156, 0x7156, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")],
                read_map={0x7156: _RESOURCE_ONLY_PE_BYTES})
    result = collect_report(mf, report_addr="0x7156")
    assert result.records[0].region.pe_header_state == "ok"
    render_report_console(result.records, result.coverage, result.diagnostics,
                          result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "non-private, non-executable mapping" in out
    assert "failed structural PE validation" not in out


def test_valid_resource_only_pe_in_unregistered_mapped_memory_is_not_injected_pe(monkeypatch):
    # A structurally valid PE with no executable section, mapped (not
    # MEM_PRIVATE) and owned by no module -- a resource-only file mapping
    # (e.g. via MapViewOfFile) legitimately has no module-list entry. This
    # must not be reported as injected/private memory: module absence and
    # memory type are independent facts.
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7160, 0x7160, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")],
                read_map={0x7160: _RESOURCE_ONLY_PE_BYTES})
    result = collect_report(mf, report_addr="0x7160")
    card = result.records[0]
    assert card.region.type == "MEM_MAPPED"
    assert card.region.module_context == MODULE_CONTEXT_UNREGISTERED
    assert card.region.mz_header_detected is True
    assert card.region.has_injected_pe is False
    assert card.region.pe_header_state == "ok"
    assert card.findings == []


def test_valid_executable_pe_in_unregistered_mapped_memory_is_still_injected_pe(monkeypatch):
    # Same MEM_MAPPED, unregistered mapping, but this time the LIVE
    # protection actually grants execute access -- executable memory with
    # no owning module is just as suspicious as MEM_PRIVATE, regardless of
    # the underlying page type (mirrors
    # dumpex.hunt.injection.memory_scan.pe_hit_is_context_scoreable's
    # identical MEM_PRIVATE-or-executable-protection test).
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7170, 0x7170, 0x1000, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READ", "MEM_MAPPED")],
                read_map={0x7170: _VALID_PE_BYTES})
    result = collect_report(mf, report_addr="0x7170")
    card = result.records[0]
    assert card.region.type == "MEM_MAPPED"
    assert card.region.has_injected_pe is True
    assert card.region.pe_header_state == "ok"
    assert card.findings == ["injected_pe"]


def test_pe_header_short_capture_leaves_injected_pe_undetermined(monkeypatch):
    # 'MZ' plus a genuine DOS header, but the read came up short of the
    # PE signature/section table -- a capture-length gap, not a structural
    # rejection, so the finding must stay undetermined rather than false.
    # The raw read is ALSO short here (48 of 64 requested bytes -- the
    # region is 64 bytes but read_map only backs 48), so this is the co-
    # firing case: REGION_READ_TRUNCATED (the raw byte count) and
    # REPORT_PE_HEADER_VALIDATION_INCOMPLETE (the downstream structural
    # parse) are independent facts that must both surface, and neither's
    # fixed text may claim the read was "in full" when it plainly was not.
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7180, 0x7180, 64, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x7180: _VALID_PE_BYTES[:48]})
    result = collect_report(mf, report_addr="0x7180")
    card = result.records[0]
    assert card.region.mz_header_detected is True
    assert card.region.has_injected_pe is None
    assert card.region.pe_header_state == "short_read"
    assert card.findings == []
    assert card.string_scan["truncated"] is True
    assert result.coverage.status == CoverageStatus.PARTIAL
    codes = {lim.code.value for lim in result.coverage.limitations}
    assert {"REGION_READ_TRUNCATED", "REPORT_PE_HEADER_VALIDATION_INCOMPLETE"} <= codes
    reasons_text = " ".join(result.coverage.reasons)
    assert "only partially read" in reasons_text
    assert "read in full" not in reasons_text
    assert "region's own extent" not in reasons_text


def test_pe_header_validation_incomplete_with_a_full_region_read_lowers_coverage(monkeypatch):
    # The region is read to completion -- bytes_read == requested_bytes,
    # so string_scan["truncated"] stays False and REGION_READ_TRUNCATED
    # never fires -- but the header's own declared e_lfanew (0x1000) needs
    # 24 more bytes than the region's own 4096-byte extent holds, so
    # parse_pe_header() still cannot settle whether this is an injected
    # PE. A consumer reading only coverage.status/verdict must not see
    # "complete"/"CLEAN" here: the PE check itself never resolved.
    import struct
    data = bytearray(4096)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x1000)
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7190, 0x7190, 4096, "MEM_COMMIT",
                                 "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x7190: bytes(data)})
    result = collect_report(mf, report_addr="0x7190")
    card = result.records[0]
    assert card.string_scan["truncated"] is False
    assert card.region.mz_header_detected is True
    assert card.region.has_injected_pe is None
    assert card.region.pe_header_state == "short_read"
    assert card.findings == []
    assert card.verdict == VERDICT_CLEAN   # never inferred malicious from an unknown
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert any("structural PE parse" in r for r in result.coverage.reasons)
    # The raw read came back FULL here (unlike the short-DOS-header case
    # above) -- REGION_READ_TRUNCATED must NOT also fire, and the
    # structural-parse gap's own text must not name a specific cause that
    # would contradict the other code whenever both eventually do co-occur.
    codes = {lim.code.value for lim in result.coverage.limitations}
    assert "REPORT_PE_HEADER_VALIDATION_INCOMPLETE" in codes
    assert "REGION_READ_TRUNCATED" not in codes
    reasons_text = " ".join(result.coverage.reasons)
    assert "region's own extent" not in reasons_text
    assert "read in full" not in reasons_text


def test_pe_header_short_capture_console_says_undetermined_not_failed_validation(
        monkeypatch, capsys):
    # has_injected_pe is None here (a genuine capture-length gap), not
    # False (a structural rejection) -- the console line must say so
    # distinctly rather than misstating that validation ran and failed.
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7185, 0x7185, 64, "MEM_COMMIT",
                                 "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
                read_map={0x7185: _VALID_PE_BYTES[:48]})
    result = collect_report(mf, report_addr="0x7185")
    render_report_console(result.records, result.coverage, result.diagnostics,
                          result.artifacts, result.summary, mf, min_len=6)
    out = capsys.readouterr().out
    assert "undetermined" in out
    assert "failed structural PE validation" not in out
    assert "not confirmed as an injected PE" not in out


def test_mz_header_in_resolved_module_is_not_injected_pe(monkeypatch):
    mf = _mk_mf(monkeypatch, modules=[Module(0x7200, 0x1000, r"C:\legit.dll")],
                regions=[Region(0x7200, 0x7200, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")],
                read_map={0x7200: b"MZ" + b"\x90" * 62})
    result = collect_report(mf, report_addr="0x7200")
    card = result.records[0]
    assert card.region.module_context == MODULE_CONTEXT_RESOLVED
    assert card.region.has_injected_pe is False
    assert card.region.pe_header_state is None
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


@pytest.mark.parametrize("returned,expected_mz,expected_injected", [
    (b"", None, None),         # 0 bytes -- can't tell either way
    (b"M", None, None),        # 1 byte -- b"M"[:2] != b"MZ", but that's "unknown", not "confirmed absent"
    # Exactly 2 bytes, MZ -- the magic is confirmed, and modules=[] ->
    # confirmed unregistered, but two bytes are nowhere near enough to
    # structurally validate a PE header: a genuine capture-length gap,
    # left undetermined rather than promoted to a finding.
    (b"MZ", True, None),
    (b"XY", False, False),     # exactly 2 bytes, genuinely not MZ -- confirmed absent
])
def test_mz_header_detected_boundary_on_short_reads(monkeypatch, returned, expected_mz, expected_injected):
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x7400, 0x7400, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])

    def _reader(mf_, addr, size):
        return returned
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)

    result = collect_report(mf, report_addr="0x7400")
    card = result.records[0]
    assert card.region.mz_header_detected is expected_mz
    assert card.region.has_injected_pe is expected_injected


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


def test_analysis_bug_after_a_successful_read_propagates_not_swallowed(monkeypatch):
    """_scan_content_range()'s try/except is scoped to ONLY the read_region()
    call (issue #19 Phase 2 review, item 6/round 2). A real programming bug
    in the analysis that runs on the bytes AFTER a successful read (string
    extraction, IOC/MZ pattern matching, ContentScanResult construction)
    must propagate as a real exception -- never get silently relabeled as
    an ordinary string_scan_error/"unreadable" the way a genuine read
    failure is. Monkeypatching _extract_strings_from_data to raise proves
    the try/except no longer wraps that call."""
    mf = _mk_mf(monkeypatch, modules=[], threads=[], regions=[
        Region(0x9150, 0x9150, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        read_map={0x9150: b"perfectly readable bytes"})

    def _broken_extract(data, min_len):
        raise TypeError("simulated programming bug in string extraction")
    monkeypatch.setattr(report_mod, "_extract_strings_from_data", _broken_extract)

    with pytest.raises(TypeError, match="simulated programming bug"):
        collect_report(mf, report_addr="0x9150")


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


# ── RevFix2-P1a: string-search clamp/truncation must not silently read as
#    "exhaustively searched, not found" ────────────────────────────────────

def test_string_search_clamp_produces_false_negative_but_marks_execution_partial(monkeypatch):
    # The review's own repro: MAX_REGION_READ set low, needle placed past
    # that cap -- the search genuinely cannot find it, but must not claim
    # a clean "not found" the same way a truly-absent needle would.
    monkeypatch.setattr(core_memory_mod, "MAX_REGION_READ", 16)
    monkeypatch.setattr(report_mod, "MAX_REGION_READ", 16)
    payload = (b"x" * 100) + b"NEEDLE1234"
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0x1000: payload.ljust(4096, b"\x00")})
    result = collect_report(mf, report_string="NEEDLE1234")
    assert result.records == []
    assert result.summary["total_hits"] == 0
    assert result.summary["clamped_regions"] == 1
    assert result.execution_status == EXECUTION_PARTIAL
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_STRING_NOT_FOUND" in codes
    msg = next(d.message for d in result.diagnostics if d.code == "REPORT_STRING_NOT_FOUND")
    assert "scan was incomplete" in msg


def test_string_search_short_read_lowers_coverage_and_scopes_not_found_message(monkeypatch):
    # A real short read (region not fully backed) is a distinct fact from
    # a policy clamp -- it's an evidence gap, so it must lower
    # coverage.status, not just execution_status.
    def _reader(mf_, addr, size):
        return b"only sixteen by"   # far short of the 4096 requested
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)
    monkeypatch.setattr(report_mod, "read_region", _reader)
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0x2000, 0x2000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])
    result = collect_report(mf, report_string="NEEDLE1234")
    assert result.records == []
    assert result.summary["truncated_regions"] == 1
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert any("only partially read" in r for r in result.coverage.reasons)
    msg = next(d.message for d in result.diagnostics if d.code == "REPORT_STRING_NOT_FOUND")
    assert "scan was incomplete" in msg


def test_string_search_hit_found_despite_other_region_being_clamped(monkeypatch):
    # The clamp/truncation facts must not swallow a genuine hit found in a
    # DIFFERENT, fully-read region -- only the affected region's own
    # coverage/execution signal fires. Region 0x4000 is only 16 bytes --
    # small enough that the needle fits entirely within the same
    # MAX_REGION_READ=16 cap applied to region 0x3000, so THAT region's
    # own read is never actually clamped (requested == its own size).
    monkeypatch.setattr(core_memory_mod, "MAX_REGION_READ", 16)
    monkeypatch.setattr(report_mod, "MAX_REGION_READ", 16)

    def _reader(mf_, addr, size):
        if addr == 0x3000:
            return (b"x" * 100 + b"NEVERFOUND").ljust(size, b"\x00")[:size]   # clamped away
        return b"NEEDLE99".ljust(size, b"\x00")[:size]
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)
    monkeypatch.setattr(report_mod, "read_region", _reader)
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[
                    Region(0x3000, 0x3000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                    Region(0x4000, 0x4000, 16, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
                ])
    result = collect_report(mf, report_string="NEEDLE99")
    assert len(result.records) == 1
    assert result.records[0].anchor_address == "0x0000000000004000"
    assert result.summary["clamped_regions"] == 1


# ── RevFix2-P1b: MZ detection reuses Section 4's own content read ────────

def test_mz_header_detected_when_a_small_separate_peek_would_have_failed(monkeypatch):
    # Before the fix, report.py did an INDEPENDENT small (<=64 byte) read
    # just to peek at the MZ header, separate from Section 4's own larger
    # content read -- a reader that only fails for small requests
    # reproduces exactly the gap the review flagged. After the fix there
    # is only ONE read per region, so this must now succeed.
    def _reader(mf_, addr, size):
        if size <= 64:
            raise RuntimeError("small peek read fails")
        return _VALID_PE_BYTES.ljust(size, b"\x00")
    mf = _mk_mf(monkeypatch, modules=[],
                regions=[Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)
    result = collect_report(mf, report_addr="0x5000")
    card = result.records[0]
    assert card.region.mz_header_detected is True
    assert card.string_scan_error is None
    # modules=[] -> present but empty -> confirmed unregistered, so the
    # tri-state correctly resolves to True here (not stuck at None the
    # way the pre-fix independent small-peek read would have left it).
    assert card.region.has_injected_pe is True
    assert card.findings == ["injected_pe"]


# ── RevFix2-P1c: extract short read must not silently write a partial
#    artifact ────────────────────────────────────────────────────────────

def test_extract_short_read_marks_truncated_diagnostic_and_partial_coverage(monkeypatch, tmp_path):
    def _reader(mf_, addr, size):
        return b"only three"[:3]   # 3 bytes, far short of whatever is requested
    monkeypatch.setattr(report_mod, "read_region", _reader)
    monkeypatch.setattr(core_memory_mod, "read_region", _reader)
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0xb000, 0xb000, 32, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")])
    out_path = str(tmp_path / "out.bin")
    result = collect_report(mf, report_addr="0xb000", extract_to=out_path, force=True)
    card = result.records[0]
    assert card.extract_read_truncated is True
    assert card.artifact_id is not None   # still written, just flagged
    artifact = result.artifacts[0]
    assert artifact.size_bytes == 3
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_EXTRACT_TRUNCATED" in codes
    assert result.coverage.status == CoverageStatus.PARTIAL
    # A short read is an evidence gap (coverage), not a policy clamp or a
    # write failure -- execution_status must stay unaffected by it alone.
    assert result.execution_status == EXECUTION_COMPLETED


def test_extract_full_read_is_not_marked_truncated(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, modules=[], threads=[],
                regions=[Region(0xb100, 0xb100, 8, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
                read_map={0xb100: b"x" * 8})
    out_path = str(tmp_path / "out.bin")
    result = collect_report(mf, report_addr="0xb100", extract_to=out_path, force=True)
    card = result.records[0]
    assert card.extract_read_truncated is False
    assert card.extract_read_clamped is False
    assert result.coverage.status == CoverageStatus.COMPLETE


# ── cmd_report thin wrapper ────────────────────────────────────────────────

def test_cmd_report_returns_command_result_and_prints(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, regions=[])
    result = cmd_report(mf, report_addr="0x1234")
    assert result.kind == "report"
    out = capsys.readouterr().out
    assert "TRIAGE REPORT" in out
    assert "No committed region found" in out
