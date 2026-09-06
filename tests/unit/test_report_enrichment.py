"""Semantics of the `--report` enrichment collectors.

Every test here pins one of the four contracts the enrichment sections
exist to keep: `missing` (nothing evaluated), `partial` (usable but
incomplete evidence), and `complete` with an empty subset (a bounded
evaluation that found no eligible item) stay distinguishable; a retained
subset is bounded, deduplicated, and deterministically ordered; a
selection reason is recorded for every retained item; and nothing any of
them produces reaches a card's findings, verdict, coverage status, or the
exit code.

End-to-end console and JSON projection is
tests/integration/test_report_enrichment_output.py.
"""
from dataclasses import replace

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

import dumpex.commands.report as report_mod
import dumpex.commands.report_enrichment as report_enrichment
from dumpex.commands.report import collect_report
from dumpex.commands.report_enrichment import (
    ENVIRONMENT_ALLOWLIST, MAX_CORRELATED_HANDLES, MAX_EXCEPTION_ENTRIES,
    MAX_IDENTITY_CONFLICTS,
    MAX_EXCEPTION_PARAMETERS, MAX_NEIGHBOR_REGIONS, MAX_REPORT_CARDS,
    MAX_STRING_CONTEXT_ENTRIES,
    collect_allocation_neighborhood, collect_exception_context, collect_process_enrichment,
)
from dumpex.commands.report_enrichment import RegionEvidence
from dumpex.output.records import (
    ENRICHMENT_COMPLETE, ENRICHMENT_MISSING, ENRICHMENT_PARTIAL, ENRICHMENT_TEXT_CAP,
    EnrichmentSection,
)
from tests.fixtures.fakes import (
    BAD_RVA, Ctx, DirectoryEntry, ExceptionListStream, ExceptionRecordDetail, ExceptionStreamEntry,
    FakeMF, FakeStream, HandleStreamDirectory, MiscInfo, Module, Peb, Region, SysInfo,
    Thread, ThreadInfo,
    mem_reader, parsed_handle_stream, wire_environment_walk,
)

REGION_BASE = 0x1000
REGION_SIZE = 0x1000
ANCHOR_TID = 0x11


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _environment_block(*entries) -> bytes:
    return b"".join(_utf16(entry) + b"\x00\x00" for entry in entries) + b"\x00\x00"


def _mf(*, regions=None, handles=None, exception=None, directories=None,
        modules=None, threads=None):
    mf = FakeMF()
    mf.modules = FakeStream(modules if modules is not None else [], "modules")
    mf.thread_info = FakeStream(
        threads if threads is not None else [ThreadInfo(ANCHOR_TID, REGION_BASE)], "infos")
    mf.memory_info = FakeStream(
        regions if regions is not None else [
            Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                   "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")
    mf.handles = handles
    mf.exception = exception
    mf.directories = list(directories) if directories is not None else []
    mf._dumpex_stream_failures = {}
    return mf


def _with_environment(mf, block: bytes):
    sysinfo = SysInfo()
    sysinfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AMD64
    mf.sysinfo = sysinfo
    mf.threads = FakeStream([Thread(ANCHOR_TID, Ctx(0))], "threads")
    wire_environment_walk(mf, block)
    return mf


def _card(monkeypatch, mf, *, data=b"", **kwargs):
    monkeypatch.setattr(report_mod, "read_region", mem_reader({REGION_BASE: data}))
    result = collect_report(mf, report_addr=hex(REGION_BASE), **kwargs)
    return result


def _sections(card):
    return {
        "exception": card.exception_context.section,
        "allocation": card.allocation_neighborhood.section,
        "handle_correlation": card.handle_correlation.section,
    }


# ── EnrichmentSection's own invariants ──────────────────────────────────

def test_a_missing_section_cannot_claim_an_eligible_population():
    """`missing` means nothing was evaluated, so there is nothing for a
    total to count and nothing for a cap to have cut."""
    with pytest.raises(ValueError, match="requires total=None"):
        EnrichmentSection(name="exception", scope="card", status=ENRICHMENT_MISSING,
                          total=0, included=0, cap=4, truncated=False)


def test_a_complete_section_must_know_what_it_selected_from():
    with pytest.raises(ValueError, match="requires a known total"):
        EnrichmentSection(name="exception", scope="card", status=ENRICHMENT_COMPLETE,
                          total=None, included=0, cap=4, truncated=False)


def test_truncation_is_exactly_the_gap_between_eligible_and_kept():
    with pytest.raises(ValueError, match="truncated must equal included < total"):
        EnrichmentSection(name="exception", scope="card", status=ENRICHMENT_COMPLETE,
                          total=4, included=2, cap=4, truncated=False)


def test_a_section_never_keeps_more_than_it_found_eligible():
    with pytest.raises(ValueError, match="included must not exceed total"):
        EnrichmentSection(name="exception", scope="card", status=ENRICHMENT_COMPLETE,
                          total=1, included=2, cap=4, truncated=False)


# ── process-wide scope ──────────────────────────────────────────────────

def test_the_process_enrichment_is_collected_once_and_shared_by_every_card(monkeypatch):
    """--report-string produces one card per private hit; the process
    context is one fact about the dump, so it lives on the summary rather
    than being repeated (and re-collected) per card."""
    regions = [
        Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
               "MEM_PRIVATE"),
        Region(0x9000, 0x9000, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mf = _mf(regions=regions)
    monkeypatch.setattr(report_mod, "read_region",
                        mem_reader({REGION_BASE: b"needle here padding\x00",
                                    0x9000: b"needle here padding\x00"}))
    monkeypatch.setattr("dumpex.core.memory.read_region",
                        mem_reader({REGION_BASE: b"needle here padding\x00",
                                    0x9000: b"needle here padding\x00"}))
    result = collect_report(mf, report_string="needle")

    assert len(result.records) == 2
    assert result.summary["process_enrichment"]["section"]["scope"] == "process"
    for card in result.records:
        for section in _sections(card).values():
            assert section.scope == "card"


def test_environment_publishes_only_allowlisted_names(monkeypatch):
    """The report is a stored, shareable product: it publishes the
    session variables an investigator needs and nothing else. The full
    block stays with --sysinfo."""
    mf = _with_environment(_mf(), _environment_block(
        "COMPUTERNAME=WORKSTATION7",
        "USERNAME=analyst",
        "PATH=C:\\Windows;D:\\SyntheticTools\\bin",
        "APPDATA=D:\\SyntheticApplicationData\\Roaming",
        "SECRET_TOKEN=hunter2"))
    enrichment, _handles = collect_process_enrichment(mf)
    environment = enrichment.environment

    published = {entry.name: entry.value for entry in environment.entries}
    assert published == {"COMPUTERNAME": "WORKSTATION7", "USERNAME": "analyst"}
    assert environment.section.status == ENRICHMENT_COMPLETE
    assert environment.section.total == environment.section.included == 2
    assert environment.section.cap == len(ENVIRONMENT_ALLOWLIST)
    for name in ("PATH", "APPDATA", "SECRET_TOKEN"):
        assert name not in published


def test_an_unreadable_environment_block_is_missing_not_an_empty_session(monkeypatch):
    """No environment evidence and an environment with no allowlisted
    variable are different answers, and only one of them means the
    session context was looked at."""
    enrichment, _handles = collect_process_enrichment(_mf())
    assert enrichment.environment.section.status == ENRICHMENT_MISSING
    assert enrichment.environment.section.total is None
    assert enrichment.environment.entries == ()
    assert enrichment.environment.section.limitations


def test_an_environment_with_no_allowlisted_name_is_complete_and_empty(monkeypatch):
    mf = _with_environment(_mf(), _environment_block("PATH=C:\\Windows", "TMP=C:\\Temp"))
    enrichment, _handles = collect_process_enrichment(mf)
    section = enrichment.environment.section

    assert section.status == ENRICHMENT_COMPLETE
    assert section.total == 0 and section.included == 0
    assert not section.truncated


def test_a_long_environment_value_is_cut_at_the_retained_text_cap(monkeypatch):
    mf = _with_environment(_mf(), _environment_block("COMPUTERNAME=" + "N" * 500))
    enrichment, _handles = collect_process_enrichment(mf)
    entry = enrichment.environment.entries[0]

    assert entry.truncated is True
    assert len(entry.value) == ENRICHMENT_TEXT_CAP


def test_process_evidence_the_record_publishes_is_never_reported_as_missing():
    """`missing` means nothing was evaluated. A section carrying a command
    line and an image base has evaluated something, and the console's own
    missing branch would otherwise hide values the document does hold."""
    mf = _mf()
    mf.peb = Peb(0x7ff600000000, None, command_line="notepad.exe secret.txt")
    enrichment, _handles = collect_process_enrichment(mf)

    assert enrichment.command_line == "notepad.exe secret.txt"
    assert enrichment.image_base_address == f"0x{0x7ff600000000:016x}"
    assert enrichment.section.status == ENRICHMENT_PARTIAL


# ── identity conflicts ──────────────────────────────────────────────────
# The canonical identity boundary resolves disagreements between captured
# sources. They are published, they are visible, and they are not coverage
# gaps -- a section that reported them as such would tell a consumer
# thresholding on `status` that a fully captured conflict was a collection
# failure.

_PEB_IMAGE_BASE = 0x7FF600400000
_MODULE_BASE = 0x7FF600500000


class _ConflictDiagnostic:
    """A ProcessDiagnostic stand-in, so a conflict family can be exercised
    without constructing the dump shape that provokes it."""

    def __init__(self, code, message="two captured sources disagree", severity="warning"):
        self.code = code
        self.message = message
        self.severity = severity


def _identity_mf():
    mf = _mf(modules=[Module(_MODULE_BASE, REGION_SIZE, "C:\\tmp\\evil.exe")])
    mf.peb = Peb(_PEB_IMAGE_BASE, "C:\\tmp\\evil.exe", command_line="evil.exe --run")
    mf.misc_info = MiscInfo(process_id=1234, process_create_time=1700000000)
    return mf


def test_a_source_disagreement_is_published_without_making_the_section_partial():
    """PID, path, start time, command line and image base all resolved:
    the identity evidence is complete. The two sources describing it
    simply do not agree, which is a different fact from missing
    evidence."""
    enrichment, _handles = collect_process_enrichment(_identity_mf())

    assert enrichment.section.status == ENRICHMENT_COMPLETE
    assert enrichment.section.limitations == ()
    assert enrichment.identity_conflicts_total == 1
    conflict = enrichment.identity_conflicts[0]
    assert conflict.code == "PROCESS_MODULE_BASE_CONFLICT"
    assert conflict.severity == "warning"
    assert "0x00007ff600500000" in conflict.message


def test_a_path_source_fallback_stays_a_completeness_limitation(monkeypatch):
    """The one diagnostic family that reports an unavailable preferred
    source rather than two sources disagreeing keeps driving the state."""
    mf = _identity_mf()
    real = report_enrichment.build_process_identity_snapshot

    def _with_fallback(dump):
        snapshot = real(dump)
        return replace(snapshot, diagnostics=(
            _ConflictDiagnostic("PROCESS_PATH_SOURCE_FALLBACK",
                                "the PEB carried no image path; the module list supplied it"),))

    monkeypatch.setattr(report_enrichment, "build_process_identity_snapshot", _with_fallback)
    enrichment, _handles = collect_process_enrichment(mf)

    assert enrichment.section.status == ENRICHMENT_PARTIAL
    assert any("PROCESS_PATH_SOURCE_FALLBACK" in limitation
               for limitation in enrichment.section.limitations)
    assert enrichment.identity_conflicts == ()
    assert enrichment.identity_conflicts_total == 0


def test_conflicts_are_bounded_and_the_overflow_is_stated(monkeypatch):
    mf = _identity_mf()
    real = report_enrichment.build_process_identity_snapshot
    extra = tuple(_ConflictDiagnostic(f"PROCESS_IDENTITY_MISMATCH_{i}") for i in range(7))

    def _with_many(dump):
        return replace(real(dump), diagnostics=extra)

    monkeypatch.setattr(report_enrichment, "build_process_identity_snapshot", _with_many)
    enrichment, _handles = collect_process_enrichment(mf)

    assert len(enrichment.identity_conflicts) == MAX_IDENTITY_CONFLICTS
    assert enrichment.identity_conflicts_total == len(extra)
    assert enrichment.section.status == ENRICHMENT_COMPLETE


def test_a_process_name_with_no_path_separator_is_bounded_and_flagged():
    """A name is the basename of a path, and a captured path with no
    separator in it is its own basename -- so it is a dump-derived string
    of unbounded length, not a short field derived from one."""
    mf = _mf()
    mf.peb = Peb(_PEB_IMAGE_BASE, "e" * (ENRICHMENT_TEXT_CAP + 700) + ".exe")
    enrichment, _handles = collect_process_enrichment(mf)

    assert enrichment.process_name_truncated is True
    assert len(enrichment.process_name) == ENRICHMENT_TEXT_CAP
    assert enrichment.process_path_truncated is True


def test_a_dump_with_no_identity_evidence_at_all_is_still_missing():
    enrichment, _handles = collect_process_enrichment(_mf())
    assert enrichment.section.status == ENRICHMENT_MISSING
    assert enrichment.section.total is None


def test_an_absent_handle_stream_counts_nothing_rather_than_zero():
    enrichment, handle_records = collect_process_enrichment(_mf())
    assert enrichment.handles.section.status == ENRICHMENT_MISSING
    assert enrichment.handles.total_handles is None
    assert handle_records == ()


def test_a_parsed_handle_stream_produces_a_bounded_per_type_census():
    handles = parsed_handle_stream([
        {"handle": 0x10, "type_name": "File", "object_name": "\\Device\\HarddiskVolume2\\a"},
        {"handle": 0x14, "type_name": "File", "object_name": "\\Device\\HarddiskVolume2\\b"},
        {"handle": 0x18, "type_name": "Key", "object_name": "\\REGISTRY\\MACHINE"},
    ])
    mf = _mf(handles=handles, directories=[HandleStreamDirectory(0, 16)])
    enrichment, handle_records = collect_process_enrichment(mf)

    assert enrichment.handles.total_handles == 3
    assert [(row.type_name, row.count) for row in enrichment.handles.by_type] == [
        ("File", 2), ("Key", 1)]
    assert enrichment.handles.section.status == ENRICHMENT_COMPLETE
    assert len(handle_records) == 3


# ── TokenStream capability ──────────────────────────────────────────────

def test_a_dump_with_no_token_stream_says_nothing_was_captured():
    enrichment, _handles = collect_process_enrichment(_mf())
    token = enrichment.token

    assert token.stream_present is False
    assert token.parser_state is None
    assert token.status == "unavailable"
    assert "declares no TokenStream" in token.detail


def test_a_captured_token_stream_dumpex_cannot_read_is_reported_as_unparsed():
    """Captured-and-unreadable must never render as "the process had no
    token evidence": one is a collection gap the analyst can close by
    re-reading the dump with another tool, the other is not."""
    mf = _mf(directories=[DirectoryEntry(MINIDUMP_STREAM_TYPE.TokenStream)])
    enrichment, _handles = collect_process_enrichment(mf)
    token = enrichment.token

    assert token.stream_present is True
    assert token.parser_state == "unparsed"
    assert token.status == "unavailable"
    assert "no parser" in token.detail


# ── exception context ───────────────────────────────────────────────────

def _exception(thread_id, address, *, code=0xC0000005, name="EXCEPTION_ACCESS_VIOLATION",
               information=()):
    return ExceptionStreamEntry(thread_id, ExceptionRecordDetail(
        code, code_name=name, address=address, information=information))


def test_an_absent_exception_stream_is_missing_not_an_empty_evaluation():
    context = collect_exception_context(_mf(), anchor_tid=ANCHOR_TID,
                                        region_base=REGION_BASE, region_size=REGION_SIZE)
    assert context.section.status == ENRICHMENT_MISSING
    assert context.section.total is None
    assert context.entries == ()


def test_an_exception_on_an_unrelated_thread_and_address_is_evaluated_and_dropped():
    """A completed evaluation with no correlated record is `complete`
    with an empty-but-for-the-process-record subset -- not `missing`, and
    not a claim that the anchor is uninvolved in anything."""
    mf = _mf(exception=ExceptionListStream([
        _exception(0x99, 0xDEAD0000),
        _exception(0x98, 0xBEEF0000),
    ]))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID,
                                        region_base=REGION_BASE, region_size=REGION_SIZE)

    assert context.section.status == ENRICHMENT_COMPLETE
    assert [e.selection_reason for e in context.entries] == ["process_exception"]
    assert context.entries[0].index == 0


def test_the_anchor_threads_exception_is_selected_ahead_of_the_process_record():
    mf = _mf(exception=ExceptionListStream([
        _exception(0x99, 0xDEAD0000),
        _exception(ANCHOR_TID, 0xDEAD0000),
    ]))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID,
                                        region_base=REGION_BASE, region_size=REGION_SIZE)

    assert [e.selection_reason for e in context.entries] == [
        "anchor_thread", "process_exception"]
    assert context.entries[0].thread_id == ANCHOR_TID


def test_a_fault_inside_the_anchor_region_is_selected_by_address():
    mf = _mf(exception=ExceptionListStream([
        _exception(0x99, 0xDEAD0000),
        _exception(0x98, REGION_BASE + 0x40),
    ]))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID,
                                        region_base=REGION_BASE, region_size=REGION_SIZE)
    reasons = [e.selection_reason for e in context.entries]

    assert reasons == ["anchor_region", "process_exception"]
    assert context.entries[0].exception_address == f"0x{REGION_BASE + 0x40:016x}"


def test_an_unrecognized_exception_code_keeps_its_raw_value_and_reports_no_name():
    mf = _mf(exception=ExceptionListStream([_exception(0x99, 0x0, code=0x1234, name=None)]))
    context = collect_exception_context(mf, anchor_tid=None, region_base=None, region_size=0)
    entry = context.entries[0]

    assert entry.exception_code == "0x00001234"
    assert entry.exception_code_name is None


def test_exception_records_and_their_parameters_are_both_bounded():
    entries = [_exception(ANCHOR_TID, 0x0, information=tuple(range(1, 12)))
               for _ in range(MAX_EXCEPTION_ENTRIES + 3)]
    mf = _mf(exception=ExceptionListStream(entries))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID,
                                        region_base=REGION_BASE, region_size=REGION_SIZE)

    assert context.section.total == len(entries)
    assert context.section.included == MAX_EXCEPTION_ENTRIES
    assert context.section.truncated is True
    assert len(context.entries[0].parameters) == MAX_EXCEPTION_PARAMETERS
    assert context.entries[0].parameters_truncated is True


# ── allocation neighborhood ─────────────────────────────────────────────

def _region(base, allocation_base, protection="PAGE_READWRITE", mem_type="MEM_PRIVATE"):
    return Region(base, allocation_base, REGION_SIZE, "MEM_COMMIT", protection, mem_type)


def _neighborhood(regions, anchor, *, modules=()):
    """collect_allocation_neighborhood over `regions`, through the same
    RegionEvidence collect_report builds once per invocation."""
    return collect_allocation_neighborhood(
        RegionEvidence.from_dump(_mf(regions=regions)), anchor_address=anchor,
        modules=modules)


def test_an_absent_region_table_leaves_the_neighborhood_unevaluated():
    mf = _mf()
    mf.memory_info = None
    neighborhood = collect_allocation_neighborhood(
        RegionEvidence.from_dump(mf), anchor_address=REGION_BASE)

    assert neighborhood.section.status == ENRICHMENT_MISSING
    assert neighborhood.allocation_base is None


def test_an_anchor_outside_every_region_is_a_completed_empty_neighborhood():
    neighborhood = _neighborhood(None, 0xF0000000)
    assert neighborhood.section.status == ENRICHMENT_COMPLETE
    assert neighborhood.section.total == 0
    assert neighborhood.entries == ()


def test_the_neighborhood_names_the_anchor_its_allocation_and_both_sides():
    regions = [_region(0x1000, 0x1000), _region(0x2000, 0x2000, "PAGE_EXECUTE_READWRITE"),
               _region(0x3000, 0x2000), _region(0x4000, 0x4000)]
    neighborhood = _neighborhood(regions, 0x2000)
    by_base = {entry.base_address: entry.relation for entry in neighborhood.entries}

    assert by_base[f"0x{0x2000:016x}"] == "anchor"
    assert by_base[f"0x{0x3000:016x}"] == "same_allocation"
    assert by_base[f"0x{0x1000:016x}"] == "preceding"
    assert by_base[f"0x{0x4000:016x}"] == "following"
    assert neighborhood.allocation_base == f"0x{0x2000:016x}"


def test_neighborhood_entries_are_ascending_deduplicated_and_bounded():
    regions = [_region(0x1000 * i, 0x1000) for i in range(1, 20)]
    neighborhood = _neighborhood(regions, 0x1000)
    bases = [entry.base_address for entry in neighborhood.entries]

    assert bases == sorted(bases)
    assert len(set(bases)) == len(bases)
    assert len(bases) == MAX_NEIGHBOR_REGIONS
    assert neighborhood.section.truncated is True


def test_a_region_descriptor_the_model_drops_makes_the_neighborhood_partial():
    """A descriptor the region model cannot represent leaves a hole in
    the map this section describes. Reporting the surviving views as a
    completed neighborhood would hide it."""
    regions = [_region(0x1000, 0x1000),
               Region(0x3000, 0x3000, 0, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    neighborhood = _neighborhood(regions, 0x1000)
    section = neighborhood.section

    assert section.status == ENRICHMENT_PARTIAL
    assert any("could not be represented" in limitation
               for limitation in section.limitations)


def test_a_dropped_descriptor_is_reported_even_when_no_region_holds_the_anchor():
    """The dropped descriptor may have been the one covering the anchor,
    so "no region contains it" is not a completed answer either."""
    regions = [Region(0x3000, 0x3000, 0, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    neighborhood = _neighborhood(regions, 0x1000)

    assert neighborhood.section.status == ENRICHMENT_PARTIAL
    assert neighborhood.entries == ()


def test_the_neighborhood_reaches_past_the_anchors_own_allocation():
    """What a private allocation abuts is the neighborhood's most
    decision-relevant fact. A multi-page reservation whose immediate index
    neighbours are its own subregions must not hide the regions outside
    it."""
    regions = [_region(0x1000, 0x1000, "PAGE_READONLY", mem_type="MEM_IMAGE")]
    regions += [_region(base, 0x2000) for base in (0x2000, 0x3000, 0x4000, 0x5000, 0x6000)]
    regions += [_region(0x7000, 0x7000, "PAGE_READONLY", mem_type="MEM_IMAGE")]
    neighborhood = _neighborhood(regions, 0x4000)
    by_base = {entry.base_address: entry.relation for entry in neighborhood.entries}

    assert by_base[f"0x{0x1000:016x}"] == "preceding"
    assert by_base[f"0x{0x7000:016x}"] == "following"
    assert neighborhood.section.total == len(regions)
    assert neighborhood.section.truncated is False


def test_out_of_allocation_neighbours_survive_a_cap_a_large_allocation_would_fill():
    """The allocation's own subregions are numerous and interchangeable;
    the regions bounding it are neither, so the cap reserves them."""
    regions = [_region(0x1000, 0x1000, "PAGE_READONLY", mem_type="MEM_IMAGE")]
    regions += [_region(0x2000 + i * 0x1000, 0x2000) for i in range(10)]
    regions += [_region(0xC000, 0xC000, "PAGE_READONLY", mem_type="MEM_IMAGE")]
    neighborhood = _neighborhood(regions, 0x6000)
    relations = [entry.relation for entry in neighborhood.entries]

    assert "preceding" in relations and "following" in relations
    assert neighborhood.section.included == MAX_NEIGHBOR_REGIONS
    # Every region the selection considered, so `truncated` is honest
    # about what the cap cut from.
    assert neighborhood.section.total == 1 + 9 + 2
    assert neighborhood.section.truncated is True


def test_a_neighbour_inside_a_loaded_module_names_its_owner():
    regions = [_region(0x1000, 0x1000), _region(0x2000, 0x2000)]
    modules = [Module(0x2000, REGION_SIZE, "ntdll.dll")]
    neighborhood = _neighborhood(regions, 0x1000, modules=modules)
    owners = {entry.base_address: entry.module_owner for entry in neighborhood.entries}

    assert owners[f"0x{0x2000:016x}"] == "ntdll.dll"
    assert owners[f"0x{0x1000:016x}"] is None


def test_an_unparseable_region_stream_is_not_reported_as_an_uncollected_one():
    """Captured-and-unreadable, declared-but-lost, and never-collected are
    three different problems with three different answers."""
    def _state(directories=(), failures=None):
        mf = _mf()
        mf.memory_info = None
        mf.directories = list(directories)
        mf._dumpex_stream_failures = failures or {}
        return collect_allocation_neighborhood(
            RegionEvidence.from_dump(mf), anchor_address=REGION_BASE).section.limitations[0]

    declared = [DirectoryEntry(MINIDUMP_STREAM_TYPE.MemoryInfoListStream)]
    assert "carries no MemoryInfoListStream" in _state()
    assert "could not be read" in _state(declared)
    assert "could not be parsed: boom" in _state(
        declared, {MINIDUMP_STREAM_TYPE.MemoryInfoListStream: "boom"})


def test_a_dropped_descriptor_makes_an_unresolved_exception_address_partial(monkeypatch):
    """An address that resolved to no captured region may live in exactly
    the descriptor the region model dropped, so the section must not claim
    it lies outside every captured region."""
    regions = [_region(REGION_BASE, REGION_BASE),
               Region(0x9000, 0x9000, 0, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf = _mf(regions=regions, exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(
            0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION", address=0x9000,
            information=(1, 0x9100)))]))
    context = collect_exception_context(
        mf, anchor_tid=ANCHOR_TID, region_base=REGION_BASE, region_size=REGION_SIZE,
        region_evidence=RegionEvidence.from_dump(mf), modules=[])

    assert context.section.status == ENRICHMENT_PARTIAL
    assert any("may lie in one of them" in limitation
               for limitation in context.section.limitations)


def test_a_resolved_exception_address_stays_complete_despite_a_dropped_descriptor():
    """The downgrade is about an address that failed to resolve, not about
    the region view having a hole anywhere at all."""
    regions = [_region(REGION_BASE, REGION_BASE),
               Region(0x9000, 0x9000, 0, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf = _mf(regions=regions, exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(
            0x80000003, code_name="EXCEPTION_BREAKPOINT", address=REGION_BASE))]))
    context = collect_exception_context(
        mf, anchor_tid=ANCHOR_TID, region_base=REGION_BASE, region_size=REGION_SIZE,
        region_evidence=RegionEvidence.from_dump(mf), modules=[])

    assert context.entries[0].address_context.region_base is not None
    assert context.section.status == ENRICHMENT_COMPLETE


# ── malformed region tables ─────────────────────────────────────────────
# A base address identifies a region here, so the view holds at most one
# descriptor per base. A dump is free to declare otherwise; the report is
# not free to crash on it, and must not silently pretend the table was
# whole either.

def test_a_repeated_region_base_is_kept_once_and_reported():
    regions = [_region(REGION_BASE, REGION_BASE), _region(REGION_BASE, REGION_BASE),
               _region(0x2000, REGION_BASE)]
    neighborhood = _neighborhood(regions, REGION_BASE)
    bases = [entry.base_address for entry in neighborhood.entries]

    assert bases == sorted(set(bases))
    assert neighborhood.section.status == ENRICHMENT_PARTIAL
    assert any("repeated a base address" in limitation
               for limitation in neighborhood.section.limitations)


def test_a_repeated_allocation_member_does_not_become_its_own_neighbour():
    """Two descriptors sharing a base are one region. Keeping both would
    make a region its own neighbour and give the position index two
    answers for one key."""
    regions = [_region(0x1000, 0x1000, mem_type="MEM_IMAGE")]
    regions += [_region(base, 0x2000) for base in (0x2000, 0x3000, 0x3000, 0x4000)]
    neighborhood = _neighborhood(regions, 0x3000)
    entries = {entry.base_address: entry.relation for entry in neighborhood.entries}

    assert entries[f"0x{0x3000:016x}"] == "anchor"
    assert len(entries) == len(neighborhood.entries)
    assert neighborhood.section.status == ENRICHMENT_PARTIAL


def test_a_malformed_region_table_still_produces_a_report(monkeypatch):
    """The other evidence a card carries is not forfeit because the region
    table was malformed."""
    regions = [_region(REGION_BASE, REGION_BASE), _region(REGION_BASE, REGION_BASE)]
    card = _card(monkeypatch, _mf(regions=regions), data=b"captured text here\x00").records[0]

    assert card.verdict in ("CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS",
                            "HIGH_CONFIDENCE_MALICIOUS")
    assert card.allocation_neighborhood.section.status == ENRICHMENT_PARTIAL


def test_overlapping_regions_are_both_kept_when_their_bases_differ():
    """Deduplication is by base address, which is the region's identity --
    it is not an overlap check, and two genuinely distinct regions are
    never merged."""
    regions = [_region(0x1000, 0x1000), Region(0x1800, 0x1000, REGION_SIZE, "MEM_COMMIT",
                                               "PAGE_READWRITE", "MEM_PRIVATE")]
    neighborhood = _neighborhood(regions, 0x1000)
    bases = {entry.base_address for entry in neighborhood.entries}

    assert len(bases) == 2
    assert neighborhood.section.status == ENRICHMENT_COMPLETE


def test_a_neighbour_distance_is_the_byte_gap_to_the_anchor_region():
    regions = [_region(0x1000, 0x1000), _region(0x9000, 0x9000)]
    neighborhood = _neighborhood(regions, 0x1000)
    by_relation = {entry.relation: entry.distance for entry in neighborhood.entries}

    assert by_relation["anchor"] == 0
    assert by_relation["following"] == 0x9000 - (0x1000 + REGION_SIZE)


# ── handle correlation ──────────────────────────────────────────────────

_PIPE_NAME = "\\Device\\NamedPipe\\evilpipe"
_PIPE_BYTES = _PIPE_NAME.encode() + b"\x00" + b"padding for the region\x00"


def _handle_mf(descriptors, *, exact_read_of=None):
    """`exact_read_of` sizes the anchor region to exactly those bytes, so
    the card's own read comes up complete. Without it the fixture region
    is larger than the bytes behind it and every card read is short, which
    is a real partial and makes a correlation resting on it partial too."""
    regions = None
    if exact_read_of is not None:
        regions = [Region(REGION_BASE, REGION_BASE, len(exact_read_of), "MEM_COMMIT",
                          "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    return _mf(handles=parsed_handle_stream(descriptors), regions=regions,
               directories=[HandleStreamDirectory(0, 16)])


def test_a_handle_name_found_in_the_cards_own_text_is_retained(monkeypatch):
    mf = _handle_mf([
        {"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME},
        {"handle": 0x44, "type_name": "Key", "object_name": "\\REGISTRY\\MACHINE\\SOFTWARE"},
    ], exact_read_of=_PIPE_BYTES)
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]
    correlation = card.handle_correlation

    assert correlation.section.status == ENRICHMENT_COMPLETE
    assert [entry.object_name for entry in correlation.entries] == [_PIPE_NAME]
    assert correlation.entries[0].selection_reason == "object_name_in_anchor_strings"
    assert correlation.section.total == 1


def test_no_matching_handle_name_is_a_completed_empty_subset(monkeypatch):
    data = b"nothing relevant in this region\x00"
    mf = _handle_mf([{"handle": 0x44, "type_name": "Key",
                      "object_name": "\\REGISTRY\\MACHINE\\SOFTWARE"}],
                    exact_read_of=data)
    card = _card(monkeypatch, mf, data=data).records[0]

    assert card.handle_correlation.section.status == ENRICHMENT_COMPLETE
    assert card.handle_correlation.section.total == 0
    assert card.handle_correlation.entries == ()


def test_every_collected_handle_is_compared_however_many_there_are(monkeypatch):
    """The collector orders records by ascending handle value, which is
    roughly the order the process opened them. A prefix cut would drop the
    most recently opened handles -- exactly the ones a post-injection
    workload holds."""
    descriptors = [{"handle": 0x1000 + i, "type_name": "Event",
                    "object_name": f"\\Sessions\\object{i:05d}"} for i in range(5000)]
    descriptors.append({"handle": 0xF0000, "type_name": "File", "object_name": _PIPE_NAME})
    mf = _handle_mf(descriptors, exact_read_of=_PIPE_BYTES)
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]

    assert [entry.object_name for entry in card.handle_correlation.entries] == [_PIPE_NAME]
    assert card.handle_correlation.section.status == ENRICHMENT_COMPLETE


def test_a_correlated_handle_carries_its_descriptor_counters(monkeypatch):
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME,
                      "attributes": 2, "granted_access": 0x120089, "handle_count": 3,
                      "pointer_count": 7}], exact_read_of=_PIPE_BYTES)
    entry = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0].handle_correlation.entries[0]

    assert entry.attributes == 2
    assert entry.granted_access == 0x120089
    assert entry.handle_count == 3
    assert entry.pointer_count == 7


def test_a_long_handle_object_name_is_published_bounded_and_flagged(monkeypatch):
    """The match is made against the whole captured name, so a truncated
    published value can lack the segment that selected it. Saying it was
    cut is what keeps the entry verifiable."""
    tail = "e" * 60
    long_name = "\\Device\\HarddiskVolume2\\" + ("d" * ENRICHMENT_TEXT_CAP) + "\\" + tail
    data = tail.encode() + b"\x00padding for this region\x00"
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": long_name}],
                    exact_read_of=data)
    entry = _card(monkeypatch, mf, data=data).records[0].handle_correlation.entries[0]

    assert entry.object_name_truncated is True
    assert entry.object_name == long_name[:ENRICHMENT_TEXT_CAP]


def test_a_clamped_card_read_is_stated_by_the_handle_correlation(monkeypatch):
    """A policy clamp is not an evidence gap, but the compared range is
    still smaller than the region and must not go unstated."""
    monkeypatch.setattr(report_mod, "MAX_REGION_READ", len(_PIPE_BYTES))
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME}])
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]

    assert card.string_scan["clamped"] is True
    assert card.string_scan["truncated"] is False
    assert any("scan cap" in limitation
               for limitation in card.handle_correlation.section.limitations)


def test_a_long_handle_type_name_is_bounded_and_flagged(monkeypatch):
    """A type name is dump-derived text like any other here."""
    mf = _handle_mf([{"handle": 0x40, "type_name": "T" * (ENRICHMENT_TEXT_CAP + 500),
                      "object_name": _PIPE_NAME}], exact_read_of=_PIPE_BYTES)
    entry = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0].handle_correlation.entries[0]

    assert entry.type_name_truncated is True
    assert len(entry.type_name) == ENRICHMENT_TEXT_CAP


def test_correlation_work_follows_the_examined_text_not_cards_times_handles(monkeypatch):
    """The inventory is indexed once per invocation, so adding cards does
    not re-walk every handle. A run that scaled with cards x handles would
    have no invocation-level bound at all."""
    seen = []
    real = report_enrichment._identifying_segment

    def _counting(name):
        seen.append(name)
        return real(name)

    descriptors = [{"handle": 0x40 + i, "type_name": "Event",
                    "object_name": f"\\Sessions\\object{i:04d}"} for i in range(400)]
    data = b"needle plus padding text\x00"
    regions = [Region(base, base, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for base in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000)]
    read_map = {base: data for base in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000)}
    monkeypatch.setattr(report_mod, "read_region", mem_reader(read_map))
    monkeypatch.setattr("dumpex.core.memory.read_region", mem_reader(read_map))
    monkeypatch.setattr(report_enrichment, "_identifying_segment", _counting)
    mf = _mf(regions=regions, handles=parsed_handle_stream(descriptors),
             directories=[HandleStreamDirectory(0, 16)])
    result = collect_report(mf, report_string="needle")

    assert len(result.records) == 5
    assert len(seen) == len(descriptors)


def test_a_generic_namespace_segment_does_not_correlate_a_handle(monkeypatch):
    """Only the object name's own last segment may match. A namespace
    prefix is shared by thousands of unrelated objects, and a correlation
    made on one would also fill the retained subset with noise."""
    data = b"\\Device\\HarddiskVolume2\\unrelated.txt\x00more padding text\x00"
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME}],
                    exact_read_of=data)
    card = _card(monkeypatch, mf, data=data).records[0]

    assert card.handle_correlation.entries == ()
    assert card.handle_correlation.section.status == ENRICHMENT_COMPLETE
    assert card.handle_correlation.section.total == 0


def test_a_repeated_handle_value_is_kept_once_and_reported(monkeypatch):
    """A malformed dump can declare one handle value twice. Two
    descriptors sharing an identity are one object, and the report must
    say so rather than fail on the pair."""
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME},
                     {"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME}],
                    exact_read_of=_PIPE_BYTES)
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]
    correlation = card.handle_correlation

    assert [entry.handle for entry in correlation.entries] == ["0x0000000000000040"]
    assert correlation.section.total == 1
    assert any("repeated a handle value" in limitation
               for limitation in correlation.section.limitations)


def test_an_unreadable_handle_name_makes_the_correlation_partial(monkeypatch):
    """A name that could not be read could not be matched, so an empty or
    short subset is not a completed check of every handle."""
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME},
                     {"handle": 0x44, "type_name": "File", "object_name": BAD_RVA}],
                    exact_read_of=_PIPE_BYTES)
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]
    section = card.handle_correlation.section

    assert section.status == ENRICHMENT_PARTIAL
    assert any("could not be read" in limitation for limitation in section.limitations)


def test_a_short_card_read_makes_the_correlation_partial(monkeypatch):
    """A handle named only in the bytes that were never read cannot be
    matched, so the subset is incomplete even though the handle inventory
    itself is whole."""
    mf = _handle_mf([{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME}])
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]
    section = card.handle_correlation.section

    assert card.string_scan["truncated"] is True
    assert section.status == ENRICHMENT_PARTIAL
    assert any("came up short" in limitation for limitation in section.limitations)


def test_without_a_handle_stream_the_cards_correlation_is_missing(monkeypatch):
    card = _card(monkeypatch, _mf(), data=_PIPE_BYTES).records[0]
    assert card.handle_correlation.section.status == ENRICHMENT_MISSING
    assert card.handle_correlation.section.total is None


def test_correlated_handles_are_bounded_and_deduplicated_by_handle(monkeypatch):
    mf = _handle_mf([{"handle": 0x40 + i, "type_name": "File", "object_name": _PIPE_NAME}
                     for i in range(MAX_CORRELATED_HANDLES + 4)])
    card = _card(monkeypatch, mf, data=_PIPE_BYTES).records[0]
    handles = [entry.handle for entry in card.handle_correlation.entries]

    assert len(handles) == MAX_CORRELATED_HANDLES
    assert len(set(handles)) == len(handles)
    assert card.handle_correlation.section.truncated is True


# ── anchor-aware string context ─────────────────────────────────────────

_IOC_BYTES = (b"a plain string of ordinary length\x00"
              b"http://c2.example.com/beacon\x00"
              b"another plain string of some length\x00")


def test_string_context_orders_ioc_matches_ahead_of_plain_neighbours(monkeypatch):
    card = _card(monkeypatch, _mf(), data=_IOC_BYTES).records[0]
    reasons = [entry.selection_reason for entry in card.string_context.entries]

    assert reasons[0] == "ioc_pattern"
    assert set(reasons[1:]) == {"adjacent_to_anchor"}


def test_plain_neighbours_are_ordered_by_distance_from_the_anchor(monkeypatch):
    card = _card(monkeypatch, _mf(), data=_IOC_BYTES).records[0]
    adjacent = [entry for entry in card.string_context.entries
                if entry.selection_reason == "adjacent_to_anchor"]

    assert [entry.distance for entry in adjacent] == sorted(entry.distance
                                                            for entry in adjacent)


def test_string_context_reuses_the_cards_own_read_and_never_leaves_it(monkeypatch):
    card = _card(monkeypatch, _mf(), data=_IOC_BYTES).records[0]
    context = card.string_context
    base = int(context.examined_base_address, 16)

    assert context.bytes_read == len(_IOC_BYTES)
    assert context.total_strings == card.string_scan["total"]
    for entry in context.entries:
        assert int(entry.address, 16) == base + entry.offset
        assert entry.offset < context.bytes_read


def test_a_string_hit_card_measures_distance_from_the_matched_string(monkeypatch):
    """The anchor of a --report-string card is the hit region's base, but
    the thing the analyst followed is the matched string inside it."""
    needle_data = b"leading filler bytes here\x00" + b"needle_marker_string\x00"
    monkeypatch.setattr("dumpex.core.memory.read_region",
                        mem_reader({REGION_BASE: needle_data}))
    monkeypatch.setattr(report_mod, "read_region", mem_reader({REGION_BASE: needle_data}))
    mf = _mf(regions=[Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")])
    card = collect_report(mf, report_string="needle_marker_string").records[0]
    context = card.string_context

    assert context.anchor_address == f"0x{REGION_BASE:016x}"
    assert int(context.distance_anchor_address, 16) > REGION_BASE
    query_entries = [e for e in context.entries if e.selection_reason == "query_match"]
    assert len(query_entries) == 1
    assert query_entries[0].distance is None


def test_the_string_the_query_matched_is_published_once_as_the_match(monkeypatch):
    """A string that IS the anchor must not also be labelled adjacent to
    it -- that is factually wrong and spends a retention slot on a
    duplicate."""
    needle = "needle_marker_string"
    data = b"leading filler bytes here\x00" + needle.encode() + b"\x00"
    monkeypatch.setattr("dumpex.core.memory.read_region", mem_reader({REGION_BASE: data}))
    monkeypatch.setattr(report_mod, "read_region", mem_reader({REGION_BASE: data}))
    mf = _mf(regions=[Region(REGION_BASE, REGION_BASE, len(data), "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")])
    context = collect_report(mf, report_string=needle).records[0].string_context

    at_hit = [e for e in context.entries if e.text == needle]
    assert len(at_hit) == 1
    assert at_hit[0].selection_reason == "query_match"
    assert context.query_text == needle


def test_an_embedded_needle_keeps_the_query_and_the_captured_string_apart(monkeypatch):
    """The searched needle and the string captured around it are different
    facts, and a consumer has to be able to tell them apart."""
    data = b"aaaaa_marker_bbbbb\x00trailing filler text\x00"
    monkeypatch.setattr("dumpex.core.memory.read_region", mem_reader({REGION_BASE: data}))
    monkeypatch.setattr(report_mod, "read_region", mem_reader({REGION_BASE: data}))
    mf = _mf(regions=[Region(REGION_BASE, REGION_BASE, len(data), "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")])
    context = collect_report(mf, report_string="marker").records[0].string_context
    match = [e for e in context.entries if e.selection_reason == "query_match"][0]

    assert match.text == "aaaaa_marker_bbbbb"
    assert context.query_text == "marker"
    assert [e.text for e in context.entries].count("aaaaa_marker_bbbbb") == 1


def test_string_context_is_bounded_and_reports_what_it_cut(monkeypatch):
    data = b"".join(f"ordinary string number {i:03d}\x00".encode()
                    for i in range(MAX_STRING_CONTEXT_ENTRIES + 10))
    card = _card(monkeypatch, _mf(), data=data).records[0]
    context = card.string_context

    assert context.section.included == MAX_STRING_CONTEXT_ENTRIES
    assert context.section.total > MAX_STRING_CONTEXT_ENTRIES
    assert context.section.truncated is True


def test_string_selection_builds_a_record_only_for_what_it_keeps(monkeypatch):
    """The card may read up to the whole region cap, so the string list
    behind it can be very large. Selection streams over it and holds only
    the cap's worth of candidates: building and validating a record per
    extracted string would make the work grow with the region instead of
    with the cap."""
    data = b"".join(f"ordinary string number {i:03d}\x00".encode() for i in range(300))
    built = []
    real_entry = report_enrichment.ReportStringContextEntry

    def _counting_entry(**kwargs):
        built.append(kwargs["address"])
        return real_entry(**kwargs)

    monkeypatch.setattr(report_enrichment, "ReportStringContextEntry", _counting_entry)
    card = _card(monkeypatch, _mf(), data=data).records[0]

    assert card.string_context.section.total > MAX_STRING_CONTEXT_ENTRIES
    assert card.string_context.section.included == MAX_STRING_CONTEXT_ENTRIES
    assert len(built) == MAX_STRING_CONTEXT_ENTRIES


def test_a_card_that_read_no_content_has_no_string_context(monkeypatch):
    """No examined range is not the same claim as an examined range that
    yielded nothing, so no ReportStringContext is invented for it. The
    region table was still present and still evaluated -- it simply
    contains no region holding this anchor."""
    mf = _mf(regions=[])
    monkeypatch.setattr(report_mod, "read_region", mem_reader({}))
    card = collect_report(mf, report_addr=hex(REGION_BASE)).records[0]

    assert card.region is None
    assert card.string_context is None
    assert card.allocation_neighborhood.section.status == ENRICHMENT_COMPLETE
    assert card.allocation_neighborhood.section.total == 0


def test_a_short_region_read_makes_the_string_context_partial(monkeypatch):
    card = _card(monkeypatch, _mf(), data=b"a string long enough to keep\x00").records[0]
    context = card.string_context

    assert context.section.status == ENRICHMENT_PARTIAL
    assert context.bytes_read < context.requested_bytes
    assert any("came up short" in limitation
               for limitation in context.section.limitations)


def test_an_access_violation_is_decoded_and_both_addresses_are_resolved():
    """The card exists to answer whether execution stopped at or
    referenced the reported address. The raw parameters alone do not."""
    regions = [_region(REGION_BASE, REGION_BASE, "PAGE_EXECUTE_READWRITE")]
    mf = _mf(regions=regions, exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(
            0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION",
            address=REGION_BASE + 0x10, information=(1, REGION_BASE + 0x40)))]))
    context = collect_exception_context(
        mf, anchor_tid=ANCHOR_TID, region_base=REGION_BASE, region_size=REGION_SIZE,
        region_evidence=RegionEvidence.from_dump(mf), modules=[])
    entry = context.entries[0]

    assert entry.access_type == "write"
    assert entry.referenced_address == f"0x{REGION_BASE + 0x40:016x}"
    assert entry.address_context.protection == "PAGE_EXECUTE_READWRITE"
    assert entry.referenced_context.region_base == f"0x{REGION_BASE:016x}"


def test_an_address_no_captured_region_describes_reports_no_region_facts():
    mf = _mf(exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(
            0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION",
            address=REGION_BASE, information=(0, 0xDEADBEEF)))]))
    context = collect_exception_context(
        mf, anchor_tid=ANCHOR_TID, region_base=REGION_BASE, region_size=REGION_SIZE,
        region_evidence=RegionEvidence.from_dump(mf), modules=[])
    entry = context.entries[0]

    assert entry.access_type == "read"
    assert entry.referenced_context.region_base is None
    assert entry.referenced_context.protection is None


def test_a_non_access_violation_code_decodes_no_access_type():
    """Only two codes define their parameters as (access, address). Every
    other code's parameters are code-specific and are not guessed at."""
    mf = _mf(exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(
            0x80000003, code_name="EXCEPTION_BREAKPOINT", address=REGION_BASE,
            information=(1, REGION_BASE)))]))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID, region_base=REGION_BASE,
                                        region_size=REGION_SIZE)
    entry = context.entries[0]

    assert entry.access_type is None
    assert entry.referenced_address is None


def test_a_retained_exception_states_that_its_capture_reason_is_unknown():
    """A breakpoint a debugger injected and a fault the process took reach
    this section identically; the dump represents no way to tell."""
    mf = _mf(exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(0xC0000005))]))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID, region_base=None,
                                        region_size=0)

    assert any("capture reason unknown" in limitation
               for limitation in context.section.limitations)


def test_a_declared_but_unparsed_exception_stream_is_failed_evidence():
    """A directory entry with no parsed object and no recorded failure
    means the stream was captured and lost on the way through the loader,
    which is not the same claim as a dump collected without one."""
    mf = _mf(directories=[DirectoryEntry(MINIDUMP_STREAM_TYPE.ExceptionStream)])
    context = collect_exception_context(mf, anchor_tid=None, region_base=None, region_size=0)

    assert context.section.status == ENRICHMENT_MISSING
    assert any("could not be read" in limitation
               for limitation in context.section.limitations)
    assert not any("carries no ExceptionStream" in limitation
                   for limitation in context.section.limitations)


def test_an_unusable_exception_parameter_keeps_its_position():
    """Parameter 0 is the access type and parameter 1 the referenced
    address. Dropping an unusable element in place would shift every
    following value one slot left and relabel it."""
    mf = _mf(exception=ExceptionListStream([
        ExceptionStreamEntry(ANCHOR_TID, ExceptionRecordDetail(
            0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION",
            information=(-1, 0x2000)))]))
    context = collect_exception_context(mf, anchor_tid=ANCHOR_TID, region_base=None,
                                        region_size=0)
    entry = context.entries[0]

    assert entry.parameters == ("0x?", "0x2000")
    assert entry.access_type is None


def test_a_long_command_line_is_bounded_like_every_other_captured_string():
    mf = _mf()
    mf.peb = Peb(0x7ff600000000, None, command_line="j" * (ENRICHMENT_TEXT_CAP + 400))
    enrichment, _handles = collect_process_enrichment(mf)

    assert enrichment.command_line_truncated is True
    assert len(enrichment.command_line) == ENRICHMENT_TEXT_CAP


def test_a_large_allocation_does_not_cost_a_full_table_walk_per_card(monkeypatch):
    """Regions are ascending and non-overlapping, so index distance inside
    an allocation is gap distance: the nearest members bracket the anchor
    and the walk stops at the cap. `total` still counts the whole
    allocation, which the index knows without looking at it."""
    members = 500
    regions = [_region(0x1000, 0x1000, mem_type="MEM_IMAGE")]
    regions += [_region(0x2000 + i * 0x1000, 0x2000) for i in range(members)]
    gaps = []
    real = report_enrichment._gap_between

    def _counting(region, anchor):
        gaps.append(region.base_address)
        return real(region, anchor)

    monkeypatch.setattr(report_enrichment, "_gap_between", _counting)
    neighborhood = _neighborhood(regions, 0x2000 + 250 * 0x1000)

    assert neighborhood.section.total == 1 + (members - 1) + 1
    assert neighborhood.section.included == MAX_NEIGHBOR_REGIONS
    # Bounded by the cap, not by the 500-member allocation behind it.
    assert len(gaps) < 4 * MAX_NEIGHBOR_REGIONS


def test_the_region_table_is_enumerated_once_per_invocation(monkeypatch):
    """The scope split process_enrichment already follows: one canonical
    collector result per run, reused by every card."""
    calls = []
    real = RegionEvidence.from_dump

    def _counting(mf):
        calls.append(mf)
        return real(mf)

    monkeypatch.setattr(report_mod.RegionEvidence, "from_dump", staticmethod(_counting))
    data = b"needle here plus padding\x00"
    regions = [Region(base, base, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for base in (REGION_BASE, 0x9000, 0xB000)]
    read_map = {base: data for base in (REGION_BASE, 0x9000, 0xB000)}
    monkeypatch.setattr(report_mod, "read_region", mem_reader(read_map))
    monkeypatch.setattr("dumpex.core.memory.read_region", mem_reader(read_map))
    result = collect_report(_mf(regions=regions), report_string="needle")

    assert len(result.records) == 3
    assert len(calls) == 1


# ── invocation budget ───────────────────────────────────────────────────
# The per-card caps bound one card and say nothing about how many cards a
# run builds. --report-string builds one per private hit, and the hit
# count belongs to the dump, so the run carries its own budget.

def _hit_dump(count, *, size=None):
    data = b"needle plus padding text here\x00"
    regions = [Region(0x1000 * i, 0x1000 * i, size if size is not None else len(data),
                      "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for i in range(1, count + 1)]
    return _mf(regions=regions), {region.BaseAddress: data for region in regions}


def _string_run(monkeypatch, mf, read_map):
    monkeypatch.setattr(report_mod, "read_region", mem_reader(read_map))
    monkeypatch.setattr("dumpex.core.memory.read_region", mem_reader(read_map))
    return collect_report(mf, report_string="needle")


def test_a_run_stops_building_cards_at_its_own_card_budget(monkeypatch):
    mf, read_map = _hit_dump(MAX_REPORT_CARDS + 20)
    result = _string_run(monkeypatch, mf, read_map)

    assert result.summary["card_count"] == MAX_REPORT_CARDS
    assert len(result.records) == MAX_REPORT_CARDS


def test_a_hit_left_untriaged_is_reported_rather_than_folded_away(monkeypatch):
    """The hit counters keep naming everything the search found, so a
    consumer can always tell a budget stop from a dump with fewer hits."""
    mf, read_map = _hit_dump(MAX_REPORT_CARDS + 20)
    result = _string_run(monkeypatch, mf, read_map)
    summary = result.summary

    assert summary["hits_private"] == MAX_REPORT_CARDS + 20
    assert summary["cards_skipped_for_budget"] == 20
    assert summary["hits_skipped_for_budget"] == 20
    assert (summary["card_count"] + summary["hits_sharing_a_region"]
            + summary["hits_skipped_for_budget"] == summary["hits_private"])
    assert result.execution_status == "partial"
    assert any(d.code == "REPORT_CARD_BUDGET_REACHED" for d in result.diagnostics)


def test_a_cumulative_read_budget_stops_a_run_of_large_regions(monkeypatch):
    """A run must not cost hits x MAX_REGION_READ just because every hit
    region is large."""
    monkeypatch.setattr(report_enrichment, "MAX_REPORT_SCAN_BYTES", 3 * REGION_SIZE)
    monkeypatch.setattr(report_mod, "MAX_REPORT_SCAN_BYTES", 3 * REGION_SIZE)
    mf, read_map = _hit_dump(10, size=REGION_SIZE)
    result = _string_run(monkeypatch, mf, read_map)

    assert result.summary["card_count"] == 3
    assert result.summary["cards_skipped_for_budget"] == 7
    assert result.execution_status == "partial"


def test_the_budget_never_suppresses_the_only_card(monkeypatch):
    """A budget that could answer a direct question with nothing would be
    worse than the cost it avoids."""
    monkeypatch.setattr(report_enrichment, "MAX_REPORT_SCAN_BYTES", 1)
    monkeypatch.setattr(report_mod, "MAX_REPORT_SCAN_BYTES", 1)
    mf, read_map = _hit_dump(4, size=REGION_SIZE)
    result = _string_run(monkeypatch, mf, read_map)

    assert result.summary["card_count"] == 1
    assert result.summary["cards_skipped_for_budget"] == 3


def test_the_budget_keeps_the_hits_it_triages_in_a_deterministic_order(monkeypatch):
    """Truncation follows the search's own hit order, so the same dump
    always yields the same retained cards."""
    mf, read_map = _hit_dump(MAX_REPORT_CARDS + 5)
    first = _string_run(monkeypatch, mf, read_map)
    second = _string_run(monkeypatch, mf, read_map)

    assert ([r.anchor_address for r in first.records]
            == [r.anchor_address for r in second.records])
    assert first.records[0].anchor_address == f"0x{0x1000:016x}"


# ── overlapping region tables ───────────────────────────────────────────
# The search reports a hit against the region it read; the card is built
# against the region that covers the hit address. Those differ only when
# the region table overlaps -- and there, resolving twice would budget one
# region's size for another region's read and publish an offset measured
# from the wrong base.

_BIG_BASE, _BIG_SIZE = 0x1000, 0x10000
_SMALL_BASES = (0x2000, 0x3000, 0x4000)


def _overlapping_dump():
    """A large region covering three smaller ones that each hold the
    needle, with the large region listed first so it wins resolution."""
    regions = [Region(_BIG_BASE, _BIG_BASE, _BIG_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
                      "MEM_PRIVATE")]
    regions += [Region(base, base, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
                       "MEM_PRIVATE") for base in _SMALL_BASES]
    data = b"needle plus padding\x00"
    read_map = {base: data for base in _SMALL_BASES}
    read_map[_BIG_BASE] = b"\x00" * _BIG_SIZE
    return _mf(regions=regions), read_map


def _recording_reader(read_map, log):
    def _read(mf, address, size):
        log.append((address, size))
        return read_map.get(address, b"\x00" * _BIG_SIZE)[:size]
    return _read


def test_hits_covered_by_one_region_produce_one_card(monkeypatch):
    mf, read_map = _overlapping_dump()
    result = _string_run(monkeypatch, mf, read_map)
    summary = result.summary

    assert summary["hits_private"] == 3
    assert summary["card_count"] == 1
    assert summary["hits_sharing_a_region"] == 2
    assert (summary["card_count"] + summary["hits_sharing_a_region"]
            + summary["hits_skipped_for_budget"] == summary["hits_private"])
    assert any(d.code == "REPORT_STRING_HITS_SHARE_A_REGION" for d in result.diagnostics)


def test_a_hit_offset_is_published_against_the_card_own_region(monkeypatch):
    """The card resolved to the covering region, so the hit's offset is
    rebased onto that region's base. Publishing the offset measured from
    the smaller region would point the analyst at the wrong address."""
    mf, read_map = _overlapping_dump()
    card = _string_run(monkeypatch, mf, read_map).records[0]
    hit = card.string_hit
    region_base = int(card.region.base_address, 16)

    assert region_base == _BIG_BASE
    assert int(hit["address"], 16) == region_base + hit["offset"]
    assert int(hit["address"], 16) == _SMALL_BASES[0]
    match = [e for e in card.string_context.entries
             if e.selection_reason == "query_match"][0]
    assert int(match.address, 16) == _SMALL_BASES[0]


def test_the_card_reads_the_region_the_budget_was_charged_for(monkeypatch):
    """A small region's size must never pay for a large region's read."""
    mf, read_map = _overlapping_dump()
    log = []
    monkeypatch.setattr(report_mod, "read_region", _recording_reader(read_map, log))
    monkeypatch.setattr("dumpex.core.memory.read_region", _recording_reader(read_map, log))
    monkeypatch.setattr(report_enrichment, "MAX_REPORT_SCAN_BYTES", 3 * REGION_SIZE)
    monkeypatch.setattr(report_mod, "MAX_REPORT_SCAN_BYTES", 3 * REGION_SIZE)
    result = collect_report(mf, report_string="needle")
    card = result.records[0]

    # The one card built asks for exactly the region it resolved to, and
    # that is the size the budget was charged.
    assert card.region.base_address == f"0x{_BIG_BASE:016x}"
    assert card.string_scan["requested_bytes"] == _BIG_SIZE
    assert result.summary["card_count"] == 1


def test_the_budget_charge_equals_what_the_cards_request(monkeypatch):
    """The declared budget is only meaningful if it counts the bytes the
    cards actually ask for."""
    sizes = (REGION_SIZE, 2 * REGION_SIZE, 4 * REGION_SIZE)
    regions = [Region(0x10000 * (i + 1), 0x10000 * (i + 1), size, "MEM_COMMIT",
                      "PAGE_READWRITE", "MEM_PRIVATE") for i, size in enumerate(sizes)]
    data = b"needle plus padding\x00"
    read_map = {region.BaseAddress: data for region in regions}
    result = _string_run(monkeypatch, _mf(regions=regions), read_map)

    requested = sum(card.string_scan["requested_bytes"] for card in result.records)
    assert result.summary["card_count"] == 3
    assert requested == sum(sizes)


def test_a_hit_inside_a_covering_image_region_is_classified_as_image(monkeypatch):
    """Classification has to describe the region the card would be built
    against. Calling a hit actionable and then producing a card that says
    "registered system module" is the summary contradicting itself."""
    regions = [Region(0x1000, 0x1000, 0x4000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
               Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
                      "MEM_PRIVATE")]
    modules = [Module(0x1000, 0x4000, "system.dll")]
    mf = _mf(regions=regions, modules=modules)
    result = _string_run(monkeypatch, mf, {0x2000: b"needle plus padding\x00"})
    summary = result.summary

    assert summary["hits_private"] == 0
    assert summary["hits_image"] == 1
    assert summary["image_hit_modules"] == ["system.dll"]
    assert summary["card_count"] == 0


def test_a_hit_inside_a_covering_private_region_still_earns_a_card(monkeypatch):
    """The reverse direction: an image region covered by a private one is
    actionable, and classifying it off the search's own region would drop
    the card entirely."""
    regions = [Region(0x1000, 0x1000, 0x4000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                      "MEM_PRIVATE"),
               Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY",
                      "MEM_IMAGE")]
    modules = [Module(0x2000, REGION_SIZE, "system.dll")]
    mf = _mf(regions=regions, modules=modules)
    result = _string_run(monkeypatch, mf, {0x2000: b"needle plus padding\x00"})

    assert result.summary["hits_image"] == 0
    assert result.summary["hits_private"] == 1
    assert result.summary["card_count"] == 1
    assert result.records[0].region.type == "MEM_PRIVATE"


def test_the_summary_classification_matches_the_card_it_produced(monkeypatch):
    """One resolved region feeds classification, budgeting and the card,
    so a card's own region can never disagree with the class its hit was
    counted under."""
    mf, read_map = _overlapping_dump()
    result = _string_run(monkeypatch, mf, read_map)

    assert result.summary["hits_image"] == 0
    for card in result.records:
        assert card.region.type == "MEM_PRIVATE"
        assert card.region.module_owner is None


def _two_overlapping_groups():
    """Two large regions, each covering two smaller ones that hold the
    needle -- four hits resolving into two groups of two.

    The small entries are registered in the read map first: mem_reader
    answers with the first span containing an address, so a covering
    blob listed earlier would shadow the needle out of the very regions
    the search is meant to find it in."""
    regions, read_map = [], {}
    for group_base in (0x10000, 0x20000):
        for offset in (0x1000, 0x2000):
            base = group_base + offset
            regions.append(Region(base, base, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
                                  "MEM_PRIVATE"))
            read_map[base] = b"needle plus padding\x00"
        read_map[group_base] = b"\x00" * 0x4000
    covers = [Region(group_base, group_base, 0x4000, "MEM_COMMIT", "PAGE_READWRITE",
                     "MEM_PRIVATE") for group_base in (0x10000, 0x20000)]
    # The covering regions come first in the table, so they win region
    # resolution and every hit groups onto one of them.
    return covers + regions, read_map


def test_a_budget_skipped_group_is_never_counted_as_already_carded(monkeypatch):
    """A group the budget skipped covers nothing. Counting its hits as
    shared would tell an analyst they are already represented by another
    card when nothing analyzed them at all."""
    monkeypatch.setattr(report_enrichment, "MAX_REPORT_CARDS", 1)
    monkeypatch.setattr(report_mod, "MAX_REPORT_CARDS", 1)
    regions, read_map = _two_overlapping_groups()
    result = _string_run(monkeypatch, _mf(regions=regions), read_map)
    summary = result.summary

    assert summary["hits_private"] == 4
    assert summary["card_count"] == 1
    assert summary["hits_sharing_a_region"] == 1     # the carded group's second hit
    assert summary["cards_skipped_for_budget"] == 1  # the group that got nothing
    assert summary["hits_skipped_for_budget"] == 2   # both of its hits, unanalyzed
    assert (summary["card_count"] + summary["hits_sharing_a_region"]
            + summary["hits_skipped_for_budget"] == summary["hits_private"])


def test_the_budget_and_sharing_diagnostics_state_their_own_counts(monkeypatch):
    monkeypatch.setattr(report_enrichment, "MAX_REPORT_CARDS", 1)
    monkeypatch.setattr(report_mod, "MAX_REPORT_CARDS", 1)
    regions, read_map = _two_overlapping_groups()
    result = _string_run(monkeypatch, _mf(regions=regions), read_map)
    by_code = {d.code: d.message for d in result.diagnostics}

    assert "1 hit(s) fall inside a region another hit is already carded for" in (
        by_code["REPORT_STRING_HITS_SHARE_A_REGION"])
    assert "1 actionable hit region(s) covering 2 hit(s) were not triaged" in (
        by_code["REPORT_CARD_BUDGET_REACHED"])


def test_a_byte_budget_stop_counts_its_skipped_group_the_same_way(monkeypatch):
    monkeypatch.setattr(report_enrichment, "MAX_REPORT_SCAN_BYTES", 0x4000)
    monkeypatch.setattr(report_mod, "MAX_REPORT_SCAN_BYTES", 0x4000)
    regions, read_map = _two_overlapping_groups()
    result = _string_run(monkeypatch, _mf(regions=regions), read_map)
    summary = result.summary

    assert summary["card_count"] == 1
    assert summary["hits_sharing_a_region"] == 1
    assert summary["hits_skipped_for_budget"] == 2
    assert result.execution_status == "partial"


def test_a_non_overlapping_table_merges_nothing(monkeypatch):
    mf, read_map = _hit_dump(4)
    result = _string_run(monkeypatch, mf, read_map)

    assert result.summary["hits_sharing_a_region"] == 0
    assert result.summary["card_count"] == 4
    assert not any(d.code == "REPORT_STRING_HITS_SHARE_A_REGION"
                   for d in result.diagnostics)


def test_a_run_inside_its_budget_stays_complete(monkeypatch):
    mf, read_map = _hit_dump(3)
    result = _string_run(monkeypatch, mf, read_map)

    assert result.summary["cards_skipped_for_budget"] == 0
    assert result.execution_status == "completed"
    assert not any(d.code == "REPORT_CARD_BUDGET_REACHED" for d in result.diagnostics)


# ── evidence boundary ───────────────────────────────────────────────────

def test_enrichment_moves_no_finding_verdict_or_coverage(monkeypatch):
    """The same dump with and without every enrichment source present
    must produce the same findings, verdict, coverage status, and
    execution status: enrichment is context, never evidence for a
    judgment."""
    bare = _card(monkeypatch, _mf(), data=_PIPE_BYTES)
    enriched_mf = _handle_mf([{"handle": 0x40, "type_name": "File",
                               "object_name": _PIPE_NAME}])
    enriched_mf.exception = ExceptionListStream([_exception(ANCHOR_TID, REGION_BASE)])
    enriched_mf.directories.append(DirectoryEntry(MINIDUMP_STREAM_TYPE.TokenStream))
    enriched = _card(monkeypatch, enriched_mf, data=_PIPE_BYTES)

    assert bare.records[0].findings == enriched.records[0].findings
    assert bare.records[0].verdict == enriched.records[0].verdict
    assert bare.coverage.status == enriched.coverage.status
    assert bare.execution_status == enriched.execution_status
    assert [l.code for l in bare.coverage.limitations] == [
        l.code for l in enriched.coverage.limitations]


def test_a_truncated_enrichment_section_does_not_make_the_run_partial(monkeypatch):
    """A cap is this command's own retention policy, not an evidence gap:
    it belongs in the section that applied it and nowhere else."""
    uncut = _card(monkeypatch, _handle_mf(
        [{"handle": 0x40, "type_name": "File", "object_name": _PIPE_NAME}]),
        data=_PIPE_BYTES)
    cut = _card(monkeypatch, _handle_mf(
        [{"handle": 0x40 + i, "type_name": "File", "object_name": _PIPE_NAME}
         for i in range(MAX_CORRELATED_HANDLES + 4)]),
        data=_PIPE_BYTES)

    assert uncut.records[0].handle_correlation.section.truncated is False
    assert cut.records[0].handle_correlation.section.truncated is True
    assert cut.execution_status == uncut.execution_status
    assert cut.coverage.status == uncut.coverage.status
    assert cut.records[0].findings == uncut.records[0].findings
    assert cut.records[0].verdict == uncut.records[0].verdict
