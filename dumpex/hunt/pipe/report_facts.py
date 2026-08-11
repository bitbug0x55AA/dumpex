"""Shared projection logic for `PipeReport` (dumpex/hunt/pipe/domain.py) --
everything `report_legacy.py`, `report_record.py`, and `report_console.py`
all three need, so it is built exactly once. Mirrors
`dumpex.hunt.stomping.report_facts`/`dumpex.hunt.injection.report_facts`/
`dumpex.hunt.encoding.report_facts` (the three completed reference
pilots): see those modules' own docstrings for why `verbose_facts` is
deliberately never populated here (that policy belongs to
`report_console.py` alone).

Every fact string below is written to match the pre-migration
`aggregate.py`'s facts text byte-for-byte for the same evidence -- these
arrays are embedded verbatim in BOTH the v1.1 findings dict and the typed
`HunterRecord`, and tests/fixtures/hunt_cli_golden/pipe_hunt_dict.json is
frozen against them. Verified by
tests/hunt/test_pipe_projectors.py's golden-scenario parity test.

This module owns no dependency on `dumpex.hunt.pipe.aggregate`:
`build_report()` is the ONE place a `PipeReport` is constructed, and this
module stays a pure function of that already-built Report.
"""
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt._finding import Finding
from dumpex.hunt.pipe.domain import CoverageSnapshot, PipeReport
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, EvaluationRequirement, LimitationCode,
    build_coverage_report, observe_source,
)

# The .dmp page size proximity facts report "same page" against -- 4 KiB,
# the x86/x64 page every one of these VAs is an address in. A literal in
# the pre-migration aggregate.py (`// 0x1000`, three times); named once
# here so the three proximity renderers below cannot drift apart.
_PAGE_SIZE = 0x1000


def _file_offset_text(file_offset) -> str:
    """"(not captured)" for None -- the bytes were never written to the
    .dmp at all, which an investigator needs to tell apart from "offset
    zero" (an ordinary, valid offset). Same wording every other migrated
    hunter's own facts use."""
    return f"0x{file_offset:x}" if file_offset is not None else "(not captured)"


def _proximity_text(target_va: int, pipe_va: int) -> str:
    """The `distance=0x.. same_page=..` suffix both proximity facts share
    -- computed from the two stored VAs rather than stored alongside them,
    so there is no second copy to fall out of step with the addresses it
    describes."""
    distance  = abs(target_va - pipe_va)
    same_page = (target_va // _PAGE_SIZE) == (pipe_va // _PAGE_SIZE)
    return f"distance=0x{distance:x} same_page={same_page}"


# ── Fact-string builders -- byte-identical to the pre-migration aggregate.py ──

def _open_handle_fact(ev, report: PipeReport) -> str:
    h = ev.handle
    return (f"Handle=0x{h.handle:x} ObjectName={h.object_name} "
            f"GrantedAccess=0x{h.granted_access:x}"
            + (f"  [framework={ev.framework.framework}]" if ev.framework else ""))


def _framework_handle_fact(ev, report: PipeReport) -> str:
    h, fw = ev.handle, ev.framework
    return (f"Handle=0x{h.handle:x} ObjectName={h.object_name} "
            f"framework={fw.framework} technique={fw.technique} mitre={fw.mitre}")


def _string_lead_fact(ev, report: PipeReport) -> str:
    return (f"VA=0x{ev.va:x} file_offset={_file_offset_text(ev.file_offset)} "
            f"name={ev.name.strip()!r} region_type={ev.region.type}")


def _corroboration_fact(ev, report: PipeReport) -> str:
    href = ev.handle.handle
    fact = (f"Handle=0x{href.handle:x} ObjectName={href.object_name} "
            f"pipe_va=0x{ev.pipe_va:x}")
    if ev.nearby_c2:
        # Only the FIRST nearby record, matching the pre-migration wire
        # fact; --verbose expands every one of them (see
        # report_console._corroboration_verbose_fact).
        rec = ev.nearby_c2[0]
        fact += (f"  c2_va=0x{rec.va:x} c2_match={rec.match!r} "
                 f"{_proximity_text(rec.va, ev.pipe_va)}")
    if ev.rip_hit is not None:
        tc = ev.rip_hit
        fact += (f"  live_rip=TID:0x{tc.thread_id:x}@{tc.ip_reg}=0x{tc.ip:x} "
                 f"{_proximity_text(tc.ip, ev.pipe_va)}")
    return fact


def _start_address_lead_fact(ev, report: PipeReport) -> str:
    href = ev.handle.handle
    # `start_address or 0`: a ThreadInfo entry with no recorded
    # StartAddress renders as 0x0 here, exactly as the pre-migration fact
    # did. The JSON wire shape keeps the distinction (null, never 0) --
    # see report_record._thread_dict.
    sa = ev.thread.start_address or 0
    return (f"Handle=0x{href.handle:x} ObjectName={href.object_name} "
            f"pipe_va=0x{ev.pipe_va:x} "
            f"TID=0x{ev.thread.thread_id:x} StartAddr=0x{sa:x} "
            f"{_proximity_text(sa, ev.pipe_va)}")


_FACT_ITEM_RENDERERS = {
    "pipe.open_handles":                   _open_handle_fact,
    "pipe.handle_framework_match":         _framework_handle_fact,
    "pipe.string_scan_lead":               _string_lead_fact,
    "pipe.corroboration":                  _corroboration_fact,
    "pipe.start_address_proximity_lead":   _start_address_lead_fact,
}


def _facts_for(result, report: PipeReport) -> tuple:
    """`CheckResult.facts`'s replacement -- rendered from `result.evidence`
    (capped at `result.evidence_limit`, with a "... and N more" summary
    line when the cap trims anything -- the same policy the pre-migration
    aggregate.py's own `[:20]`/`[:15]` slices applied).

    One deliberate change: `pipe.corroboration` capped its own list at 10
    WITHOUT the "... and N more" sentinel, so a run with 11+ corroborated
    handles silently reported only the first ten as though they were all
    of them. The cap itself is preserved; the summary line is now applied
    uniformly, since a truncated list that does not say it was truncated
    is the defect, not the fix. Every other check already had it, and no
    frozen golden reaches any of these caps.
    """
    renderer = _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        raise ValueError(
            f"report_facts: no fact renderer registered for check {result.check!r} -- "
            f"every pipe check id must have one (see _FACT_ITEM_RENDERERS)")
    items = result.evidence
    limit = result.evidence_limit
    shown = items if limit is None else items[:limit]
    facts = [renderer(item, report) for item in shown]
    if limit is not None and len(items) > limit:
        facts.append(f"... and {len(items) - limit} more")
    return tuple(facts)


def finding_from_check_result(result, report: PipeReport) -> Finding:
    """The transient compatibility `Finding` for one `CheckResult` -- built
    fresh on every call, never stored anywhere. Carries no `verbose_facts`
    -- that is `report_console.py`'s own normal/verbose detail policy to
    apply, not a wire-shaped fact every projector needs."""
    return Finding(
        check=result.check,
        facts=list(_facts_for(result, report)),
        inference=result.inference,
        confidence=result.confidence,
        rationale=result.rationale,
        limitations=list(result.limitations),
        tag=result.tag,
        technique_ids=list(result.technique_ids),
        evidence_refs=list(result.evidence_refs),
        iocs=list(result.iocs),
        rule_id=result.rule_id,
        rule_version=result.rule_version,
    )


# ── Coverage projections ──────────────────────────────────────────────────

# The two stream-absence reasons, in ONE place: `project_coverage_v1`
# renders them into `coverage_reasons` and report_console.py's COVERAGE
# section renders that same list. Byte-identical to the pre-migration
# aggregate.build_report()'s own strings -- the v1.1 `coverage_reasons`
# array is part of the frozen output contract.
MEMORY_INFO_MISSING_REASON = "MemoryInfoListStream missing from this dump"
HANDLE_DATA_MISSING_REASON = ("HandleDataStream missing from this dump (needs "
                               "MiniDumpWithHandleData) — the primary, scored "
                               "pipe-handle check could not run")


def project_coverage_v1(coverage: CoverageSnapshot) -> tuple:
    """`(coverage_status, coverage_reasons)` -- the v1.1 shape the
    pre-migration `aggregate.build_report` assembled, reproduced
    fact-for-fact from `CoverageSnapshot`'s own named fields.

    A two-element tuple, not the three-element `(coverage_counts,
    coverage_status, coverage_reasons)` stomping's own projector returns:
    the pipe hunter's v1.1 findings dict has never carried a
    `coverage_counts` mapping at all (its two derived coverage facts are
    the top-level `budget_exhausted`/`scan_complete` booleans, projected
    in report_legacy.py from `CoverageSnapshot.budget_exhausted`/
    `region_scan_complete`), and inventing one here would be a public
    schema change this migration explicitly does not make.

    Reason ORDER is part of the output contract (the pre-migration verdict
    line joined these verbatim) and is preserved exactly: stream absences
    first, then the region walk's own skip/read/short-read gaps, then the
    two independent budgets.
    """
    reasons = []
    if not coverage.memory_info_stream:
        reasons.append(MEMORY_INFO_MISSING_REASON)
    if not coverage.handle_data_stream:
        reasons.append(HANDLE_DATA_MISSING_REASON)
    reasons.extend(coverage.region_gap_reasons())
    coverage_status = derive_coverage_status(coverage.evaluated, coverage.complete)
    return coverage_status, reasons


def project_coverage_report(coverage: CoverageSnapshot) -> CoverageReport:
    """The structured `dumpex.output.coverage.CoverageReport` for a pipe
    run -- built at each gap site `project_coverage_v1` above already
    derives coverage_status/coverage_reasons from (never parsed back out of
    that free text; see docs/hunt_migration_field_matrix.md's own migration
    rule). Replaces the pre-migration `dumpex/hunt/pipe/__init__.py`'s
    `_pipe_coverage_report()`, which had to be called from OUTSIDE the
    aggregator and assigned onto the Report as a mutable attribute.

    `memory_info`/`handle_data` are ONE combined evaluation_sources group
    (OR-of-presence, matching this hunter's own
    `CoverageSnapshot.evaluated`) -- unlike stomping's AND-of-presence,
    which needs two independent groups instead. `pipe_name_scan` is a
    synthetic, always-present source (the scan attempt itself, not an
    optional minidump stream), mirroring injection's own `hidden_pe_scan`
    pattern, purely so the SCAN_REGION_*/SCAN_BUDGET_EXHAUSTED limitations
    have a source key to attach to and validate against.
    """
    sources = {
        "memory_info": observe_source("memory_info", present=coverage.memory_info_stream,
                                       items=["present"] if coverage.memory_info_stream else []),
        "handle_data": observe_source("handle_data", present=coverage.handle_data_stream,
                                       items=["present"] if coverage.handle_data_stream else []),
        "pipe_name_scan": observe_source("pipe_name_scan", present=True, items=["scanned"]),
    }
    # "memory_info" is deliberately NOT a completeness_check: this hunter's
    # own `CoverageSnapshot.complete` never consults it at all (only
    # `evaluated` does, via the combined group above) -- adding it here
    # would make memory_info's absence alone flip coverage.status to
    # "partial" even when the real v1.1 coverage_status still says
    # "complete" (confirmed by tests/hunt/test_pipe_collect.py::
    # test_memory_info_absent_alone_does_not_force_partial).
    completeness_checks = ["handle_data"]
    if coverage.skipped_oversize:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="pipe_name_scan",
            affected_count=len(coverage.skipped_oversize),
            targets=coverage.skipped_oversize))
    if coverage.read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="pipe_name_scan",
            affected_count=coverage.read_failed))
    if coverage.short_reads:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="pipe_name_scan",
            affected_count=coverage.short_reads))
    # Two SEPARATE limitations, distinguished by `scope`, never one merged
    # "budget exhausted" entry -- which signal's collection stopped early
    # is exactly what an analyst needs to know (see
    # dumpex/hunt/pipe/config.py).
    if coverage.c2_budget_exhausted:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
            scope="c2_context", detail=coverage.c2_budget_reason))
    if coverage.pipe_name_budget_exhausted:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
            scope="pipe_name", detail=coverage.pipe_name_budget_reason))

    return build_coverage_report(
        sources, evaluation_sources=EvaluationRequirement(("memory_info", "handle_data")),
        completeness_checks=completeness_checks)
