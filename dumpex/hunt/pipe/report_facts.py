"""Shared fact and coverage projections for ``PipeReport``.

Fact text, ordering, and evidence caps are wire contracts shared by legacy
and typed output. Richer verbose facts are console-only.
"""
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt._finding import Finding
from dumpex.hunt.pipe.domain import CoverageSnapshot, PipeReport
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, EvaluationRequirement, LimitationCode,
    SourceObservation, SourceState, build_coverage_report, observe_source,
)
from dumpex.output.records import hex_address

# This hunter's public coverage-source vocabulary -- the exact `sources`
# dict keys `project_coverage_report()` below builds. Extracted into a
# named constant (rather than left as inline dict-literal keys only) so
# `dumpex.hunt._registry.AnalyzerSpec` can validate a future
# `TargetedGrant.source` against a real, closed, importable vocabulary
# instead of an unenforced convention (docs/developer/hunt_analyzer_registry_contract.md
# §7.1 failure #5).
COVERAGE_SOURCE_NAMES = frozenset({"memory_info", "handle_data", "pipe_name_scan"})

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


# ── Fact-string builders ─────────────────────────────────────────────────
# Address-typed fields (`VA`, `pipe_va`, `c2_va`, `StartAddr`, and a
# thread's live `RIP`/`EIP`) go through the shared `hex_address()` helper,
# so a fact renders an address in the same fixed-width, zero-padded
# 16-hex-digit form as this hunter's `report_record.py` and `--json`
# `details`. `Handle`, `GrantedAccess`, `TID`, `distance`, and the string
# lead's `file_offset` (a dump offset) are not addresses and keep their
# compact `:x` form.

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
    return (f"VA={hex_address(ev.va)} file_offset={_file_offset_text(ev.file_offset)} "
            f"name={ev.name.strip()!r} region_type={ev.region.type}")


def _corroboration_fact(ev, report: PipeReport) -> str:
    href = ev.handle.handle
    fact = (f"Handle=0x{href.handle:x} ObjectName={href.object_name} "
            f"pipe_va={hex_address(ev.pipe_va)}")
    if ev.nearby_c2:
        # Only the FIRST nearby record, matching the pre-migration wire
        # fact; --verbose expands every one of them (see
        # report_console._corroboration_verbose_fact).
        rec = ev.nearby_c2[0]
        fact += (f"  c2_va={hex_address(rec.va)} c2_match={rec.match!r} "
                 f"{_proximity_text(rec.va, ev.pipe_va)}")
    if ev.rip_hit is not None:
        tc = ev.rip_hit
        fact += (f"  live_rip=TID:0x{tc.thread_id:x}@{tc.ip_reg}={hex_address(tc.ip)} "
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
            f"pipe_va={hex_address(ev.pipe_va)} "
            f"TID=0x{ev.thread.thread_id:x} StartAddr={hex_address(sa)} "
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


def handle_stream_failed_reason(detail: str) -> str:
    """The companion to HANDLE_DATA_MISSING_REASON for the OTHER way this
    run ends up with no handle evidence: the dump DID carry a
    HandleDataStream and it would not parse. Re-capturing with
    MiniDumpWithHandleData — what the missing-stream reason tells an
    analyst to do — is not the next step here and must not be implied;
    the parser's own detail is carried instead, and the companion
    SOURCE_FAILED limitation carries it in the structured report."""
    return (f"HandleDataStream present in this dump but could not be parsed "
            f"({detail}) — the primary, scored pipe-handle check could not run")


def handle_stream_truncated_reason(dropped: int) -> str:
    """The one wording for a HandleDataStream that declared more
    descriptors than it delivered — rendered into `coverage_reasons` here
    and into the console's COVERAGE section from that same list, so the
    gap is described once. The count is the descriptor tail; what those
    descriptors named is exactly what nothing in this run can say."""
    return (f"HandleDataStream truncated — {dropped} declared handle descriptor(s) "
            f"were not read; a pipe handle among them is neither present nor ruled out")


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
    first, then what a present stream did not deliver, then the region
    walk's own skip/read/short-read gaps, then the two independent
    budgets.
    """
    reasons = []
    if not coverage.memory_info_stream:
        reasons.append(MEMORY_INFO_MISSING_REASON)
    if coverage.handle_stream_failure is not None:
        reasons.append(handle_stream_failed_reason(coverage.handle_stream_failure))
    elif not coverage.handle_data_stream:
        reasons.append(HANDLE_DATA_MISSING_REASON)
    if coverage.handle_stream_truncated:
        reasons.append(handle_stream_truncated_reason(coverage.handle_stream_truncated))
    reasons.extend(coverage.region_gap_reasons())
    coverage_status = derive_coverage_status(coverage.evaluated, coverage.complete)
    return coverage_status, reasons


def _budget_limitation(scope: str, detail: str, targets: tuple) -> CoverageLimitation:
    """One `SCAN_BUDGET_EXHAUSTED` limitation for a pipe budget. When the
    scanner resolved the regions that budget left unresolved for `scope`,
    they ride along as `targets` (with `affected_count`); otherwise the
    limitation is reason-only, exactly as before."""
    extra = {"affected_count": len(targets), "targets": list(targets)} if targets else {}
    return CoverageLimitation(
        code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
        scope=scope, detail=detail, **extra)


def _handle_data_observation(coverage: CoverageSnapshot) -> SourceObservation:
    """The `handle_data` source: whether this run had a HandleDataStream to
    read at all.

    Failed for a stream the dump carried but the parser rejected, carrying
    the parser's own detail -- `handle_data` is a bare completeness check
    below, so that state is what raises the SOURCE_FAILED limitation an
    analyst reads instead of a re-capture instruction that would not help
    on a dump whose handle data is already there. Absent only when the dump
    never carried the stream. Present otherwise, with the same
    `record_count` a present stream has always reported. How many
    descriptors that stream then delivered is not this observation's
    subject: the HANDLE_STREAM_TRUNCATED limitation attached to this same
    source is what reports the shortfall."""
    if coverage.handle_stream_failure is not None:
        return SourceObservation(name="handle_data", state=SourceState.FAILED,
                                  detail=coverage.handle_stream_failure)
    return observe_source("handle_data", present=coverage.handle_data_stream,
                           items=["present"] if coverage.handle_data_stream else [])


def project_coverage_report(coverage: CoverageSnapshot) -> CoverageReport:
    """The structured `dumpex.output.coverage.CoverageReport` for a pipe
    run -- built at each gap site `project_coverage_v1` above already
    derives coverage_status/coverage_reasons from (never parsed back out of
    that free text; see docs/developer/hunt_architecture.md's structured-facts
    ownership rule). The returned report is the authoritative coverage value
    consumed by structured and console projectors.

    `memory_info`/`handle_data` are ONE combined evaluation_sources group
    (OR-of-presence, matching this hunter's own
    `CoverageSnapshot.evaluated`) -- unlike stomping's AND-of-presence,
    which needs two independent groups instead. `pipe_name_scan` is a
    synthetic, always-present source (the scan attempt itself, not an
    optional minidump stream), mirroring injection's own `hidden_pe_scan`
    pattern, purely so the SCAN_REGION_*/SCAN_BUDGET_EXHAUSTED limitations
    have a source key to attach to and validate against.

    `handle_data` answers every question about the HandleDataStream: which
    of its three states the dump is in (never captured /
    captured-but-unparseable / readable), and so whether the scored path
    could run at all, plus -- through the HANDLE_STREAM_TRUNCATED
    limitation attached to it -- what a readable one failed to deliver.
    One source for one stream: the roster is the same three keys on every
    run, truncated or not, which is what lets a targeted rescan publish
    that same roster and say per source what it did not evaluate.
    `--handles` names this stream `handles` in its own coverage; the
    limitation is accepted under either name (see
    `dumpex.output.coverage._CodeSpec.alternate_sources`) precisely so
    neither command has to rename a source to share the fact.
    """
    sources = {
        "memory_info": observe_source("memory_info", present=coverage.memory_info_stream,
                                       items=["present"] if coverage.memory_info_stream else []),
        "handle_data": _handle_data_observation(coverage),
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
    # Ordered ahead of the region-scan gaps, matching
    # `project_coverage_v1`'s reason order: what the handle stream did not
    # deliver is a gap in the PRIMARY, scored evidence, not in the string
    # scan.
    if coverage.handle_stream_truncated:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.HANDLE_STREAM_TRUNCATED, source="handle_data",
            affected_count=coverage.handle_stream_truncated))
    if coverage.skipped_oversize:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="pipe_name_scan",
            affected_count=len(coverage.skipped_oversize),
            targets=coverage.skipped_oversize))
    if coverage.read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="pipe_name_scan",
            affected_count=coverage.read_failed, targets=coverage.read_failed_targets))
    if coverage.short_reads:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="pipe_name_scan",
            affected_count=coverage.short_reads, targets=coverage.short_read_targets))
    # Two SEPARATE limitations, distinguished by `scope`, never one merged
    # "budget exhausted" entry -- which signal's collection stopped early
    # is exactly what an analyst needs to know (see
    # dumpex/hunt/pipe/config.py). `targets` (the eligible regions that
    # budget left unresolved for its scope) ride along when the scanner
    # could name them; an exhaustion that stopped the walk with nothing
    # eligible left to point at stays reason-only. Ordering is fixed:
    # c2_context first, then pipe_name.
    if coverage.c2_budget_exhausted:
        completeness_checks.append(_budget_limitation(
            "c2_context", coverage.c2_budget_reason,
            coverage.c2_budget_exhausted_targets))
    if coverage.pipe_name_budget_exhausted:
        completeness_checks.append(_budget_limitation(
            "pipe_name", coverage.pipe_name_budget_reason,
            coverage.pipe_name_budget_exhausted_targets))
    if coverage.unreconciled:
        # No `targets` -- see SCAN_ITEMS_UNACCOUNTED on LimitationCode
        # for why this gap cannot name what it lost. Both ledger
        # directions land on the same code: either way, that many regions
        # have no trustworthy outcome.
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_ITEMS_UNACCOUNTED, source="pipe_name_scan",
            affected_count=coverage.unreconciled))

    return build_coverage_report(
        sources, evaluation_sources=EvaluationRequirement(("memory_info", "handle_data")),
        completeness_checks=completeness_checks)
