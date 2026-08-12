"""Shared projection logic for `InjectionReport` (dumpex/hunt/injection/
domain.py) -- everything `report_legacy.py`, `report_record.py`, and
`report_console.py` all three need, so it is built exactly once:

  * a transient compatibility `Finding` for one `CheckResult`, carrying
    only the WIRE-shaped `facts` (capped at `evidence_limit`) -- never
    `verbose_facts`. `verbose_facts` is console/--txt-only detail (see
    `dumpex.hunt._finding.Finding`'s own docstring: it is excluded from
    `to_dict()` and from `id`'s hash basis), so populating it here would
    make the legacy dict and `HunterRecord` projectors execute the same
    normal/verbose detail POLICY the verdict-first console owns -- that
    policy belongs to `report_console.py` alone (see the Injection 2B
    issue's own scope bullet: "normal/verbose detail policy" is to be
    "centralized in the console projector"). `report_console.py` augments
    the Finding this module returns with `verbose_facts` itself, locally,
    only for its own rendering;
  * the coverage snapshot projected into the v1.1 `(coverage dict,
    coverage_status, coverage_reasons)` shape;
  * the coverage snapshot projected into the structured v2.4
    `dumpex.output.coverage.CoverageReport` shape.

This module owns no dependency on `dumpex.hunt.injection.aggregate` or
`collect` -- since the Injection 2C cutover, `aggregate.build_report()` is
itself the ONE place an `InjectionReport` is constructed, and this module
stays a pure function of that already-built Report rather than reaching
into `aggregate.py`'s own construction internals. Every fact string below
is written to match `aggregate.py`'s inference/rationale/facts text
byte-for-byte for the same evidence, verified by
tests/hunt/test_injection_projectors.py's golden-scenario parity test.
"""
from dumpex.hunt._finding import Finding
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt.injection.domain import CoverageSnapshot, InjectionReport
from dumpex.hunt.injection.models import PeHeaderInfo, RegionRef
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, LimitationCode, SourceObservation, SourceRequirement,
    SourceState, observe_source, build_coverage_report,
)


# ── Fact-string builders -- byte-identical to aggregate.py's own ─────────

def _region_facts(r: RegionRef) -> str:
    return (f"VA=0x{r.base_address:x} AllocationBase=0x{r.allocation_base:x} "
            f"size=0x{r.size:x} type={r.type} protect={r.protect}")


def _pe_candidate_facts(location) -> str:
    """Where inside its region a hidden-PE candidate actually starts --
    rendered ONLY when that is not the region base, so a PE at a region's
    own base reads exactly as it always has (the region facts already say
    that address once) while a PE found partway into an allocation, which
    the region-base-only scan could not report at all (issue #26), never
    hides behind its region's address."""
    if location.region_offset == 0:
        return ""
    return f" PE_VA=0x{location.va:x} region_offset=0x{location.region_offset:x}"


def _pe_facts(pe: PeHeaderInfo) -> str:
    if pe.valid:
        return (f"PE header VALID: machine={pe.machine_name} "
                f"pe32plus={pe.is_pe32_plus} sections={pe.number_of_sections} "
                f"entrypoint_rva=0x{pe.address_of_entry_point:x} "
                f"declared_image_base=0x{pe.image_base:x}")
    return f"PE header INVALID ({pe.reason})"


# ── Per-check evidence-item -> fact-string dispatch ───────────────────────
# Keyed on CheckResult.check -- one renderer per check id, mirroring
# aggregate.build_report's own per-check Finding(...) construction blocks.
# "injection.rip_correlation_unavailable" is deliberately absent: its
# single fact is derived from coverage, not from an evidence item (see
# `_facts_for` below).

def _rwx_item_fact(ev, report: InjectionReport) -> str:
    return _region_facts(ev.region)


def _pe_item_fact(hit, report: InjectionReport) -> str:
    return (_region_facts(hit.region) + _pe_candidate_facts(hit.location)
            + "  |  " + _pe_facts(hit.pe))


def _thread_item_fact(ev, report: InjectionReport) -> str:
    return f"TID=0x{ev.thread_id:x} StartAddress=0x{(ev.start_address or 0):x}"


def _rip_item_fact(hit, report: InjectionReport) -> str:
    full = hit.region.allocation_base in report.evidence.correlation.rwx_and_pe_alloc_bases
    return (f"TID=0x{hit.thread_id:x} {hit.ip_reg}=0x{hit.ip:x} "
            f"-> {_region_facts(hit.region)}  {'[FULL: RWX+validated-PE]' if full else ''}")


def _correlated_alloc_item_fact(item, report: InjectionReport) -> str:
    return (f"AllocationBase=0x{item.allocation_base:x}  regions="
            f"{', '.join(f'0x{r.base_address:x}({r.type}/{r.protect})' for r in item.regions)}")


_FACT_ITEM_RENDERERS = {
    "injection.rwx_regions":                      _rwx_item_fact,
    "injection.hidden_pe_validated":               _pe_item_fact,
    "injection.hidden_pe_validated_context_only":  _pe_item_fact,
    "injection.mz_prefix_unvalidated":             _pe_item_fact,
    "injection.unbacked_thread_startaddress":      _thread_item_fact,
    "injection.allocation_correlation":            _rip_item_fact,
    "injection.structural_allocation_correlation": _correlated_alloc_item_fact,
}

_RIP_CORRELATION_UNAVAILABLE = "injection.rip_correlation_unavailable"


def _facts_for(result, report: InjectionReport) -> tuple:
    """`CheckResult.facts`'s replacement -- rendered from `result.evidence`
    (capped at `result.evidence_limit`, with a "... and N more" summary
    line appended when the cap trims anything, same policy aggregate.py's
    own `[:20]`/`[:10]` slices apply today) rather than stored as text.
    `rip_correlation_unavailable` is the one check whose single fact comes
    from the Report's own coverage snapshot, not from an evidence item --
    it legitimately carries no evidence (see CheckResult.evidence's own
    docstring)."""
    if result.check == _RIP_CORRELATION_UNAVAILABLE:
        return (f"thread_list_stream_present={report.coverage.thread_list_stream}",)
    renderer = _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        raise ValueError(
            f"report_facts: no fact renderer registered for check {result.check!r} -- "
            f"every injection check id must have one (see _FACT_ITEM_RENDERERS)")
    items = result.evidence
    limit = result.evidence_limit
    shown = items if limit is None else items[:limit]
    facts = [renderer(item, report) for item in shown]
    if limit is not None and len(items) > limit:
        facts.append(f"... and {len(items) - limit} more")
    return tuple(facts)


def finding_from_check_result(result, report: InjectionReport) -> Finding:
    """The transient compatibility `Finding` for one `CheckResult` -- built
    fresh on every call, never stored anywhere (see this module's own
    docstring). `report` is read-only context for the two checks whose
    rendering needs more than their own evidence tuple (see `_facts_for`);
    every other check's rendering ignores it entirely.

    Carries no `verbose_facts` -- that is `report_console.py`'s own
    normal/verbose detail POLICY to apply (see this module's own
    docstring), not a wire-shaped fact every projector needs."""
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

def project_coverage_v1(coverage: CoverageSnapshot) -> tuple:
    """`(coverage_dict, coverage_status, coverage_reasons)` -- the v1.1
    shape `aggregate.build_report` assembles (its own `coverage` dict plus
    `coverage_status`/`coverage_reasons`), reproduced fact-for-fact from
    `CoverageSnapshot`'s own fields rather than the raw stream booleans/
    counters `aggregate.py` closes over."""
    coverage_dict = {
        "memory_info_stream": coverage.memory_info_stream,
        "thread_info_stream": coverage.thread_info_stream,
        "module_list_stream": coverage.module_list_stream,
        "thread_list_stream": coverage.thread_list_stream,
        "thread_context":     coverage.thread_context,
        "threads_total":      coverage.threads_total,
        "contexts_parsed":    coverage.contexts_parsed,
        "contexts_missing":   coverage.contexts_missing,
    }
    reasons = []
    if not coverage.memory_info_stream:
        reasons.append("MemoryInfoListStream missing from this dump")
    if not coverage.thread_info_stream:
        reasons.append("ThreadInfoListStream missing from this dump")
    if not coverage.module_list_stream:
        reasons.append("ModuleListStream missing from this dump")
    if coverage.pe_read_failed:
        reasons.append(f"{coverage.pe_read_failed} region(s) failed to read while checking "
                        f"for hidden PE headers")
    if coverage.pe_short_reads:
        reasons.append(f"{coverage.pe_short_reads} region(s) returned fewer bytes than "
                        f"requested while checking for hidden PE headers "
                        f"(short read) — not fully examined")
    if coverage.pe_scan_truncated:
        reasons.append(f"{coverage.pe_scan_truncated} region(s) hit a hidden-PE scan budget "
                        f"before the candidate search reached the end of the region — the "
                        f"remainder was not searched")
    if coverage.pe_evidence_capped:
        reasons.append(f"{coverage.pe_evidence_capped} validated hidden PE header(s) were "
                        f"found but not retained (evidence cap) — the reported list is not "
                        f"exhaustive")
    if not coverage.thread_context:
        reasons.append("No per-thread CONTEXT (RIP/EIP) available — live-execution "
                        "correlation could not run")
    elif coverage.contexts_missing:
        reasons.append(f"{coverage.contexts_missing}/{coverage.threads_total} "
                        f"thread(s) had no parsed CONTEXT — live-execution correlation "
                        f"ran, but not for every thread")
    coverage_status = derive_coverage_status(coverage.evaluated, coverage.complete)
    return coverage_dict, coverage_status, reasons


def _observe_counted_source(name: str, present: bool, count: "int | None") -> SourceObservation:
    """The same absent/present_empty/present inference `observe_source`
    makes from an `items` list, without ever materializing one --
    `CoverageSnapshot` already stores the record COUNT directly (`None`
    meaning "the caller did not supply the underlying list", a distinct
    input from an empty list/`0`; see that type's own docstring), so
    there is no real list to build here, only a count to pass straight
    through. `observe_source(present=True, items=list(range(n)))` would
    reach the identical `SourceObservation`, but allocates an O(n)
    placeholder purely to let `observe_source` recover `len(items)` --
    wasted, and unbounded, work for a snapshot describing a genuinely
    large region/thread count."""
    if not present:
        return SourceObservation(name=name, state=SourceState.ABSENT, record_count=None)
    if not count:
        return SourceObservation(name=name, state=SourceState.PRESENT_EMPTY, record_count=0)
    return SourceObservation(name=name, state=SourceState.PRESENT, record_count=count)


def project_coverage_report(coverage: CoverageSnapshot) -> CoverageReport:
    """The structured v2.4 `CoverageReport` -- reproduces
    `aggregate.build_report`'s own `coverage_sources`/`completeness_checks`
    block from `CoverageSnapshot`'s fields instead of the raw
    `all_regions`/`thread_info_entries`/`module_list`/`thread_contexts`
    lists `aggregate.py` still has directly (this model deliberately does
    not retain those -- see CoverageSnapshot's own docstring on why it
    keeps only their counts)."""
    coverage_sources = {
        "memory_info": _observe_counted_source("memory_info", coverage.memory_info_stream,
                                                 coverage.region_count),
        "thread_info": _observe_counted_source("thread_info", coverage.thread_info_stream,
                                                 coverage.thread_info_count),
        "modules": _observe_counted_source("modules", coverage.module_list_stream,
                                            coverage.module_count),
        "thread_list": _observe_counted_source("thread_list", coverage.thread_list_stream,
                                                 coverage.threads_total),
        "thread_context": _observe_counted_source("thread_context", coverage.thread_context,
                                                    coverage.contexts_parsed),
        "hidden_pe_scan": observe_source("hidden_pe_scan", present=True, items=["scanned"]),
    }
    completeness_checks = [
        "memory_info",
        "thread_info",
        SourceRequirement(source="modules",
                           absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
    ]
    if coverage.pe_read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PE_HEADER_READ_FAILED, source="hidden_pe_scan",
            affected_count=coverage.pe_read_failed))
    if coverage.pe_short_reads:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PE_HEADER_SHORT_READ, source="hidden_pe_scan",
            affected_count=coverage.pe_short_reads))
    if coverage.pe_scan_truncated:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PE_HEADER_SCAN_TRUNCATED, source="hidden_pe_scan",
            affected_count=coverage.pe_scan_truncated))
    if coverage.pe_evidence_capped:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PE_HEADER_EVIDENCE_CAPPED, source="hidden_pe_scan",
            affected_count=coverage.pe_evidence_capped))
    completeness_checks.append(
        SourceRequirement(source="thread_context",
                           absent_code=LimitationCode.THREAD_CONTEXT_UNAVAILABLE))
    if coverage.thread_context and coverage.contexts_missing:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.THREAD_CONTEXT_PARTIAL, source="thread_context",
            affected_count=coverage.contexts_missing))
    return build_coverage_report(
        coverage_sources, evaluation_sources=("memory_info", "thread_info"),
        completeness_checks=completeness_checks)
