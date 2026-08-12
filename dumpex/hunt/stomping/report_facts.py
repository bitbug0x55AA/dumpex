"""Shared projection logic for `StompingReport` (dumpex/hunt/stomping/
domain.py) -- everything `report_legacy.py`, `report_record.py`, and
`report_console.py` all three need, so it is built exactly once. Mirrors
`dumpex.hunt.injection.report_facts`/`dumpex.hunt.encoding.report_facts`
(the completed reference pilots): see those modules' own docstrings for
why `verbose_facts` is deliberately never populated here (that policy
belongs to `report_console.py` alone).

Every fact string below is written to match the pre-migration
`aggregate.py`'s inference/rationale/facts text byte-for-byte for the same
evidence, verified by tests/hunt/test_stomping_projectors.py's golden-
scenario parity test.

This module owns no dependency on `dumpex.hunt.stomping.aggregate`:
`build_report()` is the ONE place a `StompingReport` is constructed, and
this module stays a pure function of that already-built Report.
"""
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt._finding import Finding
from dumpex.hunt.stomping.domain import CoverageSnapshot, StompingReport
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, CoverageStatus, EvaluationRequirement, LimitationCode,
    SourceRequirement, build_coverage_report, observe_source,
)

# How many differing byte ranges one verified-change fact enumerates
# inline before it says how many more were kept -- a rendering cap on top
# of `config.MAX_DIFF_RANGES` (the display cap correlation.py already
# applied to `VerifiedChangeEvidence.diff_ranges` itself), reproduced from
# the pre-migration aggregate.py's own `[:5]` slice.
_RANGES_SHOWN_PER_FACT = 5


# ── Fact-string builders -- byte-identical to the pre-migration aggregate.py ──

def _module_name(module) -> str:
    """`(unnamed module)` for a module whose recorded path yielded no
    basename -- the wording the protection-deviation fact has always
    used. Two other checks use the shorter `(unnamed)`; see their own
    renderers."""
    return module.basename or "(unnamed module)"


def _protection_lead_fact(ev, report: StompingReport) -> str:
    return (f"module={_module_name(ev.module)} section={ev.section.name!r} "
            f"VA=0x{ev.region.base_address:x} declared={ev.expected} actual={ev.actual} "
            f"page_type={ev.region.type}")


def _rip_lead_fact(ev, report: StompingReport) -> str:
    lead, thread = ev.lead, ev.thread
    return (f"module={_module_name(lead.module)} section={lead.section.name!r} "
            f"VA=0x{lead.va_start:x}-0x{lead.va_end:x} "
            f"declared={lead.expected} actual={lead.actual} "
            f"TID=0x{thread.thread_id:x} {thread.ip_reg}=0x{thread.ip:x}")


def _verified_change_fact(vc, report: StompingReport) -> str:
    ranges_str = ", ".join(f"+0x{off:x}(len 0x{length:x})"
                            for off, length in vc.diff_ranges[:_RANGES_SHOWN_PER_FACT])
    if len(vc.diff_ranges) > _RANGES_SHOWN_PER_FACT:
        ranges_str += f", ... +{len(vc.diff_ranges) - _RANGES_SHOWN_PER_FACT} more shown"
    if vc.ranges_truncated:
        ranges_str += f" ({vc.total_ranges} total differing range(s), truncated for display)"
    live = "  [LIVE RIP/EIP inside changed range]" if vc.rip_in_changed_range else ""
    return (f"module={_module_name(vc.module)} section={vc.section.name!r} "
            f"VA=0x{vc.va_start:x} compared={vc.compared_len} bytes "
            f"changed_ranges=[{ranges_str}] "
            f"disk_sha256_prefix={vc.disk_sha256[:16]}… "
            f"mem_sha256_prefix={vc.mem_sha256[:16]}…{live}")


def _identity_mismatch_fact(ev, report: StompingReport) -> str:
    return (f"module={ev.module.basename or '(unnamed)'} section={ev.section.name!r} "
            f"reason={ev.reason}")


def _parse_failed_fact(ev, report: StompingReport) -> str:
    return (f"module={ev.module.basename or '(unnamed)'} "
            f"base=0x{ev.module.base_address:x} reason={ev.reason}")


def _ioc_hit_fact(ev, report: StompingReport) -> str:
    """One entry per REGION with a capped, deduped term list (built for
    --json). The per-TOKEN detail (absolute VA, encoding, weak/common-API
    classification) is console/--verbose-only -- see
    report_console.py's own `_ioc_verbose_fact`."""
    name = ev.module.basename if ev.module is not None else "(unknown)"
    terms = sorted({token.token for token in ev.tokens})[:8]
    return f"module={name} VA=0x{ev.region.base_address:x} terms={', '.join(terms)}"


_FACT_ITEM_RENDERERS = {
    "stomping.protection_deviation_lead":      _protection_lead_fact,
    "stomping.rip_in_anomalous_section_lead":  _rip_lead_fact,
    "stomping.verified_content_change":        _verified_change_fact,
    "stomping.reference_identity_mismatch":    _identity_mismatch_fact,
    "stomping.module_header_invalid":          _parse_failed_fact,
    "stomping.ioc_string_lead":                _ioc_hit_fact,
}

_PROTECTION_DEVIATION_LEAD = "stomping.protection_deviation_lead"


def _facts_for(result, report: StompingReport) -> tuple:
    """`CheckResult.facts`'s replacement -- rendered from `result.evidence`
    (capped at `result.evidence_limit`, with a "... and N more" summary
    line when the cap trims anything -- the same policy the pre-migration
    aggregate.py's own `[:20]`/`[:15]` slices applied).

    `stomping.protection_deviation_lead` is the one check that can
    legitimately carry NO evidence: its "no anomaly anywhere" form is a
    claim about the ABSENCE of a lead across everything checked, so its
    single fact comes from the Report's own coverage snapshot instead (see
    CheckResult.evidence's own docstring, and injection's
    `rip_correlation_unavailable` for the same shape)."""
    if result.check == _PROTECTION_DEVIATION_LEAD and not result.evidence:
        return (f"{report.coverage.headers_parsed} module(s) checked",)
    renderer = _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        raise ValueError(
            f"report_facts: no fact renderer registered for check {result.check!r} -- "
            f"every stomping check id must have one (see _FACT_ITEM_RENDERERS)")
    items = result.evidence
    limit = result.evidence_limit
    shown = items if limit is None else items[:limit]
    facts = [renderer(item, report) for item in shown]
    if limit is not None and len(items) > limit:
        facts.append(f"... and {len(items) - limit} more")
    return tuple(facts)


def finding_from_check_result(result, report: StompingReport) -> Finding:
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

def project_coverage_v1(coverage: CoverageSnapshot) -> tuple:
    """`(coverage_counts, coverage_status, coverage_reasons)` -- the v1.1
    shape the pre-migration `aggregate.build_report` assembled, reproduced
    fact-for-fact from `CoverageSnapshot`'s own named fields. The first
    element is the `coverage_counts` dict the findings dict has always
    carried, rebuilt fresh here (see CoverageSnapshot.coverage_counts) --
    the domain model cannot store it AS a dict and stay recursively
    immutable.

    Reason ORDER is part of the output contract (the verdict line used to
    join these verbatim) and is preserved exactly: stream absences first,
    then module-header failures, then either the "--ref-dir not supplied"
    blanket reason or the six per-section reference/diff failures, and
    finally the unscored IOC sub-scan's own gaps."""
    reasons = []
    if not coverage.memory_info_stream:
        reasons.append("MemoryInfoListStream missing from this dump")
    if not coverage.module_list_stream:
        reasons.append("ModuleListStream missing from this dump")
    if coverage.header_read_failed:
        reasons.append(f"{coverage.header_read_failed} module header read(s) failed")
    if coverage.header_parse_failed:
        reasons.append(f"{coverage.header_parse_failed} module header(s) failed PE "
                        f"structural validation")
    if not coverage.ref_dir_supplied:
        reasons.append("--ref-dir not supplied — verified content comparison "
                        "(the only scored signal) was not performed for any module")
    else:
        if coverage.reference_missing:
            reasons.append(f"{coverage.reference_missing} section(s) had no "
                            f"matching reference file under --ref-dir")
        if coverage.reference_mismatch:
            reasons.append(f"{coverage.reference_mismatch} section(s) had a "
                            f"reference file whose build identity didn't match")
        if coverage.reference_read_failed:
            reasons.append(f"{coverage.reference_read_failed} reference "
                            f"file(s) could not be read")
        if coverage.memory_read_failed:
            reasons.append(f"{coverage.memory_read_failed} section(s) could "
                            f"not be read from memory")
        if coverage.short_reads:
            reasons.append(f"{coverage.short_reads} section(s) had nothing "
                            f"comparable to read")
        if coverage.relocation_failed:
            reasons.append(f"{coverage.relocation_failed} section(s) needed "
                            f"relocation normalization that could not be completed "
                            f"(unsupported machine type or malformed relocation table)")
    # The unscored IOC-string sub-scan's own gaps are reported here too —
    # they are a real limit on what this hunter examined.
    reasons.extend(coverage.ioc_gap_reasons())
    coverage_status = derive_coverage_status(coverage.evaluated, coverage.complete)
    return coverage.coverage_counts(), coverage_status, reasons


def project_coverage_report(coverage: CoverageSnapshot) -> CoverageReport:
    """The structured `dumpex.output.coverage.CoverageReport` for a stomping
    run -- built at each gap site `project_coverage_v1` above already
    derives coverage_status/coverage_reasons from (never parsed back out of
    that free text; see docs/hunt_migration_field_matrix.md's own migration
    rule). Replaces the pre-migration `dumpex/hunt/stomping/__init__.py`'s
    `_stomping_coverage_report()`, which had to be called from OUTSIDE the
    aggregator and assigned onto the Report as a mutable attribute.

    `memory_info`/`modules` are each their OWN independent
    evaluation_groups entry (not one combined group) because stomping's
    real `evaluated` is AND-of-presence: EITHER one being absent alone is
    NOT_EVALUATED, unlike a combined group's OR-of-absence semantics (see
    comparison.py's own baseline.modules/target.modules precedent for the
    same pattern). `reference_files`/`module_headers`/
    `section_content_diff`/`ioc_string_scan` are synthetic sources (not
    real minidump streams), mirroring injection's own `hidden_pe_scan`
    pattern -- see dumpex.output.coverage's STOMPING_*/MODULE_HEADER_*
    codes.

    The `ioc_string_scan` limitations come from the UNSCORED IOC-string
    region scan: an eligible executable MEM_IMAGE region over
    config.IOC_SCAN_MAX (identified by ScanTarget, not merely counted), one
    whose read failed, or one that returned fewer bytes than declared. They
    downgrade coverage.status to "partial" like any other limitation -- see
    dumpex/hunt/stomping/__init__.py's package docstring for what that does
    and does not change about the hunter's verdict.

    These are appended to the report `build_coverage_report()` itself
    returns, AFTER that call, rather than folded into `completeness_checks`
    like every other gap here -- see the comment at the append site."""
    sources = {
        "memory_info": observe_source(
            "memory_info", present=coverage.memory_info_stream,
            items=["present"] if coverage.memory_info_stream else []),
        "modules": observe_source(
            "modules", present=coverage.module_list_stream,
            items=["present"] if coverage.module_list_stream else []),
        "module_headers": observe_source("module_headers", present=True, items=["scanned"]),
        "reference_files": observe_source(
            "reference_files", present=coverage.ref_dir_supplied,
            items=["supplied"] if coverage.ref_dir_supplied else []),
        "section_content_diff": observe_source("section_content_diff", present=True,
                                                items=["scanned"]),
        "ioc_string_scan": observe_source("ioc_string_scan", present=True, items=["scanned"]),
    }
    completeness_checks = []
    if coverage.header_read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.MODULE_HEADER_READ_FAILED, source="module_headers",
            affected_count=coverage.header_read_failed))
    if coverage.header_parse_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.MODULE_HEADER_PARSE_FAILED, source="module_headers",
            affected_count=coverage.header_parse_failed))
    if not coverage.ref_dir_supplied:
        completeness_checks.append(SourceRequirement(
            source="reference_files",
            absent_code=LimitationCode.STOMPING_REFERENCE_NOT_SUPPLIED))
    else:
        if coverage.reference_missing:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_REFERENCE_MISSING, source="reference_files",
                affected_count=coverage.reference_missing))
        if coverage.reference_mismatch:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_REFERENCE_MISMATCH, source="reference_files",
                affected_count=coverage.reference_mismatch))
        if coverage.reference_read_failed:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_REFERENCE_READ_FAILED, source="reference_files",
                affected_count=coverage.reference_read_failed))
        if coverage.memory_read_failed:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_SECTION_MEMORY_READ_FAILED,
                source="section_content_diff", affected_count=coverage.memory_read_failed))
        if coverage.short_reads:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_SHORT_READ, source="section_content_diff",
                affected_count=coverage.short_reads))
        if coverage.relocation_failed:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_RELOCATION_FAILED, source="section_content_diff",
                affected_count=coverage.relocation_failed))

    report = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("memory_info",)),
                           EvaluationRequirement(("modules",))],
        completeness_checks=completeness_checks)

    # The IOC-string scan's own gaps are appended to the ALREADY-BUILT
    # report, never folded into `completeness_checks` above like every
    # other gap in this function. Reason: scan_ioc_strings() only needs
    # MemoryInfoListStream (it does its own module lookup per-region via
    # addr_to_module(), tolerating an empty/absent module list) -- so it
    # can run, and find a REAL oversized/short/failed region, even when
    # `modules` is ABSENT and the "modules" evaluation_groups member above
    # fires build_coverage_report()'s own NOT_EVALUATED short-circuit.
    # That short-circuit unconditionally drops every pre-built
    # CoverageLimitation passed in `completeness_checks` (see its own
    # comment: "a pre-built business fact never applies when nothing was
    # evaluated") -- correct for every OTHER gap here, whose own scan
    # never ran without `modules`/`memory_info`, but wrong for this one.
    # Appending here instead means: hunter-level `status` is untouched
    # (still NOT_EVALUATED when the core module/section walk genuinely
    # couldn't run -- see CoverageSnapshot.evaluated, which this does not
    # change), while the one gap this scan actually observed is never
    # silently dropped from --json purely because a DIFFERENT part of the
    # hunter had nothing to evaluate. `status` and `coverage.status`
    # staying literally NOT_EVALUATED here, alongside a real limitation
    # entry, mirrors the same shape build_coverage_report() itself already
    # uses for a FAILED (not ABSENT) completeness-check source under this
    # exact short-circuit -- an established precedent for "not evaluated
    # overall, but this one fact still gets surfaced", not a new exception
    # invented here.
    ioc_limitations = []
    if coverage.ioc_oversized:
        ioc_limitations.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="ioc_string_scan",
            affected_count=len(coverage.ioc_oversized),
            targets=coverage.ioc_oversized))
    if coverage.ioc_read_failed:
        ioc_limitations.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="ioc_string_scan",
            affected_count=coverage.ioc_read_failed, targets=coverage.ioc_read_failed_targets))
    if coverage.ioc_short_reads:
        ioc_limitations.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="ioc_string_scan",
            affected_count=coverage.ioc_short_reads, targets=coverage.ioc_short_read_targets))
    if not ioc_limitations:
        return report

    status = (CoverageStatus.PARTIAL if report.status == CoverageStatus.COMPLETE
              else report.status)
    return CoverageReport(status=status, sources=report.sources,
                           limitations=[*report.limitations, *ioc_limitations])
