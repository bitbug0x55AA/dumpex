"""Shared projection logic for `CSBeaconReport` (dumpex/hunt/cs_beacon/
domain.py) -- everything `report_legacy.py`, `report_record.py`, and
`report_console.py` all three need, so it is built exactly once. Mirrors
`dumpex.hunt.hollowing.report_facts`/`dumpex.hunt.stomping.report_facts`/
`dumpex.hunt.pipe.report_facts`/`dumpex.hunt.injection.report_facts`/
`dumpex.hunt.encoding.report_facts` (the five completed reference pilots).

Every fact string below is written to match the pre-migration
`aggregate.build_report()`'s own `Finding.facts` text byte-for-byte for the
same evidence -- these arrays are embedded verbatim in BOTH the v1.1
findings dict and the typed `HunterRecord` (and feed `Finding.id`'s hash
basis), and tests/fixtures/hunt_cli_golden/cs-beacon_hunt_dict.json is
frozen against them.

This module owns no dependency on `dumpex.hunt.cs_beacon.aggregate`:
`build_report()` is the ONE place a `CSBeaconReport` is constructed, and
this module stays a pure function of that already-built Report.
"""
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt._finding import Finding
from dumpex.hunt.cs_beacon.domain import CSBeaconReport, CoverageSnapshot, ScanDiagnostics
from dumpex.hunt.cs_beacon.models import ConfigEvidence, CorroborationEvidence
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, EvaluationRequirement, LimitationCode,
    SourceRequirement, build_coverage_report, format_scan_target_preview, observe_source,
)


# ── Fact-string builders -- byte-identical to the pre-migration builder ───

def _hit_of(result) -> ConfigEvidence:
    return next(item for item in result.evidence if isinstance(item, ConfigEvidence))


def _corroboration_of(result) -> "CorroborationEvidence | None":
    return next((item for item in result.evidence if isinstance(item, CorroborationEvidence)),
                None)


def _structural_config_facts(result, report: CSBeaconReport) -> tuple:
    hit = _hit_of(result)
    region = hit.region
    facts = [f"VA=0x{hit.hit_va:x} file_offset=0x{hit.hit_fo:x} xor_key=0x{hit.xor_key:02x} "
             f"cs_version_estimated={hit.cs_version} field_count={len(hit.fields)}"]
    facts.append(f"region=0x{region.base_address:x} size=0x{region.size:x} "
                  f"protect={region.protect}"
                 if region is not None else
                 "enclosing region not covered by MemoryInfoListStream")
    return tuple(facts)


def _no_structural_config_facts(result, report: CSBeaconReport) -> tuple:
    coverage_status, coverage_reasons = project_coverage_v1(
        report.coverage, has_hits=False, any_corroborated=False)
    fact = f"{report.coverage.scan.segment_count} memory segment(s) scanned"
    if coverage_reasons:
        fact += f" ({', '.join(coverage_reasons)})"
    return (fact,)


_FACT_RENDERERS = {
    "cs_beacon.structural_config":    _structural_config_facts,
    "cs_beacon.no_structural_config": _no_structural_config_facts,
}


def _facts_for(result, report: CSBeaconReport) -> tuple:
    renderer = _FACT_RENDERERS.get(result.check)
    if renderer is None:
        raise ValueError(
            f"report_facts: no fact renderer registered for check {result.check!r} -- "
            f"every cs_beacon check id must have one (see _FACT_RENDERERS)")
    return renderer(result, report)


def finding_from_check_result(result, report: CSBeaconReport) -> Finding:
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

def _scan_reasons(scan: ScanDiagnostics) -> list:
    """The oversize/read-failed/short-read reasons -- byte-identical to
    `dumpex.hunt._coverage.CoverageTracker.build_reasons()`'s own rendering
    for the labels this hunter has always used, reproduced here because
    `ScanDiagnostics` is a frozen snapshot (tuples of `ScanTarget`), not a
    live `CoverageTracker`."""
    reasons = []
    if scan.skipped_oversize:
        reasons.append(f"{scan.skipped_oversize} oversized segment(s) skipped: "
                        f"{format_scan_target_preview(scan.skipped_oversize_targets)}")
    if scan.read_failed:
        preview = (f": {format_scan_target_preview(scan.read_failed_targets)}"
                   if scan.read_failed_targets else "")
        reasons.append(f"{scan.read_failed} segment(s) failed to read{preview}")
    if scan.short_reads:
        preview = (f": {format_scan_target_preview(scan.short_read_targets)}"
                   if scan.short_read_targets else "")
        reasons.append(f"{scan.short_reads} segment(s) returned fewer bytes than declared "
                        f"(short read) — not fully scanned{preview}")
    return reasons


def project_coverage_v1(coverage: CoverageSnapshot, *, has_hits: bool,
                         any_corroborated: bool) -> tuple:
    """`(coverage_status, coverage_reasons)` -- the v1.1 shape the
    pre-migration builder assembled inline, reproduced fact-for-fact from
    `CoverageSnapshot`'s own fields. Reason ORDER is part of the output
    contract and is preserved exactly: scan-tracker reasons, then the
    whole-scan budget reason (if a real gap), then the MemoryInfoListStream
    reason, then -- only when hits exist, none is already corroborated, and
    the thread-context picture is incomplete -- the ThreadListStream/
    partial-CONTEXT reason.
    """
    if not coverage.evaluated:
        return "not_evaluated", ["Memory64ListStream missing from this dump"]
    reasons = _scan_reasons(coverage.scan)
    if coverage.scan.has_real_budget_gap:
        reasons.append(f"scan resource budget exhausted ({coverage.scan.budget_reason}) — "
                        f"stopped before every segment/candidate was examined")
    if not coverage.mem_info_available:
        reasons.append("MemoryInfoListStream missing from this dump — region/"
                        "execution-context corroboration for any config hit "
                        "could not be verified")
    if has_hits and not any_corroborated and coverage.thread_context_gap:
        if not coverage.thread_list_stream_available:
            reasons.append("ThreadListStream missing from this dump — RIP/EIP-based "
                            "context corroboration could not run for any uncorroborated hit")
        else:
            reasons.append(f"{coverage.contexts_missing}/{coverage.threads_total} thread(s) "
                            f"had no parsed CONTEXT — RIP/EIP corroboration ran, but not for "
                            f"every thread, for a hit not otherwise corroborated")
    coverage_status = derive_coverage_status(True, coverage.complete(
        has_hits=has_hits, any_corroborated=any_corroborated))
    return coverage_status, reasons


def project_coverage_report(coverage: CoverageSnapshot, *, has_hits: bool = False,
                             any_corroborated: bool = False) -> CoverageReport:
    """The structured `dumpex.output.coverage.CoverageReport` for a
    cs-beacon run. Matches hollowing's/--peb's PEB_UNAVAILABLE-style
    precedent for the `not coverage.evaluated` branch: no memory segments
    at all -- a dedicated single-source not_evaluated case."""
    if not coverage.evaluated:
        sources = {"memory64_list": observe_source("memory64_list", present=False)}
        return build_coverage_report(
            sources, evaluation_sources=EvaluationRequirement(("memory64_list",)))

    scan = coverage.scan
    sources = {
        "memory_info": observe_source("memory_info", present=coverage.mem_info_available,
                                       items=["present"] if coverage.mem_info_available else []),
        "segment_scan": observe_source("segment_scan", present=True, items=["scanned"]),
        "thread_context": observe_source(
            "thread_context", present=coverage.contexts_parsed > 0,
            items=list(range(coverage.contexts_parsed))),
    }
    completeness_checks = ["memory_info"]
    if scan.skipped_oversize:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="segment_scan",
            affected_count=scan.skipped_oversize, targets=list(scan.skipped_oversize_targets)))
    if scan.read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="segment_scan",
            affected_count=scan.read_failed, targets=list(scan.read_failed_targets)))
    if scan.short_reads:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="segment_scan",
            affected_count=scan.short_reads, targets=list(scan.short_read_targets)))
    if scan.has_real_budget_gap:
        targets = list(scan.budget_exhausted_targets)
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED, source="segment_scan",
            detail=scan.budget_reason,
            affected_count=len(targets), targets=targets,
            scope=scan.budget_exhausted_kind,
            budget_limit=scan.budget_exhausted_limit,
            budget_consumed=scan.budget_exhausted_consumed))
    # top_tier_uncertain: only matters once hits exist and none is already
    # corroborated -- an uncorroborated hit's RIP/EIP-based top-tier
    # corroboration couldn't fully run.
    if has_hits and not any_corroborated:
        if not coverage.thread_list_stream_available:
            completeness_checks.append(SourceRequirement(
                source="thread_context", absent_code=LimitationCode.THREAD_CONTEXT_UNAVAILABLE))
        elif coverage.contexts_missing > 0:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.THREAD_CONTEXT_PARTIAL, source="thread_context",
                affected_count=coverage.contexts_missing))

    return build_coverage_report(sources, completeness_checks=completeness_checks)


# ── Public-output field sanitization (shared by report_legacy.py and ─────
# report_record.py; see each module's own docstring) ──────────────────────

def field_dict(f) -> dict:
    """One `models.ConfigField` -> the public `{"type", "value"}` shape --
    `raw`/`name` never reach a public dict (see models.py's own docstring
    on why `raw` is retained internally regardless)."""
    return {"type": f.type, "value": f.value.hex() if isinstance(f.value, bytes) else f.value}


def name_keyed_fields(hit: ConfigEvidence) -> dict:
    """`hit.fields` -> the schema_version 2.7 NAME-keyed public shape
    (`{"BeaconType": {...}, ...}`) -- raises on a field-name collision
    rather than silently overwriting the first field's entry (see
    dumpex/hunt/cs_beacon/collect.py's own pre-migration docstring for why
    this is checked explicitly)."""
    fields = {}
    for f in hit.fields:
        if f.name in fields:
            raise ValueError(
                f"cs-beacon field name collision: field ID 0x{f.field_id:04x} resolves to "
                f"{f.name!r}, which another field ID in this same config already used -- "
                f"CS_FIELD_NAMES must not map two different field IDs to the same name")
        fields[f.name] = field_dict(f)
    return fields
