"""Shared projection logic for `EncodingReport` (dumpex/hunt/encoding/
domain.py) -- everything `report_legacy.py`, `report_record.py`, and
`report_console.py` all three need, so it is built exactly once. Mirrors
`dumpex.hunt.injection.report_facts` (the completed reference pilot): see
that module's own docstring for why `verbose_facts` is deliberately never
populated here (that policy belongs to `report_console.py` alone).

Every fact string below is written to match the pre-migration
`aggregate.py`'s inference/rationale/facts text byte-for-byte for the same
evidence, verified by tests/hunt/test_encoding_projectors.py's golden-
scenario parity test.
"""
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt._finding import Finding
from dumpex.hunt.encoding.domain import CoverageSnapshot, EncodingReport
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, EvaluationRequirement, LimitationCode,
    build_coverage_report, format_scan_target_preview, observe_source, scan_target_noun,
)


# ── Fact-string builders -- byte-identical to the pre-migration aggregate.py ──

def _sleep_mask_item_fact(h, report: EncodingReport) -> str:
    return (f"VA=0x{h.location.va:x} key={h.key.hex()} rotation_offset={h.key_offset} "
            f"decoded_type={h.classification.kind}")


def _entropy_item_fact(h, report: EncodingReport) -> str:
    return (f"VA=0x{h.location.va:x} entropy={h.entropy:.3f} threshold={h.threshold} "
            f"protect={h.region.protect}")


def _base64_item_fact(h, report: EncodingReport) -> str:
    return (f"VA=0x{h.location.va:x} decoded_type={h.classification.kind} "
            f"decoded_size={len(h.decoded)}")


def _xor_item_fact(h, report: EncodingReport) -> str:
    return f"VA=0x{h.location.va:x} key=0x{h.key:02x} decoded_type={h.classification.kind}"


def _compressed_item_fact(h, report: EncodingReport) -> str:
    return (f"VA=0x{h.location.va:x} algo={h.layer} decoded_type={h.classification.kind} "
            f"decoded_size={len(h.decoded)}")


def _structural_pe_item_fact(h, report: EncodingReport) -> str:
    reg_str = "registered" if h.known_module else "UNREGISTERED"
    return (f"type=PE encoding={h.layer} container_VA=0x{h.location.va:x} "
            f"module_status={reg_str} decoded_size={len(h.decoded)}"
            + ("" if h.complete else " decode=incomplete(output-cap)"))


def _shellcode_item_fact(h, report: EncodingReport) -> str:
    in_context = h in report.evidence.shellcode_context_hits
    return (f"type=shellcode_bootstrap encoding={h.layer} container_VA=0x{h.location.va:x} "
            f"decoded_size={len(h.decoded)} prefix={h.decoded[:6].hex()}"
            + (f" container_protect={h.region.protect} (executable+private)" if in_context else ""))


_FACT_ITEM_RENDERERS = {
    "obfuscation.sleep_mask_confirmed":       _sleep_mask_item_fact,
    "obfuscation.entropy_observation":        _entropy_item_fact,
    "obfuscation.base64_observation":         _base64_item_fact,
    "obfuscation.xor_observation":            _xor_item_fact,
    "obfuscation.compressed_observation":     _compressed_item_fact,
    "obfuscation.structural_payload":         _structural_pe_item_fact,
    "obfuscation.shellcode_bootstrap_lead":   _shellcode_item_fact,
}


def _facts_for(result, report: EncodingReport) -> tuple:
    """`CheckResult.facts`'s replacement -- rendered from `result.evidence`
    (capped at `result.evidence_limit`, with a "... and N more" summary
    line when the cap trims anything -- the same policy the pre-migration
    aggregate.py's own `[:20]`/`[:15]`/`[:10]` slices applied)."""
    renderer = _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        raise ValueError(
            f"report_facts: no fact renderer registered for check {result.check!r} -- "
            f"every obfuscation check id must have one (see _FACT_ITEM_RENDERERS)")
    items = result.evidence
    limit = result.evidence_limit
    shown = items if limit is None else items[:limit]
    facts = [renderer(item, report) for item in shown]
    if limit is not None and len(items) > limit:
        facts.append(f"... and {len(items) - limit} more")
    return tuple(facts)


def finding_from_check_result(result, report: EncodingReport) -> Finding:
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

def oversized_layer_reasons(coverage: CoverageSnapshot) -> list:
    """One reason string per scan LAYER that skipped something, never a
    single summed one -- see CoverageSnapshot.oversized_targets_by_layer's
    own docstring for why the layers must stay apart."""
    out = []
    for layer, targets in coverage.oversized_targets_by_layer():
        noun = scan_target_noun(targets)
        out.append(f"{len(targets)} oversized {noun} skipped by the {layer} scan: "
                    f"{format_scan_target_preview(targets)}")
    return out


def project_coverage_v1(coverage: CoverageSnapshot) -> tuple:
    """`(coverage_dict, coverage_status, coverage_reasons)` -- the v1.1
    shape the pre-migration `aggregate.build_report` assembled,
    reproduced fact-for-fact from `CoverageSnapshot`'s own fields."""
    coverage_dict = {
        "memory_info_stream": coverage.memory_info_stream,
    }
    reasons = []
    if not coverage.memory_info_stream:
        reasons.append("MemoryInfoListStream missing from this dump")
    if coverage.fully_skipped:
        reasons.append(f"all {coverage.region_count} region(s) filtered out by every layer's "
                        f"size/type limits — nothing was actually scanned")
    reasons.extend(oversized_layer_reasons(coverage))
    if coverage.read_failed:
        reasons.append(f"{coverage.read_failed} region(s) failed to read")
    if coverage.short_reads:
        reasons.append(f"{coverage.short_reads} region(s) returned fewer bytes than "
                        f"declared (short read) — not fully scanned")
    if coverage.budget_exhausted:
        reasons.append(f"decode budget exhausted ({coverage.exhausted_reason})")
    coverage_status = derive_coverage_status(coverage.evaluated, coverage.complete)
    return coverage_dict, coverage_status, reasons


def project_coverage_report(coverage: CoverageSnapshot) -> CoverageReport:
    """The structured v2.4+ `CoverageReport` -- reproduces the
    pre-migration `aggregate._encoding_coverage_report`'s own
    `sources`/`completeness_checks` block from `CoverageSnapshot`'s
    fields. `memory_info` is this hunter's ONLY evaluation_sources gate,
    matching `CoverageSnapshot.evaluated`."""
    sources = {
        "memory_info": observe_source("memory_info", present=coverage.memory_info_stream,
                                       items=["present"] if coverage.memory_info_stream else []),
        "encoding_scan": observe_source("encoding_scan", present=True, items=["scanned"]),
    }
    completeness_checks = []
    if coverage.fully_skipped:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.ENCODING_ALL_REGIONS_FILTERED, source="encoding_scan",
            affected_count=coverage.region_count))
    for layer, targets in coverage.oversized_targets_by_layer():
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="encoding_scan",
            scope=layer, affected_count=len(targets), targets=targets))
    if coverage.read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="encoding_scan",
            affected_count=coverage.read_failed))
    if coverage.short_reads:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="encoding_scan",
            affected_count=coverage.short_reads))
    if coverage.budget_exhausted:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="encoding_scan",
            detail=coverage.exhausted_reason))
    return build_coverage_report(
        sources, evaluation_sources=EvaluationRequirement(("memory_info",)),
        completeness_checks=completeness_checks)
