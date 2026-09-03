"""Shared fact and coverage projections for ``EncodingReport``.

Fact text and ordering remain stable for legacy output, typed records, and
finding identifiers. Verbose facts are console-only.
"""
from dumpex.hunt._coverage import (
    derive_coverage_status, UNACCOUNTED_LABEL, OVER_ACCOUNTED_LABEL, UNBALANCED_LABEL,
)
from dumpex.hunt._finding import Finding
from dumpex.hunt.encoding.domain import (
    OVERSIZE_SCAN_LAYERS, CoverageSnapshot, EncodingReport,
)
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, EvaluationRequirement, LimitationCode,
    build_coverage_report, format_scan_target_preview, observe_source, scan_target_noun,
)
from dumpex.output.records import hex_address

# This hunter's public coverage-source vocabulary -- the exact `sources`
# dict keys `project_coverage_report()` below builds. Extracted into a
# named constant (rather than left as inline dict-literal keys only) so
# `dumpex.hunt._registry.AnalyzerSpec` can validate a future
# `TargetedGrant.source` against a real, closed, importable vocabulary
# instead of an unenforced convention (docs/developer/hunt_analyzer_registry_contract.md
# §7.1 failure #5).
COVERAGE_SOURCE_NAMES = frozenset({"memory_info", "encoding_scan"})


# ── Fact-string builders ─────────────────────────────────────────────────
# The address-typed fields (`VA`, `container_VA` -- both the decode
# location's absolute address) go through the shared `hex_address()`
# helper, so a fact renders an address in the same fixed-width,
# zero-padded 16-hex-digit form as this hunter's `report_record.py` and
# `--json` `details`. `key`, `rotation_offset`, `entropy`, `threshold`,
# and `decoded_size` are not addresses and keep their existing form.

def _sleep_mask_item_fact(h, report: EncodingReport) -> str:
    return (f"VA={hex_address(h.location.va)} key={h.key.hex()} rotation_offset={h.key_offset} "
            f"decoded_type={h.classification.kind}")


def _entropy_item_fact(h, report: EncodingReport) -> str:
    extent = f" window_size={h.measured_size}" if h.size is not None else ""
    return (f"VA={hex_address(h.location.va)}{extent} entropy={h.entropy:.3f} threshold={h.threshold} "
            f"protect={h.region.protect}")


def _base64_item_fact(h, report: EncodingReport) -> str:
    return (f"VA={hex_address(h.location.va)} decoded_type={h.classification.kind} "
            f"decoded_size={len(h.decoded)}")


def _xor_item_fact(h, report: EncodingReport) -> str:
    return f"VA={hex_address(h.location.va)} key=0x{h.key:02x} decoded_type={h.classification.kind}"


def _compressed_item_fact(h, report: EncodingReport) -> str:
    return (f"VA={hex_address(h.location.va)} algo={h.layer} decoded_type={h.classification.kind} "
            f"decoded_size={len(h.decoded)}")


def _structural_pe_item_fact(h, report: EncodingReport) -> str:
    reg_str = "registered" if h.known_module else "UNREGISTERED"
    return (f"type=PE encoding={h.layer} container_VA={hex_address(h.location.va)} "
            f"module_status={reg_str} decoded_size={len(h.decoded)}"
            + ("" if h.complete else " decode=incomplete(output-cap)"))


def _shellcode_item_fact(h, report: EncodingReport) -> str:
    in_context = h in report.evidence.shellcode_context_hits
    return (f"type=shellcode_bootstrap encoding={h.layer} container_VA={hex_address(h.location.va)} "
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


def _read_failed_layer_reasons(coverage: CoverageSnapshot) -> list:
    """Read-failed companion to oversized_layer_reasons() -- one reason
    per layer, same "never a single summed one" rule (issue #28)."""
    return [f"{len(targets)} region(s) failed to read under the {layer} scan: "
            f"{format_scan_target_preview(targets)}"
            for layer, targets in coverage.read_failed_targets_by_layer()]


def _short_read_layer_reasons(coverage: CoverageSnapshot) -> list:
    """Short-read companion to oversized_layer_reasons() (issue #28)."""
    return [f"{len(targets)} region(s) returned fewer bytes than declared under the "
            f"{layer} scan (short read) — not fully scanned: "
            f"{format_scan_target_preview(targets)}"
            for layer, targets in coverage.short_read_targets_by_layer()]


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
    reasons.extend(_read_failed_layer_reasons(coverage))
    reasons.extend(_short_read_layer_reasons(coverage))
    if coverage.budget_exhausted:
        reasons.append(f"decode budget exhausted ({coverage.exhausted_reason})")
    # Last, one reason per LAYER (never a single summed one, the rule the
    # three gap-reason builders above already follow) and with no target
    # preview -- see `CoverageSnapshot`'s own ledger fields for why these
    # can never name what they lost.
    reasons.extend(f"{count} region(s) in the {layer} scan {UNACCOUNTED_LABEL}"
                   for layer, count in coverage.unaccounted_by_layer())
    reasons.extend(f"{count} region(s) in the {layer} scan {OVER_ACCOUNTED_LABEL}"
                   for layer, count in coverage.over_accounted_by_layer())
    reasons.extend(f"{count} region(s) in the {layer} scan {UNBALANCED_LABEL}"
                   for layer, count in coverage.imbalance_by_layer())
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
    for layer, targets in coverage.read_failed_targets_by_layer():
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="encoding_scan",
            scope=layer, affected_count=len(targets), targets=targets))
    for layer, targets in coverage.short_read_targets_by_layer():
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="encoding_scan",
            scope=layer, affected_count=len(targets), targets=targets))
    if coverage.budget_exhausted:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="encoding_scan",
            detail=coverage.exhausted_reason))
    # One limitation per layer, `scope` naming it -- the same shape the
    # three loops above use for their own per-layer gaps. Both ledger
    # directions land on the same code and are counted together: either
    # way, that many of this layer's regions have no trustworthy outcome.
    # No `targets`: see SCAN_ITEMS_UNACCOUNTED on LimitationCode.
    for layer, count in coverage.unreconciled_by_layer():
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_ITEMS_UNACCOUNTED, source="encoding_scan",
            scope=layer, affected_count=count))
    return build_coverage_report(
        sources, evaluation_sources=EvaluationRequirement(("memory_info",)),
        completeness_checks=completeness_checks,
        eligible_bytes=coverage.eligible_bytes,
        # This hunter is the one producer whose `scope` names a real scan
        # pass rather than a budget kind, and it walks the same regions
        # once per layer -- so its gaps have to be counted per layer, the
        # same way its scope total is.
        pass_scopes=OVERSIZE_SCAN_LAYERS)
