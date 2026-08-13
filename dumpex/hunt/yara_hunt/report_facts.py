"""Shared projection logic for `domain.YaraReport` -- everything
`report_legacy.py`, `report_record.py`, and `report_console.py` all three
need, so it is built exactly once. Mirrors `dumpex.hunt.cs_beacon.
report_facts` (and, through it, the other completed reference pilots).

This module owns no dependency on `dumpex.hunt.yara_hunt.aggregate`:
`build_report()`/`build_not_evaluated_report()` are the only places a
`YaraReport` is constructed, and this module stays a pure function of an
already-built Report.
"""
from dumpex.hunt.yara_hunt.domain import CoverageSnapshot, ScanDiagnostics, YaraReport
from dumpex.hunt.yara_hunt.models import RuleMatchEvidence
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, EvaluationRequirement, LimitationCode,
    SourceRequirement, build_coverage_report, format_scan_target_preview, observe_source,
)
from dumpex.output.records import hex_address


# ── Console-facing coverage reasons (itemized -- see report_console.py's ──
# unified COVERAGE section) ────────────────────────────────────────────────

def _scan_reasons(scan: ScanDiagnostics) -> list:
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
    if scan.match_failed:
        preview = (f": {format_scan_target_preview(scan.match_failed_targets)}"
                   if scan.match_failed_targets else "")
        reasons.append(f"{scan.match_failed} match() call(s) failed{preview}")
    if scan.timed_out:
        preview = (f": {format_scan_target_preview(scan.timed_out_targets)}"
                   if scan.timed_out_targets else "")
        reasons.append(f"{scan.timed_out} match() call(s) timed out{preview}")
    if scan.truncated:
        reasons.append(f"hit cap reached ({scan.truncated_budget_limit} hits) — scan did not "
                        f"complete")
    if scan.has_real_budget_gap:
        reasons.append(f"scan resource budget exhausted ({scan.budget_exhausted_kind}) — "
                        f"stopped before every segment/rule-file pairing was examined")
    return reasons


def project_coverage_reasons(report: YaraReport) -> tuple:
    """`(coverage_status, reasons)` for the console's unified COVERAGE
    section -- reason ORDER: which prerequisite was missing (not-evaluated
    only), else rule-compile-failed, then scan-diagnostics reasons
    (oversize/read-failed/short-read/match-failed/timed-out), then hit-cap,
    then scan-budget, then -- only when hits exist and none was
    confidently classified -- the context-unverified count."""
    coverage = report.coverage
    if not coverage.evaluated:
        rules = coverage.rules
        if not rules.yara_available:
            return "not_evaluated", ["yara-python is not installed"]
        if rules.rules_dir is None:
            return "not_evaluated", ["no YARA rules directory found"]
        if rules.no_rule_files:
            return "not_evaluated", [f"no usable .yar/.yara files in {rules.rules_dir}"]
        return "not_evaluated", ["Memory64ListStream/MemoryListStream missing from this dump"]

    reasons = []
    if coverage.rules.compile_failed:
        reasons.append(f"{coverage.rules.compile_failed} rule file(s) failed to compile")
    reasons.extend(_scan_reasons(coverage.scan))
    if report.has_hits and not report.triggered_rules:
        reasons.append(f"{len(report.unverified_rules)} rule(s) matched but could not be "
                        f"classified (context_unverified)")
    return report.coverage_status, reasons


def project_coverage_report(report: YaraReport) -> CoverageReport:
    """The structured `dumpex.output.coverage.CoverageReport` -- matches
    the pre-migration `_yara_coverage_report()`'s own real
    dumpex.output.coverage.CoverageReport for a run that actually scanned,
    reusing the same `LimitationCode.YARA_*` codes."""
    coverage = report.coverage
    if not coverage.evaluated:
        sources = {"yara_scan": observe_source("yara_scan", present=False)}
        return build_coverage_report(
            sources, evaluation_sources=EvaluationRequirement(("yara_scan",)))

    scan = coverage.scan
    compile_failed = coverage.rules.compile_failed
    sources = {
        "yara_rules":   observe_source("yara_rules", present=True, items=["compiled"]),
        "segment_scan": observe_source("segment_scan", present=True, items=["scanned"]),
        "yara_context": observe_source("yara_context", present=True, items=["classified"]),
    }
    completeness_checks = []
    if compile_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.YARA_RULE_COMPILE_FAILED, source="yara_rules",
            affected_count=compile_failed))
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
    if scan.match_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.YARA_MATCH_FAILED, source="segment_scan",
            affected_count=scan.match_failed, targets=list(scan.match_failed_targets)))
    if scan.timed_out:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.YARA_MATCH_TIMED_OUT, source="segment_scan",
            affected_count=scan.timed_out, targets=list(scan.timed_out_targets)))
    if scan.truncated:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.YARA_HIT_CAP_REACHED, source="segment_scan",
            affected_count=len(scan.truncated_targets), targets=list(scan.truncated_targets),
            scope="max_total_hits", budget_limit=scan.truncated_budget_limit,
            budget_consumed=scan.truncated_budget_limit))
    if scan.has_real_budget_gap:
        targets = list(scan.budget_exhausted_targets)
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.YARA_SCAN_BUDGET_EXHAUSTED, source="segment_scan",
            affected_count=len(targets), targets=targets, scope=scan.budget_exhausted_kind,
            budget_limit=scan.budget_exhausted_limit, budget_consumed=scan.budget_exhausted_consumed))
    unverified_count = len(report.unverified_rules) if report.has_hits and not report.triggered_rules else 0
    if unverified_count:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.YARA_MATCH_CONTEXT_UNVERIFIED, source="yara_context",
            affected_count=unverified_count))

    return build_coverage_report(sources, completeness_checks=completeness_checks)


# ── v1.1 legacy `coverage` dict (7 booleans) -- unchanged shape ──────────

def legacy_coverage_dict(report: YaraReport) -> dict:
    scan = report.coverage.scan
    return {
        "rule_files_compiled": report.coverage.rules.compile_failed == 0,
        "segments_read":       scan.read_failed == 0,
        "segments_short_read": scan.short_reads == 0,
        "segments_size_ok":    scan.skipped_oversize == 0,
        "matches_completed":   scan.match_failed == 0 and scan.timed_out == 0,
        "hit_cap_not_reached": not scan.truncated,
        "scan_budget_ok":      not scan.has_real_budget_gap,
    }


# ── Public-output match shaping (shared by report_legacy.py and ─────────
# report_record.py; see each module's own docstring) ─────────────────────

def match_dict(m: RuleMatchEvidence, *, hex_va: bool) -> dict:
    """One `models.RuleMatchEvidence` -> a JSON-safe dict, in the EXACT
    pre-migration key set -- `rule`/`file`/`tags`/`meta`/`seg_va`/`seg_fo`/
    `seg_size`/`strings`/`context_unverified`/`memory_context`, no more, no
    fewer. `m.namespace`/`m.string_count`/`m.strings_truncated` are real
    facts the frozen domain model now carries (used by
    `report_console.py`'s own verbose rendering to make string-instance
    truncation visible -- issue #11's confirmed gap), but are deliberately
    NOT projected into this dict: issue #11's own Compatibility section
    preserves "current YaraDetails shape" and says "No public schema
    change occurs unless separately planned against the then-current
    schema" -- adding keys here, even additively, is exactly that kind of
    change, and belongs in its own planned/versioned follow-up, not as a
    side effect of a console-visibility fix.

    `hex_va=True` for the typed `HunterRecord` shape (VA fields become hex
    strings, per this project's own address-vs-offset type rule);
    `hex_va=False` for the v1.1 legacy shape (VA fields stay plain ints,
    unchanged from before this migration). Either way `strings[*].data`
    leaves Python `bytes` and becomes a hex string -- this is now the ONE
    place that sanitization happens, making the CLI dispatcher's post-
    render bytes->hex pass (`dumpex/hunt/__init__.py`) redundant, the same
    way issue #9 made CS Beacon's own dispatcher pass redundant.
    """
    va = (lambda v: hex_address(v)) if hex_va else (lambda v: v)
    return {
        "rule": m.rule, "file": m.file, "tags": list(m.tags), "meta": m.meta_dict(),
        "seg_va": va(m.seg_va), "seg_fo": m.seg_fo, "seg_size": m.seg_size,
        "strings": [{
            "var": s.var, "offset": s.offset, "va": va(s.va), "fo": s.fo,
            "data": s.data.hex(),
        } for s in m.strings],
        "context_unverified": m.context_unverified, "memory_context": m.memory_context,
    }
