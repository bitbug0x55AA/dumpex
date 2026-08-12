"""Unit tests for dumpex.hunt.summary_presentation.render_hunt_summary() --
the --hunt all HUNT SUMMARY card. Built from tests/fixtures/hunt_records.py's
synthetic HunterRecord fixtures (no FakeMF/real scan needed) plus the real
dumpex.hunt.summary.build_hunt_summary() reducer, so these are true
end-to-end tests of "HunterRecord in, printed card out" with no legacy
`results` dict anywhere in the loop.
"""
import contextlib
import dataclasses
import io
import re

import pytest

from dumpex.hunt.summary import build_hunt_summary
from dumpex.hunt.summary_presentation import render_hunt_summary
from dumpex.hunt.region_correlation import RegionSignal, RegionCorrelation
from dumpex.hunt._finding import Finding, TAG_DETECTION, TAG_LEAD, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM
from dumpex.hunt._investigation import (
    InvestigationAction, SkipRelationship, TriageInfo, RecommendedAction, ContentFinding,
)
from dumpex.output.coverage import (
    CoverageReport, CoverageStatus, CoverageLimitation, LimitationCode, ScanTarget, ScanTargetKind,
)
from dumpex.output.records import HUNTERS
from tests.fixtures.hunt_records import (
    injection_detected, hollowing_not_evaluated, stomping_inconclusive,
    pipe_clean, yara_detected, all_seven_detected_variety, all_seven_not_evaluated,
)


def _capture(records, summary, doc_coverage_status="complete", width=100, region_correlations=None,
             investigation_actions=None, verbose=False):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_hunt_summary(records, summary, doc_coverage_status, width=width,
                             region_correlations=region_correlations,
                             investigation_actions=investigation_actions, verbose=verbose)
    return buf.getvalue()


def _collapse_ws(text: str) -> str:
    """Join wrapped lines back into one run of text so a substring
    assertion doesn't depend on exactly where `wrap_text` happened to
    insert a line break."""
    return " ".join(text.split())


def _all_clean_records():
    return [
        dataclasses.replace(r, status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
                             verdict_level="clean",
                             confidence=None if r.hunter == "yara" else "none",
                             lead_count=None if r.hunter == "yara" else 0,
                             review_priority=None if r.hunter == "yara" else "none",
                             coverage=CoverageReport(status=CoverageStatus.COMPLETE), findings=[])
        for r in all_seven_detected_variety()
    ]


# ── all NOT_EVALUATED ────────────────────────────────────────────────────

def test_all_not_evaluated_lands_entirely_in_needs_attention():
    records = all_seven_not_evaluated()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, doc_coverage_status="not_evaluated")
    assert "REVIEW FIRST" not in out
    assert "OTHER HUNTERS" not in out
    assert "NEEDS ATTENTION" in out
    for name in ("Process Injection", "Process Hollowing", "Module Stomping",
                 "Named Pipe C2 / Lat. Move.", "Cobalt Strike Beacon", "YARA Rules",
                 "Obfuscation Detection"):
        assert name in out
    assert "NOT EVALUATED" in out.upper()


# ── all clean ─────────────────────────────────────────────────────────────

def test_all_clean_lands_entirely_in_other_hunters():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    assert "REVIEW FIRST" not in out
    assert "NEEDS ATTENTION" not in out
    assert "OTHER HUNTERS" in out
    assert "No further action required" in out


# ── one HIGH detection ────────────────────────────────────────────────────

def test_single_high_detection_appears_in_review_first():
    records = _all_clean_records()
    records[0] = injection_detected()   # HUNTERS[0] == "injection"
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    assert "REVIEW FIRST" in out
    assert "Process Injection" in out.split("REVIEW FIRST")[1].split("NEEDS ATTENTION")[0] \
        if "NEEDS ATTENTION" in out else "Process Injection" in out.split("REVIEW FIRST")[1]
    assert "HIGH" in out


# ── multiple detections sort stably (descending) ──────────────────────────

def test_multiple_detections_sorted_descending_with_stable_tiebreak():
    records = all_seven_detected_variety()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    review_first_body = out.split("REVIEW FIRST", 1)[1].split("NEEDS ATTENTION", 1)[0]
    # injection (high/high/high) and cs-beacon (high/high/high) tie on
    # every judgment field -- HUNTERS' own order (injection before
    # cs-beacon) is the deterministic tie-break; yara (high verdict, but
    # null confidence/review_priority -- ranked lowest) comes after both;
    # obfuscation (verdict "likely", strictly below "high") comes last.
    order = [name for name in
             ("Process Injection", "Cobalt Strike Beacon", "YARA Rules", "Obfuscation Detection")
             if name in review_first_body]
    idxs = [review_first_body.index(name) for name in order]
    assert idxs == sorted(idxs), f"REVIEW FIRST order was not descending: {order}"
    assert order == ["Process Injection", "Cobalt Strike Beacon", "YARA Rules", "Obfuscation Detection"]


def test_review_first_order_is_reproducible_across_calls():
    records = all_seven_detected_variety()
    summary = build_hunt_summary(records, selected="all")
    out1 = _capture(records, summary)
    out2 = _capture(records, summary)
    assert out1 == out2


# ── clean-with-leads ──────────────────────────────────────────────────────

def test_clean_hunter_with_leads_lands_in_needs_attention_not_other():
    base = pipe_clean()
    leaded = dataclasses.replace(base, lead_count=2, review_priority="low")
    records = _all_clean_records()
    records[HUNTERS.index("pipe")] = leaded
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    needs_attention_body = out.split("NEEDS ATTENTION", 1)[1].split("OTHER HUNTERS", 1)[0] \
        if "OTHER HUNTERS" in out else out.split("NEEDS ATTENTION", 1)[1]
    assert "Named Pipe C2 / Lat. Move." in needs_attention_body
    assert "2 unscored lead" in needs_attention_body
    other_body = out.split("OTHER HUNTERS", 1)[1] if "OTHER HUNTERS" in out else ""
    assert "Named Pipe C2" not in other_body


# ── DETECTED + partial coverage ────────────────────────────────────────────

def test_detected_with_partial_coverage_shows_partial_badge_and_next_step():
    limitation = CoverageLimitation(code=LimitationCode.PE_HEADER_READ_FAILED,
                                     source="hidden_pe_scan", affected_count=3)
    partial_coverage = CoverageReport(status=CoverageStatus.PARTIAL, limitations=[limitation])
    reason_text = partial_coverage.reasons[0]

    record = dataclasses.replace(injection_detected(), coverage=partial_coverage)
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = record
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)

    review_first_body = out.split("REVIEW FIRST", 1)[1]
    assert "PARTIAL" in review_first_body.split("\n\n")[0] or "PARTIAL" in review_first_body[:200]
    next_investigation = out.split("NEXT INVESTIGATION", 1)[1]
    assert _collapse_ws(reason_text) in _collapse_ws(next_investigation)


# ── INCONCLUSIVE ──────────────────────────────────────────────────────────

def test_inconclusive_hunter_lands_in_needs_attention():
    records = _all_clean_records()
    records[HUNTERS.index("stomping")] = stomping_inconclusive()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, doc_coverage_status="partial")
    needs_attention_body = out.split("NEEDS ATTENTION", 1)[1]
    assert "Module Stomping" in needs_attention_body
    assert "Inconclusive:" in needs_attention_body


# ── yara nullable fields ───────────────────────────────────────────────────

def test_yara_null_confidence_and_review_priority_do_not_crash():
    records = _all_clean_records()
    records[HUNTERS.index("yara")] = yara_detected()   # confidence=None, review_priority=None
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)   # must not raise
    assert "YARA Rules" in out


def test_yara_not_evaluated_headline_uses_rules_hit_not_findings():
    records = all_seven_not_evaluated()
    yara_record = records[HUNTERS.index("yara")]
    assert yara_record.findings == []   # contract: yara never populates the shared Finding model
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, doc_coverage_status="not_evaluated")
    assert "YARA Rules" in out   # renders without needing a Finding at all


# ── long hunter name doesn't break column alignment ────────────────────────

def test_long_hunter_name_column_alignment_preserved():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    other_lines = [l for l in out.split("OTHER HUNTERS", 1)[1].splitlines()
                    if l.strip() and "CLEAN" in l]
    # every OTHER HUNTERS line's CLEAN badge must start at the same column,
    # regardless of how short/long that row's own hunter name is (padded to
    # the longest known display name, "Named Pipe C2 / Lat. Move.").
    clean_cols = {l.index("CLEAN") for l in other_lines}
    assert len(clean_cols) == 1, f"CLEAN badges not column-aligned: {other_lines}"


# ── top inference comes from a real Finding, not re-derived ───────────────

def test_review_first_headline_is_the_actual_finding_inference():
    distinctive = Finding(check="injection.allocation_correlation",
                           facts=["VA=0x1"], inference="THE UNIQUE DISTINCTIVE INFERENCE TEXT",
                           confidence=CONFIDENCE_HIGH, rationale="because", tag=TAG_DETECTION).to_dict()
    record = dataclasses.replace(injection_detected(), findings=[distinctive])
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = record
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    assert "THE UNIQUE DISTINCTIVE INFERENCE TEXT" in out


def test_review_first_headline_prefers_detection_over_lead():
    lead = Finding(check="injection.rwx_regions", facts=[], inference="LEAD INFERENCE TEXT",
                    confidence=CONFIDENCE_MEDIUM, rationale="r", tag=TAG_LEAD).to_dict()
    detection = Finding(check="injection.allocation_correlation", facts=[],
                         inference="DETECTION INFERENCE TEXT", confidence=CONFIDENCE_HIGH,
                         rationale="r", tag=TAG_DETECTION).to_dict()
    record = dataclasses.replace(injection_detected(), findings=[lead, detection])
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = record
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    assert "DETECTION INFERENCE TEXT" in out
    assert "LEAD INFERENCE TEXT" not in out


# ── coverage reason comes from a real CoverageReport ───────────────────────

def test_needs_attention_reason_is_the_real_coverage_report_text():
    limitation = CoverageLimitation(code=LimitationCode.PE_HEADER_READ_FAILED,
                                     source="hidden_pe_scan", affected_count=7)
    cov = CoverageReport(status=CoverageStatus.NOT_EVALUATED, limitations=[limitation])
    reason_text = cov.reasons[0]
    record = dataclasses.replace(hollowing_not_evaluated(), coverage=cov)
    records = _all_clean_records()
    records[HUNTERS.index("hollowing")] = record
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, doc_coverage_status="partial")
    assert _collapse_ws(reason_text) in _collapse_ws(out)


# ── Overall matches build_hunt_summary() exactly ───────────────────────────

def test_overall_status_matches_build_hunt_summary_exactly():
    records = all_seven_detected_variety()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    assert summary["overall_status"].replace("_", " ") in out


# ── renderer never reads legacy `results` ──────────────────────────────────

def test_render_hunt_summary_signature_has_no_legacy_results_parameter():
    import inspect
    params = set(inspect.signature(render_hunt_summary).parameters)
    assert "results" not in params
    assert params == {"records", "summary", "doc_coverage_status", "width", "region_correlations",
                       "investigation_actions", "deep_triage_diagnostics", "verbose"}


def test_rejects_non_hunter_record_list():
    with pytest.raises(TypeError):
        render_hunt_summary([{"hunter": "injection"}],
                             {"overall_status": "DETECTED", "highest_verdict_level": "high",
                              "detected_count": 1, "lead_count": 0, "inconclusive_count": 0,
                              "not_evaluated_count": 0, "hunter_count": 1},
                             "complete")


# ── NEXT INVESTIGATION stays generic / structurally derived ────────────────

_ATTCK_TECHNIQUE_RE = re.compile(r"\bT\d{4}(\.\d{3})?\b")


def test_next_investigation_never_invents_attck_or_malware_family_terms():
    records = all_seven_detected_variety()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    next_investigation = out.split("NEXT INVESTIGATION", 1)[1]
    # none of the synthetic fixtures attach technique_ids -- an ATT&CK id
    # appearing in NEXT INVESTIGATION would mean it was invented, not read
    # off a real Finding.
    assert not _ATTCK_TECHNIQUE_RE.search(next_investigation)


def test_next_investigation_names_only_hunters_present_in_input():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary)
    next_investigation = out.split("NEXT INVESTIGATION", 1)[1]
    for hunter_name in ("Process Hollowing", "Module Stomping", "Named Pipe C2 / Lat. Move.",
                         "Cobalt Strike Beacon", "YARA Rules", "Obfuscation Detection"):
        # none of the OTHER (clean) hunters should be singled out by name
        # in the generic action list
        assert hunter_name not in next_investigation


# ── CORRELATED REGIONS ────────────────────────────────────────────────────

def _two_hunter_correlation(region_base=0x1f400120000, region_size=0x10000,
                             allocation_base=0x1f400120000):
    signals = (
        RegionSignal(hunter="injection", kind="hidden_pe_validated",
                     label="validated hidden PE", address=region_base,
                     region_base=region_base, region_size=region_size,
                     allocation_base=allocation_base),
        RegionSignal(hunter="injection", kind="rip_hit",
                     label="live RIP/EIP in suspicious region", address=region_base,
                     region_base=region_base, region_size=region_size,
                     allocation_base=allocation_base),
        RegionSignal(hunter="cs-beacon", kind="valid_config",
                     label="structurally valid Beacon config", address=region_base,
                     region_base=region_base, region_size=region_size,
                     allocation_base=allocation_base),
        RegionSignal(hunter="cs-beacon", kind="context_corroborated",
                     label="context corroborated", address=region_base,
                     region_base=region_base, region_size=region_size,
                     allocation_base=allocation_base),
        RegionSignal(hunter="yara", kind="rule_hit", label="RuleA, RuleB", address=region_base,
                     region_base=region_base, region_size=region_size,
                     allocation_base=allocation_base),
    )
    return RegionCorrelation(region_base=region_base, region_size=region_size,
                              allocation_base=allocation_base, signals=signals,
                              hunters=("injection", "cs-beacon", "yara"))


def test_correlated_regions_appears_when_correlations_present():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, region_correlations=[_two_hunter_correlation()])
    assert "CORRELATED REGIONS" in out


def test_correlated_regions_absent_when_no_correlations():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out_without = _capture(records, summary)
    out_with_empty = _capture(records, summary, region_correlations=[])
    assert "CORRELATED REGIONS" not in out_without
    assert "CORRELATED REGIONS" not in out_with_empty
    # Passing region_correlations=None/[] must not otherwise change a
    # single byte of the rest of the card.
    assert out_without == out_with_empty


def test_correlated_regions_section_is_between_other_hunters_and_next_investigation():
    records = _all_clean_records()   # everything clean -> lands in OTHER HUNTERS
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, region_correlations=[_two_hunter_correlation()])
    other_idx = out.index("OTHER HUNTERS")
    correlated_idx = out.index("CORRELATED REGIONS")
    next_idx = out.index("NEXT INVESTIGATION")
    assert other_idx < correlated_idx < next_idx


def test_correlated_regions_shows_hunter_names_evidence_and_address():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    corr = _two_hunter_correlation()
    out = _capture(records, summary, region_correlations=[corr])
    block = out.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert "Process Injection" in block
    assert "Cobalt Strike Beacon" in block
    assert "YARA Rules" in block
    assert "validated hidden PE" in block
    assert "structurally valid Beacon config" in block
    assert "context corroborated" in block
    assert "RuleA, RuleB" in block
    assert f"0x{corr.region_base:016x}" in block
    assert f"0x{corr.allocation_base:016x}" in block
    assert f"size=0x{corr.region_size:x}" in block


def test_correlated_regions_contains_colocation_disclaimer_once():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    corr1 = _two_hunter_correlation(region_base=0x1000, region_size=0x1000, allocation_base=0x1000)
    corr2 = _two_hunter_correlation(region_base=0x2000, region_size=0x1000, allocation_base=0x2000)
    out = _capture(records, summary, region_correlations=[corr1, corr2])
    block = out.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert block.count("does not change hunter scores or verdicts") == 1


def test_correlated_regions_wraps_at_narrow_width_without_breaking_indent():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, region_correlations=[_two_hunter_correlation()], width=80)
    block = out.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    for line in block.splitlines():
        if line.strip():
            assert len(re.sub(r"\x1b\[[0-9;]*m", "", line)) <= 80


def test_correlated_regions_never_emits_decoded_or_raw_bytes():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, region_correlations=[_two_hunter_correlation()])
    block = out.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    for banned in ("decoded", "raw_bytes", "fields", "BeaconType", "c2_host"):
        assert banned not in block


def test_render_hunt_summary_rejects_invalid_region_correlations_type():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    with pytest.raises(TypeError):
        _capture(records, summary, region_correlations=[{"not": "a RegionCorrelation"}])


def test_correlated_regions_are_capped_with_an_omission_notice():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    many = [_two_hunter_correlation(region_base=0x1000 * i, region_size=0x1000,
                                     allocation_base=0x1000 * i) for i in range(1, 26)]
    out = _capture(records, summary, region_correlations=many)
    block = out.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    # Only the cap's worth of numbered entries are printed...
    assert "  20. Region" in block
    assert "  21. Region" not in block
    # ...and the omission is stated explicitly, not silently dropped.
    assert "5 additional correlated region(s) omitted" in block


# ── SKIPPED TARGET ACTIONS (issue #19) ───────────────────────────────────

def _action(base=0x1f400130000, size=20 * 1024 * 1024, priority="high",
            reason_codes=("PRIVATE_EXECUTABLE_MEMORY", "MULTIPLE_SCOPES_SKIPPED"),
            skipped_by=None, evidence_availability="captured", high_action=True):
    t = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base, size=size,
                    size_limit=8 * 1024 * 1024,
                    file_offset=(123 if evidence_availability == "captured" else None),
                    allocation_base=base, state="MEM_COMMIT", type="MEM_PRIVATE",
                    protection="PAGE_EXECUTE_READWRITE")
    skipped_by = skipped_by or (
        SkipRelationship(hunter="pipe", source="pipe_name_scan", size_limit=8 * 1024 * 1024),
        SkipRelationship(hunter="obfuscation", source="encoding_scan", scope="entropy",
                          size_limit=10 * 1024 * 1024),
    )
    actions = [RecommendedAction(type="inspect_metadata")]
    if evidence_availability == "captured":
        actions.append(RecommendedAction(type="extract_captured_range"))
    else:
        actions.append(RecommendedAction(type="recollect_dump"))
    actions.append(RecommendedAction(type="targeted_hunter_rescan", hunters=("pipe", "obfuscation")))
    if priority == "high" and high_action:
        actions.append(RecommendedAction(type="preserve_artifact"))
    return InvestigationAction(
        target=t, skipped_by=tuple(skipped_by), priority=priority,
        priority_reason_codes=tuple(reason_codes), evidence_availability=evidence_availability,
        triage=TriageInfo(), recommended_actions=tuple(actions))


def test_skipped_target_actions_appears_when_actions_present():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, investigation_actions=[_action()])
    assert "SKIPPED TARGET ACTIONS" in out


def test_skipped_target_actions_absent_when_no_actions():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    out_without = _capture(records, summary)
    out_with_empty = _capture(records, summary, investigation_actions=[])
    assert "SKIPPED TARGET ACTIONS" not in out_without
    assert "SKIPPED TARGET ACTIONS" not in out_with_empty
    assert out_without == out_with_empty


def test_skipped_target_actions_section_is_between_correlated_regions_and_next_investigation():
    records = _all_clean_records()
    records[HUNTERS.index("injection")] = injection_detected()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, region_correlations=[_two_hunter_correlation()],
                    investigation_actions=[_action()])
    correlated_idx = out.index("CORRELATED REGIONS")
    skipped_idx = out.index("SKIPPED TARGET ACTIONS")
    next_idx = out.index("NEXT INVESTIGATION")
    assert correlated_idx < skipped_idx < next_idx


def test_skipped_target_actions_shows_address_priority_and_skipped_by():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    action = _action()
    out = _capture(records, summary, investigation_actions=[action])
    block = out.split("SKIPPED TARGET ACTIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert f"0x{action.target.base_address:016x}" in block
    assert "HIGH" in block
    assert "pipe/pipe_name_scan" in block
    assert "obfuscation/encoding_scan:entropy" in block


def test_skipped_target_actions_shows_the_skip_cause_per_relationship():
    # issue #28: hunter/source/scope alone can't say WHY a target was
    # skipped -- the console now shows the cause alongside each entry.
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    action = _action(skipped_by=(
        SkipRelationship(hunter="pipe", source="pipe_name_scan", cause="read_failed"),
        SkipRelationship(hunter="injection", source="hidden_pe_scan", cause="scan_truncated"),
    ))
    out = _capture(records, summary, investigation_actions=[action])
    block = out.split("SKIPPED TARGET ACTIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert "pipe/pipe_name_scan (read failed)" in block
    assert "injection/hidden_pe_scan (scan truncated)" in block


def test_skipped_target_actions_why_fallback_no_longer_says_oversized_unconditionally():
    # With no priority_reason_codes (a LOW-priority, single-relationship
    # target), the "Why:" fallback used to hardcode "oversized target
    # skipped" -- wrong once a read-failed/short-read/scan-truncated
    # target can land here too (issue #28).
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    action = _action(priority="low", reason_codes=(), high_action=False,
                      skipped_by=(SkipRelationship(hunter="pipe", source="pipe_name_scan",
                                                    cause="read_failed"),))
    out = _capture(records, summary, investigation_actions=[action])
    block = out.split("SKIPPED TARGET ACTIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert "Why: target not fully examined -- see Skipped by" in block
    assert "oversized target skipped" not in block


def test_skipped_target_actions_non_verbose_caps_entries_with_omission_notice():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    many = [_action(base=0x1000 * i) for i in range(1, 8)]
    out = _capture(records, summary, investigation_actions=many)
    block = out.split("SKIPPED TARGET ACTIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    for a in many[:5]:
        assert f"0x{a.target.base_address:016x}" in block
    for a in many[5:]:
        assert f"0x{a.target.base_address:016x}" not in block
    assert "2 additional skipped-target action(s) omitted" in block


def test_skipped_target_actions_verbose_shows_every_entry():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    many = [_action(base=0x1000 * i) for i in range(1, 8)]
    out = _capture(records, summary, investigation_actions=many, verbose=True)
    block = out.split("SKIPPED TARGET ACTIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    for a in many:
        assert f"0x{a.target.base_address:016x}" in block
    assert "omitted" not in block


def test_skipped_target_actions_verbose_only_changes_presentation_not_json():
    """The issue's own hard requirement: --verbose must not change the
    underlying investigation_actions list or its order -- only how much
    of each already-computed entry the console shows."""
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    actions = [_action(base=0x2000 * i) for i in range(1, 4)]
    before = [a.to_dict() for a in actions]
    _capture(records, summary, investigation_actions=actions, verbose=True)
    after = [a.to_dict() for a in actions]
    assert before == after


def test_render_hunt_summary_rejects_invalid_investigation_actions_type():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    with pytest.raises(TypeError):
        _capture(records, summary, investigation_actions=[{"not": "an InvestigationAction"}])


def test_skipped_target_actions_wraps_at_narrow_width_without_breaking():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    out = _capture(records, summary, investigation_actions=[_action()], width=80)
    block = out.split("SKIPPED TARGET ACTIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    for line in block.splitlines():
        if line.strip():
            assert len(re.sub(r"\x1b\[[0-9;]*m", "", line)) <= 80


# ── deep-triage findings console rendering (issue #19 Phase 2 review) ──────
# --triage-skipped's real, structured triage.findings/finding_count/
# findings_truncated must be reachable from the console, not just --json --
# console/JSON parity is an explicit requirement of this feature. All of
# these render from an already-computed TriageInfo -- never a real
# --triage-skipped run -- same style _action() itself already uses.

def _deep_action(triage, **kwargs):
    return dataclasses.replace(_action(**kwargs), triage=triage)


def _ioc_finding(i=0, is_network_pattern=False):
    return ContentFinding(
        type="ioc_string", address=f"0x{0x1230 + i:016x}", offset=16 + i,
        encoding="ASCII", value=f"http://evil.example/beacon-{i}",
        is_network_pattern=is_network_pattern)


def _mz_finding(module_context="unavailable"):
    return ContentFinding(type="mz_header", address="0x0000000000001230",
                           module_context=module_context)


def test_deep_triage_mz_signal_uses_friendly_label_not_raw_enum():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True, content_reason_codes=("MZ_HEADER_DETECTED",),
                         findings=(_mz_finding(),), finding_count=1, findings_truncated=False)
    out = _capture(records, summary, investigation_actions=[_deep_action(triage)])
    assert "MZ_HEADER_DETECTED" not in out
    assert "MZ header detected" in out


def test_deep_triage_injected_pe_header_uses_distinct_label_from_mz_detected():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True,
                         content_reason_codes=("MZ_HEADER_DETECTED", "INJECTED_PE_HEADER"),
                         findings=(_mz_finding(module_context="unregistered"),),
                         finding_count=1, findings_truncated=False)
    out = _capture(records, summary, investigation_actions=[_deep_action(triage)])
    assert "INJECTED_PE_HEADER" not in out
    assert "MZ header detected" in out
    assert "MZ header in confirmed unregistered memory" in out


def test_deep_triage_ioc_finding_shows_value_address_encoding():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    finding = _ioc_finding(is_network_pattern=True)
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True,
                         content_reason_codes=("IOC_PATTERN_STRING_MATCH", "NETWORK_PATTERN_STRING_MATCH"),
                         findings=(finding,), finding_count=1, findings_truncated=False)
    out = _collapse_ws(_capture(records, summary, investigation_actions=[_deep_action(triage)]))
    assert finding.value in out
    assert finding.address in out
    assert finding.encoding in out
    assert "network pattern" in out


def test_deep_triage_mz_finding_shows_module_context():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True, content_reason_codes=("MZ_HEADER_DETECTED",),
                         findings=(_mz_finding(module_context="unavailable"),),
                         finding_count=1, findings_truncated=False)
    out = _collapse_ws(_capture(records, summary, investigation_actions=[_deep_action(triage)]))
    assert "module context: unavailable" in out


def test_deep_triage_normal_mode_bounds_findings_preview():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    findings = tuple(_ioc_finding(i) for i in range(5))
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                         findings=findings, finding_count=5, findings_truncated=False)
    out = _capture(records, summary, investigation_actions=[_deep_action(triage)])
    for f in findings[:3]:
        assert f.value in out
    for f in findings[3:]:
        assert f.value not in out
    assert "2 additional retained finding(s)" in out
    # findings_truncated is False (all 5 were retained in the JSON array) --
    # the data-level truncation line must not appear.
    assert "deep-triage findings" not in out


def test_deep_triage_verbose_mode_shows_all_retained_findings():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    findings = tuple(_ioc_finding(i) for i in range(5))
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                         findings=findings, finding_count=5, findings_truncated=False)
    out = _capture(records, summary, investigation_actions=[_deep_action(triage)], verbose=True)
    for f in findings:
        assert f.value in out
    assert "additional retained finding(s)" not in out


def test_deep_triage_truncated_shows_total_count_regardless_of_verbose():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    findings = tuple(_ioc_finding(i) for i in range(20))
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                         findings=findings, finding_count=47, findings_truncated=True)
    action = _deep_action(triage)
    out_normal = _capture(records, summary, investigation_actions=[action], verbose=False)
    out_verbose = _capture(records, summary, investigation_actions=[action], verbose=True)
    assert "Showing 20 of 47 deep-triage findings." in out_normal
    assert "Showing 20 of 47 deep-triage findings." in out_verbose


def test_deep_triage_findings_rendering_does_not_mutate_action_or_json():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    findings = tuple(_ioc_finding(i) for i in range(5))
    triage = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                         region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                         findings=findings, finding_count=5, findings_truncated=False)
    action = _deep_action(triage)
    before = action.to_dict()
    _capture(records, summary, investigation_actions=[action], verbose=True)
    after = action.to_dict()
    assert before == after


def test_deep_triage_no_findings_line_when_status_lacks_content_signal():
    records = _all_clean_records()
    summary = build_hunt_summary(records, selected="all")
    triage = TriageInfo(mode="deep", status="not_captured", bytes_examined=0,
                         region_fully_examined=False)
    out = _capture(records, summary, investigation_actions=[_deep_action(triage)])
    assert "deep-triage findings" not in out
    assert "additional retained finding(s)" not in out
