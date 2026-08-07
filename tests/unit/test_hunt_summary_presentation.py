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
from dumpex.hunt._finding import Finding, TAG_DETECTION, TAG_LEAD, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM
from dumpex.output.coverage import CoverageReport, CoverageStatus, CoverageLimitation, LimitationCode
from dumpex.output.records import HUNTERS
from tests.fixtures.hunt_records import (
    injection_detected, hollowing_not_evaluated, stomping_inconclusive,
    pipe_clean, yara_detected, all_seven_detected_variety, all_seven_not_evaluated,
)


def _capture(records, summary, doc_coverage_status="complete", width=100):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_hunt_summary(records, summary, doc_coverage_status, width=width)
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
    assert params == {"records", "summary", "doc_coverage_status", "width"}


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
