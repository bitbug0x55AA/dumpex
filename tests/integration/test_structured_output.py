"""
Output-path integration tests: does dumpex.ui.structured.StructuredOutput's
CSV/JSON summary row faithfully reflect a hunter's OWN verdict_level /
confidence / coverage_status, rather than re-deriving a (possibly
disagreeing) verdict from score/confidence arithmetic on its own?
"""
from dumpex.ui.structured import StructuredOutput


# ── stomping 1/2 stays at its own verdict_level in the summary row, ───────
# not re-derived/inflated by structured.py ─────────────────────────────────

def test_stomping_verdict_not_inflated_in_summary_row():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    stomping_findings = {
        "score": 1, "max_score": 2, "status": "DETECTED", "confidence": "medium",
        "verdict_level": "likely",
        "coverage_status": "complete", "coverage_reasons": [],
        "protection_leads": [], "verified_changes": [], "findings": [],
    }
    row = out._section_to_tables("hunt", {"stomping": stomping_findings})["summary"][0]
    # verdict must equal the hunter's OWN verdict_level, uppercased — not a
    # generically re-derived "POSSIBLE" from score/confidence arithmetic.
    assert row["verdict"] == "LIKELY"
    assert row["verdict_level"] == "likely"
    assert row["confidence"] == "medium"


# ── DETECTED and partial coverage representable simultaneously ────────────

def test_detected_and_partial_coverage_coexist():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    stomping_findings = {
        "score": 1, "max_score": 2, "status": "DETECTED", "confidence": "medium",
        "verdict_level": "likely",
        "coverage_status": "partial",
        "coverage_reasons": ["2 module header(s) failed PE structural validation"],
        "protection_leads": [], "verified_changes": [], "findings": [],
    }
    row = out._section_to_tables("hunt", {"stomping": stomping_findings})["summary"][0]
    assert row["status"] == "DETECTED"
    assert row["verdict"] == "LIKELY"
    assert row["coverage_complete"] is False
    assert "module header" in row["coverage_reason"]


# ── verdict_level is consistent between the hunter's own field and what ───
# structured.py's CSV/JSON summary row reports — for every level and every
# phase-two hunter, not just stomping.

def test_verdict_level_consistent_across_hunters():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    cases = [
        ("injection", 1, "possible"), ("injection", 2, "likely"), ("injection", 3, "high"),
        ("stomping",  1, "likely"),   ("stomping",  2, "high"),
        ("pipe",      1, "possible"), ("pipe",      2, "likely"),   ("pipe", 3, "high"),
        ("obfuscation", 1, "likely"), ("obfuscation", 2, "high"),
        ("cs-beacon", 1, "likely"),   ("cs-beacon", 2, "high"),
    ]
    for ttp, score, expected_level in cases:
        mock = {
            "score": score, "max_score": 3, "status": "DETECTED",
            "confidence": "high", "verdict_level": expected_level,
            "coverage_status": "complete", "coverage_reasons": [], "findings": [],
        }
        row = out._section_to_tables("hunt", {ttp: mock})["summary"][0]
        assert row["verdict_level"] == expected_level, (ttp, score, row)
        assert row["verdict"] == expected_level.upper(), (ttp, score, row)


# ── verdict_level must never render as "clean" for INCONCLUSIVE/ ──────────
# NOT_EVALUATED rows, regardless of what the hunter's own verdict_level
# field says (a defense-in-depth check on top of _finding.verdict_level()
# itself already refusing to emit "clean" in that case).

def test_inconclusive_and_not_evaluated_never_show_as_clean():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    for status, verdict_level in (("INCONCLUSIVE", "inconclusive"), ("NOT_EVALUATED", "not_evaluated")):
        mock = {
            "score": 0, "max_score": 2, "status": status,
            "confidence": "none", "verdict_level": verdict_level,
            "coverage_status": "partial" if status == "INCONCLUSIVE" else "not_evaluated",
            "coverage_reasons": ["some coverage gap"], "findings": [],
        }
        row = out._section_to_tables("hunt", {"stomping": mock})["summary"][0]
        assert row["verdict"] != "CLEAN", (status, row)
        assert row["verdict_level"] != "clean", (status, row)
