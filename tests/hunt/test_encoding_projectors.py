"""Tests for the encoding (obfuscation) pure projectors (dumpex/hunt/
encoding/report_facts.py, report_legacy.py, report_record.py,
report_console.py) -- everything that turns a hand-built `EncodingReport`
(dumpex.hunt.encoding.domain's canonical domain model) into the legacy
v1.1 dict, the current-schema (v2.10) `HunterRecord`, and the
verdict-first console. Mirrors tests/hunt/test_injection_projectors.py
(the completed reference pilot's own test suite) -- see that module's
own docstring for the general split between this file and its
neighbours.

No hand-built golden-scenario byte-parity test is duplicated here (unlike
test_injection_projectors.py's own): tests/integration/
test_hunt_cli_compat_freeze.py already exercises the exact same
single-PE-in-Base64 scenario (tests/fixtures/hunt_cli_scenarios.py's
`_build_obfuscation`) end to end through the REAL production pipeline
against tests/fixtures/hunt_cli_golden/obfuscation_console.txt/
obfuscation_verbose_console.txt/obfuscation_hunt_dict.json -- a stronger
guarantee than re-deriving the same scenario from hand-built evidence
here would add.

Builder helpers below reuse test_encoding_domain.py's own
(`_region`/`_location`/`_cls`/`_hit`/`_entropy_hit`/`_coverage`/`_check`).
"""
import pytest

from tests.hunt.test_encoding_domain import _cls, _hit, _entropy_hit, _coverage, _check

from dumpex.hunt._finding import (
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION,
)
from dumpex.hunt.encoding.domain import CoverageSnapshot, EncodingEvidence, EncodingReport
from dumpex.hunt.encoding.report_facts import finding_from_check_result
from dumpex.hunt.encoding.report_legacy import project_legacy_dict
from dumpex.hunt.encoding.report_record import project_hunter_record
from dumpex.hunt.encoding.report_console import render_console_lines
from dumpex.output.coverage import EXIT_NOT_EVALUATED, EXIT_OK, EXIT_PARTIAL, exit_code_for


# ── Report builders ────────────────────────────────────────────────────────

_BASE = 0x7ffe30000000


def _full_report() -> EncodingReport:
    """DETECTED, complete coverage, covers all 7 check ids in one Report:
    sleep_mask_confirmed / entropy_observation / base64_observation /
    xor_observation / compressed_observation / structural_payload /
    shellcode_bootstrap_lead. Deliberately richer than any single scan
    `aggregate.build_report` would itself produce, purely to exercise
    every projector code path in one Report."""
    sm_hit = _hit(layer="sleep_mask", base=_BASE, key=b"\x11\x22\x33", key_offset=1)
    entropy = _entropy_hit(base=_BASE + 0x10000)
    b64_pe = _hit(layer="base64", base=_BASE + 0x20000, is_pe=True, raw=b"QQQQ")
    xor_hit = _hit(layer="xor", base=_BASE + 0x30000, key=0x5A,
                   classification=_cls(kind="ioc_text", ioc_strings=("http://x",)))
    gzip_hit = _hit(layer="gzip", base=_BASE + 0x40000,
                    classification=_cls(kind="plaintext"))
    shellcode_hit = _hit(layer="xor", base=_BASE + 0x50000, is_shellcode=True, is_rwx=True,
                         key=0x11)

    evidence = EncodingEvidence(
        sleep_mask_hits=(sm_hit,), entropy_hits=(entropy,), base64_hits=(b64_pe,),
        xor_hits=(xor_hit, shellcode_hit), compressed_hits=(gzip_hit,),
        pe_hits=(b64_pe,), shellcode_hits=(shellcode_hit,),
        shellcode_context_hits=(shellcode_hit,),
    )
    results = (
        _check(check="obfuscation.sleep_mask_confirmed", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(sm_hit,), evidence_limit=10),
        _check(check="obfuscation.entropy_observation", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(entropy,), evidence_limit=15),
        _check(check="obfuscation.base64_observation", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(b64_pe,), evidence_limit=15),
        _check(check="obfuscation.xor_observation", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(xor_hit,), evidence_limit=15),
        _check(check="obfuscation.compressed_observation", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(gzip_hit,), evidence_limit=15),
        _check(check="obfuscation.structural_payload", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(b64_pe,), evidence_limit=20),
        _check(check="obfuscation.shellcode_bootstrap_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(shellcode_hit,), evidence_limit=20),
    )
    return EncodingReport(score=2, coverage=_coverage(), results=results, evidence=evidence)


def _clean_report() -> EncodingReport:
    return EncodingReport(score=0, coverage=_coverage(), results=(), evidence=EncodingEvidence())


def _inconclusive_report() -> EncodingReport:
    coverage = CoverageSnapshot(memory_info_stream=True, region_count=1,
                                 any_region_scanned=True, read_failed=1)
    return EncodingReport(score=0, coverage=coverage, results=(), evidence=EncodingEvidence())


def _not_evaluated_report() -> EncodingReport:
    coverage = CoverageSnapshot(memory_info_stream=False)
    return EncodingReport(score=0, coverage=coverage, results=(), evidence=EncodingEvidence())


# ── 1. Per-projector shape tests ──────────────────────────────────────────

@pytest.mark.parametrize("report_fn", [_full_report, _clean_report,
                                        _inconclusive_report, _not_evaluated_report])
def test_projectors_do_not_raise_for_every_state(report_fn):
    report = report_fn()
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    lines = render_console_lines(report, verbose=False)
    verbose_lines = render_console_lines(report, verbose=True)
    assert isinstance(d, dict)
    assert record.hunter == "obfuscation"
    assert isinstance(lines, list) and all(isinstance(l, str) for l in lines)
    assert isinstance(verbose_lines, list)


def test_legacy_dict_has_every_v1_key():
    d = project_legacy_dict(_full_report())
    expected_keys = {
        "sleep_mask", "entropy", "base64", "xor", "compressed", "hidden_pe", "hidden_shellcode",
        "score", "max_score", "status", "coverage_status", "coverage_reasons",
        "verdict_level", "confidence", "findings", "lead_count", "review_priority",
        "budget_exhausted",
    }
    assert expected_keys <= set(d)
    assert d["score"] == 2 and d["max_score"] == 2
    assert len(d["findings"]) == 7
    assert d["sleep_mask"][0]["region"]["BaseAddress"] == _BASE


def test_hunter_record_details_shape():
    record = project_hunter_record(_full_report())
    details = record.details
    assert len(details.sleep_mask) == 1
    assert len(details.entropy) == 1
    assert len(details.base64) == 1
    # Only the xor_observation check's OWN (deduped) evidence shows up
    # here -- shellcode_hit lives on shellcode_bootstrap_lead's evidence
    # instead, even though it is also a member of evidence.xor_hits (the
    # raw, undeduped scan-layer bucket both checks partition from).
    assert len(details.xor) == 1
    assert len(details.compressed) == 1
    assert len(details.hidden_pe) == 1
    assert len(details.hidden_shellcode) == 1
    assert record.findings and all(isinstance(f, dict) for f in record.findings)


def test_console_lines_contain_expected_sections():
    lines = render_console_lines(_full_report(), verbose=False)
    text = "\n".join(lines)
    assert "HUNT: Obfuscation Detection" in text
    assert "VERDICT" in text
    assert "KEY SIGNALS" in text
    assert "WHY THIS VERDICT" in text


# ── 2. State-matrix tests ─────────────────────────────────────────────────

def test_detected_state_matches_across_projectors():
    report = _full_report()
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    assert report.status == "DETECTED"
    assert d["status"] == "DETECTED" == record.status
    assert d["score"] == record.score == 2
    assert d["verdict_level"] == record.verdict_level == "high"


def test_clean_state_is_not_detected_in_scanned_scope():
    report = _clean_report()
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    assert d["status"] == record.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert d["coverage_status"] == "complete"
    assert d["findings"] == [] and record.findings == []
    lines = render_console_lines(report, verbose=False)
    assert any("CLEAN" in l for l in lines)


def test_inconclusive_state():
    report = _inconclusive_report()
    assert report.status == "INCONCLUSIVE"
    d = project_legacy_dict(report)
    assert d["coverage_status"] == "partial"
    assert any("failed to read" in r for r in d["coverage_reasons"])
    lines = render_console_lines(report, verbose=False)
    assert any("INCONCLUSIVE" in l for l in lines)


def test_not_evaluated_state_never_implies_clean_or_shows_empty_sections():
    report = _not_evaluated_report()
    assert report.status == "NOT_EVALUATED"
    d = project_legacy_dict(report)
    assert d["status"] == "NOT_EVALUATED"
    lines = render_console_lines(report, verbose=False)
    text = "\n".join(lines)
    assert "NOT EVALUATED" in text
    assert "CLEAN" not in text
    assert "KEY SIGNALS" not in text
    assert "WHY THIS VERDICT" not in text


# ── 3. Ordering / truncation / width tests ────────────────────────────────

def test_console_groups_detection_before_lead_before_context_but_findings_stay_in_construction_order():
    entropy = _entropy_hit(base=_BASE + 0x60000)
    xor_hit = _hit(layer="xor", base=_BASE + 0x70000, key=0x5A)
    sm_hit = _hit(layer="sleep_mask", base=_BASE + 0x80000, key=b"\x11\x22\x33", key_offset=0)
    results = (
        _check(check="obfuscation.entropy_observation", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(entropy,), evidence_limit=15),
        _check(check="obfuscation.xor_observation", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
               evidence=(xor_hit,), evidence_limit=15),
        _check(check="obfuscation.sleep_mask_confirmed", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(sm_hit,), evidence_limit=10),
    )
    evidence = EncodingEvidence(entropy_hits=(entropy,), xor_hits=(xor_hit,),
                                sleep_mask_hits=(sm_hit,))
    report = EncodingReport(score=1, coverage=_coverage(), results=results, evidence=evidence)

    d = project_legacy_dict(report)
    assert [f["check"] for f in d["findings"]] == [r.check for r in results]

    lines = render_console_lines(report, verbose=False)
    text = "\n".join(lines)
    detection_pos = text.index("[!] DETECTION")
    lead_pos = text.index("[~] LEAD")
    context_pos = text.index("[i] CONTEXT")
    assert detection_pos < lead_pos < context_pos


def test_evidence_limit_caps_facts_but_not_verbose_facts():
    from dumpex.hunt.encoding.report_console import _console_finding

    hits = tuple(_hit(layer="base64", base=_BASE + 0x90000 + i * 0x1000) for i in range(5))
    result = _check(check="obfuscation.base64_observation", tag=TAG_OBSERVATION,
                    confidence=CONFIDENCE_LOW, evidence=hits, evidence_limit=2)
    evidence = EncodingEvidence(base64_hits=hits)
    report = EncodingReport(score=0, coverage=_coverage(), results=(result,), evidence=evidence)

    wire_finding = finding_from_check_result(result, report)
    assert len(wire_finding.facts) == 3
    assert wire_finding.facts[-1] == "... and 3 more"
    assert wire_finding.verbose_facts == ()

    console_finding = _console_finding(result, report)
    assert console_finding.facts == wire_finding.facts
    assert len(console_finding.verbose_facts) == 5


def test_console_wraps_within_requested_width():
    from dumpex.hunt._console import strip_ansi
    hit = _hit(layer="base64", base=_BASE + 0xa0000)
    result = _check(check="obfuscation.base64_observation", tag=TAG_OBSERVATION,
                    confidence=CONFIDENCE_LOW, evidence=(hit,), evidence_limit=15,
                    inference="x " * 60 + "end of a deliberately very long inference sentence "
                                "meant to force wrapping across several lines of output")
    evidence = EncodingEvidence(base64_hits=(hit,))
    report = EncodingReport(score=0, coverage=_coverage(), results=(result,), evidence=evidence)

    lines = render_console_lines(report, verbose=False, width=80)
    # The trailing "Use --verbose ..." hint is a fixed, non-data-dependent
    # line report_console.py deliberately never wraps (mirrors
    # dumpex.hunt.injection.report_console's own hint) -- only the
    # data-derived lines (inference/facts/etc) are expected to respect
    # the requested width.
    for line in lines:
        if "Use --verbose" in line:
            continue
        assert len(strip_ansi(line)) <= 80, repr(line)


# ── 4. Purity / order-independence tests ──────────────────────────────────

def test_projectors_are_order_independent_and_pure():
    report = _full_report()

    legacy_first = project_legacy_dict(report)
    record_first = project_hunter_record(report)
    console_first = render_console_lines(report, verbose=False)
    verbose_first = render_console_lines(report, verbose=True)

    verbose_again = render_console_lines(report, verbose=True)
    console_again = render_console_lines(report, verbose=False)
    record_again = project_hunter_record(report)
    legacy_again = project_legacy_dict(report)

    assert legacy_first == legacy_again
    assert console_first == console_again
    assert verbose_first == verbose_again
    assert record_first.details.to_dict() == record_again.details.to_dict()
    assert record_first.findings == record_again.findings
    assert record_first.status == record_again.status
    assert record_first.score == record_again.score

    legacy_first["sleep_mask"].append("tampered")
    legacy_first["findings"].append("tampered")
    legacy_third = project_legacy_dict(report)
    assert "tampered" not in legacy_third["sleep_mask"]
    assert "tampered" not in legacy_third["findings"]


def test_console_verbose_and_normal_never_change_json_projections():
    report = _full_report()
    before = project_legacy_dict(report)
    render_console_lines(report, verbose=True)
    render_console_lines(report, verbose=False)
    render_console_lines(report, verbose=True)
    after = project_legacy_dict(report)
    assert before == after
    assert project_hunter_record(report).findings == project_hunter_record(report).findings


# ── 5. Exit-code parity across coverage states ─────────────────────────────

def test_exit_code_complete_coverage_is_ok():
    record = project_hunter_record(_clean_report())
    assert record.coverage.status.value == "complete"
    assert exit_code_for(record.coverage.status) == EXIT_OK == 0


def test_exit_code_partial_coverage_is_partial():
    record = project_hunter_record(_inconclusive_report())
    assert record.coverage.status.value == "partial"
    assert exit_code_for(record.coverage.status) == EXIT_PARTIAL == 3


def test_exit_code_not_evaluated_coverage_is_not_evaluated():
    record = project_hunter_record(_not_evaluated_report())
    assert record.coverage.status.value == "not_evaluated"
    assert exit_code_for(record.coverage.status) == EXIT_NOT_EVALUATED == 4


# ── 6. The "empty/error" acceptance axis ────────────────────────────────────
# `_not_evaluated_report()` (memory_info_stream absent, no results) stands
# in for "empty" throughout this file -- see
# test_injection_projectors.py's own docstring section 7 for why "error"
# (a hunt run that failed outright) is deliberately not representable by
# this domain model at all; the same reasoning applies unchanged to
# EncodingReport.

def test_encoding_report_status_has_no_error_representation():
    from dumpex.hunt._ui import DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE, \
        NOT_EVALUATED
    known_statuses = {DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, INCONCLUSIVE, NOT_EVALUATED}
    for report_fn in (_full_report, _clean_report, _inconclusive_report, _not_evaluated_report):
        assert report_fn().status in known_statuses
