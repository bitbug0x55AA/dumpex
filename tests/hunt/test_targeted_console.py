"""Console projection for a targeted (`--hunt-addr`) rescan.

The card is a pure projection of an already-built record plus the invocation's
own closures, so console and structured output cannot disagree about what a
rescan concluded. What is pinned here is the part an analyst reads a verdict
off: the requested range appears normalized, capture and evaluation stay
separate per closure, closure order is the adapter's own, and the closing scope
statement never lets a partial or not-evaluated rescan read as clean.
"""
import pytest

from dumpex.core.va_range import (
    CaptureState, CapturedSegment, VirtualRange, slice_captured,
)
from dumpex.hunt._observation import ObservationClosure, ObservationKey, ObservationResult
from dumpex.hunt._targeted_console import render_targeted_console_lines
from dumpex.output.coverage import CoverageLimitation, LimitationCode, render_limitation
from dumpex.output.records import TargetedMeasurement
from dumpex.ui.structured import _ANSI_RE

from tests.fixtures.fakes import Segment

_BASE = 0x10000000
_SIZE = 0x2000


class _Request:
    selected = "obfuscation"
    targeted_source = "encoding_scan"
    target_range = VirtualRange(base_address=_BASE, size=_SIZE)


class _Coverage:
    def __init__(self, status, limitations=()):
        self.status = type("Status", (), {"value": status})()
        self.limitations = list(limitations)
        self.reasons = [render_limitation(l) for l in self.limitations]


def _gap(detail="window_sampled"):
    """A limitation that IS a gap in what the rescan did -- as opposed to an
    out-of-scope source, which bounds what the result is about."""
    return CoverageLimitation(
        code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE, source="encoding_scan",
        detail=detail, affected_count=1)


def _out_of_scope(source="memory_info"):
    return CoverageLimitation(
        code=LimitationCode.TARGETED_SOURCE_NOT_EVALUATED, source=source)


class _Record:
    def __init__(self, status="NOT_DETECTED_IN_SCANNED_SCOPE", coverage_status="complete",
                 findings=(), limitations=()):
        self.hunter = "obfuscation"
        self.status = status
        self.score = 0
        self.max_score = 2
        self.verdict_level = "clean"
        self.confidence = "none"
        self.lead_count = 0
        self.review_priority = "none"
        self.coverage = _Coverage(coverage_status, limitations)
        self.findings = list(findings)
        self.details = None


def _closure(status, scope, *, measurements=(), applicability_reason=None):
    requested = VirtualRange(base_address=_BASE, size=_SIZE)
    captured = slice_captured(
        requested, (CapturedSegment.from_segment(Segment(_BASE, 0x3000, _SIZE)),))
    read_slice = (None if status in ("not_evaluated", "not_applicable")
                  else captured.read_input(_SIZE))
    return ObservationClosure(source="encoding_scan", scope=scope, coverage_status=status,
                              capture_state=CaptureState.COMPLETE, read_slice=read_slice,
                              applicability_reason=applicability_reason,
                              measurements=measurements,
                              diagnostics=(f"{scope} note",))


def _context_measurement():
    """One measurement from the shared structural-context set -- the same value
    on every closure, so the default card leaves it out."""
    return TargetedMeasurement(name="containing_region_type", value="MEM_PRIVATE",
                               unit="text")


def _ranked(*values):
    """A bounded ranked list: several measurements sharing one name, in the
    order the closure ranked them."""
    return tuple(
        TargetedMeasurement(name="entropy_top_window", value=value, unit="bits_per_byte",
                            base_address=f"0x{_BASE + index * 0x1000:016x}", size=0x1000)
        for index, value in enumerate(values))


def _result(*closures):
    key = ObservationKey(analyzer="obfuscation", is_targeted=True,
                         algorithm_version="test/1",
                         requested_range=VirtualRange(base_address=_BASE, size=_SIZE))
    return ObservationResult(key=key, closures=tuple(closures))


def _render(record, result, verbose=False):
    return _ANSI_RE.sub("", "\n".join(
        render_targeted_console_lines(record, result, _Request(), verbose, width=100)))


def test_the_requested_range_is_stated_before_any_conclusion():
    text = _render(_Record(), _result(_closure("complete", "sleep_mask")))
    header_end = text.index("VERDICT")
    assert f"0x{_BASE:016x}" in text[:header_end]
    assert f"0x{_BASE + _SIZE:016x}" in text[:header_end]
    assert f"{_SIZE:#x}" in text[:header_end]


def test_closures_are_printed_in_the_adapters_own_order():
    text = _render(_Record(coverage_status="partial"),
                   _result(_closure("complete", "sleep_mask"), _closure("partial", "entropy"),
                           _closure("not_evaluated", "decode")))
    positions = [text.index(f"encoding_scan / {layer}")
                 for layer in ("sleep_mask", "entropy", "decode")]
    assert positions == sorted(positions)


def test_capture_and_evaluation_are_reported_separately_per_closure():
    """A complete capture with a partial evaluation is the case this split
    exists for: the bytes were all there, the algorithm did not finish."""
    text = _render(_Record(coverage_status="partial"), _result(_closure("partial", "entropy")))
    assert "capture     complete" in text
    assert "evaluation  partial" in text


def test_each_closures_own_diagnostics_travel_with_it():
    text = _render(_Record(coverage_status="partial"),
                   _result(_closure("complete", "sleep_mask"), _closure("partial", "entropy")))
    assert "sleep_mask note" in text and "entropy note" in text


@pytest.mark.parametrize("coverage_status", ["partial", "not_evaluated"])
def test_an_incomplete_rescan_never_reads_as_a_clean_range(coverage_status):
    status = "INCONCLUSIVE" if coverage_status == "partial" else "NOT_EVALUATED"
    text = _render(_Record(status=status, coverage_status=coverage_status),
                   _result(_closure("not_evaluated", "entropy")))
    assert "was NOT fully evaluated" in text
    assert "evaluated that range completely" not in text


def test_a_complete_rescan_states_the_scope_its_negative_covers():
    text = _render(_Record(), _result(_closure("complete", "entropy")))
    assert f"applies to [0x{_BASE:016x}, 0x{_BASE + _SIZE:016x}) only" in text
    assert "evaluated that range completely through encoding_scan" in text


def test_coverage_reports_the_gaps_in_what_the_rescan_did():
    text = _render(_Record(coverage_status="partial", limitations=[_gap()]),
                   _result(_closure("partial", "entropy")))
    assert "COVERAGE" in text
    assert "not searched exhaustively" in text


def test_out_of_scope_sources_are_named_outside_the_coverage_block():
    """Five wrapped sentences under a "COMPLETE" heading read as if the scan
    were broken. They are its boundary, so they get their own block."""
    text = _render(_Record(limitations=[_out_of_scope("memory_info"),
                                        _out_of_scope("module_headers")]),
                   _result(_closure("complete", "entropy")))
    assert "NOT COVERED BY THIS RESCAN" in text
    # Through the same display-name mapping the JSON reasons use, so an analyst
    # correlating the card against the document meets one vocabulary.
    assert "MemoryInfoListStream, module_headers" in " ".join(text.split())
    # Nothing was wrong with what this rescan DID, so no COVERAGE block at all.
    assert "COVERAGE" not in text


def test_the_console_names_a_source_exactly_as_the_json_reason_does():
    record = _Record(limitations=[_out_of_scope("memory_info")])
    text = " ".join(_render(record, _result(_closure("complete", "entropy"))).split())
    rendered = render_limitation(_out_of_scope("memory_info"))
    assert rendered.split()[0] in text


def test_a_gap_and_an_out_of_scope_source_are_reported_separately():
    text = _render(_Record(coverage_status="partial",
                           limitations=[_gap(), _out_of_scope("memory_info")]),
                   _result(_closure("partial", "entropy")))
    coverage_at = text.index("COVERAGE")
    out_of_scope_at = text.index("NOT COVERED BY THIS RESCAN")
    assert coverage_at < out_of_scope_at
    assert "memory_info" not in text[coverage_at:out_of_scope_at]


def test_findings_come_from_the_record_never_re_derived():
    finding = {"check": "obfuscation.sleep_mask_decode", "tag": "detection",
               "inference": "decoded payload", "facts": ["a verbose-only fact"]}
    text = _render(_Record(findings=[finding]), _result(_closure("complete", "entropy")))
    assert "obfuscation.sleep_mask_decode" in text and "decoded payload" in text
    assert "a verbose-only fact" not in text


def test_verbose_adds_the_findings_facts():
    finding = {"check": "obfuscation.sleep_mask_decode", "tag": "detection",
               "inference": "decoded payload", "facts": ["a verbose-only fact"]}
    text = _render(_Record(findings=[finding]), _result(_closure("complete", "entropy")),
                   verbose=True)
    assert "a verbose-only fact" in text


def test_rendering_is_pure_and_repeatable():
    record, result = _Record(), _result(_closure("complete", "entropy"))
    assert _render(record, result) == _render(record, result)


# ── YARA's own evidence model ───────────────────────────────────────────

class _YaraDetails:
    def __init__(self, matches, rules_hit):
        self.matches = matches
        self.rules_hit = rules_hit


class _YaraRecord(_Record):
    """YARA carries no shared findings by contract, so its card has to render
    `details.matches`/`details.rules_hit` instead."""

    def __init__(self, matches, rules_hit, **kwargs):
        super().__init__(**kwargs)
        self.hunter = "yara"
        self.max_score = None
        self.confidence = None
        self.review_priority = None
        self.findings = []
        self.details = _YaraDetails(matches, rules_hit)


def _match(rule, file="hit.yar", seg_va="0x0000000010000000", seg_size=0x200):
    return {"rule": rule, "file": file, "seg_va": seg_va, "seg_size": seg_size}


def test_a_yara_rescan_names_the_rules_behind_its_verdict():
    record = _YaraRecord([_match("HitRule"), _match("HitRule")], ["HitRule"],
                         status="DETECTED")
    text = _render(record, _result(_closure("complete", None)))
    assert "Rule: HitRule  (2 hit(s))" in text
    assert "hit.yar" in text


def test_a_rule_that_could_not_be_classified_is_labelled_not_counted_as_detection():
    """A hit nothing could classify is evidence the analyst still needs to see,
    but it did not earn the detection label the score is derived from."""
    record = _YaraRecord([_match("UnverifiedRule")], [], status="INCONCLUSIVE",
                         coverage_status="partial")
    text = _render(record, _result(_closure("partial", None)))
    assert "UNVERIFIED" in text and "Rule: UnverifiedRule" in text
    assert "DETECTION" not in text


def test_a_yara_rescan_with_no_matches_prints_no_signal_section():
    record = _YaraRecord([], [])
    text = _render(record, _result(_closure("complete", None)))
    assert "KEY SIGNALS" not in text


def test_verbose_adds_each_yara_hits_own_segment():
    record = _YaraRecord([_match("HitRule")], ["HitRule"], status="DETECTED")
    assert "0x0000000010000000 (512 bytes)" in _render(
        record, _result(_closure("complete", None)), verbose=True)


# ── measurements ───────────────────────────────────────────────────────

def test_a_completed_no_hit_closure_shows_what_it_measured():
    """The card an analyst reads after a negative. Without this the closure row
    says "complete" and nothing else, and the result is a bare assertion."""
    measurements = (
        TargetedMeasurement(name="bytes_evaluated", value=8192, unit="bytes"),
        TargetedMeasurement(name="whole_range_entropy", value=0.45,
                            unit="bits_per_byte"),
    )
    text = _render(_Record(), _result(_closure("complete", "entropy",
                                               measurements=measurements)))
    assert "measured" in text
    assert "bytes evaluated" in text and "8192 byte(s)" in text
    assert "whole range entropy" in text and "0.45 bits/byte" in text


def test_a_located_measurement_carries_the_address_it_was_measured_at():
    text = _render(_Record(), _result(_closure("complete", "entropy",
                                               measurements=_ranked(7.9))))
    assert f"@ 0x{_BASE:016x}" in text
    assert "4096 byte(s)" in text


def test_the_default_card_shows_a_ranked_lists_top_entry_and_says_there_are_more():
    text = _render(_Record(), _result(_closure("complete", "entropy",
                                               measurements=_ranked(7.9, 7.1, 6.4))))
    assert text.count("entropy top window") == 1
    assert "7.90 bits/byte" in text
    assert "(+2 more, --verbose)" in text
    assert "7.10 bits/byte" not in text


def test_verbose_expands_the_ranked_list_and_adds_the_structural_context():
    """--verbose has to add evidence, not reprint the default card."""
    measurements = (_context_measurement(),) + _ranked(7.9, 7.1, 6.4)
    result = _result(_closure("complete", "entropy", measurements=measurements))
    default = _render(_Record(), result)
    verbose = _render(_Record(), result, verbose=True)

    assert verbose.count("entropy top window") == 3
    assert "7.10 bits/byte" in verbose and "6.40 bits/byte" in verbose
    assert "(+2 more, --verbose)" not in verbose
    # The structural context is the same on every closure, so it is verbose-only.
    assert "containing region type" in verbose
    assert "containing region type" not in default
    assert len(verbose) > len(default)


def test_a_measurement_that_was_never_taken_is_not_a_measured_zero():
    measurements = (TargetedMeasurement(name="budget_exhausted_reason", value=None,
                                        unit="text"),)
    text = _render(_Record(), _result(_closure("complete", "decode",
                                               measurements=measurements)))
    assert "budget exhausted reason" in text
    assert "\u2014" in text or "—" in text


# ── applicability ──────────────────────────────────────────────────────

def test_an_inapplicable_closure_reads_as_not_applicable_not_as_a_gap():
    text = _render(
        _Record(),
        _result(_closure("not_applicable", "sleep_mask",
                         applicability_reason="region_protection_ineligible"),
                _closure("complete", "entropy")))
    assert "evaluation  not applicable" in text
    assert "evaluation  not evaluated" not in text


def test_a_complete_rescan_names_the_layers_that_did_not_apply():
    """"Evaluated completely" must not be readable as "every layer looked"."""
    text = _render(
        _Record(),
        _result(_closure("not_applicable", "sleep_mask",
                         applicability_reason="region_protection_ineligible"),
                _closure("complete", "entropy")))
    assert "evaluated that range completely" in text
    assert "sleep_mask does not apply to this target" in text


def test_a_complete_rescan_with_no_inapplicable_layer_says_nothing_about_one():
    text = _render(_Record(), _result(_closure("complete", "entropy")))
    assert "does not apply to this target" not in text
