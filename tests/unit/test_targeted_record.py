"""Projection of one targeted rescan's observation into a HunterRecord.

Coverage comes from the observation's closures alone, evidence comes from the
analyzer's own report, and status/verdict_level are re-derived so the three
agree. These tests drive `dumpex.hunt._targeted_record` directly against
synthetic closures, so each reduction rule is pinned independently of any real
scanner's behaviour.
"""
import pytest

from dumpex.core.va_range import (
    CaptureState, CapturedSegment, VirtualRange, slice_captured,
)
from dumpex.hunt._observation import ObservationClosure, ObservationKey, ObservationResult
from dumpex.hunt._targeted_record import (
    TARGETED_COVERAGE_SOURCE, build_targeted_coverage, build_targeted_record,
    targeted_scope_records,
)
from dumpex.output.coverage import CoverageLimitation, LimitationCode
from dumpex.output.records import HUNTERS

from tests.fixtures.fakes import Segment

_BASE = 0x10000000
_SIZE = 0x2000


class _Request:
    """The two fields the projection reads off a HuntRequest. Kept local so a
    coverage rule can be exercised without the registry grant a real
    `HuntRequest.targeted()` resolves."""

    def __init__(self, selected="obfuscation"):
        self.selected = selected
        self.target_range = VirtualRange(base_address=_BASE, size=_SIZE)


class _Context:
    def __init__(self, request=None):
        self.request = request or _Request()
        self.mf = None


def _key(analyzer="obfuscation"):
    return ObservationKey(analyzer=analyzer, is_targeted=True,
                          algorithm_version="test/1",
                          requested_range=VirtualRange(base_address=_BASE, size=_SIZE))


def _capture_slice(state):
    """A real `CapturedSlice` for the requested range in the given state, so a
    closure carries the read it actually ran against -- `ObservationResult`
    rejects a closure that claims to have run without one."""
    requested = VirtualRange(base_address=_BASE, size=_SIZE)
    if state == CaptureState.NONE:
        return slice_captured(requested, ())
    backing = _SIZE if state == CaptureState.COMPLETE else _SIZE // 2
    segment = CapturedSegment.from_segment(Segment(_BASE, 0x3000, backing))
    return slice_captured(requested, (segment,))


def _closure(status, *, scope=None, source="encoding_scan",
             capture=CaptureState.COMPLETE, limitations=()):
    captured = _capture_slice(capture)
    read_slice = None
    if status != "not_evaluated":
        read_slice = captured.read_input(captured.captured_bytes)
    return ObservationClosure(source=source, scope=scope, coverage_status=status,
                              capture_state=capture, read_slice=read_slice,
                              limitations=limitations)


def _result(*closures, analyzer="obfuscation", payload=None):
    return ObservationResult(key=_key(analyzer), closures=tuple(closures), payload=payload)


# ── coverage reduction across closures ──────────────────────────────────

def test_every_closure_complete_is_complete():
    coverage = build_targeted_coverage(
        _result(_closure("complete", scope="sleep_mask"), _closure("complete", scope="entropy")),
        "obfuscation")
    assert coverage.status.value == "complete"
    # Only the out-of-scope entries for obfuscation's other sources; no gap in
    # what this run actually covered.
    assert all(l.code == LimitationCode.TARGETED_SOURCE_NOT_EVALUATED
               and l.source != TARGETED_COVERAGE_SOURCE
               for l in coverage.limitations)


def test_every_closure_not_evaluated_is_not_evaluated():
    coverage = build_targeted_coverage(
        _result(_closure("not_evaluated", scope="sleep_mask"),
                _closure("not_evaluated", scope="entropy")),
        "obfuscation")
    assert coverage.status.value == "not_evaluated"


@pytest.mark.parametrize("statuses", [
    ("complete", "partial"),
    ("complete", "not_evaluated"),
    ("not_evaluated", "partial"),
])
def test_any_disagreement_between_closures_is_partial(statuses):
    """A mixed set is partial even when one closure completed: a layer that
    never ran leaves the range unresolved for that layer, and one complete
    closure must not speak for it. Capture is deliberately identical across
    the pair -- it is a fact of (dump, range) that every closure shares, so
    only evaluation is allowed to differ here."""
    layers = ("sleep_mask", "entropy", "decode")
    coverage = build_targeted_coverage(
        _result(*(_closure(status, scope=layers[i]) for i, status in enumerate(statuses))),
        "obfuscation")
    assert coverage.status.value == "partial"


def test_a_not_evaluated_closure_derives_its_own_limitation_with_its_scope():
    coverage = build_targeted_coverage(
        _result(_closure("complete", scope="sleep_mask"),
                _closure("not_evaluated", scope="entropy")),
        "obfuscation")
    derived = [l for l in coverage.limitations
               if l.code == LimitationCode.TARGETED_SOURCE_NOT_EVALUATED
               and l.source == TARGETED_COVERAGE_SOURCE]
    assert [l.scope for l in derived] == ["entropy"]


def test_a_not_evaluated_closures_own_prerequisite_limitations_are_kept():
    """The derived code says a closure did not run; the closure's own
    limitations say what stopped it. Both belong in the record."""
    prerequisite = CoverageLimitation(
        code=LimitationCode.YARA_RULE_COMPILE_FAILED, source="yara_rules", affected_count=2)
    coverage = build_targeted_coverage(
        _result(_closure("not_evaluated", source="segment_scan", limitations=(prerequisite,)),
                analyzer="yara"),
        "yara")
    codes = [l.code for l in coverage.limitations]
    assert codes[:2] == [LimitationCode.TARGETED_SOURCE_NOT_EVALUATED,
                         LimitationCode.YARA_RULE_COMPILE_FAILED]


def test_sources_carry_the_analyzers_whole_published_vocabulary():
    """A targeted record shows the same source roster a full-scope record does,
    so a consumer can tell per source what this run observed -- rather than
    having to notice that a key is missing."""
    coverage = build_targeted_coverage(
        _result(_closure("complete", source="segment_scan"), analyzer="yara"), "yara")
    assert set(coverage.sources) >= {TARGETED_COVERAGE_SOURCE, "segment_scan",
                                     "yara_rules", "yara_context"}
    assert coverage.sources["segment_scan"].state.value == "present"
    assert coverage.sources[TARGETED_COVERAGE_SOURCE].state.value == "present"


def test_a_source_outside_the_grant_is_absent_and_says_so():
    """The one hazard a completed targeted rescan otherwise creates: a
    consumer keying on hunter + coverage.status reading "completely covered"
    for an analyzer whose other sources were never in scope."""
    coverage = build_targeted_coverage(
        _result(_closure("complete", source="ioc_string_scan"), analyzer="stomping"),
        "stomping")
    assert coverage.status.value == "complete"
    out_of_scope = {l.source for l in coverage.limitations
                    if l.code == LimitationCode.TARGETED_SOURCE_NOT_EVALUATED}
    assert {"module_headers", "reference_files", "section_content_diff", "modules"} <= out_of_scope
    for name in out_of_scope:
        assert coverage.sources[name].state.value == "absent"
    assert any("outside this targeted rescan" in reason for reason in coverage.reasons)


def test_a_source_a_closure_limitation_reports_on_is_not_called_out_of_scope():
    """A gap the rescan itself reported is a source it spoke about. Marking it
    out of scope alongside its own limitation would contradict it."""
    prerequisite = CoverageLimitation(
        code=LimitationCode.YARA_RULE_COMPILE_FAILED, source="yara_rules", affected_count=1)
    coverage = build_targeted_coverage(
        _result(_closure("partial", source="segment_scan", limitations=(prerequisite,)),
                analyzer="yara"),
        "yara")
    out_of_scope = [l for l in coverage.limitations
                    if l.code == LimitationCode.TARGETED_SOURCE_NOT_EVALUATED]
    assert "yara_rules" not in {l.source for l in out_of_scope}


def test_a_declared_unevaluated_source_an_adapter_reports_on_fails_closed():
    """The declared set says stomping's targeted rescan never reads reference
    files. An adapter emitting a limitation about them means one of the two is
    wrong -- shipping both would put a contradiction in one record."""
    reported = CoverageLimitation(
        code=LimitationCode.STOMPING_REFERENCE_MISSING, source="reference_files",
        affected_count=1)
    with pytest.raises(ValueError, match="declared never-evaluated"):
        build_targeted_coverage(
            _result(_closure("partial", source="ioc_string_scan", limitations=(reported,)),
                    analyzer="stomping"),
            "stomping")


def test_one_gap_two_closures_report_is_recorded_once():
    """A closure's limitations are self-contained: pipe's `c2_context` closure
    carries the `pipe_name` budget's own SCAN_BUDGET_EXHAUSTED, because C2
    records are retained against this range's pipe-name hits. Flattening the
    closures must not turn that one gap into two entries, two rendered
    reasons, and two console lines."""
    budget = CoverageLimitation(
        code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
        scope="pipe_name", detail="deadline")
    coverage = build_targeted_coverage(
        _result(_closure("partial", scope="pipe_name", source="pipe_name_scan",
                         limitations=(budget,)),
                _closure("partial", scope="c2_context", source="pipe_name_scan",
                         limitations=(budget,)),
                analyzer="pipe"),
        "pipe")
    exhausted = [l for l in coverage.limitations
                 if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]
    assert exhausted == [budget]
    assert len(coverage.reasons) == len(set(coverage.reasons))


def test_two_gaps_differing_only_in_detail_are_both_kept():
    """Collapsing is by full structural equality, never by
    `(code, source, scope)`: two budgets that ran out for different reasons are
    two facts, not one repeated."""
    scope = dict(code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
                 scope="pipe_name")
    first = CoverageLimitation(detail="deadline", **scope)
    second = CoverageLimitation(detail="max_hits", **scope)
    coverage = build_targeted_coverage(
        _result(_closure("partial", scope="pipe_name", source="pipe_name_scan",
                         limitations=(first,)),
                _closure("partial", scope="c2_context", source="pipe_name_scan",
                         limitations=(second,)),
                analyzer="pipe"),
        "pipe")
    exhausted = [l for l in coverage.limitations
                 if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]
    assert exhausted == [first, second]


def test_a_limitation_naming_a_source_outside_the_roster_fails_closed():
    """Full-scope coverage gets this from build_coverage_report's own
    cross-source validation; this path builds its report directly, so the same
    rule is enforced rather than left to adapter discipline."""
    stray = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_READ_FAILED, source="not_a_yara_source",
        affected_count=1)
    with pytest.raises(ValueError, match="not one of this record's own sources"):
        build_targeted_coverage(
            _result(_closure("partial", source="segment_scan", limitations=(stray,)),
                    analyzer="yara"),
            "yara")


def test_sources_are_absent_when_no_closure_ran():
    coverage = build_targeted_coverage(
        _result(_closure("not_evaluated", source="segment_scan"), analyzer="yara"), "yara")
    assert all(obs.state.value == "absent" for obs in coverage.sources.values())


# ── targeted_scope records ──────────────────────────────────────────────

def test_scope_records_follow_closure_order_and_carry_the_requested_range():
    result = _result(_closure("complete", scope="sleep_mask"),
                     _closure("partial", scope="entropy"),
                     _closure("not_evaluated", scope="decode"))
    records = targeted_scope_records(_Request(), result)
    assert [r.scope for r in records] == ["sleep_mask", "entropy", "decode"]
    assert {r.base_address for r in records} == {f"0x{_BASE:016x}"}
    assert {r.size for r in records} == {_SIZE}
    assert [r.coverage_status for r in records] == ["complete", "partial", "not_evaluated"]


def test_an_uncaptured_closure_reports_zero_captured_bytes_not_unknown():
    """`none` is a measured fact -- the dump holds nothing for the range -- so
    it is reported as 0 rather than as unknown availability."""
    records = targeted_scope_records(
        _Request(), _result(_closure("not_evaluated", capture=CaptureState.NONE)))
    assert records[0].captured_size == 0


def test_an_unmeasured_closure_reports_unknown_captured_bytes():
    """A closure that never read carries no read slice; claiming a byte count
    for it would be inventing one."""
    records = targeted_scope_records(
        _Request(), _result(_closure("not_evaluated", capture=CaptureState.PARTIAL)))
    assert records[0].capture_state == "partial"
    assert records[0].captured_size is None


# ── record assembly ─────────────────────────────────────────────────────

class _FakeSpec:
    """A registry spec stand-in: the two callables `build_targeted_record`
    resolves, wired to a fixed report sentinel and a fixed record, so each
    reduction rule below varies one input at a time."""
    identity = "obfuscation"

    def __init__(self, record):
        self._record = record

    def targeted_report_projector(self, context, result):
        return "report-sentinel"

    def record_projector(self, report):
        assert report == "report-sentinel"
        return self._record


def _dataclass_record(status, score, verdict_level):
    from dataclasses import dataclass

    @dataclass
    class Details:
        targeted_scope: "list | None" = None

    @dataclass
    class Record:
        hunter: str
        status: str
        score: int
        max_score: int
        verdict_level: str
        confidence: str
        lead_count: int
        review_priority: str
        coverage: object
        findings: list
        details: object

    return Record(hunter="obfuscation", status=status, score=score, max_score=2,
                  verdict_level=verdict_level, confidence="none", lead_count=0,
                  review_priority="none", coverage=None, findings=[], details=Details())


@pytest.mark.parametrize("statuses, expected_status, expected_verdict", [
    (("complete",), "NOT_DETECTED_IN_SCANNED_SCOPE", "clean"),
    (("partial",), "INCONCLUSIVE", "inconclusive"),
    (("not_evaluated",), "NOT_EVALUATED", "not_evaluated"),
])
def test_status_and_verdict_follow_the_closure_coverage_for_a_scoreless_report(
        statuses, expected_status, expected_verdict):
    """A scoped negative earns "clean" only when every closure completed. The
    report's own full-scope-shaped snapshot -- which also weighs observational
    sources a rescan never read -- never decides this."""
    spec = _FakeSpec(_dataclass_record("NOT_DETECTED_IN_SCANNED_SCOPE", 0, "clean"))
    projection = build_targeted_record(
        spec, _Context(), _result(*(_closure(s) for s in statuses)))
    assert projection.record.status == expected_status
    assert projection.record.verdict_level == expected_verdict


def test_a_detected_report_keeps_its_own_verdict_tier_over_partial_coverage():
    """Detection wins over an incomplete scope: a hit inside the bytes that
    WERE evaluated is a real hit, and the gap stays visible in coverage."""
    spec = _FakeSpec(_dataclass_record("DETECTED", 2, "high"))
    projection = build_targeted_record(spec, _Context(), _result(_closure("partial")))
    assert projection.record.status == "DETECTED"
    assert projection.record.verdict_level == "high"
    assert projection.record.coverage.status.value == "partial"


def test_evidence_without_a_closure_that_ran_fails_closed():
    spec = _FakeSpec(_dataclass_record("DETECTED", 1, "likely"))
    with pytest.raises(ValueError, match="never ran"):
        build_targeted_record(spec, _Context(), _result(_closure("not_evaluated")))


def test_the_report_is_carried_out_alongside_the_record():
    """A caller needing an analyzer-specific hook (YARA's rule provenance)
    reads it off this invocation's own report rather than a global."""
    spec = _FakeSpec(_dataclass_record("NOT_DETECTED_IN_SCANNED_SCOPE", 0, "clean"))
    projection = build_targeted_record(spec, _Context(), _result(_closure("complete")))
    assert projection.report == "report-sentinel"


def test_details_gain_the_targeted_scope_entries():
    spec = _FakeSpec(_dataclass_record("NOT_DETECTED_IN_SCANNED_SCOPE", 0, "clean"))
    projection = build_targeted_record(
        spec, _Context(), _result(_closure("complete", scope="sleep_mask"),
                                  _closure("complete", scope="entropy")))
    assert [item.scope for item in projection.record.details.targeted_scope] == [
        "sleep_mask", "entropy"]


def test_obfuscation_is_a_registered_hunter():
    """The fake spec above borrows a real identity; if HUNTERS ever drops it,
    these cases are exercising a shape no analyzer has."""
    assert "obfuscation" in HUNTERS
