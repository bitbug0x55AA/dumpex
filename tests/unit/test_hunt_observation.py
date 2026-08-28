"""Execution identity, closure projection, immutability, bounds, and
instrumentation of the observation registry."""
import dataclasses

import pytest

from dumpex.core.va_range import CaptureState, VirtualRange, slice_captured
from dumpex.hunt._observation import (
    DEFAULT_MAX_ENTRIES,
    BudgetOutcome,
    ObservationBudgetExhausted,
    ObservationClosure,
    ObservationKey,
    ObservationOutcome,
    ObservationProducerFailed,
    ObservationRegistry,
    ObservationResult,
)
from dumpex.output.coverage import (
    CoverageLimitation,
    LimitationCode,
    ScanTarget,
    ScanTargetKind,
)


def _limitation():
    target = ScanTarget(
        kind=ScanTargetKind.MEMORY_SEGMENT, base_address=0x10000000, size=0x1000,
        size_limit=None, file_offset=0x2000, captured_size=0x1000)
    return CoverageLimitation(
        code=LimitationCode.SCAN_REGION_READ_FAILED, source="pipe_name_scan",
        affected_count=1, targets=(target,))


def _key(**overrides):
    kwargs = dict(analyzer="pipe", is_targeted=False, algorithm_version="1")
    kwargs.update(overrides)
    return ObservationKey(**kwargs)


def _closure(**overrides):
    kwargs = dict(source="pipe_name_scan", coverage_status="complete",
                  capture_state=CaptureState.COMPLETE)
    kwargs.update(overrides)
    return ObservationClosure(**kwargs)


def _result(key=None, closures=None, **overrides):
    key = key if key is not None else _key()
    closures = closures if closures is not None else (_closure(),)
    return ObservationResult(key=key, closures=closures, **overrides)


# ── execution identity: no source/scope in the key ────────────────────

def test_key_identity_excludes_source_and_scope():
    # Two relationships differing only in attribution build the SAME key.
    a = _key(is_targeted=True, requested_range=VirtualRange(0x10000000, 0x1000))
    b = _key(is_targeted=True, requested_range=VirtualRange(0x10000000, 0x1000))
    assert a == b and hash(a) == hash(b)
    assert not hasattr(a, "source") and not hasattr(a, "scope")


def test_full_and_targeted_do_not_collide_on_overlapping_ranges():
    vr = VirtualRange(0x10000000, 0x1000)
    assert _key(is_targeted=False, requested_range=vr) != _key(is_targeted=True, requested_range=vr)


def test_configuration_and_algorithm_are_part_of_identity():
    base = _key(config_provenance="cfg-a", rule_provenance="rules-a", algorithm_version="1")
    assert base != _key(config_provenance="cfg-b", rule_provenance="rules-a", algorithm_version="1")
    assert base != _key(config_provenance="cfg-a", rule_provenance="rules-b", algorithm_version="1")
    assert base != _key(config_provenance="cfg-a", rule_provenance="rules-a", algorithm_version="2")
    # ... but the coverage locus keys on analyzer + scope + range only
    assert base.coverage_locus == _key(config_provenance="cfg-b").coverage_locus


def test_key_rejects_a_non_hunter_analyzer():
    with pytest.raises(ValueError):
        _key(analyzer="not-a-hunter")


def test_targeted_key_requires_a_range():
    with pytest.raises(ValueError):
        _key(is_targeted=True, requested_range=None)


def test_key_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _key().algorithm_version = "2"


# ── closures: one run, many independently-validated closures ──────────

def test_one_result_projects_pipe_name_and_c2_context_independently():
    vr = VirtualRange(0x10000000, 0x40)
    complete_read = slice_captured(vr, ()).read_input(0)   # capture NONE
    result = _result(
        key=_key(is_targeted=True, requested_range=vr),
        closures=(
            _closure(source="pipe_name_scan", scope="pipe_name",
                     coverage_status="not_evaluated", capture_state=CaptureState.NONE,
                     read_slice=complete_read),
            _closure(source="pipe_name_scan", scope="c2_context",
                     coverage_status="not_evaluated", capture_state=CaptureState.NONE,
                     read_slice=complete_read),
        ))
    assert result.closure_for("pipe_name_scan", "pipe_name").scope == "pipe_name"
    assert result.closure_for("pipe_name_scan", "c2_context").scope == "c2_context"


def test_reused_observation_exposes_two_statuses_without_upgrading():
    from tests.fixtures.fakes import Segment
    from dumpex.core.va_range import CapturedSegment
    vr = VirtualRange(0x10000000, 0x40)
    seg = CapturedSegment.from_segment(Segment(0x10000000, 0x0, 0x40))
    full = slice_captured(vr, (seg,))
    complete_read = full.read_input(0x40)
    short_read = full.read_input(0x10)

    result = _result(
        key=_key(is_targeted=True, requested_range=vr),
        closures=(
            _closure(source="pipe_name_scan", scope="pipe_name",
                     coverage_status="complete", capture_state=CaptureState.COMPLETE,
                     read_slice=complete_read),
            _closure(source="pipe_name_scan", scope="c2_context",
                     coverage_status="partial", capture_state=CaptureState.COMPLETE,
                     read_slice=short_read),
        ))
    registry = ObservationRegistry()
    stored = registry.record(result)
    reused = registry.lookup(result.key)
    assert reused is stored
    assert reused.closure_for("pipe_name_scan", "pipe_name").coverage_status == "complete"
    assert reused.closure_for("pipe_name_scan", "c2_context").coverage_status == "partial"
    # reading the c2_context closure never returns 'complete'
    assert reused.closure_for("pipe_name_scan", "c2_context").coverage_status != "complete"


def test_closure_for_raises_for_an_unprojected_closure():
    result = _result()
    with pytest.raises(KeyError):
        result.closure_for("segment_scan")


def test_result_rejects_duplicate_closure_attribution():
    with pytest.raises(ValueError):
        _result(closures=(_closure(scope="x"), _closure(scope="x")))


def test_result_rejects_empty_closures():
    with pytest.raises(ValueError):
        _result(closures=())


# ── closure consistency ──────────────────────────────────────────────

def test_closure_rejects_capture_state_disagreeing_with_read_slice():
    vr = VirtualRange(0x10000000, 0x40)
    rs = slice_captured(vr, ()).read_input(0)   # capture NONE
    with pytest.raises(ValueError):
        _closure(capture_state=CaptureState.COMPLETE, coverage_status="not_evaluated", read_slice=rs)


def test_closure_rejects_complete_over_incomplete_capture():
    with pytest.raises(ValueError):
        _closure(capture_state=CaptureState.PARTIAL, coverage_status="complete")


def test_closure_rejects_complete_after_a_short_read():
    from tests.fixtures.fakes import Segment
    from dumpex.core.va_range import CapturedSegment
    vr = VirtualRange(0x10000000, 0x40)
    seg = CapturedSegment.from_segment(Segment(0x10000000, 0x0, 0x40))
    short = slice_captured(vr, (seg,)).read_input(0x10)
    with pytest.raises(ValueError):
        ObservationResult(
            key=_key(is_targeted=True, requested_range=vr),
            closures=(_closure(capture_state=CaptureState.COMPLETE,
                               coverage_status="complete", read_slice=short),))


def test_result_rejects_a_closure_read_slice_over_a_different_range():
    key_vr = VirtualRange(0x1000, 0x1000)
    other = slice_captured(VirtualRange(0x9000, 0x20), ()).read_input(0)
    with pytest.raises(ValueError):
        ObservationResult(
            key=_key(is_targeted=True, requested_range=key_vr),
            closures=(_closure(capture_state=CaptureState.NONE,
                               coverage_status="not_evaluated", read_slice=other),))


def test_range_closure_that_ran_must_carry_a_read_slice():
    vr = VirtualRange(0x10000000, 0x40)
    for status in ("partial", "complete"):
        with pytest.raises(ValueError):
            ObservationResult(
                key=_key(is_targeted=False, requested_range=vr),
                closures=(_closure(capture_state=CaptureState.COMPLETE, coverage_status=status),))


def test_range_closure_with_no_capture_must_be_not_evaluated():
    vr = VirtualRange(0x10000000, 0x40)
    with pytest.raises(ValueError):
        ObservationResult(
            key=_key(is_targeted=True, requested_range=vr),
            closures=(_closure(capture_state=CaptureState.NONE, coverage_status="partial"),))


def test_dump_wide_aggregate_needs_no_read_slice():
    result = ObservationResult(
        key=_key(is_targeted=False, requested_range=None),
        closures=(_closure(source="memory_info", capture_state=CaptureState.COMPLETE,
                           coverage_status="complete"),))
    assert result.closures[0].read_slice is None


# ── closure source vocabulary: the closure is the evidence boundary ──

def test_result_rejects_a_closure_source_outside_the_analyzers_vocabulary():
    with pytest.raises(ValueError):
        _result(closures=(_closure(source="totally_made_up_scan"),))


@pytest.mark.parametrize("identity", ["pipe", "stomping", "cs-beacon", "yara", "obfuscation"])
def test_result_accepts_every_real_source_with_no_scope(identity):
    from dumpex.hunt import _registry
    # No per-identity special case: a layer-agnostic closure (scope=None) is
    # legitimate for every real source, obfuscation's encoding_scan included.
    for source in _registry.coverage_sources_for(identity):
        ObservationResult(
            key=_key(analyzer=identity),
            closures=(_closure(source=source, scope=None, coverage_status="partial",
                               capture_state=CaptureState.PARTIAL),))


def test_layer_agnostic_encoding_scan_closure_constructs():
    # obfuscation emits ENCODING_ALL_REGIONS_FILTERED / SCAN_BUDGET_EXHAUSTED
    # on encoding_scan with no scope -- those closures must be representable.
    result = ObservationResult(
        key=_key(analyzer="obfuscation"),
        closures=(_closure(source="encoding_scan", scope=None, coverage_status="partial",
                           capture_state=CaptureState.PARTIAL,
                           budget_outcomes=[BudgetOutcome(name="encoding_decode", exhausted=True)]),))
    assert result.closure_for("encoding_scan", None).budget_outcomes[0].exhausted is True


def test_result_still_rejects_an_invented_obfuscation_layer_scope():
    with pytest.raises(ValueError):
        ObservationResult(
            key=_key(analyzer="obfuscation"),
            closures=(_closure(source="encoding_scan", scope="not-a-layer",
                               coverage_status="partial", capture_state=CaptureState.PARTIAL),))


def test_result_accepts_a_real_obfuscation_layer_scope():
    ObservationResult(
        key=_key(analyzer="obfuscation"),
        closures=(_closure(source="encoding_scan", scope="sleep_mask",
                           coverage_status="partial", capture_state=CaptureState.PARTIAL),))


# ── shared capture across a key's closures ──────────────────────────

def test_result_rejects_closures_disagreeing_about_capture_state():
    vr = VirtualRange(0x10000000, 0x40)
    key = _key(analyzer="obfuscation", is_targeted=True, requested_range=vr)
    with pytest.raises(ValueError):
        ObservationResult(key=key, closures=(
            _closure(source="encoding_scan", scope="sleep_mask",
                     coverage_status="not_evaluated", capture_state=CaptureState.NONE),
            _closure(source="encoding_scan", scope="entropy",
                     coverage_status="complete", capture_state=CaptureState.COMPLETE),
        ))


def test_result_rejects_closures_carrying_different_captured_slices():
    from tests.fixtures.fakes import Segment
    from dumpex.core.va_range import CapturedSegment
    vr = VirtualRange(0x10000000, 0x40)
    # Same COMPLETE capture state, but two structurally different slices
    # (different .dmp file offset) -- one range is captured once, so this
    # cannot happen for real and must be rejected.
    cap_a = slice_captured(vr, (CapturedSegment.from_segment(Segment(0x10000000, 0x0, 0x40)),))
    cap_b = slice_captured(vr, (CapturedSegment.from_segment(Segment(0x10000000, 0x9000, 0x40)),))
    assert cap_a != cap_b and cap_a.state == cap_b.state
    key = _key(analyzer="obfuscation", is_targeted=True, requested_range=vr)
    with pytest.raises(ValueError):
        ObservationResult(key=key, closures=(
            _closure(source="encoding_scan", scope="entropy",
                     coverage_status="complete", capture_state=CaptureState.COMPLETE,
                     read_slice=cap_a.read_input(0x40)),
            _closure(source="encoding_scan", scope="decode",
                     coverage_status="complete", capture_state=CaptureState.COMPLETE,
                     read_slice=cap_b.read_input(0x40)),
        ))


def test_obfuscation_three_layers_share_one_capture_with_differing_status():
    from tests.fixtures.fakes import Segment
    from dumpex.core.va_range import CapturedSegment
    vr = VirtualRange(0x10000000, 0x40)
    seg = CapturedSegment.from_segment(Segment(0x10000000, 0x0, 0x40))
    cap = slice_captured(vr, (seg,))
    key = _key(analyzer="obfuscation", is_targeted=True, requested_range=vr)
    result = ObservationResult(key=key, closures=(
        _closure(source="encoding_scan", scope="sleep_mask", coverage_status="complete",
                 capture_state=CaptureState.COMPLETE, read_slice=cap.read_input(0x40)),
        _closure(source="encoding_scan", scope="entropy", coverage_status="partial",
                 capture_state=CaptureState.COMPLETE, read_slice=cap.read_input(0x20)),
        _closure(source="encoding_scan", scope="decode", coverage_status="not_evaluated",
                 capture_state=CaptureState.COMPLETE, read_slice=cap.read_input(0x40)),
    ))
    assert {c.coverage_status for c in result.closures} == {"complete", "partial", "not_evaluated"}


def test_closure_rejects_a_string_limitation():
    with pytest.raises(ValueError):
        _closure(limitations=["SCAN_REGION_READ_FAILED"])


def test_closure_keeps_structured_limitations_and_budget_outcomes():
    lim = _limitation()
    bo = BudgetOutcome(name="pipe_c2", exhausted=True, limit=200, consumed=200)
    c = _closure(coverage_status="partial", limitations=[lim], budget_outcomes=[bo],
                 diagnostics=["note"])
    assert c.limitations == (lim,)
    assert c.budget_outcomes[0].name == "pipe_c2"
    assert c.diagnostics == ("note",)


def test_result_rejects_a_mutable_payload():
    with pytest.raises(TypeError):
        _result(payload=["not", "immutable"])


# ── registry: identity reuse (AC 8) ──────────────────────────────────

def test_two_attributions_run_the_producer_once(monkeypatch):
    # The pipe case from the issue: one targeted range, projected for both
    # pipe_name and c2_context. Attribution differs; the execution key does
    # not, so the expensive producer runs exactly once.
    vr = VirtualRange(0x10000000, 0x1000)
    key = _key(is_targeted=True, requested_range=vr)
    runs = []

    def producer():
        runs.append(1)
        return ObservationResult(
            key=key,
            closures=(
                _closure(source="pipe_name_scan", scope="pipe_name",
                         coverage_status="not_evaluated", capture_state=CaptureState.NONE),
                _closure(source="pipe_name_scan", scope="c2_context",
                         coverage_status="not_evaluated", capture_state=CaptureState.NONE),
            ))

    registry = ObservationRegistry()
    first = registry.get_or_compute(key, producer)     # "pipe_name" relationship asks
    second = registry.get_or_compute(key, producer)    # "c2_context" relationship asks
    assert second is first
    assert runs == [1]
    assert registry.counts()[ObservationOutcome.PRODUCED] == 1
    assert registry.counts()[ObservationOutcome.REUSED] == 1


def test_incompatible_cache_on_a_stale_config_variant():
    registry = ObservationRegistry()
    registry.record(_result(key=_key(config_provenance="cfg-a")))
    assert registry.lookup(_key(config_provenance="cfg-b")) is None
    assert registry.counts()[ObservationOutcome.INCOMPATIBLE_CACHE] == 1


def test_lookup_miss_with_no_related_entry_records_nothing():
    registry = ObservationRegistry()
    assert registry.lookup(_key()) is None
    assert registry.events() == ()


# ── registry: private storage cannot be handed in ────────────────────

def test_registry_private_storage_is_not_a_constructor_parameter():
    with pytest.raises(TypeError):
        ObservationRegistry(_entries={"x": 1})
    with pytest.raises(TypeError):
        ObservationRegistry(_events=[])


def test_a_fresh_registry_is_empty_and_all_zero():
    r = ObservationRegistry()
    assert r.retained == 0 and r.abandoned == 0
    assert set(r.counts().values()) == {0}


# ── registry: saturation is never silent ────────────────────────────

def test_get_or_compute_raises_when_saturated_and_never_runs_the_producer():
    registry = ObservationRegistry(max_entries=1)
    registry.get_or_compute(_key(config_provenance="a"),
                            lambda: _result(key=_key(config_provenance="a")))
    runs = []
    with pytest.raises(ObservationBudgetExhausted):
        registry.get_or_compute(_key(config_provenance="b"),
                                lambda: runs.append(1) or _result(key=_key(config_provenance="b")))
    assert runs == []
    assert registry.counts()[ObservationOutcome.SATURATED] == 1
    # re-referencing the refused key still raises, still no run
    with pytest.raises(ObservationBudgetExhausted):
        registry.get_or_compute(_key(config_provenance="b"),
                                lambda: runs.append(1) or _result(key=_key(config_provenance="b")))
    assert runs == []


def test_record_past_the_cap_is_saturated_not_retained():
    registry = ObservationRegistry(max_entries=2)
    for i in range(4):
        registry.record(_result(key=_key(config_provenance=f"c{i}")))
    assert registry.retained == 2
    assert registry.record_overflow == 2
    counts = registry.counts()
    assert counts[ObservationOutcome.PRODUCED] == 2
    assert counts[ObservationOutcome.SATURATED] == 2


def test_default_cap_is_positive():
    assert DEFAULT_MAX_ENTRIES > 0
    with pytest.raises(ValueError):
        ObservationRegistry(max_entries=0)


# ── registry: failure tombstones ─────────────────────────────────────

def test_get_or_compute_tombstones_a_failed_producer():
    registry = ObservationRegistry()
    runs = []

    def producer():
        runs.append(1)
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        registry.get_or_compute(_key(), producer)
    with pytest.raises(ObservationProducerFailed) as caught:
        registry.get_or_compute(_key(), producer)
    assert runs == [1]
    assert caught.value.failure_type == "RuntimeError"
    assert registry.counts()[ObservationOutcome.FAILED] == 2
    assert registry.abandoned == 1


def test_get_or_compute_tombstones_a_baseexception_producer():
    registry = ObservationRegistry()
    runs = []

    def producer():
        runs.append(1)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        registry.get_or_compute(_key(), producer)
    assert registry.abandoned == 1
    with pytest.raises(ObservationProducerFailed):
        registry.get_or_compute(_key(), producer)
    assert runs == [1]


def test_a_producer_exception_whose_str_raises_still_tombstones():
    class Nasty(RuntimeError):
        def __str__(self):
            raise ValueError("cannot format me")

    registry = ObservationRegistry()
    runs = []

    def producer():
        runs.append(1)
        raise Nasty()

    with pytest.raises(Nasty):
        registry.get_or_compute(_key(), producer)
    assert registry.abandoned == 1
    with pytest.raises(ObservationProducerFailed) as caught:
        registry.get_or_compute(_key(), producer)
    assert runs == [1]
    assert "could not be formatted" in caught.value.failure_message


def test_repeated_failed_requests_do_not_grow_a_cached_traceback():
    import traceback as _tb
    registry = ObservationRegistry()

    def producer():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        registry.get_or_compute(_key(), producer)
    depths = []
    for _ in range(5):
        try:
            registry.get_or_compute(_key(), producer)
        except ObservationProducerFailed as exc:
            depths.append(len(_tb.extract_tb(exc.__traceback__)))
    assert len(set(depths)) == 1


def test_get_or_compute_tombstones_an_invalid_producer_result():
    for produce, first_exc in (
            (lambda: "not a result", TypeError),
            (lambda: _result(key=_key(config_provenance="other")), ValueError)):
        registry = ObservationRegistry()
        with pytest.raises(first_exc):
            registry.get_or_compute(_key(), produce)
        with pytest.raises(ObservationProducerFailed):
            registry.get_or_compute(_key(), produce)
        assert registry.abandoned == 1 and registry.retained == 0


def test_record_refuses_a_key_already_tombstoned():
    registry = ObservationRegistry()
    with pytest.raises(RuntimeError):
        registry.get_or_compute(_key(), lambda: (_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(ValueError):
        registry.record(_result())
    assert registry.retained == 0
    with pytest.raises(ObservationProducerFailed):
        registry.get_or_compute(_key(), lambda: _result())


def test_tombstoned_keys_count_against_the_budget():
    registry = ObservationRegistry(max_entries=1)
    with pytest.raises(RuntimeError):
        registry.get_or_compute(_key(config_provenance="a"),
                                lambda: (_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(ObservationBudgetExhausted):
        registry.get_or_compute(_key(config_provenance="b"),
                                lambda: _result(key=_key(config_provenance="b")))


def test_note_unavailable_and_failed_record_without_storing():
    registry = ObservationRegistry()
    registry.note_unavailable(_key(config_provenance="a"))
    registry.note_failed(_key(config_provenance="b"))
    assert registry.retained == 0 and registry.abandoned == 0
    counts = registry.counts()
    assert counts[ObservationOutcome.UNAVAILABLE] == 1
    assert counts[ObservationOutcome.FAILED] == 1


def test_counts_are_exact_even_when_the_event_history_is_truncated():
    registry = ObservationRegistry(max_entries=2)
    registry.record(_result(key=_key(config_provenance="a")))
    registry.lookup(_key(config_provenance="a"))
    registry.note_failed(_key(config_provenance="b"))
    registry.note_unavailable(_key(config_provenance="c"))
    assert len(registry.events()) == 2
    counts = registry.counts()
    assert counts[ObservationOutcome.FAILED] == 1
    assert counts[ObservationOutcome.UNAVAILABLE] == 1
    assert registry.event_overflow == 2
