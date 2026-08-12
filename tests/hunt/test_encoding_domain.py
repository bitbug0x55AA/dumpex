"""Contract tests for the canonical encoding (obfuscation) domain model
(dumpex.hunt._domain.CheckResult, dumpex.hunt.encoding.domain's
CoverageSnapshot/EncodingEvidence/EncodingReport). Mirrors
tests/hunt/test_injection_domain.py (the completed reference pilot's own
test suite) -- see that module's own docstring for the general
acceptance criteria this module applies to the encoding hunter:

  1. Recursive mutation attempts fail for every nested collection and
     value object.
  2. Mutating a constructor input after construction cannot change the
     constructed object.
  3. The model retains no minidump, resolver, projector, verbosity,
     Finding, HunterRecord, dict, or console-string reference -- poison
     objects of each kind are rejected at construction.
  4. The derived judgment properties agree with the shared reducers
     dumpex.hunt._finding/_coverage already own.
"""
import dataclasses
import enum
from types import MappingProxyType

import pytest

from tests.fixtures.fakes import Region

from dumpex.hunt._domain import CheckResult, require_recursively_immutable
from dumpex.hunt._finding import (
    Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt._location import Location
from dumpex.hunt.encoding import aggregate as encoding_aggregate
from dumpex.hunt.encoding.domain import (
    MAX_SCORE, VERDICT_LEVEL_BY_SCORE, CoverageSnapshot, EncodingEvidence, EncodingReport,
)
from dumpex.hunt.encoding.models import (
    Classification, DecodedHit, DecodeResult, EntropyHit, LayerCoverage, LayerResult, RegionRef,
)
from dumpex.output.coverage import ScanTarget, ScanTargetKind


# ── Builders ────────────────────────────────────────────────────────────

def _region(base=0x300000, protect="PAGE_READWRITE", is_rwx=False):
    return RegionRef(base_address=base, allocation_base=base, size=0x1000,
                      state="MEM_COMMIT", protect=protect, type="MEM_PRIVATE", is_rwx=is_rwx)


def _location(va=0x300000):
    return Location(va=va, region_base=va, file_offset=0x400)


def _cls(kind="pe", is_pe=False, is_shellcode=False, ioc_strings=()):
    return Classification(kind=kind, is_pe=is_pe, is_shellcode=is_shellcode,
                           ioc_strings=ioc_strings, hex_prefix="4d5a", entropy=1.0)


def _hit(layer="base64", base=0x300000, is_pe=False, is_shellcode=False, is_rwx=False, **overrides):
    kwargs = dict(layer=layer, region=_region(base, is_rwx=is_rwx), location=_location(base),
                  decoded=b"X" * 32, classification=_cls(is_pe=is_pe, is_shellcode=is_shellcode))
    if layer == "base64":
        kwargs["raw"] = b"QQQQ"   # base64 hits always carry the raw encoded string in production
    kwargs.update(overrides)
    return DecodedHit(**kwargs)


def _entropy_hit(base=0x400000, entropy=7.5, threshold=7.2):
    return EntropyHit(region=_region(base), location=_location(base),
                       entropy=entropy, threshold=threshold)


def _coverage(**overrides):
    kwargs = dict(memory_info_stream=True, region_count=1, any_region_scanned=True)
    kwargs.update(overrides)
    return CoverageSnapshot(**kwargs)


def _read_failed_target(base=0x500000, size=0x2000):
    # read_failed/short_read targets never carry size_limit -- these
    # causes are never a size cap the target exceeded (see
    # dumpex.output.coverage.ScanTarget's own docstring).
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base, size=size)


def _check(check="obfuscation.base64_observation", tag=TAG_OBSERVATION,
           confidence=CONFIDENCE_LOW, evidence=(), **overrides):
    kwargs = dict(check=check, inference="something was observed",
                   confidence=confidence, rationale="because of the evidence above",
                   evidence=evidence, tag=tag)
    kwargs.update(overrides)
    return CheckResult(**kwargs)


def _report(score=0, results=(), evidence=None, coverage=None):
    return EncodingReport(score=score, coverage=coverage or _coverage(), results=results,
                           evidence=evidence if evidence is not None else EncodingEvidence())


def _populated_report():
    pe_hit = _hit(layer="base64", base=0x300000, is_pe=True)
    shellcode_hit = _hit(layer="xor", base=0x310000, is_shellcode=True, is_rwx=True)
    evidence = EncodingEvidence(
        base64_hits=(pe_hit,), xor_hits=(shellcode_hit,),
        pe_hits=(pe_hit,), shellcode_hits=(shellcode_hit,),
        shellcode_context_hits=(shellcode_hit,),
    )
    results = (
        _check(check="obfuscation.structural_payload", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(pe_hit,)),
        _check(check="obfuscation.shellcode_bootstrap_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(shellcode_hit,)),
    )
    return EncodingReport(score=1, coverage=_coverage(), results=results, evidence=evidence)


DOMAIN_TYPES = [CheckResult, CoverageSnapshot, EncodingEvidence, EncodingReport]


@pytest.mark.parametrize("domain_type", DOMAIN_TYPES, ids=[t.__name__ for t in DOMAIN_TYPES])
def test_domain_type_is_a_frozen_dataclass(domain_type):
    assert dataclasses.is_dataclass(domain_type)
    assert domain_type.__dataclass_params__.frozen is True


# ── 1. Recursive immutability ─────────────────────────────────────────────

def _walk(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            item = getattr(value, f.name)
            yield value, f.name, item
            yield from _walk(item)
    elif isinstance(value, (tuple, frozenset)):
        for item in value:
            yield from _walk(item)


def test_every_nested_value_object_rejects_attribute_assignment():
    report = _populated_report()
    seen = 0
    for owner, name, _value in _walk(report):
        seen += 1
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(owner, name, "tampered")
    assert seen > 15, "the walk did not actually reach the nested evidence"


def _reachable(value):
    yield value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from _reachable(getattr(value, f.name))
    elif isinstance(value, (tuple, frozenset)):
        for item in value:
            yield from _reachable(item)


def test_no_mutable_collection_is_reachable_from_a_report():
    for value in _reachable(_populated_report()):
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"a mutable {type(value).__name__} is reachable from the Report: {value!r}")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True, (
                f"a non-frozen {type(value).__name__} is reachable from the Report")


def test_report_collections_reject_in_place_mutation():
    report = _populated_report()
    for collection in (report.results, report.evidence.base64_hits, report.evidence.pe_hits,
                       report.evidence.shellcode_context_hits, report.results[0].evidence):
        assert isinstance(collection, tuple)
        with pytest.raises(AttributeError):
            collection.append("late")


# ── 2. Constructor inputs are copied, not retained ────────────────────────

def test_mutating_the_results_list_after_construction_cannot_change_the_report():
    results = [_check()]
    report = _report(results=results)
    results.append(_check(check="obfuscation.xor_observation"))
    assert len(report.results) == 1


def test_mutating_an_evidence_list_after_construction_cannot_change_the_report():
    hits = [_hit()]
    evidence = EncodingEvidence(base64_hits=hits)
    hits.append(_hit(base=0x320000))
    assert len(evidence.base64_hits) == 1


def test_mutating_a_check_results_evidence_list_after_construction_changes_nothing():
    evidence_list = [_hit()]
    result = _check(evidence=evidence_list)
    evidence_list.clear()
    assert len(result.evidence) == 1


# ── 3. Poison objects: what the model must refuse to retain ───────────────

class _FakeResolver:
    def __call__(self, *args, **kwargs):   # pragma: no cover - never invoked
        raise AssertionError("a resolver must never be reachable from the domain model")


class _FakeMinidumpFile:
    pass


_POISON = [
    pytest.param(Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                        "MEM_PRIVATE"), id="raw-minidump-region"),
    pytest.param(_FakeMinidumpFile(), id="minidump-file"),
    pytest.param(_FakeResolver(), id="address-resolver"),
    pytest.param({"base_address": 0x1000}, id="hand-rolled-dict"),
    pytest.param("VA=0x1000 decoded_type=PE", id="console-fact-string"),
    pytest.param(True, id="verbosity-flag"),
]


@pytest.mark.parametrize("poison", _POISON)
def test_check_result_evidence_rejects_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        _check(evidence=(poison,))


@pytest.mark.parametrize("poison", _POISON)
def test_report_evidence_buckets_reject_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        EncodingEvidence(base64_hits=(poison,))


def test_check_result_evidence_rejects_a_finding():
    finding = Finding(check="obfuscation.base64_observation", facts=["VA=0x1000"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _check(evidence=(finding,))


def test_report_results_reject_findings():
    finding = Finding(check="obfuscation.base64_observation", facts=["VA=0x1000"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _report(results=(finding,))


@dataclasses.dataclass(frozen=True)
class _EvidenceHoldingAList:
    hits: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class _MutableEvidence:
    base_address: int = 0


def test_check_result_evidence_rejects_a_frozen_object_holding_a_mutable_collection():
    with pytest.raises(TypeError):
        _check(evidence=(_EvidenceHoldingAList(hits=[1, 2]),))


def test_check_result_evidence_rejects_a_non_frozen_dataclass():
    with pytest.raises(TypeError):
        _check(evidence=(_MutableEvidence(),))


def test_frozen_dataclass_with_undeclared_instance_state_is_rejected():
    hit = _hit()
    object.__setattr__(hit, "extra_payload", [])
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(hit, "test")


def test_subclass_cannot_hide_mutable_state_in_its_own_extra_slot():
    @dataclasses.dataclass(frozen=True)
    class _SlottedBase:
        __slots__ = ("a",)
        a: int

    class _Evil(_SlottedBase):
        __slots__ = ("hidden",)

        def __init__(self, a):
            object.__setattr__(self, "a", a)
            object.__setattr__(self, "hidden", [])

    instance = _Evil(1)
    assert not hasattr(instance, "__dict__")
    assert "hidden" not in {f.name for f in dataclasses.fields(instance)}
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(instance, "test")


class _MutablePayloadWrapper:
    def __init__(self):
        self.hits = []


@pytest.mark.parametrize("smuggled", [
    pytest.param(_FakeMinidumpFile(), id="minidump-file"),
    pytest.param(_FakeResolver(), id="address-resolver"),
    pytest.param(_MutablePayloadWrapper(), id="custom-mutable-payload"),
    pytest.param(object(), id="bare-object"),
    pytest.param(RegionRef, id="class-object"),
])
def test_frozen_evidence_cannot_smuggle_an_unrecognized_object_in_a_field(smuggled):
    # EntropyHit's own __post_init__ now type-checks `region` directly, so
    # the poison reference is rejected at EntropyHit construction itself
    # -- never getting far enough to reach CheckResult/EncodingEvidence at
    # all (a strictly earlier, stronger rejection point than a bare
    # `require_recursively_immutable` walk from the container alone would
    # give, since that walk cannot tell "wrong type" from "right type,
    # unrecognized contents" -- see EntropyHit.__post_init__).
    with pytest.raises(TypeError, match="EntropyHit.region must be"):
        EntropyHit(region=smuggled, location=_location(), entropy=7.5, threshold=7.2)


class _State(enum.Enum):
    PRESENT = "present"


class _StrState(str, enum.Enum):
    PRESENT = "present"


def test_immutable_leaves_and_containers_are_still_accepted():
    @dataclasses.dataclass(frozen=True)
    class _Leaves:
        a: object = None
        b: object = 0x1000
        c: object = "PAGE_EXECUTE_READWRITE"
        d: object = b"MZ"
        e: object = 1.5
        f: object = _State.PRESENT
        g: object = _StrState.PRESENT
        h: object = dataclasses.field(default_factory=tuple)
        i: object = dataclasses.field(default_factory=frozenset)

    require_recursively_immutable(_Leaves(), "leaves")


def test_a_mapping_proxy_view_is_rejected():
    with pytest.raises(TypeError, match="EntropyHit.region must be"):
        EntropyHit(region=MappingProxyType({0x1000: ()}), location=_location(),
                  entropy=7.5, threshold=7.2)


def test_a_mapping_proxy_view_nested_inside_a_well_typed_field_is_still_rejected():
    # The isinstance checks in DecodedHit's own __post_init__ only look at
    # its DIRECT fields (region/location/classification) -- a
    # MappingProxyType hiding a level deeper, inside an otherwise
    # correctly-typed Classification's own `pe_info` field, is exactly
    # what the require_recursively_immutable(self, ...) depth check
    # exists to still catch.
    poisoned = Classification(kind="pe", is_pe=True, is_shellcode=False,
                              pe_info=MappingProxyType({0x1000: ()}))
    with pytest.raises(TypeError, match="read-only view is not an immutable value"):
        DecodedHit(layer="base64", region=_region(), location=_location(),
                  decoded=b"X", classification=poisoned)


@pytest.mark.parametrize("not_a_sequence", [
    pytest.param({"base64_hits": ()}, id="dict"),
    pytest.param("VA=0x1000", id="bare-string"),
    pytest.param(iter(()), id="generator"),
    pytest.param({_hit()}, id="set"),
])
def test_evidence_must_be_a_list_or_tuple_not_any_iterable(not_a_sequence):
    with pytest.raises(TypeError):
        _check(evidence=not_a_sequence)


def test_report_rejects_a_coverage_dict_in_place_of_the_snapshot():
    with pytest.raises(TypeError):
        EncodingReport(score=0, coverage={"memory_info_stream": True})


def test_report_rejects_an_evidence_dict_in_place_of_the_container():
    with pytest.raises(TypeError):
        EncodingReport(score=0, coverage=_coverage(), evidence={"base64_hits": ()})


def test_report_evidence_buckets_reject_the_wrong_evidence_type():
    with pytest.raises(TypeError):
        EncodingEvidence(base64_hits=(_entropy_hit(),))


def test_a_bucket_rejects_the_same_object_listed_twice():
    hit = _hit()
    with pytest.raises(ValueError, match="already in this bucket"):
        EncodingEvidence(base64_hits=(hit, hit))


# ── Bucket-to-bucket identity relations ───────────────────────────────────

def test_pe_hits_must_be_drawn_from_the_source_hit_buckets():
    stray_pe = _hit(base=0x999000, is_pe=True)
    with pytest.raises(ValueError, match="not one of"):
        EncodingEvidence(base64_hits=(_hit(base=0x300000, is_pe=True),), pe_hits=(stray_pe,))


def test_pe_hits_and_shellcode_hits_are_mutually_exclusive():
    hit = _hit(is_pe=True)
    # A hit cannot be BOTH classified is_pe AND is_shellcode -- constructing
    # such a hit at all is already a contradiction, so exercise the overlap
    # check with two distinct hits sharing identity via a shared bucket
    # entry instead: same object placed in both subset buckets.
    with pytest.raises(ValueError):
        EncodingEvidence(base64_hits=(hit,), pe_hits=(hit,), shellcode_hits=(hit,))


def test_pe_hits_rejects_a_hit_not_actually_classified_as_pe():
    hit = _hit(is_pe=False)
    with pytest.raises(ValueError, match="is not is_pe"):
        EncodingEvidence(base64_hits=(hit,), pe_hits=(hit,))


def test_shellcode_hits_rejects_a_hit_not_actually_classified_as_shellcode():
    hit = _hit(is_shellcode=False)
    with pytest.raises(ValueError, match="is not is_shellcode"):
        EncodingEvidence(base64_hits=(hit,), shellcode_hits=(hit,))


def test_shellcode_context_hits_must_be_a_subset_of_shellcode_hits():
    stray = _hit(base=0x999000, is_shellcode=True, is_rwx=True)
    with pytest.raises(ValueError, match="not one of"):
        EncodingEvidence(xor_hits=(_hit(base=0x300000, is_shellcode=True, is_rwx=True),),
                         shellcode_hits=(_hit(base=0x300000, is_shellcode=True, is_rwx=True),),
                         shellcode_context_hits=(stray,))


def test_shellcode_context_hits_rejects_a_hit_whose_region_is_not_rwx_private():
    hit = _hit(is_shellcode=True, is_rwx=False)
    with pytest.raises(ValueError, match="MEM_PRIVATE \\+ RWX"):
        EncodingEvidence(xor_hits=(hit,), shellcode_hits=(hit,), shellcode_context_hits=(hit,))


def test_report_stores_no_second_copy_of_its_evidence():
    hit = _hit(is_pe=True)
    report = _report(results=(_check(check="obfuscation.structural_payload", evidence=(hit,)),),
                     evidence=EncodingEvidence(base64_hits=(hit,), pe_hits=(hit,)))
    assert report.results[0].evidence[0] is report.evidence.base64_hits[0]


def test_report_rejects_a_result_citing_evidence_no_bucket_accounts_for():
    bucket_hit = _hit(base=0x300000)
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        _report(results=(_check(evidence=(_hit(base=0x999000),)),),
                evidence=EncodingEvidence(base64_hits=(bucket_hit,)))


def test_report_rejects_a_result_citing_an_equal_but_separate_copy():
    bucket_item, identical_copy = _hit(), _hit()
    assert bucket_item == identical_copy and bucket_item is not identical_copy
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(identical_copy,)),),
                evidence=EncodingEvidence(base64_hits=(bucket_item,)))


def test_report_rejects_a_result_citing_a_merely_nested_object():
    hit = _hit()
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(hit.region,)),),
                evidence=EncodingEvidence(base64_hits=(hit,)))


# ── 4. Derived judgment fields ────────────────────────────────────────────

def test_status_is_derived_from_score_and_coverage():
    assert _report(score=0).status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert _report(score=1).status == "DETECTED"
    assert _report(score=0,
                    coverage=_coverage(entropy_read_failed=(_read_failed_target(),))
                    ).status == "INCONCLUSIVE"
    not_evaluated = _coverage(memory_info_stream=False)
    assert _report(score=0, coverage=not_evaluated).status == "NOT_EVALUATED"


def test_derived_judgment_fields_match_the_shared_reducers():
    report = _populated_report()
    assert report.max_score == MAX_SCORE
    assert report.confidence == overall_confidence(report.results, report.score)
    assert report.verdict_level == verdict_level(report.score, VERDICT_LEVEL_BY_SCORE,
                                                  status=report.status)
    assert report.lead_count == lead_count(report.results)
    assert report.review_priority == review_priority(report.results, report.score,
                                                      report.status)


def test_verdict_level_table_is_shared_with_the_production_domain():
    assert encoding_aggregate.build_report.__module__.endswith("aggregate")
    from dumpex.hunt.encoding import domain as encoding_domain
    assert encoding_domain.VERDICT_LEVEL_BY_SCORE is VERDICT_LEVEL_BY_SCORE


def test_score_above_the_hunters_ceiling_is_rejected():
    with pytest.raises(ValueError):
        _report(score=MAX_SCORE + 1)


def test_check_result_severity_is_derived_not_settable():
    assert _check(tag=TAG_OBSERVATION, confidence=CONFIDENCE_HIGH).severity == "info"
    assert _check(tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH).severity == "critical"
    assert "severity" not in {f.name for f in dataclasses.fields(CheckResult)}


def test_report_holds_no_dump_resolver_or_projection_field():
    field_names = {f.name for f in dataclasses.fields(EncodingReport)}
    assert field_names == {"score", "coverage", "results", "evidence"}
    forbidden = field_names & {"mf", "verbose", "detail_level", "level", "findings",
                                "findings_list", "record", "coverage_report"}
    assert not forbidden


# ── Coverage snapshot ─────────────────────────────────────────────────────

def test_coverage_snapshot_status_matches_the_shared_reducer():
    assert _coverage().status == "complete"
    assert _coverage(sleep_mask_read_failed=(_read_failed_target(),)).status == "partial"
    assert _coverage(entropy_short_read=(_read_failed_target(),)).status == "partial"
    assert _coverage(budget_exhausted=True).status == "partial"
    assert _coverage(memory_info_stream=False).status == "not_evaluated"


def test_coverage_snapshot_read_failed_and_short_reads_sum_across_layers():
    # read_failed/short_reads (issue #28 P2 follow-up) are derived totals
    # across all three layers, NOT stored counts -- a region failing under
    # two layers' own independent scans counts as two gaps, one per layer.
    coverage = _coverage(sleep_mask_read_failed=(_read_failed_target(base=0x1000),),
                          decode_read_failed=(_read_failed_target(base=0x1000),),
                          entropy_short_read=(_read_failed_target(base=0x2000),))
    assert coverage.read_failed == 2
    assert coverage.short_reads == 1
    layers = {layer for layer, _ in coverage.read_failed_targets_by_layer()}
    assert layers == {"sleep_mask", "decode"}


def test_coverage_snapshot_keeps_unsupplied_record_counts_distinct_from_empty():
    assert CoverageSnapshot(memory_info_stream=True).region_count is None
    assert CoverageSnapshot(memory_info_stream=True, region_count=0).region_count == 0


def test_coverage_snapshot_fully_skipped_requires_regions_and_no_scan():
    assert _coverage(any_region_scanned=False).fully_skipped is True
    assert _coverage(any_region_scanned=True).fully_skipped is False
    assert _coverage(region_count=0, any_region_scanned=False).fully_skipped is False
    assert _coverage(memory_info_stream=False, any_region_scanned=False).fully_skipped is False


def test_coverage_snapshot_oversized_targets_by_layer_preserves_fixed_order():
    target = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x2000,
                        size_limit=0x1000)
    coverage = _coverage(decode_oversized=(target,), sleep_mask_oversized=(target,))
    layers = [layer for layer, _ in coverage.oversized_targets_by_layer()]
    assert layers == ["sleep_mask", "decode"]


def test_coverage_snapshot_rejects_non_boolean_stream_flag():
    with pytest.raises(TypeError):
        _coverage(memory_info_stream=1)


def test_coverage_snapshot_oversized_buckets_reject_non_scan_target_items():
    with pytest.raises(TypeError):
        _coverage(decode_oversized=({"base_address": 0x1000},))


def test_coverage_snapshot_read_failed_short_read_buckets_reject_non_scan_target_items():
    # Companion to the oversized-bucket check above -- the per-layer
    # read-failed/short-read tuples (issue #28 P2 follow-up) go through
    # the exact same _require_scan_targets() validation.
    with pytest.raises(TypeError):
        _coverage(sleep_mask_read_failed=({"base_address": 0x1000},))
    with pytest.raises(TypeError):
        _coverage(entropy_short_read=({"base_address": 0x1000},))


# ── Scan-layer transport types (LayerResult/DecodeResult/LayerCoverage) ───
# Issue #5 names `Hit`/`EntropyHit`/`LayerResult`/`DecodeResult` and
# coverage explicitly as recursively-immutable -- distinct from the four
# domain types above (CheckResult/CoverageSnapshot/EncodingEvidence/
# EncodingReport), these three are the scan-layer-to-aggregate transport
# shapes `sleep_mask.py`/`entropy.py`/`decoding.py` return, never
# retained on the Report itself, but still required to be frozen so a
# scan's own result cannot be mutated between collection and the one
# `aggregate.build_report()` read of it.

SCAN_TRANSPORT_TYPES = [LayerCoverage, LayerResult, DecodeResult]


@pytest.mark.parametrize("transport_type", SCAN_TRANSPORT_TYPES,
                         ids=[t.__name__ for t in SCAN_TRANSPORT_TYPES])
def test_scan_transport_type_is_a_frozen_dataclass(transport_type):
    assert dataclasses.is_dataclass(transport_type)
    assert transport_type.__dataclass_params__.frozen is True


def _tracker(**overrides):
    from dumpex.hunt._coverage import CoverageTracker
    tracker = CoverageTracker()
    for name, value in overrides.items():
        setattr(tracker, name, value)
    return tracker


def test_layer_coverage_from_tracker_snapshots_the_trackers_current_state():
    target = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x2000,
                        size_limit=0x1000)
    tracker = _tracker(scanned=3, read_failed=1, short_reads=2, budget_exhausted=True,
                       skipped_oversize_targets=[target])
    snapshot = LayerCoverage.from_tracker(tracker)
    assert snapshot == LayerCoverage(scanned=3, read_failed=1, short_reads=2,
                                     budget_exhausted=True, skipped_oversize_targets=(target,))
    assert isinstance(snapshot.skipped_oversize_targets, tuple)


def test_layer_coverage_does_not_stay_linked_to_the_live_tracker():
    # The whole point of freezing at the scan/aggregate boundary: further
    # mutation of the ORIGINAL tracker (e.g. a later region in the same
    # scan loop) must not retroactively change an already-returned
    # snapshot.
    tracker = _tracker(scanned=1)
    snapshot = LayerCoverage.from_tracker(tracker)
    tracker.scanned = 99
    tracker.note_read_failed()
    assert snapshot.scanned == 1
    assert snapshot.read_failed == 0


def test_layer_coverage_mutating_the_source_target_list_after_construction_cannot_change_it():
    target = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x2000,
                        size_limit=0x1000)
    targets = [target]
    snapshot = LayerCoverage(skipped_oversize_targets=targets)
    targets.append(ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x2000, size=0x2000,
                              size_limit=0x1000))
    assert snapshot.skipped_oversize_targets == (target,)


def test_layer_coverage_fields_reject_attribute_assignment():
    snapshot = LayerCoverage.from_tracker(_tracker())
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.scanned = 99
    with pytest.raises(AttributeError):
        snapshot.skipped_oversize_targets.append("late")


@pytest.mark.parametrize("result_type, field_name, builder", [
    (LayerResult, "hits", lambda: _hit()),
    (DecodeResult, "base64", lambda: _hit(layer="base64")),
    (DecodeResult, "xor", lambda: _hit(layer="xor")),
    (DecodeResult, "compressed", lambda: _hit(layer="gzip")),
], ids=["LayerResult.hits", "DecodeResult.base64", "DecodeResult.xor", "DecodeResult.compressed"])
def test_transport_result_field_is_frozen_to_a_tuple(result_type, field_name, builder):
    hit = builder()
    items = [hit]
    result = result_type(**{field_name: items})
    stored = getattr(result, field_name)
    assert isinstance(stored, tuple)
    assert stored == (hit,)

    # 2. Mutating the constructor's own list afterward must not reach in.
    items.append(builder())
    assert len(getattr(result, field_name)) == 1

    # 1. The returned tuple itself rejects in-place mutation.
    with pytest.raises(AttributeError):
        stored.append("late")


def test_layer_result_rejects_attribute_reassignment():
    result = LayerResult(hits=(_hit(),), coverage=LayerCoverage.from_tracker(_tracker()))
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.hits = ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.coverage = None


def test_decode_result_rejects_attribute_reassignment():
    result = DecodeResult(base64=(_hit(),))
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.base64 = ()


def _reachable_from_transport(value):
    yield value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from _reachable_from_transport(getattr(value, f.name))
    elif isinstance(value, (tuple, frozenset)):
        for item in value:
            yield from _reachable_from_transport(item)


def test_no_mutable_collection_or_non_frozen_dataclass_reachable_from_layer_result():
    target = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x2000,
                        size_limit=0x1000)
    result = LayerResult(hits=(_hit(), _entropy_hit()),
                         coverage=LayerCoverage(skipped_oversize_targets=(target,)))
    seen = 0
    for value in _reachable_from_transport(result):
        seen += 1
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"a mutable {type(value).__name__} is reachable from LayerResult: {value!r}")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True, (
                f"a non-frozen {type(value).__name__} is reachable from LayerResult")
    assert seen > 10, "the walk did not actually reach the nested hits/coverage"


def test_no_mutable_collection_or_non_frozen_dataclass_reachable_from_decode_result():
    target = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x2000,
                        size_limit=0x1000)
    result = DecodeResult(base64=(_hit(layer="base64"),), xor=(_hit(layer="xor"),),
                          compressed=(_hit(layer="gzip"),),
                          coverage=LayerCoverage(skipped_oversize_targets=(target,)))
    seen = 0
    for value in _reachable_from_transport(result):
        seen += 1
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"a mutable {type(value).__name__} is reachable from DecodeResult: {value!r}")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True, (
                f"a non-frozen {type(value).__name__} is reachable from DecodeResult")
    assert seen > 15, "the walk did not actually reach the nested hits/coverage"


# ── Poison-object rejection for the scan-transport types themselves ──────
# The tests above only ever exercise LEGITIMATE, already-immutable
# samples -- a recursive walk over well-formed input proves nothing about
# whether a poisoned CONSTRUCTOR ARGUMENT gets rejected. These exercise
# construction with bad input directly (the exact `LayerResult(hits=
# [inner_list])` shape reported as still-accepted before this fix).

def test_layer_result_hits_rejects_a_bare_mutable_list_item():
    # The reported gap: tuple(value) only copies the OUTER container: a
    # `list` sitting INSIDE that tuple was still reachable and still
    # mutable, since nothing checked what type each item actually was.
    with pytest.raises(TypeError, match="must be a DecodedHit or EntropyHit"):
        LayerResult(hits=[["late-appendable"]])


def test_layer_result_hits_rejects_the_wrong_evidence_type():
    with pytest.raises(TypeError, match="must be a DecodedHit or EntropyHit"):
        LayerResult(hits=[{"region": None}])


def test_layer_result_coverage_only_accepts_a_layer_coverage():
    from dumpex.hunt._coverage import CoverageTracker
    with pytest.raises(TypeError, match="LayerResult.coverage must be a LayerCoverage"):
        LayerResult(hits=(), coverage=CoverageTracker())
    with pytest.raises(TypeError, match="LayerResult.coverage must be a LayerCoverage"):
        LayerResult(hits=(), coverage={"scanned": 1})


def test_decode_result_buckets_reject_a_bare_mutable_list_item():
    with pytest.raises(TypeError, match="DecodeResult.base64\\[0\\] must be a DecodedHit"):
        DecodeResult(base64=[["late-appendable"]])
    with pytest.raises(TypeError, match="DecodeResult.xor\\[0\\] must be a DecodedHit"):
        DecodeResult(xor=[["late-appendable"]])
    with pytest.raises(TypeError, match="DecodeResult.compressed\\[0\\] must be a DecodedHit"):
        DecodeResult(compressed=[["late-appendable"]])


def test_decode_result_rejects_an_entropy_hit_in_a_decode_bucket():
    # DecodeResult's three buckets are DecodedHit-only -- unlike
    # LayerResult.hits, which legitimately holds either type depending on
    # which scan layer produced it.
    with pytest.raises(TypeError, match="must be a DecodedHit"):
        DecodeResult(base64=(_entropy_hit(),))


def test_decode_result_coverage_only_accepts_a_layer_coverage():
    from dumpex.hunt._coverage import CoverageTracker
    with pytest.raises(TypeError, match="DecodeResult.coverage must be a LayerCoverage"):
        DecodeResult(coverage=CoverageTracker())


def test_layer_coverage_skipped_oversize_targets_rejects_non_scan_target_items():
    with pytest.raises(TypeError, match="must be a ScanTarget"):
        LayerCoverage(skipped_oversize_targets=({"base_address": 0x1000},))
    with pytest.raises(TypeError, match="must be a ScanTarget"):
        LayerCoverage(skipped_oversize_targets=([],))


def test_layer_coverage_skipped_oversize_targets_rejects_a_target_holding_a_mutable_field():
    # Depth check: a well-TYPED ScanTarget whose own field was smuggled a
    # mutable payload (via object.__setattr__, bypassing frozen's blocked
    # __setattr__ the same way a subclass or a hand-built poison object
    # would) must still be rejected -- proves the require_recursively_
    # immutable() call is genuinely walking INTO each target, not just
    # isinstance-checking it.
    target = ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x2000,
                        size_limit=0x1000)
    object.__setattr__(target, "hidden", [])
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        LayerCoverage(skipped_oversize_targets=(target,))


@pytest.mark.parametrize("poison", [
    pytest.param(Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                        "MEM_PRIVATE"), id="raw-minidump-region"),
    pytest.param(object(), id="bare-object"),
    pytest.param(True, id="bool"),
])
def test_decoded_hit_region_rejects_poison_objects(poison):
    with pytest.raises(TypeError, match="DecodedHit.region must be a RegionRef"):
        DecodedHit(layer="base64", region=poison, location=_location(),
                  decoded=b"X", classification=_cls())


def test_decoded_hit_location_rejects_a_region_ref_in_its_place():
    # A real, correctly-typed value for the WRONG field -- proves the
    # check is exact-field-typed, not "any recognized type will do".
    with pytest.raises(TypeError, match="DecodedHit.location must be a Location"):
        DecodedHit(layer="base64", region=_region(), location=_region(),
                  decoded=b"X", classification=_cls())


def test_decoded_hit_classification_rejects_a_hand_rolled_dict():
    with pytest.raises(TypeError, match="DecodedHit.classification must be a Classification"):
        DecodedHit(layer="base64", region=_region(), location=_location(),
                  decoded=b"X", classification={"type": "pe", "is_pe": True})


# ── LayerCoverage's own scalar fields ──────────────────────────────────────
# `scanned`/`read_failed`/`short_reads`/`budget_exhausted` are typed int/
# bool in the annotation only -- Python does not enforce that at runtime,
# so nothing previously stopped e.g. `LayerCoverage(scanned=[])` from
# constructing a "frozen" snapshot that still held, and leaked, a mutable
# list through a scalar field (and from there into LayerResult.coverage/
# DecodeResult.coverage, since those only checked `isinstance(coverage,
# LayerCoverage)` -- never that the LayerCoverage itself was well-formed).

@pytest.mark.parametrize("bad_count", [
    pytest.param([], id="list"),
    pytest.param({}, id="dict"),
    pytest.param(-1, id="negative-int"),
    pytest.param(True, id="bool-as-count"),
    pytest.param(1.5, id="float"),
    pytest.param("3", id="numeric-string"),
])
@pytest.mark.parametrize("field_name", ["scanned", "read_failed", "short_reads"])
def test_layer_coverage_count_fields_reject_bad_values(field_name, bad_count):
    with pytest.raises((TypeError, ValueError)):
        LayerCoverage(**{field_name: bad_count})


@pytest.mark.parametrize("bad_flag", [
    pytest.param([], id="list"),
    pytest.param(1, id="int-one"),
    pytest.param(0, id="int-zero"),
    pytest.param("true", id="string"),
    pytest.param(None, id="none"),
])
def test_layer_coverage_budget_exhausted_rejects_non_bool_values(bad_flag):
    with pytest.raises(TypeError, match="LayerCoverage.budget_exhausted must be a bool"):
        LayerCoverage(budget_exhausted=bad_flag)


def test_layer_coverage_scanned_mutable_list_cannot_reach_layer_result_or_decode_result():
    # The reported gap, exercised end to end: constructing a LayerCoverage
    # with a mutable `scanned` must never succeed, so it can never reach
    # LayerResult/DecodeResult's own `coverage` field in the first place.
    inner = []
    with pytest.raises(TypeError, match="LayerCoverage.scanned must be a non-negative int"):
        LayerCoverage(scanned=inner)

    # A well-FORMED LayerCoverage, by contrast, is accepted by both --
    # confirms the fix did not overcorrect into rejecting valid input.
    coverage = LayerCoverage(scanned=1)
    assert LayerResult(hits=(), coverage=coverage).coverage.scanned == 1
    assert DecodeResult(coverage=coverage).coverage.scanned == 1


def test_layer_result_and_decode_result_reject_a_layer_coverage_that_fails_to_construct():
    # A LayerCoverage that never successfully constructs obviously cannot
    # reach LayerResult/DecodeResult either -- but this alone does NOT
    # prove the receiving boundary itself re-validates anything (the error
    # here comes from LayerCoverage's own __post_init__, before
    # LayerResult/DecodeResult ever run). See the test below for the
    # boundary check this one cannot make on its own.
    with pytest.raises(TypeError):
        LayerResult(hits=(), coverage=LayerCoverage(scanned=[]))
    with pytest.raises(TypeError):
        DecodeResult(coverage=LayerCoverage(read_failed={}))


def test_layer_result_and_decode_result_reject_a_layer_coverage_poisoned_after_construction():
    # The real receiving-boundary case: a LayerCoverage that constructed
    # successfully (its own __post_init__ passed) and only afterward had
    # a field poisoned via object.__setattr__ -- frozen blocks ordinary
    # attribute reassignment, not this. `isinstance(coverage,
    # LayerCoverage)` alone is satisfied by this object; only re-walking
    # it with require_recursively_immutable() at the LayerResult/
    # DecodeResult boundary itself catches it.
    coverage = LayerCoverage()
    object.__setattr__(coverage, "scanned", [])

    with pytest.raises(TypeError):
        LayerResult(coverage=coverage)
    with pytest.raises(TypeError):
        DecodeResult(coverage=coverage)
