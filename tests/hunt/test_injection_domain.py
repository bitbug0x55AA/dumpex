"""Contract tests for the canonical injection domain model
(dumpex.hunt._domain.CheckResult, dumpex.hunt.injection.domain's
CoverageSnapshot/InjectionEvidence/InjectionReport).

Distinct from its neighbours: tests/hunt/test_injection_models.py covers
the SCAN-layer Evidence value objects and how memory_scan/thread_scan/
correlation build them; tests/hunt/test_output_source_architecture.py
covers the cross-hunter Report boundary and stays xfail for injection's
still-in-production `aggregate.Report` until the cutover issue removes it.
This module covers the model that replaces that Report, which nothing
constructs in production yet.

Acceptance criteria exercised here:

  1. Recursive mutation attempts fail for every nested collection and
     value object -- not merely `__dataclass_params__.frozen is True`,
     which a Report holding a plain list already satisfies.
  2. Mutating a constructor input after construction cannot change the
     constructed object.
  3. The model retains no minidump, resolver, projector, verbosity,
     Finding, HunterRecord, dict, or console-string reference -- poison
     objects of each kind are rejected at construction.
  4. The derived judgment properties agree with the shared reducers
     dumpex.hunt._finding/_coverage already own.
"""
import dataclasses
from types import MappingProxyType

import pytest

from tests.fixtures.fakes import Region, ThreadInfo

from dumpex.hunt._domain import CheckResult, require_recursively_immutable
from dumpex.hunt._finding import (
    Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt._location import Location
from dumpex.hunt.injection import aggregate as injection_aggregate
from dumpex.hunt.injection.domain import (
    MAX_SCORE, VERDICT_LEVEL_BY_SCORE, CoverageSnapshot, InjectionEvidence, InjectionReport,
)
from dumpex.hunt.injection.models import (
    Correlation, CorrelatedAllocationEvidence, HiddenPeEvidence, PeHeaderInfo, RegionRef,
    RipHitEvidence, RwxRegionEvidence, StartHitEvidence, ThreadContext, UnbackedThreadEvidence,
)


# ── Builders (plain helpers, not fixtures: several tests need two or ──────
# three independent instances within one test).

def _region(base=0x7ffe10000000, protect="PAGE_EXECUTE_READWRITE"):
    return RegionRef(base_address=base, allocation_base=base, size=0x1000,
                      type="MEM_PRIVATE", protect=protect)


def _location(va=0x7ffe10000000):
    return Location(va=va, region_base=va, file_offset=0x400)


def _rwx(base=0x7ffe10000000):
    return RwxRegionEvidence(region=_region(base), location=_location(base))


def _pe_hit(base=0x7ffe20000000):
    pe = PeHeaderInfo(valid=True, machine_name="AMD64", is_pe32_plus=True,
                       number_of_sections=1, address_of_entry_point=0x1000,
                       image_base=0x140000000, reason="")
    return HiddenPeEvidence(region=_region(base, "PAGE_READWRITE"), pe=pe,
                             in_module_list=False, location=_location(base))


def _thread(tid=0x1, start=0x9999000):
    return UnbackedThreadEvidence(thread_id=tid, start_address=start,
                                   location=_location(start))


def _coverage(**overrides):
    kwargs = dict(memory_info_stream=True, thread_info_stream=True,
                   module_list_stream=True, thread_list_stream=True,
                   threads_total=2, contexts_parsed=2)
    kwargs.update(overrides)
    return CoverageSnapshot(**kwargs)


def _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
            evidence=(), **overrides):
    kwargs = dict(check=check, inference="something was observed",
                   confidence=confidence, rationale="because of the evidence above",
                   evidence=evidence, tag=tag)
    kwargs.update(overrides)
    return CheckResult(**kwargs)


def _report(score=0, results=(), evidence=None, coverage=None):
    return InjectionReport(score=score, coverage=coverage or _coverage(),
                            results=results,
                            evidence=evidence if evidence is not None else InjectionEvidence())


DOMAIN_TYPES = [CheckResult, CoverageSnapshot, InjectionEvidence, InjectionReport,
                 ThreadContext, CorrelatedAllocationEvidence]


@pytest.mark.parametrize("domain_type", DOMAIN_TYPES, ids=[t.__name__ for t in DOMAIN_TYPES])
def test_domain_type_is_a_frozen_dataclass(domain_type):
    assert dataclasses.is_dataclass(domain_type)
    assert domain_type.__dataclass_params__.frozen is True


# ── 1. Recursive immutability ─────────────────────────────────────────────

def _walk(value):
    """Yield (owner, field_name, value) for every dataclass field reachable
    from `value`, so a test can attempt the actual mutation on each nested
    object rather than only inspecting the top-level one."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            item = getattr(value, f.name)
            yield value, f.name, item
            yield from _walk(item)
    elif isinstance(value, (tuple, frozenset)):
        for item in value:
            yield from _walk(item)
    elif isinstance(value, MappingProxyType):
        for item in value.values():
            yield from _walk(item)


def _populated_report():
    rwx, pe_hit, thread = _rwx(), _pe_hit(), _thread()
    correlation = Correlation(
        rwx_by_alloc={rwx.region.allocation_base: [rwx.region]},
        pe_by_alloc={pe_hit.region.allocation_base: [pe_hit.region]},
        rwx_and_pe_alloc_bases={rwx.region.allocation_base},
        suspicious_alloc_bases={rwx.region.allocation_base},
        rip_hits=[RipHitEvidence(thread_id=0x1, ip=0x7ffe10000010, ip_reg="RIP",
                                  region=rwx.region)],
        start_hits=[StartHitEvidence(thread_id=0x1, start_address=0x9999000,
                                      region=rwx.region)],
    )
    evidence = InjectionEvidence(
        rwx=[rwx], validated_pe_hits=[pe_hit], suspicious_pe_hits=[pe_hit],
        start_threads=[thread],
        thread_contexts=[ThreadContext(thread_id=0x1, ip=0x7ffe10000010,
                                        ip_reg="RIP", is_wow64=False)],
        correlated_allocations=[CorrelatedAllocationEvidence(
            allocation_base=rwx.region.allocation_base, regions=[rwx.region, pe_hit.region])],
        correlation=correlation,
    )
    results = (
        _check(evidence=(rwx,), evidence_limit=20),
        _check(check="injection.allocation_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=correlation.rip_hits),
    )
    return InjectionReport(score=3, coverage=_coverage(), results=results, evidence=evidence)


def test_every_nested_value_object_rejects_attribute_assignment():
    report = _populated_report()
    seen = 0
    for owner, name, _value in _walk(report):
        seen += 1
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(owner, name, "tampered")
    assert seen > 20, "the walk did not actually reach the nested evidence"


def test_no_mutable_collection_is_reachable_from_a_report():
    # The whole-graph assertion the top-level `frozen=True` check cannot
    # make: a frozen Report holding a plain list is still mutable in place.
    require_recursively_immutable(_populated_report(), "InjectionReport")


def test_report_collections_reject_in_place_mutation():
    report = _populated_report()
    for collection in (report.results, report.evidence.rwx, report.evidence.start_threads,
                       report.evidence.correlated_allocations[0].regions,
                       report.results[0].evidence):
        assert isinstance(collection, tuple)
        with pytest.raises(AttributeError):
            collection.append("late")
    with pytest.raises(TypeError):
        report.evidence.correlation.rwx_by_alloc[0x2000] = ()
    with pytest.raises(AttributeError):
        report.evidence.correlation.rwx_and_pe_alloc_bases.add(0x2000)


# ── 2. Constructor inputs are copied, not retained ────────────────────────

def test_mutating_the_results_list_after_construction_cannot_change_the_report():
    results = [_check()]
    report = _report(results=results)
    results.append(_check(check="injection.mz_prefix_unvalidated"))
    assert len(report.results) == 1


def test_mutating_an_evidence_list_after_construction_cannot_change_the_report():
    rwx_list = [_rwx()]
    evidence = InjectionEvidence(rwx=rwx_list)
    rwx_list.append(_rwx(0x7ffe30000000))
    assert len(evidence.rwx) == 1


def test_mutating_a_check_results_evidence_list_after_construction_changes_nothing():
    evidence_list = [_rwx()]
    result = _check(evidence=evidence_list)
    evidence_list.clear()
    assert len(result.evidence) == 1


def test_mutating_a_correlated_allocations_region_list_changes_nothing():
    regions = [_region()]
    correlated = CorrelatedAllocationEvidence(allocation_base=0x1000, regions=regions)
    regions.append(_region(0x7ffe30000000))
    assert len(correlated.regions) == 1


@pytest.mark.parametrize("not_a_sequence", [
    pytest.param("ab", id="bare-string"),
    pytest.param({"region": None}, id="dict"),
    pytest.param({_region()}, id="set"),
    pytest.param(iter(()), id="generator"),
])
def test_correlated_allocation_regions_must_be_a_list_or_tuple(not_a_sequence):
    # `tuple(value)` alone would accept every one of these -- silently
    # turning "ab" into ("a", "b"), and taking hash-order-dependent
    # ordering from a set/dict into a field whose order is the contract.
    with pytest.raises(TypeError):
        CorrelatedAllocationEvidence(allocation_base=0x1000, regions=not_a_sequence)


def test_correlated_allocation_regions_must_hold_region_refs():
    with pytest.raises(TypeError):
        CorrelatedAllocationEvidence(allocation_base=0x1000, regions=[_rwx()])


# ── 3. Poison objects: what the model must refuse to retain ───────────────

class _FakeResolver:
    """Stands in for a `read_region`/`va_to_file_offset`-style callable a
    Report must never hold: address resolution belongs to the scan layer
    that already resolved every Location once."""

    def __call__(self, *args, **kwargs):   # pragma: no cover - never invoked
        raise AssertionError("a resolver must never be reachable from the domain model")


class _FakeMinidumpFile:
    """Stands in for `mf` -- the raw dump handle the guardrails name first."""


_POISON = [
    pytest.param(Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                        "MEM_PRIVATE"), id="raw-minidump-region"),
    pytest.param(ThreadInfo(0x1, 0x2000), id="raw-minidump-threadinfo"),
    pytest.param(_FakeMinidumpFile(), id="minidump-file"),
    pytest.param(_FakeResolver(), id="address-resolver"),
    pytest.param({"base_address": 0x1000}, id="hand-rolled-dict"),
    pytest.param("VA=0x1000 AllocationBase=0x1000 size=0x1000", id="console-fact-string"),
    pytest.param(True, id="verbosity-flag"),
]


@pytest.mark.parametrize("poison", _POISON)
def test_check_result_evidence_rejects_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        _check(evidence=(poison,))


@pytest.mark.parametrize("poison", _POISON)
def test_report_evidence_buckets_reject_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        InjectionEvidence(rwx=(poison,))


def test_check_result_evidence_rejects_a_finding():
    # Finding IS a frozen dataclass, so the generic frozen-dataclass rule
    # alone would let it back in -- it is the rendered PROJECTION of a
    # CheckResult and must never become one's evidence.
    finding = Finding(check="injection.rwx_regions", facts=["VA=0x1000"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _check(evidence=(finding,))


def test_report_results_reject_findings():
    finding = Finding(check="injection.rwx_regions", facts=["VA=0x1000"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _report(results=(finding,))


@dataclasses.dataclass(frozen=True)
class _EvidenceHoldingAList:
    """A frozen dataclass is not automatically an immutable one: `frozen`
    blocks reassigning `hits`, not `hits.append(...)`. An evidence type
    written this way is exactly the recursive-immutability hole the
    guardrail names, and must be refused rather than quietly stored."""
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


class _MutablePayloadWrapper:
    """An arbitrary custom object holding a mutable payload. A denylist
    walker that only knows list/dict/set/dataclass would treat this as an
    immutable leaf and let `hits` stay mutable through the Report."""

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
    # The evidence ITEM is a frozen dataclass, so the item-level check
    # passes -- the escape hatch is one level down, in a field the scan
    # layer's own value objects do not type-check. An unrecognized object
    # is never assumed immutable.
    smuggling = RwxRegionEvidence(region=smuggled, location=_location())
    with pytest.raises(TypeError):
        _check(evidence=(smuggling,))
    with pytest.raises(TypeError):
        InjectionEvidence(rwx=(smuggling,))


def test_immutable_leaves_and_containers_are_still_accepted():
    # The allowlist must not be so strict that legitimate evidence fails:
    # scalars, None, bytes, enum members, tuples, frozensets and the
    # MappingProxyType Correlation normalizes to all pass.
    import enum

    class _State(enum.Enum):
        PRESENT = "present"

    @dataclasses.dataclass(frozen=True)
    class _Leaves:
        a: object = None
        b: object = 0x1000
        c: object = "PAGE_EXECUTE_READWRITE"
        d: object = b"MZ"
        e: object = 1.5
        f: object = _State.PRESENT
        g: object = dataclasses.field(default_factory=tuple)
        h: object = dataclasses.field(default_factory=frozenset)

    require_recursively_immutable(_Leaves(), "leaves")
    require_recursively_immutable(
        Correlation(rwx_by_alloc={0x1000: [_region()]}), "correlation")


@pytest.mark.parametrize("not_a_sequence", [
    pytest.param({"rwx": ()}, id="dict"),
    pytest.param("VA=0x1000", id="bare-string"),
    pytest.param(iter(()), id="generator"),
    pytest.param({_rwx()}, id="set"),
])
def test_evidence_must_be_a_list_or_tuple_not_any_iterable(not_a_sequence):
    # A bare string would explode into characters, a set/dict would carry
    # hash-order-dependent ordering into an order-significant field, and a
    # generator would read empty on the second pass.
    with pytest.raises(TypeError):
        _check(evidence=not_a_sequence)


def test_report_rejects_a_coverage_dict_in_place_of_the_snapshot():
    # The v1.1 `coverage` dict is a PROJECTION of the snapshot, not an
    # alternative representation the Report may hold instead.
    with pytest.raises(TypeError):
        InjectionReport(score=0, coverage={"memory_info_stream": True})


def test_report_rejects_an_evidence_dict_in_place_of_the_container():
    with pytest.raises(TypeError):
        InjectionReport(score=0, coverage=_coverage(), evidence={"rwx": ()})


def test_report_evidence_buckets_reject_the_wrong_evidence_type():
    with pytest.raises(TypeError):
        InjectionEvidence(rwx=(_thread(),))


def test_evidence_container_rejects_a_non_correlation():
    with pytest.raises(TypeError):
        InjectionEvidence(correlation={"rwx_by_alloc": {}})


def test_report_holds_no_dump_resolver_or_projection_field():
    field_names = {f.name for f in dataclasses.fields(InjectionReport)}
    assert field_names == {"score", "coverage", "results", "evidence"}
    forbidden = field_names & {"mf", "verbose", "detail_level", "level", "findings",
                                "findings_list", "record", "coverage_report"}
    assert not forbidden


def test_report_stores_no_second_copy_of_its_evidence():
    # The CheckResult references the SAME object the bucket holds --
    # shared immutable structure, not a parallel representation that could
    # drift from it.
    rwx = _rwx()
    report = _report(results=(_check(evidence=(rwx,)),),
                      evidence=InjectionEvidence(rwx=(rwx,)))
    assert report.results[0].evidence[0] is report.evidence.rwx[0]


def test_report_rejects_a_result_citing_evidence_no_bucket_accounts_for():
    # Both halves are individually well-formed; together they claim two
    # different regions for the same observation. Constructing that Report
    # at all is what "exactly one canonical representation" forbids.
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        _report(results=(_check(evidence=(_rwx(0x7ffe10000000),)),),
                 evidence=InjectionEvidence(rwx=(_rwx(0x7ffe20000000),)))


def test_report_rejects_a_result_citing_an_equal_but_separate_copy():
    # Equality is not enough: an equal-but-distinct object is a second
    # copy of the same fact, which is what "held once" forbids.
    bucket_item, identical_copy = _rwx(), _rwx()
    assert bucket_item == identical_copy and bucket_item is not identical_copy
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(identical_copy,)),),
                 evidence=InjectionEvidence(rwx=(bucket_item,)))


def test_report_accepts_results_citing_correlation_hit_evidence():
    # rip_hits/rip_full_correlation/start_hits are top-level evidence too,
    # they just live on the correlation result rather than in a bucket
    # that would duplicate them.
    hit = RipHitEvidence(thread_id=0x1, ip=0x7ffe10000010, ip_reg="RIP", region=_region())
    evidence = InjectionEvidence(correlation=Correlation(rip_hits=[hit]))
    report = _report(results=(_check(check="injection.allocation_correlation",
                                      evidence=(hit,)),), evidence=evidence)
    assert report.results[0].evidence[0] is report.evidence.correlation.rip_hits[0]


def test_report_rejects_a_result_citing_a_merely_nested_object():
    # A RegionRef reachable INSIDE an RwxRegionEvidence is not itself a
    # citable evidence item -- allowing nested objects would make the
    # containment check vacuous.
    rwx = _rwx()
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(rwx.region,)),),
                 evidence=InjectionEvidence(rwx=(rwx,)))


# ── 4. Derived judgment fields ────────────────────────────────────────────

def test_status_is_derived_from_score_and_coverage():
    assert _report(score=0).status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert _report(score=2).status == "DETECTED"
    assert _report(score=0, coverage=_coverage(module_list_stream=False)).status == "INCONCLUSIVE"
    not_evaluated = _coverage(memory_info_stream=False, thread_info_stream=False)
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


def test_verdict_level_table_is_shared_with_the_production_aggregate():
    # One table, not two copies that a later scoring change could update
    # separately.
    assert injection_aggregate._VERDICT_LEVEL_BY_SCORE is VERDICT_LEVEL_BY_SCORE


def test_score_above_the_hunters_ceiling_is_rejected():
    with pytest.raises(ValueError):
        _report(score=MAX_SCORE + 1)


def test_check_result_severity_is_derived_not_settable():
    assert _check(tag=TAG_OBSERVATION, confidence=CONFIDENCE_HIGH).severity == "info"
    assert _check(tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH).severity == "critical"
    assert "severity" not in {f.name for f in dataclasses.fields(CheckResult)}


def test_check_result_rejects_an_unknown_tag_or_confidence():
    with pytest.raises(ValueError):
        _check(tag="critical")
    with pytest.raises(ValueError):
        _check(confidence="very-high")


def test_check_result_evidence_limit_must_be_a_positive_int():
    assert _check(evidence_limit=20).evidence_limit == 20
    assert _check().evidence_limit is None
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            _check(evidence_limit=bad)


def test_check_result_rule_id_defaults_to_the_check_id():
    assert _check().rule_id == "injection.rwx_regions"
    assert _check(rule_id="custom").rule_id == "custom"


# ── Coverage snapshot ─────────────────────────────────────────────────────

def test_coverage_snapshot_derives_thread_context_and_missing_counts():
    coverage = _coverage(threads_total=5, contexts_parsed=2)
    assert coverage.thread_context is True
    assert coverage.contexts_missing == 3
    assert coverage.complete is False
    assert coverage.status == "partial"

    none_parsed = _coverage(threads_total=5, contexts_parsed=0)
    assert none_parsed.thread_context is False
    assert none_parsed.contexts_missing == 5


def test_coverage_snapshot_status_matches_the_shared_reducer():
    assert _coverage().status == "complete"
    assert _coverage(pe_read_failed=1).status == "partial"
    assert _coverage(pe_short_reads=1).status == "partial"
    assert _coverage(memory_info_stream=False, thread_info_stream=False).status == "not_evaluated"
    # A single missing evaluation source still leaves the hunter evaluated
    # (it produced a narrower but real result), just not complete.
    assert _coverage(memory_info_stream=False).status == "partial"


def test_coverage_snapshot_keeps_unsupplied_record_counts_distinct_from_empty():
    assert _coverage().region_count is None
    assert _coverage(region_count=0).region_count == 0


def test_coverage_snapshot_rejects_non_boolean_stream_flags_and_bad_counts():
    with pytest.raises(TypeError):
        _coverage(memory_info_stream=1)
    with pytest.raises(TypeError):
        _coverage(threads_total=True)
    with pytest.raises(ValueError):
        _coverage(contexts_parsed=-1)
