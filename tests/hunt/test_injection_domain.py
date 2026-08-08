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
import enum
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

def _region(base=0x7ffe10000000, protect="PAGE_EXECUTE_READWRITE", alloc=None):
    return RegionRef(base_address=base, allocation_base=base if alloc is None else alloc,
                      size=0x1000, type="MEM_PRIVATE", protect=protect)


def _location(va=0x7ffe10000000):
    return Location(va=va, region_base=va, file_offset=0x400)


def _rwx(base=0x7ffe10000000, alloc=None):
    return RwxRegionEvidence(region=_region(base, alloc=alloc), location=_location(base))


def _pe_hit(base=0x7ffe20000000, alloc=None):
    pe = PeHeaderInfo(valid=True, machine_name="AMD64", is_pe32_plus=True,
                       number_of_sections=1, address_of_entry_point=0x1000,
                       image_base=0x140000000, reason="")
    return HiddenPeEvidence(region=_region(base, "PAGE_READWRITE", alloc=alloc), pe=pe,
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


def _correlation_for(rwx=(), validated_pe_hits=(), **overrides):
    """Build the Correlation InjectionEvidence now REQUIRES to match a
    given `rwx`/`validated_pe_hits` pair -- group_regions_by_allocation()'s
    own grouping, reproduced here so ordinary fixtures don't need to
    hand-write a consistent correlation for every test that isn't
    specifically exercising the correlation-vs-bucket relationship itself.
    Snapshots `rwx`/`validated_pe_hits` at call time (never holds the
    caller's own list), so it is safe to call before a test goes on to
    mutate the list it passed in."""
    rwx_by_alloc, pe_by_alloc = {}, {}
    for ev in rwx:
        rwx_by_alloc.setdefault(ev.region.allocation_base, []).append(ev.region)
    for h in validated_pe_hits:
        pe_by_alloc.setdefault(h.region.allocation_base, []).append(h.region)
    kwargs = dict(rwx_by_alloc=rwx_by_alloc, pe_by_alloc=pe_by_alloc,
                  rwx_and_pe_alloc_bases=set(rwx_by_alloc) & set(pe_by_alloc),
                  suspicious_alloc_bases=set(rwx_by_alloc) | set(pe_by_alloc))
    kwargs.update(overrides)
    return Correlation(**kwargs)


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


_ALLOC = 0x7ffe10000000


def _correlated_evidence(**overrides):
    """One realistic correlated allocation: an RWX sub-region and a
    validated-PE sub-region of the SAME allocation (the split a
    VirtualProtect routinely produces), plus the correlation result that
    recorded the join."""
    rwx = _rwx(_ALLOC)
    pe_hit = _pe_hit(_ALLOC + 0x1000, alloc=_ALLOC)
    rip_hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=rwx.region)
    correlation = Correlation(
        rwx_by_alloc={_ALLOC: [rwx.region]},
        pe_by_alloc={_ALLOC: [pe_hit.region]},
        rwx_and_pe_alloc_bases={_ALLOC},
        suspicious_alloc_bases={_ALLOC},
        rip_hits=[rip_hit],
        rip_full_correlation=[rip_hit],
        start_hits=[StartHitEvidence(thread_id=0x1, start_address=_ALLOC + 0x30,
                                      region=rwx.region)],
    )
    kwargs = dict(
        rwx=[rwx], validated_pe_hits=[pe_hit], suspicious_pe_hits=[pe_hit],
        start_threads=[_thread(start=_ALLOC + 0x30)],
        thread_contexts=[ThreadContext(thread_id=0x1, ip=_ALLOC + 0x10,
                                        ip_reg="RIP", is_wow64=False)],
        correlated_allocations=[CorrelatedAllocationEvidence(
            allocation_base=_ALLOC, regions=[rwx.region, pe_hit.region])],
        correlation=correlation,
    )
    kwargs.update(overrides)
    return InjectionEvidence(**kwargs)


def _populated_report():
    evidence = _correlated_evidence()
    results = (
        _check(evidence=evidence.rwx, evidence_limit=20),
        _check(check="injection.allocation_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=evidence.correlation.rip_hits),
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


def _reachable(value):
    """Every object reachable from `value`. Deliberately an INDEPENDENT
    walk rather than a call into `require_recursively_immutable`: the
    point is to assert the property directly, so a hole opened in the
    production validator cannot also silence the test that checks it."""
    yield value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from _reachable(getattr(value, f.name))
    elif isinstance(value, (tuple, frozenset)):
        for item in value:
            yield from _reachable(item)
    elif isinstance(value, MappingProxyType):
        for key, item in value.items():
            yield from _reachable(key)
            yield from _reachable(item)


def test_no_mutable_collection_is_reachable_from_a_report():
    # The whole-graph assertion the top-level `frozen=True` check cannot
    # make: a frozen Report holding a plain list is still mutable in place.
    for value in _reachable(_populated_report()):
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"a mutable {type(value).__name__} is reachable from the Report: {value!r}")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True, (
                f"a non-frozen {type(value).__name__} is reachable from the Report")


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
    evidence = InjectionEvidence(rwx=rwx_list, correlation=_correlation_for(rwx=rwx_list))
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


def test_frozen_dataclass_with_undeclared_instance_state_is_rejected():
    # A subclass (or any code holding a reference before this function
    # ever sees it) can attach extra state a frozen dataclass's own
    # declared fields say nothing about -- object.__setattr__ bypasses
    # frozen's blocked __setattr__ just as easily for an undeclared
    # attribute as for a declared one. Only walking dataclasses.fields()
    # would never see this at all.
    ev = _rwx()
    object.__setattr__(ev, "extra_payload", [])
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(ev, "test")


def test_frozen_dataclass_missing_a_declared_field_from_its_dict_is_not_rejected():
    # The reverse of the case above must NOT be an error: mixed slotted/
    # unslotted inheritance can legitimately store some declared fields in
    # a __slots__ descriptor rather than in __dict__, so __dict__ holding
    # FEWER entries than declared fields is not itself a defect -- only an
    # EXTRA, undeclared entry is. Each field is still validated regardless
    # of where it physically lives, via getattr().
    @dataclasses.dataclass(frozen=True)
    class _SlottedBase:
        __slots__ = ("a",)
        a: int

    @dataclasses.dataclass(frozen=True)
    class _MixedSubclass(_SlottedBase):
        b: int = 0

    instance = _MixedSubclass(a=1, b=2)
    # `a` lives in the base class's slot descriptor, not in __dict__ --
    # confirms this test actually exercises the scenario it claims to.
    assert "a" not in vars(instance) and "b" in vars(instance)
    require_recursively_immutable(instance, "test")


def test_fully_slotted_dataclass_has_no_dict_at_all_and_is_still_validated():
    @dataclasses.dataclass(frozen=True, slots=True)
    class _FullySlotted:
        a: int = 1
        b: str = "x"

    instance = _FullySlotted()
    assert not hasattr(instance, "__dict__")
    require_recursively_immutable(instance, "test")


def test_subclass_cannot_hide_mutable_state_in_its_own_extra_slot():
    # The escape __dict__-only checking missed: a subclass adds its OWN
    # __slots__ entry beyond its declared dataclass fields. That name
    # never appears in __dict__ (slots don't populate it) and never
    # appears in dataclasses.fields() (it isn't an annotated dataclass
    # field at all) -- so it is invisible to both a __dict__ scan and a
    # declared-fields walk, yet still holds real, mutable, post-
    # construction-writable state.
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
    # Confirms this test actually exercises the scenario it claims to:
    # no __dict__ at all, and "hidden" absent from declared fields.
    assert not hasattr(instance, "__dict__")
    assert "hidden" not in {f.name for f in dataclasses.fields(instance)}
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(instance, "test")


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


class _State(enum.Enum):
    PRESENT = "present"


class _StrState(str, enum.Enum):
    PRESENT = "present"


class _EnumWithMutableValue(enum.Enum):
    LAYERS = ["base64"]      # Enum places no constraint at all on a value


class _EnumWithMutableAttribute(enum.Enum):
    """A member's own instance attributes are no more constrained than its
    value -- `vars(member)` carries them alongside Enum's bookkeeping."""
    LAYER = "base64"

    def __init__(self, _value):
        self.payload = []


class _StrWithMutableAttribute(str):
    """A subclass of an immutable builtin, carrying a mutable payload.
    Every `isinstance(x, str)` test in the world says this is a string."""

    def __new__(cls):
        instance = super().__new__(cls, "MEM_PRIVATE")
        instance.payload = []
        return instance


class _TupleWithMutableAttribute(tuple):
    def __new__(cls):
        instance = super().__new__(cls, ())
        instance.payload = []
        return instance


def test_immutable_leaves_and_containers_are_still_accepted():
    # The allowlist must not be so strict that legitimate evidence fails:
    # scalars, None, bytes, plain and str-backed enum members, tuples and
    # frozensets all pass.
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


@pytest.mark.parametrize("smuggled", [
    pytest.param(_EnumWithMutableValue.LAYERS, id="enum-with-mutable-value"),
    pytest.param(_EnumWithMutableAttribute.LAYER, id="enum-with-mutable-attribute"),
    pytest.param(_StrWithMutableAttribute(), id="str-subclass-with-payload"),
    pytest.param(_TupleWithMutableAttribute(), id="tuple-subclass-with-payload"),
    pytest.param(MappingProxyType({0x1000: ()}), id="mapping-proxy-view"),
])
def test_frozen_evidence_cannot_smuggle_a_mutable_payload_past_the_allowlist(smuggled):
    smuggling = RwxRegionEvidence(region=smuggled, location=_location())
    with pytest.raises(TypeError):
        _check(evidence=(smuggling,))
    with pytest.raises(TypeError):
        InjectionEvidence(rwx=(smuggling,))


def test_a_mapping_proxy_view_stays_mutable_through_its_backing_dict():
    # The concrete reason a proxy is refused rather than walked: it is a
    # live view, so validating its contents at construction proves nothing
    # about what it will report afterwards.
    backing = {0x1000: ()}
    view = MappingProxyType(backing)
    smuggling = RwxRegionEvidence(region=view, location=_location())
    with pytest.raises(TypeError, match="read-only view is not an immutable value"):
        InjectionEvidence(rwx=(smuggling,))
    backing[0x2000] = ("changed after the fact",)
    assert view[0x2000] == ("changed after the fact",)


def test_report_owns_its_correlation_maps_not_the_callers():
    # InjectionEvidence re-creates the correlation so the dicts behind its
    # read-only views are unreachable to whoever built it -- while the hit
    # and region objects inside keep their identity.
    rwx = _rwx()
    backing = {rwx.region.allocation_base: [rwx.region]}
    hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=rwx.region)
    correlation = Correlation(rwx_by_alloc=backing, rip_hits=[hit],
                               suspicious_alloc_bases={rwx.region.allocation_base})
    thread_contexts = (ThreadContext(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP",
                                      is_wow64=False),)
    evidence = InjectionEvidence(rwx=(rwx,), thread_contexts=thread_contexts,
                                  correlation=correlation)

    backing[0x999000] = ["tampered"]
    assert 0x999000 not in evidence.correlation.rwx_by_alloc
    assert evidence.correlation.rwx_by_alloc is not correlation.rwx_by_alloc
    assert evidence.correlation.rip_hits[0] is hit
    assert evidence.correlation.rwx_by_alloc[rwx.region.allocation_base][0] is rwx.region


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


def test_evidence_container_rejects_a_correlation_subclass():
    # A subclass could declare its own __slots__ entry beyond Correlation's
    # own fields -- invisible to require_recursively_immutable's generic
    # dataclass walk because _own_correlation deliberately never runs that
    # walk over the container itself (MappingProxyType would be refused
    # outright). Confirmed: without this check, a subclass's __init__
    # could plant a live, post-construction-mutable list via
    # object.__setattr__ that nothing here would ever see.
    class _EvilCorrelation(Correlation):
        __slots__ = ("payload",)

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            object.__setattr__(self, "payload", [])

    evil = _EvilCorrelation()
    assert evil.payload == []   # confirms the subclass really carries extra state
    with pytest.raises(TypeError, match="exactly Correlation"):
        InjectionEvidence(correlation=evil)


def test_correlation_stored_on_the_report_is_never_a_subclass():
    # Locks in the reconstruction itself, not just the rejection above:
    # even for an ordinary, successful construction, what ends up on the
    # Report is built via the bare Correlation(...) constructor, never
    # dataclasses.replace(correlation) (which would have preserved
    # type(correlation) exactly, including a subclass).
    evidence = InjectionEvidence(correlation=Correlation())
    assert type(evidence.correlation) is Correlation


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
                      evidence=InjectionEvidence(rwx=(rwx,), correlation=_correlation_for(rwx=(rwx,))))
    assert report.results[0].evidence[0] is report.evidence.rwx[0]


def test_report_rejects_a_result_citing_evidence_no_bucket_accounts_for():
    # Both halves are individually well-formed; together they claim two
    # different regions for the same observation. Constructing that Report
    # at all is what "exactly one canonical representation" forbids.
    bucket_rwx = (_rwx(0x7ffe20000000),)
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        _report(results=(_check(evidence=(_rwx(0x7ffe10000000),)),),
                 evidence=InjectionEvidence(rwx=bucket_rwx,
                                             correlation=_correlation_for(rwx=bucket_rwx)))


def test_report_rejects_a_result_citing_an_equal_but_separate_copy():
    # Equality is not enough: an equal-but-distinct object is a second
    # copy of the same fact, which is what "held once" forbids.
    bucket_item, identical_copy = _rwx(), _rwx()
    assert bucket_item == identical_copy and bucket_item is not identical_copy
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(identical_copy,)),),
                 evidence=InjectionEvidence(rwx=(bucket_item,),
                                             correlation=_correlation_for(rwx=(bucket_item,))))


def test_report_accepts_results_citing_correlation_hit_evidence():
    # rip_hits/rip_full_correlation/start_hits are top-level evidence too,
    # they just live on the correlation result rather than in a bucket
    # that would duplicate them. A rip_hit can only legitimately reference
    # an allocation that genuinely carries RWX or a validated PE (see
    # _require_correlation_matches_buckets/_own_correlation's own
    # suspicious_alloc_bases membership check), so this needs a real rwx
    # bucket entry backing it, not a free-floating hit.
    rwx = _rwx(_ALLOC)
    hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=rwx.region)
    thread_contexts = (ThreadContext(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP",
                                      is_wow64=False),)
    evidence = InjectionEvidence(
        rwx=(rwx,), thread_contexts=thread_contexts,
        correlation=_correlation_for(rwx=(rwx,), rip_hits=[hit]))
    report = _report(results=(_check(check="injection.allocation_correlation",
                                      evidence=(hit,)),), evidence=evidence)
    assert report.results[0].evidence[0] is report.evidence.correlation.rip_hits[0]


# ── Bucket-to-bucket identity relations ───────────────────────────────────
# Checking each bucket's own item types still lets two buckets that stand
# in a subset/partition relation describe different facts.

def test_suspicious_and_informational_must_be_drawn_from_validated():
    validated = _pe_hit(0x7ffe20000000)
    with pytest.raises(ValueError, match="not one of"):
        InjectionEvidence(validated_pe_hits=(validated,),
                           suspicious_pe_hits=(_pe_hit(0x7ffe30000000),),
                           correlation=_correlation_for(validated_pe_hits=(validated,)))


def test_a_subset_bucket_rejects_an_equal_but_separate_copy():
    validated, identical_copy = _pe_hit(), _pe_hit()
    assert validated == identical_copy and validated is not identical_copy
    with pytest.raises(ValueError):
        InjectionEvidence(validated_pe_hits=(validated,),
                           suspicious_pe_hits=(identical_copy,),
                           correlation=_correlation_for(validated_pe_hits=(validated,)))


def test_a_validated_hit_cannot_be_both_scoreable_and_context_only():
    hit = _pe_hit()
    with pytest.raises(ValueError, match="partition|both"):
        InjectionEvidence(validated_pe_hits=(hit,), suspicious_pe_hits=(hit,),
                           informational_pe_hits=(hit,),
                           correlation=_correlation_for(validated_pe_hits=(hit,)))


def test_a_validated_hit_in_neither_half_of_the_split_is_rejected():
    # A hit no projection would ever account for: it scores nothing and is
    # reported nowhere.
    validated = (_pe_hit(0x7ffe20000000), _pe_hit(0x7ffe30000000))
    with pytest.raises(ValueError, match="partition"):
        InjectionEvidence(validated_pe_hits=validated, suspicious_pe_hits=(),
                           correlation=_correlation_for(validated_pe_hits=validated))


def test_split_buckets_must_keep_validated_order():
    first, second = _pe_hit(0x7ffe20000000), _pe_hit(0x7ffe30000000)
    validated = (first, second)
    correlation = _correlation_for(validated_pe_hits=validated)
    InjectionEvidence(validated_pe_hits=validated, suspicious_pe_hits=(first, second),
                       correlation=correlation)
    with pytest.raises(ValueError, match="relative order"):
        InjectionEvidence(validated_pe_hits=validated, suspicious_pe_hits=(second, first),
                           correlation=correlation)


def test_mz_only_and_validated_hits_must_be_disjoint():
    hit = _pe_hit()
    with pytest.raises(ValueError, match="both mz_only_hits and validated"):
        InjectionEvidence(validated_pe_hits=(hit,), suspicious_pe_hits=(hit,),
                           mz_only_hits=(hit,),
                           correlation=_correlation_for(validated_pe_hits=(hit,)))


def test_genuinely_disjoint_mz_only_hits_are_accepted():
    validated, mz_only = _pe_hit(0x7ffe20000000), _pe_hit(0x7ffe30000000)
    evidence = InjectionEvidence(validated_pe_hits=(validated,),
                                  suspicious_pe_hits=(validated,),
                                  mz_only_hits=(mz_only,),
                                  correlation=_correlation_for(validated_pe_hits=(validated,)))
    assert evidence.mz_only_hits == (mz_only,)


def test_own_correlation_rejects_a_rip_hit_whose_ip_is_outside_its_own_region():
    # region_ref.base_address/size fully determine the region's own
    # bounds -- this needs no raw MemoryInfo list, unlike proving the
    # region itself was the geometrically correct pick among every region
    # in the dump.
    region = _region(0x1000)   # [0x1000, 0x2000)
    hit = RipHitEvidence(thread_id=0x1, ip=0x9000, ip_reg="RIP", region=region)
    with pytest.raises(ValueError, match=r"does not fall within its own region"):
        InjectionEvidence(correlation=Correlation(
            rip_hits=[hit], suspicious_alloc_bases={0x1000}))


def test_own_correlation_rejects_a_start_hit_whose_address_is_outside_its_own_region():
    region = _region(0x1000)   # [0x1000, 0x2000)
    hit = StartHitEvidence(thread_id=0x1, start_address=0x9000, region=region)
    with pytest.raises(ValueError, match=r"does not fall within its own region"):
        InjectionEvidence(correlation=Correlation(
            start_hits=[hit], suspicious_alloc_bases={0x1000}))


def test_own_correlation_accepts_a_start_hit_with_no_start_address():
    # start_address=None is 0-substituted for the geometric lookup only
    # (matching correlate()'s own `ti.start_address or 0`) -- a region
    # genuinely containing VA 0 must accept a None start_address hit.
    region = _region(0x0, protect="PAGE_EXECUTE_READWRITE")
    rwx = RwxRegionEvidence(region=region, location=Location(va=0, region_base=0, file_offset=None))
    hit = StartHitEvidence(thread_id=0x1, start_address=None, region=region)
    unbacked = UnbackedThreadEvidence(thread_id=0x1, start_address=None,
                                       location=Location(va=0, region_base=0, file_offset=None))
    evidence = InjectionEvidence(
        rwx=(rwx,), start_threads=(unbacked,),
        correlation=_correlation_for(rwx=(rwx,), start_hits=[hit]))
    assert evidence.correlation.start_hits[0] is hit


def test_own_correlation_rejects_a_rip_hit_whose_ip_is_at_the_regions_upper_bound():
    # Half-open interval: base_address + size is one past the last valid
    # byte, matching _region_for_addr's own `addr < BaseAddress + Size`.
    region = _region(0x1000)   # size 0x1000 -> [0x1000, 0x2000)
    hit = RipHitEvidence(thread_id=0x1, ip=0x2000, ip_reg="RIP", region=region)
    with pytest.raises(ValueError, match=r"does not fall within its own region"):
        InjectionEvidence(correlation=Correlation(
            rip_hits=[hit], suspicious_alloc_bases={0x1000}))


def test_own_correlation_rejects_a_rip_hit_whose_ip_is_below_the_regions_base():
    region = _region(0x1000)
    hit = RipHitEvidence(thread_id=0x1, ip=0xfff, ip_reg="RIP", region=region)
    with pytest.raises(ValueError, match=r"does not fall within its own region"):
        InjectionEvidence(correlation=Correlation(
            rip_hits=[hit], suspicious_alloc_bases={0x1000}))


def test_own_correlation_rejects_a_rip_hit_outside_suspicious_alloc_bases():
    # correlate() only ever appends a RipHitEvidence whose OWN region
    # already qualified as suspicious -- a hit referencing an allocation
    # outside suspicious_alloc_bases could not have been produced by it.
    hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=_region())
    with pytest.raises(ValueError, match="rip_hits holds"):
        InjectionEvidence(correlation=Correlation(rip_hits=[hit]))   # suspicious_alloc_bases empty


def test_own_correlation_rejects_a_start_hit_outside_suspicious_alloc_bases():
    hit = StartHitEvidence(thread_id=0x1, start_address=0x9999000, region=_region())
    with pytest.raises(ValueError, match="start_hits holds"):
        InjectionEvidence(correlation=Correlation(start_hits=[hit]))


def test_rip_hits_must_be_drawn_from_thread_contexts():
    # suspicious_alloc_bases is satisfied (a real rwx bucket backs it),
    # but no thread_contexts entry reports this (thread_id, ip, ip_reg) --
    # a fabricated or stale rip_hit.
    rwx = _rwx(_ALLOC)
    hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=rwx.region)
    with pytest.raises(ValueError, match="not one of InjectionEvidence.thread_contexts"):
        InjectionEvidence(rwx=(rwx,), correlation=_correlation_for(rwx=(rwx,), rip_hits=[hit]))


def test_start_hits_must_be_drawn_from_start_threads():
    rwx = _rwx(_ALLOC)
    hit = StartHitEvidence(thread_id=0x1, start_address=_ALLOC + 0x30, region=rwx.region)
    with pytest.raises(ValueError, match="not one of InjectionEvidence.start_threads"):
        InjectionEvidence(rwx=(rwx,), correlation=_correlation_for(rwx=(rwx,), start_hits=[hit]))


def test_rip_hits_can_skip_thread_contexts_entries_that_did_not_correlate():
    # A leading thread_context that never correlated must not block a
    # later one that did -- the subsequence match has to keep consuming
    # candidates past a non-matching one, not just check the first.
    rwx = _rwx(_ALLOC)
    other_tc = ThreadContext(thread_id=0x2, ip=0x1000, ip_reg="RIP", is_wow64=False)
    matching_tc = ThreadContext(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", is_wow64=False)
    hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=rwx.region)
    evidence = InjectionEvidence(
        rwx=(rwx,), thread_contexts=(other_tc, matching_tc),
        correlation=_correlation_for(rwx=(rwx,), rip_hits=[hit]))
    assert evidence.correlation.rip_hits[0] is hit


def test_rip_full_correlation_must_be_a_subset_of_rip_hits():
    hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP", region=_region())
    other = RipHitEvidence(thread_id=0x2, ip=_ALLOC + 0x20, ip_reg="RIP", region=_region())
    thread_contexts = (ThreadContext(thread_id=0x1, ip=_ALLOC + 0x10, ip_reg="RIP",
                                      is_wow64=False),)
    with pytest.raises(ValueError, match="rip_full_correlation"):
        InjectionEvidence(thread_contexts=thread_contexts,
                           correlation=Correlation(rip_hits=[hit], rip_full_correlation=[other],
                                                    suspicious_alloc_bases={_ALLOC}))


def test_a_bucket_rejects_the_same_object_listed_twice():
    rwx = _rwx()
    with pytest.raises(ValueError, match="already in this bucket"):
        InjectionEvidence(rwx=(rwx, rwx))


def test_correlated_allocations_must_materialize_exactly_the_correlated_bases():
    evidence = _correlated_evidence()
    assert [item.allocation_base for item in evidence.correlated_allocations] == [_ALLOC]
    # Dropping the entry leaves the frozenset claiming a correlated
    # allocation the bucket does not account for.
    with pytest.raises(ValueError, match="materialize exactly"):
        _correlated_evidence(correlated_allocations=())


def test_correlated_allocation_regions_must_match_what_correlation_recorded():
    with pytest.raises(ValueError, match="RWX regions followed by"):
        _correlated_evidence(correlated_allocations=[CorrelatedAllocationEvidence(
            allocation_base=_ALLOC, regions=[_region(0x7ffe90000000)])])


def test_correlation_rwx_by_alloc_must_hold_the_buckets_own_regions_in_order():
    # Same allocation, two distinct sub-regions (the routine VirtualProtect
    # split) -- same KEY, but the map lists them in the wrong order.
    rwx_a1 = RwxRegionEvidence(region=_region(0x1000, alloc=0x1000), location=_location(0x1000))
    rwx_a2 = RwxRegionEvidence(region=_region(0x1500, alloc=0x1000), location=_location(0x1500))
    rwx = (rwx_a1, rwx_a2)
    reversed_map = {0x1000: (rwx_a2.region, rwx_a1.region)}
    correlation = Correlation(rwx_by_alloc=reversed_map, suspicious_alloc_bases={0x1000})
    with pytest.raises(ValueError, match="in the order"):
        InjectionEvidence(rwx=rwx, correlation=correlation)


def test_correlation_rwx_and_pe_alloc_bases_must_equal_the_real_intersection():
    rwx = (_rwx(0x1000),)
    validated = (_pe_hit(0x2000),)   # different allocations -- no real overlap
    correlation = _correlation_for(rwx=rwx, validated_pe_hits=validated,
                                    rwx_and_pe_alloc_bases={0x1000})   # wrong: claims overlap
    with pytest.raises(ValueError, match="rwx_and_pe_alloc_bases"):
        InjectionEvidence(rwx=rwx, validated_pe_hits=validated, correlation=correlation)


def test_correlation_suspicious_alloc_bases_must_equal_the_real_union():
    rwx = (_rwx(0x1000), _rwx(0x2000))
    validated = (_pe_hit(0x1000),)
    correlation = _correlation_for(rwx=rwx, validated_pe_hits=validated,
                                    suspicious_alloc_bases={0x1000})   # wrong: missing 0x2000
    with pytest.raises(ValueError, match="suspicious_alloc_bases"):
        InjectionEvidence(rwx=rwx, validated_pe_hits=validated, correlation=correlation)


def test_correlated_allocations_must_be_sorted_and_unique():
    rwx_a, rwx_b = _rwx(0x1000), _rwx(0x2000)
    pe_a, pe_b = _pe_hit(0x1000), _pe_hit(0x2000)
    rwx, validated = (rwx_a, rwx_b), (pe_a, pe_b)
    correlation = _correlation_for(rwx=rwx, validated_pe_hits=validated)
    descending = [CorrelatedAllocationEvidence(allocation_base=0x2000,
                                                regions=[rwx_b.region, pe_b.region]),
                   CorrelatedAllocationEvidence(allocation_base=0x1000,
                                                regions=[rwx_a.region, pe_a.region])]
    with pytest.raises(ValueError, match="ascending"):
        InjectionEvidence(rwx=rwx, validated_pe_hits=validated, suspicious_pe_hits=validated,
                           correlation=correlation, correlated_allocations=descending)


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
