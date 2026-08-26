"""Hunter-specific contracts for the canonical stomping domain model."""
import dataclasses
import enum
from types import MappingProxyType

import pytest

from tests.fixtures.fakes import Region, Module

from dumpex.hunt._domain import CheckResult, require_recursively_immutable
from dumpex.hunt._finding import (
    Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.stomping import aggregate as stomping_aggregate
from dumpex.hunt.stomping.domain import (
    MAX_SCORE, VERDICT_LEVEL_BY_SCORE, COVERAGE_COUNT_FIELDS,
    CoverageSnapshot, StompingEvidence, StompingReport,
)
from dumpex.hunt.stomping.models import (
    IdentityMismatchEvidence, IocCoverage, IocHitEvidence, IocScanResult, IocTokenHit,
    ModuleRef, ParseFailedEvidence, ProtectionLeadEvidence, RegionRef,
    RipCorrelatedLeadEvidence, SectionDiffResult, SectionRef, ThreadHitRef,
    VerifiedChangeEvidence, module_ref, region_ref, section_ref,
)
from dumpex.output.coverage import ScanTarget, ScanTargetKind


# ── Builders ────────────────────────────────────────────────────────────

_MODULE_BASE = 0x7ff600000000
_SECTION_VA  = _MODULE_BASE + 0x1000


def _module(base=_MODULE_BASE, name=r"C:\Windows\System32\legit.dll"):
    return ModuleRef(name=name, basename=name.rsplit("\\", 1)[-1] if name else "",
                      base_address=base, size=0x5000)


def _section(name=".text", vaddr=0x1000, vsize=0x2000):
    return SectionRef(name=name, virtual_address=vaddr, virtual_size=vsize,
                       pointer_to_raw_data=0x400, size_of_raw_data=vsize,
                       characteristics=0x60000020, is_executable=True,
                       is_writable=False, is_readable=True)


def _region(base=_SECTION_VA, protect="PAGE_EXECUTE_READWRITE"):
    return RegionRef(base_address=base, allocation_base=_MODULE_BASE, size=0x2000,
                      state="MEM_COMMIT", protect=protect, type="MEM_IMAGE")


def _thread(tid=0x42, ip=_SECTION_VA + 0x10):
    return ThreadHitRef(thread_id=tid, ip=ip, ip_reg="RIP")


def _protection_lead(base=_SECTION_VA, **overrides):
    kwargs = dict(module=_module(), section=_section(), region=_region(base),
                   expected="PAGE_EXECUTE_READ", actual="PAGE_EXECUTE_READWRITE",
                   va_start=base, va_end=base + 0x2000)
    kwargs.update(overrides)
    return ProtectionLeadEvidence(**kwargs)


def _verified_change(rip=False, ranges=((0x0, 0x10),), **overrides):
    kwargs = dict(module=_module(), section=_section(), va_start=_SECTION_VA,
                   diff_ranges=ranges, ranges_truncated=False, total_ranges=len(ranges),
                   compared_len=0x2000, rip_in_changed_range=rip,
                   disk_sha256="a" * 64, mem_sha256="b" * 64)
    kwargs.update(overrides)
    return VerifiedChangeEvidence(**kwargs)


def _identity_mismatch(reason="TimeDateStamp mismatch"):
    return IdentityMismatchEvidence(module=_module(), section=_section(), reason=reason)


def _parse_failed(reason="no MZ signature"):
    return ParseFailedEvidence(module=_module(), reason=reason)


def _token(offset=0x40, va=_SECTION_VA + 0x40, token="mimikatz", is_weak=False):
    return IocTokenHit(offset=offset, va=va, encoding="ASCII", token=token, is_weak=is_weak)


def _ioc_hit(base=_SECTION_VA, tokens=None, module=True):
    return IocHitEvidence(region=_region(base), module=_module() if module else None,
                           tokens=tokens if tokens is not None else (_token(),),
                           not_whitelisted=True)


def _coverage(**overrides):
    kwargs = dict(memory_info_stream=True, module_list_stream=True, ref_dir_supplied=True,
                   modules_total=1, headers_parsed=1, sections_total=1, sections_compared=1)
    kwargs.update(overrides)
    return CoverageSnapshot(**kwargs)


def _check(check="stomping.protection_deviation_lead", tag=TAG_OBSERVATION,
           confidence=CONFIDENCE_LOW, evidence=(), **overrides):
    kwargs = dict(check=check, inference="something was observed",
                   confidence=confidence, rationale="because of the evidence above",
                   evidence=evidence, tag=tag)
    kwargs.update(overrides)
    return CheckResult(**kwargs)


def _report(score=0, results=(), evidence=None, coverage=None):
    return StompingReport(score=score, coverage=coverage or _coverage(), results=results,
                           evidence=evidence if evidence is not None else StompingEvidence())


def _populated_report():
    lead = _protection_lead()
    correlated = RipCorrelatedLeadEvidence(lead=lead, thread=_thread())
    change = _verified_change(rip=True)
    ioc = _ioc_hit()
    evidence = StompingEvidence(
        protection_leads=(lead,), rip_correlated_leads=(correlated,),
        verified_changes=(change,), identity_mismatches=(_identity_mismatch(),),
        parse_failures=(_parse_failed(),), ioc_hits=(ioc,))
    results = (
        _check(check="stomping.protection_deviation_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(lead,), evidence_limit=20),
        _check(check="stomping.verified_content_change", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(change,), evidence_limit=15),
        _check(check="stomping.ioc_string_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(ioc,), evidence_limit=15),
    )
    return StompingReport(score=2, coverage=_coverage(), results=results, evidence=evidence)


DOMAIN_TYPES = [CheckResult, CoverageSnapshot, StompingEvidence, StompingReport]
EVIDENCE_TYPES = [ModuleRef, SectionRef, RegionRef, ThreadHitRef, ProtectionLeadEvidence,
                  RipCorrelatedLeadEvidence, VerifiedChangeEvidence, IdentityMismatchEvidence,
                  ParseFailedEvidence, IocTokenHit, IocHitEvidence, IocCoverage,
                  IocScanResult, SectionDiffResult]


# ── Construction success for every evidence type ──────────────────────────

def test_every_evidence_type_constructs_from_well_formed_input():
    assert _module().basename == "legit.dll"
    assert _section().name == ".text"
    assert _region().protect == "PAGE_EXECUTE_READWRITE"
    assert _thread().ip_reg == "RIP"
    assert _protection_lead().va_end == _SECTION_VA + 0x2000
    assert RipCorrelatedLeadEvidence(lead=_protection_lead(), thread=_thread()).thread.thread_id
    assert _verified_change().total_ranges == 1
    assert _identity_mismatch().reason
    assert _parse_failed().reason
    assert _token().va == _SECTION_VA + 0x40
    assert _ioc_hit().tokens[0].token == "mimikatz"
    assert IocCoverage().complete is True
    assert IocScanResult().hits == ()
    assert SectionDiffResult(module=_module(), section=_section(),
                             va_start=_SECTION_VA).all_ranges == ()


def test_scan_time_builders_resolve_identity_once():
    """`module_ref`/`section_ref`/`region_ref` are the ONE place a raw
    minidump object/PE-header dict becomes a snapshot -- basename and
    prot_str() resolution happen there, never later."""
    raw_module = Module(_MODULE_BASE, 0x5000, r"C:\Windows\System32\legit.dll")
    raw_region = Region(_SECTION_VA, _MODULE_BASE, 0x2000, "MEM_COMMIT",
                         "PAGE_EXECUTE_READWRITE", "MEM_IMAGE")
    raw_section = {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x2000,
                   "pointer_to_raw_data": 0x400, "size_of_raw_data": 0x2000,
                   "characteristics": 0x60000020, "is_executable": True,
                   "is_writable": False, "is_readable": True}

    assert module_ref(raw_module).basename == "legit.dll"
    assert module_ref(raw_module).name == r"C:\Windows\System32\legit.dll"
    assert region_ref(raw_region).protect == "PAGE_EXECUTE_READWRITE"
    assert region_ref(raw_region).state == "MEM_COMMIT"
    assert section_ref(raw_section).is_executable is True
    for snapshot in (module_ref(raw_module), region_ref(raw_region), section_ref(raw_section)):
        require_recursively_immutable(snapshot, "snapshot")


@pytest.mark.parametrize("factory, kwargs, exc", [
    pytest.param(ModuleRef, dict(name=b"x", basename="x", base_address=0), TypeError,
                 id="module-name-bytes"),
    pytest.param(ModuleRef, dict(name="x", basename="x", base_address=-1), ValueError,
                 id="module-negative-base"),
    pytest.param(ModuleRef, dict(name="x", basename="x", base_address=True), TypeError,
                 id="module-bool-base"),
    pytest.param(SectionRef, dict(name=".text", virtual_address=0, virtual_size=0,
                                   pointer_to_raw_data=0, size_of_raw_data=0,
                                   characteristics=0, is_executable=1,
                                   is_writable=False, is_readable=True), TypeError,
                 id="section-int-for-bool"),
    pytest.param(RegionRef, dict(base_address=0, allocation_base=None, size=0,
                                  state="MEM_COMMIT", protect=None, type="MEM_IMAGE"), TypeError,
                 id="region-none-protect"),
    pytest.param(ThreadHitRef, dict(thread_id=1, ip=1, ip_reg=None), TypeError,
                 id="thread-none-ip-reg"),
    pytest.param(IocTokenHit, dict(offset=0, va=0, encoding="ASCII", token="x",
                                    is_weak="yes"), TypeError, id="token-str-for-bool"),
])
def test_evidence_construction_rejects_bad_field_values(factory, kwargs, exc):
    with pytest.raises(exc):
        factory(**kwargs)


def test_verified_change_rejects_a_total_smaller_than_what_it_kept():
    with pytest.raises(ValueError, match="total_ranges"):
        _verified_change(ranges=((0, 1), (4, 1)), total_ranges=1)


def test_verified_change_normalizes_diff_ranges_to_tuples_of_ints():
    change = _verified_change(ranges=[[0x10, 0x4]])
    assert change.diff_ranges == ((0x10, 0x4),)
    assert all(isinstance(r, tuple) for r in change.diff_ranges)


@pytest.mark.parametrize("bad_ranges", [
    pytest.param([(0x10,)], id="one-element-pair"),
    pytest.param([(0x10, 0x4, 0x2)], id="three-element-pair"),
    pytest.param([(0x10, "4")], id="string-length"),
    pytest.param([(-1, 4)], id="negative-offset"),
])
def test_verified_change_rejects_malformed_diff_ranges(bad_ranges):
    with pytest.raises((TypeError, ValueError)):
        _verified_change(ranges=bad_ranges)


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
    assert seen > 40, "the walk did not actually reach the nested evidence"


def _reachable(value):
    yield value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from _reachable(getattr(value, f.name))
    elif isinstance(value, (tuple, frozenset)):
        for item in value:
            yield from _reachable(item)


def test_report_collections_reject_in_place_mutation():
    report = _populated_report()
    for collection in (report.results, report.evidence.protection_leads,
                       report.evidence.verified_changes, report.evidence.ioc_hits,
                       report.evidence.ioc_hits[0].tokens,
                       report.evidence.verified_changes[0].diff_ranges,
                       report.results[0].evidence):
        assert isinstance(collection, tuple)
        with pytest.raises(AttributeError):
            collection.append("late")


def test_the_whole_report_passes_the_shared_recursive_immutability_check():
    require_recursively_immutable(_populated_report(), "StompingReport")


# ── 2. Constructor inputs are copied, not retained ────────────────────────

def test_mutating_the_results_list_after_construction_cannot_change_the_report():
    results = [_check()]
    report = _report(results=results)
    results.append(_check(check="stomping.module_header_invalid"))
    assert len(report.results) == 1


def test_mutating_an_evidence_list_after_construction_cannot_change_the_report():
    leads = [_protection_lead()]
    evidence = StompingEvidence(protection_leads=leads)
    leads.append(_protection_lead(base=_SECTION_VA + 0x4000))
    assert len(evidence.protection_leads) == 1


def test_mutating_a_check_results_evidence_list_after_construction_changes_nothing():
    evidence_list = [_protection_lead()]
    result = _check(evidence=evidence_list)
    evidence_list.clear()
    assert len(result.evidence) == 1


def test_mutating_a_diff_range_list_after_construction_changes_nothing():
    ranges = [(0x0, 0x10)]
    change = _verified_change(ranges=ranges, total_ranges=1)
    ranges.append((0x40, 0x4))
    assert change.diff_ranges == ((0x0, 0x10),)


def test_ioc_coverage_does_not_stay_linked_to_the_live_tracker():
    from dumpex.hunt._coverage import CoverageTracker
    tracker = CoverageTracker()
    tracker.read_failed = 1
    snapshot = IocCoverage.from_tracker(tracker, ["wininet.dll"])
    tracker.note_read_failed()
    tracker.note_short_read()
    assert snapshot.read_failed == 1
    assert snapshot.short_reads == 0
    assert snapshot.whitelisted_skipped == ("wininet.dll",)


# ── 3. Poison objects: what the model must refuse to retain ───────────────

class _FakeResolver:
    def __call__(self, *args, **kwargs):   # pragma: no cover - never invoked
        raise AssertionError("a resolver must never be reachable from the domain model")


class _FakeMinidumpFile:
    pass


_POISON = [
    pytest.param(Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                        "MEM_PRIVATE"), id="raw-minidump-region"),
    pytest.param(Module(0x1000, 0x1000, "legit.dll"), id="raw-minidump-module"),
    pytest.param(_FakeMinidumpFile(), id="minidump-file"),
    pytest.param(_FakeResolver(), id="address-resolver"),
    pytest.param({"module": None, "section": None}, id="hand-rolled-dict"),
    pytest.param("module=legit.dll VA=0x1000", id="console-fact-string"),
    pytest.param(True, id="verbosity-flag"),
]


@pytest.mark.parametrize("poison", _POISON)
def test_report_evidence_buckets_reject_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        StompingEvidence(protection_leads=(poison,))


@pytest.mark.parametrize("poison", _POISON)
def test_protection_lead_rejects_a_poisoned_module_reference(poison):
    with pytest.raises(TypeError, match="ProtectionLeadEvidence.module must be a ModuleRef"):
        _protection_lead(module=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_protection_lead_rejects_a_poisoned_region_reference(poison):
    with pytest.raises(TypeError, match="ProtectionLeadEvidence.region must be a RegionRef"):
        _protection_lead(region=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_ioc_hit_rejects_a_poisoned_region_reference(poison):
    with pytest.raises(TypeError, match="IocHitEvidence.region must be a RegionRef"):
        IocHitEvidence(region=poison, module=_module(), tokens=(_token(),))


def test_ioc_hit_tokens_reject_a_bare_mutable_list_item():
    with pytest.raises(TypeError, match="IocHitEvidence.tokens\\[0\\] must be a IocTokenHit"):
        IocHitEvidence(region=_region(), module=None, tokens=[["late-appendable"]])


def test_check_result_evidence_rejects_a_finding():
    finding = Finding(check="stomping.protection_deviation_lead", facts=["module=x"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _check(evidence=(finding,))


def test_report_results_reject_findings():
    finding = Finding(check="stomping.protection_deviation_lead", facts=["module=x"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _report(results=(finding,))


def test_report_evidence_buckets_reject_findings():
    finding = Finding(check="stomping.protection_deviation_lead", facts=["module=x"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        StompingEvidence(protection_leads=(finding,))


def test_report_rejects_a_hunter_record_as_evidence():
    from tests.fixtures.hunt_records import stomping_detected
    with pytest.raises(TypeError):
        StompingEvidence(verified_changes=(stomping_detected(),))


@dataclasses.dataclass(frozen=True)
class _EvidenceHoldingAList:
    items: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class _MutableEvidence:
    base_address: int = 0


def test_check_result_evidence_rejects_a_frozen_object_holding_a_mutable_collection():
    with pytest.raises(TypeError):
        _check(evidence=(_EvidenceHoldingAList(items=[1, 2]),))


def test_frozen_dataclass_with_undeclared_instance_state_is_rejected():
    lead = _protection_lead()
    object.__setattr__(lead, "extra_payload", [])
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(lead, "test")


def test_evidence_bucket_rejects_an_item_poisoned_after_its_own_construction():
    """frozen blocks attribute REASSIGNMENT, not `object.__setattr__` -- the
    depth walk at the bucket boundary is what still catches a well-typed
    evidence object whose own field was smuggled a mutable payload."""
    lead = _protection_lead()
    object.__setattr__(lead, "hidden", {})
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        StompingEvidence(protection_leads=(lead,))


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
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(instance, "test")


class _State(enum.Enum):
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
        g: object = dataclasses.field(default_factory=tuple)
        h: object = dataclasses.field(default_factory=frozenset)

    require_recursively_immutable(_Leaves(), "leaves")


def test_a_mapping_proxy_view_is_rejected():
    with pytest.raises(TypeError, match="ProtectionLeadEvidence.region must be a RegionRef"):
        _protection_lead(region=MappingProxyType({0x1000: ()}))


def test_a_mapping_proxy_view_nested_inside_a_well_typed_field_is_still_rejected():
    """The isinstance checks in ProtectionLeadEvidence's own __post_init__
    only look at its DIRECT fields -- a MappingProxyType hiding a level
    deeper, inside an otherwise correctly-typed ModuleRef, is what the
    require_recursively_immutable(self, ...) depth check still catches."""
    poisoned_module = _module()
    object.__setattr__(poisoned_module, "name", MappingProxyType({0x1000: ()}))
    with pytest.raises(TypeError, match="read-only view is not an immutable value"):
        _protection_lead(module=poisoned_module)


def test_report_rejects_a_coverage_dict_in_place_of_the_snapshot():
    with pytest.raises(TypeError):
        StompingReport(score=0, coverage={"memory_info_stream": True})


def test_report_rejects_an_evidence_dict_in_place_of_the_container():
    with pytest.raises(TypeError):
        StompingReport(score=0, coverage=_coverage(), evidence={"protection_leads": ()})


def test_report_evidence_buckets_reject_the_wrong_evidence_type():
    with pytest.raises(TypeError):
        StompingEvidence(protection_leads=(_verified_change(),))
    with pytest.raises(TypeError):
        StompingEvidence(verified_changes=(_protection_lead(),))


def test_a_bucket_rejects_the_same_object_listed_twice():
    lead = _protection_lead()
    with pytest.raises(ValueError, match="already in this bucket"):
        StompingEvidence(protection_leads=(lead, lead))


# ── Bucket-to-bucket identity relations ───────────────────────────────────

def test_rip_correlated_leads_must_cite_the_reports_own_protection_leads():
    stray = _protection_lead(base=_SECTION_VA + 0x8000)
    with pytest.raises(ValueError, match="not one of"):
        StompingEvidence(protection_leads=(_protection_lead(),),
                         rip_correlated_leads=(RipCorrelatedLeadEvidence(
                             lead=stray, thread=_thread()),))


def test_rip_correlated_leads_reject_an_equal_but_separate_copy_of_a_lead():
    bucket_lead, identical_copy = _protection_lead(), _protection_lead()
    assert bucket_lead == identical_copy and bucket_lead is not identical_copy
    with pytest.raises(ValueError, match="not one of"):
        StompingEvidence(protection_leads=(bucket_lead,),
                         rip_correlated_leads=(RipCorrelatedLeadEvidence(
                             lead=identical_copy, thread=_thread()),))


def test_report_stores_no_second_copy_of_its_evidence():
    lead = _protection_lead()
    report = _report(results=(_check(evidence=(lead,)),),
                     evidence=StompingEvidence(protection_leads=(lead,)))
    assert report.results[0].evidence[0] is report.evidence.protection_leads[0]


def test_report_rejects_a_result_citing_evidence_no_bucket_accounts_for():
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        _report(results=(_check(evidence=(_protection_lead(base=_SECTION_VA + 0x8000),)),),
                evidence=StompingEvidence(protection_leads=(_protection_lead(),)))


def test_report_rejects_a_result_citing_an_equal_but_separate_copy():
    bucket_item, identical_copy = _protection_lead(), _protection_lead()
    assert bucket_item == identical_copy and bucket_item is not identical_copy
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(identical_copy,)),),
                evidence=StompingEvidence(protection_leads=(bucket_item,)))


def test_report_rejects_a_result_citing_a_merely_nested_object():
    lead = _protection_lead()
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(lead.region,)),),
                evidence=StompingEvidence(protection_leads=(lead,)))


# ── 4. Derived judgment fields ────────────────────────────────────────────

def test_status_is_derived_from_score_and_coverage():
    assert _report(score=0).status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert _report(score=1).status == "DETECTED"
    assert _report(score=0, coverage=_coverage(ref_dir_supplied=False)).status == "INCONCLUSIVE"
    assert _report(score=1, coverage=_coverage(ref_dir_supplied=False)).status == "DETECTED"
    assert _report(score=0,
                   coverage=_coverage(memory_info_stream=False)).status == "NOT_EVALUATED"
    assert _report(score=0,
                   coverage=_coverage(module_list_stream=False)).status == "NOT_EVALUATED"


def test_build_report_omits_the_no_anomaly_claim_when_not_evaluated():
    """`protection_leads=()` with `module_list_stream=False` means the
    module/section walk never ran at all -- build_report must not claim
    "no anomaly found" over a scope it never looked at (that claim is only
    true when the walk actually completed; see
    domain.CoverageSnapshot.evaluated)."""
    report = stomping_aggregate.build_report(
        memory_info_stream=True, module_list_stream=False)
    assert report.status == "NOT_EVALUATED"
    assert [r.check for r in report.results] == []


def test_build_report_still_makes_the_no_anomaly_claim_when_evaluated():
    """Same empty-`protection_leads` input, but genuinely evaluated (both
    streams present) -- "no anomaly anywhere" is now a real, honest claim
    and must still fire, unchanged from before the NOT_EVALUATED guard."""
    report = stomping_aggregate.build_report(
        memory_info_stream=True, module_list_stream=True)
    assert [r.check for r in report.results] == ["stomping.protection_deviation_lead"]
    assert report.results[0].tag == TAG_OBSERVATION
    # Not NOT_DETECTED_IN_SCANNED_SCOPE: no `ref_dir_supplied` here means the
    # ONE scored signal never ran either -- see CoverageSnapshot.
    # content_complete -- so this stays INCONCLUSIVE, matching this
    # hunter's documented "no bare clean without --ref-dir" policy.
    assert report.status == "INCONCLUSIVE"


def test_stomping_jumps_from_possible_straight_to_high_skipping_likely():
    """The deliberate gap in this hunter's scale: a protection deviation
    alone is only "possible", but the second signal is a VERIFIED content
    change against a trusted same-build reference, which is conclusive
    enough that there is no intermediate "likely" tier to land on.
    Asserted through verdict_level() rather than by re-typing the table;
    its structural properties are covered for every hunter in
    tests/hunt/test_verdict_level_tables.py."""
    from dumpex.hunt.stomping import domain as stomping_domain

    table = stomping_domain.VERDICT_LEVEL_BY_SCORE
    assert verdict_level(1, table, status="DETECTED") == "possible"
    assert verdict_level(MAX_SCORE, table, status="DETECTED") == "high"
    assert "likely" not in table.values()
    assert stomping_aggregate.build_report.__module__.endswith("aggregate")


def test_negative_score_is_rejected():
    with pytest.raises(ValueError):
        _report(score=-1)


def test_report_holds_no_dump_resolver_or_projection_field():
    field_names = {f.name for f in dataclasses.fields(StompingReport)}
    assert field_names == {"score", "coverage", "results", "evidence"}
    forbidden = field_names & {"mf", "verbose", "detail_level", "level", "findings",
                                "findings_list", "record", "coverage_report", "ref_dir",
                                "ioc_scan", "ioc_coverage_reasons"}
    assert not forbidden


def test_coverage_snapshot_holds_no_ref_dir_path():
    field_names = {f.name for f in dataclasses.fields(CoverageSnapshot)}
    assert "ref_dir" not in field_names
    assert "ref_dir_supplied" in field_names
    with pytest.raises(TypeError):
        _coverage(ref_dir_supplied="/tmp/refs")


# ── Coverage snapshot ─────────────────────────────────────────────────────

def test_coverage_snapshot_status_matches_the_shared_reducer():
    assert _coverage().status == "complete"
    assert _coverage(ref_dir_supplied=False).status == "partial"
    assert _coverage(header_read_failed=1).status == "partial"
    assert _coverage(header_parse_failed=1).status == "partial"
    assert _coverage(sections_compared=0).status == "partial"
    assert _coverage(reference_missing=1).status == "partial"
    assert _coverage(memory_info_stream=False).status == "not_evaluated"
    assert _coverage(module_list_stream=False).status == "not_evaluated"


@pytest.mark.parametrize("gap", ["reference_missing", "reference_mismatch",
                                  "reference_read_failed", "memory_read_failed",
                                  "short_reads", "relocation_failed"])
def test_every_reference_gap_makes_content_incomplete(gap):
    assert _coverage().content_complete is True
    assert _coverage(**{gap: 1}).content_complete is False


def test_content_complete_requires_a_reference_directory():
    assert _coverage(ref_dir_supplied=False).content_complete is False


def test_content_complete_requires_every_eligible_section_compared():
    assert _coverage(sections_total=2, sections_compared=1).content_complete is False


def _oversize_target(base=0x7ff600100000):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=6 * 1024 * 1024, size_limit=5 * 1024 * 1024)


@pytest.mark.parametrize("gap, value", [
    ("ioc_oversized", (_oversize_target(),)),
    ("ioc_read_failed", 1),
    ("ioc_short_reads", 1),
])
def test_an_ioc_sub_scan_gap_alone_makes_the_run_partial_and_inconclusive(gap, value):
    coverage = _coverage(**{gap: value})
    assert coverage.ioc_complete is False
    assert coverage.content_complete is True   # the scored check itself was fine
    assert coverage.status == "partial"
    assert _report(score=0, coverage=coverage).status == "INCONCLUSIVE"
    # ...but a real detection still wins over incomplete coverage.
    assert _report(score=1, coverage=coverage).status == "DETECTED"


def test_module_list_absent_forces_not_evaluated_even_with_a_real_ioc_gap():
    """The ONE documented exception to "coverage_status and status move
    together": the IOC sub-scan only needs MemoryInfoListStream, so it can
    still run and still find a gap, but the scored content-diff check never
    ran at all."""
    coverage = _coverage(module_list_stream=False, ioc_oversized=(_oversize_target(),))
    assert coverage.ioc_complete is False
    assert coverage.evaluated is False
    assert coverage.status == "not_evaluated"
    assert _report(score=0, coverage=coverage).status == "NOT_EVALUATED"
    assert coverage.ioc_gap_reasons()   # the gap itself is NOT dropped


def test_ioc_gap_reasons_are_ordered_and_worded_once():
    coverage = _coverage(ioc_oversized=(_oversize_target(),), ioc_read_failed=2,
                          ioc_short_reads=3)
    reasons = coverage.ioc_gap_reasons()
    assert len(reasons) == 3
    assert reasons[0].startswith("1 oversized executable module region(s) never scanned")
    assert "0x00007ff600100000" in reasons[0] and "6 MB > 5 MB limit" in reasons[0]
    assert reasons[1] == "2 region(s) failed to read and were not scanned for IOC strings"
    assert reasons[2].startswith("3 region(s) returned fewer bytes than declared")
    assert isinstance(reasons, tuple)


def test_coverage_counts_rebuilds_the_v1_dict_fresh_every_call():
    coverage = _coverage(reference_missing=2)
    first, second = coverage.coverage_counts(), coverage.coverage_counts()
    assert set(first) == set(COVERAGE_COUNT_FIELDS)
    assert first == second and first is not second
    first["reference_missing"] = 999
    assert coverage.coverage_counts()["reference_missing"] == 2


def test_coverage_snapshot_rejects_non_boolean_stream_flags_and_bad_counts():
    with pytest.raises(TypeError):
        _coverage(memory_info_stream=1)
    with pytest.raises(TypeError):
        _coverage(module_list_stream="yes")
    with pytest.raises(TypeError):
        _coverage(reference_missing=True)
    with pytest.raises(ValueError):
        _coverage(reference_missing=-1)


def test_coverage_snapshot_oversized_bucket_rejects_non_scan_target_items():
    with pytest.raises(TypeError):
        _coverage(ioc_oversized=({"base_address": 0x1000},))


def test_coverage_snapshot_whitelisted_modules_must_be_strings():
    with pytest.raises(TypeError):
        _coverage(ioc_whitelisted_modules=(object(),))
    assert _coverage(ioc_whitelisted_modules=["wininet.dll"]).ioc_whitelisted_modules == \
        ("wininet.dll",)


# ── Scan-layer transport types ────────────────────────────────────────────

def test_ioc_scan_result_rejects_a_live_coverage_tracker():
    from dumpex.hunt._coverage import CoverageTracker
    with pytest.raises(TypeError, match="IocScanResult.coverage must be a IocCoverage"):
        IocScanResult(hits=(), coverage=CoverageTracker())


def test_ioc_scan_result_rejects_an_ioc_coverage_poisoned_after_construction():
    coverage = IocCoverage()
    object.__setattr__(coverage, "read_failed", [])
    with pytest.raises(TypeError):
        IocScanResult(coverage=coverage)


def test_ioc_coverage_targets_reject_non_scan_target_items():
    with pytest.raises(TypeError, match="must be a ScanTarget"):
        IocCoverage(skipped_oversize_targets=([],))


def test_section_diff_result_rejects_raw_minidump_objects():
    raw_module = Module(_MODULE_BASE, 0x5000, "legit.dll")
    with pytest.raises(TypeError, match="SectionDiffResult.module must be a ModuleRef"):
        SectionDiffResult(module=raw_module, section=_section(), va_start=_SECTION_VA)
    with pytest.raises(TypeError, match="SectionDiffResult.section must be a SectionRef"):
        SectionDiffResult(module=_module(), section={"name": ".text"}, va_start=_SECTION_VA)


def _reachable_from_transport(value):
    yield from _reachable(value)


def test_no_mutable_collection_is_reachable_from_an_ioc_scan_result():
    result = IocScanResult(hits=(_ioc_hit(),),
                            coverage=IocCoverage(skipped_oversize_targets=(_oversize_target(),),
                                                  whitelisted_skipped=("wininet.dll",)))
    seen = 0
    for value in _reachable_from_transport(result):
        seen += 1
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"a mutable {type(value).__name__} is reachable from IocScanResult: {value!r}")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True
    assert seen > 15, "the walk did not actually reach the nested hits/coverage"
