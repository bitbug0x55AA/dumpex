"""Hunter-specific contracts for the canonical named-pipe domain model."""
import dataclasses
import enum
from types import MappingProxyType

import pytest

from tests.fixtures.fakes import Region, Handle, ThreadInfo

from dumpex.hunt._domain import CheckResult, require_recursively_immutable
from dumpex.hunt._finding import (
    Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.pipe import aggregate as pipe_aggregate
from dumpex.hunt.pipe.report_facts import project_coverage_v1
from dumpex.hunt.pipe.domain import (
    MAX_SCORE, VERDICT_LEVEL_BY_SCORE, CoverageSnapshot, PipeEvidence, PipeReport,
)
from dumpex.hunt.pipe.models import (
    C2ContextEvidence, C2ContextRecord, CorrelationResult, CorroboratedHandleEvidence,
    FrameworkAttribution, FrameworkStringHitEvidence, HandleRef, HandleScanResult,
    PipeHandleEvidence, PipeNameScanResult, PipeScanCoverage, PipeStringEvidence, RegionC2Records,
    RegionRef, StartAddressLeadEvidence, ThreadHitRef, ThreadStartRef, UnbackedThreadEvidence,
    dedupe_evidence, framework_attribution, handle_ref, region_ref, thread_hit_ref,
    thread_start_ref,
)
from dumpex.output.coverage import ScanTarget, ScanTargetKind


# ── Builders ────────────────────────────────────────────────────────────

_REGION_BASE = 0x1230000
_PIPE_OFFSET = 0x101
_PIPE_VA     = _REGION_BASE + _PIPE_OFFSET


def _handle_ref(handle=0x88, object_name=r"\Device\NamedPipe\msagent_1337"):
    return HandleRef(handle=handle, type_name="File", object_name=object_name,
                      granted_access=0x12019f)


def _region(base=_REGION_BASE, protect="PAGE_EXECUTE_READ"):
    return RegionRef(base_address=base, allocation_base=base, size=0x1000,
                      state="MEM_COMMIT", protect=protect, type="MEM_PRIVATE")


def _thread_hit(tid=0x999, ip=_PIPE_VA + 4):
    return ThreadHitRef(thread_id=tid, ip=ip, ip_reg="RIP")


def _thread_start(tid=0x999, start_address=_REGION_BASE + 0x10):
    return ThreadStartRef(thread_id=tid, start_address=start_address)


def _framework(framework="Cobalt Strike", technique="SMB Beacon peer-to-peer pipe",
                mitre="T1090.001"):
    return FrameworkAttribution(framework=framework, technique=technique, mitre=mitre)


def _handle(canonical_name="msagent_1337", framework=True, **overrides):
    kwargs = dict(handle=_handle_ref(), canonical_name=canonical_name,
                   framework=_framework() if framework else None)
    kwargs.update(overrides)
    return PipeHandleEvidence(**kwargs)


def _string_lead(region=None, offset=_PIPE_OFFSET, name="\\\\.\\pipe\\msagent_1337", **overrides):
    """`va` defaults to `region.base_address + offset` -- computed with a
    getattr fallback so a POISONED `region` still reaches
    `PipeStringEvidence`'s own field validator (which is what the poison
    tests below are checking) instead of blowing up in this builder."""
    region = region if region is not None else _region()
    kwargs = dict(region=region, offset=offset, name=name, sha256="d" * 64,
                   original_length=20, truncated=False, encoding="ascii",
                   va=getattr(region, "base_address", 0) + offset, file_offset=None)
    kwargs.update(overrides)
    return PipeStringEvidence(**kwargs)


def _c2_record(match="http://", va=_PIPE_VA + 0x15, **overrides):
    kwargs = dict(match=match, context=b"AAAA", va=va, sha256="8" * 64, original_length=7)
    kwargs.update(overrides)
    return C2ContextRecord(**kwargs)


def _c2_context(records=None, string_hit=None):
    string_hit = string_hit if string_hit is not None else _string_lead()
    return C2ContextEvidence(string_hit=string_hit,
                              records=records if records is not None else (_c2_record(),))


def _corroborated(handle=None, string_hit=None, nearby_c2=None, rip_hit=None):
    """`pipe_va` is a property, always the string hit's OWN address -- the
    anchor the whole proximity window is measured from (see
    config.PIPE_CONTEXT_DISTANCE)."""
    string_hit = string_hit if string_hit is not None else _string_lead()
    return CorroboratedHandleEvidence(
        handle=handle if handle is not None else _handle(),
        string_hit=string_hit,
        nearby_c2=(_c2_record(),) if nearby_c2 is None else nearby_c2,
        rip_hit=rip_hit)


def _start_lead(handle=None, string_hit=None):
    string_hit = string_hit if string_hit is not None else _string_lead()
    return StartAddressLeadEvidence(
        handle=handle if handle is not None else _handle(),
        string_hit=string_hit, thread=_thread_start())


def _framework_string_hit(pipe_name="\\.\\pipe\\msagent_1337", string_hit=None):
    string_hit = (string_hit if string_hit is not None
                  else _string_lead(name=pipe_name))
    return FrameworkStringHitEvidence(string_hit=string_hit, framework=_framework())


def _unbacked(tid=0x999):
    return UnbackedThreadEvidence(thread=_thread_start(tid=tid), region=_region())


def _coverage(**overrides):
    kwargs = dict(memory_info_stream=True, handle_data_stream=True)
    kwargs.update(overrides)
    return CoverageSnapshot(**kwargs)


def _check(check="pipe.open_handles", tag=TAG_OBSERVATION, confidence=CONFIDENCE_LOW,
           evidence=(), **overrides):
    kwargs = dict(check=check, inference="something was observed",
                   confidence=confidence, rationale="because of the evidence above",
                   evidence=evidence, tag=tag)
    kwargs.update(overrides)
    return CheckResult(**kwargs)


def _report(score=0, results=(), evidence=None, coverage=None):
    return PipeReport(score=score, coverage=coverage or _coverage(), results=results,
                       evidence=evidence if evidence is not None else PipeEvidence())


def _populated_report():
    handle     = _handle()
    lead       = _string_lead()
    corrob     = _corroborated(handle=handle, string_hit=lead, rip_hit=_thread_hit())
    evidence = PipeEvidence(
        handle_pipes=(handle,), string_leads=(lead,), corroborated_handles=(corrob,),
        # `string_hit=lead`: the SAME object `string_leads` holds, by
        # identity -- PipeEvidence rejects a c2_context/framework_string_hits
        # entry whose string_hit is not one of its own string_leads.
        c2_context=(_c2_context(string_hit=lead),),
        framework_string_hits=(_framework_string_hit(string_hit=lead),),
        unbacked_threads=(_unbacked(),))
    results = (
        _check(check="pipe.open_handles", tag=TAG_OBSERVATION, confidence=CONFIDENCE_MEDIUM,
               evidence=(handle,), evidence_limit=20),
        _check(check="pipe.handle_framework_match", tag=TAG_DETECTION,
               confidence=CONFIDENCE_MEDIUM, evidence=(handle,)),
        _check(check="pipe.string_scan_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
               evidence=(lead,), evidence_limit=15),
        _check(check="pipe.corroboration", tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH,
               evidence=(corrob,), evidence_limit=10),
    )
    return PipeReport(score=3, coverage=_coverage(), results=results, evidence=evidence)


def _oversize_target(base=0x7ff600100000):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=9 * 1024 * 1024, size_limit=8 * 1024 * 1024)


DOMAIN_TYPES = [CheckResult, CoverageSnapshot, PipeEvidence, PipeReport]
EVIDENCE_TYPES = [HandleRef, RegionRef, ThreadHitRef, ThreadStartRef, FrameworkAttribution,
                  PipeHandleEvidence, PipeStringEvidence, C2ContextRecord, C2ContextEvidence,
                  CorroboratedHandleEvidence, StartAddressLeadEvidence,
                  FrameworkStringHitEvidence, UnbackedThreadEvidence, HandleScanResult,
                  RegionC2Records, PipeScanCoverage, PipeNameScanResult, CorrelationResult]


# ── Construction success for every evidence type ──────────────────────────

def test_every_evidence_type_constructs_from_well_formed_input():
    assert _handle_ref().object_name.endswith("msagent_1337")
    assert _region().protect == "PAGE_EXECUTE_READ"
    assert _thread_hit().ip_reg == "RIP"
    assert _thread_start().start_address == _REGION_BASE + 0x10
    assert _framework().mitre == "T1090.001"
    assert _handle().canonical_name == "msagent_1337"
    assert _string_lead().va == _PIPE_VA
    assert _c2_record().context == b"AAAA"
    assert _c2_context().records[0].match == "http://"
    assert _corroborated().pipe_va == _PIPE_VA
    assert _start_lead().thread.thread_id == 0x999
    assert _framework_string_hit().framework.framework == "Cobalt Strike"
    assert _unbacked().region.base_address == _REGION_BASE
    assert HandleScanResult().handles == ()
    assert PipeNameScanResult().string_leads == ()
    assert PipeScanCoverage().read_failed == 0
    assert CorrelationResult().corroborated_handles == ()


def test_scan_time_builders_resolve_identity_once():
    """`handle_ref`/`region_ref`/`thread_hit_ref`/`thread_start_ref`/
    `framework_attribution` are the ONE place a raw minidump object, a
    thread-context dict, or a rules 3-tuple becomes a snapshot --
    prot_str() resolution happens there, never later."""
    raw_region = Region(_REGION_BASE, _REGION_BASE, 0x1000, "MEM_COMMIT",
                         "PAGE_EXECUTE_READ", "MEM_PRIVATE")
    raw_handle = Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")
    raw_info   = ThreadInfo(0x999, _REGION_BASE + 0x10)

    assert region_ref(raw_region).protect == "PAGE_EXECUTE_READ"
    assert region_ref(raw_region).state == "MEM_COMMIT"
    assert region_ref(raw_region).type == "MEM_PRIVATE"
    assert handle_ref(raw_handle).object_name == r"\Device\NamedPipe\msagent_1337"
    assert handle_ref(raw_handle).granted_access == 0x12019f
    assert thread_start_ref(raw_info).start_address == _REGION_BASE + 0x10
    context = {"ThreadId": 1, "ip": 0x2000, "ip_reg": "EIP", "is_wow64": True}
    assert thread_hit_ref(context) == ThreadHitRef(thread_id=1, ip=0x2000, ip_reg="EIP")
    assert framework_attribution(None) is None
    assert framework_attribution(("CS", "tech", "T1")) == FrameworkAttribution("CS", "tech", "T1")

    for snapshot in (region_ref(raw_region), handle_ref(raw_handle), thread_start_ref(raw_info),
                     thread_hit_ref(context)):
        require_recursively_immutable(snapshot, "snapshot")


def test_thread_hit_ref_defaults_to_rip_when_the_context_names_no_register():
    assert thread_hit_ref({"ThreadId": 1, "ip": 0x10}).ip_reg == "RIP"


def test_region_ref_knows_whether_it_is_executable():
    """RIP/EIP corroboration gates on this -- derived from the
    already-resolved protection string, so correlation.py never needs the
    live region back to ask."""
    assert _region(protect="PAGE_EXECUTE_READ").is_executable is True
    assert _region(protect="PAGE_EXECUTE_READWRITE").is_executable is True
    assert _region(protect="PAGE_READWRITE").is_executable is False


def test_framework_attribution_projects_back_to_the_v1_positional_tuple():
    assert _framework().as_tuple() == ("Cobalt Strike", "SMB Beacon peer-to-peer pipe",
                                        "T1090.001")


@pytest.mark.parametrize("factory, kwargs, exc", [
    pytest.param(HandleRef, dict(handle=-1, type_name="File", object_name="x"), ValueError,
                 id="handle-negative"),
    pytest.param(HandleRef, dict(handle=True, type_name="File", object_name="x"), TypeError,
                 id="handle-bool"),
    pytest.param(HandleRef, dict(handle=1, type_name=None, object_name="x"), TypeError,
                 id="handle-none-type-name"),
    pytest.param(RegionRef, dict(base_address=0, allocation_base=None, size=0,
                                  state="MEM_COMMIT", protect=None, type="MEM_PRIVATE"), TypeError,
                 id="region-none-protect"),
    pytest.param(ThreadHitRef, dict(thread_id=1, ip=1, ip_reg=None), TypeError,
                 id="thread-none-ip-reg"),
    pytest.param(ThreadStartRef, dict(thread_id=1, start_address="0x10"), TypeError,
                 id="thread-start-str-address"),
    pytest.param(FrameworkAttribution, dict(framework="CS", technique="t", mitre=None), TypeError,
                 id="framework-none-mitre"),
    pytest.param(C2ContextRecord, dict(match="x", context=bytearray(b"x"), va=0, sha256="y",
                                        original_length=1), TypeError,
                 id="c2-record-bytearray-context"),
    pytest.param(C2ContextRecord, dict(match="x", context="x", va=0, sha256="y",
                                        original_length=1), TypeError,
                 id="c2-record-str-context"),
])
def test_evidence_construction_rejects_bad_field_values(factory, kwargs, exc):
    with pytest.raises(exc):
        factory(**kwargs)


def test_string_lead_rejects_a_va_that_disagrees_with_its_own_region_and_offset():
    """The absolute address is resolved once, at scan time; a projector
    that re-derived a different one would silently point an analyst at the
    wrong bytes."""
    with pytest.raises(ValueError, match="must be this hit's own region base"):
        _string_lead(va=_PIPE_VA + 1)


def test_a_thread_with_no_recorded_start_address_is_representable():
    """`None`, never 0 -- address zero is an ordinary, valid address, and
    the v2 wire shape renders the distinction as JSON null."""
    assert _thread_start(start_address=None).start_address is None


def test_corroboration_requires_at_least_one_corroborating_signal():
    """An entry with neither nearby C2 context nor a live RIP/EIP hit is
    not corroboration -- it would silently score a bare open handle."""
    with pytest.raises(ValueError, match="at least one corroborating signal"):
        _corroborated(nearby_c2=(), rip_hit=None)


def test_full_corroboration_requires_both_signals_at_once():
    assert _corroborated(nearby_c2=(_c2_record(),), rip_hit=None).fully_corroborated is False
    assert _corroborated(nearby_c2=(), rip_hit=_thread_hit()).fully_corroborated is False
    assert _corroborated(nearby_c2=(_c2_record(),),
                         rip_hit=_thread_hit()).fully_corroborated is True


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
    for collection in (report.results, report.evidence.handle_pipes,
                       report.evidence.string_leads, report.evidence.corroborated_handles,
                       report.evidence.corroborated_handles[0].nearby_c2,
                       report.evidence.c2_context[0].records,
                       report.results[0].evidence):
        assert isinstance(collection, tuple)
        with pytest.raises(AttributeError):
            collection.append("late")


def test_the_whole_report_passes_the_shared_recursive_immutability_check():
    require_recursively_immutable(_populated_report(), "PipeReport")


# ── 2. Constructor inputs are copied, not retained ────────────────────────

def test_mutating_the_results_list_after_construction_cannot_change_the_report():
    results = [_check()]
    report = _report(results=results)
    results.append(_check(check="pipe.string_scan_lead"))
    assert len(report.results) == 1


def test_mutating_an_evidence_list_after_construction_cannot_change_the_report():
    handles = [_handle()]
    evidence = PipeEvidence(handle_pipes=handles)
    handles.append(_handle(canonical_name="other"))
    assert len(evidence.handle_pipes) == 1


def test_mutating_a_check_results_evidence_list_after_construction_changes_nothing():
    evidence_list = [_handle()]
    result = _check(evidence=evidence_list)
    evidence_list.clear()
    assert len(result.evidence) == 1


def test_pipe_scan_coverage_does_not_stay_linked_to_the_live_tracker_or_budgets():
    """The ONE place the still-mutable CoverageTracker and both ScanBudgets
    get frozen before they can cross the scan/aggregate boundary."""
    from dumpex.hunt._budget import ScanBudget
    from dumpex.hunt._coverage import CoverageTracker
    tracker = CoverageTracker()
    tracker.read_failed = 1
    name_budget = ScanBudget(max_bytes_read=10, max_attempts=10, max_retained_bytes=10,
                              max_hits=10)
    c2_budget = ScanBudget(max_bytes_read=10, max_attempts=10, max_retained_bytes=10, max_hits=10)
    snapshot = PipeScanCoverage.from_scan(tracker, name_budget, c2_budget,
                                           image_pipe_refs=2,
                                           image_pipe_modules=["kernel32.dll"])
    tracker.note_read_failed()
    tracker.note_short_read()
    name_budget.exhausted_reason = "max_hits"
    assert snapshot.read_failed == 1
    assert snapshot.short_reads == 0
    assert snapshot.pipe_name_budget_exhausted is False
    assert snapshot.image_pipe_modules == ("kernel32.dll",)


def test_pipe_scan_coverage_notices_an_expired_deadline_when_it_freezes():
    """`exhausted()` (not a bare `exhausted_reason` read) -- a budget only
    notices an expired DEADLINE when asked."""
    from dumpex.hunt._budget import ScanBudget
    from dumpex.hunt._coverage import CoverageTracker
    expired = ScanBudget(max_bytes_read=10, max_attempts=10, max_retained_bytes=10,
                         max_hits=10, deadline=0.0)
    live = ScanBudget(max_bytes_read=10, max_attempts=10, max_retained_bytes=10, max_hits=10)
    snapshot = PipeScanCoverage.from_scan(CoverageTracker(), live, expired)
    assert snapshot.c2_budget_exhausted is True
    assert snapshot.c2_budget_reason == "deadline"
    assert snapshot.pipe_name_budget_exhausted is False


def test_dedupe_evidence_collapses_only_exact_duplicates():
    first, duplicate, other = _handle(), _handle(), _handle(canonical_name="other")
    assert first == duplicate and first is not duplicate
    deduped = dedupe_evidence([first, duplicate, other])
    assert deduped == (first, other)
    assert deduped[0] is first


# ── 3. Poison objects: what the model must refuse to retain ───────────────

class _FakeResolver:
    def __call__(self, *args, **kwargs):   # pragma: no cover - never invoked
        raise AssertionError("a resolver must never be reachable from the domain model")


class _FakeMinidumpFile:
    pass


_POISON = [
    pytest.param(Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                        "MEM_PRIVATE"), id="raw-minidump-region"),
    pytest.param(Handle(0x1, "File", r"\Device\NamedPipe\x"), id="raw-minidump-handle"),
    pytest.param(ThreadInfo(0x1, 0x1000), id="raw-minidump-thread-info"),
    pytest.param(_FakeMinidumpFile(), id="minidump-file"),
    pytest.param(_FakeResolver(), id="address-resolver"),
    pytest.param({"handle": None, "canonical_name": None}, id="hand-rolled-dict"),
    pytest.param("Handle=0x88 ObjectName=x", id="console-fact-string"),
    pytest.param(True, id="verbosity-flag"),
]


@pytest.mark.parametrize("poison", _POISON)
def test_report_evidence_buckets_reject_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        PipeEvidence(handle_pipes=(poison,))


@pytest.mark.parametrize("poison", _POISON)
def test_pipe_handle_evidence_rejects_a_poisoned_handle_reference(poison):
    with pytest.raises(TypeError, match="PipeHandleEvidence.handle must be a HandleRef"):
        _handle(handle=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_string_lead_rejects_a_poisoned_region_reference(poison):
    with pytest.raises(TypeError, match="PipeStringEvidence.region must be a RegionRef"):
        _string_lead(region=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_unbacked_thread_rejects_a_poisoned_thread_reference(poison):
    with pytest.raises(TypeError, match="UnbackedThreadEvidence.thread must be a ThreadStartRef"):
        UnbackedThreadEvidence(thread=poison, region=_region())


def test_corroboration_rejects_a_raw_thread_context_dict_as_its_rip_hit():
    with pytest.raises(TypeError, match="CorroboratedHandleEvidence.rip_hit must be a ThreadHitRef"):
        _corroborated(rip_hit={"ThreadId": 1, "ip": 0x10, "ip_reg": "RIP"})


def test_c2_context_records_reject_a_bare_mutable_list_item():
    with pytest.raises(TypeError, match="C2ContextEvidence.records\\[0\\] must be a C2ContextRecord"):
        C2ContextEvidence(string_hit=_string_lead(), records=[["late-appendable"]])


def test_check_result_evidence_rejects_a_finding():
    finding = Finding(check="pipe.open_handles", facts=["Handle=0x1"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _check(evidence=(finding,))


def test_report_results_reject_findings():
    finding = Finding(check="pipe.open_handles", facts=["Handle=0x1"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        _report(results=(finding,))


def test_report_evidence_buckets_reject_findings():
    finding = Finding(check="pipe.open_handles", facts=["Handle=0x1"],
                       inference="x", confidence=CONFIDENCE_LOW, rationale="y")
    with pytest.raises(TypeError):
        PipeEvidence(handle_pipes=(finding,))


def test_report_rejects_a_hunter_record_as_evidence():
    from tests.fixtures.hunt_records import pipe_detected
    with pytest.raises(TypeError):
        PipeEvidence(handle_pipes=(pipe_detected(),))


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
    handle = _handle()
    object.__setattr__(handle, "extra_payload", [])
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(handle, "test")


def test_evidence_bucket_rejects_an_item_poisoned_after_its_own_construction():
    """frozen blocks attribute REASSIGNMENT, not `object.__setattr__` -- the
    depth walk at the bucket boundary is what still catches a well-typed
    evidence object whose own field was smuggled a mutable payload."""
    handle = _handle()
    object.__setattr__(handle, "hidden", {})
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        PipeEvidence(handle_pipes=(handle,))


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
        c: object = "PAGE_EXECUTE_READ"
        d: object = b"MZ"
        e: object = 1.5
        f: object = _State.PRESENT
        g: object = dataclasses.field(default_factory=tuple)
        h: object = dataclasses.field(default_factory=frozenset)

    require_recursively_immutable(_Leaves(), "leaves")


def test_a_mapping_proxy_view_is_rejected():
    with pytest.raises(TypeError, match="PipeStringEvidence.region must be a RegionRef"):
        _string_lead(region=MappingProxyType({0x1000: ()}))


def test_a_mapping_proxy_view_nested_inside_a_well_typed_field_is_still_rejected():
    """The isinstance checks in PipeHandleEvidence's own __post_init__ only
    look at its DIRECT fields -- a MappingProxyType hiding a level deeper,
    inside an otherwise correctly-typed HandleRef, is what the
    require_recursively_immutable(self, ...) depth check still catches."""
    poisoned = _handle_ref()
    object.__setattr__(poisoned, "object_name", MappingProxyType({0x1000: ()}))
    with pytest.raises(TypeError, match="read-only view is not an immutable value"):
        _handle(handle=poisoned)


def test_report_rejects_a_coverage_dict_in_place_of_the_snapshot():
    with pytest.raises(TypeError):
        PipeReport(score=0, coverage={"memory_info_stream": True})


def test_report_rejects_an_evidence_dict_in_place_of_the_container():
    with pytest.raises(TypeError):
        PipeReport(score=0, coverage=_coverage(), evidence={"handle_pipes": ()})


def test_report_evidence_buckets_reject_the_wrong_evidence_type():
    with pytest.raises(TypeError):
        PipeEvidence(handle_pipes=(_string_lead(),))
    with pytest.raises(TypeError):
        PipeEvidence(string_leads=(_handle(),))


def test_a_bucket_rejects_the_same_object_listed_twice():
    handle = _handle()
    with pytest.raises(ValueError, match="already in this bucket"):
        PipeEvidence(handle_pipes=(handle, handle))


def test_a_bucket_rejects_an_equal_but_separate_duplicate():
    """Duplicate-by-EQUALITY, not merely by identity: two evidence objects
    that compare equal describe the same observed fact, and the scan layer
    is where an exact duplicate is collapsed (models.dedupe_evidence)."""
    first, duplicate = _framework_string_hit(), _framework_string_hit()
    assert first == duplicate and first is not duplicate
    with pytest.raises(ValueError, match="already in this bucket"):
        PipeEvidence(framework_string_hits=(first, duplicate))


# ── Bucket-to-bucket identity relations ───────────────────────────────────

def test_corroborated_handles_must_cite_the_reports_own_handle_and_string_buckets():
    stray_handle = _handle(canonical_name="stray")
    with pytest.raises(ValueError, match="not one of"):
        PipeEvidence(handle_pipes=(_handle(),), string_leads=(_string_lead(),),
                     corroborated_handles=(_corroborated(handle=stray_handle),))


def test_corroborated_handles_reject_an_equal_but_separate_copy_of_a_string_lead():
    handle = _handle()
    bucket_lead, identical_copy = _string_lead(), _string_lead()
    assert bucket_lead == identical_copy and bucket_lead is not identical_copy
    with pytest.raises(ValueError, match="not one of"):
        PipeEvidence(handle_pipes=(handle,), string_leads=(bucket_lead,),
                     corroborated_handles=(_corroborated(handle=handle,
                                                          string_hit=identical_copy),))


def test_start_address_leads_must_cite_the_reports_own_buckets_too():
    handle, lead = _handle(), _string_lead()
    with pytest.raises(ValueError, match="not one of"):
        PipeEvidence(handle_pipes=(handle,), string_leads=(lead,),
                     start_address_leads=(_start_lead(handle=handle,
                                                       string_hit=_string_lead()),))
    # ...and the well-wired form is accepted.
    evidence = PipeEvidence(handle_pipes=(handle,), string_leads=(lead,),
                             start_address_leads=(_start_lead(handle=handle, string_hit=lead),))
    assert evidence.start_address_leads[0].handle is evidence.handle_pipes[0]


def test_framework_handles_is_a_derived_view_never_a_stored_second_bucket():
    framework_handle = _handle()
    plain_handle = _handle(canonical_name="ordinary-ipc", framework=False)
    evidence = PipeEvidence(handle_pipes=(framework_handle, plain_handle))
    assert evidence.framework_handles == (framework_handle,)
    assert evidence.framework_handles[0] is evidence.handle_pipes[0]
    assert "framework_handles" not in {f.name for f in dataclasses.fields(PipeEvidence)}
    assert "framework_pipes" not in {f.name for f in dataclasses.fields(PipeEvidence)}


def test_report_stores_no_second_copy_of_its_evidence():
    handle = _handle()
    report = _report(results=(_check(evidence=(handle,)),),
                     evidence=PipeEvidence(handle_pipes=(handle,)))
    assert report.results[0].evidence[0] is report.evidence.handle_pipes[0]


def test_report_rejects_a_result_citing_evidence_no_bucket_accounts_for():
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        _report(results=(_check(evidence=(_handle(canonical_name="stray"),)),),
                evidence=PipeEvidence(handle_pipes=(_handle(),)))


def test_report_rejects_a_result_citing_an_equal_but_separate_copy():
    bucket_item, identical_copy = _handle(), _handle()
    assert bucket_item == identical_copy and bucket_item is not identical_copy
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(identical_copy,)),),
                evidence=PipeEvidence(handle_pipes=(bucket_item,)))


def test_report_rejects_a_result_citing_a_merely_nested_object():
    handle = _handle()
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(handle.handle,)),),
                evidence=PipeEvidence(handle_pipes=(handle,)))


# ── 4. Derived judgment fields ────────────────────────────────────────────

def test_status_is_derived_from_score_and_coverage():
    assert _report(score=0).status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert _report(score=1).status == "DETECTED"
    assert _report(score=0, coverage=_coverage(short_reads=1)).status == "INCONCLUSIVE"
    assert _report(score=1, coverage=_coverage(short_reads=1)).status == "DETECTED"
    assert _report(score=0,
                   coverage=_coverage(handle_data_stream=False)).status == "INCONCLUSIVE"
    assert _report(score=0, coverage=_coverage(memory_info_stream=False,
                                                handle_data_stream=False)).status == "NOT_EVALUATED"


def test_pipe_scores_escalate_one_tier_at_a_time_to_high():
    """Pipe evidence is individually weak (a name is contextual and can
    be spoofed), so this hunter climbs through every tier rather than
    jumping: one signal is only "possible", and "high" needs all three.
    Asserted through verdict_level() across the hunter's whole score
    range -- the values are a calibration decision with no other home in
    the repo, so they are pinned here on purpose; what IS derivable (the
    table covering exactly 1..MAX_SCORE, its top being "high", severity
    rising with score) is checked for every hunter in
    tests/hunt/test_verdict_level_tables.py instead."""
    verdicts = [verdict_level(score, VERDICT_LEVEL_BY_SCORE, status="DETECTED")
                for score in range(1, MAX_SCORE + 1)]
    assert verdicts == ["possible", "likely", "high"]


def test_negative_score_is_rejected():
    with pytest.raises(ValueError):
        _report(score=-1)


def test_report_holds_no_dump_resolver_or_projection_field():
    field_names = {f.name for f in dataclasses.fields(PipeReport)}
    assert field_names == {"score", "coverage", "results", "evidence"}
    forbidden = field_names & {"mf", "verbose", "detail_level", "level", "findings",
                                "findings_list", "record", "coverage_report", "verdict_reason",
                                "handle_scan", "pipe_name_scan", "correlation", "evaluated",
                                "handle_stream_available", "coverage_status", "coverage_reasons"}
    assert not forbidden


def test_coverage_snapshot_holds_no_live_tracker_or_budget():
    field_names = {f.name for f in dataclasses.fields(CoverageSnapshot)}
    assert not (field_names & {"coverage_counts", "c2_budget", "pipe_name_budget", "tracker"})
    with pytest.raises(TypeError):
        _coverage(c2_budget_exhausted="yes")


# ── Coverage snapshot ─────────────────────────────────────────────────────

def test_evaluation_is_or_of_presence_not_and_of_presence():
    """Unlike stomping's AND-of-presence gate: EITHER stream alone is
    enough for this hunter to have done real work."""
    assert _coverage().evaluated is True
    assert _coverage(memory_info_stream=False).evaluated is True
    assert _coverage(handle_data_stream=False).evaluated is True
    assert _coverage(memory_info_stream=False, handle_data_stream=False).evaluated is False


def test_memory_info_absent_alone_never_makes_coverage_partial():
    """`complete` never consults `memory_info_stream` -- a dump captured
    with MiniDumpWithHandleData but no MemoryInfoListStream still ran this
    hunter's whole scored path to completion."""
    coverage = _coverage(memory_info_stream=False)
    assert coverage.complete is True
    assert coverage.status == "complete"


def test_handle_data_absent_always_makes_coverage_partial():
    coverage = _coverage(handle_data_stream=False)
    assert coverage.complete is False
    assert coverage.status == "partial"


def test_a_stream_that_was_not_read_cannot_have_dropped_a_tail():
    """Only a stream this run could read can be known to have dropped a
    declared tail. Without this the snapshot can claim both "no readable
    HandleDataStream" and "3 of its descriptors were not read", which
    projects as an ABSENT source carrying an affected_count=3 limitation
    and prints two mutually exclusive COVERAGE impacts at once."""
    with pytest.raises(ValueError, match="handle_data_stream=False"):
        _coverage(handle_data_stream=False, handle_stream_truncated=3)


def test_a_stream_that_was_read_cannot_also_carry_a_parse_failure():
    with pytest.raises(ValueError, match="handle_data_stream=True"):
        _coverage(handle_stream_failure="framing is unreadable")


def test_a_parse_failure_is_not_the_same_gap_as_a_missing_stream():
    """`handle_data_stream=False` covers both ways there is nothing to
    read; `handle_stream_failure` is what tells them apart, and each
    states its own reason."""
    absent = _coverage(handle_data_stream=False)
    failed = _coverage(handle_data_stream=False,
                        handle_stream_failure="SizeOfHeader 4 is out of bounds")
    assert absent.evaluated is failed.evaluated is True   # memory_info still ran
    assert absent.complete is failed.complete is False
    assert project_coverage_v1(absent)[1] != project_coverage_v1(failed)[1]


def test_a_truncated_handle_stream_makes_coverage_partial():
    """A captured stream that delivered only part of its descriptor array
    was evaluated, but not completely: the handles the scored checks saw
    are a head, and a pipe handle in the dropped tail is neither found nor
    ruled out."""
    coverage = _coverage(handle_stream_truncated=3)
    assert coverage.evaluated is True
    assert coverage.complete is False
    assert coverage.status == "partial"
    # The region walk itself finished -- truncation is a stream gap, and
    # must not be laundered into the v1.1 `scan_complete` key.
    assert coverage.region_scan_complete is True


@pytest.mark.parametrize("gap, value", [
    ("skipped_oversize", (_oversize_target(),)),
    ("read_failed", 1),
    ("short_reads", 1),
])
def test_a_region_scan_gap_alone_makes_the_run_partial_and_inconclusive(gap, value):
    coverage = _coverage(**{gap: value})
    assert coverage.region_scan_complete is False
    assert coverage.status == "partial"
    assert _report(score=0, coverage=coverage).status == "INCONCLUSIVE"
    # ...but a real detection still wins over incomplete coverage.
    assert _report(score=1, coverage=coverage).status == "DETECTED"


def test_the_two_budgets_stay_independent():
    """Merging them would let one signal's exhaustion silently misreport
    the other signal's coverage -- see dumpex/hunt/pipe/config.py."""
    c2_only = _coverage(c2_budget_exhausted=True, c2_budget_reason="deadline")
    name_only = _coverage(pipe_name_budget_exhausted=True, pipe_name_budget_reason="max_hits")
    assert c2_only.budget_exhausted is True and name_only.budget_exhausted is True
    assert c2_only.pipe_name_budget_exhausted is False
    assert name_only.c2_budget_exhausted is False
    assert c2_only.region_gap_reasons() == ("C2-context scan budget exhausted (deadline)",)
    assert name_only.region_gap_reasons() == ("pipe-name scan budget exhausted (max_hits)",)


def test_region_gap_reasons_are_ordered_and_worded_once():
    coverage = _coverage(skipped_oversize=(_oversize_target(),), read_failed=2, short_reads=3,
                          c2_budget_exhausted=True, c2_budget_reason="max_hits",
                          pipe_name_budget_exhausted=True, pipe_name_budget_reason="deadline")
    reasons = coverage.region_gap_reasons()
    assert len(reasons) == 5
    assert reasons[0].startswith("1 oversized region(s) skipped")
    assert "0x00007ff600100000" in reasons[0] and "9 MB > 8 MB limit" in reasons[0]
    assert reasons[1] == "2 region(s) failed to read"
    assert reasons[2].startswith("3 region(s) returned fewer bytes than declared (short read)")
    assert reasons[3] == "C2-context scan budget exhausted (max_hits)"
    assert reasons[4] == "pipe-name scan budget exhausted (deadline)"
    assert isinstance(reasons, tuple)


def test_system_dll_pipe_references_are_scan_detail_never_a_coverage_gap():
    coverage = _coverage(image_pipe_refs=3, image_pipe_modules=("kernel32.dll", "ntdll.dll"))
    assert coverage.region_scan_complete is True
    assert coverage.status == "complete"
    assert coverage.region_gap_reasons() == ()


def test_coverage_snapshot_rejects_non_boolean_stream_flags_and_bad_counts():
    with pytest.raises(TypeError):
        _coverage(memory_info_stream=1)
    with pytest.raises(TypeError):
        _coverage(handle_data_stream="yes")
    with pytest.raises(TypeError):
        _coverage(read_failed=True)
    with pytest.raises(ValueError):
        _coverage(read_failed=-1)


def test_coverage_snapshot_oversized_bucket_rejects_non_scan_target_items():
    with pytest.raises(TypeError):
        _coverage(skipped_oversize=({"base_address": 0x1000},))


def test_coverage_snapshot_image_pipe_modules_must_be_strings():
    with pytest.raises(TypeError):
        _coverage(image_pipe_modules=(object(),))
    assert _coverage(image_pipe_modules=["ntdll.dll"]).image_pipe_modules == ("ntdll.dll",)


# ── Scan-layer transport types ────────────────────────────────────────────

def test_pipe_name_scan_result_rejects_a_live_coverage_tracker():
    from dumpex.hunt._coverage import CoverageTracker
    with pytest.raises(TypeError, match="PipeNameScanResult.coverage must be a PipeScanCoverage"):
        PipeNameScanResult(coverage=CoverageTracker())


def test_pipe_name_scan_result_rejects_a_coverage_snapshot_poisoned_after_construction():
    coverage = PipeScanCoverage()
    object.__setattr__(coverage, "read_failed", [])
    with pytest.raises(TypeError):
        PipeNameScanResult(coverage=coverage)


def test_pipe_scan_coverage_targets_reject_non_scan_target_items():
    with pytest.raises(TypeError, match="must be a ScanTarget"):
        PipeScanCoverage(skipped_oversize_targets=([],))


def test_handle_scan_result_rejects_raw_minidump_handles():
    with pytest.raises(TypeError, match="HandleScanResult.handles\\[0\\] must be a "
                                          "PipeHandleEvidence"):
        HandleScanResult(handles=(Handle(0x1, "File", r"\Device\NamedPipe\x"),))


def test_handle_scan_result_rejects_a_negative_dropped_descriptor_count():
    with pytest.raises(ValueError, match="dropped_descriptors must be a non-negative int"):
        HandleScanResult(dropped_descriptors=-1)


def test_correlation_result_rejects_the_wrong_evidence_type_per_bucket():
    with pytest.raises(TypeError):
        CorrelationResult(corroborated_handles=(_start_lead(),))
    with pytest.raises(TypeError):
        CorrelationResult(unbacked_threads=(_c2_context(),))


def test_no_mutable_collection_is_reachable_from_a_scan_result():
    result = PipeNameScanResult(
        string_leads=(_string_lead(),),
        c2_regions=(RegionC2Records(region=_region(), records=(_c2_record(),)),),
        coverage=PipeScanCoverage(skipped_oversize_targets=(_oversize_target(),),
                                   image_pipe_modules=("ntdll.dll",)))
    seen = 0
    for value in _reachable(result):
        seen += 1
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"a mutable {type(value).__name__} is reachable from PipeNameScanResult: {value!r}")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True
    assert seen > 20, "the walk did not actually reach the nested leads/coverage"


# ── aggregate.build_report's own gating ───────────────────────────────────

def test_build_report_omits_the_open_handles_check_without_the_stream():
    """`handle_pipes` is empty both when the dump recorded zero pipe
    handles and when HandleDataStream was never captured -- only the first
    is worth an observation."""
    report = pipe_aggregate.build_report(memory_info_stream=True, handle_data_stream=False)
    assert [r.check for r in report.results] == []
    assert report.status == "INCONCLUSIVE"


def test_build_report_scores_only_from_handle_anchored_evidence():
    """A bare pipe string never becomes scored handle evidence -- not even
    one whose name matches a known framework convention."""
    lead = _string_lead()
    report = pipe_aggregate.build_report(
        (), (lead,), (), (), (), (_framework_string_hit(string_hit=lead),), (_unbacked(),),
        memory_info_stream=True, handle_data_stream=True)
    assert report.score == 0
    assert [r.check for r in report.results] == ["pipe.string_scan_lead"]
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"


@pytest.mark.parametrize("nearby_c2, rip_hit, expected", [
    pytest.param(None, None, 1, id="framework-only"),
    pytest.param((_c2_record(),), None, 2, id="c2-only"),
    pytest.param((), _thread_hit(), 2, id="rip-only"),
    pytest.param((_c2_record(),), _thread_hit(), 3, id="both"),
])
def test_build_report_score_tiers(nearby_c2, rip_hit, expected):
    handle, lead = _handle(), _string_lead()
    corroborated = ()
    if nearby_c2 is not None:
        corroborated = (_corroborated(handle=handle, string_hit=lead, nearby_c2=nearby_c2,
                                       rip_hit=rip_hit),)
    report = pipe_aggregate.build_report(
        (handle,), (lead,), corroborated, (), (), (), (),
        memory_info_stream=True, handle_data_stream=True)
    assert report.score == expected


def test_build_report_scores_a_corroborated_non_framework_pipe():
    """Tiers 2-3 are deliberately NOT gated on a framework name match."""
    handle = _handle(canonical_name="my_custom_ipc_channel", framework=False)
    lead = _string_lead()
    report = pipe_aggregate.build_report(
        (handle,), (lead,), (_corroborated(handle=handle, string_hit=lead),), (), (), (), (),
        memory_info_stream=True, handle_data_stream=True)
    assert report.score == 2
    assert "pipe.handle_framework_match" not in [r.check for r in report.results]


def test_build_report_start_address_lead_never_scores():
    handle, lead = _handle(framework=False), _string_lead()
    report = pipe_aggregate.build_report(
        (handle,), (lead,), (), (_start_lead(handle=handle, string_hit=lead),), (), (), (),
        memory_info_stream=True, handle_data_stream=True)
    assert report.score == 0
    assert "pipe.start_address_proximity_lead" in [r.check for r in report.results]


def test_build_report_takes_no_dump_or_projection_state():
    import inspect
    parameters = set(inspect.signature(pipe_aggregate.build_report).parameters)
    assert not (parameters & {"mf", "verbose", "detail_level", "level", "regions", "modules",
                               "thread_contexts", "coverage_counts", "c2_budget",
                               "pipe_name_budget"})
