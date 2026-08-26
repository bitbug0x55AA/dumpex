"""Hunter-specific contracts for the canonical hollowing domain model."""
import dataclasses
import enum
from types import MappingProxyType

import pytest

from tests.fixtures.fakes import Module, Region

from dumpex.hunt._domain import CheckResult, require_recursively_immutable
from dumpex.hunt._finding import (
    Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
    overall_confidence, verdict_level, lead_count, review_priority,
)
from dumpex.hunt.hollowing import aggregate as hollowing_aggregate
from dumpex.hunt.hollowing import correlation as hollowing_correlation
from dumpex.hunt.hollowing import memory_scan
from dumpex.hunt.hollowing.domain import (
    HEADER_READ_FAILED_REASON, MAX_SCORE, MODULE_LIST_MISSING_REASON, PEB_MISSING_REASON,
    REGION_MISSING_REASON, VERDICT_LEVEL_BY_SCORE,
    CoverageSnapshot, HollowingEvidence, HollowingReport,
)
from dumpex.hunt.hollowing.models import (
    HeaderRead, ImageBaseContext, MemPrivateEvidence, ModuleRef, NameMismatchEvidence,
    OUTCOME_CLEAN, OUTCOME_EXCEPTION, OUTCOME_SHORT_READ, OUTCOME_WIPED_OTHER,
    OUTCOME_WIPED_ZERO, RegionRef, RwxProtectionEvidence, StructuralCorrelationEvidence,
    WipedHeaderEvidence, basename_lower, module_ref, region_ref,
)


# ── Builders ────────────────────────────────────────────────────────────

_IMAGE_BASE = 0x140000000
_IMAGE_PATH = r"C:\Windows\System32\legit.exe"
_MZ_BYTES   = b"MZ" + b"\x90" * 62
_ZERO_BYTES = b"\x00" * 64


def _module(base=_IMAGE_BASE, name=_IMAGE_PATH):
    return ModuleRef(name=name, basename=name.rsplit("\\", 1)[-1] if name else "",
                      base_address=base, size=0x5000)


def _region(base=_IMAGE_BASE, protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE"):
    return RegionRef(base_address=base, allocation_base=base, size=0x5000,
                      state="MEM_COMMIT", protect=protect, type=type)


def _header(outcome=OUTCOME_CLEAN, header_bytes=_MZ_BYTES, error=None):
    if outcome == OUTCOME_EXCEPTION:
        return HeaderRead(outcome=outcome, error=error or "simulated read failure")
    return HeaderRead(outcome=outcome, header_bytes=header_bytes)


def _context(**overrides):
    kwargs = dict(image_base=_IMAGE_BASE, image_path=_IMAGE_PATH,
                   peb_image_path=_IMAGE_PATH, header=_header(),
                   file_offset=0x3000, region=_region(), region_file_offset=0x3000,
                   module=_module())
    kwargs.update(overrides)
    return ImageBaseContext(**kwargs)


def _mem_private(**overrides):
    return MemPrivateEvidence(**{"region": _region(), **overrides})


def _wiped_header(**overrides):
    return WipedHeaderEvidence(**{"image_base": _IMAGE_BASE,
                                   "header_bytes": _ZERO_BYTES, **overrides})


def _rwx(**overrides):
    return RwxProtectionEvidence(**{"region": _region(), **overrides})


def _name_mismatch(**overrides):
    return NameMismatchEvidence(**{"image_path": _IMAGE_PATH,
                                    "module": _module(name=r"C:\Windows\System32\other.exe"),
                                    **overrides})


def _correlation(mem_private=None, wiped_header=None, rwx=None, image_base=_IMAGE_BASE):
    return StructuralCorrelationEvidence(
        image_base=image_base, mem_private=mem_private if mem_private is not None
        else _mem_private(), wiped_header=wiped_header,
        rwx=rwx if (rwx is not None or wiped_header is not None) else _rwx())


def _coverage(**overrides):
    kwargs = dict(peb_present=True, image_base_region_found=True, mz_read_failed=False,
                   modules_available=True)
    kwargs.update(overrides)
    return CoverageSnapshot(**kwargs)


def _check(check="hollowing.mem_private_at_image_base", tag=TAG_LEAD,
           confidence=CONFIDENCE_MEDIUM, evidence=(), **overrides):
    kwargs = dict(check=check, inference="something was observed at the image base",
                   confidence=confidence, rationale="because of the evidence above",
                   evidence=evidence, tag=tag)
    kwargs.update(overrides)
    return CheckResult(**kwargs)


# An explicit sentinel rather than a callable/None default: `context` is
# itself a parametrized POISON slot below (including a callable resolver
# and None), so "was a context passed at all" cannot be inferred from the
# value.
_DEFAULT_CONTEXT = object()


def _report(score=0, results=(), evidence=None, coverage=None, context=_DEFAULT_CONTEXT):
    coverage = coverage if coverage is not None else _coverage()
    if context is _DEFAULT_CONTEXT:
        context = _context() if coverage.peb_present else None
    return HollowingReport(score=score, coverage=coverage, context=context, results=results,
                            evidence=evidence if evidence is not None else HollowingEvidence())


def _populated_report():
    """Every one of the five check ids in one Report, with the full
    three-signal correlation -- deliberately richer than any single scan
    would produce, purely to exercise the whole model at once."""
    mem_private = _mem_private()
    wiped = _wiped_header()
    rwx = _rwx()
    mismatch = _name_mismatch()
    correlation = _correlation(mem_private=mem_private, wiped_header=wiped, rwx=rwx)
    evidence = HollowingEvidence(
        mem_private=(mem_private,), wiped_headers=(wiped,), rwx=(rwx,),
        name_mismatches=(mismatch,), correlations=(correlation,))
    results = (
        _check(check="hollowing.mem_private_at_image_base", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(mem_private,)),
        _check(check="hollowing.mz_header_missing", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(wiped,)),
        _check(check="hollowing.rwx_at_image_base", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(rwx,)),
        _check(check="hollowing.peb_module_name_mismatch", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(mismatch,)),
        _check(check="hollowing.structural_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(correlation,)),
    )
    return HollowingReport(score=2, coverage=_coverage(), context=_context(),
                            results=results, evidence=evidence)


DOMAIN_TYPES = [CheckResult, CoverageSnapshot, HollowingEvidence, HollowingReport]
EVIDENCE_TYPES = [ModuleRef, RegionRef, HeaderRead, ImageBaseContext, MemPrivateEvidence,
                  WipedHeaderEvidence, RwxProtectionEvidence, NameMismatchEvidence,
                  StructuralCorrelationEvidence]


# ── Construction success for every evidence type ──────────────────────────

def test_every_evidence_type_constructs_from_well_formed_input():
    assert _module().basename == "legit.exe"
    assert _module().basename_lower == "legit.exe"
    assert _region().protect == "PAGE_EXECUTE_READWRITE"
    assert _header().header_present is True
    assert _context().image_name == "legit.exe"
    assert _mem_private().region.type == "MEM_PRIVATE"
    assert _wiped_header().header_bytes == _ZERO_BYTES
    assert _rwx().region.protect == "PAGE_EXECUTE_READWRITE"
    assert _name_mismatch().module.basename_lower == "other.exe"
    assert _correlation().corroborators == ("MEM_PRIVATE at image base", "RWX protection")


def test_scan_time_builders_resolve_identity_once():
    """`module_ref`/`region_ref` are the ONE place a raw minidump object
    becomes a snapshot -- basename and prot_str() resolution happen there,
    never later."""
    raw_module = Module(_IMAGE_BASE, 0x5000, _IMAGE_PATH)
    raw_region = Region(_IMAGE_BASE, _IMAGE_BASE, 0x5000, "MEM_COMMIT",
                         "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    assert module_ref(raw_module).basename == "legit.exe"
    assert module_ref(raw_module).name == _IMAGE_PATH
    assert region_ref(raw_region).protect == "PAGE_EXECUTE_READWRITE"
    assert region_ref(raw_region).state == "MEM_COMMIT"
    assert region_ref(raw_region).type == "MEM_PRIVATE"
    for snapshot in (module_ref(raw_module), region_ref(raw_region)):
        require_recursively_immutable(snapshot, "snapshot")


def test_basename_lower_uses_windows_path_rules_on_any_host():
    """A minidump's paths are always Windows paths, whatever OS dumpex is
    running on -- os.path.basename would return the whole string unchanged
    on POSIX."""
    assert basename_lower(r"C:\Windows\System32\Legit.EXE") == "legit.exe"
    assert basename_lower(None) == ""
    assert basename_lower("") == ""


@pytest.mark.parametrize("factory, kwargs, exc", [
    pytest.param(ModuleRef, dict(name=b"x", basename="x", base_address=0), TypeError,
                 id="module-name-bytes"),
    pytest.param(ModuleRef, dict(name="x", basename="x", base_address=-1), ValueError,
                 id="module-negative-base"),
    pytest.param(ModuleRef, dict(name="x", basename="x", base_address=True), TypeError,
                 id="module-bool-base"),
    pytest.param(RegionRef, dict(base_address=0, allocation_base=None, size=0,
                                  state="MEM_COMMIT", protect=None, type="MEM_IMAGE"), TypeError,
                 id="region-none-protect"),
    pytest.param(HeaderRead, dict(outcome="brand_new_outcome"), ValueError,
                 id="header-unknown-outcome"),
    pytest.param(HeaderRead, dict(outcome=OUTCOME_CLEAN, header_bytes=bytearray(b"MZ")),
                 TypeError, id="header-mutable-bytearray"),
])
def test_evidence_construction_rejects_bad_field_values(factory, kwargs, exc):
    with pytest.raises(exc):
        factory(**kwargs)


def test_header_read_requires_bytes_unless_the_read_raised():
    with pytest.raises(ValueError, match="header_bytes is required"):
        HeaderRead(outcome=OUTCOME_CLEAN)
    with pytest.raises(ValueError, match="must be None for an exception outcome"):
        HeaderRead(outcome=OUTCOME_EXCEPTION, header_bytes=b"MZ")


@pytest.mark.parametrize("outcome, read_failed, wiped, present", [
    (OUTCOME_CLEAN,       False, False, True),
    (OUTCOME_WIPED_ZERO,  False, True,  False),
    (OUTCOME_WIPED_OTHER, False, True,  False),
    (OUTCOME_SHORT_READ,  True,  False, None),
    (OUTCOME_EXCEPTION,   True,  False, None),
])
def test_header_read_tri_state_is_derived_never_stored(outcome, read_failed, wiped, present):
    """The pre-migration Report carried `mz_read_failed`/`mz_wiped` as
    independent booleans alongside `mz_outcome`, and recomputed
    `mz_header_present` a third time inside the record projector."""
    header = _header(outcome=outcome, header_bytes=b"\x00" * 4)
    assert header.read_failed is read_failed
    assert header.wiped is wiped
    assert header.header_present is present
    assert "read_failed" not in {f.name for f in dataclasses.fields(HeaderRead)}


def test_context_rejects_a_region_file_offset_without_a_region():
    with pytest.raises(ValueError, match="region_file_offset cannot be set without a region"):
        _context(region=None, region_file_offset=0x3000)


def test_correlation_requires_at_least_one_corroborator():
    """A lone MEM_PRIVATE anchor is a lead, never a correlation -- the rule
    this hunter exists to enforce, pinned at the type level so no caller can
    build a "correlation" of one signal."""
    with pytest.raises(ValueError, match="requires at least one corroborating signal"):
        StructuralCorrelationEvidence(image_base=_IMAGE_BASE, mem_private=_mem_private())


@pytest.mark.parametrize("wiped, rwx, expected", [
    (True,  False, ("MEM_PRIVATE at image base", "MZ header missing/wiped")),
    (False, True,  ("MEM_PRIVATE at image base", "RWX protection")),
    (True,  True,  ("MEM_PRIVATE at image base", "MZ header missing/wiped", "RWX protection")),
])
def test_corroborator_labels_are_derived_from_the_references_actually_held(wiped, rwx, expected):
    correlation = _correlation(wiped_header=_wiped_header() if wiped else None,
                                rwx=_rwx() if rwx else None)
    assert correlation.corroborators == expected
    assert correlation.full_correlation is (wiped and rwx)


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
    for collection in (report.results, report.evidence.mem_private,
                       report.evidence.wiped_headers, report.evidence.rwx,
                       report.evidence.name_mismatches, report.evidence.correlations,
                       report.results[0].evidence):
        assert isinstance(collection, tuple)
        with pytest.raises(AttributeError):
            collection.append("late")


def test_the_whole_report_passes_the_shared_recursive_immutability_check():
    require_recursively_immutable(_populated_report(), "HollowingReport")


def test_the_report_holds_no_minidump_or_module_object_anywhere():
    """The pre-migration Report kept a live `MinidumpMemoryInfo`
    (`base_region`) and a live `Module` (`main_mod`) "ONLY for console
    formatting" -- which is exactly why the renderer also needed `mf`."""
    for value in _reachable(_populated_report()):
        assert not isinstance(value, (Region, Module)), (
            f"a raw minidump object is reachable from the Report: {value!r}")


# ── 2. Constructor inputs are copied, not retained ────────────────────────

def test_mutating_the_results_list_after_construction_cannot_change_the_report():
    results = [_check()]
    report = _report(results=results)
    results.append(_check(check="hollowing.rwx_at_image_base"))
    assert len(report.results) == 1


def test_mutating_an_evidence_list_after_construction_cannot_change_the_report():
    leads = [_mem_private()]
    evidence = HollowingEvidence(mem_private=leads)
    leads.append(_mem_private(region=_region(base=_IMAGE_BASE + 0x10000)))
    assert len(evidence.mem_private) == 1


def test_mutating_a_check_results_evidence_list_after_construction_changes_nothing():
    evidence_list = [_mem_private()]
    result = _check(evidence=evidence_list)
    evidence_list.clear()
    assert len(result.evidence) == 1


# ── 3. Poison objects: what the model must refuse to retain ───────────────

class _FakeResolver:
    def __call__(self, *args, **kwargs):   # pragma: no cover - never invoked
        raise AssertionError("a resolver must never be reachable from the domain model")


class _FakeMinidumpFile:
    pass


class _FakePeb:
    image_base_address = _IMAGE_BASE
    image_path = _IMAGE_PATH


_POISON = [
    pytest.param(Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                        "MEM_PRIVATE"), id="raw-minidump-region"),
    pytest.param(Module(0x1000, 0x1000, "legit.exe"), id="raw-minidump-module"),
    pytest.param(_FakeMinidumpFile(), id="minidump-file"),
    pytest.param(_FakePeb(), id="raw-peb"),
    pytest.param(_FakeResolver(), id="address-resolver"),
    pytest.param({"region": None, "module": None}, id="hand-rolled-dict"),
    pytest.param("VA=0x140000000 type=MEM_PRIVATE", id="console-fact-string"),
    pytest.param(True, id="verbosity-flag"),
]


@pytest.mark.parametrize("poison", _POISON)
def test_report_evidence_buckets_reject_non_evidence_objects(poison):
    with pytest.raises(TypeError):
        HollowingEvidence(mem_private=(poison,))


@pytest.mark.parametrize("poison", _POISON)
def test_mem_private_rejects_a_poisoned_region_reference(poison):
    with pytest.raises(TypeError, match="MemPrivateEvidence.region must be a RegionRef"):
        _mem_private(region=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_name_mismatch_rejects_a_poisoned_module_reference(poison):
    with pytest.raises(TypeError, match="NameMismatchEvidence.module must be a ModuleRef"):
        _name_mismatch(module=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_context_rejects_a_poisoned_region_or_module(poison):
    with pytest.raises(TypeError, match="ImageBaseContext.region must be a RegionRef"):
        _context(region=poison)
    with pytest.raises(TypeError, match="ImageBaseContext.module must be a ModuleRef"):
        _context(module=poison)


@pytest.mark.parametrize("poison", _POISON)
def test_report_rejects_a_poisoned_context(poison):
    with pytest.raises(TypeError, match="context must be an ImageBaseContext"):
        _report(context=poison)


def test_context_rejects_a_poisoned_header_read():
    with pytest.raises(TypeError, match="ImageBaseContext.header must be a HeaderRead"):
        _context(header={"outcome": "clean"})


def test_wiped_header_rejects_a_mutable_byte_buffer():
    with pytest.raises(TypeError, match="header_bytes must be bytes"):
        _wiped_header(header_bytes=bytearray(_ZERO_BYTES))


def _finding():
    return Finding(check="hollowing.mem_private_at_image_base", facts=["VA=0x1"],
                   inference="x", confidence=CONFIDENCE_LOW, rationale="y")


def test_check_result_evidence_rejects_a_finding():
    with pytest.raises(TypeError):
        _check(evidence=(_finding(),))


def test_report_results_reject_findings():
    with pytest.raises(TypeError):
        _report(results=(_finding(),))


def test_report_evidence_buckets_reject_findings():
    with pytest.raises(TypeError):
        HollowingEvidence(mem_private=(_finding(),))


def test_report_rejects_a_hunter_record_as_evidence():
    from tests.fixtures.hunt_records import hollowing_detected
    with pytest.raises(TypeError):
        HollowingEvidence(mem_private=(hollowing_detected(),))


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
    lead = _mem_private()
    object.__setattr__(lead, "extra_payload", [])
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        require_recursively_immutable(lead, "test")


def test_evidence_bucket_rejects_an_item_poisoned_after_its_own_construction():
    """frozen blocks attribute REASSIGNMENT, not `object.__setattr__` -- the
    depth walk at the bucket boundary is what still catches a well-typed
    evidence object whose own field was smuggled a mutable payload."""
    lead = _mem_private()
    object.__setattr__(lead, "hidden", {})
    with pytest.raises(TypeError, match="undeclared instance attribute"):
        HollowingEvidence(mem_private=(lead,))


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
    with pytest.raises(TypeError, match="MemPrivateEvidence.region must be a RegionRef"):
        _mem_private(region=MappingProxyType({0x1000: ()}))


def test_a_mapping_proxy_view_nested_inside_a_well_typed_field_is_still_rejected():
    """The isinstance checks in MemPrivateEvidence's own __post_init__ only
    look at its DIRECT fields -- a MappingProxyType hiding a level deeper,
    inside an otherwise correctly-typed RegionRef, is what the
    require_recursively_immutable(self, ...) depth check still catches."""
    poisoned_region = _region()
    object.__setattr__(poisoned_region, "protect", MappingProxyType({0x1000: ()}))
    with pytest.raises(TypeError, match="read-only view is not an immutable value"):
        _mem_private(region=poisoned_region)


def test_report_rejects_a_coverage_dict_in_place_of_the_snapshot():
    with pytest.raises(TypeError):
        HollowingReport(score=0, coverage={"peb_present": True})


def test_report_rejects_an_evidence_dict_in_place_of_the_container():
    with pytest.raises(TypeError):
        HollowingReport(score=0, coverage=_coverage(peb_present=False),
                        evidence={"mem_private": ()})


def test_report_evidence_buckets_reject_the_wrong_evidence_type():
    with pytest.raises(TypeError):
        HollowingEvidence(mem_private=(_rwx(),))
    with pytest.raises(TypeError):
        HollowingEvidence(rwx=(_mem_private(),))


def test_a_bucket_rejects_the_same_object_listed_twice():
    lead = _mem_private()
    with pytest.raises(ValueError, match="already in this bucket"):
        HollowingEvidence(mem_private=(lead, lead))


def test_a_bucket_rejects_a_second_observation_of_the_single_image_base():
    """One address means one answer per check -- a second entry would mean
    two different answers for the same image base."""
    with pytest.raises(ValueError, match="at most one item"):
        HollowingEvidence(mem_private=(_mem_private(),
                                        _mem_private(region=_region(base=_IMAGE_BASE + 0x10000))))


# ── Bucket-to-bucket identity relations ───────────────────────────────────

def test_correlation_must_cite_the_reports_own_anchor_objects():
    stray = _mem_private(region=_region(base=_IMAGE_BASE + 0x10000))
    with pytest.raises(ValueError, match="not one of"):
        HollowingEvidence(mem_private=(_mem_private(),), rwx=(_rwx(),),
                          correlations=(_correlation(mem_private=stray, rwx=_rwx()),))


def test_correlation_rejects_an_equal_but_separate_copy_of_an_anchor():
    bucket_anchor, identical_copy = _mem_private(), _mem_private()
    rwx = _rwx()
    assert bucket_anchor == identical_copy and bucket_anchor is not identical_copy
    with pytest.raises(ValueError, match="not one of"):
        HollowingEvidence(mem_private=(bucket_anchor,), rwx=(rwx,),
                          correlations=(_correlation(mem_private=identical_copy, rwx=rwx),))


def test_correlation_must_cite_the_reports_own_corroborator_objects():
    mem_private = _mem_private()
    with pytest.raises(ValueError, match="not one of"):
        HollowingEvidence(mem_private=(mem_private,), rwx=(_rwx(),),
                          correlations=(_correlation(mem_private=mem_private, rwx=_rwx()),))


def test_report_stores_no_second_copy_of_its_evidence():
    lead = _mem_private()
    report = _report(results=(_check(evidence=(lead,)),),
                     evidence=HollowingEvidence(mem_private=(lead,)))
    assert report.results[0].evidence[0] is report.evidence.mem_private[0]


def test_report_rejects_a_result_citing_evidence_no_bucket_accounts_for():
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        _report(results=(_check(evidence=(_mem_private(
                    region=_region(base=_IMAGE_BASE + 0x10000)),)),),
                evidence=HollowingEvidence(mem_private=(_mem_private(),)))


def test_report_rejects_a_result_citing_an_equal_but_separate_copy():
    bucket_item, identical_copy = _mem_private(), _mem_private()
    assert bucket_item == identical_copy and bucket_item is not identical_copy
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(identical_copy,)),),
                evidence=HollowingEvidence(mem_private=(bucket_item,)))


def test_report_rejects_a_result_citing_a_merely_nested_object():
    lead = _mem_private()
    with pytest.raises(ValueError):
        _report(results=(_check(evidence=(lead.region,)),),
                evidence=HollowingEvidence(mem_private=(lead,)))


# ── 4. Derived judgment fields ────────────────────────────────────────────

def test_status_is_derived_from_score_and_coverage():
    assert _report(score=0).status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert _report(score=1).status == "DETECTED"
    assert _report(score=0,
                   coverage=_coverage(mz_read_failed=True)).status == "INCONCLUSIVE"
    assert _report(score=1,
                   coverage=_coverage(mz_read_failed=True)).status == "DETECTED"
    assert _report(score=0, coverage=_coverage(peb_present=False)).status == "NOT_EVALUATED"


def test_one_hollowing_signal_already_reads_as_likely_unlike_injections_scale():
    """This hunter's calibration, asserted through the function the
    console and the JSON both call rather than by re-typing the table:
    a hollowing signal is heavy enough that ONE already means "likely",
    where injection's score 1 means only "possible". That same-number-
    different-meaning is exactly why verdict_level() takes a per-hunter
    table instead of deriving from score/max_score arithmetic.

    The table's STRUCTURE -- keys covering 1..MAX_SCORE with nothing
    beyond, the ceiling being the strongest verdict, severity rising with
    score, values inside the schema's verdict_level enum -- is checked
    generically for every hunter in tests/hunt/test_verdict_level_tables.py
    and is deliberately not repeated here."""
    from dumpex.hunt.injection.domain import VERDICT_LEVEL_BY_SCORE as INJECTION_TABLE

    assert verdict_level(1, VERDICT_LEVEL_BY_SCORE, status="DETECTED") == "likely"
    assert verdict_level(MAX_SCORE, VERDICT_LEVEL_BY_SCORE, status="DETECTED") == "high"
    assert (verdict_level(1, VERDICT_LEVEL_BY_SCORE, status="DETECTED")
            != verdict_level(1, INJECTION_TABLE, status="DETECTED"))


def test_negative_score_is_rejected():
    with pytest.raises(ValueError):
        _report(score=-1)


def test_report_holds_no_dump_resolver_or_projection_field():
    field_names = {f.name for f in dataclasses.fields(HollowingReport)}
    assert field_names == {"score", "coverage", "context", "results", "evidence"}
    forbidden = field_names & {"mf", "verbose", "detail_level", "level", "findings",
                                "findings_list", "record", "coverage_report", "base_region",
                                "main_mod", "mz_header_bytes", "status", "confidence"}
    assert not forbidden


def test_report_requires_a_context_exactly_when_the_peb_was_present():
    with pytest.raises(ValueError, match="context is required"):
        HollowingReport(score=0, coverage=_coverage(), context=None)
    with pytest.raises(ValueError, match="context must be None"):
        HollowingReport(score=0, coverage=_coverage(peb_present=False), context=_context())


# ── Coverage snapshot ─────────────────────────────────────────────────────

def test_coverage_snapshot_status_matches_the_shared_reducer():
    assert _coverage().status == "complete"
    assert _coverage(image_base_region_found=False).status == "partial"
    assert _coverage(mz_read_failed=True).status == "partial"
    assert _coverage(modules_available=False).status == "partial"
    assert _coverage(peb_present=False).status == "not_evaluated"


@pytest.mark.parametrize("gap", [
    pytest.param(dict(image_base_region_found=False), id="image-base-page-not-captured"),
    pytest.param(dict(mz_read_failed=True), id="header-read-failed"),
    pytest.param(dict(modules_available=False), id="module-list-missing"),
])
def test_every_per_check_gap_alone_makes_the_run_partial_and_inconclusive(gap):
    coverage = _coverage(**gap)
    assert coverage.evaluated is True
    assert coverage.complete is False
    assert coverage.status == "partial"
    assert _report(score=0, coverage=coverage).status == "INCONCLUSIVE"
    # ...but a real detection still wins over incomplete coverage.
    assert _report(score=1, coverage=coverage).status == "DETECTED"


def test_gap_reasons_are_ordered_and_worded_once():
    coverage = _coverage(image_base_region_found=False, mz_read_failed=True,
                          modules_available=False)
    reasons = coverage.gap_reasons()
    assert reasons == (REGION_MISSING_REASON, HEADER_READ_FAILED_REASON,
                       MODULE_LIST_MISSING_REASON)
    assert isinstance(reasons, tuple)
    assert _coverage().gap_reasons() == ()
    # The PEB's own absence is deliberately NOT one of these: it is the
    # `evaluated` gate, and none of the three checks above was ever reached.
    assert PEB_MISSING_REASON not in reasons


def test_coverage_snapshot_rejects_non_boolean_flags():
    with pytest.raises(TypeError):
        _coverage(peb_present=1)
    with pytest.raises(TypeError):
        _coverage(modules_available="yes")
    with pytest.raises(TypeError):
        _coverage(mz_read_failed=None)


# ── Scan layer: header classification and signal observation ──────────────

def _read(data):
    def _reader(mf, addr, size):
        if isinstance(data, Exception):
            raise data
        return data[:size]
    return _reader


@pytest.mark.parametrize("data, outcome", [
    pytest.param(_MZ_BYTES, OUTCOME_CLEAN, id="clean"),
    pytest.param(_ZERO_BYTES, OUTCOME_WIPED_ZERO, id="zeroed"),
    pytest.param(b"\x41" * 64, OUTCOME_WIPED_OTHER, id="unexpected-bytes"),
    pytest.param(b"M", OUTCOME_SHORT_READ, id="short-read"),
    pytest.param(b"", OUTCOME_SHORT_READ, id="empty-read"),
])
def test_header_read_classification(data, outcome):
    header = memory_scan.read_image_base_header(None, _read(data), _IMAGE_BASE)
    assert header.outcome == outcome
    assert header.header_bytes == data


def test_header_read_that_raises_is_an_exception_outcome_not_a_crash():
    header = memory_scan.read_image_base_header(
        None, _read(OSError("simulated read failure")), _IMAGE_BASE)
    assert header.outcome == OUTCOME_EXCEPTION
    assert header.header_bytes is None
    assert "simulated read failure" in header.error
    assert header.read_failed is True
    assert header.wiped is False


def test_a_short_read_is_a_coverage_gap_never_a_wiped_header():
    """Regression: a one-byte read combined with MEM_PRIVATE previously
    reached a false DETECTED."""
    header = memory_scan.read_image_base_header(None, _read(b"M"), _IMAGE_BASE)
    assert header.wiped is False
    assert header.read_failed is True
    context = _context(header=header)
    _, wiped_headers, _, _ = memory_scan.collect_signals(context, ("PAGE_EXECUTE_READWRITE",),
                                                          modules_available=True)
    assert wiped_headers == ()


def test_collect_signals_skips_the_region_checks_when_no_region_was_captured():
    mem_private, _, rwx, _ = memory_scan.collect_signals(
        _context(region=None, region_file_offset=None), ("PAGE_EXECUTE_READWRITE",),
        modules_available=True)
    assert mem_private == () and rwx == ()


def test_collect_signals_reports_mem_image_as_clean_not_as_an_anchor():
    mem_private, _, _, _ = memory_scan.collect_signals(
        _context(region=_region(type="MEM_IMAGE")), (), modules_available=True)
    assert mem_private == ()


def test_collect_signals_does_not_fire_the_name_check_without_a_module_list():
    """`addr_to_module()` returns None both when the stream is missing and
    when the base genuinely isn't listed -- only `modules_available` can
    tell "the check never ran" from "the base is unmapped"."""
    context = _context(module=None)
    _, _, _, missing_stream = memory_scan.collect_signals(context, (),
                                                           modules_available=False)
    _, _, _, unlisted_base = memory_scan.collect_signals(context, (),
                                                          modules_available=True)
    assert missing_stream == ()
    assert len(unlisted_base) == 1 and unlisted_base[0].module is None


def test_collect_signals_compares_names_case_insensitively():
    context = _context(module=_module(name=r"C:\Windows\System32\LEGIT.exe"))
    _, _, _, mismatches = memory_scan.collect_signals(context, (), modules_available=True)
    assert mismatches == ()


def test_find_image_base_region_matches_a_region_that_began_earlier():
    regions = [Region(_IMAGE_BASE - 0x1000, _IMAGE_BASE - 0x1000, 0x5000, "MEM_COMMIT",
                       "PAGE_READONLY", "MEM_IMAGE")]
    assert memory_scan.find_image_base_region(regions, _IMAGE_BASE) is regions[0]
    assert memory_scan.find_image_base_region([], _IMAGE_BASE) is None


# ── Correlation: the one statement of the scoring requirement ─────────────

@pytest.mark.parametrize("mem_private, wiped, rwx, expected_score", [
    pytest.param(False, False, False, 0, id="nothing"),
    pytest.param(True,  False, False, 0, id="mem-private-alone"),
    pytest.param(False, True,  False, 0, id="wiped-header-alone"),
    pytest.param(False, False, True,  0, id="rwx-alone"),
    pytest.param(True,  True,  False, 1, id="mem-private-plus-wiped"),
    pytest.param(True,  False, True,  1, id="mem-private-plus-rwx"),
    pytest.param(True,  True,  True,  2, id="all-three"),
])
def test_correlation_requirement_and_score(mem_private, wiped, rwx, expected_score):
    mp = (_mem_private(),) if mem_private else ()
    wh = (_wiped_header(),) if wiped else ()
    rx = (_rwx(),) if rwx else ()
    correlations = hollowing_correlation.correlate(mp, wh, rx, _IMAGE_BASE)
    report = hollowing_aggregate.build_report(
        mp, wh, rx, (), correlations, context=_context(), peb_present=True,
        image_base_region_found=True, modules_available=True)
    assert report.score == expected_score
    assert (report.status == "DETECTED") is (expected_score > 0)


def test_a_name_mismatch_never_contributes_to_the_score():
    """Corroborator 4 is a lead in its own right and nothing more -- DLL
    redirection, WoW64 path differences, and capture-time races all produce
    it benignly."""
    mismatches = (_name_mismatch(),)
    correlations = hollowing_correlation.correlate((_mem_private(),), (), (), _IMAGE_BASE)
    assert correlations == ()
    report = hollowing_aggregate.build_report(
        (_mem_private(),), (), (), mismatches, correlations, context=_context(),
        peb_present=True, image_base_region_found=True, modules_available=True)
    assert report.score == 0
    assert report.lead_count == 2


def test_build_report_with_no_arguments_is_the_not_evaluated_result():
    report = hollowing_aggregate.build_report()
    assert report.status == "NOT_EVALUATED"
    assert report.score == 0
    assert report.results == ()
    assert report.context is None
    assert report.verdict_level == "not_evaluated"
    assert report.review_priority == "none"


def test_aggregate_emits_the_checks_in_the_frozen_wire_order():
    """The v1.1 `findings` array and the typed HunterRecord both carry the
    checks in construction order -- console DISPLAY order is a separate,
    presentation-owned decision (report_console._DISPLAY_RANK)."""
    mp, wh, rx = (_mem_private(),), (_wiped_header(),), (_rwx(),)
    correlations = hollowing_correlation.correlate(mp, wh, rx, _IMAGE_BASE)
    report = hollowing_aggregate.build_report(
        mp, wh, rx, (_name_mismatch(),), correlations, context=_context(), peb_present=True,
        image_base_region_found=True, modules_available=True)
    assert [r.check for r in report.results] == [
        "hollowing.mem_private_at_image_base",
        "hollowing.mz_header_missing",
        "hollowing.rwx_at_image_base",
        "hollowing.peb_module_name_mismatch",
        "hollowing.structural_correlation",
    ]
