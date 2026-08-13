"""
Contract tests for the injection Evidence migration (dumpex.hunt.injection.
models) -- distinct from tests/hunt/test_injection.py (end-to-end hunter
behavior) and tests/hunt/test_output_source_architecture.py (the
cross-hunter Report-level contract). Covers the acceptance criteria for
this commit:

  1. Every Evidence type is a frozen dataclass.
  2. Evidence fields hold only scalars/tuples/frozensets/nested immutable
     Evidence/Location -- never a raw minidump Region/ThreadInfo object.
  3. The scan layer (memory_scan.py/thread_scan.py) builds Evidence WITH
     its Location already resolved, in one step -- there is no longer a
     separate "raw object list" + "parallel BaseAddress -> Location dict"
     to keep in sync (the pattern dumpex.hunt.injection.aggregate.py's own
     docstring describes this migration as replacing).
"""
import dataclasses
from types import MappingProxyType

import pytest

from tests.fixtures.fakes import (Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader)

from dumpex.hunt._location import Location
from dumpex.hunt.injection import memory_scan, thread_scan, correlation
from dumpex.hunt.injection.models import (
    RegionRef, PeHeaderInfo, RwxRegionEvidence, HiddenPeEvidence, UnbackedThreadEvidence,
    RipHitEvidence, StartHitEvidence, HiddenPeScan, Correlation,
)


EVIDENCE_TYPES = [
    RegionRef, PeHeaderInfo, RwxRegionEvidence, HiddenPeEvidence, UnbackedThreadEvidence,
    RipHitEvidence, StartHitEvidence, HiddenPeScan, Correlation,
]


@pytest.mark.parametrize("evidence_type", EVIDENCE_TYPES, ids=[t.__name__ for t in EVIDENCE_TYPES])
def test_evidence_type_is_a_frozen_dataclass(evidence_type):
    assert dataclasses.is_dataclass(evidence_type)
    assert evidence_type.__dataclass_params__.frozen is True


_RAW_MINIDUMP_TYPES = (Region, ThreadInfo, Module, Ctx, Thread)


def _assert_no_raw_minidump_objects(value, seen=None):
    """Recursively walk a constructed Evidence instance's own field values
    (not the minidump-typed constructor inputs a test fixture builds) and
    assert none of them is a raw Region/ThreadInfo/Module/Ctx/Thread --
    only scalars, tuples, dicts, frozensets, or nested dataclasses that
    themselves pass the same check."""
    if isinstance(value, _RAW_MINIDUMP_TYPES):
        pytest.fail(f"raw minidump object leaked into Evidence: {value!r}")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            _assert_no_raw_minidump_objects(getattr(value, f.name))
    elif isinstance(value, (tuple, list, frozenset, set)):
        for item in value:
            _assert_no_raw_minidump_objects(item)
    elif isinstance(value, (dict, MappingProxyType)):
        for k, v in value.items():
            _assert_no_raw_minidump_objects(k)
            _assert_no_raw_minidump_objects(v)


def _fake_mf_with_rwx_and_hidden_pe():
    rwx_base = 0x7ffe10000000
    pe_base = 0x7ffe20000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(rwx_base, rwx_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(pe_base, pe_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, 0x9999000)]   # unbacked -> UnbackedThreadEvidence

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")

    mf = MF()
    reader = mem_reader({pe_base: pe_bytes})
    return mf, reader, rwx_base, pe_base


def test_hunt_rwx_returns_frozen_evidence_with_location_already_resolved():
    mf, _reader, rwx_base, _pe_base = _fake_mf_with_rwx_and_hidden_pe()
    hits = memory_scan._hunt_rwx(mf)

    assert isinstance(hits, tuple)
    assert len(hits) == 1
    ev = hits[0]
    assert isinstance(ev, RwxRegionEvidence)
    assert isinstance(ev.region, RegionRef)
    assert ev.region.base_address == rwx_base
    # The Location is already resolved as part of THIS SAME evidence object
    # -- no separate address->Location dict for aggregate.py to look up.
    assert isinstance(ev.location, Location)
    _assert_no_raw_minidump_objects(ev)


def test_hunt_hidden_pe_returns_frozen_evidence_with_location_already_resolved():
    mf, reader, _rwx_base, pe_base = _fake_mf_with_rwx_and_hidden_pe()
    scan = memory_scan._hunt_hidden_pe(mf, reader, module_list_available=True)

    assert isinstance(scan, HiddenPeScan)
    assert isinstance(scan.hits, tuple)
    assert len(scan.hits) == 1
    ev = scan.hits[0]
    assert isinstance(ev, HiddenPeEvidence)
    assert isinstance(ev.region, RegionRef)
    assert ev.region.base_address == pe_base
    assert isinstance(ev.pe, PeHeaderInfo)
    assert ev.pe.valid is True
    assert isinstance(ev.location, Location)
    _assert_no_raw_minidump_objects(ev)


def test_hunt_unbacked_threads_returns_frozen_evidence_with_location_already_resolved():
    mf, _reader, _rwx_base, _pe_base = _fake_mf_with_rwx_and_hidden_pe()
    hits = thread_scan._hunt_unbacked_threads(mf, module_list_available=True)

    assert isinstance(hits, tuple)
    assert len(hits) == 1
    ev = hits[0]
    assert isinstance(ev, UnbackedThreadEvidence)
    assert ev.thread_id == 0x1
    assert ev.start_address == 0x9999000
    assert isinstance(ev.location, Location)
    _assert_no_raw_minidump_objects(ev)


# ── frozen=True is shallow: HiddenPeScan/Correlation must independently ──
# close the in-place-mutation gap for their own dict/list-typed fields, the
# same way dumpex.hunt._finding.Finding normalizes its list fields to
# tuples. These tests attempt the actual mutation, not just check
# `__dataclass_params__.frozen` (which frozen=True alone already
# satisfies even when a field's mutable CONTENTS remain reachable).

def test_hidden_pe_scan_hits_is_a_tuple_and_rejects_in_place_mutation():
    scan = HiddenPeScan(hits=[])   # list on construction, like Finding accepts
    assert isinstance(scan.hits, tuple)
    with pytest.raises(AttributeError):
        scan.hits.append("late")


def test_hidden_pe_scan_does_not_retain_the_callers_original_list():
    hits = []
    scan = HiddenPeScan(hits=hits)
    hits.append("tampered")
    assert scan.hits == ()


def test_correlation_rwx_by_alloc_rejects_item_assignment():
    corr = Correlation(rwx_by_alloc={0x1000: []})
    assert isinstance(corr.rwx_by_alloc, MappingProxyType)
    with pytest.raises(TypeError):
        corr.rwx_by_alloc[0x2000] = ()


def test_correlation_pe_by_alloc_rejects_item_assignment():
    corr = Correlation(pe_by_alloc={0x1000: []})
    with pytest.raises(TypeError):
        corr.pe_by_alloc[0x2000] = ()


def test_correlation_does_not_retain_the_callers_original_dict():
    rwx_by_alloc = {0x1000: [object()]}
    corr = Correlation(rwx_by_alloc=rwx_by_alloc)
    rwx_by_alloc[0x2000] = ["tampered"]
    assert 0x2000 not in corr.rwx_by_alloc


def test_correlation_hit_lists_are_tuples_and_reject_in_place_mutation():
    corr = Correlation(rip_hits=[], rip_full_correlation=[], start_hits=[])
    for attr in ("rip_hits", "rip_full_correlation", "start_hits"):
        value = getattr(corr, attr)
        assert isinstance(value, tuple)
        with pytest.raises(AttributeError):
            value.append("late")


def test_correlation_alloc_base_sets_are_frozensets_and_reject_mutation():
    corr = Correlation(rwx_and_pe_alloc_bases={0x1000}, suspicious_alloc_bases={0x1000})
    assert isinstance(corr.rwx_and_pe_alloc_bases, frozenset)
    assert isinstance(corr.suspicious_alloc_bases, frozenset)
    with pytest.raises(AttributeError):
        corr.rwx_and_pe_alloc_bases.add(0x2000)


# ── Evidence must never leak into the legacy findings dict a caller gets ──
# (dumpex.hunt.injection.report_legacy.project_legacy_dict()).
# `_render_injection_console()` is what _hunt_injection()/cmd_hunt()'s bare
# results["injection"] actually returns -- these exercise it end to end,
# not just the projector function in isolation, so a future change that
# stops calling the projector (or calls it on the wrong Report) is still
# caught.

def test_hunt_injection_return_value_never_holds_evidence_dataclasses():
    from dumpex.hunt.injection import _hunt_injection
    from dumpex.hunt.injection import models as injection_models

    mf, reader, rwx_base, pe_base = _fake_mf_with_rwx_and_hidden_pe()
    f = _hunt_injection(mf, verbose=False)

    evidence_types = tuple(
        cls for cls in vars(injection_models).values()
        if isinstance(cls, type) and dataclasses.is_dataclass(cls))
    for key in ("rwx", "hidden_pe_validated", "hidden_pe_unvalidated",
                "suspicious_validated_pe_hits", "informational_validated_pe_hits",
                "threads", "rip_hits", "rip_full_correlation", "start_hits"):
        for item in f[key]:
            assert isinstance(item, dict), f"{key} item is not a plain dict: {item!r}"
            assert not isinstance(item, evidence_types)


def test_legacy_findings_dict_rwx_and_hidden_pe_shape():
    from dumpex.hunt.injection.domain import InjectionEvidence, InjectionReport
    from dumpex.hunt.injection.report_legacy import project_legacy_dict
    from dumpex.hunt.injection.models import (
        RegionRef, PeHeaderInfo, RwxRegionEvidence, HiddenPeEvidence,
    )
    from dumpex.hunt._location import Location
    from tests.hunt.test_injection_domain import _coverage, _correlation_for

    rwx_region = RegionRef(base_address=0x1000, allocation_base=0x1000, size=0x1000,
                            type="MEM_PRIVATE", protect="PAGE_EXECUTE_READWRITE")
    pe_region = RegionRef(base_address=0x2000, allocation_base=0x2000, size=0x1000,
                           type="MEM_PRIVATE", protect="PAGE_READWRITE")
    rwx_loc = Location(va=0x1000, region_base=0x1000, file_offset=None)
    pe_loc = Location(va=0x2000, region_base=0x2000, file_offset=None)
    rwx_ev = RwxRegionEvidence(region=rwx_region, location=rwx_loc)
    pe = PeHeaderInfo(valid=True, machine_name="AMD64", is_pe32_plus=True,
                       number_of_sections=1, address_of_entry_point=0x10, image_base=0x400000,
                       reason="")
    pe_ev = HiddenPeEvidence(region=pe_region, pe=pe, in_module_list=False, location=pe_loc)

    evidence = InjectionEvidence(
        rwx=[rwx_ev], validated_pe_hits=[pe_ev], informational_pe_hits=[pe_ev],
        correlation=_correlation_for(rwx=[rwx_ev], validated_pe_hits=[pe_ev]))
    report = InjectionReport(score=1, coverage=_coverage(), results=(), evidence=evidence)
    out = project_legacy_dict(report)

    assert out["rwx"] == [{"base_address": 0x1000, "allocation_base": 0x1000,
                            "size": 0x1000, "type": "MEM_PRIVATE",
                            "protect": "PAGE_EXECUTE_READWRITE"}]
    assert out["hidden_pe_validated"] == [{
        "region": {"base_address": 0x2000, "allocation_base": 0x2000, "size": 0x1000,
                   "type": "MEM_PRIVATE", "protect": "PAGE_READWRITE"},
        "in_module_list": False,
        "pe": {"valid": True, "machine_name": "AMD64", "is_pe32_plus": True,
               "number_of_sections": 1, "address_of_entry_point": 0x10,
               "image_base": 0x400000, "reason": ""},
    }]
    assert out["score"] == 1   # non-Evidence keys pass through unchanged


def test_hunt_injection_not_evaluated_branch_also_uses_the_projector():
    # render()'s NOT_EVALUATED early return is a SEPARATE `return` statement
    # from its main-path return -- verified this is actually a distinct code
    # path (an earlier revert-one-return-only mistake during regression
    # verification let a reverted main-path projector call slip through
    # undetected because this scenario alone exercises NOT_EVALUATED).
    from dumpex.hunt.injection import _hunt_injection

    class MF(FakeMF):
        memory_info = None
        thread_info = None
        modules = FakeStream([], "modules")

    f = _hunt_injection(MF(), verbose=False)
    assert f["status"] == "NOT_EVALUATED"
    for key in ("rwx", "hidden_pe_validated", "threads"):
        assert f[key] == []


# `project_legacy_dict` not mutating its input, and being pure/order-
# independent across repeated calls, is already covered for the canonical
# `InjectionReport` by tests/hunt/test_injection_projectors.py's
# `test_projectors_are_order_independent_and_pure`/
# `test_console_verbose_and_normal_never_change_json_projections` -- no
# separate test needed here now that this module builds an `InjectionReport`
# (itself immutable by construction, see test_injection_domain.py) rather
# than handing a raw dict to a standalone projector function.


# ── StartAddress=None must never be fabricated into a fake known address ──
# Regression: an early version stored `ti.StartAddress or 0` directly onto
# UnbackedThreadEvidence.start_address, permanently losing the distinction
# between "this thread really starts at VA 0" and "this thread has no
# recorded StartAddress at all" -- the v2.6 record then reported a
# fabricated "0x0000000000000000" where the wire contract must emit `null`
# (hex_address(None) is None, see dumpex.output.records.hex_address).

def _fake_mf_with_unbacked_thread_missing_start_address():
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    infos = [ThreadInfo(0x1, None)]   # StartAddress genuinely absent

    class MF(FakeMF):
        modules = FakeStream(mods, "modules")
        thread_info = FakeStream(infos, "infos")

    return MF()


def test_unbacked_thread_evidence_preserves_none_start_address():
    mf = _fake_mf_with_unbacked_thread_missing_start_address()
    hits = thread_scan._hunt_unbacked_threads(mf, module_list_available=True)

    assert len(hits) == 1
    assert hits[0].start_address is None
    # Location resolution still ran (using a 0-substituted lookup address
    # internally) without raising.
    assert isinstance(hits[0].location, Location)


def test_v2_6_record_emits_null_not_a_fabricated_zero_address():
    from dumpex.hunt.injection import collect

    mf = _fake_mf_with_unbacked_thread_missing_start_address()
    record = collect.collect_injection_record(mf)

    assert len(record.details.threads) == 1
    assert record.details.threads[0].start_address is None


def test_console_facts_do_not_crash_and_display_zero_for_none_start_address(capsys):
    from dumpex.hunt.injection import _hunt_injection

    mf = _fake_mf_with_unbacked_thread_missing_start_address()

    f = _hunt_injection(mf, verbose=False)   # must not raise formatting None as hex
    assert len(f["threads"]) == 1

    f = _hunt_injection(mf, verbose=True)    # must not raise either
    out = capsys.readouterr().out
    assert "StartAddress_VA=0x0000000000000000" in out


def test_correlate_returns_frozen_region_ref_hits_not_raw_regions():
    mf, reader, rwx_base, pe_base = _fake_mf_with_rwx_and_hidden_pe()
    from dumpex.core.memory import get_memory_regions

    rwx = memory_scan._hunt_rwx(mf)
    scan = memory_scan._hunt_hidden_pe(mf, reader, module_list_available=True)
    validated_pe_hits, _mz_only = memory_scan.split_hidden_pe_hits(scan)
    start_threads = thread_scan._hunt_unbacked_threads(mf, module_list_available=True)
    regions = get_memory_regions(mf)
    thread_contexts = thread_scan.resolve_thread_contexts(mf)   # typed ThreadContext tuple

    corr = correlation.correlate(rwx, validated_pe_hits, thread_contexts, start_threads, regions)

    assert isinstance(corr, Correlation)
    for ab, refs in corr.rwx_by_alloc.items():
        assert isinstance(refs, tuple)
        for r in refs:
            assert isinstance(r, RegionRef)
    for hit in corr.rip_hits:
        assert isinstance(hit, RipHitEvidence)
        assert isinstance(hit.region, RegionRef)
    for hit in corr.start_hits:
        assert isinstance(hit, StartHitEvidence)
        assert isinstance(hit.region, RegionRef)
    _assert_no_raw_minidump_objects(corr)
