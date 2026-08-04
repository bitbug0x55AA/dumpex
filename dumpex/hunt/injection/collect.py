"""
`collect_injection_record()` -- the v2.4 migration's (PR2) `HunterRecord`-
producing entry point for the injection hunter, alongside the console-
oriented `_hunt_injection()` in `dumpex/hunt/injection/__init__.py`. Both
call the exact same `_build_injection_report()` pipeline (see that
module's own docstring), so this module only RESHAPES the resulting
`aggregate.Report` into a `HunterRecord` -- it never recomputes score,
status, verdict, or coverage itself. That is what guarantees the console
path and this v2.4 path can never silently disagree about the same input.

Every raw `Region`/`ThreadInfo`/context-dict object the aggregate's
`findings`/`Report` fields hold is converted here into a typed
`HuntRegionRef`/`HuntThreadRef`/`HuntPeHeaderHit` with hex-formatted
addresses -- this is the fix for the confirmed pre-migration defect
documented in docs/hunt_migration_field_matrix.md's cross-cutting finding
#1 (raw objects reaching JSON via `_json_safe()`'s `str(obj)` fallback,
embedding a non-reproducible interpreter heap address). Nothing in this
module is read by `dumpex/hunt/__init__.py`'s dispatcher yet -- the CLI
switch is PR4.
"""
from dumpex.core.memory import prot_str
from dumpex.hunt.injection import _build_injection_report
from dumpex.output.records import (
    HunterRecord, InjectionDetails, HuntRegionRef, HuntThreadRef, HuntThreadRegionHit,
    HuntPeHeaderHit, hex_address,
)


def _region_ref(region) -> HuntRegionRef:
    return HuntRegionRef(
        base_address=hex_address(region.BaseAddress),
        allocation_base=hex_address(getattr(region, "AllocationBase", None)),
        size=region.RegionSize,
        type=prot_str(region.Type),
        protect=prot_str(region.Protect),
    )


def _pe_hit_ref(hit: dict) -> HuntPeHeaderHit:
    region = _region_ref(hit["region"])
    pe = hit["pe"]
    if pe["valid"]:
        return HuntPeHeaderHit(
            region=region, valid=True, machine_name=pe["machine_name"],
            is_pe32_plus=pe["is_pe32_plus"], number_of_sections=pe["number_of_sections"],
            entry_point_rva=pe["address_of_entry_point"], image_base=hex_address(pe["image_base"]))
    return HuntPeHeaderHit(region=region, valid=False, reason=pe["reason"])


def _thread_ref_from_info(ti) -> HuntThreadRef:
    return HuntThreadRef(tid=ti.ThreadId, start_address=hex_address(ti.StartAddress))


def _thread_ref_from_context(ctx: dict) -> HuntThreadRef:
    return HuntThreadRef(tid=ctx["ThreadId"], ip=hex_address(ctx["ip"]), ip_reg=ctx["ip_reg"])


def _thread_region_hit_from_context_pair(pair) -> HuntThreadRegionHit:
    ctx, region = pair
    return HuntThreadRegionHit(thread=_thread_ref_from_context(ctx), region=_region_ref(region))


def _thread_region_hit_from_info_pair(pair) -> HuntThreadRegionHit:
    ti, region = pair
    return HuntThreadRegionHit(thread=_thread_ref_from_info(ti), region=_region_ref(region))


def _record_from_injection_report(report) -> HunterRecord:
    """Pure `aggregate.Report` -> `HunterRecord` conversion -- no
    scanning, no printing. The ONE place both `collect_injection_record()`
    (below) and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4
    orchestrator, PR4) build the typed record from an ALREADY-BUILT
    Report, so a single `_build_injection_report()` call can feed both
    the console renderer and this conversion without scanning twice."""
    f = report.findings
    corr = report.correlation

    details = InjectionDetails(
        rwx=[_region_ref(r) for r in report.rwx],
        hidden_pe_validated=[_pe_hit_ref(h) for h in report.validated_pe_hits],
        hidden_pe_unvalidated=[_pe_hit_ref(h) for h in report.mz_only_hits],
        suspicious_validated_pe_hits=[_pe_hit_ref(h) for h in report.suspicious_pe_hits],
        informational_validated_pe_hits=[_pe_hit_ref(h) for h in report.informational_pe_hits],
        threads=[_thread_ref_from_info(ti) for ti in report.start_threads],
        thread_contexts=[_thread_ref_from_context(ctx) for ctx in f["thread_contexts"]],
        rwx_and_pe_alloc_bases=[hex_address(a) for a in f["rwx_and_pe_alloc_bases"]],
        rip_hits=[_thread_region_hit_from_context_pair(p) for p in corr.rip_hits],
        rip_full_correlation=[_thread_region_hit_from_context_pair(p)
                               for p in corr.rip_full_correlation],
        start_hits=[_thread_region_hit_from_info_pair(p) for p in corr.start_hits],
    )

    return HunterRecord(
        hunter="injection",
        status=f["status"],
        score=f["score"],
        max_score=f["max_score"],
        verdict_level=f["verdict_level"],
        confidence=f["confidence"],
        lead_count=f["lead_count"],
        review_priority=f["review_priority"],
        coverage=report.coverage_report,
        findings=f["findings"],
        details=details,
    )


def collect_injection_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="injection"`) for `mf` -- the v2.4
    equivalent of `_hunt_injection()`'s v1.1 dict, sharing the exact same
    underlying `Report`. Thin compat wrapper: builds a fresh Report and
    converts it -- `collect_hunt()` calls `_build_injection_report()` and
    `_record_from_injection_report()` directly instead, so it never scans
    twice just to also get console output from the same run."""
    return _record_from_injection_report(_build_injection_report(mf))
