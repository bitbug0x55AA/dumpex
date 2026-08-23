"""`InjectionReport` -> current-schema (v2.13) `HunterRecord` pure
projector. Since the Injection 2C cutover, `dumpex.hunt.injection.collect.
_record_from_injection_report` is simply this module's own
`project_hunter_record`, re-exported under that name.

Deliberately does not import `dumpex.hunt.injection.collect`/`aggregate`
-- the five small Hunt*Ref-builder helpers below are pure functions of
`dumpex.hunt.injection.models` types, entirely independent of how
`aggregate.py` builds the `InjectionReport` they project. `thread_contexts`
here never needs to subscript a raw dict -- `InjectionEvidence.
thread_contexts` is already a tuple of typed `ThreadContext` objects, so
the same typed-attribute read every other ref builder here already uses
applies to it too.
"""
from dumpex.hunt.injection.domain import InjectionReport
from dumpex.hunt.injection.report_facts import finding_from_check_result, project_coverage_report
from dumpex.output.records import (
    HunterRecord, InjectionDetails, HuntRegionRef, HuntThreadRef, HuntThreadRegionHit,
    HuntPeHeaderHit, hex_address,
)


def _region_ref(region_ref) -> HuntRegionRef:
    return HuntRegionRef(
        base_address=hex_address(region_ref.base_address),
        allocation_base=hex_address(region_ref.allocation_base),
        size=region_ref.size,
        type=region_ref.type,
        protect=region_ref.protect,
    )


def _pe_hit_ref(hit) -> HuntPeHeaderHit:
    # The candidate's own location travels with it (schema_version 2.11):
    # `hit.location` is the address the 'MZ' was actually found at, which
    # since the whole-region candidate search (issue #26) is not
    # necessarily the containing region's base -- a consumer given only
    # `region` could not carve the image or tell two hits inside one
    # region apart. `file_offset` stays None when the VA is not covered by
    # a captured segment; `hex_address` preserves that None rather than
    # inventing a zero.
    region = _region_ref(hit.region)
    location = hit.location
    where = dict(va=hex_address(location.va), region_offset=location.region_offset,
                  file_offset=hex_address(location.file_offset))
    pe = hit.pe
    if pe.valid:
        return HuntPeHeaderHit(
            region=region, valid=True, machine_name=pe.machine_name,
            is_pe32_plus=pe.is_pe32_plus, number_of_sections=pe.number_of_sections,
            entry_point_rva=pe.address_of_entry_point, image_base=hex_address(pe.image_base),
            **where)
    return HuntPeHeaderHit(region=region, valid=False, reason=pe.reason, **where)


def _thread_ref_from_evidence(ev) -> HuntThreadRef:
    return HuntThreadRef(tid=ev.thread_id, start_address=hex_address(ev.start_address))


def _thread_ref_from_context(tc) -> HuntThreadRef:
    return HuntThreadRef(tid=tc.thread_id, ip=hex_address(tc.ip), ip_reg=tc.ip_reg)


def _thread_region_hit_from_rip_hit(hit) -> HuntThreadRegionHit:
    thread = HuntThreadRef(tid=hit.thread_id, ip=hex_address(hit.ip), ip_reg=hit.ip_reg)
    return HuntThreadRegionHit(thread=thread, region=_region_ref(hit.region))


def _thread_region_hit_from_start_hit(hit) -> HuntThreadRegionHit:
    thread = HuntThreadRef(tid=hit.thread_id, start_address=hex_address(hit.start_address))
    return HuntThreadRegionHit(thread=thread, region=_region_ref(hit.region))


def project_hunter_record(report: InjectionReport) -> HunterRecord:
    """Pure `InjectionReport -> HunterRecord` projection -- a NEW
    `HunterRecord`/`InjectionDetails` on every call, no shared mutable
    state, and no dependency on call order relative to `report_legacy.
    project_legacy_dict`/`report_console.render_console_lines` for the
    SAME `report`."""
    evidence = report.evidence

    details = InjectionDetails(
        rwx=[_region_ref(ev.region) for ev in evidence.rwx],
        hidden_pe_validated=[_pe_hit_ref(h) for h in evidence.validated_pe_hits],
        hidden_pe_unvalidated=[_pe_hit_ref(h) for h in evidence.mz_only_hits],
        suspicious_validated_pe_hits=[_pe_hit_ref(h) for h in evidence.suspicious_pe_hits],
        informational_validated_pe_hits=[_pe_hit_ref(h) for h in evidence.informational_pe_hits],
        threads=[_thread_ref_from_evidence(ev) for ev in evidence.start_threads],
        thread_contexts=[_thread_ref_from_context(tc) for tc in evidence.thread_contexts],
        rwx_and_pe_alloc_bases=[hex_address(a)
                                 for a in sorted(evidence.correlation.rwx_and_pe_alloc_bases)],
        rip_hits=[_thread_region_hit_from_rip_hit(h) for h in evidence.correlation.rip_hits],
        rip_full_correlation=[_thread_region_hit_from_rip_hit(h)
                               for h in evidence.correlation.rip_full_correlation],
        start_hits=[_thread_region_hit_from_start_hit(h) for h in evidence.correlation.start_hits],
    )

    return HunterRecord(
        hunter="injection",
        status=report.status,
        score=report.score,
        max_score=report.max_score,
        verdict_level=report.verdict_level,
        confidence=report.confidence,
        lead_count=report.lead_count,
        review_priority=report.review_priority,
        coverage=project_coverage_report(report.coverage),
        findings=[finding_from_check_result(r, report).to_dict() for r in report.results],
        details=details,
    )
