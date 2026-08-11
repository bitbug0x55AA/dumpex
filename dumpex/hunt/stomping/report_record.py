"""`StompingReport` -> `HunterRecord` (the current typed record) -- a pure
projection, independent of `report_legacy.py`/`report_console.py`. Mirrors
`dumpex.hunt.injection.report_record`/`dumpex.hunt.encoding.report_record`
(the completed reference pilots): builds the SAME `StompingDetails` shape
the pre-migration `dumpex/hunt/stomping/collect.py` built, directly from
the typed evidence buckets rather than from an already-JSON-shaped
`findings` dict -- no public schema/wire-shape change.

The pre-migration `collect.py` had to convert a live `Module` and a live
`MinidumpMemoryInfo` (both embedded in the `protection_leads`/
`verified_changes` dicts) into JSON-safe dicts here, calling `prot_str()`
a second time at projection time. Both are now resolved once, at scan time
(dumpex.hunt.stomping.models), so this module only reshapes already-typed
facts.
"""
from dumpex.hunt.stomping.domain import StompingReport
from dumpex.hunt.stomping.report_facts import finding_from_check_result, project_coverage_report
from dumpex.output.records import HunterRecord, StompingDetails, hex_address


def _module_dict(module) -> dict:
    """No `module is None` guard (unlike the pre-migration `collect.py`'s
    own): a `ProtectionLeadEvidence`/`VerifiedChangeEvidence` validates its
    `module` as a real `ModuleRef` at construction, so None is no longer
    representable here. The same applies to `_region_dict` below."""
    return {
        "name": module.name,
        "base_address": hex_address(module.base_address),
        "size": module.size,
    }


def _section_dict(section) -> dict:
    return {
        "name": section.name,
        "virtual_address": section.virtual_address,
        "virtual_size": section.virtual_size,
        "pointer_to_raw_data": section.pointer_to_raw_data,
        "size_of_raw_data": section.size_of_raw_data,
        "characteristics": section.characteristics,
        "is_executable": section.is_executable,
        "is_writable": section.is_writable,
        "is_readable": section.is_readable,
    }


def _region_dict(region) -> dict:
    return {
        "base_address": hex_address(region.base_address),
        "allocation_base": hex_address(region.allocation_base),
        "size": region.size,
        "type": region.type,
        "protect": region.protect,
    }


def _protection_lead_dict(ev) -> dict:
    return {
        "module": _module_dict(ev.module),
        "section": _section_dict(ev.section),
        "region": _region_dict(ev.region),
        "expected": ev.expected,
        "actual": ev.actual,
        "va_start": hex_address(ev.va_start),
        "va_end": hex_address(ev.va_end),
    }


def _verified_change_dict(vc) -> dict:
    return {
        "module": _module_dict(vc.module),
        "section": _section_dict(vc.section),
        "va_start": hex_address(vc.va_start),
        "diff_ranges": [list(r) for r in vc.diff_ranges],
        "ranges_truncated": vc.ranges_truncated,
        "total_ranges": vc.total_ranges,
        "compared_len": vc.compared_len,
        "rip_in_changed_range": vc.rip_in_changed_range,
        "disk_sha256": vc.disk_sha256,
        "mem_sha256": vc.mem_sha256,
    }


def project_hunter_record(report: StompingReport) -> HunterRecord:
    """Pure `StompingReport` -> `HunterRecord` conversion -- no scanning,
    no printing."""
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    details = StompingDetails(
        protection_leads=[_protection_lead_dict(ev) for ev in report.evidence.protection_leads],
        verified_changes=[_verified_change_dict(vc) for vc in report.evidence.verified_changes],
    )

    return HunterRecord(
        hunter="stomping", status=report.status, score=report.score,
        max_score=report.max_score, verdict_level=report.verdict_level,
        confidence=report.confidence, lead_count=report.lead_count,
        review_priority=report.review_priority,
        coverage=project_coverage_report(report.coverage),
        findings=[f.to_dict() for f in findings_list], details=details,
    )
