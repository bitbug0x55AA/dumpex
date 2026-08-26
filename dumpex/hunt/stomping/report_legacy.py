"""Project a ``StompingReport`` into the legacy v1.1 findings shape.

Evidence entries are rebuilt by value while preserving the public key set
and the fields consumed by compatibility clients.
"""
from dumpex.hunt.stomping.domain import StompingReport
from dumpex.hunt.stomping.report_facts import finding_from_check_result, project_coverage_v1


def _module_dict(module) -> dict:
    """No `module is None` guard (unlike the pre-migration `collect.py`'s
    own): a `ProtectionLeadEvidence`/`VerifiedChangeEvidence` validates its
    `module` as a real `ModuleRef` at construction, so None is no longer
    representable here."""
    return {"name": module.name, "base_address": module.base_address, "size": module.size}


def _section_dict(section) -> dict:
    """The exact nine keys `dumpex.core.pe_utils.parse_pe_header()` puts on
    one `sections` entry -- the shape this dict has always carried."""
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
    """JSON-safe description of a region BY VALUE -- `state`/`protect`/
    `type` are already `prot_str()`-resolved strings on `RegionRef` (see
    models.py), so nothing here needs `dumpex.ui.structured._json_safe()`
    to reduce an enum-like value to its `.name`."""
    return {
        "BaseAddress": region.base_address,
        "AllocationBase": region.allocation_base,
        "RegionSize": region.size,
        "State": region.state,
        "Protect": region.protect,
        "Type": region.type,
    }


def _protection_lead_dict(ev) -> dict:
    return {
        "module": _module_dict(ev.module),
        "section": _section_dict(ev.section),
        "region": _region_dict(ev.region),
        "expected": ev.expected,
        "actual": ev.actual,
        "va_start": ev.va_start,
        "va_end": ev.va_end,
    }


def _verified_change_dict(vc) -> dict:
    return {
        "module": _module_dict(vc.module),
        "section": _section_dict(vc.section),
        "va_start": vc.va_start,
        "diff_ranges": [list(r) for r in vc.diff_ranges],
        "ranges_truncated": vc.ranges_truncated,
        "total_ranges": vc.total_ranges,
        "compared_len": vc.compared_len,
        "rip_in_changed_range": vc.rip_in_changed_range,
        "disk_sha256": vc.disk_sha256,
        "mem_sha256": vc.mem_sha256,
    }


def project_legacy_dict(report: StompingReport) -> dict:
    """The v1.1 findings dict -- the same shape `_hunt_stomping()` has
    always returned, built purely from `report.evidence`/`report.results`/
    `report.coverage`/derived properties."""
    coverage_counts, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    return {
        "protection_leads": [_protection_lead_dict(ev)
                             for ev in report.evidence.protection_leads],
        "verified_changes": [_verified_change_dict(vc)
                             for vc in report.evidence.verified_changes],
        "score": report.score,
        "max_score": report.max_score,
        "status": report.status,
        "coverage_status": coverage_status,
        "coverage_reasons": coverage_reasons,
        "coverage_counts": coverage_counts,
        "verdict_level": report.verdict_level,
        "confidence": report.confidence,
        "findings": [f.to_dict() for f in findings_list],
        "lead_count": report.lead_count,
        "review_priority": report.review_priority,
    }
