"""
`collect_stomping_record()` -- the v2.4 migration's (PR2b) `HunterRecord`-
producing entry point for the stomping hunter, alongside the console-
oriented `_hunt_stomping()` in `dumpex/hunt/stomping/__init__.py`. Both
call the exact same `_build_stomping_report()` pipeline, so this module
only RESHAPES the resulting `aggregate.Report` into a `HunterRecord` --
it never recomputes score, status, verdict, or coverage itself.

`protection_leads`/`verified_changes` both embed raw `Module`/
`MinidumpMemoryInfo` objects today (confirmed against the running code,
NOT assumed identical to injection's own defect -- see
docs/hunt_migration_field_matrix.md's stomping section, which only
flagged `verified_changes[*]["va_start"]`'s int-vs-hex gap and missed
`protection_leads`' raw-object one entirely) -- both are converted here
into plain, JSON-safe dicts.
"""
from dumpex.core.memory import prot_str
from dumpex.hunt.stomping import _build_stomping_report
from dumpex.output.records import HunterRecord, StompingDetails, hex_address


def _module_dict(module) -> dict:
    if module is None:
        return None
    return {
        "name": module.name,
        "base_address": hex_address(module.baseaddress),
        "size": module.size,
    }


def _region_dict(region) -> dict:
    if region is None:
        return None
    return {
        "base_address": hex_address(region.BaseAddress),
        "allocation_base": hex_address(getattr(region, "AllocationBase", None)),
        "size": region.RegionSize,
        "type": prot_str(region.Type),
        "protect": prot_str(region.Protect),
    }


def _protection_lead_dict(lead: dict) -> dict:
    return {
        "module": _module_dict(lead["module"]),
        "section": dict(lead["section"]),
        "region": _region_dict(lead["region"]),
        "expected": lead["expected"],
        "actual": lead["actual"],
        "va_start": hex_address(lead["va_start"]),
        "va_end": hex_address(lead["va_end"]),
    }


def _verified_change_dict(vc: dict) -> dict:
    return {
        "module": _module_dict(vc["module"]),
        "section": dict(vc["section"]),
        "va_start": hex_address(vc["va_start"]),
        "diff_ranges": [list(r) for r in vc["diff_ranges"]],
        "ranges_truncated": vc["ranges_truncated"],
        "total_ranges": vc["total_ranges"],
        "compared_len": vc["compared_len"],
        "rip_in_changed_range": vc["rip_in_changed_range"],
        "disk_sha256": vc["disk_sha256"],
        "mem_sha256": vc["mem_sha256"],
    }


def _record_from_stomping_report(report) -> HunterRecord:
    """Pure `aggregate.Report` -> `HunterRecord` conversion -- no
    scanning, no printing. The ONE place both `collect_stomping_record()`
    (below) and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4
    orchestrator, PR4) build the typed record from an ALREADY-BUILT
    Report, so a single `_build_stomping_report()` call can feed both
    the console renderer and this conversion without scanning twice."""
    f = report.findings

    details = StompingDetails(
        protection_leads=[_protection_lead_dict(lead) for lead in f["protection_leads"]],
        verified_changes=[_verified_change_dict(vc) for vc in f["verified_changes"]],
    )

    return HunterRecord(
        hunter="stomping", status=f["status"], score=f["score"], max_score=f["max_score"],
        verdict_level=f["verdict_level"], confidence=f["confidence"],
        lead_count=f["lead_count"], review_priority=f["review_priority"],
        coverage=report.coverage_report, findings=f["findings"], details=details,
    )


def collect_stomping_record(mf, ref_dir: str = None) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="stomping"`) for `mf` -- the
    v2.4 equivalent of `_hunt_stomping()`'s v1.1 dict, sharing the exact
    same underlying `Report`. Thin compat wrapper: builds a fresh Report
    and converts it -- `collect_hunt()` calls `_build_stomping_report()`
    and `_record_from_stomping_report()` directly instead, so it never
    scans twice just to also get console output from the same run."""
    return _record_from_stomping_report(_build_stomping_report(mf, ref_dir=ref_dir))
