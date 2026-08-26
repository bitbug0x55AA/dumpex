"""Project an ``InjectionReport`` into the legacy v1.1 findings shape.

The projection rebuilds raw legacy dictionaries from immutable typed
evidence without changing their public keys or value semantics.
"""
from dumpex.hunt.injection.domain import InjectionReport
from dumpex.hunt.injection.report_facts import finding_from_check_result, project_coverage_v1


def _region_dict(r) -> dict:
    return {"base_address": r.base_address, "allocation_base": r.allocation_base,
            "size": r.size, "type": r.type, "protect": r.protect}


def _pe_dict(pe) -> dict:
    return {"valid": pe.valid, "machine_name": pe.machine_name, "is_pe32_plus": pe.is_pe32_plus,
            "number_of_sections": pe.number_of_sections,
            "address_of_entry_point": pe.address_of_entry_point, "image_base": pe.image_base,
            "reason": pe.reason}


def _pe_hit_dict(hit) -> dict:
    return {"region": _region_dict(hit.region), "in_module_list": hit.in_module_list,
            "pe": _pe_dict(hit.pe)}


def _thread_dict(ev) -> dict:
    return {"thread_id": ev.thread_id, "start_address": ev.start_address}


def _thread_context_dict(tc) -> dict:
    """The raw `{"ThreadId", "ip", "ip_reg", "is_wow64"}` shape
    `dumpex.core.memory.get_thread_contexts()` returns -- the v1.1 dict's
    `thread_contexts` key was never projected by `legacy.py` (it stayed a
    list of these same raw dicts even after the Evidence migration, see
    aggregate.py's own comment on `findings["thread_contexts"]`), so this
    reproduces that raw shape from the now-typed `ThreadContext` instead."""
    return {"ThreadId": tc.thread_id, "ip": tc.ip, "ip_reg": tc.ip_reg, "is_wow64": tc.is_wow64}


def _rip_hit_dict(hit) -> dict:
    return {"thread_id": hit.thread_id, "ip": hit.ip, "ip_reg": hit.ip_reg,
            "region": _region_dict(hit.region)}


def _start_hit_dict(hit) -> dict:
    return {"thread_id": hit.thread_id, "start_address": hit.start_address,
            "region": _region_dict(hit.region)}


def project_legacy_dict(report: InjectionReport) -> dict:
    """Return a new legacy findings dictionary for ``report``."""
    evidence = report.evidence
    coverage_dict, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)

    return {
        "rwx":                              [_region_dict(ev.region) for ev in evidence.rwx],
        "hidden_pe_validated":               [_pe_hit_dict(h) for h in evidence.validated_pe_hits],
        "hidden_pe_unvalidated":             [_pe_hit_dict(h) for h in evidence.mz_only_hits],
        "suspicious_validated_pe_hits":      [_pe_hit_dict(h) for h in evidence.suspicious_pe_hits],
        "informational_validated_pe_hits":   [_pe_hit_dict(h) for h in evidence.informational_pe_hits],
        "threads":                           [_thread_dict(ev) for ev in evidence.start_threads],
        "thread_contexts":                   [_thread_context_dict(tc) for tc in evidence.thread_contexts],
        "rwx_and_pe_alloc_bases":            sorted(evidence.correlation.rwx_and_pe_alloc_bases),
        "rip_hits":                          [_rip_hit_dict(h) for h in evidence.correlation.rip_hits],
        "rip_full_correlation":              [_rip_hit_dict(h)
                                                for h in evidence.correlation.rip_full_correlation],
        "start_hits":                        [_start_hit_dict(h) for h in evidence.correlation.start_hits],
        "score":                             report.score,
        "max_score":                         report.max_score,
        "status":                            report.status,
        "coverage":                          coverage_dict,
        "coverage_status":                   coverage_status,
        "coverage_reasons":                  coverage_reasons,
        "confidence":                        report.confidence,
        "verdict_level":                     report.verdict_level,
        "pe_read_failed":                    report.coverage.pe_read_failed,
        "pe_short_reads":                    report.coverage.pe_short_reads,
        # Third counter of the same family (see models.HiddenPeScan): the
        # candidate search stopped on its own per-region read budget, so
        # part of that region was never searched. Emitted alongside the
        # other two rather than folded into either -- "we stopped early"
        # is a different fact from "the dump would not give us the bytes".
        "pe_scan_truncated":                 report.coverage.pe_scan_truncated,
        # Fourth counter of the same family (issue #28): a LATER region the
        # whole-hunt scan budget was already exhausted before its own
        # search ever started -- distinct from pe_scan_truncated's "we
        # started this region and stopped partway through".
        "pe_scan_not_started":               report.coverage.pe_scan_not_started,
        "findings":                          [finding_from_check_result(r, report).to_dict()
                                                for r in report.results],
        "lead_count":                        report.lead_count,
        "review_priority":                   report.review_priority,
    }
