"""`InjectionReport` -> legacy v1.1 findings-dict pure projector -- since
the Injection 2C cutover, this is the ONE place that dict gets built (the
pre-cutover `dumpex.hunt.injection.aggregate.build_report`'s own `findings`
dict, and `dumpex.hunt.injection.legacy.legacy_findings_dict`'s
Evidence-dataclass -> plain-dict conversion that ran on top of it, have
both been deleted; this module replaces both as ONE pure function of an
already-built, already-frozen `InjectionReport`).

Deliberately does not import `dumpex.hunt.injection.aggregate`: this
module (and the sibling `report_record.py`/`report_console.py` projectors)
depends only on the canonical `InjectionReport`/typed evidence, never on
`aggregate.py`'s own construction internals -- the six small dict-builder
helpers below are pure functions of `dumpex.hunt.injection.models` types,
independently verified against production output by
tests/hunt/test_injection_projectors.py's golden-scenario parity test.
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
    """Pure `InjectionReport -> dict` projection -- a NEW dict on every
    call, no shared mutable state, and no dependency on call order
    relative to `report_record.project_hunter_record`/`report_console.
    render_console_lines` for the SAME `report`."""
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
        "findings":                          [finding_from_check_result(r, report).to_dict()
                                                for r in report.results],
        "lead_count":                        report.lead_count,
        "review_priority":                   report.review_priority,
    }
