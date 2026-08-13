"""`CSBeaconReport` -> the v1.1 legacy `findings` dict -- a pure projection,
independent of `report_record.py`/`report_console.py`. Mirrors
`dumpex.hunt.hollowing.report_legacy`/`dumpex.hunt.stomping.report_legacy`/
`dumpex.hunt.pipe.report_legacy` (the completed reference pilots).

The dict's KEY SET and `configs[*]` shape are unchanged by this migration
(issue #9's "current-contract freeze": `va`/`file_offset`/`region_base` stay
plain JSON ints, `fields` stays keyed by the field ID's decimal STRING with
`name`/`type`/`raw`/`value`) -- this is the SAME shape
`dumpex/hunt/__init__.py`'s dispatcher used to hand-assemble from
`results["cs-beacon"]["configs"]` AFTER rendering (the "orchestration-layer
CS config byte-sanitization pass" issue #9 asks to remove). That
sanitization is now done HERE, once, as part of building the legacy dict
itself -- the dispatcher's own pass is now redundant and has been deleted.
"""
from dumpex.hunt.cs_beacon.domain import CSBeaconReport
from dumpex.hunt.cs_beacon.report_facts import finding_from_check_result, project_coverage_v1


def _legacy_field_dict(f) -> dict:
    """One `models.ConfigField` -> the v1.1 int(str)-keyed shape's own
    per-field dict -- byte-identical to what
    `dumpex/hunt/__init__.py`'s pre-migration dispatcher sanitization pass
    built field-by-field."""
    return {
        "name":  f.name,
        "type":  f.type,
        "raw":   f.raw.hex() if isinstance(f.raw, bytes) else str(f.raw),
        "value": f.value.hex() if isinstance(f.value, bytes) else f.value,
    }


def _legacy_config_dict(hit, corroborated: bool) -> dict:
    region = hit.region
    return {
        "va": hit.hit_va, "file_offset": hit.hit_fo,
        "region_base":    region.base_address if region is not None else None,
        "region_size":    region.size         if region is not None else None,
        "region_protect": region.protect      if region is not None else None,
        "xor_key": hit.xor_key, "cs_version": hit.cs_version,
        "cs_version_note": "estimated from highest recognized field ID — not a "
                            "fingerprinted/confirmed build",
        "context_corroborated": corroborated,
        "fields": {str(f.field_id): _legacy_field_dict(f) for f in hit.fields},
    }


def project_legacy_dict(report: CSBeaconReport) -> dict:
    """The v1.1 findings dict -- the same shape `_hunt_cs_beacon()` has
    always returned, built purely from `report.evidence`/`report.coverage`/
    derived properties."""
    has_hits = bool(report.evidence.hits)
    any_corroborated = report.any_corroborated
    coverage_status, coverage_reasons = project_coverage_v1(
        report.coverage, has_hits=has_hits, any_corroborated=any_corroborated)
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    configs = [
        _legacy_config_dict(hit, report.evidence.corroboration_for(hit) is not None)
        for hit in report.evidence.hits
    ]

    result = {
        "configs": configs,
        "score": report.score,
        "max_score": report.max_score,
        "coverage_status": coverage_status,
        "coverage_reasons": coverage_reasons,
        "status": report.status,
        "verdict_level": report.verdict_level,
        "confidence": report.confidence,
        "findings": [f.to_dict() for f in findings_list],
        "lead_count": report.lead_count,
        "review_priority": report.review_priority,
    }
    if report.evaluated:
        result["coverage"] = {
            "mem_info_stream":    report.coverage.mem_info_available,
            "thread_list_stream": report.coverage.thread_list_stream_available,
            "threads_total":      report.coverage.threads_total,
            "contexts_parsed":    report.coverage.contexts_parsed,
            "contexts_missing":   report.coverage.contexts_missing,
        }
    if has_hits:
        result["config_count"] = report.config_count
    return result
