"""Project a ``CSBeaconReport`` into the current ``HunterRecord``.

Configuration fields are keyed by field name and carry ``type``/``value``.
Process addresses are hex strings; dump offsets and XOR keys remain integers.
"""
from dumpex.hunt.cs_beacon.domain import CSBeaconReport
from dumpex.hunt.cs_beacon.report_facts import (
    finding_from_check_result, name_keyed_fields, project_coverage_report,
)
from dumpex.output.records import CsBeaconDetails, HunterRecord, hex_address


def _record_config_dict(hit, corroborated: bool) -> dict:
    region = hit.region
    return {
        "va": hex_address(hit.hit_va),
        "file_offset": hit.hit_fo,
        "region_base":    hex_address(region.base_address) if region is not None else None,
        "region_size":    region.size    if region is not None else None,
        "region_protect": region.protect if region is not None else None,
        "xor_key": hit.xor_key,
        "cs_version": hit.cs_version,
        "cs_version_note": "estimated from highest recognized field ID — not a "
                            "fingerprinted/confirmed build",
        "context_corroborated": corroborated,
        "fields": name_keyed_fields(hit),
    }


def project_hunter_record(report: CSBeaconReport) -> HunterRecord:
    """Pure `CSBeaconReport` -> `HunterRecord` conversion -- no scanning,
    no printing."""
    findings_list = [finding_from_check_result(r, report) for r in report.results]
    configs = [
        _record_config_dict(hit, report.evidence.corroboration_for(hit) is not None)
        for hit in report.evidence.hits
    ]
    details = CsBeaconDetails(configs=configs, config_count=len(configs))

    return HunterRecord(
        hunter="cs-beacon", status=report.status, score=report.score,
        max_score=report.max_score, verdict_level=report.verdict_level,
        confidence=report.confidence, lead_count=report.lead_count,
        review_priority=report.review_priority,
        coverage=project_coverage_report(
            report.coverage, has_hits=bool(report.evidence.hits),
            any_corroborated=report.any_corroborated),
        findings=[f.to_dict() for f in findings_list], details=details,
    )
