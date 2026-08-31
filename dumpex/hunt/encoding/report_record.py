"""Project an ``EncodingReport`` into the current ``HunterRecord``.

Typed evidence is reshaped directly while preserving ``ObfuscationDetails``
wire semantics.
"""
from dumpex.hunt.encoding.domain import EncodingReport
from dumpex.hunt.encoding.report_facts import finding_from_check_result, project_coverage_report
from dumpex.hunt.encoding.report_legacy import _classification_dict
from dumpex.output.records import HunterRecord, ObfuscationDetails, hex_address


def _region_dict(region) -> dict:
    return {
        "base_address": hex_address(region.base_address),
        "allocation_base": hex_address(region.allocation_base),
        "size": region.size,
        "state": region.state,
        "protect": region.protect,
        "type": region.type,
    }


def _bytes_to_hex(value):
    return value.hex() if isinstance(value, bytes) else value


def _decoded_hit_dict(h) -> dict:
    return {
        "layer": h.layer,
        "region": _region_dict(h.region),
        "offset": h.location.region_offset,
        "decoded": _bytes_to_hex(h.decoded),
        "cls": _classification_dict(h.classification),
        "complete": h.complete,
        "raw": _bytes_to_hex(h.raw),
        "key": _bytes_to_hex(h.key),
        "key_offset": h.key_offset,
    }


def _entropy_hit_dict(h) -> dict:
    """`window` appears only for a value measured over a bounded sub-range of
    its region: a targeted rescan locates high entropy inside a sparse
    allocation whose own average is under the threshold, and the address of
    that sub-range is the thing an investigator extracts. A whole-region value
    -- every full-scope hit -- omits the key entirely rather than emitting a
    window equal to the region."""
    out = {"region": _region_dict(h.region), "entropy": h.entropy,
           "threshold": h.threshold}
    if h.size is not None:
        out["window"] = {"base_address": hex_address(h.location.va), "size": h.size}
    return out


def _evidence_for(report: EncodingReport, check: str) -> tuple:
    for result in report.results:
        if result.check == check:
            return result.evidence
    return ()


def project_hunter_record(report: EncodingReport) -> HunterRecord:
    """Pure `EncodingReport` -> `HunterRecord` conversion -- no scanning,
    no printing."""
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    details = ObfuscationDetails(
        sleep_mask=[_decoded_hit_dict(h) for h in report.evidence.sleep_mask_hits],
        entropy=[_entropy_hit_dict(h) for h in report.evidence.entropy_hits],
        base64=[_decoded_hit_dict(h) for h in _evidence_for(report, "obfuscation.base64_observation")],
        xor=[_decoded_hit_dict(h) for h in _evidence_for(report, "obfuscation.xor_observation")],
        compressed=[_decoded_hit_dict(h) for h in _evidence_for(report, "obfuscation.compressed_observation")],
        hidden_pe=[_decoded_hit_dict(h) for h in report.evidence.pe_hits],
        hidden_shellcode=[_decoded_hit_dict(h) for h in report.evidence.shellcode_hits],
    )

    return HunterRecord(
        hunter="obfuscation", status=report.status, score=report.score, max_score=report.max_score,
        verdict_level=report.verdict_level, confidence=report.confidence,
        lead_count=report.lead_count, review_priority=report.review_priority,
        coverage=project_coverage_report(report.coverage),
        findings=[f.to_dict() for f in findings_list], details=details,
    )
