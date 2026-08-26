"""Project an ``EncodingReport`` into the legacy v1.1 findings shape."""
from dumpex.hunt.encoding.domain import EncodingReport
from dumpex.hunt.encoding.report_facts import finding_from_check_result, project_coverage_v1


def _region_dict(region) -> dict:
    """JSON-safe description of a region BY VALUE -- `state`/`protect`/
    `type` are already `prot_str()`-resolved strings on `RegionRef` (see
    models.py), so unlike the pre-migration `_region_to_dict` this needs
    no help from `dumpex.ui.structured._json_safe()` to reduce an
    enum-like value to its `.name`."""
    return {
        "BaseAddress": region.base_address,
        "AllocationBase": region.allocation_base,
        "RegionSize": region.size,
        "State": region.state,
        "Protect": region.protect,
        "Type": region.type,
    }


def _pe_info_dict(pe) -> "dict | None":
    if pe is None:
        return None
    return {
        "valid": pe.valid, "has_mz": pe.has_mz, "has_pe_sig": pe.has_pe_sig,
        "e_lfanew": pe.e_lfanew, "machine": pe.machine, "machine_name": pe.machine_name,
        "time_date_stamp": pe.time_date_stamp, "is_pe32_plus": pe.is_pe32_plus,
        "number_of_sections": pe.number_of_sections, "size_of_image": pe.size_of_image,
        "address_of_entry_point": pe.address_of_entry_point, "image_base": pe.image_base,
        "sections": [
            {"name": s.name, "virtual_address": s.virtual_address, "virtual_size": s.virtual_size,
             "pointer_to_raw_data": s.pointer_to_raw_data, "size_of_raw_data": s.size_of_raw_data,
             "characteristics": s.characteristics, "is_executable": s.is_executable,
             "is_writable": s.is_writable, "is_readable": s.is_readable}
            for s in pe.sections],
        "data_directories": [list(d) for d in pe.data_directories],
        "reason": pe.reason,
    }


def _classification_dict(classification) -> dict:
    d = {
        "type": classification.kind,
        "is_pe": classification.is_pe,
        "is_shellcode": classification.is_shellcode,
        "ioc_strings": list(classification.ioc_strings),
        "hex_prefix": classification.hex_prefix,
        "entropy": classification.entropy,
    }
    if classification.pe_info is not None:
        d["pe_info"] = _pe_info_dict(classification.pe_info)
    return d


def _decoded_hit_dict(h) -> dict:
    """Matches the pre-migration `Hit.to_dict()` shape exactly -- bytes
    fields (`decoded`/`raw`/sleep-mask `key`) stay raw `bytes` here and
    get hex-encoded by `dumpex.ui.structured._json_safe()` at actual
    `--json` serialization time, same as every other hunter's raw bytes
    fields."""
    return {
        "layer": h.layer,
        "region": _region_dict(h.region),
        "offset": h.location.region_offset,
        "decoded": h.decoded,
        "cls": _classification_dict(h.classification),
        "complete": h.complete,
        "raw": h.raw,
        "key": h.key,
        "key_offset": h.key_offset,
    }


def _entropy_hit_dict(h) -> dict:
    return {"region": _region_dict(h.region), "entropy": h.entropy, "threshold": h.threshold}


def _evidence_for(report: EncodingReport, check: str) -> tuple:
    for result in report.results:
        if result.check == check:
            return result.evidence
    return ()


def project_legacy_dict(report: EncodingReport) -> dict:
    """The v1.1 findings dict -- the same shape `_hunt_encoding()` has
    always returned, built purely from `report.evidence`/`report.results`/
    `report.coverage`/derived properties."""
    _, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    return {
        "sleep_mask":       [_decoded_hit_dict(h) for h in report.evidence.sleep_mask_hits],
        "entropy":          [_entropy_hit_dict(h) for h in report.evidence.entropy_hits],
        "base64":           [_decoded_hit_dict(h) for h in _evidence_for(report, "obfuscation.base64_observation")],
        "xor":              [_decoded_hit_dict(h) for h in _evidence_for(report, "obfuscation.xor_observation")],
        "compressed":       [_decoded_hit_dict(h) for h in _evidence_for(report, "obfuscation.compressed_observation")],
        "hidden_pe":        [_decoded_hit_dict(h) for h in report.evidence.pe_hits],
        "hidden_shellcode": [_decoded_hit_dict(h) for h in report.evidence.shellcode_hits],
        "score": report.score,
        "max_score": report.max_score,
        "status": report.status,
        "coverage_status": coverage_status,
        "coverage_reasons": coverage_reasons,
        "verdict_level": report.verdict_level,
        "confidence": report.confidence,
        "findings": [f.to_dict() for f in findings_list],
        "lead_count": report.lead_count,
        "review_priority": report.review_priority,
        "budget_exhausted": report.coverage.budget_exhausted,
    }
