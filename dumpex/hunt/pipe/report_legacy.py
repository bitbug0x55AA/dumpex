"""Project a ``PipeReport`` into the legacy v1.1 findings shape.

Evidence is rebuilt from typed values so serialized output cannot expose
analysis-host object identities. ``c2_context`` and ``unbacked_in_rgn``
remain positional tuples because v1.1 consumers index them by position.
"""
from dumpex.hunt.pipe.domain import PipeReport
from dumpex.hunt.pipe.report_facts import finding_from_check_result, project_coverage_v1


def _region_dict(region) -> dict:
    """JSON-safe description of a region BY VALUE, under the raw
    MemoryInfo attribute names the embedded object exposed -- `state`/
    `protect`/`type` are already `prot_str()`-resolved strings on
    `RegionRef` (see models.py), so nothing here needs
    `dumpex.ui.structured._json_safe()` to reduce an enum-like value to
    its `.name`."""
    return {
        "BaseAddress": region.base_address,
        "AllocationBase": region.allocation_base,
        "RegionSize": region.size,
        "State": region.state,
        "Protect": region.protect,
        "Type": region.type,
    }


def _handle_dict(handle) -> dict:
    """The four facts HandleDataStream recorded, under the raw
    `MinidumpHandleDescriptor` attribute names the embedded object
    exposed. `GrantedAccess` is an access-mask BITFIELD, not an address,
    so it stays a plain int here exactly as it always has."""
    return {
        "Handle": handle.handle,
        "TypeName": handle.type_name,
        "ObjectName": handle.object_name,
        "GrantedAccess": handle.granted_access,
    }


def _handle_pipe_dict(ev) -> dict:
    """`framework_match` stays the `(framework, technique, mitre)` 3-TUPLE
    v1.1 has always carried (see
    tests/integration/test_hunt_compat_freeze.py, which compares it
    against a literal tuple), rebuilt from the typed
    `FrameworkAttribution` rather than stored twice."""
    return {
        "handle": _handle_dict(ev.handle),
        "canonical_name": ev.canonical_name,
        "framework_match": ev.framework.as_tuple() if ev.framework is not None else None,
    }


def _string_lead_dict(ev) -> dict:
    return {
        "region": _region_dict(ev.region),
        "offset": ev.offset,
        "name": ev.name,
        "sha256": ev.sha256,
        "original_length": ev.original_length,
        "truncated": ev.truncated,
        "encoding": ev.encoding,
    }


def _c2_record_dict(rec) -> dict:
    """`context` stays raw `bytes` here (as it always has in v1.1) --
    `dumpex.ui.structured._json_safe` hex-encodes it on the way out. The
    typed record's own `context` is `bytes`, never `bytearray`, so no
    caller can edit what this hands back."""
    return {
        "match": rec.match,
        "context": rec.context,
        "va": rec.va,
        "sha256": rec.sha256,
        "original_length": rec.original_length,
    }


def _c2_context_tuple(ev) -> tuple:
    return (_region_dict(ev.region), ev.pipe_name, [_c2_record_dict(r) for r in ev.records])


def _unbacked_thread_tuple(ev) -> tuple:
    return ({"ThreadId": ev.thread.thread_id, "StartAddress": ev.thread.start_address},
            _region_dict(ev.region))


def project_legacy_dict(report: PipeReport) -> dict:
    """The v1.1 findings dict -- the same shape `_hunt_pipe()` has always
    returned, built purely from `report.evidence`/`report.results`/
    `report.coverage`/derived properties."""
    coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    findings_list = [finding_from_check_result(r, report) for r in report.results]
    evidence = report.evidence

    return {
        "handle_pipes":    [_handle_pipe_dict(ev) for ev in evidence.handle_pipes],
        "private_pipes":   [_string_lead_dict(ev) for ev in evidence.string_leads],
        "c2_context":      [_c2_context_tuple(ev) for ev in evidence.c2_context],
        "framework_pipes": [_handle_pipe_dict(ev) for ev in evidence.framework_handles],
        "unbacked_in_rgn": [_unbacked_thread_tuple(ev) for ev in evidence.unbacked_threads],
        "score": report.score,
        "max_score": report.max_score,
        "budget_exhausted": report.coverage.budget_exhausted,
        "scan_complete": report.coverage.region_scan_complete,
        "findings": [f.to_dict() for f in findings_list],
        "coverage_status": coverage_status,
        "coverage_reasons": coverage_reasons,
        "status": report.status,
        "verdict_level": report.verdict_level,
        "confidence": report.confidence,
        "lead_count": report.lead_count,
        "review_priority": report.review_priority,
    }
