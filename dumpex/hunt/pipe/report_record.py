"""`PipeReport` -> `HunterRecord` (the current typed record) -- a pure
projection, independent of `report_legacy.py`/`report_console.py`. Mirrors
`dumpex.hunt.stomping.report_record`/`dumpex.hunt.injection.report_record`/
`dumpex.hunt.encoding.report_record` (the three completed reference
pilots): builds the SAME `PipeDetails` shape the pre-migration
`dumpex/hunt/pipe/collect.py` built, directly from the typed evidence
buckets rather than from an already-JSON-shaped `findings` dict -- no
public schema/wire-shape change.

The pre-migration `collect.py` had to convert a live `Handle`, a live
`MinidumpMemoryInfo`, and a live `MinidumpThreadInfo` (all embedded in the
legacy `findings` dict's own entries) into JSON-safe dicts here, calling
`prot_str()` a second time at projection time. All of them are now
resolved once, at scan time (dumpex.hunt.pipe.models), so this module only
reshapes already-typed facts.
"""
from dumpex.hunt.pipe.domain import PipeReport
from dumpex.hunt.pipe.report_facts import finding_from_check_result, project_coverage_report
from dumpex.output.records import HunterRecord, PipeDetails, hex_address


def _region_dict(region) -> dict:
    """No `region is None` guard (unlike the pre-migration `collect.py`'s
    own): every evidence type carrying a region validates it as a real
    `RegionRef` at construction, so None is no longer representable."""
    return {
        "base_address": hex_address(region.base_address),
        "allocation_base": hex_address(region.allocation_base),
        "size": region.size,
        "type": region.type,
        "protect": region.protect,
    }


def _handle_dict(handle) -> dict:
    return {
        "handle": hex_address(handle.handle),
        "type_name": handle.type_name,
        "object_name": handle.object_name,
        # GrantedAccess is an access-mask BITFIELD, not an address/pointer/
        # handle -- stays a plain JSON integer per this project's own
        # hex-formatting rule (only addresses/pointers/handles get the
        # fixed 16-hex-digit treatment).
        "granted_access": handle.granted_access,
    }


def _framework_match_dict(framework) -> "dict | None":
    if framework is None:
        return None
    return {"framework": framework.framework, "technique": framework.technique,
            "mitre": framework.mitre}


def _handle_pipe_dict(ev) -> dict:
    return {
        "handle": _handle_dict(ev.handle),
        "canonical_name": ev.canonical_name,
        "framework_match": _framework_match_dict(ev.framework),
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
    return {
        "match": rec.match,
        "context": rec.context.hex(),
        "va": hex_address(rec.va),
        "sha256": rec.sha256,
        "original_length": rec.original_length,
    }


def _c2_context_dict(ev) -> dict:
    return {
        "region": _region_dict(ev.region),
        "name": ev.pipe_name,
        "records": [_c2_record_dict(r) for r in ev.records],
    }


def _unbacked_thread_dict(ev) -> dict:
    """`start_address` goes through `hex_address`, which returns None for
    a ThreadInfo entry that recorded none -- JSON `null`, never address
    zero (an ordinary, valid address)."""
    return {
        "thread": {"tid": ev.thread.thread_id,
                   "start_address": hex_address(ev.thread.start_address)},
        "region": _region_dict(ev.region),
    }


def project_hunter_record(report: PipeReport) -> HunterRecord:
    """Pure `PipeReport` -> `HunterRecord` conversion -- no scanning, no
    printing."""
    findings_list = [finding_from_check_result(r, report) for r in report.results]
    evidence = report.evidence

    details = PipeDetails(
        handle_pipes=[_handle_pipe_dict(ev) for ev in evidence.handle_pipes],
        private_pipes=[_string_lead_dict(ev) for ev in evidence.string_leads],
        c2_context=[_c2_context_dict(ev) for ev in evidence.c2_context],
        framework_pipes=[_handle_pipe_dict(ev) for ev in evidence.framework_handles],
        unbacked_in_rgn=[_unbacked_thread_dict(ev) for ev in evidence.unbacked_threads],
    )

    return HunterRecord(
        hunter="pipe", status=report.status, score=report.score,
        max_score=report.max_score, verdict_level=report.verdict_level,
        confidence=report.confidence, lead_count=report.lead_count,
        review_priority=report.review_priority,
        coverage=project_coverage_report(report.coverage),
        findings=[f.to_dict() for f in findings_list], details=details,
    )
