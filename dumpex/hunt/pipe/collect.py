"""
`collect_pipe_record()` -- the v2.4 migration's (PR2b) `HunterRecord`-
producing entry point for the pipe hunter, alongside the console-oriented
`_hunt_pipe()` in `dumpex/hunt/pipe/__init__.py`. Both call the exact
same `_build_pipe_report()` pipeline, so this module only RESHAPES the
resulting `aggregate.Report` into a `HunterRecord` -- it never
recomputes score, status, verdict, or coverage itself.

Every one of `handle_pipes`/`framework_pipes` (raw HANDLE records),
`private_pipes`/`c2_context` (raw region + raw bytes `context` field),
and `unbacked_in_rgn` (raw ThreadInfo+region tuples) embeds at least one
non-JSON-safe object today -- confirmed against the running code, not
merely inferred from docs/hunt_migration_field_matrix.md (whose own
pipe section flagged the handle/region defects but not `c2_context`'s
second, distinct raw-bytes `context` field). All are converted here.
"""
from dumpex.core.memory import prot_str
from dumpex.hunt.pipe import _build_pipe_report
from dumpex.output.records import HunterRecord, PipeDetails, hex_address


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


def _handle_dict(h) -> dict:
    return {
        "handle": hex_address(h.Handle),
        "type_name": h.TypeName,
        "object_name": h.ObjectName,
        # GrantedAccess is an access-mask BITFIELD, not an address/pointer/
        # handle -- stays a plain JSON integer per this project's own
        # hex-formatting rule (only addresses/pointers/handles get the
        # fixed 16-hex-digit treatment).
        "granted_access": h.GrantedAccess,
    }


def _framework_match_dict(match) -> "dict | None":
    if match is None:
        return None
    fw, technique, mitre = match
    return {"framework": fw, "technique": technique, "mitre": mitre}


def _handle_classified_dict(hc: dict) -> dict:
    return {
        "handle": _handle_dict(hc["handle"]),
        "canonical_name": hc["canonical_name"],
        "framework_match": _framework_match_dict(hc["framework_match"]),
    }


def _private_pipe_dict(hit: dict) -> dict:
    return {
        "region": _region_dict(hit["region"]),
        "offset": hit["offset"],
        "name": hit["name"],
        "sha256": hit["sha256"],
        "original_length": hit["original_length"],
        "truncated": hit["truncated"],
        "encoding": hit["encoding"],
    }


def _c2_record_dict(rec: dict) -> dict:
    return {
        "match": rec["match"],
        "context": rec["context"].hex(),
        "va": hex_address(rec["va"]),
        "sha256": rec["sha256"],
        "original_length": rec["original_length"],
    }


def _c2_hit_dict(hit) -> dict:
    region, name, records = hit
    return {
        "region": _region_dict(region),
        "name": name,
        "records": [_c2_record_dict(r) for r in records],
    }


def _unbacked_in_rgn_dict(pair) -> dict:
    ti, region = pair
    return {
        "thread": {"tid": ti.ThreadId, "start_address": hex_address(ti.StartAddress)},
        "region": _region_dict(region),
    }


def _record_from_pipe_report(report) -> HunterRecord:
    """Pure `aggregate.Report` -> `HunterRecord` conversion -- no
    scanning, no printing. The ONE place both `collect_pipe_record()`
    (below) and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4
    orchestrator, PR4) build the typed record from an ALREADY-BUILT
    Report, so a single `_build_pipe_report()` call can feed both the
    console renderer and this conversion without scanning twice."""
    f = report.findings

    details = PipeDetails(
        handle_pipes=[_handle_classified_dict(hc) for hc in f["handle_pipes"]],
        private_pipes=[_private_pipe_dict(hit) for hit in f["private_pipes"]],
        c2_context=[_c2_hit_dict(hit) for hit in f["c2_context"]],
        framework_pipes=[_handle_classified_dict(hc) for hc in f["framework_pipes"]],
        unbacked_in_rgn=[_unbacked_in_rgn_dict(pair) for pair in f["unbacked_in_rgn"]],
    )

    return HunterRecord(
        hunter="pipe", status=f["status"], score=f["score"], max_score=f["max_score"],
        verdict_level=f["verdict_level"], confidence=f["confidence"],
        lead_count=f["lead_count"], review_priority=f["review_priority"],
        coverage=report.coverage_report, findings=f["findings"], details=details,
    )


def collect_pipe_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="pipe"`) for `mf` -- the v2.4
    equivalent of `_hunt_pipe()`'s v1.1 dict, sharing the exact same
    underlying `Report`. Thin compat wrapper: builds a fresh Report and
    converts it -- `collect_hunt()` calls `_build_pipe_report()` and
    `_record_from_pipe_report()` directly instead, so it never scans
    twice just to also get console output from the same run."""
    return _record_from_pipe_report(_build_pipe_report(mf))
