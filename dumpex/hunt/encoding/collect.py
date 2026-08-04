"""
`collect_obfuscation_record()` -- the v2.4 migration's (PR2b)
`HunterRecord`-producing entry point for the obfuscation hunter,
alongside the console-oriented `_hunt_encoding()` in
`dumpex/hunt/encoding/__init__.py`. Both call the exact same
`_build_encoding_report()` pipeline, so this module only RESHAPES the
resulting `EncodingReport`'s `findings` dict into a `HunterRecord` -- it
never recomputes score, status, verdict, or coverage itself.

`Hit.to_dict()`/`EntropyHit.to_dict()` (dumpex/hunt/encoding/models.py)
already convert region-by-reference into region-by-value, but
deliberately leave two things for a downstream pass: the region's own
State/Protect/Type stay as whatever enum-like object the caller passed
(relying on dumpex.ui.structured._json_safe()'s `.name` reduction at
serialize time), and `decoded`/`raw`/`key` stay raw `bytes` (relying on
that same `_json_safe()` for hex-encoding). This module finishes both
conversions itself so `ObfuscationDetails.to_dict()` needs no
`_json_safe()` help at all, per docs/hunt_migration_field_matrix.md's
own obfuscation section.
"""
from dumpex.core.memory import prot_str
from dumpex.hunt.encoding import _build_encoding_report
from dumpex.output.records import HunterRecord, ObfuscationDetails, hex_address


def _region_dict(region: "dict | None") -> "dict | None":
    if region is None:
        return None
    return {
        "base_address": hex_address(region["BaseAddress"]),
        "allocation_base": hex_address(region["AllocationBase"]),
        "size": region["RegionSize"],
        "state": prot_str(region["State"]),
        "protect": prot_str(region["Protect"]),
        "type": prot_str(region["Type"]),
    }


def _bytes_to_hex(value):
    return value.hex() if isinstance(value, bytes) else value


def _hit_dict(hit: dict) -> dict:
    return {
        "layer": hit["layer"],
        "region": _region_dict(hit["region"]),
        "offset": hit["offset"],
        "decoded": _bytes_to_hex(hit["decoded"]),
        "cls": hit["cls"],
        "complete": hit["complete"],
        "raw": _bytes_to_hex(hit["raw"]),
        "key": _bytes_to_hex(hit["key"]),
        "key_offset": hit["key_offset"],
    }


def _entropy_hit_dict(hit: dict) -> dict:
    return {
        "region": _region_dict(hit["region"]),
        "entropy": hit["entropy"],
        "threshold": hit["threshold"],
    }


def _record_from_encoding_report(report) -> HunterRecord:
    """Pure `EncodingReport` -> `HunterRecord` conversion -- no scanning,
    no printing. The ONE place both `collect_obfuscation_record()`
    (below) and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4
    orchestrator, PR4) build the typed record from an ALREADY-BUILT
    Report, so a single `_build_encoding_report()` call can feed both
    the console renderer and this conversion without scanning twice."""
    f = report.findings

    details = ObfuscationDetails(
        sleep_mask=[_hit_dict(h) for h in f["sleep_mask"]],
        entropy=[_entropy_hit_dict(h) for h in f["entropy"]],
        base64=[_hit_dict(h) for h in f["base64"]],
        xor=[_hit_dict(h) for h in f["xor"]],
        compressed=[_hit_dict(h) for h in f["compressed"]],
        hidden_pe=[_hit_dict(h) for h in f["hidden_pe"]],
        hidden_shellcode=[_hit_dict(h) for h in f["hidden_shellcode"]],
    )

    return HunterRecord(
        hunter="obfuscation", status=f["status"], score=f["score"], max_score=f["max_score"],
        verdict_level=f["verdict_level"], confidence=f["confidence"],
        lead_count=f["lead_count"], review_priority=f["review_priority"],
        coverage=report.coverage_report, findings=f["findings"], details=details,
    )


def collect_obfuscation_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="obfuscation"`) for `mf` -- the
    v2.4 equivalent of `_hunt_encoding()`'s v1.1 dict, sharing the exact
    same underlying `EncodingReport`. Thin compat wrapper: builds a fresh
    Report and converts it -- `collect_hunt()` calls
    `_build_encoding_report()` and `_record_from_encoding_report()`
    directly instead, so it never scans twice just to also get console
    output from the same run."""
    return _record_from_encoding_report(_build_encoding_report(mf, verbose=False))
