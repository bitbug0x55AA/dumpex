"""
`collect_yara_record()` -- the v2.4 migration's (PR2b) `HunterRecord`-
producing entry point for the yara hunter, alongside the console-
oriented `_hunt_yara()` in `dumpex/hunt/yara_hunt/__init__.py`. Both call
the exact same `_build_yara_report()` pipeline, so this module only
RESHAPES the resulting `aggregate.Report` into a `HunterRecord` -- it
never recomputes score, status, verdict, or coverage itself.

yara stays off the shared `Finding` model (see
`dumpex.output.records.YaraDetails`'s own docstring) -- `matches`/
`rules_hit` are its own typed shape. `matches[*].strings[*].data` is
ALSO sanitized at the CLI dispatcher layer (`dumpex/hunt/__init__.py`'s
bytes->hex block) -- that hand-rolled version was not deleted; it still
runs, unchanged, for `cmd_hunt()`'s console-rendering `results` dict and
any other non-v2 caller. This module's own, independent conversion is
what feeds `--hunt`'s v2.4 `--json`/`--csv` output specifically (see
docs/hunt_migration_field_matrix.md's cross-cutting finding #2 update).
`seg_va`/`va` (real process addresses) become hex strings; `seg_fo`/
`fo` (.dmp byte offsets, not addresses) stay plain JSON integers.
"""
from dumpex.hunt.yara_hunt import _build_yara_report
from dumpex.output.records import HunterRecord, YaraDetails, hex_address


def _string_hit_dict(sv: dict) -> dict:
    data = sv.get("data")
    return {
        "var": sv.get("var"),
        "offset": sv.get("offset"),
        "va": hex_address(sv.get("va")),
        "fo": sv.get("fo"),
        "data": data.hex() if isinstance(data, bytes) else data,
    }


def _match_dict(hit: dict) -> dict:
    out = dict(hit)
    out["seg_va"] = hex_address(hit.get("seg_va"))
    out["strings"] = [_string_hit_dict(sv) for sv in hit.get("strings", [])]
    return out


def _record_from_yara_report(report) -> HunterRecord:
    """Pure `aggregate.Report` -> `HunterRecord` conversion -- no
    scanning, no printing. The ONE place both `collect_yara_record()`
    (below) and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4
    orchestrator, PR4) build the typed record from an ALREADY-BUILT
    Report, so a single `_build_yara_report()` call can feed both the
    console renderer and this conversion without scanning twice.
    `max_score`/`confidence`/`lead_count`/`review_priority` are always
    `None` and `findings` is always `[]` for this hunter (see
    `HunterRecord`'s own yara-only-null rule)."""
    f = report.findings

    details = YaraDetails(
        matches=[_match_dict(hit) for hit in f["matches"]],
        rules_hit=list(f.get("rules_hit", [])),
    )

    return HunterRecord(
        hunter="yara", status=f["status"], score=f["score"], max_score=None,
        verdict_level=f["verdict_level"], confidence=None, lead_count=None,
        review_priority=None, coverage=report.coverage_report, findings=[], details=details,
    )


def collect_yara_record(mf, rules_dir: str = None) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="yara"`) for `mf` -- the v2.4
    equivalent of `_hunt_yara()`'s v1.1 dict, sharing the exact same
    underlying `Report`. Thin compat wrapper: builds a fresh Report and
    converts it -- `collect_hunt()` calls `_build_yara_report()` and
    `_record_from_yara_report()` directly instead, so it never scans
    twice just to also get console output from the same run."""
    return _record_from_yara_report(_build_yara_report(mf, rules_dir=rules_dir))
