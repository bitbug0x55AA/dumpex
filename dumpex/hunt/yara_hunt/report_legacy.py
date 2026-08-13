"""`domain.YaraReport` -> the v1.1 legacy `findings` dict -- a pure
projection, independent of `report_record.py`/`report_console.py`. Mirrors
`dumpex.hunt.cs_beacon.report_legacy` (and, through it, the other completed
reference pilots).

The dict's KEY SET and `matches[*]` shape are unchanged by this migration
(issue #11's "Compatibility" section) -- `seg_va`/`va` (real process
addresses) stay plain JSON ints in this v1.1 shape (unlike the v2.4
`HunterRecord` shape, which hex-encodes them -- see `report_facts.
match_dict`'s own `hex_va` parameter), `seg_fo`/`fo` (.dmp byte offsets,
never addresses) stay plain ints either way, and `strings[*].data` becomes
a hex string HERE, once, as part of building the legacy dict itself -- the
CLI dispatcher's own post-render bytes->hex pass
(`dumpex/hunt/__init__.py`) is now redundant, the same way issue #9 made
the CS-beacon-equivalent pass redundant.
"""
from dumpex.hunt.yara_hunt.domain import YaraReport
from dumpex.hunt.yara_hunt.report_facts import legacy_coverage_dict, match_dict


def project_legacy_dict(report: YaraReport) -> dict:
    """The v1.1 findings dict -- the same shape `_hunt_yara()` has always
    returned, built purely from `report.evidence`/`report.coverage`/
    derived properties."""
    result = {
        "matches": [match_dict(m, hex_va=False) for m in report.evidence.matches],
        "score": report.score,
        "status": report.status,
        "coverage_status": report.coverage_status,
        "verdict_level": report.verdict_level,
    }
    if report.coverage.evaluated:
        result["coverage"] = legacy_coverage_dict(report)
        result["scan_complete"] = report.scan_complete
    if report.has_hits:
        result["rules_hit"] = list(report.triggered_rules)
    return result
