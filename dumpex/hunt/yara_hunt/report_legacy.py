"""Project a ``YaraReport`` into the legacy v1.1 findings shape.

Process addresses and dump offsets remain integers in v1.1 output, while
matched string bytes are hex encoded. The key and match shapes are stable.
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
