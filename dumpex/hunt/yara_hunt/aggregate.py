"""The ONE place a `domain.YaraReport` gets constructed for the YARA
hunter.

Nothing here prints; nothing here scans. This module only turns an
already-completed `scanner.ScanResult` plus `domain.RulesDiagnostics` into
the immutable `domain.YaraReport` -- score/status/coverage_status/
verdict_level are all DERIVED properties on that Report itself (see
domain.py's own docstring), so there is nothing left to compute here beyond
assembling the two typed inputs into the two nested snapshots the Report
requires. YARA deliberately does not build `dumpex.hunt._domain.
CheckResult`s (see domain.py's own docstring on why) -- this is the whole
aggregate layer for this hunter.
"""
from dumpex.hunt.yara_hunt.domain import CoverageSnapshot, RulesDiagnostics, YaraEvidence, YaraReport
from dumpex.hunt.yara_hunt.scanner import ScanResult


def build_not_evaluated_report(rules: RulesDiagnostics) -> YaraReport:
    """The ONE place every "prerequisite missing" early return (no
    yara-python, no rules directory, no usable rule files, no memory
    segments) builds its Report -- which of the four applies is fully
    determined by `rules` itself (see `domain.RulesDiagnostics`'s own
    docstring), so there is no separate reason/render_kind argument here."""
    return YaraReport(coverage=CoverageSnapshot(rules=rules))


def build_report(scan_result: ScanResult, rules: RulesDiagnostics) -> YaraReport:
    """Turn a completed scan (`scan_result` from `scanner.scan_segments()`)
    into the final `YaraReport`."""
    coverage = CoverageSnapshot(rules=rules, scan=scan_result.diagnostics)
    evidence = YaraEvidence(matches=scan_result.matches)
    return YaraReport(coverage=coverage, evidence=evidence)
