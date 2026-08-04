"""
Unit tests for `dumpex.hunt._hunt_coverage_report()` -- the single,
document-level `CommandResult.coverage` for `--hunt`.

`status` (DETECTED/INCONCLUSIVE/NOT_EVALUATED/NOT_DETECTED_IN_SCANNED_SCOPE)
and `coverage.status` (complete/partial/not_evaluated) are independent
dimensions on every `HunterRecord`: a hunter can be DETECTED from a
finding in one region while ANOTHER region failed to read, or a required
context source was missing -- `status=DETECTED` with
`coverage.status=partial` at the same time. `dumpex.hunt.summary.
build_hunt_summary()`'s own detected_count/inconclusive_count/
not_evaluated_count are derived from `status` only, so a DETECTED-with-
partial-coverage record contributes to none of them. These tests pin
that `_hunt_coverage_report()` inspects each record's own `coverage.status`
directly rather than re-deriving the document-level rollup from those
summary counts alone, which would silently under-report "complete" for a
run with a genuine, real evidence gap (see
tests/integration/test_hunt_cli_compat_freeze.py::
test_hunt_injection_detected_full_correlation_cli and
::test_hunt_pipe_detected_cli, whose own FakeMF fixtures independently hit
this exact DETECTED+partial case and therefore exercise this same fix at
the CLI/exit-code layer too).
"""
import dataclasses

from dumpex.hunt import _hunt_coverage_report
from dumpex.hunt.summary import build_hunt_summary
from dumpex.output.coverage import CoverageReport, CoverageStatus

from tests.fixtures.hunt_records import (
    injection_detected, hollowing_detected, stomping_detected, pipe_detected,
    cs_beacon_detected, yara_detected, obfuscation_detected, all_seven_not_evaluated,
    coverage,
)


def _with_coverage(record, status):
    return dataclasses.replace(record, coverage=coverage(status))


def test_single_hunter_detected_with_partial_coverage_is_partial():
    record = _with_coverage(injection_detected(), CoverageStatus.PARTIAL)
    summary = build_hunt_summary([record], selected="injection")

    assert summary["overall_status"] == "DETECTED"
    assert summary["inconclusive_count"] == 0
    assert summary["not_evaluated_count"] == 0

    result = _hunt_coverage_report([record], summary)
    assert result.status == CoverageStatus.PARTIAL


def test_single_hunter_detected_with_complete_coverage_is_complete():
    record = _with_coverage(injection_detected(), CoverageStatus.COMPLETE)
    summary = build_hunt_summary([record], selected="injection")

    result = _hunt_coverage_report([record], summary)
    assert result.status == CoverageStatus.COMPLETE


def test_hunt_all_one_detected_with_partial_coverage_rest_complete_is_partial():
    """One hunter is DETECTED with a real coverage gap; the other six are
    all fully complete (clean/detected, doesn't matter) -- the
    document-level rollup must still be "partial", not "complete", even
    though summary.overall_status is "DETECTED" and neither
    inconclusive_count nor not_evaluated_count is nonzero."""
    records = [
        _with_coverage(injection_detected(), CoverageStatus.PARTIAL),
        hollowing_detected(),
        stomping_detected(),
        pipe_detected(),
        cs_beacon_detected(),
        yara_detected(),
        obfuscation_detected(),
    ]
    summary = build_hunt_summary(records, selected="all")

    assert summary["overall_status"] == "DETECTED"
    assert summary["inconclusive_count"] == 0
    assert summary["not_evaluated_count"] == 0

    result = _hunt_coverage_report(records, summary)
    assert result.status == CoverageStatus.PARTIAL


def test_hunt_all_every_record_complete_is_complete():
    records = [
        injection_detected(), hollowing_detected(), stomping_detected(), pipe_detected(),
        cs_beacon_detected(), yara_detected(), obfuscation_detected(),
    ]
    summary = build_hunt_summary(records, selected="all")

    result = _hunt_coverage_report(records, summary)
    assert result.status == CoverageStatus.COMPLETE


def test_hunt_all_not_evaluated_is_not_evaluated_even_with_partial_records():
    """NOT_EVALUATED takes priority: when every hunter is NOT_EVALUATED,
    the document-level rollup is "not_evaluated" regardless of what any
    individual (synthetically mutated) record's own coverage.status
    claims -- summary.overall_status short-circuits before per-record
    coverage is ever consulted."""
    records = all_seven_not_evaluated()
    summary = build_hunt_summary(records, selected="all")
    assert summary["overall_status"] == "NOT_EVALUATED"

    result = _hunt_coverage_report(records, summary)
    assert result.status == CoverageStatus.NOT_EVALUATED
