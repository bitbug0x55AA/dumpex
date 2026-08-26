"""Shared behavioral contracts for hunter record projectors."""

import pytest

from dumpex.output.coverage import (
    EXIT_NOT_EVALUATED,
    EXIT_OK,
    EXIT_PARTIAL,
    exit_code_for,
)
from tests.hunt import (
    test_encoding_projectors as encoding,
    test_hollowing_projectors as hollowing,
    test_injection_projectors as injection,
    test_pipe_projectors as pipe,
    test_stomping_projectors as stomping,
)


_HUNTERS = (
    ("obfuscation", encoding.project_hunter_record, encoding._clean_report,
     encoding._inconclusive_report, encoding._not_evaluated_report),
    ("hollowing", hollowing.project_hunter_record, hollowing._clean_report,
     hollowing._partial_report, hollowing._not_evaluated_report),
    ("injection", injection.project_hunter_record, injection._clean_report,
     injection._inconclusive_report, injection._not_evaluated_report),
    ("pipe", pipe.project_hunter_record, pipe._clean_report,
     pipe._inconclusive_report, pipe._not_evaluated_report),
    ("stomping", stomping.project_hunter_record, stomping._clean_report,
     stomping._inconclusive_report, stomping._not_evaluated_report),
)

_CASES = tuple(
    pytest.param(projector, report_factory, status, expected_exit, id=f"{hunter}-{status}")
    for hunter, projector, clean, partial, not_evaluated in _HUNTERS
    for report_factory, status, expected_exit in (
        (clean, "complete", EXIT_OK),
        (partial, "partial", EXIT_PARTIAL),
        (not_evaluated, "not_evaluated", EXIT_NOT_EVALUATED),
    )
)


@pytest.mark.parametrize("projector,report_factory,status,expected_exit", _CASES)
def test_projected_coverage_status_drives_the_shared_exit_code(
        projector, report_factory, status, expected_exit):
    coverage_status = projector(report_factory()).coverage.status
    assert coverage_status.value == status
    assert exit_code_for(coverage_status) == expected_exit
