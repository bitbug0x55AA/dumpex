"""Unit tests for dumpex.output.command_result.CommandResult -- the
generic per-command return type replacing the ad hoc positional tuple
every recon command used to return."""
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_COMPLETE
from dumpex.output.envelope import EXECUTION_COMPLETED


def test_command_result_defaults():
    result = CommandResult(kind="modules", records=[],
                            coverage=CoverageReport(status=COVERAGE_COMPLETE))
    assert result.kind == "modules"
    assert result.records == []
    assert result.execution_status == EXECUTION_COMPLETED
    assert result.summary == {}
    assert result.diagnostics == []
    assert result.artifacts == []


def test_command_result_holds_arbitrary_record_type():
    class FakeRecord:
        pass

    records = [FakeRecord(), FakeRecord()]
    result = CommandResult(kind="modules", records=records,
                            coverage=CoverageReport(status=COVERAGE_COMPLETE),
                            summary={"count": 2})
    assert result.records is records
    assert result.summary == {"count": 2}


def test_command_result_mutable_defaults_are_not_shared_between_instances():
    r1 = CommandResult(kind="a", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE))
    r2 = CommandResult(kind="b", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE))
    r1.diagnostics.append("x")
    assert r2.diagnostics == []
