"""Unit tests for dumpex.output.command_result.CommandResult -- the
generic per-command return type replacing the ad hoc positional tuple
every recon command used to return."""
import inspect

import dumpex.output.command_result as command_result_mod
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_COMPLETE, EXECUTION_COMPLETED


def test_command_result_module_does_not_import_envelope_or_hunt():
    # Regression guard for the P2 layering fix: this is a command/domain
    # model and must not depend on the wire-format layer (envelope.py) or
    # detection logic (dumpex.hunt.*) -- only on dumpex.output.coverage.
    # Checked against actual import statements, not the whole source text,
    # since the module's own docstring mentions envelope.py in prose.
    import_lines = [line.strip() for line in inspect.getsource(command_result_mod).splitlines()
                    if line.strip().startswith(("import ", "from "))]
    assert not any("dumpex.output.envelope" in line for line in import_lines)
    assert not any("dumpex.hunt" in line for line in import_lines)


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
