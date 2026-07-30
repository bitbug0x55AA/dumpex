"""
Unit tests for dumpex.output.csv_export and the CSV-writing half of
dumpex.output.collector.V2Output -- trivial by construction (every v2
record is already a flat dict via to_dict()), but still worth a direct
test since a per-kind branching bug in a hand-rolled CSV path is exactly
the kind of regression the old dumpex/ui/structured.py._section_to_tables
special-casing was prone to.
"""
import csv
import io
import json

from dumpex.output.envelope import Result
from dumpex.output.csv_export import records_to_rows
from dumpex.output.collector import V2Output
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_COMPLETE
from dumpex.output.records import Diagnostic, SEVERITY_WARNING, SEVERITY_ERROR


def test_records_to_rows_returns_the_records_list_verbatim():
    result = Result(kind="modules", execution_status="completed",
                     coverage_status="complete",
                     records=[{"name": "a.dll"}, {"name": "b.dll"}])
    rows = records_to_rows(result)
    assert rows == [{"name": "a.dll"}, {"name": "b.dll"}]


def test_write_csv_single_file_mode(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    out.set_result("modules", _fake_records(), "complete")

    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="modules")

    text = csv_path.read_text(encoding="utf-8")
    assert "## modules / summary" in text
    assert "## modules / records" in text
    records_block = text.split("## modules / records\n", 1)[1]
    rows = list(csv.DictReader(io.StringIO(records_block)))
    assert len(rows) == 2
    assert rows[0]["name"] == "a.dll"


def test_write_csv_directory_mode_creates_one_file_per_table(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    out = V2Output(str(dump_path), command="modules", options={})
    out.set_result("modules", _fake_records(), "complete")

    out.write_csv(str(out_dir) + "/", cmd_label="modules")

    csv_files = {f.name for f in out_dir.glob("*.csv")}
    assert any("summary" in f for f in csv_files)
    assert any("records" in f for f in csv_files)
    records_file = next(f for f in out_dir.glob("*.csv") if "records" in f.name)
    rows = list(csv.DictReader(io.StringIO(records_file.read_text(encoding="utf-8"))))
    assert len(rows) == 2


def test_write_csv_with_no_records_still_writes_a_summary_table(tmp_path, capsys):
    # A genuinely empty result (0 records) must still produce real CSV
    # content -- a directory-mode export writing NO file at all would be
    # indistinguishable from --csv having silently failed.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "out"
    out = V2Output(str(dump_path), command="modules", options={})
    out.set_result("modules", [], "complete")

    out.write_csv(str(out_dir) + "/", cmd_label="modules")

    csv_files = list(out_dir.glob("*.csv"))
    assert len(csv_files) == 1   # only "summary" -- "records" has zero rows, not written
    assert "summary" in csv_files[0].name
    rows = list(csv.DictReader(io.StringIO(csv_files[0].read_text(encoding="utf-8"))))
    assert rows == [{"kind": "modules", "execution_status": "completed",
                      "coverage_status": "complete", "coverage_reasons": "", "count": "0"}]


def test_list_typed_field_becomes_json_cell_not_python_repr(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="threads", options={})
    out.set_result("threads", [_FakeThreadRecord(["EXITED"])], "complete")

    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="threads")
    text = csv_path.read_text(encoding="utf-8")

    assert "['EXITED']" not in text   # never Python repr()
    records_block = text.split("## threads / records\n", 1)[1]
    rows = list(csv.DictReader(io.StringIO(records_block)))
    import json
    assert json.loads(rows[0]["flags"]) == ["EXITED"]


def test_peb_environment_variables_broken_out_into_own_table(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "out"
    out = V2Output(str(dump_path), command="peb", options={})
    out.set_result("peb", [_FakePebRecord([{"name": "PATH", "value": "C:\\Windows"}])], "complete")

    out.write_csv(str(out_dir) + "/", cmd_label="peb")

    csv_files = {f.name for f in out_dir.glob("*.csv")}
    assert any("environment_variables" in f for f in csv_files)
    records_file = next(f for f in out_dir.glob("*.csv") if f.name.endswith("_records.csv"))
    rows = list(csv.DictReader(io.StringIO(records_file.read_text(encoding="utf-8"))))
    assert "environment_variables" not in rows[0]   # broken out, not duplicated in main row


# ── set_command_result: must not drop execution_status/diagnostics/
# artifacts the way routing a CommandResult through set_result() used to
# (P1 review fix) ──────────────────────────────────────────────────────

def test_set_command_result_forwards_execution_status(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    result = CommandResult(kind="modules", records=_fake_records(),
                            coverage=CoverageReport(status=COVERAGE_COMPLETE),
                            execution_status="partial")

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["result"]["execution_status"] == "partial"


def test_set_command_result_forwards_diagnostics_by_severity(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    result = CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        diagnostics=[
            Diagnostic(severity=SEVERITY_WARNING, message="w1"),
            Diagnostic(severity=SEVERITY_ERROR, message="e1"),
        ],
    )

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert [d["message"] for d in doc["diagnostics"]["warnings"]] == ["w1"]
    assert [d["message"] for d in doc["diagnostics"]["errors"]] == ["e1"]


def test_set_command_result_forwards_artifacts(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    result = CommandResult(kind="modules", records=_fake_records(),
                            coverage=CoverageReport(status=COVERAGE_COMPLETE),
                            artifacts=[{"id": "a1", "path": "x.bin"}])

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"] == [{"id": "a1", "path": "x.bin"}]


def test_set_command_result_defaults_match_set_result_for_list_modules_shape(tmp_path):
    # list_cmd.py/modules.py never populate execution_status/diagnostics/
    # artifacts -- confirms routing them through set_command_result()
    # instead of set_result() produces an identical result/artifacts/
    # diagnostics shape (meta.execution timestamps naturally differ
    # between two separate calls, so those are excluded from comparison).
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")

    out_a = V2Output(str(dump_path), command="modules", options={})
    out_a.set_result("modules", _fake_records(), "complete")
    doc_a = json.loads(out_a.to_json())

    out_b = V2Output(str(dump_path), command="modules", options={})
    out_b.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc_b = json.loads(out_b.to_json())

    assert doc_a["result"] == doc_b["result"]
    assert doc_a["artifacts"] == doc_b["artifacts"]
    assert doc_a["diagnostics"] == doc_b["diagnostics"]


class _FakeRecord:
    def __init__(self, name):
        self._name = name

    def to_dict(self):
        return {"name": self._name}


def _fake_records():
    return [_FakeRecord("a.dll"), _FakeRecord("b.dll")]


class _FakeThreadRecord:
    def __init__(self, flags):
        self._flags = flags

    def to_dict(self):
        return {"tid": 1, "flags": self._flags}


class _FakePebRecord:
    def __init__(self, env_vars):
        self._env_vars = env_vars

    def to_dict(self):
        return {"peb_address": None, "environment_variables": self._env_vars}
