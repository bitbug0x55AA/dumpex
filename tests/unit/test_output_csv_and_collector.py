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

from dumpex.output.envelope import Result
from dumpex.output.csv_export import records_to_rows
from dumpex.output.collector import V2Output


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
