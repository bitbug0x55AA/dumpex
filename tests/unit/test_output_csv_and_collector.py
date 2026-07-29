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

    rows = list(csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8"))))
    assert len(rows) == 2
    assert rows[0]["name"] == "a.dll"


def test_write_csv_directory_mode_creates_one_file(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    out = V2Output(str(dump_path), command="modules", options={})
    out.set_result("modules", _fake_records(), "complete")

    out.write_csv(str(out_dir) + "/", cmd_label="modules")

    csv_files = list(out_dir.glob("*.csv"))
    assert len(csv_files) == 1
    rows = list(csv.DictReader(io.StringIO(csv_files[0].read_text(encoding="utf-8"))))
    assert len(rows) == 2


def test_write_csv_with_no_records_does_not_crash(tmp_path, capsys):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    out.set_result("modules", [], "complete")

    out.write_csv(str(tmp_path / "out") + "/", cmd_label="modules")
    assert "no rows to write" in capsys.readouterr().out


class _FakeRecord:
    def __init__(self, name):
        self._name = name

    def to_dict(self):
        return {"name": self._name}


def _fake_records():
    return [_FakeRecord("a.dll"), _FakeRecord("b.dll")]
