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
import os
import json

import pytest

from dumpex.output.envelope import Result, EvidenceInput
from dumpex.output.csv_export import records_to_rows, build_tables
from dumpex.output.collector import V2Output
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_COMPLETE
from dumpex.output.records import Diagnostic, Artifact, SEVERITY_WARNING, SEVERITY_ERROR
from tests.fixtures.fakes import Module, FakeStream, FakeMF, mem_reader
from dumpex.commands.comparison import collect_comparison


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
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(), coverage=CoverageReport(status=COVERAGE_COMPLETE)))

    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="modules")

    raw = csv_path.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n\n")
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
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(), coverage=CoverageReport(status=COVERAGE_COMPLETE)))

    out.write_csv(str(out_dir) + "/", cmd_label="modules")

    csv_files = {f.name for f in out_dir.glob("*.csv")}
    assert any("summary" in f for f in csv_files)
    assert any("records" in f for f in csv_files)
    records_file = next(f for f in out_dir.glob("*.csv") if "records" in f.name)
    assert b"\r" not in records_file.read_bytes()
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
    out.set_command_result(CommandResult(
        kind="modules", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE)))

    out.write_csv(str(out_dir) + "/", cmd_label="modules")

    csv_files = list(out_dir.glob("*.csv"))
    assert len(csv_files) == 1   # only "summary" -- "records" has zero rows, not written
    assert "summary" in csv_files[0].name
    rows = list(csv.DictReader(io.StringIO(csv_files[0].read_text(encoding="utf-8"))))
    assert rows == [{"kind": "modules", "execution_status": "completed",
                      "coverage_status": "complete", "coverage_reasons": "", "count": "0"}]


# ── artifacts / diagnostics CSV tables (P1-2 remediation) ────────────────
# Before this fix, build_tables() only ever consumed `result` -- JSON's
# top-level artifacts[]/diagnostics were completely invisible in CSV, and
# a custom result.summary field (e.g. --strings' shown) was silently
# dropped by summary_rows() too.

def test_build_tables_omits_artifacts_and_diagnostics_tables_when_none_given():
    result = Result(kind="modules", execution_status="completed", coverage_status="complete",
                     records=[{"name": "a.dll"}])
    tables = build_tables(result)
    assert "artifacts" not in tables
    assert "diagnostic_warnings" not in tables
    assert "diagnostic_errors" not in tables


def test_build_tables_includes_artifacts_table_when_present():
    result = Result(kind="extract", execution_status="completed", coverage_status="complete",
                     records=[{"bytes_read": 16}])
    artifact = Artifact(id="extract_output", kind="extracted_region", path="out.bin",
                         size_bytes=16, sha256="abc123", description="Bytes extracted")
    tables = build_tables(result, artifacts=[artifact.to_dict()])
    assert tables["artifacts"] == [{
        "id": "extract_output", "kind": "extracted_region", "path": "out.bin",
        "size_bytes": 16, "sha256": "abc123", "description": "Bytes extracted",
    }]


def test_build_tables_includes_diagnostic_warnings_table_when_present():
    result = Result(kind="extract", execution_status="completed", coverage_status="complete",
                     records=[{"bytes_read": 64}])
    warning = Diagnostic(severity=SEVERITY_WARNING, message="MZ header detected",
                          code="EXTRACT_MZ_HEADER_DETECTED")
    tables = build_tables(result, diagnostic_warnings=[warning.to_dict()])
    assert tables["diagnostic_warnings"] == [{
        "severity": "warning", "message": "MZ header detected",
        "code": "EXTRACT_MZ_HEADER_DETECTED",
    }]
    assert "diagnostic_errors" not in tables


def test_summary_rows_merges_custom_summary_fields():
    result = Result(kind="strings", execution_status="completed", coverage_status="complete",
                     records=[{"text": "a"}, {"text": "b"}], summary={"count": 2, "shown": 1})
    tables = build_tables(result)
    assert tables["summary"][0]["shown"] == 1
    assert tables["summary"][0]["count"] == 2   # fixed field, unaffected by merge


def test_summary_rows_fixed_fields_win_over_a_same_named_custom_field():
    # A future command's result.summary must never be able to shadow a
    # fixed summary field by accident -- kind/execution_status/
    # coverage_status/coverage_reasons/count always come from the real
    # Result attributes, never from summary's own dict.
    result = Result(kind="modules", execution_status="completed", coverage_status="complete",
                     records=[{"name": "a.dll"}], summary={"kind": "SPOOFED", "count": 999})
    tables = build_tables(result)
    assert tables["summary"][0]["kind"] == "modules"
    assert tables["summary"][0]["count"] == 1


def test_write_csv_single_file_includes_artifact_and_diagnostic_tables(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract", options={})

    import dumpex.commands.extract as extract_mod
    mf = FakeMF()
    mf.filename = str(dump_path)
    extract_mod.read_region = mem_reader({0x1000: b"MZ" + b"\x90" * 14})
    result = extract_mod.collect_extract(mf, 0x1000, 16, str(tmp_path / "extracted.bin"),
                                          force=True)
    out.set_command_result(result)

    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="extract")
    text = csv_path.read_text(encoding="utf-8")

    assert "## extract / artifacts" in text
    assert "## extract / diagnostic_warnings" in text
    artifacts_block = text.split("## extract / artifacts\n", 1)[1].split("\n\n", 1)[0]
    rows = list(csv.DictReader(io.StringIO(artifacts_block)))
    assert rows[0]["path"] == str(tmp_path / "extracted.bin")
    assert rows[0]["size_bytes"] == "16"
    import hashlib
    assert rows[0]["sha256"] == hashlib.sha256(b"MZ" + b"\x90" * 14).hexdigest()
    warnings_block = text.split("## extract / diagnostic_warnings\n", 1)[1].split("\n\n", 1)[0]
    warning_rows = list(csv.DictReader(io.StringIO(warnings_block)))
    assert warning_rows[0]["code"] == "EXTRACT_MZ_HEADER_DETECTED"


def test_write_csv_directory_mode_includes_artifact_and_diagnostic_tables(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    out = V2Output(str(dump_path), command="extract", options={})

    import dumpex.commands.extract as extract_mod
    mf = FakeMF()
    mf.filename = str(dump_path)
    extract_mod.read_region = mem_reader({0x1000: b"MZ" + b"\x90" * 14})
    result = extract_mod.collect_extract(mf, 0x1000, 16, str(tmp_path / "extracted2.bin"),
                                          force=True)
    out.set_command_result(result)

    out.write_csv(str(out_dir) + "/", cmd_label="extract")

    csv_files = {f.name: f for f in out_dir.glob("*.csv")}
    assert any("artifacts" in name for name in csv_files)
    assert any("diagnostic_warnings" in name for name in csv_files)
    artifacts_file = next(f for name, f in csv_files.items() if "artifacts" in name)
    rows = list(csv.DictReader(io.StringIO(artifacts_file.read_text(encoding="utf-8"))))
    assert rows[0]["path"] == str(tmp_path / "extracted2.bin")


def test_json_and_csv_agree_on_artifact_facts(tmp_path):
    # The same CommandResult must produce the same artifact facts in both
    # JSON (top-level artifacts[]) and CSV (the 'artifacts' table) --
    # before this fix, only JSON carried this information at all.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract", options={})

    import dumpex.commands.extract as extract_mod
    mf = FakeMF()
    mf.filename = str(dump_path)
    extract_mod.read_region = mem_reader({0x2000: b"plain data, no MZ header"})
    result = extract_mod.collect_extract(mf, 0x2000, 24, str(tmp_path / "extracted3.bin"),
                                          force=True)
    out.set_command_result(result)

    doc = json.loads(out.to_json())
    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="extract")
    text = csv_path.read_text(encoding="utf-8")
    artifacts_block = text.split("## extract / artifacts\n", 1)[1].split("\n\n", 1)[0]
    csv_rows = list(csv.DictReader(io.StringIO(artifacts_block)))

    assert doc["artifacts"][0]["path"] == csv_rows[0]["path"]
    assert str(doc["artifacts"][0]["size_bytes"]) == csv_rows[0]["size_bytes"]
    assert doc["artifacts"][0]["sha256"] == csv_rows[0]["sha256"]


def test_strings_requested_address_reaches_both_json_and_csv_summary(tmp_path):
    # P2 remediation: --strings' summary.requested_address must be
    # visible through both output formats, not just JSON.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="strings", options={})

    import dumpex.commands.extract as extract_mod
    mf = FakeMF()
    mf.filename = str(dump_path)
    extract_mod.read_region = mem_reader({0x1000: b"\x01\x02\x03" * 5})   # no strings found
    result = extract_mod.collect_strings(mf, 0x1000, 15, 6, None, "both")
    out.set_command_result(result)

    doc = json.loads(out.to_json())
    assert doc["result"]["summary"]["requested_address"] == "0x0000000000001000"

    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="strings")
    text = csv_path.read_text(encoding="utf-8")
    summary_block = text.split("## strings / summary\n", 1)[1].split("\n\n", 1)[0]
    csv_rows = list(csv.DictReader(io.StringIO(summary_block)))
    assert csv_rows[0]["requested_address"] == "0x0000000000001000"


def test_list_typed_field_becomes_json_cell_not_python_repr(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="threads", options={})
    out.set_command_result(CommandResult(
        kind="threads", records=[_FakeThreadRecord(["EXITED"])],
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))

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
    out.set_command_result(CommandResult(
        kind="peb", records=[_FakePebRecord([{"name": "PATH", "value": "C:\\Windows"}])],
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))

    out.write_csv(str(out_dir) + "/", cmd_label="peb")

    csv_files = {f.name for f in out_dir.glob("*.csv")}
    assert any("environment_variables" in f for f in csv_files)
    records_file = next(f for f in out_dir.glob("*.csv") if f.name.endswith("_records.csv"))
    rows = list(csv.DictReader(io.StringIO(records_file.read_text(encoding="utf-8"))))
    assert "environment_variables" not in rows[0]   # broken out, not duplicated in main row


# ── comparison-kind CSV table splitting (Phase C, PR2) ───────────────────
# A "comparison" result's records are a tagged union (module/thread/
# memory_region), so the generic "records" table is skipped entirely --
# see csv_export.build_tables' own kind == "comparison" branch.

def _comparison_result():
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, r"C:\a.dll")], "modules")
    mf_target = FakeMF()
    mf_target.modules = FakeStream([Module(0x2000, 0x1000, r"C:\b.dll")], "modules")
    return collect_comparison(mf_baseline, mf_target, mode="modules")


def test_build_tables_comparison_kind_has_no_generic_records_table():
    result = Result(kind="comparison", execution_status="completed", coverage_status="complete",
                     records=[r.to_dict() for r in _comparison_result().records])
    tables = build_tables(result)
    assert "records" not in tables
    assert set(tables) == {"summary", "module_diffs", "thread_diffs", "memory_diffs"}


def test_build_tables_comparison_kind_splits_by_entity_type():
    result = Result(kind="comparison", execution_status="completed", coverage_status="complete",
                     records=[r.to_dict() for r in _comparison_result().records])
    tables = build_tables(result)
    assert len(tables["module_diffs"]) == 2   # a.dll removed from baseline, b.dll added in target
    assert tables["thread_diffs"] == []
    assert tables["memory_diffs"] == []


def test_build_tables_comparison_kind_raises_on_unrecognized_entity_type():
    # A future 4th entity type added to the tagged union without updating
    # build_tables() must fail loudly, not silently vanish from every
    # table while summary.count still reports the true total.
    result = Result(kind="comparison", execution_status="completed", coverage_status="complete",
                     records=[{"entity_type": "some_future_entity", "change_type": "added"}])
    with pytest.raises(ValueError, match="some_future_entity"):
        build_tables(result)


def test_write_csv_directory_mode_comparison_writes_per_entity_files_not_records(tmp_path):
    dump_a = tmp_path / "a.dmp"; dump_a.write_bytes(b"a")
    dump_b = tmp_path / "b.dmp"; dump_b.write_bytes(b"b")
    out_dir = tmp_path / "out"
    out = V2Output.from_evidence(
        [EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
         EvidenceInput(id="target", role="target", path=str(dump_b))],
        command="comparison", options={})
    out.set_command_result(_comparison_result())

    out.write_csv(str(out_dir) + "/", cmd_label="comparison")

    csv_files = {f.name for f in out_dir.glob("*.csv")}
    assert any("module_diffs" in f for f in csv_files)
    assert not any(f.endswith("_records.csv") for f in csv_files)
    module_file = next(f for f in out_dir.glob("*.csv") if "module_diffs" in f.name)
    rows = list(csv.DictReader(io.StringIO(module_file.read_text(encoding="utf-8"))))
    assert len(rows) == 2
    assert {row["change_type"] for row in rows} == {"added", "removed"}


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
    result = CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="a1", kind="extracted_region", path="x.bin")])

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"] == [{"id": "a1", "kind": "extracted_region", "path": "x.bin",
                                  "size_bytes": None, "sha256": None, "description": None}]


def test_set_command_result_protects_artifact_path_from_later_writes(tmp_path, capsys):
    # P1-1 remediation, second line of defense: an artifact this run
    # already wrote (e.g. --extract's own --output file) must become a
    # protected path for a LATER write_json/write_csv call, so a
    # collision (--json pointed at the same path) is refused instead of
    # silently overwriting the artifact -- see safe_io.check_not_dump_path's
    # (path, description) tuple support.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    artifact_path = tmp_path / "extracted.bin"
    artifact_path.write_bytes(b"original artifact bytes")

    out = V2Output(str(dump_path), command="extract", options={})
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region",
                             path=str(artifact_path))])
    out.set_command_result(result)

    with pytest.raises(SystemExit) as exc:
        out.write_json(str(artifact_path), cmd_label="extract")
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "extracted_region" in err
    assert artifact_path.read_bytes() == b"original artifact bytes"   # untouched


def test_set_command_result_then_to_json_redacts_artifact_path_when_requested(tmp_path):
    # P1-3 remediation: artifacts[].path leaked the full absolute path
    # even under --redact-paths -- only meta.evidence.path and
    # meta.execution.options were ever redacted.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract",
                    options={"output": str(tmp_path / "extracted.bin")}, redact_paths=True)
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region",
                             path=str(tmp_path / "extracted.bin"), size_bytes=64,
                             sha256="abc123")])
    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"][0]["path"] == "extracted.bin"
    assert doc["artifacts"][0]["size_bytes"] == 64
    assert doc["artifacts"][0]["sha256"] == "abc123"
    assert doc["meta"]["execution"]["options"]["output"] == "extracted.bin"
    assert str(tmp_path) not in json.dumps(doc)


def test_real_collect_extract_redact_paths_leaves_no_absolute_path_in_json(tmp_path):
    # P1 remediation (round 2): collect_extract()'s own summary used to
    # carry a second, UNREDACTED copy of the output path
    # (summary["output_path"]) -- --redact-paths only ever touched
    # meta.execution.options.output and artifacts[].path, so the full
    # absolute path (and its parent directory) still leaked through
    # result.summary in the JSON text. Uses the REAL collect_extract(),
    # not a hand-built CommandResult, so this exercises the exact
    # producer the bug was in.
    import dumpex.commands.extract as extract_mod
    from tests.fixtures.fakes import mem_reader

    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "case_evidence_dir"
    out_dir.mkdir()
    output_path = str(out_dir / "extracted.bin")

    mf = FakeMF()
    mf.filename = str(dump_path)
    extract_mod.read_region = mem_reader({0x1000: b"hello world"})
    result = extract_mod.collect_extract(mf, 0x1000, 11, output_path, force=True)

    out = V2Output(str(dump_path), command="extract",
                    options={"output": output_path}, redact_paths=True)
    out.set_command_result(result)
    doc = json.loads(out.to_json())
    full_text = json.dumps(doc)

    assert str(out_dir) not in full_text, "parent directory leaked despite --redact-paths"
    assert output_path not in full_text, "full absolute output path leaked despite --redact-paths"
    assert doc["artifacts"][0]["path"] == "extracted.bin"
    assert "output_path" not in doc["result"]["summary"]
    assert doc["meta"]["execution"]["options"]["output"] == "extracted.bin"


def test_set_command_result_then_to_json_keeps_full_artifact_path_by_default(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract",
                    options={"output": str(tmp_path / "extracted.bin")}, redact_paths=False)
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region",
                             path=str(tmp_path / "extracted.bin"))])
    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"][0]["path"] == str(tmp_path / "extracted.bin")
    assert doc["meta"]["execution"]["options"]["output"] == str(tmp_path / "extracted.bin")


def test_redact_paths_does_not_affect_csv_artifact_path(tmp_path):
    # --redact-paths is documented as a --json-only concern -- CSV export
    # (an analyst-local file, not something shared off-machine the way
    # --json commonly is) keeps the full path either way, matching
    # today's un-redacted CSV behavior for every other path-bearing field.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract", options={}, redact_paths=True)
    artifact_path = str(tmp_path / "extracted.bin")
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region", path=artifact_path)])
    out.set_command_result(result)

    csv_path = tmp_path / "out.csv"
    out.write_csv(str(csv_path), cmd_label="extract")
    text = csv_path.read_text(encoding="utf-8")
    artifacts_block = text.split("## extract / artifacts\n", 1)[1].split("\n\n", 1)[0]
    rows = list(csv.DictReader(io.StringIO(artifacts_block)))
    assert rows[0]["path"] == artifact_path


def test_command_result_rejects_bare_dict_artifact():
    # A bare dict would bypass Artifact's own validation (required
    # `kind`, type checks) and could reach the wire in a shape the JSON
    # Schema rejects -- must fail loudly at construction time instead.
    with pytest.raises(TypeError, match="Artifact"):
        CommandResult(kind="modules", records=_fake_records(),
                      coverage=CoverageReport(status=COVERAGE_COMPLETE),
                      artifacts=[{"id": "a1", "path": "x.bin"}])


def test_command_result_rejects_bare_dict_diagnostic():
    with pytest.raises(TypeError, match="Diagnostic"):
        CommandResult(kind="modules", records=_fake_records(),
                      coverage=CoverageReport(status=COVERAGE_COMPLETE),
                      diagnostics=[{"severity": "warning", "message": "x"}])


def test_set_command_result_minimal_produces_expected_shape(tmp_path):
    # list_cmd.py/modules.py never populate execution_status/diagnostics/
    # artifacts, nor coverage.sources/limitations -- a CommandResult built
    # with only kind/records/coverage (every other field left at its own
    # default) must still produce the full, correctly-shaped document,
    # including empty (not missing) sources/limitations/artifacts/
    # diagnostics.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")

    out = V2Output(str(dump_path), command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert doc["result"]["kind"] == "modules"
    assert doc["result"]["execution_status"] == "completed"
    assert doc["result"]["coverage"] == {
        "status": "complete", "reasons": [], "sources": {}, "limitations": []}
    assert doc["result"]["summary"] == {"count": 2}
    assert doc["result"]["data"]["records"] == [{"name": "a.dll"}, {"name": "b.dll"}]
    assert doc["artifacts"] == []
    assert doc["diagnostics"] == {"warnings": [], "errors": []}


# ── V2Output multi-evidence construction (Phase C groundwork) ────────────
# No current command calls from_evidence() -- these tests pin the
# capability itself (a future comparison command's one-line integration
# point), independent of whether any command uses it yet.

def test_v2output_requires_dump_path_or_evidence():
    with pytest.raises(TypeError, match="evidence"):
        V2Output()


def test_v2output_from_evidence_produces_two_element_evidence_array(tmp_path):
    # kind="modules" deliberately -- "comparison" isn't a schema-registered
    # result.kind yet (that's Phase C's PR2); a real schema-validating
    # round trip for this same construction lives in
    # tests/integration/test_json_schema_v2.py, where kind="comparison"
    # would validate for the wrong reason (or not at all).
    from dumpex.output.envelope import EvidenceInput

    dump_a = tmp_path / "baseline.dmp"
    dump_a.write_bytes(b"aaa")
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"bbbbb")

    out = V2Output.from_evidence([
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert len(doc["meta"]["evidence"]) == 2
    baseline, target = doc["meta"]["evidence"]
    assert baseline["id"] == baseline["role"] == "baseline"
    assert target["id"] == target["role"] == "target"
    assert doc["result"]["kind"] == "modules"


def test_v2output_from_evidence_requires_nonempty_list():
    from dumpex.output.envelope import EvidenceInput
    with pytest.raises(ValueError, match="at least one"):
        V2Output.from_evidence([])


def test_v2output_rejects_both_dump_path_and_evidence(tmp_path):
    from dumpex.output.envelope import EvidenceInput
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")
    with pytest.raises(TypeError, match="both"):
        V2Output(str(dump), evidence=[EvidenceInput(id="a", role="a", path=str(dump))])


def test_v2output_from_evidence_rejects_duplicate_ids(tmp_path):
    from dumpex.output.envelope import EvidenceInput
    dump_a = tmp_path / "a.dmp"
    dump_a.write_bytes(b"a")
    dump_b = tmp_path / "b.dmp"
    dump_b.write_bytes(b"b")
    with pytest.raises(ValueError, match="unique"):
        V2Output.from_evidence([
            EvidenceInput(id="same", role="baseline", path=str(dump_a)),
            EvidenceInput(id="same", role="target", path=str(dump_b)),
        ])


def test_v2output_from_evidence_rejects_bare_dict_entries():
    with pytest.raises(TypeError, match="EvidenceInput"):
        V2Output.from_evidence([{"id": "a", "role": "a", "path": "x"}])


def test_v2output_from_evidence_rejects_generator(tmp_path):
    # A generator would otherwise be silently exhausted by the first of
    # several validation passes over it (see envelope._normalize_evidence_
    # inputs), leaving self._evidence and self._protected_paths BOTH
    # empty from a genuinely non-empty input -- schema-invalid output and
    # a fully disabled overwrite guard from one construction call.
    from dumpex.output.envelope import EvidenceInput

    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")

    def gen():
        yield EvidenceInput(id="a", role="a", path=str(dump))
        yield EvidenceInput(id="b", role="b", path=str(dump))

    with pytest.raises(TypeError, match="list or tuple"):
        V2Output.from_evidence(gen())


def test_v2output_evidence_path_stays_stable_across_a_cwd_change(tmp_path, monkeypatch):
    # EvidenceInput.path is resolved to absolute ONCE, at construction --
    # a caller passing a relative path, followed by a cwd change before
    # to_json()/write_json() runs, must not cause metadata and the
    # overwrite guard to silently disagree about which on-disk file a
    # given entry refers to.
    from dumpex.output.envelope import EvidenceInput

    dir_a = tmp_path / "a"
    dir_a.mkdir()
    dir_b = tmp_path / "b"
    dir_b.mkdir()
    (dir_a / "same.dmp").write_bytes(b"AAAA")
    (dir_b / "same.dmp").write_bytes(b"BBBB")

    monkeypatch.chdir(dir_a)
    out = V2Output.from_evidence([EvidenceInput(id="x", role="x", path="same.dmp")],
                                  command="modules", options={})
    protected_at_construction = out._protected_paths[0]

    monkeypatch.chdir(dir_b)
    out.set_command_result(CommandResult(
        kind="modules", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert out._evidence[0].path == protected_at_construction
    assert doc["meta"]["evidence"][0]["path"] == str(dir_a / "same.dmp")
    assert doc["meta"]["evidence"][0]["size_bytes"] == 4   # b"AAAA", not dir_b's b"BBBB"


# ── V2Output write_json/write_csv refuse to overwrite ANY evidence path ──
# (Phase C review finding: an evidence=-constructed instance previously
# passed dump_path_abs=None into the safe-write layer, silently disabling
# the guard entirely for both baseline and target.)

def _comparison_output(dump_a, dump_b):
    from dumpex.output.envelope import EvidenceInput
    out = V2Output.from_evidence([
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    return out


@pytest.mark.parametrize("which", ["baseline", "target"])
def test_write_json_refuses_to_overwrite_either_evidence_path(tmp_path, which):
    dump_a = tmp_path / "baseline.dmp"
    dump_a.write_bytes(b"BASELINE CONTENT")
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"TARGET CONTENT")
    out = _comparison_output(dump_a, dump_b)
    target_path = dump_a if which == "baseline" else dump_b
    original = target_path.read_bytes()

    with pytest.raises(SystemExit):
        out.write_json(str(target_path), force=True)
    assert target_path.read_bytes() == original


@pytest.mark.parametrize("which", ["baseline", "target"])
def test_write_csv_single_file_refuses_to_overwrite_either_evidence_path(tmp_path, which):
    # write_csv's single-file vs. directory mode is chosen by the
    # REQUESTED path's own ".csv" suffix (see V2Output.write_csv), not by
    # what the evidence file happens to be named -- so exercising single-
    # file mode against an evidence path requires the evidence path
    # itself to end in ".csv" (an arbitrary but legal evidence filename
    # for this test; nothing about EvidenceInput requires a ".dmp" name).
    dump_a = tmp_path / "baseline.csv"
    dump_a.write_bytes(b"BASELINE CONTENT")
    dump_b = tmp_path / "target.csv"
    dump_b.write_bytes(b"TARGET CONTENT")
    out = _comparison_output(dump_a, dump_b)
    target_path = dump_a if which == "baseline" else dump_b
    original = target_path.read_bytes()

    with pytest.raises(SystemExit):
        out.write_csv(str(target_path), force=True)
    assert target_path.read_bytes() == original


@pytest.mark.parametrize("which", ["baseline", "target"])
def test_write_csv_directory_mode_refuses_to_overwrite_either_evidence_path(tmp_path, which):
    # Directory mode's per-table filename is deterministic --
    # dumpex_{kind}_{table_name}.csv (no cmd_label, no timestamp; see
    # V2Output.write_csv) -- so a genuine collision is reproduced by
    # pointing an evidence path at exactly that name inside the output
    # directory, rather than needing to predict a timestamp.
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    colliding_name = "dumpex_modules_summary.csv"
    colliding_path = out_dir / colliding_name
    other_path = tmp_path / "other.dmp"

    dump_a = colliding_path if which == "baseline" else other_path
    dump_b = other_path if which == "baseline" else colliding_path
    dump_a.write_bytes(b"BASELINE CONTENT")
    dump_b.write_bytes(b"TARGET CONTENT")
    out = _comparison_output(dump_a, dump_b)
    original = colliding_path.read_bytes()

    with pytest.raises(SystemExit):
        out.write_csv(str(out_dir) + os.sep, force=True)
    assert colliding_path.read_bytes() == original


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
