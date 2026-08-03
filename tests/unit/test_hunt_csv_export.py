"""
Unit tests for dumpex.output.csv_export's "hunt" partitioning (PR3) --
build_tables(kind="hunt") splits result.records (a homogeneous list of
hunterRecord dicts) into summary/hunters/findings plus one evidence table
per hunter whose `details` holds list-shaped evidence
(injection_evidence/stomping_changes/pipe_evidence/beacon_configs/
yara_matches/obfuscation_hits) -- hollowing has no list-shaped evidence at
all, so its scalar `details` fields are flattened straight into the
"hunters" table instead of getting an unused table of their own. Mirrors
the existing "comparison" kind's own build_tables tests in
test_output_csv_and_collector.py, including its
partition-completeness-must-fail-loudly precedent.
"""
import csv
import io

import pytest

from dumpex.output.envelope import Result, EvidenceInput
from dumpex.output.csv_export import build_tables
from dumpex.output.collector import V2Output
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_PARTIAL

from tests.fixtures.hunt_records import (
    injection_detected, hollowing_not_evaluated, stomping_inconclusive, pipe_clean,
    cs_beacon_detected, yara_detected, obfuscation_detected, all_seven_detected_variety,
    hunt_summary_for,
)


def _hunt_result(records, selected=None, coverage_status="partial"):
    # build_hunt_summary() (via hunt_summary_for()) requires `selected` to
    # match the records it's given exactly -- "all" only for the real
    # 7-record set, the single hunter's own name otherwise. These CSV
    # tests are about build_tables()' own partitioning, not the summary
    # reducer (covered separately by tests/unit/test_hunt_summary.py and
    # the schema tests) -- an arbitrary partial subset (e.g. "injection
    # plus yara only", to exercise two specific tables at once) isn't a
    # shape the reducer accepts, so it falls back to a minimal literal
    # summary dict rather than contorting the fixture to fit the reducer.
    if selected is None:
        selected = "all" if len(records) != 1 else records[0].hunter
    try:
        summary = hunt_summary_for(records, selected=selected)
    except (ValueError, TypeError):
        summary = {"selected": selected, "hunter_count": len(records)}
    return Result(kind="hunt", execution_status="completed", coverage_status=coverage_status,
                  summary=summary, records=[r.to_dict() for r in records])


def test_build_tables_hunt_kind_has_no_generic_records_table():
    result = _hunt_result(all_seven_detected_variety())
    tables = build_tables(result)
    assert "records" not in tables
    assert set(tables) == {"summary", "hunters", "findings", "injection_evidence",
                            "stomping_changes", "pipe_evidence", "beacon_configs",
                            "yara_matches", "obfuscation_hits"}


def test_hunters_table_has_one_row_per_hunter_record():
    records = all_seven_detected_variety()
    tables = build_tables(_hunt_result(records))
    assert len(tables["hunters"]) == 7
    assert {row["hunter"] for row in tables["hunters"]} == {r.hunter for r in records}


def test_hunters_table_flattens_hollowing_scalar_details_in_place():
    tables = build_tables(_hunt_result(all_seven_detected_variety()))
    hollowing_row = next(r for r in tables["hunters"] if r["hunter"] == "hollowing")
    assert hollowing_row["image_base"] == "0x0000000000000004"
    assert hollowing_row["mem_private_at_base"] is None


def test_hunters_table_yara_row_carries_rules_hit_as_json_cell():
    tables = build_tables(_hunt_result([yara_detected()]))
    row = tables["hunters"][0]
    assert row["rules_hit"] == '["CS_Beacon_Config_XOR69"]'


def test_findings_table_excludes_yara_and_includes_others():
    records = [injection_detected(), yara_detected()]
    tables = build_tables(_hunt_result(records))
    assert len(tables["findings"]) == 1
    assert tables["findings"][0]["hunter"] == "injection"
    assert tables["findings"][0]["check"] == "injection.rwx_regions"


def test_injection_evidence_table_tags_rows_by_source_field():
    tables = build_tables(_hunt_result([injection_detected()]))
    rows = tables["injection_evidence"]
    fields_seen = {row["field"] for row in rows}
    assert "rwx" in fields_seen
    assert "hidden_pe_validated" in fields_seen
    assert "rwx_and_pe_alloc_bases" in fields_seen
    # a scalar list entry (a bare hex string) gets a "value" column, not a
    # flattened dict's worth of columns
    alloc_row = next(r for r in rows if r["field"] == "rwx_and_pe_alloc_bases")
    assert alloc_row["value"] == "0x0000000000000003"
    # a dict-shaped entry (a region ref) is flattened, not JSON-blobbed
    rwx_row = next(r for r in rows if r["field"] == "rwx")
    assert rwx_row["base_address"] == "0x0000000000000001"
    assert "value" not in rwx_row


def test_stomping_changes_table_only_present_for_stomping_records():
    tables = build_tables(_hunt_result([stomping_inconclusive()]))
    assert tables["stomping_changes"] == [
        {"hunter": "stomping", "field": "protection_leads", "module": "a.dll",
         "va": "0x0000000000000005"}]
    assert tables["injection_evidence"] == []
    assert tables["pipe_evidence"] == []


def test_pipe_evidence_table_flattens_handle_dicts():
    tables = build_tables(_hunt_result([pipe_clean()]))
    assert tables["pipe_evidence"] == []


def test_beacon_configs_table_has_no_field_tag_column():
    tables = build_tables(_hunt_result([cs_beacon_detected()]))
    rows = tables["beacon_configs"]
    assert len(rows) == 1
    assert "field" not in rows[0]
    assert rows[0]["cs_version"] == 4


def test_yara_matches_table_one_row_per_match():
    tables = build_tables(_hunt_result([yara_detected()]))
    rows = tables["yara_matches"]
    assert len(rows) == 1
    assert rows[0]["rule"] == "CS_Beacon_Config_XOR69"
    # nested list-of-dict (strings) is JSON-encoded, not a Python repr()
    assert rows[0]["strings"].startswith("[")


def test_obfuscation_hits_table_tags_rows_by_source_field():
    tables = build_tables(_hunt_result([obfuscation_detected()]))
    rows = tables["obfuscation_hits"]
    fields_seen = {row["field"] for row in rows}
    assert fields_seen == {"entropy", "hidden_pe"}


def test_summary_table_carries_hunt_specific_fields():
    records = all_seven_detected_variety()
    result = _hunt_result(records)
    tables = build_tables(result)
    row = tables["summary"][0]
    assert row["kind"] == "hunt"
    assert row["count"] == 7
    assert row["selected"] == result.summary["selected"]
    assert row["overall_status"] == result.summary["overall_status"]
    assert row["hunter_count"] == 7


# ── partition completeness: unknown hunter / details drift must fail loudly ─

def test_build_tables_hunt_kind_raises_on_unrecognized_hunter():
    records = all_seven_detected_variety()
    dicts = [r.to_dict() for r in records]
    dicts[0] = dict(dicts[0])
    dicts[0]["hunter"] = "some_future_hunter"
    result = Result(kind="hunt", execution_status="completed", coverage_status="partial",
                     summary=hunt_summary_for(records), records=dicts)
    with pytest.raises(ValueError, match="some_future_hunter"):
        build_tables(result)


def test_build_tables_hunt_kind_raises_on_details_shape_drift():
    records = all_seven_detected_variety()
    dicts = [r.to_dict() for r in records]
    dicts[0] = dict(dicts[0])
    dicts[0]["details"] = dict(dicts[0]["details"])
    dicts[0]["details"]["a_new_field_nobody_knows_about"] = "oops"
    result = Result(kind="hunt", execution_status="completed", coverage_status="partial",
                     summary=hunt_summary_for(records), records=dicts)
    with pytest.raises(ValueError, match="a_new_field_nobody_knows_about"):
        build_tables(result)


def test_build_tables_hunt_kind_raises_on_missing_details_field():
    records = all_seven_detected_variety()
    dicts = [r.to_dict() for r in records]
    dicts[0] = dict(dicts[0])
    d = dict(dicts[0]["details"])
    del d["rwx"]
    dicts[0]["details"] = d
    result = Result(kind="hunt", execution_status="completed", coverage_status="partial",
                     summary=hunt_summary_for(records), records=dicts)
    with pytest.raises(ValueError, match="rwx"):
        build_tables(result)


# ── directory-mode CSV write, mirroring the comparison-kind precedent ──────

def test_write_csv_directory_mode_writes_hunt_tables_not_records(tmp_path):
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"fake")
    out_dir = tmp_path / "out"
    records = all_seven_detected_variety()
    out = V2Output(dump_path=str(dump), command="hunt", options={"hunt": "all"})
    out.set_command_result(CommandResult(
        kind="hunt", execution_status="completed",
        coverage=CoverageReport(status=COVERAGE_PARTIAL),
        summary=hunt_summary_for(records), records=records))

    out.write_csv(str(out_dir) + "/", cmd_label="hunt")

    csv_files = {f.name for f in out_dir.glob("*.csv")}
    assert any("hunters" in f for f in csv_files)
    assert not any(f.endswith("_records.csv") for f in csv_files)
    hunters_file = next(f for f in out_dir.glob("*.csv") if "hunters" in f.name)
    rows = list(csv.DictReader(io.StringIO(hunters_file.read_text(encoding="utf-8"))))
    assert len(rows) == 7
