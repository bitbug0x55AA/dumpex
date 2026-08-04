"""
Validates dumpex.output.records.HunterRecord/*Details instances (and full
v2 envelopes built around them) against dumpex-output-v2.5.schema.json --
originally the PR3 "Schema v2.4" hunt migration step (see
docs/hunt_migration_field_matrix.md and the migration plan's own PR3
description), carried forward onto v2.5's extended `finding` $def
(id/severity/technique_ids/evidence_refs/iocs/rule_id/rule_version --
see dumpex/hunt/_finding.py). Built directly from
tests/fixtures/hunt_records.py's synthetic HunterRecord fixtures, NOT
through a real hunter collect_*() pipeline -- only injection's
collect_injection_record() exists so far; the other six hunters' real
collector wiring is tracked follow-up work (see
dumpex/output/records.py's own module-level comment above HUNTERS).

Also confirms dumpex-output-v1.1.schema.json, dumpex-output-v2.3.schema.json,
and dumpex-output-v2.4.schema.json stay byte-identical and functionally
frozen (v2.3 still rejects result.kind == "hunt", the same way v2.2
already rejects "report" in test_json_schema_v2.py; v2.4's own `finding`
$def still rejects the new v2.5 properties via additionalProperties:
false) -- a v2.5 addition must never leak backward into an already-
shipped schema copy.
"""
import hashlib
import json

import pytest

jsonschema = pytest.importorskip("jsonschema")

from tests.fixtures.hunt_records import (
    injection_detected, hollowing_not_evaluated, hollowing_detected, stomping_inconclusive,
    stomping_detected, pipe_clean, pipe_detected, cs_beacon_detected, yara_not_evaluated,
    yara_detected, obfuscation_detected, all_seven_detected_variety, all_seven_not_evaluated,
    hunt_summary_for,
)
from dumpex.schemas import schema_path


@pytest.fixture(scope="module")
def schema():
    with schema_path("dumpex-output-v2.5.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def schema_v2_4():
    with schema_path("dumpex-output-v2.4.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def hunter_record_validator_v2_4(schema_v2_4):
    wrapper = {"$schema": schema_v2_4["$schema"], "$ref": "#/$defs/hunterRecord",
               "$defs": schema_v2_4["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


@pytest.fixture(scope="module")
def validator(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def hunter_record_validator(schema):
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/hunterRecord", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


@pytest.fixture(scope="module")
def hunt_summary_validator(schema):
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/huntSummary", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def test_v2_4_finding_shape_is_rejected_by_the_frozen_v2_4_schema(hunter_record_validator_v2_4):
    # dumpex-output-v2.4.schema.json's own `finding` $def predates
    # id/severity/technique_ids/evidence_refs/iocs/rule_id/rule_version
    # entirely -- proves the frozen historical schema was never silently
    # updated to accept a real, current Finding.to_dict() shape (same
    # precedent as test_json_schema_v2.py's "kind" freeze tests, applied
    # to a nested $def instead of the root result.kind).
    d = injection_detected().to_dict()
    errors = list(hunter_record_validator_v2_4.iter_errors(d))
    assert errors


def test_a_genuine_v2_4_era_finding_shape_still_validates_against_the_v2_4_schema(
        hunter_record_validator_v2_4):
    # The frozen historical schema must keep validating a real v2.4-era
    # finding dict -- i.e. the old shape minus the seven v2.5 additions.
    d = injection_detected().to_dict()
    for f in d["findings"]:
        for key in ("id", "severity", "technique_ids", "evidence_refs", "iocs",
                    "rule_id", "rule_version"):
            del f[key]
    errors = list(hunter_record_validator_v2_4.iter_errors(d))
    assert errors == []


def _envelope(records, summary, coverage_status="complete", command="hunt", options=None):
    return {
        "meta": {
            "schema_version": "2.5",
            "tool": {"name": "dumpex", "version": None},
            "execution": {"started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z",
                          "duration_seconds": 1.0, "command": command, "options": options or {}},
            "evidence": [{"id": "primary", "role": "primary"}],
        },
        "result": {
            "kind": "hunt",
            "execution_status": "completed",
            "coverage": {"status": coverage_status, "reasons": [], "sources": {}, "limitations": []},
            "summary": summary,
            "data": {"records": [r.to_dict() for r in records]},
        },
        "artifacts": [],
        "diagnostics": {"warnings": [], "errors": []},
    }


# ── one HunterRecord per hunter, validated standalone ──────────────────────

@pytest.mark.parametrize("build", [
    injection_detected, hollowing_not_evaluated, hollowing_detected, stomping_inconclusive,
    stomping_detected, pipe_clean, pipe_detected, cs_beacon_detected, yara_not_evaluated,
    yara_detected, obfuscation_detected,
])
def test_hunter_record_fixture_validates(hunter_record_validator, build):
    errors = list(hunter_record_validator.iter_errors(build().to_dict()))
    assert errors == []


def test_hunter_record_covers_all_seven_hunter_types():
    records = all_seven_detected_variety()
    assert {r.hunter for r in records} == {
        "injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation"}


# ── full envelopes ───────────────────────────────────────────────────────

def test_hunt_all_envelope_validates(validator):
    records = all_seven_detected_variety()
    summary = hunt_summary_for(records)
    doc = _envelope(records, summary, coverage_status="partial", options={"hunt": "all"})
    errors = list(validator.iter_errors(doc))
    assert errors == []


def test_hunt_all_envelope_with_partial_not_evaluated_end_to_end(validator):
    # End-to-end: hand-build 7 HunterRecords with a real mix of states
    # (3 NOT_EVALUATED, 4 clean, none DETECTED/INCONCLUSIVE), run them
    # through the real dumpex.hunt.summary.build_hunt_summary() reducer
    # (not a hand-typed summary dict), and confirm the resulting envelope
    # validates -- specifically exercising the "partial NOT_EVALUATED ->
    # INCONCLUSIVE" rule this review round added.
    import dataclasses
    from dumpex.output.coverage import CoverageReport, CoverageStatus

    clean = [dataclasses.replace(
        r, status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0, verdict_level="clean",
        confidence=None if r.hunter == "yara" else "none",
        lead_count=None if r.hunter == "yara" else 0,
        review_priority=None if r.hunter == "yara" else "none",
        coverage=CoverageReport(status=CoverageStatus.COMPLETE), findings=[],
    ) for r in all_seven_detected_variety()]
    records = list(clean)
    for idx in (1, 3, 5):
        r = records[idx]
        records[idx] = dataclasses.replace(
            r, status="NOT_EVALUATED", verdict_level="not_evaluated",
            confidence=None if r.hunter == "yara" else "none",
            lead_count=None if r.hunter == "yara" else 0,
            review_priority=None if r.hunter == "yara" else "none",
            coverage=CoverageReport(status=CoverageStatus.NOT_EVALUATED), findings=[],
        )

    summary = hunt_summary_for(records, selected="all")
    assert summary["overall_status"] == "INCONCLUSIVE"
    assert summary["not_evaluated_count"] == 3
    doc = _envelope(records, summary, coverage_status="partial", options={"hunt": "all"})
    assert list(validator.iter_errors(doc)) == []


def test_hunt_single_hunter_envelope_validates(validator):
    rec = injection_detected()
    summary = hunt_summary_for([rec], selected="injection")
    doc = _envelope([rec], summary, options={"hunt": "injection"})
    assert list(validator.iter_errors(doc)) == []


def test_hunt_all_not_evaluated_envelope_validates(validator):
    records = all_seven_not_evaluated()
    summary = hunt_summary_for(records, selected="all")
    assert summary["overall_status"] == "NOT_EVALUATED"
    doc = _envelope(records, summary, coverage_status="not_evaluated", options={"hunt": "all"})
    assert list(validator.iter_errors(doc)) == []


def test_hunt_single_hunter_not_evaluated_envelope_validates(validator):
    rec = hollowing_not_evaluated()
    summary = hunt_summary_for([rec], selected="hollowing")
    doc = _envelope([rec], summary, coverage_status="not_evaluated", options={"hunt": "hollowing"})
    assert list(validator.iter_errors(doc)) == []


def test_hunt_all_clean_envelope_validates(validator):
    records = [pipe_clean()]
    summary = hunt_summary_for(records, selected="pipe")
    assert summary["overall_status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    doc = _envelope(records, summary, options={"hunt": "pipe"})
    assert list(validator.iter_errors(doc)) == []


def test_meta_rules_and_yara_rules_accepted(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["rules"] = {"path": "rules.yaml", "sha256": "a" * 64, "explicit": False,
                             "version": 1}
    doc["meta"]["yara_rules"] = {"rules_dir": "yara", "files": [
        {"name": "cs_indicators.yar", "sha256": "b" * 64, "compiled": True, "error": None}],
        "aggregate_sha256": "c" * 64, "compiled_ok": 1, "compile_failed": 0}
    assert list(validator.iter_errors(doc)) == []


# ── negative: hunterRecord cross-field constraints ──────────────────────────

def test_inconclusive_status_rejects_clean_verdict_level(hunter_record_validator):
    d = stomping_inconclusive().to_dict()
    d["verdict_level"] = "clean"
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_not_evaluated_status_rejects_complete_coverage(hunter_record_validator):
    d = hollowing_not_evaluated().to_dict()
    d["coverage"]["status"] = "complete"
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_not_detected_in_scanned_scope_rejects_high_verdict_level(hunter_record_validator):
    # Review finding #3: verified against dumpex/hunt/_coverage.py's
    # derive_status()/derive_coverage_status() and
    # dumpex/hunt/_finding.py's verdict_level() -- score==0 and complete
    # coverage can ONLY ever produce verdict_level "clean", never "high".
    d = pipe_clean().to_dict()
    d["verdict_level"] = "high"
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_not_evaluated_rejects_high_verdict_with_partial_coverage(hunter_record_validator):
    # Review finding #3: NOT_EVALUATED must pin verdict_level ==
    # "not_evaluated" AND coverage.status == "not_evaluated" exactly, not
    # merely "not complete".
    d = hollowing_not_evaluated().to_dict()
    d["verdict_level"] = "high"
    d["coverage"]["status"] = "partial"
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_detected_requires_positive_score(hunter_record_validator):
    d = injection_detected().to_dict()
    d["score"] = 0
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_coverage_not_evaluated_requires_status_not_evaluated(hunter_record_validator):
    # The reverse-direction safety net: coverage.status == "not_evaluated"
    # must force status == "NOT_EVALUATED" even if some future edit only
    # touches the forward per-status branches.
    d = injection_detected().to_dict()
    d["coverage"]["status"] = "not_evaluated"
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_yara_record_rejects_non_null_confidence(hunter_record_validator):
    d = yara_detected().to_dict()
    d["confidence"] = "high"
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_yara_record_rejects_nonempty_findings(hunter_record_validator):
    d = yara_detected().to_dict()
    d["findings"] = [{"check": "x", "tag": "lead", "confidence": "low", "facts": [],
                       "inference": "x", "rationale": "y", "limitations": []}]
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_injection_record_rejects_yara_details_shape(hunter_record_validator):
    d = injection_detected().to_dict()
    d["details"] = {"matches": [], "rules_hit": []}
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


def test_injection_record_rejects_null_confidence(hunter_record_validator):
    d = injection_detected().to_dict()
    d["confidence"] = None
    errors = list(hunter_record_validator.iter_errors(d))
    assert errors


# ── negative: huntSummary cross-field constraints ───────────────────────────

def test_hunt_summary_rejects_detected_without_detected_overall_status(hunt_summary_validator):
    summary = hunt_summary_for([injection_detected()], selected="injection")
    summary["overall_status"] = "INCONCLUSIVE"
    errors = list(hunt_summary_validator.iter_errors(summary))
    assert errors


def test_hunt_summary_rejects_inconclusive_with_clean_highest_verdict(hunt_summary_validator):
    summary = hunt_summary_for([stomping_inconclusive()], selected="stomping")
    summary["highest_verdict_level"] = "clean"
    errors = list(hunt_summary_validator.iter_errors(summary))
    assert errors


def test_hunt_summary_rejects_not_evaluated_with_non_not_evaluated_highest_verdict(
        hunt_summary_validator):
    summary = hunt_summary_for([hollowing_not_evaluated()], selected="hollowing")
    summary["highest_verdict_level"] = "clean"
    errors = list(hunt_summary_validator.iter_errors(summary))
    assert errors


def test_hunt_summary_rejects_hunter_count_mismatched_with_selected(hunt_summary_validator):
    # Review round 3, finding #1: selected="all" pins hunter_count to
    # exactly 7; a single hunter pins it to exactly 1.
    summary = hunt_summary_for([injection_detected()], selected="injection")
    summary["hunter_count"] = 999
    assert list(hunt_summary_validator.iter_errors(summary))


def test_hunt_summary_rejects_inconclusive_with_non_inconclusive_highest_verdict(
        hunt_summary_validator):
    # Tightened from "highest_verdict_level != clean" to exactly
    # "inconclusive".
    summary = hunt_summary_for([stomping_inconclusive()], selected="stomping")
    summary["highest_verdict_level"] = "high"
    assert list(hunt_summary_validator.iter_errors(summary))


def test_hunt_summary_partial_not_evaluated_among_seven_requires_inconclusive(
        hunt_summary_validator):
    # Review round 3, finding #1: 3 of 7 hunters NOT_EVALUATED, the rest
    # clean, none individually INCONCLUSIVE -- overall must still be
    # INCONCLUSIVE (a partly-unevaluated scope hasn't earned "clean"),
    # not silently allowed to say NOT_DETECTED_IN_SCANNED_SCOPE.
    good = {"selected": "all", "hunter_count": 7, "detected_count": 0,
            "inconclusive_count": 0, "not_evaluated_count": 3, "overall_status": "INCONCLUSIVE",
            "highest_verdict_level": "inconclusive", "lead_count": 0}
    assert list(hunt_summary_validator.iter_errors(good)) == []

    bad = dict(good)
    bad["overall_status"] = "NOT_DETECTED_IN_SCANNED_SCOPE"
    bad["highest_verdict_level"] = "clean"
    assert list(hunt_summary_validator.iter_errors(bad))


# ── negative: top-level result.coverage vs summary.overall_status ──────────

def test_hunt_envelope_rejects_not_evaluated_summary_with_complete_coverage(validator):
    records = all_seven_not_evaluated()
    summary = hunt_summary_for(records, selected="all")
    doc = _envelope(records, summary, coverage_status="complete", options={"hunt": "all"})
    errors = list(validator.iter_errors(doc))
    assert errors


def test_hunt_envelope_rejects_not_evaluated_coverage_with_detected_summary(validator):
    records = [injection_detected()]
    summary = hunt_summary_for(records, selected="injection")
    doc = _envelope(records, summary, coverage_status="not_evaluated", options={"hunt": "injection"})
    errors = list(validator.iter_errors(doc))
    assert errors


# ── negative: --hunt all/single record count, order, and `selected` value ──
# (review finding #2)

def test_hunt_summary_selected_rejects_unknown_value(hunt_summary_validator):
    summary = hunt_summary_for([injection_detected()], selected="injection")
    summary["selected"] = "banana"
    assert list(hunt_summary_validator.iter_errors(summary))


def test_hunt_result_requires_summary_present(validator):
    doc = _envelope([], {}, coverage_status="not_evaluated")
    del doc["result"]["summary"]
    assert list(validator.iter_errors(doc))


def test_hunt_all_rejects_fewer_than_seven_records(validator):
    # A hand-built (not build_hunt_summary()-derived) mismatched
    # summary+records pair -- the schema itself must catch this
    # independently of the reducer's own shape check.
    records = [injection_detected()]
    summary = {"selected": "all", "hunter_count": 1, "detected_count": 1,
               "inconclusive_count": 0, "not_evaluated_count": 0, "overall_status": "DETECTED",
               "highest_verdict_level": "high", "lead_count": 1}
    doc = _envelope(records, summary, coverage_status="partial", options={"hunt": "all"})
    assert list(validator.iter_errors(doc))


def test_hunt_all_rejects_records_out_of_fixed_order(validator):
    records = list(reversed(all_seven_detected_variety()))
    summary = dict(hunt_summary_for(all_seven_detected_variety(), selected="all"))
    doc = _envelope(records, summary, coverage_status="partial", options={"hunt": "all"})
    assert list(validator.iter_errors(doc))


def test_hunt_all_accepts_the_fixed_order(validator):
    records = all_seven_detected_variety()
    summary = hunt_summary_for(records, selected="all")
    doc = _envelope(records, summary, coverage_status="partial", options={"hunt": "all"})
    assert list(validator.iter_errors(doc)) == []


# ── negative: summary counts bound to the ACTUAL records array (review
# round 4, finding #1 -- summary and data.records were validated
# independently; a document could claim any count regardless of what the
# records themselves said) ─────────────────────────────────────────────────

def test_hunt_summary_detected_count_must_match_an_actual_detected_record(validator):
    records = [injection_detected()]   # a real DETECTED record
    bad_summary = {"selected": "injection", "hunter_count": 1, "detected_count": 0,
                   "inconclusive_count": 0, "not_evaluated_count": 1,
                   "overall_status": "NOT_DETECTED_IN_SCANNED_SCOPE",
                   "highest_verdict_level": "clean", "lead_count": 0}
    doc = _envelope(records, bad_summary, coverage_status="complete", options={"hunt": "injection"})
    assert list(validator.iter_errors(doc))


def test_hunt_summary_detected_count_cannot_exceed_hunter_count(validator):
    records = [injection_detected()]
    bad_summary = dict(hunt_summary_for(records, selected="injection"))
    bad_summary["detected_count"] = 99
    doc = _envelope(records, bad_summary, options={"hunt": "injection"})
    assert list(validator.iter_errors(doc))


def test_hunt_summary_inconclusive_count_must_match_actual_records(validator):
    records = [stomping_inconclusive()]
    bad_summary = dict(hunt_summary_for(records, selected="stomping"))
    bad_summary["inconclusive_count"] = 0
    bad_summary["overall_status"] = "NOT_DETECTED_IN_SCANNED_SCOPE"
    bad_summary["highest_verdict_level"] = "clean"
    doc = _envelope(records, bad_summary, coverage_status="complete", options={"hunt": "stomping"})
    assert list(validator.iter_errors(doc))


def test_hunt_summary_not_evaluated_count_must_match_actual_records(validator):
    records = [hollowing_not_evaluated()]
    bad_summary = dict(hunt_summary_for(records, selected="hollowing"))
    bad_summary["not_evaluated_count"] = 0
    doc = _envelope(records, bad_summary, coverage_status="not_evaluated",
                     options={"hunt": "hollowing"})
    assert list(validator.iter_errors(doc))


def test_hunt_summary_correct_counts_for_all_seven_still_validate(validator):
    records = all_seven_detected_variety()
    summary = hunt_summary_for(records, selected="all")
    doc = _envelope(records, summary, coverage_status="partial", options={"hunt": "all"})
    assert list(validator.iter_errors(doc)) == []


def test_hunt_single_hunter_rejects_more_than_one_record(validator):
    records = [injection_detected(), hollowing_detected()]
    summary = dict(hunt_summary_for([injection_detected()], selected="injection"))
    doc = _envelope(records, summary, options={"hunt": "injection"})
    assert list(validator.iter_errors(doc))


def test_hunt_single_hunter_rejects_mismatched_record_hunter(validator):
    records = [hollowing_detected()]
    summary = dict(hunt_summary_for([injection_detected()], selected="injection"))
    doc = _envelope(records, summary, options={"hunt": "injection"})
    assert list(validator.iter_errors(doc))


# ── negative: meta.rules / meta.yara_rules provenance shapes (review #4) ───

def test_meta_rules_empty_object_is_rejected(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["rules"] = {}
    assert list(validator.iter_errors(doc))


def test_meta_yara_rules_unknown_extra_field_is_rejected(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["yara_rules"] = {"surprise": 1}
    assert list(validator.iter_errors(doc))


def test_meta_rules_non_hex_sha256_is_rejected(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["rules"] = {"path": "rules.yaml", "sha256": "not-hex", "explicit": True,
                             "version": 1}
    assert list(validator.iter_errors(doc))


def test_meta_rules_error_shape_still_validates(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["rules"] = {"error": "boom"}
    assert list(validator.iter_errors(doc)) == []


def test_meta_yara_rules_compiled_true_requires_null_error(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["yara_rules"] = {"rules_dir": "yara", "files": [
        {"name": "a.yar", "sha256": "a" * 64, "compiled": True, "error": "should be null"}],
        "aggregate_sha256": "b" * 64, "compiled_ok": 1, "compile_failed": 0}
    assert list(validator.iter_errors(doc))


def test_meta_rules_builtin_defaults_shape_rejects_explicit_true(validator):
    # Review round 3, finding #2: verified against dumpex.rules_pkg.
    # loader's own hardcoded fallback dict -- path=null is EXACTLY the
    # built-in-defaults case, which is always explicit=False, version=1.
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["rules"] = {"path": None, "sha256": None, "explicit": True, "version": 1}
    assert list(validator.iter_errors(doc))


def test_meta_rules_builtin_defaults_shape_accepts_the_real_fixed_values(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["rules"] = {"path": None, "sha256": None, "explicit": False, "version": 1}
    assert list(validator.iter_errors(doc)) == []


def test_meta_yara_rules_normal_shape_rejects_null_aggregate_sha256(validator):
    # Review round 3, finding #3: load_and_compile() calls
    # hashlib.sha256().hexdigest() unconditionally, even over zero rule
    # files -- aggregate_sha256 is never null outside the error-only
    # branch.
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["yara_rules"] = {"rules_dir": "yara", "files": [], "aggregate_sha256": None,
                                 "compiled_ok": 0, "compile_failed": 0}
    assert list(validator.iter_errors(doc))


def test_meta_yara_rules_normal_shape_with_zero_files_still_has_real_aggregate_sha256(validator):
    records = [injection_detected()]
    doc = _envelope(records, hunt_summary_for(records, selected="injection"))
    doc["meta"]["yara_rules"] = {"rules_dir": "yara", "files": [],
                                 "aggregate_sha256": "e" * 64,
                                 "compiled_ok": 0, "compile_failed": 0}
    assert list(validator.iter_errors(doc)) == []


# ── frozen historical schemas stay frozen ───────────────────────────────────
#
# Hardcoded sha256 of each file as of the commit introducing v2.4 --
# these two files must never change as PART of a hunt-migration step (see
# the migration plan's own "v1.1/v2.3 schema 文件保持冻结" acceptance
# criterion). A deliberate, separately-reviewed future change to either
# file is expected to update these constants explicitly, not have this
# test silently pass through it.
_FROZEN_SHA256 = {
    "dumpex-output-v1.1.schema.json":
        "a9d6fcf21aab0f9d0586d807805c3f5fcd8923f510af8fad16d0f6b1f3d72a55",
    "dumpex-output-v2.3.schema.json":
        "ca02f62b42ff6f4baba2da1bb4ff5ab7cbf190ebab5d9a1521854367ca798775",
}


@pytest.mark.parametrize("filename, expected_sha256", sorted(_FROZEN_SHA256.items()))
def test_frozen_schema_file_is_byte_identical(filename, expected_sha256):
    with schema_path(filename) as path, open(path, "rb") as fh:
        content = fh.read()
    assert hashlib.sha256(content).hexdigest() == expected_sha256


def test_v2_3_still_rejects_hunt_kind():
    # Same precedent as test_json_schema_v2.py's v2.2-rejects-"report" check
    # -- a closed enum's already-shipped copy must never start silently
    # accepting a value it didn't originally define.
    with schema_path("dumpex-output-v2.3.schema.json") as path, open(path, encoding="utf-8") as fh:
        schema_v2_3 = json.load(fh)
    assert "hunt" not in schema_v2_3["$defs"]["result"]["properties"]["kind"]["enum"]
    assert "hunterRecord" not in schema_v2_3["$defs"]
    assert "rules" not in schema_v2_3["$defs"]["meta"]["properties"]
    assert "yara_rules" not in schema_v2_3["$defs"]["meta"]["properties"]
