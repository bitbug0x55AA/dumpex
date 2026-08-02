"""
Validates real dumpex.output.V2Output JSON against
dumpex/schemas/dumpex-output-v2.2.schema.json (the current v2 schema --
every producer now stamps schema_version "2.2") for each of the six
recon-command kinds (memory_regions/modules/threads/sysinfo/pid/peb),
in normal, empty, and partial-coverage shapes -- built through the
actual collect_*() functions against synthetic fixtures, not
hand-written fixture JSON, so a shape change in any of them is caught
here. dumpex-output-v2.0.schema.json and dumpex-output-v2.1.schema.json
(the frozen historical shapes) are also exercised directly (see the
"schema version history" section below) to prove each still validates a
genuine document from its own era and still rejects a `result.kind` it
was never updated to know about.

Loaded through dumpex.schemas.schema_path() (importlib.resources) so
this also proves the v2 schema is reachable the way an installed
(wheel) consumer would reach it.
"""
import json
import os
import tempfile

import pytest
import dumpex

jsonschema = pytest.importorskip("jsonschema")

from tests.fixtures.fakes import (
    Region, Module, ThreadInfo, Thread, Ctx, Peb, SysInfo, MiscInfo,
    ExceptionStream, FakeStream, FakeMF, mem_reader,
)

from dumpex.output import V2Output
from dumpex.schemas import schema_path
from dumpex.commands.list_cmd import collect_regions
from dumpex.commands.modules import collect_modules
from dumpex.commands.threads import collect_threads
from dumpex.commands.sysinfo import collect_sysinfo, collect_pid
from dumpex.commands.peb import collect_peb
from dumpex.output.coverage import (
    SourceObservation, CoverageLimitation, LimitationCode, CoverageReport, COVERAGE_COMPLETE,
)
from dumpex.output.command_result import CommandResult
from dumpex.output.records import Artifact, Diagnostic, SEVERITY_WARNING, SEVERITY_ERROR


@pytest.fixture(scope="module")
def schema():
    with schema_path("dumpex-output-v2.2.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def schema_v2_0():
    with schema_path("dumpex-output-v2.0.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_0(schema_v2_0):
    jsonschema.Draft202012Validator.check_schema(schema_v2_0)
    return jsonschema.Draft202012Validator(schema_v2_0)


@pytest.fixture(scope="module")
def schema_v2_1():
    with schema_path("dumpex-output-v2.1.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_1(schema_v2_1):
    jsonschema.Draft202012Validator.check_schema(schema_v2_1)
    return jsonschema.Draft202012Validator(schema_v2_1)


@pytest.fixture(scope="module")
def validator(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def source_observation_schema(schema):
    return schema["$defs"]["sourceObservation"]


@pytest.fixture(scope="module")
def coverage_limitation_schema(schema):
    return schema["$defs"]["coverageLimitation"]


def _fragment_validator(schema, def_name):
    # Wraps a single $defs entry as its own root document (a $ref sibling
    # to the same $defs map) rather than validating the extracted dict
    # directly -- moduleDiffRecord/threadDiffRecord/memoryDiffRecord all
    # contain "#/$defs/hexAddress" $refs, which only resolve when $defs is
    # still reachable from the document actually being validated. This is
    # unlike sourceObservation/coverageLimitation above, whose extracted
    # fragments happen to contain no $ref at all.
    wrapper = {"$schema": schema["$schema"], "$ref": f"#/$defs/{def_name}", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


@pytest.fixture(scope="module")
def module_diff_record_schema(schema):
    return _fragment_validator(schema, "moduleDiffRecord")


@pytest.fixture(scope="module")
def thread_diff_record_schema(schema):
    return _fragment_validator(schema, "threadDiffRecord")


@pytest.fixture(scope="module")
def memory_diff_record_schema(schema):
    return _fragment_validator(schema, "memoryDiffRecord")


def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def _validate(validator, result):
    dump_path = _make_dump_file()
    try:
        out = V2Output(dump_path, command=result.kind, options={"verbose": False})
        out.set_command_result(result)
        doc = json.loads(out.to_json())
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, "\n".join(str(e) for e in errors)
        return doc
    finally:
        os.remove(dump_path)


# ── memory_regions (--list) ───────────────────────────────────────────────

def test_memory_regions_normal_validates(validator):
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    result = collect_regions(mf)
    doc = _validate(validator, result)
    assert doc["result"]["execution_status"] == "completed"
    assert doc["result"]["coverage"]["status"] == "complete"


def test_memory_regions_empty_validates(validator):
    result = collect_regions(FakeMF())
    assert result.records == []
    _validate(validator, result)


# ── modules ────────────────────────────────────────────────────────────

def test_modules_normal_validates(validator):
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")],
                             "modules")
    result = collect_modules(mf)
    _validate(validator, result)


def test_modules_empty_validates(validator):
    result = collect_modules(FakeMF())
    _validate(validator, result)


# ── threads ────────────────────────────────────────────────────────────

def test_threads_normal_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
    result = collect_threads(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["data"]["records"][0]["module_context"] == "resolved"


def test_threads_degraded_is_partial_and_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info stream
    result = collect_threads(mf)
    assert result.coverage.status == "partial"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "partial"
    assert doc["result"]["coverage"]["reasons"]
    # Structured coverage reaches the wire alongside `reasons`, not instead
    # of it -- schema-valid AND matches the Python-side CoverageReport.
    sources = doc["result"]["coverage"]["sources"]
    assert sources["threads"] == {"state": "present", "record_count": 1, "detail": None}
    assert sources["thread_info"] == {"state": "absent", "record_count": None, "detail": None}
    limitations = doc["result"]["coverage"]["limitations"]
    assert [l["code"] for l in limitations] == ["SOURCE_ABSENT", "MODULE_CLASSIFICATION_UNAVAILABLE"]
    assert limitations[0]["source"] == "thread_info"


def test_threads_empty_validates(validator):
    result = collect_threads(FakeMF())
    _validate(validator, result)


# ── sysinfo ────────────────────────────────────────────────────────────

def test_sysinfo_normal_validates(validator):
    mf = FakeMF()
    mf.sysinfo = SysInfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    result = collect_sysinfo(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_sysinfo_partial_missing_streams_validates(validator):
    result = collect_sysinfo(FakeMF())
    assert result.coverage.status == "partial"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["reasons"]


# ── pid ────────────────────────────────────────────────────────────────

def test_pid_normal_via_misc_info_validates(validator):
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=4321)
    result = collect_pid(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_pid_fallback_partial_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
    mf.exception = ExceptionStream(9)
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["reasons"]


def test_pid_empty_validates(validator):
    result = collect_pid(FakeMF())
    _validate(validator, result)


# ── peb ────────────────────────────────────────────────────────────────

def test_peb_normal_validates(validator):
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    result = collect_peb(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_peb_missing_is_not_evaluated_and_validates(validator):
    # --peb has exactly one data source; when it's absent there is
    # nothing to report at all, not merely an incomplete subset.
    result = collect_peb(FakeMF())
    assert result.coverage.status == "not_evaluated"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["reasons"]
    assert doc["result"]["coverage"]["sources"] == {
        "peb": {"state": "absent", "record_count": None, "detail": None}}
    assert doc["result"]["coverage"]["limitations"] == [
        {"code": "PEB_UNAVAILABLE", "source": "peb", "scope": "dump", "affected_count": None,
         "unavailable_fields": [], "available_fields": [], "counterpart_source": None,
         "related_sources": [], "related_tids": [], "thread_id": None, "detail": None}]


# ── negative cases: documents that MUST fail schema validation ───────────
# The schema being internally well-formed and every REAL collect_*() output
# validating is necessary but not sufficient -- these prove the schema
# actually rejects the malformed shapes it claims to guard against, not
# just "happens to accept everything real code produces."

def _minimal_valid_doc(kind="modules"):
    return {
        "meta": {
            "schema_version": "2.2",
            "tool": {"name": "dumpex", "version": dumpex.__version__},
            "execution": {"started_at": "x", "finished_at": "x", "duration_seconds": 0.1,
                          "command": kind, "options": {}},
            "evidence": [{"id": "primary", "role": "primary"}],
        },
        "result": {
            "kind": kind,
            "execution_status": "completed",
            "coverage": {"status": "complete", "reasons": []},
            "summary": {"count": 1},
            "data": {"records": [_minimal_module_record()]},
        },
    }


def _minimal_module_record():
    return {"name": "a.dll", "full_path": None, "base_address": "0x0000000000001000",
            "end_address": "0x0000000000002000", "size": 4096, "compiled_utc": None,
            "file_version": None, "checksum": None, "anomaly_flags": []}


def _minimal_thread_record():
    return {"tid": 1, "start_address": None, "backing_module": None, "module_context": None,
            "flags": [], "create_time": None, "exit_time": None, "exit_status": None,
            "kernel_time_100ns": None, "user_time_100ns": None, "suspend_count": None,
            "priority": None, "teb": None}


def test_dropped_required_field_is_rejected(validator):
    doc = _minimal_valid_doc()
    del doc["result"]["data"]["records"][0]["checksum"]
    assert not validator.is_valid(doc)


def test_variable_width_hex_address_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["base_address"] = "0x1000"   # not zero-padded to 16 digits
    assert not validator.is_valid(doc)


def test_uppercase_hex_address_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["base_address"] = "0X0000000000001000"
    assert not validator.is_valid(doc)


def test_size_as_string_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["size"] = "4096"
    assert not validator.is_valid(doc)


def test_tid_as_string_is_rejected(validator):
    doc = _minimal_valid_doc(kind="threads")
    doc["result"]["data"]["records"] = [_minimal_thread_record()]
    doc["result"]["data"]["records"][0]["tid"] = "1"
    assert not validator.is_valid(doc)


def test_thread_fields_in_a_modules_record_is_rejected(validator):
    # Cross-kind contamination: a thread-shaped record where a
    # modules-shaped one is required by result.kind.
    doc = _minimal_valid_doc(kind="modules")
    doc["result"]["data"]["records"] = [_minimal_thread_record()]
    assert not validator.is_valid(doc)


def test_unknown_extra_field_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["totally_unexpected_field"] = "x"
    assert not validator.is_valid(doc)


def test_invalid_module_context_enum_value_is_rejected(validator):
    doc = _minimal_valid_doc(kind="threads")
    rec = _minimal_thread_record()
    rec["module_context"] = "definitely_not_a_valid_value"
    doc["result"]["data"]["records"] = [rec]
    assert not validator.is_valid(doc)


def test_limitation_missing_required_source_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["coverage"]["limitations"] = [{"code": "SOURCE_ABSENT"}]   # no `source`
    assert not validator.is_valid(doc)


def test_limitation_unknown_extra_field_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["coverage"]["limitations"] = [
        {"code": "SOURCE_ABSENT", "source": "modules", "totally_unexpected_field": "x"}]
    assert not validator.is_valid(doc)


def test_source_observation_invalid_state_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["coverage"]["sources"] = {"modules": {"state": "not_a_real_state"}}
    assert not validator.is_valid(doc)


# ── Python model <-> JSON Schema alignment ───────────────────────────────
# The Python dataclasses (SourceObservation/CoverageLimitation) and the
# JSON Schema fragments they're supposed to produce ($defs/sourceObservation,
# $defs/coverageLimitation) are two independent descriptions of the same
# shape -- nothing forces them to agree just because both exist. These
# tests close that gap from both directions where the schema CAN express
# the same rule: every real to_dict() output must validate, and the
# domain-invalid shapes the Python model itself refuses to construct
# must ALSO be rejected by the schema directly (in case some future
# producer builds the JSON without going through these classes at all).
#
# This is NOT full parity, and no test here claims otherwise: standard
# JSON Schema cannot express "these two field VALUES must differ"
# (CoverageLimitation's source != counterpart_source) or a check against
# a DIFFERENT object entirely outside this fragment (counterpart_source's
# own record_count in result.coverage.sources, a sibling key the
# coverageLimitation fragment never sees in isolation) -- those stay
# Python-only, enforced in CoverageLimitation.__post_init__ and
# _validate_source_absent_against_sources, with their own dedicated unit
# tests in test_output_coverage.py instead of here.

@pytest.mark.parametrize("state,record_count", [
    ("absent", None), ("failed", None), ("present_empty", 0), ("present", 1), ("present", 5),
])
def test_source_observation_to_dict_validates_for_every_state(
        state, record_count, source_observation_schema):
    obs = SourceObservation(name="x", state=state, record_count=record_count)
    jsonschema.validate(obs.to_dict(), source_observation_schema)


@pytest.mark.parametrize("doc", [
    {"state": "present", "record_count": 0, "detail": None},        # present must be >= 1
    {"state": "absent", "record_count": 3, "detail": None},         # absent must be null
    {"state": "present", "record_count": True, "detail": None},     # bool, not a real int
    {"state": "present_empty", "record_count": False, "detail": None},  # bool, not a real int
    {"state": "present_empty", "record_count": 1, "detail": None},  # present_empty must be exactly 0
    {"state": "modules"},                                            # missing record_count/detail
])
def test_source_observation_domain_invalid_shapes_rejected_by_schema(
        doc, source_observation_schema):
    assert not jsonschema.Draft202012Validator(source_observation_schema).is_valid(doc)


@pytest.mark.parametrize("code,kwargs", [
    (LimitationCode.SOURCE_ABSENT, dict(source="modules", scope="dump")),
    (LimitationCode.SOURCE_FAILED, dict(source="modules", scope="dump", detail="boom")),
    (LimitationCode.SOURCE_GROUP_ABSENT,
     dict(source="threads", scope="dump", related_sources=["threads", "thread_info"])),
    (LimitationCode.PID_THREAD_LIST_FALLBACK,
     dict(source="misc_info", counterpart_source="threads", related_tids=[1, 2])),
    (LimitationCode.PID_EXCEPTION_TID_FALLBACK, dict(source="exception", thread_id=9)),
])
def test_coverage_limitation_to_dict_validates_for_representative_codes(
        code, kwargs, coverage_limitation_schema):
    limitation = CoverageLimitation(code=code, **kwargs)
    jsonschema.validate(limitation.to_dict(), coverage_limitation_schema)


def test_coverage_limitation_minimal_shape_rejected_by_schema(coverage_limitation_schema):
    # Same fact as test_limitation_missing_required_source_is_rejected
    # above, checked directly against the fragment rather than a full
    # envelope -- code/source alone is not enough; every field
    # CoverageLimitation.to_dict() always emits is required.
    doc = {"code": "SOURCE_ABSENT", "source": "modules"}
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


@pytest.mark.parametrize("thread_id", [0, -1, True])
def test_coverage_limitation_non_positive_thread_id_rejected_by_schema(
        thread_id, coverage_limitation_schema):
    # The Python model already refuses to construct one of these (see
    # test_output_coverage.py) -- this proves the schema independently
    # rejects the same shape too, in case a future producer builds the
    # JSON without going through CoverageLimitation at all.
    doc = CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK,
                              source="exception", thread_id=9).to_dict()
    doc["thread_id"] = thread_id
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


@pytest.mark.parametrize("related_tids", [[0], [-1], [9, True], [9, 0]])
def test_coverage_limitation_non_positive_related_tid_rejected_by_schema(
        related_tids, coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                              counterpart_source="threads", related_tids=[9]).to_dict()
    doc["related_tids"] = related_tids
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


# ── coverageLimitation's per-code allOf/if-then (review round 2/3, P1) ────
# The Python model (CoverageLimitation.__post_init__) already refuses to
# construct a shape where a code's disallowed fields are set, or where a
# code-specific field-shape/dependency rule is violated -- these tests
# prove the schema independently rejects the same shapes too, for a
# hand-built JSON document that never went through the Python model at
# all (the exact scenario the schema is the last line of defense for).
# Each test below isolates exactly ONE violated rule -- bundling several
# wrong fields into one document (as the very first version of these
# tests did) proves only that AT LEAST ONE of them was caught, not that
# each one individually is; a single test with several unrelated invalid
# fields set would still pass even if all but one of the corresponding
# `then` constraints were missing or wrong.

def test_coverage_limitation_pid_no_usable_fallback_wrong_source_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    doc["source"] = "modules"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_no_usable_fallback_nonnull_scope_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    doc["scope"] = "module"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_no_usable_fallback_nonnull_affected_count_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    doc["affected_count"] = 7
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_no_usable_fallback_correct_shape_accepted_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    jsonschema.validate(doc, coverage_limitation_schema)


def test_coverage_limitation_source_group_absent_single_related_source_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="a",
                              related_sources=["a", "b"]).to_dict()
    doc["related_sources"] = ["a"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_sources_absent_wrong_related_sources_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_SOURCES_ABSENT, source="misc_info",
                              related_sources=["misc_info", "threads", "exception"]).to_dict()
    doc["related_sources"] = ["misc_info", "threads"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_thread_list_fallback_missing_counterpart_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                              counterpart_source="threads", related_tids=[1]).to_dict()
    doc["counterpart_source"] = None
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_thread_list_fallback_empty_related_tids_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                              counterpart_source="threads", related_tids=[1]).to_dict()
    doc["related_tids"] = []
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_exception_tid_fallback_null_thread_id_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception",
                              thread_id=9).to_dict()
    doc["thread_id"] = None
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_absent_count_without_counterpart_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="modules").to_dict()
    doc["affected_count"] = 3
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_absent_available_without_unavailable_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="modules").to_dict()
    doc["available_fields"] = ["TID"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_absent_available_with_counterpart_rejected_by_schema(
        coverage_limitation_schema):
    # available_fields alongside unavailable_fields alone isn't enough --
    # _render_source_absent branches on counterpart_source FIRST, so
    # available_fields is unused whenever it's set too.
    doc = CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="modules",
                              unavailable_fields=["StartAddress"]).to_dict()
    doc["available_fields"] = ["TID"]
    doc["counterpart_source"] = "other"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_failed_with_unavailable_fields_validates(
        coverage_limitation_schema):
    # comparison.py's thread diff customizes a FAILED target.modules with
    # scope="thread" + unavailable_fields (see dumpex.commands.comparison
    # collect_thread_diff) -- the schema must accept this shape, not just
    # the plain no-context SOURCE_FAILED every other producer emits.
    doc = CoverageLimitation(
        code=LimitationCode.SOURCE_FAILED, source="modules", scope="thread", detail="boom",
        unavailable_fields=["backing_module_after", "backing_module_context"]).to_dict()
    jsonschema.validate(doc, coverage_limitation_schema)


def test_coverage_limitation_source_failed_available_without_unavailable_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source="modules").to_dict()
    doc["available_fields"] = ["tid"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_failed_nonnull_affected_count_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source="modules").to_dict()
    doc["affected_count"] = 3
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_unknown_future_code_stays_open_in_schema(coverage_limitation_schema):
    # `code` deliberately stays a plain string, not an enum, so a future
    # LimitationCode the schema hasn't been updated for isn't rejected
    # outright -- none of the per-code `if` branches match an unlisted
    # value, so it's validated only against the generic per-field types,
    # same as before this allOf block existed.
    doc = {
        "code": "SOME_FUTURE_CODE", "source": "anything", "scope": "whatever",
        "affected_count": 99, "unavailable_fields": [], "available_fields": [],
        "counterpart_source": None, "related_sources": [], "related_tids": [],
        "thread_id": None, "detail": "free text",
    }
    jsonschema.validate(doc, coverage_limitation_schema)


def test_real_artifact_and_diagnostic_instances_validate_in_full_envelope(validator):
    # Routes real Artifact/Diagnostic instances through the actual
    # CommandResult -> V2Output.set_command_result() -> to_json() path
    # (not a hand-built dict) and validates the WHOLE envelope --
    # confirms the tightened artifact/diagnosticEntry $defs agree with
    # what these two classes' own to_dict() actually produces.
    result = CommandResult(
        kind="modules", records=[],
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        diagnostics=[
            Diagnostic(severity=SEVERITY_WARNING, message="w1", code="W001"),
            Diagnostic(severity=SEVERITY_ERROR, message="e1"),
        ],
        artifacts=[
            Artifact(id="a1", kind="extracted_region", path="region_0x1000.bin",
                     size_bytes=4096, sha256="deadbeef", description="RWX region"),
            Artifact(id="a2", kind="extracted_region", path="region_0x2000.bin"),
        ],
    )
    doc = _validate(validator, result)
    assert doc["artifacts"][0]["kind"] == "extracted_region"
    assert doc["artifacts"][1]["size_bytes"] is None
    assert doc["diagnostics"]["warnings"][0]["code"] == "W001"
    assert doc["diagnostics"]["errors"][0]["code"] is None


def test_sanity_the_minimal_valid_doc_itself_validates(validator):
    # Guards against the negative tests above passing for the wrong
    # reason (a typo elsewhere making _minimal_valid_doc() invalid too).
    assert validator.is_valid(_minimal_valid_doc())
    thread_doc = _minimal_valid_doc(kind="threads")
    thread_doc["result"]["data"]["records"] = [_minimal_thread_record()]
    assert validator.is_valid(thread_doc)


# ── multi-evidence V2Output.from_evidence() (Phase C, PR1) ────────────────
# kind="modules" here deliberately, even though "comparison" is now a
# schema-registered result.kind (PR2) -- the point of this specific test
# is proving the EVIDENCE ARRAY produced by from_evidence() satisfies the
# real schema end to end, independent of which kind is being reported.
# See the "kind == comparison" section below for comparisonRecord's own
# schema coverage.

def test_v2output_from_evidence_full_envelope_validates_against_schema(validator):
    from dumpex.output.envelope import EvidenceInput

    dump_a = _make_dump_file()
    dump_b = _make_dump_file()
    try:
        out = V2Output.from_evidence([
            EvidenceInput(id="baseline", role="baseline", path=dump_a),
            EvidenceInput(id="target", role="target", path=dump_b),
        ], command="modules", options={"verbose": False})
        out.set_command_result(CommandResult(
            kind="modules", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE)))
        doc = json.loads(out.to_json())
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, "\n".join(str(e) for e in errors)
        assert len(doc["meta"]["evidence"]) == 2
        assert doc["meta"]["evidence"][0]["id"] == "baseline"
        assert doc["meta"]["evidence"][1]["id"] == "target"
    finally:
        os.remove(dump_a)
        os.remove(dump_b)


# ── result.kind == "comparison" (Phase C, PR2) ────────────────────────────

def test_comparison_full_envelope_with_all_three_entity_types_validates(validator):
    from dumpex.output.envelope import EvidenceInput
    from dumpex.commands.comparison import collect_comparison

    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, r"C:\a.dll")], "modules")
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")

    mf_target = FakeMF()
    mf_target.modules = FakeStream([Module(0x2000, 0x1000, r"C:\b.dll")], "modules")
    mf_target.thread_info = FakeStream([ThreadInfo(2, 0x2000)], "infos")
    mf_target.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")

    result = collect_comparison(mf_baseline, mf_target, mode="all")
    assert result.coverage.status == "complete"

    dump_a = _make_dump_file()
    dump_b = _make_dump_file()
    try:
        out = V2Output.from_evidence([
            EvidenceInput(id="baseline", role="baseline", path=dump_a),
            EvidenceInput(id="target", role="target", path=dump_b),
        ], command="comparison", options={"verbose": False})
        out.set_command_result(result)
        doc = json.loads(out.to_json())
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, "\n".join(str(e) for e in errors)
        entity_types = {r["entity_type"] for r in doc["result"]["data"]["records"]}
        assert entity_types == {"module", "thread", "memory_region"}
        assert doc["result"]["coverage"]["sources"]["baseline.modules"]["state"] == "present"
    finally:
        os.remove(dump_a)
        os.remove(dump_b)


# ── result.kind == "extract" (Phase E, PR1) ───────────────────────────────

def test_extract_full_envelope_with_mz_header_validates(validator, tmp_path):
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_extract

    mf = FakeMF()
    mf.filename = "test.dmp"
    extract_mod.read_region = mem_reader({0x1000: b"MZ" + b"\x90" * 62})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x1000, 64, out_path, auto_size=False, force=True)
    doc = _validate(validator, result)
    assert doc["result"]["kind"] == "extract"
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["artifacts"][0]["kind"] == "extracted_region"
    assert doc["diagnostics"]["warnings"][0]["code"] == "EXTRACT_MZ_HEADER_DETECTED"


def test_extract_short_read_validates_with_region_read_truncated_limitation(validator, tmp_path):
    # P1-4 remediation: a short read must still produce a schema-valid
    # document -- coverage.status becomes "partial" and a
    # REGION_READ_TRUNCATED limitation appears, rather than silently
    # reporting a truncated read as "complete".
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_extract

    mf = FakeMF()
    mf.filename = "test.dmp"
    extract_mod.read_region = mem_reader({0x1000: b"short"})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x1000, 64, out_path, auto_size=False, force=True)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "partial"
    assert doc["result"]["data"]["records"][0]["requested_size"] == 64
    assert doc["result"]["data"]["records"][0]["bytes_read"] == 5
    codes = {lim["code"] for lim in doc["result"]["coverage"]["limitations"]}
    assert codes == {"REGION_READ_TRUNCATED"}


# ── result.kind == "strings" (Phase E, PR2) ───────────────────────────────

def test_strings_full_envelope_with_grep_validates(validator):
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_strings

    mf = FakeMF()
    mf.filename = "test.dmp"
    data = b"apple pie recipe" + b"\x00" * 5 + b"cherry tart notes"
    extract_mod.read_region = mem_reader({0x1000: data})
    result = collect_strings(mf, 0x1000, len(data), 6, "recipe", "ascii")
    doc = _validate(validator, result)
    assert doc["result"]["kind"] == "strings"
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["data"]["records"][0]["matched_grep"] is True
    assert doc["result"]["data"]["records"][1]["matched_grep"] is False


def test_strings_empty_result_validates(validator):
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_strings

    mf = FakeMF()
    mf.filename = "test.dmp"
    extract_mod.read_region = mem_reader({0x4000: b"\x01\x02\x03" * 5})
    result = collect_strings(mf, 0x4000, 15, 6, None, "both")
    doc = _validate(validator, result)
    assert doc["result"]["kind"] == "strings"
    assert doc["result"]["data"]["records"] == []
    assert doc["result"]["coverage"]["sources"]["requested_region"]["state"] == "present_empty"


def test_string_record_null_address_is_rejected_by_schema(validator):
    # P2-1 remediation: unlike most hexAddress-typed fields, stringRecord's
    # `address` is never null on the wire (a string is always found at
    # some real address) -- the schema must reject a null there even
    # though hexAddress itself otherwise allows it.
    doc = _minimal_valid_doc(kind="strings")
    doc["result"]["data"]["records"] = [{
        "offset": 0, "address": None, "encoding": "ASCII", "text": "x", "matched_grep": None}]
    assert not validator.is_valid(doc)


def test_string_record_negative_offset_is_rejected_by_schema(validator):
    doc = _minimal_valid_doc(kind="strings")
    doc["result"]["data"]["records"] = [{
        "offset": -1, "address": "0x0000000000001000", "encoding": "ASCII",
        "text": "x", "matched_grep": None}]
    assert not validator.is_valid(doc)


def test_string_record_unknown_encoding_is_rejected_by_schema(validator):
    doc = _minimal_valid_doc(kind="strings")
    doc["result"]["data"]["records"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "BOGUS",
        "text": "x", "matched_grep": None}]
    assert not validator.is_valid(doc)


def test_extract_record_negative_bytes_read_is_rejected_by_schema(validator):
    doc = _minimal_valid_doc(kind="extract")
    doc["result"]["data"]["records"] = [{
        "requested_address": "0x0000000000001000", "requested_size": 16,
        "auto_sized": False, "bytes_read": -1, "mz_header_detected": False}]
    assert not validator.is_valid(doc)


def test_extract_record_null_requested_address_is_rejected_by_schema(validator):
    # P2 remediation: requested_address is non-nullable on extractRecord --
    # a successful --extract always knows the exact address it read.
    doc = _minimal_valid_doc(kind="extract")
    doc["result"]["data"]["records"] = [{
        "requested_address": None, "requested_size": 16,
        "auto_sized": False, "bytes_read": 16, "mz_header_detected": False}]
    assert not validator.is_valid(doc)


def test_extract_record_null_requested_size_is_rejected_by_schema(validator):
    doc = _minimal_valid_doc(kind="extract")
    doc["result"]["data"]["records"] = [{
        "requested_address": "0x0000000000001000", "requested_size": None,
        "auto_sized": False, "bytes_read": 16, "mz_header_detected": False}]
    assert not validator.is_valid(doc)


def test_strings_kind_is_rejected_by_the_frozen_v2_1_schema(validator_v2_1):
    # dumpex-output-v2.1.schema.json predates "strings" entirely -- proves
    # the frozen historical schema was never silently updated to accept
    # it (same precedent as "extract" and "comparison" above).
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.1"
    doc["result"]["kind"] = "strings"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_1.is_valid(doc)


def test_extract_kind_is_rejected_by_the_frozen_v2_1_schema(validator_v2_1):
    # dumpex-output-v2.1.schema.json predates "extract" entirely -- proves
    # the frozen historical schema was never silently updated to accept
    # it (the whole point of keeping it as its own file, same precedent
    # as v2.0 not accepting "comparison").
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.1"
    doc["result"]["kind"] = "extract"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_1.is_valid(doc)


def test_a_genuine_v2_1_era_document_still_validates_against_the_v2_1_schema(validator_v2_1):
    # The frozen historical schema must keep validating output produced
    # before schema_version 2.2 existed.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.1"
    assert validator_v2_1.is_valid(doc)


def test_comparison_kind_is_rejected_by_the_frozen_v2_0_schema(validator_v2_0):
    # dumpex-output-v2.0.schema.json predates "comparison" entirely --
    # proves the frozen historical schema was never silently updated to
    # accept it (the whole point of keeping it as its own file).
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.0"
    doc["result"]["kind"] = "comparison"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_0.is_valid(doc)


def test_a_genuine_v2_0_era_document_still_validates_against_the_v2_0_schema(validator_v2_0):
    # The frozen historical schema must keep validating output produced
    # before schema_version 2.1 existed -- freezing it is only useful if
    # it still actually works for that purpose.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.0"
    assert validator_v2_0.is_valid(doc)


def test_module_diff_record_added_with_a_before_value_rejected(module_diff_record_schema):
    from dumpex.output.records import ModuleDiffRecord, MODULE_DIFF_ADDED
    doc = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                            full_path_before=None, full_path_after="C:\\a.dll",
                            base_address_before=None,
                            base_address_after="0x0000000000001000").to_dict()
    doc["full_path_before"] = "C:\\a.dll"   # added must never carry a baseline-side value
    assert not module_diff_record_schema.is_valid(doc)


def test_module_diff_record_rebased_valid_shape_accepted(module_diff_record_schema):
    from dumpex.output.records import ModuleDiffRecord, MODULE_DIFF_REBASED
    doc = ModuleDiffRecord(change_type=MODULE_DIFF_REBASED, name="a.dll",
                            full_path_before="C:\\a.dll", full_path_after="C:\\a.dll",
                            base_address_before="0x0000000000001000",
                            base_address_after="0x0000000000009000").to_dict()
    assert module_diff_record_schema.is_valid(doc)


def test_module_diff_record_anonymous_added_module_accepted(module_diff_record_schema):
    # Regression: an anonymous module (no name at all) has a real
    # base_address but no full_path -- the schema must not require
    # full_path_after to be non-null for "added" (only base_address is
    # the field a module diff actually always has).
    from dumpex.output.records import ModuleDiffRecord, MODULE_DIFF_ADDED
    doc = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="(unnamed)",
                            full_path_before=None, full_path_after=None,
                            base_address_before=None,
                            base_address_after="0x0000000000001000").to_dict()
    assert module_diff_record_schema.is_valid(doc)


def test_thread_diff_record_removed_with_a_backing_module_rejected(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_REMOVED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_REMOVED, tid=1,
                            start_address_before="0x0000000000001000",
                            start_address_after=None).to_dict()
    doc["backing_module_after"] = "ntdll.dll"   # diff_threads never resolves this for removed
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_added_valid_shape_accepted(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED
    from dumpex.output.records import MODULE_CONTEXT_UNREGISTERED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None,
                            start_address_after="0x0000000000002000",
                            backing_module_after=None,
                            backing_module_context=MODULE_CONTEXT_UNREGISTERED).to_dict()
    assert thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_resolved_without_backing_module_rejected(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED, MODULE_CONTEXT_RESOLVED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None,
                            start_address_after="0x0000000000001000",
                            backing_module_after="ntdll.dll",
                            backing_module_context=MODULE_CONTEXT_RESOLVED).to_dict()
    doc["backing_module_after"] = None   # resolved must carry a backing module
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_unregistered_with_backing_module_rejected(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED, MODULE_CONTEXT_UNREGISTERED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None,
                            start_address_after="0x0000000000001000",
                            backing_module_after=None,
                            backing_module_context=MODULE_CONTEXT_UNREGISTERED).to_dict()
    doc["backing_module_after"] = "ntdll.dll"   # unregistered must never carry one
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_added_null_address_with_module_context_rejected(
        thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None, start_address_after=None).to_dict()
    doc["backing_module_context"] = "unavailable"   # address unknown -- resolution never attempted
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_added_known_address_without_module_context_rejected(
        thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord
    doc = {"entity_type": "thread", "change_type": "added", "tid": 1,
           "start_address_before": None, "start_address_after": "0x0000000000001000",
           "backing_module_after": None, "backing_module_context": None}
    assert not thread_diff_record_schema.is_valid(doc)


def test_memory_diff_record_protection_changed_missing_protect_after_rejected(
        memory_diff_record_schema):
    from dumpex.output.records import MemoryDiffRecord, MEMORY_DIFF_PROTECTION_CHANGED
    doc = MemoryDiffRecord(
        change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address="0x0000000000001000",
        size_before=4096, size_after=4096,
        protect_before="PAGE_READWRITE", protect_after="PAGE_EXECUTE_READWRITE",
        type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
        suspicious_before=False, suspicious_after=True).to_dict()
    doc["protect_after"] = None   # protection_changed requires both sides populated
    assert not memory_diff_record_schema.is_valid(doc)


def test_memory_diff_record_added_valid_shape_accepted(memory_diff_record_schema):
    from dumpex.output.records import MemoryDiffRecord, MEMORY_DIFF_ADDED
    doc = MemoryDiffRecord(
        change_type=MEMORY_DIFF_ADDED, base_address="0x0000000000001000",
        size_before=None, size_after=4096,
        protect_before=None, protect_after="PAGE_READWRITE",
        type_before=None, type_after="MEM_PRIVATE",
        suspicious_before=None, suspicious_after=False).to_dict()
    assert memory_diff_record_schema.is_valid(doc)


def test_memory_diff_record_protection_changed_null_suspicious_rejected(memory_diff_record_schema):
    from dumpex.output.records import MemoryDiffRecord, MEMORY_DIFF_PROTECTION_CHANGED
    doc = MemoryDiffRecord(
        change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address="0x0000000000001000",
        size_before=4096, size_after=4096,
        protect_before="PAGE_READWRITE", protect_after="PAGE_EXECUTE_READWRITE",
        type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
        suspicious_before=False, suspicious_after=True).to_dict()
    doc["suspicious_before"] = None
    doc["suspicious_after"] = None
    assert not memory_diff_record_schema.is_valid(doc)


# ── empty string "" is never a legitimate stand-in for "no value" ────────
# (Phase C review round 3) -- these optional string fields only gained
# minLength: 1 in this same round, matching the stricter check the Python
# model's own field-shape validators had already started enforcing.

def test_module_diff_record_empty_full_path_rejected_by_schema(module_diff_record_schema):
    doc = {"entity_type": "module", "change_type": "rebased", "name": "a.dll",
           "full_path_before": "", "full_path_after": "x",
           "base_address_before": "0x0000000000001000", "base_address_after": "0x0000000000002000"}
    assert not module_diff_record_schema.is_valid(doc)


def test_thread_diff_record_empty_backing_module_after_rejected_by_schema(thread_diff_record_schema):
    doc = {"entity_type": "thread", "change_type": "added", "tid": 1,
           "start_address_before": None, "start_address_after": "0x0000000000001000",
           "backing_module_after": "", "backing_module_context": "resolved"}
    assert not thread_diff_record_schema.is_valid(doc)


def test_memory_diff_record_empty_protect_rejected_by_schema(memory_diff_record_schema):
    doc = {"entity_type": "memory_region", "change_type": "added", "base_address": "0x0000000000001000",
           "size_before": None, "size_after": 4096,
           "protect_before": None, "protect_after": "",
           "type_before": None, "type_after": "MEM_PRIVATE",
           "suspicious_before": None, "suspicious_after": False}
    assert not memory_diff_record_schema.is_valid(doc)


def test_memory_diff_record_null_base_address_rejected_by_schema(memory_diff_record_schema):
    # Regression: base_address is memory_diff's match key -- it can never
    # legitimately be null (unlike moduleDiffRecord/threadDiffRecord's
    # OWN address fields, which reuse the same hexAddress $ref precisely
    # because they CAN be null on the missing side). Reusing hexAddress
    # bare here let a null base_address through the schema even though
    # MemoryDiffRecord.__post_init__ already rejects it outright.
    doc = {"entity_type": "memory_region", "change_type": "added", "base_address": None,
           "size_before": None, "size_after": 4096,
           "protect_before": None, "protect_after": "PAGE_READWRITE",
           "type_before": None, "type_after": "MEM_PRIVATE",
           "suspicious_before": None, "suspicious_after": False}
    assert not memory_diff_record_schema.is_valid(doc)
