"""
Validates real dumpex.output.V2Output JSON against
dumpex/schemas/dumpex-output-v2.0.schema.json for each of the six
recon-command kinds (memory_regions/modules/threads/sysinfo/pid/peb),
in normal, empty, and partial-coverage shapes -- built through the
actual collect_*() functions against synthetic fixtures, not
hand-written fixture JSON, so a shape change in any of them is caught
here.

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
    ExceptionStream, FakeStream, FakeMF,
)

from dumpex.output import V2Output
from dumpex.schemas import schema_path
from dumpex.commands.list_cmd import collect_regions
from dumpex.commands.modules import collect_modules
from dumpex.commands.threads import collect_threads
from dumpex.commands.sysinfo import collect_sysinfo, collect_pid
from dumpex.commands.peb import collect_peb
from dumpex.output.coverage import SourceObservation, CoverageLimitation, LimitationCode


@pytest.fixture(scope="module")
def schema():
    with schema_path("dumpex-output-v2.0.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


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
            "schema_version": "2.0",
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
# tests close that gap from both directions: every real to_dict() output
# must validate, and the domain-invalid shapes the Python model itself
# refuses to construct must ALSO be rejected by the schema directly (in
# case some future producer builds the JSON without going through these
# classes at all).

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


def test_sanity_the_minimal_valid_doc_itself_validates(validator):
    # Guards against the negative tests above passing for the wrong
    # reason (a typo elsewhere making _minimal_valid_doc() invalid too).
    assert validator.is_valid(_minimal_valid_doc())
    thread_doc = _minimal_valid_doc(kind="threads")
    thread_doc["result"]["data"]["records"] = [_minimal_thread_record()]
    assert validator.is_valid(thread_doc)
