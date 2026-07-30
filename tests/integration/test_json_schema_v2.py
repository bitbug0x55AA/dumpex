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


@pytest.fixture(scope="module")
def schema():
    with schema_path("dumpex-output-v2.0.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def _validate(validator, kind, records, coverage_status, coverage_reasons=None):
    dump_path = _make_dump_file()
    try:
        out = V2Output(dump_path, command=kind, options={"verbose": False})
        out.set_result(kind, records, coverage_status, coverage_reasons)
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
    doc = _validate(validator, "memory_regions", result.records, result.coverage.status,
                     result.coverage.reasons)
    assert doc["result"]["execution_status"] == "completed"
    assert doc["result"]["coverage"]["status"] == "complete"


def test_memory_regions_empty_validates(validator):
    result = collect_regions(FakeMF())
    assert result.records == []
    _validate(validator, "memory_regions", result.records, result.coverage.status,
              result.coverage.reasons)


# ── modules ────────────────────────────────────────────────────────────

def test_modules_normal_validates(validator):
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")],
                             "modules")
    result = collect_modules(mf)
    _validate(validator, "modules", result.records, result.coverage.status, result.coverage.reasons)


def test_modules_empty_validates(validator):
    result = collect_modules(FakeMF())
    _validate(validator, "modules", result.records, result.coverage.status, result.coverage.reasons)


# ── threads ────────────────────────────────────────────────────────────

def test_threads_normal_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
    result = collect_threads(mf)
    doc = _validate(validator, "threads", result.records, result.coverage.status,
                     result.coverage.reasons)
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["data"]["records"][0]["module_context"] == "resolved"


def test_threads_degraded_is_partial_and_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info stream
    result = collect_threads(mf)
    assert result.coverage.status == "partial"
    doc = _validate(validator, "threads", result.records, result.coverage.status,
                     result.coverage.reasons)
    assert doc["result"]["coverage"]["status"] == "partial"
    assert doc["result"]["coverage"]["reasons"]


def test_threads_empty_validates(validator):
    result = collect_threads(FakeMF())
    _validate(validator, "threads", result.records, result.coverage.status, result.coverage.reasons)


# ── sysinfo ────────────────────────────────────────────────────────────

def test_sysinfo_normal_validates(validator):
    mf = FakeMF()
    mf.sysinfo = SysInfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    records, status, reasons, *_ = collect_sysinfo(mf)
    doc = _validate(validator, "sysinfo", records, status, reasons)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_sysinfo_partial_missing_streams_validates(validator):
    records, status, reasons, *_ = collect_sysinfo(FakeMF())
    assert status == "partial"
    doc = _validate(validator, "sysinfo", records, status, reasons)
    assert doc["result"]["coverage"]["reasons"]


# ── pid ────────────────────────────────────────────────────────────────

def test_pid_normal_via_misc_info_validates(validator):
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=4321)
    records, status, reasons = collect_pid(mf)
    doc = _validate(validator, "pid", records, status, reasons)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_pid_fallback_partial_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
    mf.exception = ExceptionStream(9)
    records, status, reasons = collect_pid(mf)
    assert status == "partial"
    doc = _validate(validator, "pid", records, status, reasons)
    assert doc["result"]["coverage"]["reasons"]


def test_pid_empty_validates(validator):
    records, status, reasons = collect_pid(FakeMF())
    _validate(validator, "pid", records, status, reasons)


# ── peb ────────────────────────────────────────────────────────────────

def test_peb_normal_validates(validator):
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    result = collect_peb(mf)
    doc = _validate(validator, "peb", result.records, result.coverage.status, result.coverage.reasons)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_peb_missing_is_not_evaluated_and_validates(validator):
    # --peb has exactly one data source; when it's absent there is
    # nothing to report at all, not merely an incomplete subset.
    result = collect_peb(FakeMF())
    assert result.coverage.status == "not_evaluated"
    doc = _validate(validator, "peb", result.records, result.coverage.status, result.coverage.reasons)
    assert doc["result"]["coverage"]["reasons"]


# ── negative cases: documents that MUST fail schema validation ───────────
# The schema being internally well-formed and every REAL collect_*() output
# validating is necessary but not sufficient -- these prove the schema
# actually rejects the malformed shapes it claims to guard against, not
# just "happens to accept everything real code produces."

def _minimal_valid_doc(kind="modules"):
    return {
        "meta": {
            "schema_version": "2.0",
            "tool": {"name": "dumpex", "version": "2.1.0"},
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


def test_sanity_the_minimal_valid_doc_itself_validates(validator):
    # Guards against the negative tests above passing for the wrong
    # reason (a typo elsewhere making _minimal_valid_doc() invalid too).
    assert validator.is_valid(_minimal_valid_doc())
    thread_doc = _minimal_valid_doc(kind="threads")
    thread_doc["result"]["data"]["records"] = [_minimal_thread_record()]
    assert validator.is_valid(thread_doc)
