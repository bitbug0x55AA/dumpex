"""
Validates real `--json` output against schemas/dumpex-output-v1.0.schema.json
-- typical DETECTED, DETECTED+partial coverage, INCONCLUSIVE, and
NOT_EVALUATED outputs from actual hunters (not hand-written fixture JSON),
so a future change to any hunter's output shape is caught here rather than
only being noticed by a downstream SIEM/SOAR integration guessing at field
types and status combinations.
"""
import json
import os
import tempfile

import pytest

jsonschema = pytest.importorskip("jsonschema")

from tests.fixtures.fakes import (Region, Module, ThreadInfo, Thread, Ctx, Peb,
                                   FakeStream, FakeMF, mem_reader,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ)

from dumpex.ui.structured import StructuredOutput
import dumpex.hunt.injection as injection
import dumpex.hunt.hollowing as hollowing
import dumpex.hunt.pipe as pipe

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "schemas", "dumpex-output-v1.0.schema.json")


@pytest.fixture(scope="module")
def schema():
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
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


def _doc_for(hunt_results: dict) -> dict:
    path = _make_dump_file()
    try:
        out = StructuredOutput(path, mf=None, command="hunt_all", options={"hunt": "all"})
        out.add("hunt", hunt_results)
        return json.loads(out.to_json())
    finally:
        os.unlink(path)


def _assert_valid(validator, doc):
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


# ── typical DETECTED, full coverage ────────────────────────────────────────

def test_detected_full_correlation_validates(validator):
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    injection.read_region = mem_reader({alloc_base + 0x2000: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["status"] == "DETECTED"
    _assert_valid(validator, _doc_for({"injection": f}))


# ── DETECTED but coverage partial -- must be ALLOWED, not rejected ────────

def test_detected_with_partial_coverage_validates(validator):
    region_base = 0x1230000

    def flaky_reader(mf, addr, size):
        raise OSError("simulated read failure")
    injection.read_region = flaky_reader
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["coverage_status"] == "partial"
    _assert_valid(validator, _doc_for({"injection": f}))


# ── INCONCLUSIVE must never carry verdict_level: clean ─────────────────────

def test_inconclusive_validates_and_is_not_clean(validator):
    class MF(FakeMF):
        handles = None
        memory_info = None
    f = pipe._hunt_pipe(MF(), verbose=False)
    assert f["status"] in ("INCONCLUSIVE", "NOT_EVALUATED")
    _assert_valid(validator, _doc_for({"pipe": f}))


# ── NOT_EVALUATED must carry coverage_status: not_evaluated ────────────────

def test_not_evaluated_validates(validator):
    class MF(FakeMF):
        peb = None
    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["status"] == "NOT_EVALUATED"
    assert f["coverage_status"] == "not_evaluated"
    _assert_valid(validator, _doc_for({"hollowing": f}))


# ── a combined --hunt all style document (multiple TTPs at once) ──────────

def test_combined_hunt_all_document_validates(validator):
    class MF(FakeMF):
        peb = None
        handles = None
    hollowing_f = hollowing._hunt_hollowing(MF(), verbose=False)
    pipe_f      = pipe._hunt_pipe(MF(), verbose=False)
    _assert_valid(validator, _doc_for({"hollowing": hollowing_f, "pipe": pipe_f}))


# ── deliberately broken document must be REJECTED by the schema ───────────
# (a schema that accepts everything is worthless — this proves it actually
# catches the exact violations it's meant to)

def test_schema_rejects_not_evaluated_with_wrong_coverage_status(validator):
    doc = _doc_for({"injection": {
        "status": "NOT_EVALUATED", "coverage_status": "complete", "score": 0,
    }})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)


def test_schema_rejects_inconclusive_marked_clean(validator):
    doc = _doc_for({"injection": {
        "status": "INCONCLUSIVE", "verdict_level": "clean", "score": 0,
    }})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)


def test_schema_rejects_unknown_status_value(validator):
    doc = _doc_for({"injection": {"status": "MAYBE", "score": 0}})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)
