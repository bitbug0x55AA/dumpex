"""
Validates real `--json` output against
dumpex/schemas/dumpex-output-v1.0.schema.json -- typical DETECTED,
DETECTED+partial coverage, INCONCLUSIVE, and NOT_EVALUATED outputs from
actual hunters (not hand-written fixture JSON), so a future change to any
hunter's output shape is caught here rather than only being noticed by a
downstream SIEM/SOAR integration guessing at field types and status
combinations.

The schema is loaded through dumpex.schemas.schema_path() (importlib.resources)
rather than a hardcoded repo-relative path, so this suite also proves the
schema is actually reachable the way an installed (wheel) consumer would
reach it, not just from a source checkout.
"""
import json
import os
import tempfile

import pytest

jsonschema = pytest.importorskip("jsonschema")

from tests.fixtures.fakes import (Region, Module, ThreadInfo, Thread, Ctx, Peb,
                                   FakeStream, FakeMF, mem_reader,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   Segment, FakeReader, matching_module_and_ref,
                                   cs_beacon_config_bytes)

from dumpex.ui.structured import StructuredOutput
from dumpex.schemas import schema_path
import dumpex.hunt.injection as injection
import dumpex.hunt.hollowing as hollowing
import dumpex.hunt.pipe as pipe
import dumpex.hunt.stomping as stomping
import dumpex.hunt.cs_beacon as cs_beacon
import dumpex.hunt.encoding as encoding
import dumpex.hunt.yara_hunt as yara_hunt


@pytest.fixture(scope="module")
def schema():
    with schema_path() as path, open(path, encoding="utf-8") as fh:
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


# ── the remaining hunters: stomping, cs-beacon, obfuscation, yara ─────────
# (previously only injection/hollowing/pipe were exercised against the
# schema -- a shape regression in any of these four could ship unnoticed)

def test_stomping_result_validates(validator):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    _assert_valid(validator, _doc_for({"stomping": f}))


def test_cs_beacon_detected_result_validates(validator):
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = b'\x00' * 0x100 + config + b'\x00' * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = None
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["status"] == "DETECTED"
    _assert_valid(validator, _doc_for({"cs-beacon": f}))


def test_obfuscation_detected_result_validates(validator):
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    import gzip
    payload = gzip.compress(pe_bytes)
    region_base = 0x8f0000
    regions = [Region(region_base, region_base, len(payload) + 0x100, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: payload.ljust(len(payload) + 0x100, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["status"] == "DETECTED"
    _assert_valid(validator, _doc_for({"obfuscation": f}))


def test_yara_not_evaluated_result_validates(validator):
    # Degrades to NOT_EVALUATED whether or not yara-python is installed
    # (missing rules dir is checked before the optional `import yara`
    # would even matter), so this runs unconditionally.
    f = yara_hunt._hunt_yara(FakeMF(), rules_dir="/definitely_not_a_real_dir_xyz123", verbose=False)
    assert f["status"] == "NOT_EVALUATED"
    _assert_valid(validator, _doc_for({"yara": f}))


def test_yara_detected_result_validates(validator):
    pytest.importorskip("yara")
    seg_va, seg_fo = 0x50000, 0x5000
    data = b'A' * 0x100 + b'FINDME_MARKER' + b'B' * 0x100
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "hit.yar"), "w") as fh:
            fh.write('rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "DETECTED"
    _assert_valid(validator, _doc_for({"yara": f}))


# ── the exact broken shapes a prior version of this schema let through ────
# (status+score only, string lead_count, empty-string review_priority) --
# each must now be REJECTED, not silently accepted.

def test_schema_rejects_detected_result_missing_common_fields(validator):
    # A DETECTED result carrying only the two originally-`required` keys --
    # no coverage_status/verdict_level at all.
    doc = _doc_for({"injection": {"status": "DETECTED", "score": 1}})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)


def test_schema_rejects_finding_hunter_result_missing_confidence_and_findings(validator):
    # coverage_status/verdict_level present but confidence/findings/
    # lead_count/review_priority absent -- for a Finding-model hunter
    # (injection here) these are documented as unconditionally present and
    # must be required, unlike yara (see test_yara_not_evaluated_result_validates
    # and test_yara_detected_result_validates, which legitimately lack them).
    doc = _doc_for({"injection": {
        "status": "DETECTED", "score": 1,
        "coverage_status": "complete", "verdict_level": "high",
    }})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)


def test_schema_rejects_string_lead_count(validator):
    doc = _doc_for({"injection": {
        "status": "DETECTED", "score": 1,
        "coverage_status": "complete", "verdict_level": "high",
        "lead_count": "many",
    }})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)


def test_schema_rejects_empty_string_review_priority(validator):
    doc = _doc_for({"injection": {
        "status": "DETECTED", "score": 1,
        "coverage_status": "complete", "verdict_level": "high",
        "review_priority": "",
    }})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)


def test_schema_rejects_minimal_result_under_an_unknown_hunter_name(validator):
    # `hunt` keys other than "yara" are open (additionalProperties ->
    # findingHunterResult) precisely so new/renamed hunters don't need a
    # schema edit -- but the VALUE must still satisfy findingHunterResult
    # (the stricter of the two hunter shapes) regardless of what the key is
    # called.
    doc = _doc_for({"some_new_hunter": {"status": "DETECTED", "score": 1}})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(doc)
