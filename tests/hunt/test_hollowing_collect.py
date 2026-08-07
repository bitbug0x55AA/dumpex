"""
Unit tests for dumpex.hunt.hollowing.collect_hollowing_record() -- PR2b's
HunterRecord-producing path for the hollowing hunter. Every scenario here
mirrors tests/hunt/test_hollowing.py's own fixtures (same literal inputs),
confirming collect_hollowing_record() and the console path
(_hunt_hollowing()) always agree on the same underlying Report -- both are
built from the exact same _build_hollowing_report() call, never a
separately (and possibly differently) computed one.
"""
import json

import pytest

from tests.fixtures.fakes import Region, Module, Peb, FakeStream, FakeMF, mem_reader

import dumpex.hunt.hollowing as hollowing
from dumpex.hunt.hollowing import collect_hollowing_record
from dumpex.output.records import HunterRecord, HollowingDetails

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import schema_path


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path("dumpex-output-v2.7.schema.json") as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/hunterRecord", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def _assert_matches_console_dict(rec: HunterRecord, console_dict: dict):
    assert rec.score == console_dict["score"]
    assert rec.max_score == console_dict["max_score"]
    assert rec.status == console_dict["status"]
    assert rec.verdict_level == console_dict["verdict_level"]
    assert rec.confidence == console_dict["confidence"]
    assert rec.lead_count == console_dict["lead_count"]
    assert rec.review_priority == console_dict["review_priority"]
    assert rec.findings == console_dict["findings"]


def test_no_peb_is_not_evaluated(hunter_record_validator):
    class MF(FakeMF):
        peb = None
    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "hollowing"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "not_evaluated"
    assert isinstance(rec.details, HollowingDetails)
    assert rec.details.image_base is None
    assert rec.details.mem_private_at_base is None
    assert rec.details.mz_header_present is None
    assert rec.details.is_rwx_at_base is None
    assert rec.details.peb_image_path is None
    assert rec.details.module_name is None
    assert rec.details.name_mismatch is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_image_base_region_not_captured_is_inconclusive(hunter_record_validator):
    image_base = 0x140000000
    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")
        memory_info = FakeStream([], "infos")
    hollowing.read_region = mem_reader({})

    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert rec.details.mem_private_at_base is None
    assert rec.details.is_rwx_at_base is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_mz_read_failure_is_partial_and_mz_header_present_is_null(hunter_record_validator):
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")

    def flaky_reader(mf, addr, size):
        raise OSError("simulated read failure")
    hollowing.read_region = flaky_reader

    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    assert rec.details.mz_header_present is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_module_list_unavailable_is_partial_and_name_mismatch_is_null(hunter_record_validator):
    image_base = 0x140000000
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.details.name_mismatch is None
    assert rec.details.module_name is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_fully_clean_scores_0(hunter_record_validator):
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert rec.coverage.status.value == "complete"
    assert rec.details.image_base == "0x0000000140000000"
    assert rec.details.mem_private_at_base is False
    assert rec.details.mz_header_present is True
    assert rec.details.is_rwx_at_base is False
    assert rec.details.module_name == r"C:\Windows\System32\legit.exe"
    assert rec.details.name_mismatch is False
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_mem_private_plus_mz_wiped_correlates_detected(hunter_record_validator):
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})

    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 1
    assert rec.status == "DETECTED"
    assert rec.details.mem_private_at_base is True
    assert rec.details.mz_header_present is False
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_all_signals_correlate_scores_2_high_confidence(hunter_record_validator):
    image_base = 0x140000000
    other_base = 0x150000000
    other_module = Module(other_base, 0x5000, r"C:\Windows\System32\other.dll")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([other_module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})

    console_dict = hollowing._hunt_hollowing(MF(), verbose=False)
    rec = collect_hollowing_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 2
    assert rec.status == "DETECTED"
    assert rec.verdict_level == "high"
    assert rec.details.is_rwx_at_base is True
    assert rec.details.mem_private_at_base is True
    assert rec.details.module_name is None      # image_base not in the module list
    assert rec.details.name_mismatch is True    # module list WAS available, just no match
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []
