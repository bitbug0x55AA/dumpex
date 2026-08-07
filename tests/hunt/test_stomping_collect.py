"""
Unit tests for dumpex.hunt.stomping.collect.collect_stomping_record() --
PR2b's HunterRecord-producing path for the stomping hunter. Every
scenario here mirrors tests/hunt/test_stomping.py's own fixtures (same
literal inputs), confirming collect_stomping_record() and the console
path (_hunt_stomping()) always agree on the same underlying Report.
"""
import json
import os
import tempfile

import pytest

from tests.fixtures.fakes import (Region, Module, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader, matching_module_and_ref)

import dumpex.hunt.stomping as stomping
from dumpex.hunt.stomping.collect import collect_stomping_record
from dumpex.output.records import HunterRecord, StompingDetails

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import schema_path


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path("dumpex-output-v2.6.schema.json") as path, open(path, encoding="utf-8") as fh:
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


def test_normal_writecopy_is_clean(hunter_record_validator):
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
        console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec = collect_stomping_record(MF(), ref_dir=d)

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "stomping"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert rec.coverage.status.value == "complete"
    assert isinstance(rec.details, StompingDetails)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_no_ref_dir_is_inconclusive_partial(hunter_record_validator):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    rec = collect_stomping_record(MF(), ref_dir=None)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "STOMPING_REFERENCE_NOT_SUPPLIED"
               for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_all_headers_invalid_is_partial(hunter_record_validator):
    module_base = 0x7ff600000000
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base, module_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: b"not a real PE header"})

    console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    rec = collect_stomping_record(MF(), ref_dir=None)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "MODULE_HEADER_PARSE_FAILED"
               for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_verified_change_scores_1_then_2_with_rip(hunter_record_validator):
    module_base = 0x7ff600000000
    timestamp = 0x11111111
    sections = [{"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
                 "rawsize": 0x2000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}]
    header = build_pe_header(sections, timestamp=timestamp, size_of_image=0x5000,
                              image_base=module_base)

    text_original = bytes((i * 7) % 251 for i in range(0x2000))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (sections[0]["rawptr"] - len(ref_file))
    ref_file += text_original

    mem_text = bytearray(text_original)
    mem_text[0x100:0x110] = b'\xCC' * 0x10

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]
    read_map = {module_base: header, module_base + 0x1000: bytes(mem_text)}

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))

        stomping.read_region = mem_reader(read_map)
        stomping.get_thread_contexts = lambda mf: []
        console_dict1 = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec1 = collect_stomping_record(MF(), ref_dir=d)
        _assert_matches_console_dict(rec1, console_dict1)
        assert rec1.score == 1
        assert rec1.status == "DETECTED"
        assert len(rec1.details.verified_changes) == 1
        vc = rec1.details.verified_changes[0]
        assert vc["va_start"] == f"0x{module_base + 0x1000:016x}"
        assert vc["module"]["name"] == r"C:\Windows\System32\legit.dll"
        assert vc["rip_in_changed_range"] is False
        assert list(hunter_record_validator.iter_errors(rec1.to_dict())) == []

        changed_va = module_base + 0x1000 + 0x100
        stomping.get_thread_contexts = lambda mf: [{"ThreadId": 1, "ip": changed_va + 2,
                                                      "ip_reg": "RIP", "is_wow64": False}]
        console_dict2 = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec2 = collect_stomping_record(MF(), ref_dir=d)
        _assert_matches_console_dict(rec2, console_dict2)
        assert rec2.score == 2
        assert rec2.details.verified_changes[0]["rip_in_changed_range"] is True
        assert list(hunter_record_validator.iter_errors(rec2.to_dict())) == []
