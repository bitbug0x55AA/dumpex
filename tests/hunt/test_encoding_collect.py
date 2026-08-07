"""
Unit tests for dumpex.hunt.encoding.collect.collect_obfuscation_record() --
PR2b's HunterRecord-producing path for the obfuscation hunter. Every
scenario here mirrors tests/hunt/test_encoding.py's own fixtures (same
literal inputs), confirming collect_obfuscation_record() and the console
path (_hunt_encoding()) always agree on the same underlying Report.
"""
import base64
import json
import random

import pytest

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding
from dumpex.hunt.encoding.collect import collect_obfuscation_record
from dumpex.output.records import HunterRecord, ObfuscationDetails

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


def test_call_pop_prefix_never_scores(hunter_record_validator):
    random.seed(2)
    region_base = 0x400000
    shellcode_prefix = b'\xe8\x00\x00\x00\x00\x58'
    payload = shellcode_prefix + bytes(random.getrandbits(8) for _ in range(200))
    b64_payload = base64.b64encode(payload)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    console_dict = encoding._hunt_encoding(MF(), verbose=False)
    rec = collect_obfuscation_record(MF())

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "obfuscation"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 0
    assert isinstance(rec.details, ObfuscationDetails)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_validated_pe_still_scores(hunter_record_validator):
    region_base = 0x300000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_pe.ljust(0x1000, b'\x00')})

    console_dict = encoding._hunt_encoding(MF(), verbose=False)
    rec = collect_obfuscation_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 1
    assert rec.confidence == "high"
    assert rec.coverage.status.value == "complete"
    hidden_pe = rec.details.hidden_pe
    assert len(hidden_pe) == 1
    hit = hidden_pe[0]
    assert isinstance(hit["decoded"], str)   # hex-encoded, never raw bytes
    assert hit["region"]["base_address"] == f"0x{region_base:016x}"
    assert isinstance(hit["region"]["state"], str)   # enum reduced to plain string
    assert isinstance(hit["region"]["protect"], str)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_sleep_mask_layer_short_read_makes_result_inconclusive(hunter_record_validator):
    region_base = 0x500000
    declared_size = 0x2000
    actual_bytes  = b'\x00' * 0x400
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: actual_bytes})

    console_dict = encoding._hunt_encoding(MF(), verbose=False)
    rec = collect_obfuscation_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 0
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "SCAN_REGION_SHORT_READ" for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []
