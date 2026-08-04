"""
Unit tests for dumpex.hunt.cs_beacon.collect.collect_cs_beacon_record() --
PR2b's HunterRecord-producing path for the cs-beacon hunter. Every
scenario here mirrors tests/hunt/test_cs_beacon.py's own fixtures (same
literal inputs), confirming collect_cs_beacon_record() and the console
path (_hunt_cs_beacon()) always agree on the same underlying Report.
"""
import json

import pytest

from tests.fixtures.fakes import Region, Segment, FakeStream, FakeMF, FakeReader, cs_beacon_config_bytes

import dumpex.hunt.cs_beacon as cs_beacon
from dumpex.hunt.cs_beacon.collect import collect_cs_beacon_record
from dumpex.output.records import HunterRecord, CsBeaconDetails


def _mk_segment_data(config: bytes, pad_before: int = 0) -> bytes:
    return b"\x00" * pad_before + config + b"\x00" * 0x100


jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import schema_path


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path("dumpex-output-v2.4.schema.json") as path, open(path, encoding="utf-8") as fh:
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


def test_no_memory_segments_not_evaluated(hunter_record_validator):
    class MF(FakeMF):
        memory_segments_64 = None
        memory_segments      = None

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "cs-beacon"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_EVALUATED"
    assert rec.coverage.status.value == "not_evaluated"
    assert isinstance(rec.details, CsBeaconDetails)
    assert rec.details.configs == []
    assert rec.details.config_count == 0
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_clean_scan_no_hits(hunter_record_validator):
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x2000
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert rec.coverage.status.value == "complete"
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_missing_mem_info_makes_coverage_partial_even_when_clean(hunter_record_validator):
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x2000
    seg = Segment(seg_va, seg_fo, len(data))

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = None
        _reader                = FakeReader({seg_va: data})

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert any(lim.source == "memory_info" for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_structural_config_uncorroborated_scores_1(hunter_record_validator):
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = None
        _reader                = FakeReader({seg_va: data})

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 1
    assert rec.status == "DETECTED"
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "THREAD_CONTEXT_UNAVAILABLE" for lim in rec.coverage.limitations)
    assert len(rec.details.configs) == 1
    cfg = rec.details.configs[0]
    assert cfg["va"] == f"0x{seg_va:016x}"
    assert cfg["context_corroborated"] is False
    assert isinstance(cfg["fields"], dict)
    assert all(isinstance(k, str) for k in cfg["fields"])
    for field in cfg["fields"].values():
        assert isinstance(field["raw"], str)   # hex-encoded, never raw bytes
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_executable_private_region_corroborates_scores_2(hunter_record_validator):
    seg_va, seg_fo = 0x30000, 0x3000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 2
    assert rec.coverage.status.value == "complete"
    assert rec.details.configs[0]["context_corroborated"] is True
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []
