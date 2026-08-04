"""
Unit tests for dumpex.hunt.yara_hunt.collect.collect_yara_record() --
PR2b's HunterRecord-producing path for the yara hunter. Every scenario
here mirrors tests/hunt/test_yara_hunt.py's own fixtures (same literal
inputs), confirming collect_yara_record() and the console path
(_hunt_yara()) always agree on the same underlying Report.

Needs the real yara-python package -- skipped (not failed) when it
isn't present, same as test_yara_hunt.py.
"""
import json
import os
import tempfile

import pytest

pytest.importorskip("yara")

from tests.fixtures.fakes import Segment, FakeReader, FakeStream, FakeMF

import dumpex.hunt.yara_hunt as yara_hunt
from dumpex.hunt.yara_hunt.collect import collect_yara_record
from dumpex.output.records import HunterRecord, YaraDetails

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import schema_path


def _write_rule(d, name, body):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(body)


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path("dumpex-output-v2.4.schema.json") as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/hunterRecord", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def _assert_matches_console_dict(rec: HunterRecord, console_dict: dict):
    assert rec.score == console_dict["score"]
    assert rec.status == console_dict["status"]
    assert rec.verdict_level == console_dict["verdict_level"]
    assert rec.max_score is None
    assert rec.confidence is None
    assert rec.lead_count is None
    assert rec.review_priority is None
    assert rec.findings == []


def test_no_rules_directory_is_not_evaluated(hunter_record_validator):
    class MF(FakeMF):
        memory_segments_64 = FakeStream([], "memory_segments")

    with tempfile.TemporaryDirectory() as d:
        empty_dir = os.path.join(d, "does_not_exist")
        console_dict = yara_hunt._hunt_yara(MF(), rules_dir=empty_dir, verbose=False)
        rec = collect_yara_record(MF(), rules_dir=empty_dir)

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "yara"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_EVALUATED"
    assert rec.coverage.status.value == "not_evaluated"
    assert isinstance(rec.details, YaraDetails)
    assert rec.details.matches == []
    assert rec.details.rules_hit == []
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_clean_scan_no_matches_is_not_detected(hunter_record_validator):
    seg_va, seg_fo = 0x40000, 0x4000
    data = b'\x00' * 0x1000
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "never.yar",
                    'rule NeverMatches { strings: $a = "NOPE_NEVER_SEEN" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})

        console_dict = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)
        rec = collect_yara_record(MF(), rules_dir=d)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert rec.coverage.status.value == "complete"
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_matching_rule_is_detected(hunter_record_validator):
    seg_va, seg_fo = 0x50000, 0x5000
    data = b'A' * 0x100 + b'FINDME_MARKER' + b'B' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "hit.yar",
                    'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})

        console_dict = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)
        rec = collect_yara_record(MF(), rules_dir=d)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "DETECTED"
    assert rec.score == 1
    assert "HitRule" in rec.details.rules_hit
    assert len(rec.details.matches) == 1
    match = rec.details.matches[0]
    assert match["seg_va"] == f"0x{seg_va:016x}"
    assert len(match["strings"]) >= 1
    for sv in match["strings"]:
        assert isinstance(sv["data"], str)   # hex-encoded, never raw bytes
        assert sv["va"].startswith("0x")
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_segment_read_failure_makes_result_inconclusive(hunter_record_validator):
    good_va, good_fo = 0x20000, 0x2000
    bad_va, bad_fo   = 0x30000, 0x3000
    data = b'\x00' * 0x1000
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        good_seg = Segment(good_va, good_fo, len(data))
        bad_seg  = Segment(bad_va, bad_fo, 0x1000)

        class FlakyReader:
            def read(self, addr, size):
                if addr == bad_va:
                    raise OSError("simulated unreadable segment")
                return data

        class MF(FakeMF):
            memory_segments_64 = FakeStream([good_seg, bad_seg], "memory_segments")
            _reader                = FlakyReader()

        console_dict = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)
        rec = collect_yara_record(MF(), rules_dir=d)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "SCAN_REGION_READ_FAILED" for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []
