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
from dumpex.hunt.cs_beacon.models import ConfigField, ConfigEvidence
from dumpex.hunt.cs_beacon.parser import _cs_decode_and_parse_tlv
from dumpex.hunt.cs_beacon.report_facts import field_dict as _field_dict, name_keyed_fields
from dumpex.output.records import HunterRecord, CsBeaconDetails


def _mk_segment_data(config: bytes, pad_before: int = 0) -> bytes:
    return b"\x00" * pad_before + config + b"\x00" * 0x100


jsonschema = pytest.importorskip("jsonschema")
from dumpex.output.envelope import SCHEMA_VERSION
from dumpex.schemas import CURRENT_SCHEMA, schema_path


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path("dumpex-output-v2.12.schema.json") as path, open(path, encoding="utf-8") as fh:
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
    # schema_version 2.7: fields is keyed by NAME, not the numeric TLV
    # field ID string -- cs_beacon_config_bytes() is documented to embed
    # exactly BeaconType (0x0001) and PublicKey (0x0007).
    assert set(cfg["fields"]) == {"BeaconType", "PublicKey"}
    assert not any(k.lstrip("-").isdigit() for k in cfg["fields"]), (
        "no field key may be a bare numeric string -- that was the pre-2.7 shape")
    for field in cfg["fields"].values():
        # v2 public output (schema_version 2.7+) carries only type/value --
        # `name` is redundant now that the dict KEY is the name, and `raw`
        # was already dropped in 2.6 (PublicKey/Malleable C2/inject-
        # transform fields could otherwise carry very long hex strings here).
        assert set(field.keys()) == {"type", "value"}
        assert isinstance(field["type"], int)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []

    # The internal parser result (never exposed to v2 JSON) must still
    # carry `raw` as bytes -- DER public-key validation
    # (fields[0x0007]["raw"]) and Malleable C2 instruction decoding both
    # depend on it. This guards against ever deleting `raw` from the
    # parser itself while trimming it from the public output shape.
    parsed = _cs_decode_and_parse_tlv(data, 0, 0x69, len(data))
    assert parsed["complete"] is True
    assert parsed["fields"]
    for fid, field in parsed["fields"].items():
        assert isinstance(field["raw"], bytes)
    assert isinstance(parsed["fields"][0x0007]["raw"], bytes)


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


# ── schema_version 2.7 shape: reviewer-requested expanded coverage ────────
# (more than "two known fields happen to pass"). The cs-beacon field
# shape below was introduced in 2.7 and is unchanged in 2.8; the identity
# check right underneath tracks whatever the CURRENT schema file is.

def test_current_schema_id_title_and_version_const_all_agree():
    """Not just 'a document happens to validate' -- the schema FILE ITSELF
    must actually claim to be the current version in every place that
    matters, or a producer stamping schema_version 2.8 would validate
    against a schema whose own meta.schema_version.const still says 2.7
    and fail. Asserted against SCHEMA_VERSION/CURRENT_SCHEMA rather than a
    second hardcoded copy of the number, so the next bump can't leave this
    test silently pinned to the previous one."""
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    assert CURRENT_SCHEMA == f"dumpex-output-v{SCHEMA_VERSION}.schema.json"
    assert schema["$id"].endswith(CURRENT_SCHEMA)
    assert SCHEMA_VERSION in schema["title"]
    assert schema["$defs"]["meta"]["properties"]["schema_version"]["const"] == SCHEMA_VERSION


def _fields_validator():
    with schema_path("dumpex-output-v2.12.schema.json") as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/csBeaconDetails", "$defs": schema["$defs"]}
    return jsonschema.Draft202012Validator(wrapper)


def test_name_keyed_shape_validates_against_v2_7():
    details = {
        "configs": [{"fields": {"BeaconType": {"type": 1, "value": 0},
                                 "field_0x004a": {"type": 3, "value": "ff"}}}],
        "config_count": 1,
    }
    assert list(_fields_validator().iter_errors(details)) == []


def test_old_numeric_keyed_name_carrying_shape_is_rejected_by_v2_7():
    # The pre-2.7 (schema_version 2.6) shape -- proves the new
    # propertyNames/additionalProperties constraint actually bites, not
    # just that the new shape happens to pass.
    details = {
        "configs": [{"fields": {"1": {"name": "BeaconType", "type": 1, "value": 0}}}],
        "config_count": 1,
    }
    assert list(_fields_validator().iter_errors(details)) != []


def test_unknown_field_id_produces_field_0xnnnn_key_and_validates(hunter_record_validator):
    seg_va, seg_fo = 0xa0000, 0xa000
    # Start from the same valid (BeaconType + validated PublicKey +
    # terminator) config _cs_sanity_check() actually accepts -- a
    # synthetic blob with only an unknown field never passes that check
    # at all, so it would never reach `fields` as a scored hit -- and
    # splice an unrecognized field ID (0x004a, one past MaxRetry_Duration,
    # the highest entry in CS_FIELD_NAMES) in before the terminator.
    import struct
    base = cs_beacon_config_bytes(0x69)
    decoded = bytes(b ^ 0x69 for b in base)
    terminator = struct.pack('>H', 0)
    assert decoded.endswith(terminator)
    body = decoded[:-len(terminator)]
    unknown_field = struct.pack('>HHH', 0x004a, 1, 2) + struct.pack('>H', 7)
    plaintext = body + unknown_field + terminator
    config = bytes(b ^ 0x69 for b in plaintext)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    rec = collect_cs_beacon_record(MF())
    assert len(rec.details.configs) == 1
    fields = rec.details.configs[0]["fields"]
    assert "field_0x004a" in fields
    assert fields["field_0x004a"] == {"type": 1, "value": 7}
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_name_keyed_fields_raises_on_field_name_collision():
    # CS_FIELD_NAMES has no real collision today (verified separately),
    # so this forces one synthetically: two different field IDs whose
    # resolved `name` happens to be identical.
    hit = ConfigEvidence(
        xor_key=0x69, hit_va=0x1000, hit_fo=0, cs_version="3.x",
        fields=(
            ConfigField(field_id=0x0001, name="SameName", type=1, value=0, raw=b""),
            ConfigField(field_id=0x0002, name="SameName", type=1, value=1, raw=b""),
        ),
    )
    with pytest.raises(ValueError, match="collision"):
        name_keyed_fields(hit)


def test_field_dict_never_includes_name():
    f = ConfigField(field_id=0x0001, name="BeaconType", type=1, value=0, raw=b"\x00\x00")
    assert set(_field_dict(f)) == {"type", "value"}


def test_no_is_text_or_similar_leaks_into_legacy_dict_or_hunter_record():
    # is_text (the printable/binary decision -- see parser.py's
    # _cs_decode_type3_value) is computed on demand from `raw` at
    # console-render time and never stored on the parser's own field
    # dict, so it can never reach either the legacy _hunt_cs_beacon()
    # Python return value or the HunterRecord/v2 JSON.
    seg_va, seg_fo = 0xc0000, 0xc000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    legacy = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    for cfg in legacy["configs"]:
        for field in cfg["fields"].values():
            assert "is_text" not in field
            assert set(field) == {"name", "type", "raw", "value"}

    rec = collect_cs_beacon_record(MF())
    for cfg in rec.details.configs:
        for field in cfg["fields"].values():
            assert "is_text" not in field
            assert set(field) == {"type", "value"}


def test_oversized_segment_skip_identifies_the_segment(monkeypatch, hunter_record_validator):
    """`CS_MAX_SEG_SCAN` shrunk below this segment's own size, so it's
    skipped without ever being read. The limitation must name the segment
    (VA, size, dump-file offset) and the cap it exceeded -- an aggregate
    count alone tells an analyst coverage is partial but not which
    address still needs a targeted rescan or a wider recollection."""
    seg_va, seg_fo = 0x40000, 0x4000
    seg_size = 0x8000
    seg = Segment(seg_va, seg_fo, seg_size)

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream([], "infos")
        _reader                = FakeReader({})

    # Read off cs_beacon's own re-exported global when CSBeaconConfig is
    # built (see that module's comment) -- patched there, not in config.py.
    monkeypatch.setattr(cs_beacon, "CS_MAX_SEG_SCAN", 0x1000)

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert lim.source == "segment_scan"
    assert lim.affected_count == 1 == len(lim.targets)
    target = lim.targets[0]
    # A segment-table entry carries no MemoryInfo, so those fields stay
    # unset -- but its own start_file_address IS the dump-file offset.
    assert target.kind.value == "memory_segment"
    assert (target.base_address, target.size, target.size_limit) == (seg_va, seg_size, 0x1000)
    assert target.file_offset == seg_fo
    assert (target.allocation_base, target.state, target.type, target.protection) == (
        None, None, None, None)
    # The rendered text must say "segment(s)", never "region(s)" -- the
    # target is a Memory64List segment, not a MemoryInfo region, and the
    # code's own NAME (SCAN_REGION_OVERSIZED_SKIPPED) must not leak a
    # wrong noun into either coverage.reasons or the console verdict.
    reason = next(r for r in rec.coverage.reasons if "oversized" in r)
    assert "segment(s)" in reason
    assert "region(s)" not in reason
    assert reason in console_dict["coverage_reasons"]
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_budget_exhausted_identifies_the_unstarted_segments(monkeypatch, hunter_record_validator):
    """issue #28 P5 follow-up: a scan deadline discovered before segment 0
    even starts must name BOTH segment 0 (mid-processing/never started)
    and segment 1 (never started at all) as targets, not just report a
    bare count."""
    n_segs = 2
    seg_size = 0x1000
    segs = []
    read_map = {}
    for i in range(n_segs):
        va = 0x73000000 + i * 0x100000
        segs.append(Segment(va, va, seg_size))
        read_map[va] = b'\x00' * seg_size

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segs, "memory_segments")
        memory_info          = FakeStream([], "infos")
        _reader                = FakeReader(read_map)

    calls = {"n": 0}

    def fake_monotonic():
        calls["n"] += 1
        return calls["n"] * (cs_beacon.CS_SCAN_DEADLINE_SECONDS * 2)

    monkeypatch.setattr(cs_beacon.time, "monotonic", fake_monotonic)

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())
    _assert_matches_console_dict(rec, console_dict)

    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "CS_BEACON_SCAN_BUDGET_EXHAUSTED")
    assert lim.affected_count == 2 == len(lim.targets)
    assert {t.base_address for t in lim.targets} == {segs[0].start_virtual_address,
                                                        segs[1].start_virtual_address}
    assert all(t.kind.value == "memory_segment" for t in lim.targets)
    # issue #28 P6 follow-up: the structured budget fact too.
    assert lim.scope == "scan_deadline_seconds"
    assert lim.budget_limit == cs_beacon.CS_SCAN_DEADLINE_SECONDS
    # issue #28 review follow-up: budget_consumed is the REAL elapsed
    # wall-clock time (measured via the fake clock above), not assumed
    # equal to the configured limit -- this fake clock's own stride
    # overshoots the deadline by exactly one more full "tick" of it.
    assert lim.budget_consumed == 2 * cs_beacon.CS_SCAN_DEADLINE_SECONDS
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_max_candidates_budget_reports_its_own_kind(monkeypatch, hunter_record_validator):
    # issue #28 P6 follow-up: CS_BEACON_SCAN_BUDGET_EXHAUSTED can stop on
    # any of FIVE independent resources -- max_candidates is a different
    # one from the deadline the test above exercises.
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 5)
    seg_va, seg_fo = 0xd0000, 0xd000
    data = cs_beacon.CS_SIG_XOR69 * 50   # far more than the 5-candidate budget

    class MF(FakeMF):
        memory_segments_64 = FakeStream([Segment(seg_va, seg_fo, len(data))], "memory_segments")
        memory_info          = FakeStream([], "infos")
        _reader                = FakeReader({seg_va: data})

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())
    _assert_matches_console_dict(rec, console_dict)

    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "CS_BEACON_SCAN_BUDGET_EXHAUSTED")
    assert lim.scope == "max_candidates"
    assert lim.budget_limit == 5
    # issue #28 review follow-up: total_candidates is incremented BEFORE
    # the `> config.max_candidates` check runs, so the real consumption
    # at the moment the budget is attributed is limit + 1, not the limit
    # itself.
    assert lim.budget_consumed == 6
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_budget_exhausted_on_last_segment_after_it_finished_has_no_targets(
        monkeypatch, hunter_record_validator):
    """issue #28 P5 follow-up (targets): when the deadline is only
    discovered AFTER the one (and only, and therefore last) segment has
    already finished its own candidate scan cleanly, there is genuinely
    nothing left to name -- the underlying ScanOutcome's own
    budget_exhausted_targets stays empty, not claiming a target that
    doesn't exist.

    issue #28 review follow-up (coverage semantics): an empty target list
    here means there is no real coverage gap at all -- a deadline noticed
    only after full, clean coverage is wall-clock telemetry, not a
    partial result. No CS_BEACON_SCAN_BUDGET_EXHAUSTED limitation must be
    constructed, and the result must come back exactly as clean/complete
    as it would have if the deadline check had never fired."""
    seg_size = 0x100
    va = 0x74000000
    seg = Segment(va, va, seg_size)
    regions = [Region(va, va, seg_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({va: b'\x00' * seg_size})

    # scan_deadline=10; top-of-loop ok; post-segment recheck fails -- a
    # fresh sequence per call, since _hunt_cs_beacon and
    # collect_cs_beacon_record each independently re-run the whole scan.
    def _install_fake_clock():
        times = iter([0, 1, 1000])
        monkeypatch.setattr(cs_beacon.time, "monotonic", lambda: next(times))

    monkeypatch.setattr(cs_beacon, "CS_SCAN_DEADLINE_SECONDS", 10)

    _install_fake_clock()
    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    _install_fake_clock()
    rec = collect_cs_beacon_record(MF())
    _assert_matches_console_dict(rec, console_dict)

    assert not any(l.code.value == "CS_BEACON_SCAN_BUDGET_EXHAUSTED"
                   for l in rec.coverage.limitations)
    assert rec.coverage.status.value == "complete"
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert console_dict["coverage_status"] == "complete"
    assert console_dict["coverage_reasons"] == []
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_multiple_oversized_segments_preview_truncates_but_json_stays_complete(
        monkeypatch, hunter_record_validator):
    """Four segments over the cap: the rendered console/coverage_reasons
    preview stops at three and points at --json, but every one of the
    four skipped segments is still present in the structured targets
    list -- the console truncation must never lose data only the JSON
    consumer can see."""
    segs = [Segment(0x10000 * (i + 1), 0x1000 * (i + 1), 0x9000) for i in range(4)]

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segs, "memory_segments")
        memory_info          = FakeStream([], "infos")
        _reader                = FakeReader({})

    monkeypatch.setattr(cs_beacon, "CS_MAX_SEG_SCAN", 0x1000)

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert lim.affected_count == 4 == len(lim.targets)
    assert {t.base_address for t in lim.targets} == {s.start_virtual_address for s in segs}

    reason = next(r for r in rec.coverage.reasons if "oversized" in r)
    assert "4 oversized segment(s) skipped" in reason
    assert "+1 more (see coverage.limitations[].targets in --json output)" in reason
    assert reason in console_dict["coverage_reasons"]
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


class _RaisingReader:
    """A `reader.read(addr, size)` stand-in that always raises -- unlike
    `FakeReader`, which returns `b''` for an unmapped address (a SHORT
    read, not a genuine failure)."""
    def read(self, addr, size):
        raise OSError("simulated read failure")


def test_segment_read_failure_identifies_the_segment(hunter_record_validator):
    """issue #28: SCAN_REGION_READ_FAILED retains the failed segment's own
    identity, the same way SCAN_REGION_OVERSIZED_SKIPPED already does."""
    seg_va, seg_fo, seg_size = 0x50000, 0x5000, 0x8000
    seg = Segment(seg_va, seg_fo, seg_size)

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream([], "infos")
        _reader                = _RaisingReader()

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations if l.code.value == "SCAN_REGION_READ_FAILED")
    assert lim.affected_count == 1 == len(lim.targets)
    target = lim.targets[0]
    assert target.kind.value == "memory_segment"
    assert (target.base_address, target.size) == (seg_va, seg_size)
    assert target.file_offset == seg_fo
    assert target.size_limit is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_segment_short_read_identifies_the_segment(hunter_record_validator):
    seg_va, seg_fo, seg_size = 0x60000, 0x6000, 0x8000
    seg = Segment(seg_va, seg_fo, seg_size)

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream([], "infos")
        # Fewer bytes mapped than the segment's own declared size -> short read.
        _reader                = FakeReader({seg_va: b"\x00" * 0x100})

    console_dict = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    rec = collect_cs_beacon_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations if l.code.value == "SCAN_REGION_SHORT_READ")
    assert lim.affected_count == 1 == len(lim.targets)
    target = lim.targets[0]
    assert (target.base_address, target.size) == (seg_va, seg_size)
    assert target.size_limit is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []
