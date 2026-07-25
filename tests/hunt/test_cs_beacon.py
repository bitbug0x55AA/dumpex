"""Hunter-level tests for dumpex.hunt.cs_beacon (Cobalt Strike beacon config)."""
from tests.fixtures.fakes import (Region, Segment, FakeReader, FakeStream, FakeMF,
                                   cs_beacon_config_bytes)

import dumpex.hunt.cs_beacon as cs_beacon
from dumpex.ui.structured import StructuredOutput


def _mk_segment_data(config_bytes: bytes, pad_before: int = 0x100, pad_after: int = 0x100) -> bytes:
    return b'\x00' * pad_before + config_bytes + b'\x00' * pad_after


# ── no memory segments at all -> NOT_EVALUATED, never a bare CLEAN ────────

def test_no_memory_segments_not_evaluated():
    class MF(FakeMF):
        memory_segments_64 = None
        memory_segments      = None

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_EVALUATED"
    assert f["verdict_level"] == "not_evaluated"


# ── segments present, nothing found -> NOT_DETECTED_IN_SCANNED_SCOPE ──────

def test_clean_scan_no_hits():
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x2000
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["verdict_level"] == "clean"
    assert f["coverage_status"] == "complete"


# ── missing MemoryInfoListStream must not pretend full verification even ──
# on an otherwise-clean (no hits) result -- region/context corroboration
# could not be checked, so this must be INCONCLUSIVE, not "clean".

def test_missing_mem_info_makes_coverage_partial_even_when_clean():
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x2000
    seg = Segment(seg_va, seg_fo, len(data))

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = None   # stream ABSENT
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["verdict_level"] == "inconclusive"
    assert f["coverage_status"] == "partial"
    assert any("MemoryInfoListStream" in r for r in f["coverage_reasons"])


# ── a single structurally-valid config, no context corroboration -> 1 ─────

def test_structural_config_uncorroborated_scores_1():
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    # Ordinary, non-executable, non-private region -> no corroboration signal.
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = None
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 1
    assert f["max_score"] == 2
    assert f["status"] == "DETECTED"
    assert f["verdict_level"] == "likely"
    assert f["config_count"] == 1
    assert len(f["configs"]) == 1
    assert f["configs"][0]["context_corroborated"] is False
    assert f["configs"][0]["cs_version_note"]   # estimated, not confirmed
    dets = [x for x in f["findings"] if x["tag"] == "detection"]
    assert len(dets) == 1
    assert dets[0]["confidence"] == "medium"


# ── same config, but enclosing region is executable+private -> 2 ──────────

def test_executable_private_region_corroborates_scores_2():
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

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 2
    assert f["verdict_level"] == "high"
    assert f["configs"][0]["context_corroborated"] is True
    dets = [x for x in f["findings"] if x["tag"] == "detection"]
    assert dets[0]["confidence"] == "high"


# ── a thread's current RIP executing in the same allocation also ──────────
# corroborates (not just region protection) -----------------------------

def test_rip_in_same_allocation_corroborates_scores_2():
    seg_va, seg_fo = 0x40000, 0x4000
    config = cs_beacon_config_bytes(0x69)
    pad_before = 0x100
    data = _mk_segment_data(config, pad_before=pad_before)
    seg = Segment(seg_va, seg_fo, len(data))
    # Region is ordinary (RW) -- corroboration must come from the RIP hit,
    # not region protection.
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = FakeStream([object()], "threads")   # presence only
        _reader                = FakeReader({seg_va: data})

    cs_beacon.get_thread_contexts = lambda mf: [
        {"ThreadId": 7, "ip": seg_va + 10, "ip_reg": "RIP", "is_wow64": False}
    ]
    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)

    assert f["score"] == 2
    assert f["configs"][0]["context_corroborated"] is True


# ── multiple DISTINCT hits, none corroborated -> score stays 1, never ─────
# auto-escalates from the count alone (config_count is a fact, not a
# confidence multiplier).

def test_multiple_uncorroborated_hits_stay_at_score_1():
    seg1_va, seg1_fo = 0x50000, 0x5000
    seg2_va, seg2_fo = 0x60000, 0x6000
    config1 = cs_beacon_config_bytes(0x69)
    config2 = cs_beacon_config_bytes(0x2e)
    data1 = _mk_segment_data(config1)
    data2 = _mk_segment_data(config2)
    seg1 = Segment(seg1_va, seg1_fo, len(data1))
    seg2 = Segment(seg2_va, seg2_fo, len(data2))
    regions = [
        Region(seg1_va, seg1_va, len(data1), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(seg2_va, seg2_va, len(data2), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg1_va: data1, seg2_va: data2})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["config_count"] == 2
    assert len(f["configs"]) == 2
    assert f["score"] == 1, "two distinct uncorroborated hits must not escalate to 2"
    assert f["verdict_level"] == "likely"


# ── a segment read failure must be counted as a coverage gap, not ─────────
# silently dropped: a "clean" result achieved only because a segment could
# never actually be read must not read as a genuine NOT_DETECTED_IN_SCANNED_SCOPE.

def test_read_failed_segment_makes_result_inconclusive():
    good_va, good_fo = 0x70000, 0x7000
    bad_va, bad_fo   = 0x80000, 0x8000
    data = b'\x00' * 0x1000
    good_seg = Segment(good_va, good_fo, len(data))
    bad_seg  = Segment(bad_va, bad_fo, 0x1000)
    regions = [Region(good_va, good_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class FlakyReader:
        def read(self, addr, size):
            if addr == bad_va:
                raise OSError("simulated unreadable segment")
            return data

    class MF(FakeMF):
        memory_segments_64 = FakeStream([good_seg, bad_seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FlakyReader()

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert any("failed to read" in r for r in f["coverage_reasons"])


# ── the ACTUAL hunter output (not a mock) round-trips through structured.py ─
# with the identical verdict_level it reports itself -- console and JSON/CSV
# must never disagree on the same result.

def test_real_hunter_output_verdict_level_matches_structured_output():
    seg_va, seg_fo = 0x90000, 0x9000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    result = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert result["verdict_level"] == "high"

    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    row = out._section_to_tables("hunt", {"cs-beacon": result})["summary"][0]
    assert row["verdict_level"] == result["verdict_level"]
    assert row["verdict"] == result["verdict_level"].upper()
