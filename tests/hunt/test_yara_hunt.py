"""
Hunter-level tests for dumpex.hunt.yara_hunt (_hunt_yara), focused on the
failure/coverage paths this module previously had almost no test coverage
for: no rules directory, all rule files failing to compile, missing
memory segments, segment read failures, and match() raising outside of a
timeout -- none of these may be silently indistinguishable from "scanned,
clean".

Needs the real yara-python package to actually compile a rule file — it's
an optional ("full") dependency, not part of the base dev install, so
this whole module is skipped (not failed) when it isn't present.
"""
import os
import tempfile

import pytest

pytest.importorskip("yara")

from tests.fixtures.fakes import Region, Segment, FakeReader, FakeStream, FakeMF

import dumpex.hunt.yara_hunt as yara_hunt


def _write_rule(d, name, body):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(body)


# ── no rules directory found ────────────────────────────────────────────

def test_no_rules_directory_is_not_evaluated():
    f = yara_hunt._hunt_yara(FakeMF(), rules_dir="/definitely_not_a_real_dir_xyz123", verbose=False)
    assert f["status"] == "NOT_EVALUATED"
    assert f["score"] == 0


def test_empty_rules_directory_is_not_evaluated():
    with tempfile.TemporaryDirectory() as d:
        f = yara_hunt._hunt_yara(FakeMF(), rules_dir=d, verbose=False)
    assert f["status"] == "NOT_EVALUATED"


def test_all_rule_files_fail_to_compile_is_not_evaluated():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "bad.yar", "rule Bad { condition: this is not valid yara }")
        f = yara_hunt._hunt_yara(FakeMF(), rules_dir=d, verbose=False)
    assert f["status"] == "NOT_EVALUATED"


# ── no memory segments in the dump ──────────────────────────────────────

def test_no_memory_segments_is_not_evaluated():
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", "rule Good { strings: $a = \"nomatch\" condition: $a }")

        class MF(FakeMF):
            memory_segments_64 = None
            memory_segments      = None
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)
    assert f["status"] == "NOT_EVALUATED"


# ── clean scan (rules compile, segments scanned, nothing matches) ──────

def test_clean_scan_no_matches_is_not_detected():
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x1000
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["score"] == 0
    assert f["coverage"]["rule_files_compiled"] is True
    assert f["coverage"]["segments_read"] is True


# ── segment read failure must be counted, not silently dropped ────────

def test_segment_read_failure_makes_result_inconclusive():
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
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage"]["segments_read"] is False


# ── an oversized segment is skipped, not silently scanned/dropped ──────

def test_oversized_segment_is_skipped_and_makes_result_inconclusive():
    seg_va, seg_fo = 0x40000, 0x4000
    huge_size = yara_hunt.CS_MAX_SEG_SCAN + 1
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg = Segment(seg_va, seg_fo, huge_size)

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage"]["segments_size_ok"] is False


# ── a genuine rule match is detected and scored ─────────────────────────

def test_matching_rule_is_detected():
    seg_va, seg_fo = 0x50000, 0x5000
    data = b'A' * 0x100 + b'FINDME_MARKER' + b'B' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "hit.yar",
                    'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "DETECTED"
    assert f["score"] == 1
    assert "HitRule" in f["rules_hit"]
    assert len(f["matches"]) == 1


# ── a match() call that raises something OTHER than a timeout must be ──
# counted as a coverage gap, not silently treated as "ran, no match" ────

def test_match_failure_makes_result_inconclusive(monkeypatch):
    seg_va, seg_fo = 0x60000, 0x6000
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})

        class BoomCompiled:
            def match(self, data, timeout):
                raise RuntimeError("simulated internal YARA error")

        monkeypatch.setattr(yara_hunt, "_load_yara_rules",
                             lambda rules_dir: ([("good.yar", BoomCompiled())], 0))
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage"]["matches_completed"] is False
