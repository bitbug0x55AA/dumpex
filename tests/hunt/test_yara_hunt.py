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
    # Required by the JSON schema's hunterResultBase (all 7 hunters,
    # including yara) -- a clean result must still carry these, not just
    # yara's own internal "coverage" dict.
    assert f["coverage_status"] == "complete"
    assert f["verdict_level"] == "clean"


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
    assert f["coverage_status"] == "partial"
    assert f["verdict_level"] == "inconclusive"


# ── a short read (fewer bytes than the segment's declared size) must ──────
# count as a coverage gap, not read as "scanned, clean" (mirrors
# dumpex/hunt/cs_beacon/'s identical check on the same reader.read() pattern)

def test_short_read_segment_makes_result_inconclusive():
    seg_va, seg_fo = 0x21000, 0x2100
    declared_size = 0x1000
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg = Segment(seg_va, seg_fo, declared_size)

        class ShortReader:
            def read(self, addr, size):
                return b'\x00' * (size // 2)   # always returns half of what's asked
        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = ShortReader()
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage"]["segments_short_read"] is False
    assert f["coverage_status"] == "partial"


# ── the whole-scan budget (time/total bytes) must bound the ENTIRE scan, ──
# not just a single (segment, rule-file) match() call -- many segments must
# not be able to run past it unbounded even if every match() call itself
# stays well inside YARA_MATCH_TIMEOUT

def test_scan_byte_budget_exhaustion_makes_result_inconclusive(monkeypatch):
    monkeypatch.setattr(yara_hunt, "YARA_MAX_TOTAL_BYTES_SCANNED", 10)
    seg1_va, seg1_fo = 0x22000, 0x2200
    seg2_va, seg2_fo = 0x23000, 0x2300
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg1 = Segment(seg1_va, seg1_fo, len(data))
        seg2 = Segment(seg2_va, seg2_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
            _reader                = FakeReader({seg1_va: data, seg2_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage"]["scan_budget_ok"] is False
    assert f["coverage_status"] == "partial"
    # the first segment's read (0x100 bytes) already exceeds the 10-byte
    # cap, so the second segment must never have been scanned at all.
    assert f["coverage"]["rule_files_compiled"] is True


def test_scan_byte_budget_exceeded_by_the_only_segment_still_marks_exhausted(monkeypatch):
    # The exact gap this closes: with only ONE (or the LAST) segment, there
    # is no subsequent loop iteration to catch the budget having been blown
    # -- the flag must be set as soon as the overrun is detected, not only
    # when checked before starting a next segment that may not exist.
    monkeypatch.setattr(yara_hunt, "YARA_MAX_TOTAL_BYTES_SCANNED", 10)
    seg_va, seg_fo = 0x25000, 0x2500
    data = b'\x00' * 0x100   # 256 bytes, well past the 10-byte cap
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["status"] != "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["coverage"]["scan_budget_ok"] is False
    assert f["coverage_status"] == "partial"


def test_scan_deadline_exceeded_mid_segment_across_many_rule_files_is_caught(monkeypatch):
    # A single segment scanned against several rule files, each match()
    # call individually well inside YARA_MATCH_TIMEOUT, must still trip the
    # whole-scan deadline if the CUMULATIVE time across those rule files
    # exceeds it -- the per-call timeout alone cannot bound this. Uses a
    # fake monotonic clock (rather than a real short sleep) so this is
    # deterministic: real match() calls against a tiny buffer are fast
    # enough that a real wall-clock deadline could race and never trip.
    calls = {"n": 0}
    def fake_monotonic():
        calls["n"] += 1
        # Stays "no time elapsed" for the first few calls (covers computing
        # scan_deadline, the top-of-outer-loop check, and a couple of rule
        # files actually running), then jumps far past the deadline --
        # simulating the deadline expiring PARTWAY through this segment's
        # rule-file loop, not before it even started.
        return 100.0 if calls["n"] >= 4 else 0.0
    monkeypatch.setattr(yara_hunt.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(yara_hunt, "YARA_SCAN_DEADLINE_SECONDS", 50)
    seg_va, seg_fo = 0x26000, 0x2600
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        for i in range(5):
            _write_rule(d, f"rule{i}.yar",
                        f'rule Good{i} {{ strings: $a = "nomatch_marker" condition: $a }}')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["coverage"]["scan_budget_ok"] is False
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"


def test_deadline_crossed_during_the_only_match_call_is_still_caught(monkeypatch):
    # The exact gap this closes: a match() call that starts BEFORE the
    # global deadline expires, but the deadline is crossed DURING that
    # call (or is discovered to be crossed as soon as it returns) -- if
    # this is the last (or only) rule file for the last (or only) segment,
    # there is no subsequent check-before-a-next-call to catch it. The
    # post-call recheck (added alongside tightening call_timeout to
    # whatever's left of the global budget) must catch this even when
    # nothing else runs afterward.
    calls = {"n": 0}
    def fake_monotonic():
        calls["n"] += 1
        # calls 1-3: computing scan_deadline, the top-of-outer-loop check,
        # and the pre-match "remaining" check all see plenty of time left,
        # so the match() call is allowed to start. Call 4 (checked
        # immediately after match() returns) reports the deadline as
        # already passed -- simulating the call itself having consumed it.
        return 1000.0 if calls["n"] >= 4 else 0.0
    monkeypatch.setattr(yara_hunt.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(yara_hunt, "YARA_SCAN_DEADLINE_SECONDS", 50)
    seg_va, seg_fo = 0x27000, 0x2700
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["coverage"]["scan_budget_ok"] is False
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert f["status"] != "NOT_DETECTED_IN_SCANNED_SCOPE"


def test_scan_deadline_exhaustion_makes_result_inconclusive(monkeypatch):
    monkeypatch.setattr(yara_hunt, "YARA_SCAN_DEADLINE_SECONDS", -1)   # already expired
    seg_va, seg_fo = 0x24000, 0x2400
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "good.yar", 'rule Good { strings: $a = "nomatch_marker" condition: $a }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage"]["scan_budget_ok"] is False
    assert f["coverage_status"] == "partial"


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
