"""Unit tests for dumpex.core.memory's cross-platform path helpers."""
import types

import pytest

from dumpex.core.memory import (
    module_name_only, verdict_for, _verdict, _search_string_in_memory, StringSearchStats,
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_LIKELY_MALICIOUS, VERDICT_HIGH_CONFIDENCE_MALICIOUS,
    va_range_captured_bytes, clamped_reader, read_region_clamped, read_region_spanning,
    has_stream_directory, handle_stream_evidence,
    HandleStreamContractError, declared_descriptor_count, truncated_descriptor_count,
)
from minidump.constants import MINIDUMP_STREAM_TYPE
from tests.fixtures.fakes import (
    FakeMF, FakeStream, Handle, Region, Segment, mem_reader,
    mf_with_handle_stream, parsed_handle_stream,
)


def test_module_name_only_extracts_windows_backslash_path_basename():
    # Module paths recorded in a minidump are always Windows paths (e.g.
    # "C:\\Windows\\System32\\foo.dll") regardless of the host OS this
    # tool runs on. os.path.basename only splits on "/" on a POSIX host,
    # silently returning the whole backslash-separated string unchanged
    # there -- module_name_only() must use ntpath.basename instead so
    # this extracts correctly on every host, not just Windows.
    assert module_name_only(r"C:\Windows\System32\ntdll.dll") == "ntdll.dll"


def test_module_name_only_lowercases():
    assert module_name_only(r"C:\Windows\System32\NTDLL.DLL") == "ntdll.dll"


def test_module_name_only_same_basename_different_directory_matches():
    # The exact scenario dumpex.commands.comparison.collect_module_diff
    # (and diff.py's own diff_modules) relies on: the "same" module
    # relocated to a different directory between two dumps must still
    # produce the SAME match key -- and therefore report as "rebased,"
    # not a spurious removed+added pair -- regardless of host OS.
    a = module_name_only(r"C:\Program Files\App\a.dll")
    b = module_name_only(r"C:\Windows\System32\a.dll")
    assert a == b == "a.dll"


def test_module_name_only_empty_for_none_or_empty_path():
    assert module_name_only(None) == ""
    assert module_name_only("") == ""


def test_module_name_only_forward_slash_path_still_works():
    # Not the primary case (minidump module paths are Windows paths), but
    # ntpath.basename also handles "/" -- confirms nothing regressed for
    # a path that happens to use forward slashes.
    assert module_name_only("C:/Windows/System32/ntdll.dll") == "ntdll.dll"


# ── verdict_for() (Phase E, PR3) ──────────────────────────────────────────
# _verdict()'s own colored console text is derived from verdict_for(), not
# hand-maintained separately -- these tests pin the four tier boundaries
# verdict_for() itself decides, independent of any console rendering.

def test_verdict_for_zero_dims_is_clean():
    assert verdict_for({}) == VERDICT_CLEAN


def test_verdict_for_one_dim_is_suspicious():
    assert verdict_for({"rwx_private": "x"}) == VERDICT_SUSPICIOUS


def test_verdict_for_two_dims_is_likely_malicious():
    assert verdict_for({"rwx_private": "x", "injected_pe": "y"}) == VERDICT_LIKELY_MALICIOUS


def test_verdict_for_three_dims_is_high_confidence_malicious():
    assert verdict_for(
        {"rwx_private": "x", "injected_pe": "y", "ioc_strings": "z"}
    ) == VERDICT_HIGH_CONFIDENCE_MALICIOUS


def test_verdict_for_four_dims_is_still_high_confidence_malicious():
    # INDICATOR_DIMS has exactly four possible keys -- the tier stays
    # HIGH_CONFIDENCE_MALICIOUS (not a fifth tier) once all four fire.
    assert verdict_for({
        "unbacked_thread": "a", "rwx_private": "x", "injected_pe": "y", "ioc_strings": "z",
    }) == VERDICT_HIGH_CONFIDENCE_MALICIOUS


def test_verdict_console_text_tier_matches_verdict_for():
    # _verdict()'s own colored text and verdict_for()'s machine tier must
    # never disagree about which of the four tiers a given dims dict is in
    # -- both derive from the same len(dims) rule, verdict_for() is not a
    # second, independently-maintained copy of _verdict()'s own thresholds.
    for dims, expected_substr in (
        ({}, "CLEAN"),
        ({"a": "1"}, "SUSPICIOUS"),
        ({"a": "1", "b": "2"}, "LIKELY MALICIOUS"),
        ({"a": "1", "b": "2", "c": "3"}, "HIGH CONFIDENCE MALICIOUS"),
    ):
        assert expected_substr in _verdict(dims)


# ── _search_string_in_memory() telemetry (Phase E, PR3; RevFix2-P1a) ──────
# Returns (hits, StringSearchStats(skipped, clamped, truncated)) instead of
# a bare list -- closes both the pre-existing silent-skip gap (a region
# read failure during --report-string's scan was completely invisible) and
# a false-negative gap (a needle past MAX_REGION_READ's own clamp, or past
# a short real read within that clamp, was silently treated as "not
# found" with no trace either).

def _mf_with_regions(regions, read_map):
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    return mf


def test_search_string_in_memory_returns_hits_and_zero_skipped_when_all_readable():
    # Region content padded to the full region size -- a short fixture
    # payload would otherwise register as `truncated`, conflating this
    # test's own single purpose (the skip counter) with truncation.
    data = b"header NEEDLE1234 trailer".ljust(0x1000, b"\x00")
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        {0x1000: data})
    import dumpex.core.memory as core_memory
    core_memory.read_region = mem_reader({0x1000: data})
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert len(hits) == 1
    assert stats == StringSearchStats(skipped=0, clamped=0, truncated=0)


def test_search_string_in_memory_counts_skipped_unreadable_regions():
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
         Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        {})
    import dumpex.core.memory as core_memory

    def _reader(mf_, addr, size):
        if addr == 0x1000:
            raise RuntimeError("simulated read failure")
        return b"header NEEDLE1234 trailer".ljust(0x1000, b"\x00")
    core_memory.read_region = _reader
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert stats.skipped == 1
    assert stats.clamped == 0
    assert stats.truncated == 0
    assert len(hits) == 1
    assert hits[0][0].BaseAddress == 0x2000


def test_search_string_in_memory_counts_clamped_regions_bigger_than_cap(monkeypatch):
    import dumpex.core.memory as core_memory
    monkeypatch.setattr(core_memory, "MAX_REGION_READ", 16)
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], {})
    monkeypatch.setattr(core_memory, "read_region", lambda mf_, addr, size: b"\x00" * size)
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert stats.clamped == 1
    assert stats.truncated == 0
    assert stats.skipped == 0


def test_search_string_in_memory_counts_truncated_short_reads():
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], {})
    import dumpex.core.memory as core_memory
    core_memory.read_region = lambda mf_, addr, size: b"only nine"   # far short of 4096
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert stats.truncated == 1
    assert stats.clamped == 0
    assert stats.skipped == 0


def test_search_string_in_memory_needle_past_truncation_is_a_miss_but_counted():
    # The exact false-negative the review flagged: the needle sits past
    # where the (clamped-and-then-short) read actually reached, so it's
    # never found -- but stats.truncated must say so, rather than the scan
    # silently claiming to have covered the whole region.
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], {})
    import dumpex.core.memory as core_memory
    payload = (b"x" * 100) + b"NEEDLE1234"
    core_memory.read_region = lambda mf_, addr, size: payload[:16]   # cuts off before the needle
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert hits == []
    assert stats.truncated == 1


# ── va_range_captured_bytes() (issue #28 P1 follow-up) ────────────────────
# The structural "how much of this VA range does the dump's own segment
# table actually back" fact ScanTarget.captured_size/capture_state are
# built from -- independent of any hunt's own live-read outcome.

def _mf_with_segments(segments):
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream(segments, "memory_segments")
    return mf


def test_va_range_captured_bytes_zero_when_va_not_covered_at_all():
    mf = _mf_with_segments([Segment(0x2000, 0x2000, 0x1000)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0


def test_va_range_captured_bytes_full_when_one_segment_covers_the_whole_range():
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x2000)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x1000


def test_va_range_captured_bytes_partial_when_segment_covers_only_a_prefix():
    # The exact short-read shape: the requested range starts inside a
    # segment but the segment ends before the range does -- only the
    # PREFIX up to the segment's own end is actually captured.
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x800)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x800


def test_va_range_captured_bytes_stops_at_a_gap_between_segments():
    # A LATER segment covering the range's tail, with a gap in between,
    # must not count -- the missing middle still can't be extracted as one
    # contiguous read, so only the contiguous run starting at `va` counts.
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x400),
                             Segment(0x1800, 0x1800, 0x400)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x400


def test_va_range_captured_bytes_spans_contiguous_segments():
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x800),
                             Segment(0x1800, 0x1800, 0x800)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x1000


def test_va_range_captured_bytes_zero_for_no_segment_table_at_all():
    assert va_range_captured_bytes(FakeMF(), 0x1000, 0x1000) == 0


def test_va_range_captured_bytes_zero_for_zero_or_negative_size():
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x2000)])
    assert va_range_captured_bytes(mf, 0x1000, 0) == 0
    assert va_range_captured_bytes(mf, 0x1000, -1) == 0


def test_va_range_captured_bytes_reads_an_unsorted_table_in_address_order():
    """The segment table is indexed by ascending VA before it is walked,
    so a table stored out of order resolves the same contiguous run as an
    ordered one."""
    ordered = _mf_with_segments([Segment(0x1000, 0x1000, 0x800),
                                  Segment(0x1800, 0x1800, 0x800)])
    shuffled = _mf_with_segments([Segment(0x1800, 0x1800, 0x800),
                                   Segment(0x1000, 0x1000, 0x800)])
    assert (va_range_captured_bytes(shuffled, 0x1000, 0x1000)
            == va_range_captured_bytes(ordered, 0x1000, 0x1000) == 0x1000)


def test_va_range_captured_bytes_covers_a_range_an_earlier_segment_overlaps():
    """An overlapping table (an earlier entry extending past a later
    entry's start) still resolves against the entry that actually covers
    the range, not whichever one the index landed on first."""
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x4000),
                             Segment(0x2000, 0x9000, 0x400)])
    assert va_range_captured_bytes(mf, 0x2000, 0x1000) == 0x1000


def test_va_range_captured_bytes_sees_past_short_segments_nested_in_a_long_one():
    """Short entries nested inside a longer one sit between it and the
    query address in start order, and every one of them ends before that
    address. The covering entry still has to be found -- reporting 0 here
    would claim the dump captured none of a range it holds in full."""
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x5000),    # [0x1000, 0x6000)
                             Segment(0x2000, 0x9000, 0x100),     # [0x2000, 0x2100)
                             Segment(0x3000, 0x9100, 0x100)])    # [0x3000, 0x3100)
    assert va_range_captured_bytes(mf, 0x4000, 0x800) == 0x800


def test_va_range_captured_bytes_matches_a_plain_address_ordered_walk():
    """Randomized differential check over overlapping, nested, and
    gapped tables: the index is only an entry point into the same
    contiguous-run walk, never a different answer from it."""
    import random

    def plain_walk(segments, va, size):
        end, cursor = va + size, va
        for seg in sorted(segments, key=lambda s: s.start_virtual_address):
            if seg.end_virtual_address <= cursor:
                continue
            if seg.start_virtual_address > cursor:
                break
            cursor = min(seg.end_virtual_address, end)
            if cursor >= end:
                break
        return cursor - va

    rng = random.Random(7)
    for _ in range(200):
        segments = [Segment(start, start, rng.randrange(0x100, 0x4000, 0x100))
                    for start in (rng.randrange(0x1000, 0x9000, 0x100)
                                  for _ in range(rng.randint(1, 12)))]
        rng.shuffle(segments)
        mf = _mf_with_segments(segments)
        for _ in range(25):
            va = rng.randrange(0x1000, 0x9000, 0x100)
            size = rng.randrange(0x100, 0x3000, 0x100)
            assert va_range_captured_bytes(mf, va, size) == plain_walk(segments, va, size), (
                f"va={va:#x} size={size:#x} over "
                f"{[(s.start_virtual_address, s.end_virtual_address) for s in segments]}")


def test_va_range_captured_bytes_rebuilds_its_index_when_the_table_is_replaced():
    """The per-dump index is keyed on the segment list it was built from,
    so swapping the stream out (which tests do) cannot serve an answer
    from the previous table."""
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x1000)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x1000

    mf.memory_segments_64 = FakeStream([Segment(0x1000, 0x1000, 0x400)],
                                        "memory_segments")
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x400


# ── clamped_reader() / read_region_clamped() (issue #40) ─────────────────
# A read(addr, size) primitive that never asks for more than the CURRENT
# segment's own remaining bytes -- see clamped_reader()'s own docstring
# for why this differs from va_range_captured_bytes() (which accumulates
# across CONTIGUOUS segments, a boundary the underlying buffered reader
# itself does not honor).

class _FakeSegment:
    def __init__(self, start, data):
        self.start_address = start
        self.data = data
        self.end_address = start + len(data)

    def remaining_len(self, position):
        if not (self.start_address <= position < self.end_address):
            return None
        return self.end_address - position


class _FakeBufferedReader:
    def __init__(self, segments: dict):
        self._segments = [_FakeSegment(start, data) for start, data in segments.items()]
        self.current_segment = None
        self.current_position = None

    def move(self, address):
        for seg in self._segments:
            if seg.start_address <= address < seg.end_address:
                self.current_segment = seg
                self.current_position = address
                return
        raise Exception("not in process memory space")

    def read(self, size):
        end = self.current_position + size
        if end > self.current_segment.end_address:
            raise Exception("read over segment boundary")
        off = self.current_position - self.current_segment.start_address
        data = self.current_segment.data[off:off + size]
        self.current_position = end
        return data


class _FakeReader:
    def __init__(self, buffered):
        self._buffered = buffered

    def get_buffered_reader(self):
        return self._buffered


def _mf_with_memory(memory: dict):
    mf = FakeMF()
    mf._reader = _FakeReader(_FakeBufferedReader(memory))
    mf.get_reader = lambda: mf._reader
    return mf


def test_clamped_reader_returns_exactly_what_is_captured():
    mf = _mf_with_memory({0x1000: b"KERNEL32.dll\x00"})
    read = clamped_reader(mf)
    assert read(0x1000, 512) == b"KERNEL32.dll\x00"   # clamped to the 13 real bytes present


def test_clamped_reader_returns_empty_bytes_when_nothing_captured():
    mf = _mf_with_memory({0x1000: b"MZ"})
    read = clamped_reader(mf)
    assert read(0x9000, 512) == b""


def test_clamped_reader_stays_within_current_segment_when_a_neighbour_follows():
    # The layout that broke a prior version of this primitive: reading
    # from the FIRST segment must never spill into the immediately
    # adjacent second one just because the two are contiguous.
    mf = _mf_with_memory({0x1000: b"AB", 0x1002: b"CD"})
    read = clamped_reader(mf)
    assert read(0x1000, 512) == b"AB"


def test_clamped_reader_construction_failure_never_raises():
    """clamped_reader(mf) itself must not propagate an exception even
    when building the bound reader fails -- the whole point of this
    primitive is "hand back bytes, never an exception", and that
    guarantee has to cover construction, not just each individual read."""
    mf = FakeMF()
    mf.get_reader = lambda: (_ for _ in ()).throw(Exception("reader unavailable"))

    read = clamped_reader(mf)   # must not raise
    assert read(0x1000, 512) == b""
    assert read(0x9999, 4) == b""


def test_clamped_reader_reuses_one_buffered_reader_across_calls():
    mf = _mf_with_memory({0x1000: b"AB", 0x2000: b"CD"})
    get_reader_calls = []
    real_get_reader = mf.get_reader
    mf.get_reader = lambda: (get_reader_calls.append(1), real_get_reader())[1]

    read = clamped_reader(mf)
    read(0x1000, 2)
    read(0x2000, 2)
    read(0x1000, 2)
    assert len(get_reader_calls) == 1


def test_read_region_clamped_one_shot_matches_clamped_reader():
    mf = _mf_with_memory({0x1000: b"KERNEL32.dll\x00"})
    assert read_region_clamped(mf, 0x1000, 512) == b"KERNEL32.dll\x00"
    assert read_region_clamped(mf, 0x9000, 512) == b""


# ── read_region_spanning() (issue #40) ────────────────────────────────────
# Walks across CONTIGUOUS segments -- the boundary va_range_captured_
# bytes() computes -- unlike read_region()/clamped_reader(), which only
# ever read through whichever ONE segment reader.move() first landed on.

def test_read_region_spanning_reads_within_a_single_segment_like_read_region():
    mf = _mf_with_memory({0x1000: b"KERNEL32.dll\x00"})
    assert read_region_spanning(mf, 0x1000, 13) == b"KERNEL32.dll\x00"


def test_read_region_spanning_recovers_a_read_split_across_two_contiguous_segments():
    # The exact layout that broke a naive read_region(mf, addr,
    # va_range_captured_bytes(mf, addr, size)) combination: two segments,
    # back to back with no gap, each holding half of what is logically
    # one contiguous structure.
    mf = _mf_with_memory({0x1000: b"ABCD", 0x1004: b"EFGH"})
    assert read_region_spanning(mf, 0x1000, 8) == b"ABCDEFGH"


def test_read_region_spanning_recovers_a_read_split_across_three_segments():
    mf = _mf_with_memory({0x1000: b"AB", 0x1002: b"CD", 0x1004: b"EF"})
    assert read_region_spanning(mf, 0x1000, 6) == b"ABCDEF"


def test_read_region_spanning_stops_at_a_genuine_gap_between_segments():
    # 0x1002..0x1010 is NOT captured -- the second segment is not
    # contiguous with the first, so the read must stop at the true end of
    # what was actually captured, not silently skip the gap.
    mf = _mf_with_memory({0x1000: b"AB", 0x1010: b"CD"})
    assert read_region_spanning(mf, 0x1000, 8) == b"AB"


def test_read_region_spanning_returns_empty_bytes_when_nothing_captured():
    mf = _mf_with_memory({0x1000: b"AB"})
    assert read_region_spanning(mf, 0x9000, 8) == b""


def test_read_region_spanning_zero_for_zero_or_negative_size():
    mf = _mf_with_memory({0x1000: b"AB"})
    assert read_region_spanning(mf, 0x1000, 0) == b""
    assert read_region_spanning(mf, 0x1000, -1) == b""


def test_read_region_spanning_never_raises_when_get_reader_fails():
    mf = FakeMF()
    mf.get_reader = lambda: (_ for _ in ()).throw(Exception("reader unavailable"))
    assert read_region_spanning(mf, 0x1000, 8) == b""


# ── has_stream_directory (issue #42 §5.5 case 1 vs case 2) ───────────────
# mf.<stream> is None both for "never captured" and for "captured, but its
# parse raised" -- the directory table is the only place those two are
# still distinguishable once open_dump() has run.

class _Dir:
    def __init__(self, stream_type):
        self.StreamType = stream_type


def test_has_stream_directory_true_when_the_dump_declares_the_stream():
    mf = FakeMF()
    mf.directories = [_Dir(MINIDUMP_STREAM_TYPE.ThreadListStream),
                       _Dir(MINIDUMP_STREAM_TYPE.HandleDataStream)]
    assert has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is True


def test_has_stream_directory_false_when_another_stream_is_declared():
    mf = FakeMF()
    mf.directories = [_Dir(MINIDUMP_STREAM_TYPE.ThreadListStream)]
    assert has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is False


def test_has_stream_directory_is_independent_of_whether_the_parse_succeeded():
    # The whole point: a declared stream stays declared after its parser
    # raised and left mf.handles at None.
    mf = FakeMF()
    mf.directories = [_Dir(MINIDUMP_STREAM_TYPE.HandleDataStream)]
    mf.handles = None
    mf._dumpex_stream_failures = {MINIDUMP_STREAM_TYPE.HandleDataStream: "boom"}
    assert has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is True


def test_has_stream_directory_tolerates_a_dump_object_without_directories():
    # A test/fixture-built mf that never went through open_dump() has no
    # directories list at all -- treated as declaring nothing, never an
    # AttributeError, matching stream_failure()'s own tolerance.
    assert has_stream_directory(FakeMF(), MINIDUMP_STREAM_TYPE.HandleDataStream) is False


# ── The one reader of header.NumberOfDescriptors ─────────────────────────
# `--handles`, `--profile` and `--hunt pipe` all describe the same
# truncated stream from these two functions, so one dump cannot be
# reported three different ways in one case file.

def _stream(handles, declared=None):
    return FakeStream(handles, "handles", declared=declared)


@pytest.mark.parametrize("parsed, expected", [
    (None, 0),                                              # no stream at all
    (_stream([Handle(0x1, "File", "x")], declared=False), 0),   # no usable declared count
    (_stream([], declared=0), 0),                            # declared none, delivered none
    (_stream([Handle(0x1, "File", "x")], declared=1), 0),    # delivered what it declared
    (_stream([Handle(0x1, "File", "x")], declared=9), 8),
    (_stream([], declared=3), 3),                            # array cut off entirely
    # More delivered than declared is a contradiction in the dump's own
    # numbers, not a negative shortfall: no descriptor is missing.
    (_stream([Handle(0x10 * (i + 1), "File", "x") for i in range(4)], declared=2), 0),
])
def test_truncated_descriptor_count_never_invents_a_gap(parsed, expected):
    assert truncated_descriptor_count(parsed) == expected


def test_truncated_descriptor_count_over_a_really_truncated_file():
    """The real parser, over a stream whose framing claims room for five
    descriptors while the file only ever held two -- the shape where
    reading the shortfall off the header and recomputing it from the
    framing disagree (3 versus 0)."""
    parsed = parsed_handle_stream([{"handle": 0x10 * (i + 1)} for i in range(2)],
                                   number_of_descriptors=5,
                                   declared_data_size=16 + 5 * 32)
    assert (parsed.header.NumberOfDescriptors, len(parsed.handles)) == (5, 2)
    assert truncated_descriptor_count(parsed) == 3


@pytest.mark.parametrize("declared", [True, "4", 4.0, None, -1])
def test_a_declared_count_that_is_not_a_count_states_nothing(declared):
    """A declared count that is not usable as one says nothing about how
    many descriptors the stream holds, and a fabricated number would be
    worse than none -- `bool` included, since it is an int subclass and a
    stray boolean there is a parse bug, not 0 or 1. Mirrors how
    parse_handle_stream itself treats those values when it bounds its own
    read."""
    parsed = _stream([Handle(0x1, "File", "x")], declared=declared)
    assert declared_descriptor_count(parsed) is None
    assert truncated_descriptor_count(parsed) == 0


@pytest.mark.parametrize("parsed", [
    types.SimpleNamespace(handles=[]),                                   # no .header
    types.SimpleNamespace(header=types.SimpleNamespace(), handles=[]),    # header, no count
])
def test_a_stream_shape_the_parser_no_longer_produces_fails_loudly(parsed):
    """A renamed attribute or a changed return shape must not degrade into
    "0 declared, so nothing was truncated": that answer is
    indistinguishable from a complete stream, which is the silent clean
    result the truncation limitation exists to prevent."""
    with pytest.raises(HandleStreamContractError):
        truncated_descriptor_count(parsed)


def test_a_stream_missing_only_its_handles_list_also_fails_loudly():
    parsed = types.SimpleNamespace(header=types.SimpleNamespace(NumberOfDescriptors=3))
    with pytest.raises(HandleStreamContractError):
        truncated_descriptor_count(parsed)


# ── The one discriminator of the handle stream's three states ────────────

def test_handle_stream_evidence_tells_never_captured_from_unparseable():
    absent = mf_with_handle_stream()
    parsed = mf_with_handle_stream(parsed=parsed_handle_stream([{"handle": 0x10}]))
    failed = mf_with_handle_stream(failure="SizeOfHeader 4 is out of bounds")

    assert handle_stream_evidence(absent) == ("absent", None, None)
    assert handle_stream_evidence(parsed)[0] == "parsed"
    assert handle_stream_evidence(failed) == (
        "failed", None, "SizeOfHeader 4 is out of bounds")


def test_a_declared_stream_that_never_arrived_is_failed_not_absent():
    """A directory entry with neither a parsed stream nor a recorded
    failure means the stream was captured but never reached the loader.
    Unreachable through today's open_dump(), and it fails closed toward
    the honest answer: the dump HAS handle data, so telling an analyst to
    re-collect with it would be wrong."""
    mf = mf_with_handle_stream(has_directory=True)
    state, parsed, detail = handle_stream_evidence(mf)
    assert (state, parsed) == ("failed", None)
    assert "no parsed stream is available" in detail
