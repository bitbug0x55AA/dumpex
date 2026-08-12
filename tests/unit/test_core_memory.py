"""Unit tests for dumpex.core.memory's cross-platform path helpers."""
from dumpex.core.memory import (
    module_name_only, verdict_for, _verdict, _search_string_in_memory, StringSearchStats,
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_LIKELY_MALICIOUS, VERDICT_HIGH_CONFIDENCE_MALICIOUS,
    va_range_captured_bytes,
)
from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment, mem_reader


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
