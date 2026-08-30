"""Direct unit tests for dumpex.hunt.pipe.memory_scan.scan_pipe_names' own
per-region C2 retention rule -- exercised full-scope, with no targeted adapter
involved.

Retention is proximity-first: pass 1 keeps every match within
PIPE_CONTEXT_DISTANCE of one of that region's own pipe-name hits for as long as
the whole-hunt c2_budget allows, and pass 2 keeps the first
PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION non-adjacent matches. Which records survive
depends only on scan order within each class -- never on where the other
class's matches happen to sit in the stream. `context_only_cap_hit` says
whether that quota actually dropped a record.
"""
import re

from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment

from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt.pipe.config import (
    PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION, PIPE_CONTEXT_DISTANCE,
)
from dumpex.hunt.pipe.memory_scan import scan_pipe_names

_BASE = 0x20000000
_SIZE = 0x8000
_C2_PAT = re.compile(r"https?://")

# Far enough apart that a token beside one pipe name is outside the window of
# the other -- so "proximity" and "context-only" are decided by the layout, not
# by luck.
_NAME_A = 0x40
_NAME_B = 0x4000


def _budget():
    return ScanBudget(max_bytes_read=10 ** 9, max_attempts=10 ** 9,
                      max_retained_bytes=10 ** 9, max_hits=10 ** 9)


def _mf():
    class MF(FakeMF):
        memory_info = FakeStream([], "infos")
    MF.memory_segments_64 = FakeStream([Segment(_BASE, 0x1000, _SIZE)], "memory_segments")
    return MF()


def _region():
    return Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")


def _place(data, offset, blob):
    data[offset:offset + len(blob)] = blob


def _url(index):
    """One C2 token yielding exactly one `https?://` match, so a retained-record
    count is a token count."""
    return b"http://host%02d.example/" % index


def _scan(data):
    result = scan_pipe_names(_mf(), lambda _mf, _addr, _size: bytes(data), [_region()],
                             [], CoverageTracker(), _budget(), _budget(), _C2_PAT)
    records = [record for group in result.c2_regions for record in group.records]
    return result, records


def _offsets(records):
    return sorted(record.va - _BASE for record in records)


def test_the_two_pipe_name_anchors_are_far_enough_apart_to_separate_the_classes():
    """Guard on the fixtures themselves: the layout below only means what the
    tests claim if a token beside one name is genuinely outside the other's
    window."""
    assert _NAME_B - _NAME_A > 2 * PIPE_CONTEXT_DISTANCE


def test_trailing_proximity_matches_do_not_change_which_context_only_records_survive():
    """A region whose stream ends with proximity matches, after more
    context-only matches than the quota allows. Pass 1 keeps every proximity
    match; pass 2 keeps the FIRST `PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION`
    context-only ones in scan order. The proximity matches sitting later in the
    stream neither displace a context-only record nor change which ones are
    kept."""
    context_only = [0x2000 + index * 0x40
                    for index in range(PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION + 3)]
    proximity = [_NAME_B + 0x40 + index * 0x40 for index in range(3)]

    data = bytearray(b"\x00" * _SIZE)
    _place(data, _NAME_A, br"\\.\pipe\demoA")
    _place(data, _NAME_B, br"\\.\pipe\demoB")
    for index, offset in enumerate(context_only):
        _place(data, offset, _url(index))
    for index, offset in enumerate(proximity):
        _place(data, offset, _url(90 + index))

    result, records = _scan(data)

    assert len(result.string_leads) == 2, "both pipe-name anchors have to be retained"
    kept = _offsets(records)
    assert kept == sorted(context_only[:PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION] + proximity)
    assert result.coverage.context_only_cap_hit is True


def test_a_proximity_match_between_the_quota_and_a_dropped_record_still_reports_it():
    """The case the two retention passes can disagree about: the quota fills,
    then a PROXIMITY match arrives (which pass 2 would skip anyway), and only
    after it a further context-only match that is genuinely dropped.

    Retention is the same either way -- the first N context-only matches plus
    every proximity match -- but the quota did drop a record, and a scan that
    stopped walking at the proximity match would report no gap at all."""
    context_only = [0x2000 + index * 0x40
                    for index in range(PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION)]
    interleaved_proximity = _NAME_B + 0x40
    dropped = 0x6000

    data = bytearray(b"\x00" * _SIZE)
    _place(data, _NAME_A, br"\\.\pipe\demoA")
    _place(data, _NAME_B, br"\\.\pipe\demoB")
    for index, offset in enumerate(context_only):
        _place(data, offset, _url(index))
    _place(data, interleaved_proximity, _url(90))
    _place(data, dropped, _url(91))

    result, records = _scan(data)

    assert _offsets(records) == sorted(context_only + [interleaved_proximity])
    assert dropped not in _offsets(records)
    assert result.coverage.context_only_cap_hit is True


def test_a_region_under_the_quota_reports_no_context_only_gap():
    context_only = [0x2000 + index * 0x40
                    for index in range(PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION)]

    data = bytearray(b"\x00" * _SIZE)
    _place(data, _NAME_A, br"\\.\pipe\demoA")
    for index, offset in enumerate(context_only):
        _place(data, offset, _url(index))

    result, records = _scan(data)

    assert _offsets(records) == context_only
    assert result.coverage.context_only_cap_hit is False
    assert result.coverage.match_cap_hit is False
