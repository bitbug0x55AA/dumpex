"""Targeted CS Beacon rescan adapter (dumpex.hunt.cs_beacon.targeted).

One targeted invocation searches a single requested virtual-address range,
resolved to a slice of the captured segment containing its base, for beacon
configurations. Hit addresses and dump-file offsets stay absolute; only
CS_MAX_SEG_SCAN is bypassed and every other budget stays enforced; a stop
part-way names the exact unexamined suffix.
"""
import pytest

from dumpex.core.va_range import CaptureState, VirtualRange
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._observation import ObservationResult
from dumpex.hunt._request import HuntRequest
from dumpex.output.coverage import LimitationCode

import dumpex.hunt.cs_beacon as cs_beacon
import dumpex.hunt.cs_beacon.scanner as scanner
import dumpex.hunt.cs_beacon.targeted as targeted

from tests.fixtures.fakes import (
    FakeMF, FakeReader, FakeStream, Region, Segment, cs_beacon_config_bytes,
)

_SEG_VA = 0x20000000
_SEG_FO = 0x3000
_CONFIG_OFF = 0x1100


def _segment_data(size=0x2000, config_offset=None):
    """A buffer of ``size`` zero bytes, optionally carrying one
    structurally-valid XOR-0x69 config at ``config_offset``."""
    data = bytearray(b"\x00" * size)
    if config_offset is not None:
        config = cs_beacon_config_bytes(0x69)
        data[config_offset:config_offset + len(config)] = config
    return bytes(data)


def _mf(segments, read_map, regions=None):
    class MF(FakeMF):
        memory_segments_64 = FakeStream(list(segments), "memory_segments")
        memory_info = FakeStream(list(regions), "infos") if regions is not None else None
        _reader = FakeReader(dict(read_map))
    return MF()


def _region(base, size):
    return Region(base, base, size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")


def _run(mf, requested):
    request = HuntRequest.targeted("cs-beacon", "segment_scan", requested)
    ctx = build_execution_context(mf, request)
    return ctx, targeted.run_targeted_cs_beacon(ctx)


def _one(result):
    assert len(result.closures) == 1
    return result.closures[0]


# ── request validation ──────────────────────────────────────────────────

def test_a_full_scope_request_is_refused_before_any_read():
    ctx = build_execution_context(_mf([], {}), HuntRequest.full("cs-beacon"))
    with pytest.raises(targeted.TargetedCSBeaconError):
        targeted.run_targeted_cs_beacon(ctx)


def test_another_analyzers_targeted_request_is_refused():
    request = HuntRequest.targeted("yara", "segment_scan", VirtualRange(_SEG_VA, 0x1000))
    ctx = build_execution_context(_mf([], {}), request)
    with pytest.raises(targeted.TargetedCSBeaconError):
        targeted.run_targeted_cs_beacon(ctx)


# ── structure and absolute addresses ────────────────────────────────────

def test_slice_scan_reports_absolute_hit_addresses_and_file_offsets():
    size = 0x2000
    data = _segment_data(size, config_offset=_CONFIG_OFF)
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])

    # Request the second half only: the config sits 0x100 bytes into it.
    requested = VirtualRange(_SEG_VA + 0x1000, 0x1000)
    ctx, result = _run(mf, requested)

    assert isinstance(result, ObservationResult)
    assert result.key.analyzer == "cs-beacon" and result.key.is_targeted
    assert result.key.requested_range == requested

    hits = result.payload.hits
    assert hits, "the config inside the requested slice produced no hit"
    hit = hits[0]
    assert hit.xor_key == 0x69
    assert hit.hit_va == _SEG_VA + _CONFIG_OFF
    assert hit.hit_fo == _SEG_FO + _CONFIG_OFF
    # The enclosing region still resolves off the real region table.
    assert hit.region.base_address == _SEG_VA


class _OverServingReader:
    """A reader that ignores the requested size and hands back everything it
    holds from `addr` on -- models a reader over-serving past the extent of the
    unit being scanned."""

    def __init__(self, base, data):
        self._base, self._data = base, data

    def read(self, addr, size):
        off = addr - self._base
        return self._data[off:] if 0 <= off < len(self._data) else b""


def test_a_config_past_the_requested_range_is_never_returned():
    # The config sits beyond the end of the requested slice. Even handed more
    # bytes than it asked for, the scan must not report it: a hit outside the
    # requested range is not this closure's to report, and a `complete` closure
    # carrying it would be actively false.
    size = 0x2000
    data = _segment_data(size, config_offset=0x1100)

    class MF(FakeMF):
        memory_segments_64 = FakeStream([Segment(_SEG_VA, _SEG_FO, size)], "memory_segments")
        memory_info = FakeStream([_region(_SEG_VA, size)], "infos")
        _reader = _OverServingReader(_SEG_VA, data)

    ctx, result = _run(MF(), VirtualRange(_SEG_VA, 0x1000))

    closure = _one(result)
    assert result.payload.hits == ()
    assert result.payload.diagnostics.total_scanned_bytes == 0x1000
    assert closure.coverage_status == "complete"
    assert closure.read_slice.read_bytes == 0x1000


def test_fully_captured_slice_with_no_hit_is_complete_and_clean():
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _segment_data(size)},
             regions=[_region(_SEG_VA, size)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.source == "segment_scan" and closure.scope is None
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "complete"
    assert closure.limitations == ()
    assert closure.read_slice.read_bytes == size
    assert result.payload.hits == ()


def test_corroboration_reaches_the_payload_for_a_hit():
    size = 0x2000
    data = _segment_data(size, config_offset=0x100)
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    assert result.payload.hits
    assert result.payload.corroborations is not None
    assert result.payload.containing_segment.base_address == _SEG_VA


# ── the bypassed cap, and the ones that stay ────────────────────────────

def test_oversized_slice_is_scanned_where_full_scope_would_skip_it(monkeypatch):
    size = 0x2000
    data = _segment_data(size, config_offset=0x100)
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_SEG_SCAN", 0x100)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.coverage_status == "complete"
    assert not [l for l in closure.limitations
                if l.code == LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED]
    assert result.payload.hits


def test_total_scanned_byte_budget_still_stops_the_slice_and_names_it(monkeypatch):
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _segment_data(size)},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_TOTAL_SCANNED_BYTES", 0x10)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    # The bytes never reached the marker search, so this is not a clean negative.
    assert closure.coverage_status == "not_evaluated"
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "max_total_scanned_bytes"
    target = budget[0].targets[0]
    assert (target.base_address, target.size) == (_SEG_VA, size)


def test_scan_deadline_still_stops_the_slice(monkeypatch):
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _segment_data(size)},
             regions=[_region(_SEG_VA, size)])
    # Already expired before the scan starts.
    monkeypatch.setattr(cs_beacon, "CS_SCAN_DEADLINE_SECONDS", -1)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "scan_deadline_seconds"


def test_decoded_byte_budget_still_bites(monkeypatch):
    size = 0x2000
    data = _segment_data(size, config_offset=0x100)
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_DECODED_BYTES", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.coverage_status == "partial"
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "max_decoded_bytes"


def test_candidate_budget_still_bites_and_leaves_the_slice_partial(monkeypatch):
    size = 0x2000
    data = _segment_data(size, config_offset=0x100)
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.coverage_status == "partial"
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "max_candidates"


# ── capture semantics ───────────────────────────────────────────────────

def test_address_outside_every_captured_segment_is_not_evaluated():
    mf = _mf([Segment(_SEG_VA, _SEG_FO, 0x1000)], {_SEG_VA: _segment_data(0x1000)})
    ctx, result = _run(mf, VirtualRange(0x9EEE0000, 0x1000))

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    assert closure.capture_state == CaptureState.NONE
    assert any("no captured segment contains" in d for d in closure.diagnostics)


def test_short_read_is_partial_and_names_the_unexamined_suffix():
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _segment_data(0x800)},
             regions=[_region(_SEG_VA, size)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "partial"
    assert LimitationCode.SCAN_REGION_SHORT_READ in {l.code for l in closure.limitations}
    assert closure.read_slice.unread_suffix == VirtualRange(_SEG_VA + 0x800, 0x1800)
    assert any("never searched for a config marker" in d for d in closure.diagnostics)


def test_last_xor_key_is_the_key_the_walk_actually_finishes_with():
    # The whole byte-exact residual rests on LAST_XOR_KEY naming the final
    # pass. Derived from the walk's own key table rather than restated, and
    # pinned here against the order the generator really yields: a third key,
    # or a reordering, would otherwise silently start reporting a residual
    # narrower than the work actually left undone.
    from dumpex.hunt.cs_beacon import scanner as cs_scanner

    data = bytearray(b"\x00" * 0x400)
    data[0x40:0x40 + len(scanner.CS_SIG_XOR69)] = scanner.CS_SIG_XOR69
    data[0x200:0x200 + len(scanner.CS_SIG_XOR2E)] = scanner.CS_SIG_XOR2E
    yielded = [key for key, _, _, _ in cs_scanner._cs_scan_segment(bytes(data), 0, 0)]

    assert len(set(yielded)) == len(cs_scanner._XOR_KEY_PASSES)
    assert yielded[-1] == cs_scanner.LAST_XOR_KEY


def _last_pass_config_at(offset, size=0x2000):
    """A buffer whose ONLY marker is an XOR-0x2e config at `offset`, so the
    0x69 pass sweeps the whole slice and the stop lands in the last pass."""
    data = bytearray(b"\x00" * size)
    config = cs_beacon_config_bytes(0x2e)
    data[offset:offset + len(config)] = config
    return bytes(data)


def _residual_target(result):
    budget = [l for l in result.closures[0].limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget
    return budget[0].targets[0]


def test_a_deadline_reached_after_the_candidate_resumes_at_the_next_byte(monkeypatch):
    # A clock that stays inside the deadline until the candidate at `offset`
    # has been decoded and judged, then jumps past it -- so the post-candidate
    # recheck is what stops the walk. A plain expired deadline would instead
    # trip at the top of the segment loop, before the walk ever starts.
    size, offset = 0x2000, 0x900
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _last_pass_config_at(offset, size)},
             regions=[_region(_SEG_VA, size)])

    # scan_start, the segment-loop top, and the pre-decode candidate check all
    # see 0; every call after that -- the first being the recheck that runs
    # once this candidate has been decoded and judged -- is past the deadline.
    ticks = iter([0, 0, 0])

    def fake_monotonic():
        return next(ticks, 10_000)

    monkeypatch.setattr(cs_beacon.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(cs_beacon, "CS_SCAN_DEADLINE_SECONDS", 1)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    diag = result.payload.diagnostics
    assert diag.budget_exhausted_kind == "scan_deadline_seconds"
    assert diag.scanned == 1, "the walk must actually have run"
    assert diag.budget_stop_offset == offset + 1
    assert _residual_target(result).base_address == _SEG_VA + offset + 1


@pytest.mark.parametrize("budget_const,budget_value,kind", [
    ("CS_MAX_HITS", 1, "max_hits"),
    ("CS_MAX_DECODED_BYTES", 0, "max_decoded_bytes"),
])
def test_a_stop_after_the_candidate_was_judged_resumes_at_the_next_byte(
        monkeypatch, budget_const, budget_value, kind):
    # These three budgets all trip AFTER the candidate at `offset` has been
    # decoded and judged. The walk's own next search starts at `offset + 1`, so
    # that -- not `offset` -- is the first unexamined byte. Reporting `offset`
    # would widen the residual by one byte and stop it being byte-exact.
    size, offset = 0x2000, 0x900
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _last_pass_config_at(offset, size)},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, budget_const, budget_value)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    assert result.payload.diagnostics.budget_exhausted_kind == kind
    assert result.payload.diagnostics.budget_stop_offset == offset + 1
    target = _residual_target(result)
    assert target.base_address == _SEG_VA + offset + 1
    assert target.size == size - offset - 1
    assert target.file_offset == _SEG_FO + offset + 1
    assert target.captured_size == size - offset - 1


def test_a_stop_before_the_candidate_was_judged_keeps_that_candidates_offset(monkeypatch):
    # The candidate cap trips on the candidate's own arrival, before it is
    # decoded, so that candidate is still unexamined and its own offset is the
    # first unsearched byte.
    size, offset = 0x2000, 0x900
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _last_pass_config_at(offset, size)},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    assert result.payload.diagnostics.budget_stop_offset == offset
    assert _residual_target(result).base_address == _SEG_VA + offset


def test_a_budget_stop_inside_the_last_key_pass_names_the_exact_residual(monkeypatch):
    # The buffer carries only an XOR-0x2e marker, so the 0x69 pass sweeps the
    # whole slice and finds nothing; the candidate cap then stops the 0x2e pass
    # at that marker. Every offset below it has now been searched by both keys,
    # so the remaining work is exactly the suffix from there on.
    size = 0x2000
    offset = 0x900
    data = bytearray(b"\x00" * size)
    config = cs_beacon_config_bytes(0x2e)
    data[offset:offset + len(config)] = config
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert result.payload.diagnostics.budget_stop_offset == offset
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget
    target = budget[0].targets[0]
    assert target.base_address == _SEG_VA + offset
    assert target.size == size - offset
    assert target.file_offset == _SEG_FO + offset


def test_a_stop_during_an_earlier_key_pass_names_the_whole_slice(monkeypatch):
    # The cap stops the FIRST key's pass, so the second key never looked at the
    # segment at all. No offset bounds that gap -- the whole slice is still
    # unresolved, and reporting a suffix would under-report it.
    size = 0x2000
    data = _segment_data(size, config_offset=0x900)   # XOR-0x69 marker
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert result.payload.diagnostics.budget_stop_offset is None
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget
    assert [(t.base_address, t.size) for t in budget[0].targets] == [(_SEG_VA, size)]


def test_a_budget_stop_after_a_short_read_spans_the_unsearched_prefix_too(monkeypatch):
    # The read came back short AND the candidate cap stopped the last key's
    # pass inside what WAS read. The residual therefore starts at the stop
    # cursor, not at the end of the read: the bytes between the cursor and the
    # end of the read prefix are just as unsearched as the ones never read.
    size = 0x2000
    offset = 0x100
    data = bytearray(b"\x00" * 0x800)
    config = cs_beacon_config_bytes(0x2e)
    data[offset:offset + len(config)] = config
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED]
    assert budget
    target = budget[0].targets[0]
    assert target.base_address == _SEG_VA + offset
    assert target.size == size - offset
    # captured_size is what the segment table backs, not what this read
    # returned -- the dump holds the whole residual, and the read coming back
    # short is a separate fact carried by SCAN_REGION_SHORT_READ.
    assert target.captured_size == size - offset
    assert [l for l in closure.limitations
            if l.code == LimitationCode.SCAN_REGION_SHORT_READ]
    assert closure.read_slice.read_bytes == 0x800


def test_range_past_the_segment_end_truncates_evaluation_but_not_capture():
    segs = [Segment(_SEG_VA, _SEG_FO, 0x1000),
            Segment(_SEG_VA + 0x1000, _SEG_FO + 0x1000, 0x1000)]
    mf = _mf(segs, {_SEG_VA: _segment_data(0x2000)},
             regions=[_region(_SEG_VA, 0x2000)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA, 0x2000))

    closure = _one(result)
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "partial"
    trunc = [l for l in closure.limitations
             if l.code == LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED]
    assert trunc and trunc[0].targets[0].size == 0x2000
    assert trunc[0].targets[0].captured_size == 0x2000
    assert any("clipped to containing segment end" in d for d in closure.diagnostics)


def test_sub_segment_request_names_the_containing_segment():
    size = 0x40000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: _segment_data(size)},
             regions=[_region(_SEG_VA, size)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA + 0x1000, 0x1000))

    closure = _one(result)
    assert closure.coverage_status == "complete"
    assert any("containing captured segment" in d for d in closure.diagnostics)
    assert result.payload.containing_segment.size == size


def test_partial_capture_is_partial_not_a_negative():
    mf = _mf([Segment(_SEG_VA, _SEG_FO, 0x800)], {_SEG_VA: _segment_data(0x800)},
             regions=[_region(_SEG_VA, 0x2000)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA, 0x2000))

    closure = _one(result)
    assert closure.capture_state == CaptureState.PARTIAL
    assert closure.coverage_status == "partial"


def test_overlapping_capture_makes_a_negative_non_authoritative():
    segs = [Segment(_SEG_VA, _SEG_FO, 0x2000),
            Segment(_SEG_VA + 0x800, _SEG_FO + 0x9000, 0x800)]
    mf = _mf(segs, {_SEG_VA: _segment_data(0x2000)},
             regions=[_region(_SEG_VA, 0x2000)])
    ctx, result = _run(mf, VirtualRange(_SEG_VA, 0x2000))

    closure = _one(result)
    assert closure.coverage_status == "partial"
    incomplete = [l for l in closure.limitations
                  if l.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE]
    assert incomplete and incomplete[0].detail == "overlapping_capture"


# ── full-scope behaviour is untouched ───────────────────────────────────

def test_full_scope_records_a_reader_returning_nothing_usable_as_a_read_failure():
    # The read clamp is defensive, but it also means a reader handing back
    # something with no extent is dispositioned as a failed read rather than
    # escaping the scan loop as an unhandled error -- pinned on the full-scope
    # path, which the clamp also governs.
    size = 0x1000

    class NoneReader:
        def read(self, addr, size):
            return None

    class MF(FakeMF):
        memory_segments_64 = FakeStream([Segment(_SEG_VA, _SEG_FO, size)], "memory_segments")
        memory_info = FakeStream([_region(_SEG_VA, size)], "infos")
        _reader = NoneReader()

    report = cs_beacon._build_cs_beacon_report(MF())
    assert report.coverage.scan.read_failed == 1
    assert report.coverage.scan.scanned == 0
    assert report.coverage_status != "complete"


def test_full_scope_still_skips_an_oversized_segment(monkeypatch):
    size = 0x2000
    data = _segment_data(size, config_offset=0x100)
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: data},
             regions=[_region(_SEG_VA, size)])
    monkeypatch.setattr(cs_beacon, "CS_MAX_SEG_SCAN", 0x100)

    report = cs_beacon._build_cs_beacon_report(mf)
    assert report.coverage.scan.skipped_oversize == 1
    assert report.coverage.scan.scanned == 0
