"""Targeted pipe rescan adapter (dumpex.hunt.pipe.targeted).

One targeted invocation collects pipe names and the C2 context around them from
a single requested virtual-address range, and projects the two signals as
independent closures: completing `pipe_name` never closes `c2_context`. Only
PIPE_SCAN_MAX is bypassed -- both whole-invocation budgets stay enforced and
stay separately attributed. Hit addresses and dump-file offsets stay absolute.
"""
import pytest

from dumpex.core.va_range import CaptureState, VirtualRange
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._observation import ObservationResult
from dumpex.hunt._request import HuntRequest
from dumpex.output.coverage import LimitationCode

import dumpex.hunt._budget as _budget_mod
import dumpex.hunt.pipe as _pipe
import dumpex.hunt.pipe.memory_scan as memory_scan
import dumpex.hunt.pipe.targeted as targeted
from dumpex.hunt.pipe.patterns import PIPE_PAT_ASCII

from tests.fixtures.fakes import FakeStream, Module, Region, Segment

_BASE = 0x10000000
_FILE_OFFSET = 0x3000
_SIZE = 0x2000

_PIPE_NAME = br"\\.\pipe\msagent_x"
_C2_TOKEN = b"http://10.0.0.5:8080/submit.php"
_NAME_OFF = 0x100
_C2_OFF = 0x140


def _payload(size=_SIZE, name_off=_NAME_OFF, c2_off=_C2_OFF):
    """A zero-filled buffer carrying one `\\pipe\\` name and, close enough to
    be proximity evidence for it, one C2 URL."""
    data = bytearray(b"\x00" * size)
    if name_off is not None:
        data[name_off:name_off + len(_PIPE_NAME)] = _PIPE_NAME
    if c2_off is not None:
        data[c2_off:c2_off + len(_C2_TOKEN)] = _C2_TOKEN
    return bytes(data)


def _mf(regions, segments, modules=()):
    class MF:
        pass
    MF.memory_info = FakeStream(list(regions), "infos")
    MF.memory_segments_64 = FakeStream(list(segments), "memory_segments")
    MF.memory_segments = None
    MF.modules = FakeStream(list(modules), "modules")
    return MF()


def _spanning_reader(captured):
    """A read_region_spanning stand-in: returns only the bytes the dump
    actually holds for [addr, addr+size), b'' past the captured run."""
    def _read(mf, addr, size):
        for base, data in captured.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off:off + size]
        return b""
    return _read


def _private_rw(base=_BASE, size=_SIZE, state="MEM_COMMIT"):
    return Region(base, base, size, state, "PAGE_READWRITE", "MEM_PRIVATE")


def _run(monkeypatch, *, requested, regions=None, segments=None,
         captured=None, reader=None, modules=()):
    if regions is None:
        regions = [_private_rw()]
    if segments is None:
        segments = [Segment(_BASE, _FILE_OFFSET, _SIZE)]
    mf = _mf(regions, segments, modules)
    monkeypatch.setattr(
        targeted, "read_region_spanning",
        reader if reader is not None else _spanning_reader(captured or {_BASE: _payload()}))
    request = HuntRequest.targeted("pipe", "pipe_name_scan", requested)
    ctx = build_execution_context(mf, request)
    return ctx, targeted.run_targeted_pipe(ctx)


def _closures(result):
    return {c.scope: c for c in result.closures}


def _codes(closure):
    return [limitation.code for limitation in closure.limitations]


def _search_incomplete(closure):
    return {l.detail for l in closure.limitations
            if l.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE}


def _many_names(count, size=_SIZE, stride=0x40, start=0x40):
    """`count` distinct `\\pipe\\` occurrences, each in its own printable run
    so the scan sees them as separate strings."""
    data = bytearray(b"\x00" * size)
    for index in range(count):
        name = br"\\.\pipe\lead%04d" % index
        offset = start + index * stride
        data[offset:offset + len(name)] = name
    return bytes(data)


def _distant_c2(count, size=0x4000, start=0x2000, stride=0x40):
    """One pipe name at the front and `count` C2 URLs far enough past it to be
    context-only (non-proximity) evidence. Each URL yields exactly one match of
    the combined C2 pattern, so the retained count is the token count."""
    data = bytearray(b"\x00" * size)
    data[0x40:0x40 + len(_PIPE_NAME)] = _PIPE_NAME
    for index in range(count):
        token = b"http://host%02d.example/" % index
        offset = start + index * stride
        data[offset:offset + len(token)] = token
    return bytes(data)


# ── request validation ──────────────────────────────────────────────────

def test_a_full_scope_request_is_refused_before_any_read():
    ctx = build_execution_context(_mf([], []), HuntRequest.full("pipe"))
    with pytest.raises(targeted.TargetedPipeError):
        targeted.run_targeted_pipe(ctx)


def test_another_analyzers_targeted_request_is_refused():
    request = HuntRequest.targeted("stomping", "ioc_string_scan",
                                   VirtualRange(_BASE, 0x1000))
    ctx = build_execution_context(_mf([], []), request)
    with pytest.raises(targeted.TargetedPipeError):
        targeted.run_targeted_pipe(ctx)


# ── structure, absolute addresses, and the payload ──────────────────────

def test_two_independent_closures_in_fixed_order_with_evidence_payload(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    assert isinstance(result, ObservationResult)
    assert result.key.analyzer == "pipe" and result.key.is_targeted
    assert result.key.requested_range == VirtualRange(_BASE, _SIZE)
    assert [c.scope for c in result.closures] == ["pipe_name", "c2_context"]
    assert {c.source for c in result.closures} == {"pipe_name_scan"}

    payload = result.payload
    assert isinstance(payload, targeted.TargetedPipeEvidence)
    assert payload.containing_region.base_address == _BASE
    assert payload.containing_region.size == _SIZE


def test_hits_report_absolute_virtual_addresses_and_file_offsets(monkeypatch):
    # Request the second half only: the name and the C2 token sit inside it.
    data = _payload(name_off=0x1100, c2_off=0x1140)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE + 0x1000, 0x1000),
                       captured={_BASE: data})

    # The pattern's own match offset, not the byte the fixture wrote the name
    # at: what is being pinned is that the offset is carried through to an
    # absolute address, not where the regex anchors.
    name_at = PIPE_PAT_ASCII.search(data).start()
    leads = result.payload.string_leads
    assert leads, "the pipe name inside the requested slice produced no lead"
    lead = leads[0]
    assert lead.va == _BASE + name_at
    assert lead.file_offset == _FILE_OFFSET + name_at
    assert lead.region.base_address == _BASE + 0x1000

    records = [r for group in result.payload.c2_regions for r in group.records]
    assert records, "the C2 token next to the name produced no context record"
    assert records[0].va == _BASE + 0x1140
    assert all(_BASE + 0x1000 <= r.va < _BASE + 0x2000 for r in records)


def test_fully_captured_range_with_no_pipe_name_completes_both_scopes(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: b"\x00" * _SIZE})

    for closure in result.closures:
        assert closure.capture_state == CaptureState.COMPLETE
        assert closure.coverage_status == "complete"
        assert closure.limitations == ()
        assert closure.read_slice.read_bytes == _SIZE
    assert result.payload.string_leads == ()


def test_a_pipe_name_past_the_requested_range_is_never_returned(monkeypatch):
    # The reader hands back more than the requested extent. A hit outside the
    # requested range is not this closure's to report, and a `complete` closure
    # carrying it would be actively false.
    data = _payload(name_off=0x1100, c2_off=None)

    def _over_serving(mf, addr, size):
        off = addr - _BASE
        return data[off:] if 0 <= off < len(data) else b""

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, 0x1000),
                       reader=_over_serving)

    assert result.payload.string_leads == ()
    for closure in result.closures:
        assert closure.coverage_status == "complete"
        assert closure.read_slice.read_bytes == 0x1000


# ── the bypassed cap, and the ones that stay ────────────────────────────

def test_oversized_range_is_scanned_where_full_scope_would_skip_it(monkeypatch):
    monkeypatch.setattr(memory_scan, "PIPE_SCAN_MAX", 0x100)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    for closure in result.closures:
        assert LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED not in _codes(closure)
    assert result.payload.string_leads, "the bypassed cap did not let the range be read"


def test_full_scope_still_skips_the_same_oversized_region(monkeypatch):
    # The other half of the bypass contract: the ordinary per-region skip is
    # unchanged, so the same target full mode declines is the one targeted mode
    # reads above.
    monkeypatch.setattr(memory_scan, "PIPE_SCAN_MAX", 0x100)
    region = _private_rw()
    mf = _mf([region], [Segment(_BASE, _FILE_OFFSET, _SIZE)])

    def _budget(max_hits):
        return ScanBudget(max_bytes_read=1 << 30, max_attempts=10 ** 9,
                          max_retained_bytes=1 << 20, max_hits=max_hits)

    scan = memory_scan.scan_pipe_names(
        mf, lambda _mf, addr, size: _payload(), [region], [], CoverageTracker(),
        _budget(500), _budget(200), [])

    assert scan.string_leads == ()
    assert [t.size_limit for t in scan.coverage.skipped_oversize_targets] == [0x100]


def test_both_budgets_are_registered_on_the_context_ledger(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))
    assert set(ctx.budgets.names()) == {targeted.BUDGET_PIPE_NAME, targeted.BUDGET_C2}
    outcomes = {c.scope: c.budget_outcomes[0].name for c in result.closures}
    assert outcomes == {"pipe_name": targeted.BUDGET_PIPE_NAME,
                        "c2_context": targeted.BUDGET_C2}


def test_a_spent_pipe_name_budget_leaves_both_scopes_not_evaluated(monkeypatch):
    monkeypatch.setattr(_pipe, "PIPE_NAME_BUDGET_TIME_SECONDS", -1.0)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    # No pattern ran at all, so neither signal can vouch for the range -- and
    # C2 records are anchored on pipe-name hits that were never collected.
    for closure in result.closures:
        assert closure.coverage_status == "not_evaluated"
        assert closure.read_slice is None
        assert closure.diagnostics


def test_a_spent_c2_budget_leaves_the_pipe_name_scope_untouched(monkeypatch):
    monkeypatch.setattr(_pipe, "PIPE_C2_BUDGET_TIME_SECONDS", -1.0)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    closures = _closures(result)
    # Completing one scope does not close the other, in either direction.
    assert closures["pipe_name"].coverage_status == "complete"
    assert closures["c2_context"].coverage_status == "not_evaluated"
    assert result.payload.string_leads, "pipe-name collection was cut by the C2 budget"
    assert result.payload.c2_regions == ()

    budget = [l for l in closures["c2_context"].limitations
              if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "c2_context"
    assert (budget[0].targets[0].base_address, budget[0].targets[0].size) == (_BASE, _SIZE)


def test_a_spent_c2_budget_over_a_range_with_no_anchor_is_not_a_gap(monkeypatch):
    # C2 records are gathered around this range's own pipe-name hits. With no
    # pipe name here, the C2 pass would not have run under any budget, so
    # reporting a gap would send an analyst after a larger-budget rerun that
    # can never return anything.
    monkeypatch.setattr(_pipe, "PIPE_C2_BUDGET_TIME_SECONDS", -1.0)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: b"\x00" * _SIZE})

    closures = _closures(result)
    assert result.payload.string_leads == ()
    assert closures["c2_context"].coverage_status == "complete"
    assert closures["pipe_name"].coverage_status == "complete"


def test_a_cut_pipe_name_pass_makes_the_c2_scope_partial(monkeypatch):
    # The C2 pass retains records against THIS range's own pipe-name hits, so a
    # name pass the pipe-name budget cut short leaves its anchors incomplete
    # too. The gap belongs to the closure that owns the budget: `pipe_name`
    # raises it, and `c2_context` carries the same dependency through its own
    # status and its own diagnostic rather than a second copy of it.
    monkeypatch.setattr(_pipe, "PIPE_NAME_BUDGET_MAX_HITS", 0)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    closures = _closures(result)
    assert closures["pipe_name"].coverage_status == "partial"
    assert closures["c2_context"].coverage_status == "partial"

    def _budget(scope):
        return [l.scope for l in closures[scope].limitations
                if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]

    assert _budget("pipe_name") == ["pipe_name"]
    assert _budget("c2_context") == []
    assert any("stopped short of its own budget" in note
               for note in closures["c2_context"].diagnostics)


def test_one_context_shares_one_cumulative_budget_across_two_ranges(monkeypatch):
    mf = _mf([_private_rw()], [Segment(_BASE, _FILE_OFFSET, _SIZE)])
    monkeypatch.setattr(targeted, "read_region_spanning",
                        _spanning_reader({_BASE: _payload()}))
    request = HuntRequest.targeted("pipe", "pipe_name_scan", VirtualRange(_BASE, _SIZE))
    ctx = build_execution_context(mf, request)

    targeted.run_targeted_pipe(ctx)
    first = ctx.budgets.get(targeted.BUDGET_PIPE_NAME)
    targeted.run_targeted_pipe(ctx)
    assert ctx.budgets.get(targeted.BUDGET_PIPE_NAME) is first


# ── the budget window covers the target read ────────────────────────────
#
# A targeted range runs up to the whole request ceiling, so reading it is the
# expensive part of the rescan, not free setup before the budgeted part. Both
# deadlines therefore have to be running while the read runs -- and a range
# neither pass can make a claim about must not be read at all.


class _Clock:
    """A `time.monotonic` stand-in whose only motion is what a test asks for,
    so a read's duration is exact instead of raced against the wall clock."""

    def __init__(self, now=1000.0):
        self.now = now

    def monotonic(self) -> float:
        return self.now


def _fixed_clock(monkeypatch, now=1000.0) -> _Clock:
    """Drive the clock the budgets' deadlines are BUILT from and the one
    `ScanBudget.exhausted()` compares against off one controllable source --
    patching only one of the two would move the deadline and the comparison
    apart and prove nothing."""
    clock = _Clock(now)
    monkeypatch.setattr(_pipe, "time", clock)
    monkeypatch.setattr(_budget_mod, "time", clock)
    return clock


def test_a_read_that_outlasts_both_deadlines_leaves_neither_scope_complete(monkeypatch):
    # The read alone takes longer than either budget allows. A closure reporting
    # `complete` here would be a clean negative for a search that never ran.
    clock = _fixed_clock(monkeypatch)
    over = max(_pipe.PIPE_NAME_BUDGET_TIME_SECONDS,
               _pipe.PIPE_C2_BUDGET_TIME_SECONDS) + 1.0

    def _slow(mf, addr, size):
        clock.now += over
        return _payload()

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE), reader=_slow)

    assert ctx.budgets.get(targeted.BUDGET_PIPE_NAME).exhausted_reason == "deadline"
    assert result.payload.string_leads == ()
    for closure in result.closures:
        assert closure.coverage_status == "not_evaluated"
        # A budget the read itself consumed points at a different rerun than one
        # an earlier range had already used up, so the note distinguishes them.
        assert any("while this range was being read" in note
                   for note in closure.diagnostics)
    # One deadline, raised once, by the one closure whose budget it was.
    closures = _closures(result)
    assert [(l.scope, l.detail) for l in closures["pipe_name"].limitations
            if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED] == [("pipe_name", "deadline")]
    assert not [l for l in closures["c2_context"].limitations
                if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]


def test_a_read_crossing_only_the_c2_deadline_leaves_pipe_name_complete(monkeypatch):
    # The read is charged against both deadlines INDEPENDENTLY: long enough to
    # spend the C2 budget, well inside the pipe-name one. The two stay
    # separately attributed across the read exactly as they do across a scan.
    clock = _fixed_clock(monkeypatch)
    monkeypatch.setattr(_pipe, "PIPE_C2_BUDGET_TIME_SECONDS", 10.0)
    monkeypatch.setattr(_pipe, "PIPE_NAME_BUDGET_TIME_SECONDS", 600.0)

    def _slow(mf, addr, size):
        clock.now += 20.0
        return _payload()

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE), reader=_slow)

    closures = _closures(result)
    assert closures["pipe_name"].coverage_status == "complete"
    assert result.payload.string_leads, "the pipe-name pass was cut by the C2 deadline"
    assert closures["c2_context"].coverage_status == "partial"
    assert result.payload.c2_regions == ()
    budget = [l for l in closures["c2_context"].limitations
              if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]
    assert [(l.scope, l.detail) for l in budget] == [("c2_context", "deadline")]


def test_a_range_both_budgets_are_already_spent_for_is_never_read(monkeypatch):
    # Neither pass can make a claim about these bytes, so paying to read them
    # buys nothing. Both budgets are still attributed -- the range is unresolved
    # for both scopes, which is the fact a rerun with more budget acts on.
    monkeypatch.setattr(_pipe, "PIPE_NAME_BUDGET_TIME_SECONDS", -1.0)
    monkeypatch.setattr(_pipe, "PIPE_C2_BUDGET_TIME_SECONDS", -1.0)
    reads = []

    def _counting(mf, addr, size):
        reads.append((addr, size))
        return _payload()

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE), reader=_counting)

    assert reads == [], "the range was read even though neither pass could use it"
    for closure in result.closures:
        assert closure.coverage_status == "not_evaluated"
        assert closure.read_slice is None
        assert any("was not read" in note for note in closure.diagnostics)

    # Both budgets are still attributed -- the range is unresolved for both
    # scopes, which is the fact a rerun with more budget acts on -- and each
    # exhaustion is raised once, by the closure that owns that budget.
    closures = _closures(result)
    assert [(l.scope, l.detail) for l in closures["c2_context"].limitations
            if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED] == [("c2_context", "deadline")]
    assert [(l.scope, l.detail) for l in closures["pipe_name"].limitations
            if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED] == [("pipe_name", "deadline")]


def test_one_execution_reads_the_range_once_and_never_outside_it(monkeypatch):
    # One request is one read, however many times a pass asks for the bytes:
    # the second ask reuses what the first produced instead of going back to
    # the dump. An ask for any other address is outside the requested range and
    # yields nothing, so no pass can reach a byte the closures do not cover.
    reads = []
    probes = {}
    real_scan = memory_scan.scan_pipe_names

    def _spy(mf, read_region, regions, *args, **kwargs):
        base = regions[0].BaseAddress
        probes["first"] = read_region(mf, base, _SIZE)
        probes["again"] = read_region(mf, base, _SIZE)
        probes["outside"] = read_region(mf, base + _SIZE, _SIZE)
        return real_scan(mf, read_region, regions, *args, **kwargs)

    monkeypatch.setattr(memory_scan, "scan_pipe_names", _spy)

    def _counting(mf, addr, size):
        reads.append((addr, size))
        return _payload()

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE), reader=_counting)

    assert reads == [(_BASE, _SIZE)], "the range was read more than once"
    assert probes["first"] == probes["again"] == _payload()
    assert probes["outside"] == b""
    assert result.payload.string_leads and result.payload.c2_regions


# ── per-region quotas the cap bypass makes reachable ────────────────────
#
# Full scope never hands one region more than PIPE_SCAN_MAX; targeted mode
# hands a single synthetic region up to the request ceiling, so a rescan of
# exactly the oversized region this feature exists for is where these quotas
# start dropping evidence. A quota that drops an occurrence must not leave a
# closure claiming a full search.

def test_the_match_quota_dropping_an_occurrence_makes_pipe_name_partial(monkeypatch):
    from dumpex.hunt.pipe.config import PIPE_MAX_MATCHES_PER_REGION

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: _many_names(PIPE_MAX_MATCHES_PER_REGION + 1)})

    closures = _closures(result)
    assert len(result.payload.string_leads) == PIPE_MAX_MATCHES_PER_REGION
    assert closures["pipe_name"].coverage_status == "partial"
    assert "match_cap_reached" in _search_incomplete(closures["pipe_name"])
    # The C2 pass anchors on those same names, so its own negative is not a
    # full-search negative either.
    assert closures["c2_context"].coverage_status == "partial"
    assert "match_cap_reached" in _search_incomplete(closures["c2_context"])


def test_exactly_the_match_quota_is_still_a_complete_search(monkeypatch):
    from dumpex.hunt.pipe.config import PIPE_MAX_MATCHES_PER_REGION

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: _many_names(PIPE_MAX_MATCHES_PER_REGION)})

    closures = _closures(result)
    assert len(result.payload.string_leads) == PIPE_MAX_MATCHES_PER_REGION
    assert closures["pipe_name"].coverage_status == "complete"
    assert _search_incomplete(closures["pipe_name"]) == set()


def test_the_context_only_quota_dropping_a_record_makes_c2_partial(monkeypatch):
    from dumpex.hunt.pipe.config import PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION

    size = 0x4000
    ctx, result = _run(
        monkeypatch, requested=VirtualRange(_BASE, size),
        regions=[_private_rw(size=size)], segments=[Segment(_BASE, _FILE_OFFSET, size)],
        captured={_BASE: _distant_c2(PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION + 3, size=size)})

    closures = _closures(result)
    records = [r for group in result.payload.c2_regions for r in group.records]
    assert len(records) == PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION
    assert closures["c2_context"].coverage_status == "partial"
    assert "context_only_cap_reached" in _search_incomplete(closures["c2_context"])
    # The quota bounds C2 retention only; pipe-name collection is untouched.
    assert closures["pipe_name"].coverage_status == "complete"


def test_exactly_the_context_only_quota_is_still_a_complete_search(monkeypatch):
    from dumpex.hunt.pipe.config import PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION

    size = 0x4000
    ctx, result = _run(
        monkeypatch, requested=VirtualRange(_BASE, size),
        regions=[_private_rw(size=size)], segments=[Segment(_BASE, _FILE_OFFSET, size)],
        captured={_BASE: _distant_c2(PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION, size=size)})

    closures = _closures(result)
    records = [r for group in result.payload.c2_regions for r in group.records]
    assert len(records) == PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION
    assert closures["c2_context"].coverage_status == "complete"
    assert _search_incomplete(closures["c2_context"]) == set()


def test_an_overlapping_capture_makes_both_scopes_partial(monkeypatch):
    # Two segment-table entries place the same virtual run at two file
    # offsets. The bytes searched are one arbitrary choice among conflicting
    # claims, so neither negative is authoritative -- even though every
    # requested byte is captured.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       segments=[Segment(_BASE, _FILE_OFFSET, _SIZE),
                                 Segment(_BASE, _FILE_OFFSET + 0x10000, _SIZE)])

    for closure in result.closures:
        assert closure.capture_state == CaptureState.COMPLETE
        assert closure.coverage_status == "partial"
        assert "overlapping_capture" in _search_incomplete(closure)


# ── descriptor boundaries ───────────────────────────────────────────────

def test_a_request_past_the_region_end_is_captured_whole_but_evaluated_short(monkeypatch):
    regions = [_private_rw(size=0x1000)]
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE), regions=regions)

    for closure in result.closures:
        assert closure.capture_state == CaptureState.COMPLETE
        assert closure.coverage_status == "partial"
        truncated = [l for l in closure.limitations
                     if l.code == LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED]
        assert truncated and truncated[0].scope == closure.scope
        assert (truncated[0].targets[0].base_address, truncated[0].targets[0].size) \
            == (_BASE, _SIZE)


def test_a_sub_range_of_a_larger_allocation_says_so(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, 0x1000))

    for closure in result.closures:
        assert closure.coverage_status == "complete"
        assert any("sub-range" in note for note in closure.diagnostics)


def test_a_base_in_no_region_is_not_evaluated_for_either_scope(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(0x50000000, 0x1000),
                       segments=[])

    for closure in result.closures:
        assert closure.coverage_status == "not_evaluated"
        assert closure.capture_state == CaptureState.NONE
        assert closure.read_slice is None
    assert result.payload is None


def test_an_uncommitted_region_is_not_applicable_for_either_scope(monkeypatch):
    # Uncommitted memory is outside the population this source examines at all,
    # so both closures decline the target and name the gate -- distinct from a
    # range this source would have searched and could not.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       regions=[_private_rw(state="MEM_RESERVE")])

    for closure in result.closures:
        assert closure.coverage_status == "not_applicable"
        assert closure.applicability_reason == "region_not_committed"
        assert any("not committed" in note for note in closure.diagnostics)


# ── short and failed reads ──────────────────────────────────────────────

def test_a_short_capture_names_the_exact_unread_suffix(monkeypatch):
    # The dump backs only the first half of the requested range.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       segments=[Segment(_BASE, _FILE_OFFSET, 0x1000)],
                       captured={_BASE: _payload(size=0x1000)})

    for closure in result.closures:
        assert closure.capture_state == CaptureState.PARTIAL
        assert closure.coverage_status == "partial"
        assert closure.read_slice.read_bytes == 0x1000
        assert closure.read_slice.unread_suffix == VirtualRange(_BASE + 0x1000, 0x1000)
        assert LimitationCode.SCAN_REGION_SHORT_READ in _codes(closure)
    # The evidence inside the readable prefix is still real evidence.
    assert result.payload.string_leads


def test_a_failed_read_is_not_evaluated_for_either_scope(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       reader=lambda mf, addr, size: b"")

    for closure in result.closures:
        assert closure.coverage_status == "not_evaluated"
        assert closure.read_slice is None
        assert LimitationCode.SCAN_REGION_READ_FAILED in _codes(closure)


# ── the sources this executor does NOT speak for ────────────────────────

def test_a_clean_result_makes_no_claim_about_handle_evidence(monkeypatch):
    # Handle data is a different coverage source; a `pipe_name_scan` closure
    # never projects one for it.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))
    assert {c.source for c in result.closures} == {"pipe_name_scan"}
    with pytest.raises(KeyError):
        result.closure_for("handle_data")


def test_a_system_dll_pipe_reference_is_not_retained_as_a_lead(monkeypatch):
    # The same expected-reference rule as full-scope: a pipe name inside a
    # Microsoft system DLL is a --verbose fact, never a retained lead.
    region = Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")
    module = Module(_BASE, _SIZE, r"C:\Windows\System32\rpcrt4.dll")
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       regions=[region], modules=[module])

    assert result.payload.string_leads == ()
    assert result.payload.coverage.image_pipe_refs == 1
    # Suppressing the lead also leaves the C2 passes with nothing to gather
    # around, so the C2 negative names the suppression instead of standing
    # unexplained -- the payload count alone reaches no reader of the closure.
    c2 = _closures(result)["c2_context"]
    assert result.payload.c2_regions == ()
    assert any("system-DLL references" in note for note in c2.diagnostics)
