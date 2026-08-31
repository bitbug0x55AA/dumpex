"""Targeted stomping rescan adapter (dumpex.hunt.stomping.targeted).

One targeted invocation runs the unscored IOC-string scan over a single
requested virtual-address range. Only IOC_SCAN_MAX is bypassed; hit addresses
stay absolute; reads never escape the requested range. The single closure
speaks for `ioc_string_scan` alone -- it never asserts that stomping's module,
header, reference-file, or content-diff sources were evaluated.
"""
import pytest

from dumpex.core.va_range import CaptureState, VirtualRange
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._observation import ObservationResult
from dumpex.hunt._request import HuntRequest
from dumpex.output.coverage import LimitationCode

import dumpex.hunt.stomping.memory_scan as memory_scan
import dumpex.hunt.stomping.targeted as targeted

from tests.fixtures.fakes import FakeStream, Module, Region, Segment

_BASE = 0x10000000
_FILE_OFFSET = 0x3000
_SIZE = 0x2000

# "meterpreter" is a strong token; "VirtualAlloc" is one of the weak,
# common-API ones a lead is never built from on its own.
_STRONG = b"meterpreter-stage\x00"
_WEAK = b"VirtualAllocEx\x00"
_STRONG_OFF = 0x200


def _payload(size=_SIZE, token=_STRONG, offset=_STRONG_OFF):
    data = bytearray(b"\x00" * size)
    if token is not None:
        data[offset:offset + len(token)] = token
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


def _exec_image(base=_BASE, size=_SIZE, state="MEM_COMMIT",
                protect="PAGE_EXECUTE_READ", mtype="MEM_IMAGE"):
    return Region(base, base, size, state, protect, mtype)


def _run(monkeypatch, *, requested, regions=None, segments=None, captured=None,
         reader=None, modules=()):
    if regions is None:
        regions = [_exec_image()]
    if segments is None:
        segments = [Segment(_BASE, _FILE_OFFSET, _SIZE)]
    mf = _mf(regions, segments, modules)
    monkeypatch.setattr(
        targeted, "read_region_spanning",
        reader if reader is not None else _spanning_reader(captured or {_BASE: _payload()}))
    request = HuntRequest.targeted("stomping", "ioc_string_scan", requested)
    ctx = build_execution_context(mf, request)
    return ctx, targeted.run_targeted_stomping(ctx)


def _one(result):
    assert len(result.closures) == 1
    return result.closures[0]


def _codes(closure):
    return [limitation.code for limitation in closure.limitations]


def _tokens(result):
    return [t.token for hit in result.payload.hits for t in hit.tokens]


def _ioc_patterns():
    from dumpex.rules_pkg.loader import get_rules
    rules = get_rules(announce=False)
    return rules["stomping_ioc_patterns"], rules["stomping_net_ioc_patterns"]


# ── request validation ──────────────────────────────────────────────────

def test_a_full_scope_request_is_refused_before_any_read():
    ctx = build_execution_context(_mf([], []), HuntRequest.full("stomping"))
    with pytest.raises(targeted.TargetedStompingError):
        targeted.run_targeted_stomping(ctx)


def test_another_analyzers_targeted_request_is_refused():
    request = HuntRequest.targeted("pipe", "pipe_name_scan", VirtualRange(_BASE, 0x1000))
    ctx = build_execution_context(_mf([], []), request)
    with pytest.raises(targeted.TargetedStompingError):
        targeted.run_targeted_stomping(ctx)


# ── structure, absolute addresses, and the payload ──────────────────────

def test_one_ioc_closure_with_an_evidence_payload(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    assert isinstance(result, ObservationResult)
    assert result.key.analyzer == "stomping" and result.key.is_targeted
    assert result.key.requested_range == VirtualRange(_BASE, _SIZE)

    closure = _one(result)
    assert closure.source == "ioc_string_scan" and closure.scope is None

    payload = result.payload
    assert isinstance(payload, targeted.TargetedStompingEvidence)
    assert payload.containing_region.base_address == _BASE
    assert payload.containing_region.size == _SIZE


def test_hits_report_absolute_virtual_addresses(monkeypatch):
    # Request the second half only: the token sits 0x100 bytes into it.
    data = _payload(offset=0x1100)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE + 0x1000, 0x1000),
                       captured={_BASE: data})

    hits = result.payload.hits
    assert hits, "the IOC token inside the requested slice produced no hit"
    hit = hits[0]
    assert hit.region.base_address == _BASE + 0x1000
    assert [t.va for t in hit.tokens] == [_BASE + 0x1100]
    assert [t.is_weak for t in hit.tokens] == [False]


def test_fully_captured_range_with_no_ioc_is_complete_and_clean(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: b"\x00" * _SIZE})

    closure = _one(result)
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "complete"
    assert closure.limitations == ()
    assert closure.read_slice.read_bytes == _SIZE
    assert result.payload.hits == ()


def test_a_weak_only_token_is_not_a_lead_but_coverage_still_completes(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: _payload(token=_WEAK)})

    closure = _one(result)
    assert closure.coverage_status == "complete"
    assert result.payload.hits == ()
    assert result.payload.weak_only_regions == 1


def test_an_ioc_past_the_requested_range_is_never_returned(monkeypatch):
    # The reader hands back more than the requested extent. A hit outside the
    # requested range is not this closure's to report, and a `complete` closure
    # carrying it would be actively false.
    data = _payload(offset=0x1100)

    def _over_serving(mf, addr, size):
        off = addr - _BASE
        return data[off:] if 0 <= off < len(data) else b""

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, 0x1000),
                       reader=_over_serving)

    closure = _one(result)
    assert result.payload.hits == ()
    assert closure.coverage_status == "complete"
    assert closure.read_slice.read_bytes == 0x1000


# ── the bypassed cap, and what it does not touch ────────────────────────

def test_oversized_range_is_scanned_where_full_scope_would_skip_it(monkeypatch):
    monkeypatch.setattr(memory_scan, "IOC_SCAN_MAX", 0x100)
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE))

    closure = _one(result)
    assert LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED not in _codes(closure)
    assert closure.coverage_status == "complete"
    assert _tokens(result) == ["meterpreter"]


def test_full_scope_still_skips_the_same_oversized_region(monkeypatch):
    # The other half of the bypass contract: the ordinary per-region skip is
    # unchanged, so the same target full mode declines is the one targeted mode
    # reads above.
    monkeypatch.setattr(memory_scan, "IOC_SCAN_MAX", 0x100)
    region = _exec_image()
    mf = _mf([region], [Segment(_BASE, _FILE_OFFSET, _SIZE)])
    rules_patterns = _ioc_patterns()

    scan = memory_scan.scan_ioc_strings(
        mf, lambda _mf, addr, size: _payload(), [region], [], frozenset(),
        *rules_patterns)

    assert scan.hits == ()
    assert [t.size_limit for t in scan.coverage.skipped_oversize_targets] == [0x100]


# ── descriptor boundaries ───────────────────────────────────────────────

def test_a_request_past_the_region_end_is_captured_whole_but_evaluated_short(monkeypatch):
    # The token sits past the containing region's end: captured, but outside
    # what this closure is allowed to evaluate.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       regions=[_exec_image(size=0x1000)],
                       captured={_BASE: _payload(offset=0x1500)})

    closure = _one(result)
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "partial"
    truncated = [l for l in closure.limitations
                 if l.code == LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED]
    assert truncated
    assert (truncated[0].targets[0].base_address, truncated[0].targets[0].size) \
        == (_BASE, _SIZE)
    # Evaluation stopped at the boundary, so the token past it is not reported.
    assert result.payload.hits == ()


def test_a_sub_range_of_a_larger_allocation_says_so(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, 0x1000))

    closure = _one(result)
    assert closure.coverage_status == "complete"
    assert any("sub-range" in note for note in closure.diagnostics)


def test_a_base_in_no_region_is_not_evaluated(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(0x50000000, 0x1000),
                       segments=[])

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    assert closure.capture_state == CaptureState.NONE
    assert closure.read_slice is None
    assert result.payload is None


@pytest.mark.parametrize("region,reason", [
    (Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE"),
     "region_type_ineligible"),
    (Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
     "region_protection_ineligible"),
    (Region(_BASE, _BASE, _SIZE, "MEM_RESERVE", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
     "region_not_committed"),
])
def test_an_ineligible_region_is_not_applicable_with_its_reason(monkeypatch, region, reason):
    # The same source-eligibility gate as full-scope: committed, executable
    # MEM_IMAGE only. A target outside that population is one this source does
    # not apply to -- distinct from one it would have examined and could not,
    # and named by the exact filter that declined it. An inherited region fact
    # is context, not a result.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       regions=[region])

    closure = _one(result)
    assert closure.coverage_status == "not_applicable"
    assert closure.applicability_reason == reason
    assert closure.read_slice is None
    assert closure.diagnostics


# ── short and failed reads ──────────────────────────────────────────────

def test_a_short_capture_names_the_exact_unread_suffix(monkeypatch):
    # The dump backs only the first half of the requested range; the token
    # sits inside that half.
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       segments=[Segment(_BASE, _FILE_OFFSET, 0x1000)],
                       captured={_BASE: _payload(size=0x1000)})

    closure = _one(result)
    assert closure.capture_state == CaptureState.PARTIAL
    assert closure.coverage_status == "partial"
    assert closure.read_slice.read_bytes == 0x1000
    assert closure.read_slice.unread_suffix == VirtualRange(_BASE + 0x1000, 0x1000)
    assert LimitationCode.SCAN_REGION_SHORT_READ in _codes(closure)
    # The evidence inside the readable prefix is still real evidence.
    assert _tokens(result) == ["meterpreter"]


def test_a_failed_read_is_not_evaluated(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       reader=lambda mf, addr, size: b"")

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    assert closure.read_slice is None
    assert LimitationCode.SCAN_REGION_READ_FAILED in _codes(closure)


# ── the sources this executor does NOT speak for ────────────────────────

def test_a_clean_ioc_closure_makes_no_claim_about_the_other_sources(monkeypatch):
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: b"\x00" * _SIZE})

    assert {c.source for c in result.closures} == {"ioc_string_scan"}
    for source in ("modules", "module_headers", "reference_files",
                   "section_content_diff", "memory_info"):
        assert not result.has_closure(source)
        with pytest.raises(KeyError):
            result.closure_for(source)


def test_a_whitelisted_module_still_drops_the_network_pattern_set(monkeypatch):
    # The whitelist decision is unchanged in targeted mode: a network string
    # inside a whitelisted network DLL is expected, not a lead. What the
    # closure must not do is present the result as a clean network-IOC
    # negative, because the network patterns were never applied.
    url = b"http://10.0.0.5:8080/beacon-path\x00"
    module = Module(_BASE, _SIZE, r"C:\Windows\System32\ws2_32.dll")
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: _payload(token=url)}, modules=[module])

    # "beacon" is a non-network IOC term and still matches; the URL and the
    # IP:port, which only the network set carries, do not.
    assert _tokens(result) == ["beacon"]
    closure = _one(result)
    assert closure.coverage_status == "partial"
    withheld = [l for l in closure.limitations
                if l.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE]
    assert [l.detail for l in withheld] == ["pattern_set_withheld"]
    assert any("ws2_32.dll" in note for note in closure.diagnostics)


def test_the_withheld_pattern_set_is_recorded_whether_or_not_the_range_hits(monkeypatch):
    # The pre-existing `whitelisted_skipped` console fact is only appended on
    # the no-hit path, so it cannot answer "was a pattern class withheld here".
    module = Module(_BASE, _SIZE, r"C:\Windows\System32\ws2_32.dll")

    def _withheld(token):
        _ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                            captured={_BASE: _payload(token=token)}, modules=[module])
        return result.payload.coverage.network_ioc_withheld

    assert _withheld(b"http://10.0.0.5:8080/beacon-path\x00") == ("ws2_32.dll",)
    assert _withheld(b"nothing-interesting-here\x00") == ("ws2_32.dll",)


def test_a_non_whitelisted_range_records_no_withheld_pattern_set(monkeypatch):
    module = Module(_BASE, _SIZE, r"C:\tmp\evil.dll")
    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       modules=[module])

    assert result.payload.coverage.network_ioc_withheld == ()
    assert _one(result).coverage_status == "complete"


def test_a_utf16_token_reports_its_true_byte_address(monkeypatch):
    # A pattern match reports a CHARACTER index into the decoded run; a hit's
    # VA is a byte address. For UTF-16LE the two differ by a factor of two, and
    # the whole product of a targeted rescan is an address an investigator
    # extracts or pivots on.
    prefix = "PADPADPADPADPADP"
    run = (prefix + "meterpreter").encode("utf-16-le")
    run_at = 0x200
    data = bytearray(b"\x00" * _SIZE)
    data[run_at:run_at + len(run)] = run

    ctx, result = _run(monkeypatch, requested=VirtualRange(_BASE, _SIZE),
                       captured={_BASE: bytes(data)})

    hits = result.payload.hits
    assert hits, "the UTF-16LE IOC token produced no hit"
    token = hits[0].tokens[0]
    assert token.encoding == "UTF16"
    assert token.token == "meterpreter"
    assert token.offset == run_at + len(prefix) * 2
    assert token.va == _BASE + run_at + len(prefix) * 2
