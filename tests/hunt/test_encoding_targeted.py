"""Targeted obfuscation rescan adapter (dumpex.hunt.encoding.targeted).

One targeted invocation runs the sleep-mask, entropy, and decode layers over a
single requested virtual-address range. Each layer projects its own
ObservationClosure; one layer's gate failure or gap never changes another's.
Only the per-region size cap is bypassed -- every other budget stays enforced.
The per-layer scan results are reachable off the result payload.
"""
import base64
import random
import time

import pytest

from dumpex.core.va_range import CaptureState, VirtualRange
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._observation import ObservationResult
from dumpex.hunt._request import HuntRequest
from dumpex.output.coverage import LimitationCode

import dumpex.hunt.encoding as _enc
import dumpex.hunt.encoding.targeted as targeted
import dumpex.hunt.encoding.sleep_mask as sleep_mask
from dumpex.hunt.encoding.entropy import _scan_entropy
from dumpex.hunt.encoding.config import EncodingConfig

from tests.fixtures.fakes import (FakeStream, Module, Region, Segment, build_pe_header,
                                  IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ)

_MIB = 1 << 20
_BASE = 0x10000000

# 13-byte key with high average-consecutive-byte-difference, no byte repeated
# >= SLEEP_MASK_MAX_BYTE_FREQ times -- passes _sm_recover_candidates' filters.
_SM_KEY = bytes([0, 200, 10, 210, 20, 220, 30, 230, 40, 240, 50, 250, 60])
_SM_MARKER = b"sha256\x00"


def _mf(regions, segments, modules=()):
    class MF:
        memory_info = FakeStream(regions, "infos")
        memory_segments_64 = FakeStream(segments, "memory_segments")
        memory_segments = None
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


def _over_serving_reader(data, base):
    """A reader that hands back the whole buffer regardless of what the segment
    table says is captured -- models the raw minidump reader over-serving past a
    descriptor the capture model dropped."""
    def _read(mf, addr, size):
        off = addr - base
        return data[off:off + size] if 0 <= off < len(data) else b""
    return _read


def _run(monkeypatch, *, region, segment_len=None, captured, requested,
         enc_override=None, budget_factory=None, reader=None, segments=None,
         modules=()):
    regions = [region]
    if segments is None:
        segments = ([Segment(region.BaseAddress, 0x1000, segment_len)]
                    if segment_len else [])
    mf = _mf(regions, segments, modules)
    monkeypatch.setattr(targeted, "read_region_spanning",
                        reader if reader is not None else _spanning_reader(captured))
    for name, value in (enc_override or {}).items():
        monkeypatch.setattr(_enc, name, value)
    if budget_factory is not None:
        monkeypatch.setattr(targeted, "_fresh_budget", budget_factory)
    request = HuntRequest.targeted("obfuscation", "encoding_scan", requested)
    ctx = build_execution_context(mf, request)
    return ctx, targeted.run_targeted_encoding(ctx)


def _private_rw(base, size):
    return Region(base, base, size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")


def _closures(result):
    return {c.scope: c for c in result.closures}


# ── structure & payload ─────────────────────────────────────────────────

def test_three_layer_closures_in_fixed_order_with_evidence_payload(monkeypatch):
    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    assert isinstance(result, ObservationResult)
    assert result.key.analyzer == "obfuscation"
    assert result.key.is_targeted
    assert result.key.requested_range == VirtualRange(_BASE, size)
    assert [c.scope for c in result.closures] == ["sleep_mask", "entropy", "decode"]
    assert {c.source for c in result.closures} == {"encoding_scan"}

    payload = result.payload
    assert isinstance(payload, targeted.TargetedEncodingEvidence)
    assert payload.sleep_mask is not None and payload.entropy is not None
    assert payload.decode is not None
    assert payload.containing_region.base_address == _BASE


def test_fully_captured_low_entropy_range_completes_every_layer(monkeypatch):
    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    for c in result.closures:
        assert c.capture_state == CaptureState.COMPLETE
        assert c.coverage_status == "complete"
        assert c.limitations == ()


# ── findings are reachable per layer ────────────────────────────────────

def test_recovered_sleep_mask_key_and_hit_offset_reach_the_payload(monkeypatch):
    plaintext = bytearray(b"\x00" * (len(_SM_KEY) * 200))
    plaintext[500:500 + len(_SM_MARKER)] = _SM_MARKER
    encoded = sleep_mask._sm_xor(bytes(plaintext), _SM_KEY, 0)
    size = len(encoded)

    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: encoded}, requested=VirtualRange(_BASE, size))

    hits = result.payload.sleep_mask.hits
    assert hits, "sleep-mask layer recovered nothing from a keyed buffer"
    hit = hits[0]
    assert hit.key == _SM_KEY
    assert hit.key_offset is not None
    assert hit.location.va == _BASE
    # The closure still reports its own honest coverage, independent of the hit.
    assert _closures(result)["sleep_mask"].coverage_status == "complete"


def test_entropy_hit_reaches_the_payload_with_its_threshold(monkeypatch):
    random.seed(11)
    size = 0x2000
    data = bytes(random.getrandbits(8) for _ in range(size))   # ~8.0 bits/byte
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: data}, requested=VirtualRange(_BASE, size))

    hits = result.payload.entropy.hits
    assert hits, "a high-entropy range produced no entropy hit"
    assert hits[0].entropy >= hits[0].threshold
    assert hits[0].location.va == _BASE


def test_decode_base64_pe_hit_reaches_the_payload(monkeypatch):
    pe = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                           "rawptr": 0x400, "rawsize": 0x200,
                           "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                         size_of_image=0x2000, trailing_padding=0x300)
    blob = base64.b64encode(pe)
    data = blob.ljust(0x2000, b"\x00")
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, len(data)), segment_len=len(data),
        captured={_BASE: data}, requested=VirtualRange(_BASE, len(data)))

    b64_hits = result.payload.decode.base64
    assert b64_hits, "a base64-wrapped PE produced no decode hit"
    assert b64_hits[0].location.va == _BASE
    assert b64_hits[0].classification.is_pe


def test_decode_hit_cap_still_bites_in_targeted_mode(monkeypatch):
    # The size cap is bypassed but ENCODING_BUDGET_MAX_HITS is not: a range with
    # more DISTINCT base64 blobs than the hit budget still leaves decode
    # `partial`. The payloads must differ -- ScanBudget.seen_content() discards
    # exact duplicates before take_hit() is ever consulted.
    data = b"".join(base64.b64encode(b"MEOW%03d" % i * 24) + b"\x00" * 16
                    for i in range(6))
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, len(data)), segment_len=len(data),
        captured={_BASE: data}, requested=VirtualRange(_BASE, len(data)),
        enc_override=dict(ENCODING_BUDGET_MAX_HITS=1))

    dec = _closures(result)["decode"]
    assert dec.coverage_status == "partial"
    budget_lims = [l for l in dec.limitations
                   if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED]
    assert budget_lims and budget_lims[0].detail == "max_hits"
    assert dec.budget_outcomes[0].exhausted is True


# ── _budget_layer_eligible mirrors the real scanner gates ──────────────

_SYS_DLL = Module(_BASE, 0x4000, r"C:\Windows\System32\ntdll.dll")
_APP_DLL = Module(_BASE, 0x4000, r"C:\app\payload.dll")


@pytest.mark.parametrize("state,mtype,protect,size,mods,sleep_ok,decode_ok", [
    ("MEM_COMMIT", "MEM_PRIVATE", "PAGE_READWRITE", 0x2000, (), True, True),
    ("MEM_COMMIT", "MEM_PRIVATE", "PAGE_EXECUTE_READWRITE", 0x2000, (), False, True),
    ("MEM_COMMIT", "MEM_IMAGE", "PAGE_READWRITE", 0x2000, (), False, True),
    ("MEM_COMMIT", "MEM_MAPPED", "PAGE_READWRITE", 0x2000, (), False, False),
    ("MEM_RESERVE", "MEM_PRIVATE", "PAGE_READWRITE", 0x2000, (), False, False),
    ("MEM_COMMIT", "MEM_PRIVATE", "PAGE_READWRITE", 0x400, (), False, True),  # < key*repeat
    ("MEM_COMMIT", "MEM_PRIVATE", "PAGE_READWRITE", 0x2000, (_APP_DLL,), False, True),
    ("MEM_COMMIT", "MEM_IMAGE", "PAGE_READWRITE", 0x2000, (_SYS_DLL,), False, False),
    ("MEM_COMMIT", "MEM_IMAGE", "PAGE_READWRITE", 0x2000, (_APP_DLL,), False, True),
])
def test_budget_layer_eligible_agrees_with_the_real_scan_loop(
        monkeypatch, state, mtype, protect, size, mods, sleep_ok, decode_ok):
    region = Region(_BASE, _BASE, size, state, protect, mtype)
    ctx, result = _run(
        monkeypatch, region=region, segment_len=size, modules=mods,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    payload = result.payload
    assert (payload.sleep_mask.coverage.eligible_total > 0) is sleep_ok
    assert (payload.decode.coverage.eligible_total > 0) is decode_ok

    from dumpex.core.va_range import region_containing
    from dumpex.core.memory import get_modules
    cap = region_containing(_BASE, ctx.captured_regions())
    module_list = get_modules(ctx.mf)
    assert targeted._budget_layer_eligible(
        "sleep_mask", cap, _BASE, size, module_list) is sleep_ok
    assert targeted._budget_layer_eligible(
        "decode", cap, _BASE, size, module_list) is decode_ok


# ── per-layer eligibility gates are independent ────────────────────────

def test_executable_rw_region_gates_out_sleep_mask_only(monkeypatch):
    size = 0x2000
    region = Region(_BASE, _BASE, size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    ctx, result = _run(
        monkeypatch, region=region, segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    cl = _closures(result)
    assert cl["sleep_mask"].coverage_status == "not_evaluated"
    assert cl["entropy"].coverage_status == "complete"
    assert cl["decode"].coverage_status == "complete"


def test_image_region_gates_out_entropy_and_sleep_mask_but_not_decode(monkeypatch):
    size = 0x2000
    region = Region(_BASE, _BASE, size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_IMAGE")
    ctx, result = _run(
        monkeypatch, region=region, segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    cl = _closures(result)
    assert cl["sleep_mask"].coverage_status == "not_evaluated"
    assert cl["entropy"].coverage_status == "not_evaluated"
    assert cl["decode"].coverage_status == "complete"


def test_entropy_below_minimum_input_is_not_evaluated(monkeypatch):
    size = 200
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, 0x2000), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    cl = _closures(result)
    assert cl["entropy"].coverage_status == "not_evaluated"
    assert cl["decode"].coverage_status in ("partial", "complete")


# ── capture semantics ─────────────────────────────────────────────────

def test_address_outside_every_region_is_not_evaluated_never_clean(monkeypatch):
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, 0x1000), segment_len=0,
        captured={}, requested=VirtualRange(0x9EEE0000, 0x1000))

    assert {c.coverage_status for c in result.closures} == {"not_evaluated"}
    for c in result.closures:
        assert c.capture_state == CaptureState.NONE
        assert c.diagnostics


def test_partial_capture_is_partial_not_a_negative(monkeypatch):
    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=0x800,
        captured={_BASE: b"\x00" * 0x800}, requested=VirtualRange(_BASE, size))

    for c in result.closures:
        assert c.capture_state == CaptureState.PARTIAL
        assert c.coverage_status != "complete"


def test_range_past_region_end_truncates_evaluation_but_not_capture(monkeypatch):
    region = _private_rw(_BASE, 0x1000)
    ctx, result = _run(
        monkeypatch, region=region, segment_len=0x2000,
        captured={_BASE: b"\x00" * 0x2000}, requested=VirtualRange(_BASE, 0x2000))

    for c in result.closures:
        assert c.capture_state == CaptureState.COMPLETE
        assert c.coverage_status == "partial"
        codes = {lim.code for lim in c.limitations}
        assert LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED in codes
        trunc = next(l for l in c.limitations
                     if l.code == LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED)
        assert trunc.scope == c.scope
        assert trunc.targets[0].size == 0x2000
        assert any("clipped to containing region end" in d for d in c.diagnostics)


def test_sub_region_request_names_the_containing_allocation(monkeypatch):
    # Request wholly inside a larger allocation: complete, but the closure
    # states the requested-boundary caveat and the containing region.
    region = _private_rw(_BASE, 0x40000)
    ctx, result = _run(
        monkeypatch, region=region, segment_len=0x40000,
        captured={_BASE: b"\x00" * 0x40000},
        requested=VirtualRange(_BASE + 0x1000, 0x1000))

    for c in result.closures:
        assert c.coverage_status == "complete"
        assert any("sub-range of the containing allocation" in d for d in c.diagnostics)
    assert result.payload.containing_region.size == 0x40000


def test_reader_over_serving_past_the_captured_prefix_is_clamped(monkeypatch):
    # The segment table backs only 0x400 bytes; the raw reader hands back the
    # whole keyed buffer. The layers must see only the captured prefix -- a
    # short read against the request -- not analyze bytes the closure reports
    # as uncaptured.
    plaintext = bytearray(b"\x00" * (len(_SM_KEY) * 200))
    plaintext[2000:2000 + len(_SM_MARKER)] = _SM_MARKER   # marker past the 0x400 prefix
    encoded = sleep_mask._sm_xor(bytes(plaintext), _SM_KEY, 0)

    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, len(encoded)), segment_len=0x400,
        captured={}, requested=VirtualRange(_BASE, len(encoded)),
        reader=_over_serving_reader(encoded, _BASE))

    sm = _closures(result)["sleep_mask"]
    assert sm.capture_state == CaptureState.PARTIAL
    assert sm.coverage_status == "partial"
    assert sm.read_slice.read_bytes == 0x400
    assert LimitationCode.SCAN_REGION_SHORT_READ in {l.code for l in sm.limitations}
    # No hit reconstructed from the over-served bytes past the captured prefix.
    assert result.payload.sleep_mask.hits == ()


def test_capture_none_with_an_over_serving_reader_is_not_evaluated_not_a_raise(monkeypatch):
    # An unrepresentable / zero-length segment over the base makes capture NONE
    # while the raw reader still returns bytes. The clamp -> b"" -> read_failed
    # -> not_evaluated, and ObservationResult validation is satisfied rather
    # than violated.
    data = b"\x41" * 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, 0x2000), segment_len=0,
        captured={}, requested=VirtualRange(_BASE, 0x2000),
        reader=_over_serving_reader(data, _BASE))

    assert isinstance(result, ObservationResult)
    assert {c.coverage_status for c in result.closures} == {"not_evaluated"}
    assert {c.capture_state for c in result.closures} == {CaptureState.NONE}


def _search_incomplete(closure):
    return {l.detail for l in closure.limitations
            if l.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE}


def test_overlapping_segments_forbid_a_clean_closure(monkeypatch):
    # Two segments place [_BASE, _BASE+0x2000) at two file offsets. The bytes
    # analyzed are one arbitrary choice among conflicting claims, so no layer
    # may report `complete`, and every closure carries a structured limitation
    # (scope-tagged) plus a human diagnostic.
    size = 0x2000
    segs = [Segment(_BASE, 0x1000, size), Segment(_BASE, 0x9000, size)]
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segments=segs,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    for c in result.closures:
        assert c.coverage_status != "complete"
        assert any("overlapping segments" in d for d in c.diagnostics)
        lim = next(l for l in c.limitations
                   if l.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE)
        assert lim.source == "encoding_scan"
        assert lim.scope == c.scope
        assert lim.detail == "overlapping_capture"


def test_sleep_mask_window_cap_keeps_the_closure_partial(monkeypatch):
    # A range large enough that SLEEP_MASK_MAX_WINDOWS strides the recovery
    # scan: sleep-mask cannot report a full-search negative. entropy and decode
    # are untouched.
    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size),
        enc_override=dict(SLEEP_MASK_MAX_WINDOWS=13))

    cl = _closures(result)
    assert cl["sleep_mask"].coverage_status == "partial"
    assert _search_incomplete(cl["sleep_mask"]) == {"window_sampled"}
    assert any("sampled a strided subset of windows" in d
               for d in cl["sleep_mask"].diagnostics)
    assert cl["entropy"].coverage_status == "complete"
    assert cl["decode"].coverage_status == "complete"
    assert _search_incomplete(cl["entropy"]) == set()


def test_sleep_mask_candidate_cap_keeps_the_closure_partial(monkeypatch):
    # More recoverable keys than SLEEP_MASK_MAX_CANDIDATES: the recovered key
    # list was cut, so a negative sleep-mask result is not authoritative.
    key_a = bytes([0, 200, 10, 210, 20, 220, 30, 230, 40, 240, 50, 250, 60])
    key_b = bytes([5, 190, 15, 205, 25, 215, 35, 225, 45, 235, 55, 245, 65])
    encoded = (sleep_mask._sm_xor(b"\x00" * (13 * 120), key_a, 0)
               + sleep_mask._sm_xor(b"\x00" * (13 * 120), key_b, 0))
    size = len(encoded)
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: encoded}, requested=VirtualRange(_BASE, size),
        enc_override=dict(SLEEP_MASK_MAX_CANDIDATES=1))

    cl = _closures(result)
    assert cl["sleep_mask"].coverage_status == "partial"
    assert _search_incomplete(cl["sleep_mask"]) == {"candidate_list_truncated"}
    assert cl["entropy"].coverage_status == "complete"
    assert cl["decode"].coverage_status == "complete"


def test_exactly_max_candidates_does_not_trip_the_cap(monkeypatch):
    # A buffer with exactly one recoverable key and SLEEP_MASK_MAX_CANDIDATES=1:
    # the list is AT the cap but nothing was dropped -- the closure stays
    # complete, no SCAN_REGION_SEARCH_INCOMPLETE.
    key = bytes([0, 200, 10, 210, 20, 220, 30, 230, 40, 240, 50, 250, 60])
    encoded = sleep_mask._sm_xor(b"\x00" * (13 * 200), key, 0)
    size = len(encoded)
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: encoded}, requested=VirtualRange(_BASE, size),
        enc_override=dict(SLEEP_MASK_MAX_CANDIDATES=1))

    sm = _closures(result)["sleep_mask"]
    assert sm.coverage_status == "complete"
    assert _search_incomplete(sm) == set()


def test_dropped_region_descriptor_is_named_not_hidden(monkeypatch):
    # A region whose AllocationBase the value model cannot represent is dropped
    # from the view; the diagnostic must say a descriptor was dropped, not that
    # no region contains the address.
    region = Region(_BASE, 1 << 70, 0x2000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
    ctx, result = _run(
        monkeypatch, region=region, segment_len=0x2000,
        captured={_BASE: b"\x00" * 0x2000}, requested=VirtualRange(_BASE, 0x2000))

    assert {c.coverage_status for c in result.closures} == {"not_evaluated"}
    assert all(any("dropped as unrepresentable" in d for d in c.diagnostics)
               for c in result.closures)


def test_budget_prevention_is_not_attributed_to_a_structurally_ineligible_layer(monkeypatch):
    # MEM_IMAGE region + spent budget: sleep-mask can never apply here, so it
    # must not carry SCAN_BUDGET_EXHAUSTED; decode still does.
    def _expired():
        return ScanBudget(max_bytes_read=1, max_attempts=1, max_retained_bytes=1,
                          max_hits=1, deadline=time.monotonic() - 1.0)

    region = Region(_BASE, _BASE, 0x2000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_IMAGE")
    ctx, result = _run(
        monkeypatch, region=region, segment_len=0x2000,
        captured={_BASE: b"\x00" * 0x2000}, requested=VirtualRange(_BASE, 0x2000),
        budget_factory=_expired)

    cl = _closures(result)
    assert cl["sleep_mask"].coverage_status == "not_evaluated"
    assert LimitationCode.SCAN_BUDGET_EXHAUSTED not in {l.code for l in cl["sleep_mask"].limitations}
    assert cl["sleep_mask"].budget_outcomes == ()
    assert LimitationCode.SCAN_BUDGET_EXHAUSTED in {l.code for l in cl["decode"].limitations}


def test_unreconciled_layer_ledger_surfaces_as_a_limitation(monkeypatch):
    # A LayerResult whose coverage ledger does not balance must degrade the
    # closure to partial AND carry SCAN_ITEMS_UNACCOUNTED, at full-scope parity.
    from dumpex.hunt.encoding.models import LayerCoverage, LayerResult

    real_scan = targeted._scan_entropy

    def _leaky(*args, **kwargs):
        r = real_scan(*args, **kwargs)
        bad = LayerCoverage(scanned=1, eligible_total=2)   # one eligible item unaccounted
        return LayerResult(hits=r.hits, coverage=bad)

    monkeypatch.setattr(targeted, "_scan_entropy", _leaky)
    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    ent = _closures(result)["entropy"]
    assert ent.coverage_status == "partial"
    assert LimitationCode.SCAN_ITEMS_UNACCOUNTED in {l.code for l in ent.limitations}


# ── size-cap bypass, other budgets retained ──────────────────────────

def test_targeted_bypasses_the_per_region_size_cap(monkeypatch):
    # A region larger than every layer's own cap is skipped_oversize in full
    # scope; a targeted rescan evaluates it. Caps are lowered here so the test
    # data stays small.
    size = 0x2000
    caps = dict(ENTROPY_SCAN_MAX=0x400, SLEEP_MASK_REGION_MAX=0x400,
                DECODE_SCAN_MAX=0x400, XOR_SCAN_MAX=0x400)
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size),
        enc_override=caps)

    for c in result.closures:
        codes = {lim.code for lim in c.limitations}
        assert LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED not in codes
        assert c.coverage_status == "complete"

    # Same region and cap through the ordinary (non-targeted) entropy scan:
    # still skipped for size.
    cov = _scan_entropy(
        [_private_rw(_BASE, size)], [], ctx.mf, (),
        _spanning_reader({_BASE: b"\x00" * size}),
        EncodingConfig(entropy_scan_max=0x400)).coverage
    assert cov.skipped_oversize_targets


def test_shared_budget_deadline_still_stops_layers_in_targeted_mode(monkeypatch):
    # A pre-expired deadline: sleep-mask and decode are prevented (they poll
    # the shared budget); entropy has no budget and still runs.
    def _expired():
        return ScanBudget(max_bytes_read=1, max_attempts=1, max_retained_bytes=1,
                          max_hits=1, deadline=time.monotonic() - 1.0)

    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size),
        budget_factory=_expired)

    cl = _closures(result)
    for layer in ("sleep_mask", "decode"):
        assert cl[layer].coverage_status == "not_evaluated"
        codes = {lim.code for lim in cl[layer].limitations}
        assert LimitationCode.SCAN_BUDGET_EXHAUSTED in codes
        reason = next(l for l in cl[layer].limitations
                      if l.code == LimitationCode.SCAN_BUDGET_EXHAUSTED)
        assert reason.detail == "deadline"
        assert cl[layer].budget_outcomes[0].exhausted is True
    assert cl["entropy"].coverage_status == "complete"
    assert cl["entropy"].budget_outcomes == ()


def test_budget_is_reused_across_adapter_calls_on_one_context(monkeypatch):
    # _fresh_budget is only ever consulted when the ledger has no budget yet;
    # a second call on the same context must reuse the first (here: exhausted)
    # budget, not mint a new one.
    made = {"n": 0}

    def _expired():
        made["n"] += 1
        return ScanBudget(max_bytes_read=1, max_attempts=1, max_retained_bytes=1,
                          max_hits=1, deadline=time.monotonic() - 1.0)

    size = 0x2000
    ctx, first = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size),
        budget_factory=_expired)

    second = targeted.run_targeted_encoding(ctx)
    assert made["n"] == 1
    assert _closures(second)["decode"].budget_outcomes[0].exhausted is True


# ── request validation, fail closed ──────────────────────────────────

def test_request_over_the_obfuscation_ceiling_is_rejected_before_scanning():
    with pytest.raises(ValueError):
        HuntRequest.targeted("obfuscation", "encoding_scan",
                             VirtualRange(_BASE, 33 * _MIB))


def test_executor_refuses_a_non_obfuscation_targeted_request(monkeypatch):
    mf = _mf([_private_rw(_BASE, 0x1000)],
             [Segment(_BASE, 0x1000, 0x1000)])
    request = HuntRequest.targeted("pipe", "pipe_name_scan", VirtualRange(_BASE, 0x1000))
    ctx = build_execution_context(mf, request)
    with pytest.raises(targeted.TargetedEncodingError):
        targeted.run_targeted_encoding(ctx)


def test_executor_refuses_a_full_scope_request():
    mf = _mf([_private_rw(_BASE, 0x1000)], [Segment(_BASE, 0x1000, 0x1000)])
    ctx = build_execution_context(mf, HuntRequest.full("obfuscation"))
    with pytest.raises(targeted.TargetedEncodingError):
        targeted.run_targeted_encoding(ctx)


# ── observation reuse ────────────────────────────────────────────────

def test_result_is_reused_without_recomputing(monkeypatch):
    size = 0x2000
    ctx, result = _run(
        monkeypatch, region=_private_rw(_BASE, size), segment_len=size,
        captured={_BASE: b"\x00" * size}, requested=VirtualRange(_BASE, size))

    calls = {"n": 0}

    def _producer():
        calls["n"] += 1
        return result

    first = ctx.observations.get_or_compute(result.key, _producer)
    second = ctx.observations.get_or_compute(result.key, _producer)
    assert first is result and second is result
    assert calls["n"] == 1
