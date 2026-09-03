"""
Unit/hunter-level tests for dumpex.hunt.encoding's CS Sleep Mask layer
(_sm_recover_candidates / _sm_validate_and_decode / _scan_sleep_mask /
the sleep-mask path through _hunt_encoding).

Real sleep-masked beacon memory is mostly constant (commonly zero-filled)
padding XOR-encoded with a repeating key -- once encoded, that padding
becomes a periodic pattern whose repeating window IS the key itself
(constant byte XOR key == key, for an all-zero constant). Every fixture
below constructs plaintext this way (constant padding + one embedded
'sha256\\x00' validation marker) rather than an arbitrary repeating
pattern, which recovers a DIFFERENT (and wrong) candidate -- see the
docstrings on _sm_recover_candidates/_scan_sleep_mask in encoding.py for
why.
"""
from tests.fixtures.fakes import Region, FakeStream, FakeMF, mem_reader

import dumpex.hunt.encoding as encoding
import dumpex.hunt.encoding.sleep_mask as sleep_mask

# A 13-byte (SLEEP_MASK_KEY_SIZE) key with high average-consecutive-byte-
# difference (>= SLEEP_MASK_MIN_ACBD) and no byte repeated >= SLEEP_MASK_
# MAX_BYTE_FREQ times -- passes _sm_recover_candidates' own filters.
_KEY = bytes([0, 200, 10, 210, 20, 220, 30, 230, 40, 240, 50, 250, 60])
_MARKER = b'sha256\x00'


def _sleep_masked_region(key=_KEY, n_key_blocks=150, marker_offset=500,
                          include_marker=True):
    """Build (plaintext, encoded) for a synthetic sleep-masked region."""
    plaintext = bytearray(b'\x00' * (encoding.SLEEP_MASK_KEY_SIZE * n_key_blocks))
    if include_marker:
        plaintext[marker_offset:marker_offset + len(_MARKER)] = _MARKER
    plaintext = bytes(plaintext)
    encoded = sleep_mask._sm_xor(plaintext, key, 0)
    return plaintext, encoded


# ── _sm_recover_candidates / _sm_validate_and_decode as pure functions ────

def test_recover_candidates_finds_the_repeating_key():
    _, encoded = _sleep_masked_region()
    candidates = sleep_mask._sm_recover_candidates(encoded)
    assert candidates, "expected at least one candidate key"
    keys = [k for k, _count in candidates]
    assert _KEY in keys


def test_validate_and_decode_confirms_marker_and_recovers_plaintext():
    plaintext, encoded = _sleep_masked_region()
    candidates = sleep_mask._sm_recover_candidates(encoded)
    confirmed = sleep_mask._sm_validate_and_decode(encoded, candidates)
    assert len(confirmed) == 1
    key, offset, decoded = confirmed[0]
    assert key == _KEY
    assert offset == 0
    assert _MARKER in decoded


def test_recover_candidates_rejects_monotonic_key():
    # A monotonic key (constant per-byte step) has low average-consecutive-
    # byte-difference relative to a real key, and/or repeats a byte value
    # -- either way it must not be recovered as a plausible sleep-mask key.
    monotonic_key = bytes(range(0, 13))   # diffs of 1 each -> ACBD == 1.0
    _, encoded = _sleep_masked_region(key=monotonic_key)
    candidates = sleep_mask._sm_recover_candidates(encoded)
    assert candidates == []


def test_validate_and_decode_rejects_candidate_with_no_marker():
    # A repeating-window candidate exists structurally, but the "plaintext"
    # never actually contains the sha256\x00 validation marker anywhere --
    # must not be confirmed (a repeating pattern alone is not proof this
    # is beacon memory).
    _, encoded = _sleep_masked_region(include_marker=False)
    candidates = sleep_mask._sm_recover_candidates(encoded)
    assert candidates   # the repeating key IS still recoverable structurally
    confirmed = sleep_mask._sm_validate_and_decode(encoded, candidates)
    assert confirmed == []


# ── _scan_sleep_mask / _hunt_encoding integration ──────────────────────────

def test_confirmed_sleep_mask_decode_scores():
    region_base = 0x50000
    _, encoded = _sleep_masked_region()
    regions = [Region(region_base, region_base, len(encoded), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: encoded})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] >= 1
    assert f["status"] == "DETECTED"
    tags = {finding["check"] for finding in f["findings"]}
    assert "obfuscation.sleep_mask_confirmed" in tags


def test_region_too_small_for_min_repeat_is_skipped():
    # Below SLEEP_MASK_KEY_SIZE * SLEEP_MASK_MIN_REPEAT -- can never
    # contain enough key repetitions, must not even be attempted.
    region_base = 0x60000
    tiny = b'\x00' * (encoding.SLEEP_MASK_KEY_SIZE * (encoding.SLEEP_MASK_MIN_REPEAT - 1))
    regions = [Region(region_base, region_base, len(tiny), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: tiny})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    tags = {finding["check"] for finding in f["findings"]}
    assert "obfuscation.sleep_mask_confirmed" not in tags


# ── sleep-mask shares the whole-hunt deadline budget (P2-03 review) ────────
# Before this fix, Layer 0 ran with no cross-region time bound at all: a
# dump with many qualifying <=10MB regions could make it run for
# unboundedly long even though each region alone stayed within its own
# size cap. It now polls the same ScanBudget layers 2-4 use.

def test_sleep_mask_budget_exhaustion_leaves_partial_coverage(monkeypatch):
    monkeypatch.setattr(encoding, "ENCODING_BUDGET_TIME_SECONDS", -1)   # already expired
    region_base = 0x80000
    _, encoded = _sleep_masked_region()
    regions = [Region(region_base, region_base, len(encoded), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: encoded})

    f = encoding._hunt_encoding(MF(), verbose=False)
    # The deadline was already expired before Layer 0 even started, so the
    # otherwise-confirmable sleep-mask hit must never have been attempted.
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["budget_exhausted"] is True


def test_no_repeating_pattern_no_candidates_no_score():
    import random
    random.seed(7)
    region_base = 0x70000
    noisy = bytes(random.getrandbits(8) for _ in range(encoding.SLEEP_MASK_KEY_SIZE
                                                          * (encoding.SLEEP_MASK_MIN_REPEAT + 20)))
    regions = [Region(region_base, region_base, len(noisy), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: noisy})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0


# ── issue #25: validation must cover the COMPLETE region, not just a prefix ─
# `validate_sample` used to be a hard search boundary: a candidate/rotation
# combination was checked ONLY against the first `validate_sample` bytes of
# the region, so a correctly recovered key whose decoded marker happened to
# sit past that boundary was silently rejected as unconfirmed. It is now a
# per-chunk streaming size instead -- `_sm_marker_in_region` walks the WHOLE
# region in chunks of this size -- so a small `validate_sample` below is used
# purely to keep these tests fast, not because the boundary still matters.

def test_validate_and_decode_finds_marker_immediately_before_chunk_boundary():
    chunk_size = 500
    marker_offset = chunk_size - 20   # fully inside the first chunk
    _, encoded = _sleep_masked_region(marker_offset=marker_offset)
    candidates = sleep_mask._sm_recover_candidates(encoded)
    confirmed = sleep_mask._sm_validate_and_decode(encoded, candidates, validate_sample=chunk_size)
    assert len(confirmed) == 1
    key, offset, decoded = confirmed[0]
    assert key == _KEY
    assert offset == 0
    assert _MARKER in decoded


def test_validate_and_decode_finds_marker_spanning_chunk_boundary():
    chunk_size = 500
    marker_offset = chunk_size - 3   # straddles the boundary between chunk 0 and chunk 1
    _, encoded = _sleep_masked_region(marker_offset=marker_offset)
    candidates = sleep_mask._sm_recover_candidates(encoded)
    confirmed = sleep_mask._sm_validate_and_decode(encoded, candidates, validate_sample=chunk_size)
    assert len(confirmed) == 1
    key, offset, decoded = confirmed[0]
    assert key == _KEY
    assert offset == 0
    assert _MARKER in decoded


def test_validate_and_decode_finds_marker_immediately_after_chunk_boundary():
    # This is the exact shape of the reported bug: with the OLD prefix-only
    # search, a marker placed past `validate_sample` bytes was never found
    # even though the key was recovered correctly.
    chunk_size = 500
    marker_offset = chunk_size + 10   # fully inside the second chunk
    _, encoded = _sleep_masked_region(marker_offset=marker_offset)
    candidates = sleep_mask._sm_recover_candidates(encoded)
    assert candidates, "expected the key to still be recoverable structurally"
    confirmed = sleep_mask._sm_validate_and_decode(encoded, candidates, validate_sample=chunk_size)
    assert len(confirmed) == 1
    key, offset, decoded = confirmed[0]
    assert key == _KEY
    assert offset == 0
    assert _MARKER in decoded


def test_validate_and_decode_stops_when_budget_runs_out_mid_search():
    # Deterministic stand-in for the shared ScanBudget: returns True from
    # poll() for a fixed number of calls, then False forever -- lets this
    # test simulate the budget running out PARTWAY through the chunked
    # marker search without depending on wall-clock timing.
    class _CountdownBudget:
        def __init__(self, allowed):
            self._remaining = allowed
            self.exhausted_reason = ""

        def poll(self):
            if self._remaining <= 0:
                self.exhausted_reason = self.exhausted_reason or "test-exhausted"
                return False
            self._remaining -= 1
            return True

        def exhausted(self):
            return self._remaining <= 0

    chunk_size = 32
    marker_offset = 3 * chunk_size + 5   # sits in the 4th chunk (index 3)
    total_len = 6 * chunk_size
    plaintext = bytearray(b'\x00' * total_len)
    plaintext[marker_offset:marker_offset + len(_MARKER)] = _MARKER
    encoded = sleep_mask._sm_xor(bytes(plaintext), _KEY, 0)

    # 4 successful polls cover chunks at pos 0, 32, 64 (none contain the
    # marker) before the 5th poll call -- for the chunk at pos 96, the one
    # that DOES contain the marker -- returns False first.
    budget = _CountdownBudget(allowed=4)
    confirmed = sleep_mask._sm_validate_and_decode(
        encoded, [(_KEY, 999)], validate_sample=chunk_size, budget=budget)

    # Cut short by the budget, not a completed search: must not be reported
    # as a confirmed negative even though the marker WAS present.
    assert confirmed == []
    assert budget.exhausted()


def test_hunt_encoding_reports_partial_coverage_when_budget_runs_out_during_validation(monkeypatch):
    # Integration-level companion to the unit test above: the REAL
    # ScanBudget instance _hunt_encoding builds is what _sm_validate_and_decode
    # polls, so exhausting it PARTWAY through validation -- not before Layer 0
    # even starts, unlike test_sleep_mask_budget_exhaustion_leaves_partial_coverage
    # above -- must still surface as partial coverage / budget_exhausted at
    # the top level rather than a silent score == 0 clean negative.
    from dumpex.hunt._budget import ScanBudget as RealScanBudget

    class _CountdownScanBudget(RealScanBudget):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._countdown = 16   # 13 (candidate recovery) + 1 (validate
                                    # outer loop) + 2 chunk polls, then the
                                    # poll for the chunk holding the marker fails

        def poll(self):
            if self.exhausted():
                return False
            if self._countdown <= 0:
                # One of ScanBudget's own reasons rather than an invented
                # string: this budget's exhaustion reaches a real
                # SCAN_BUDGET_EXHAUSTED limitation, whose `detail`
                # vocabulary is closed, so a made-up value would fail
                # construction instead of exercising the budget path.
                self.exhausted_reason = self.exhausted_reason or "max_attempts"
                return False
            self._countdown -= 1
            return True

    monkeypatch.setattr(encoding, "ScanBudget", _CountdownScanBudget)
    monkeypatch.setattr(encoding, "SLEEP_MASK_VALIDATE_SAMPLE", 32)

    region_base = 0xA0000
    # marker_offset=101 sits inside the chunk starting at pos=64 (covers
    # 64..102 with overlap) -- the chunk the countdown above is tuned to
    # never reach.
    _, encoded = _sleep_masked_region(marker_offset=101)
    regions = [Region(region_base, region_base, len(encoded), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: encoded})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["budget_exhausted"] is True
    tags = {finding["check"] for finding in f["findings"]}
    assert "obfuscation.sleep_mask_confirmed" not in tags
