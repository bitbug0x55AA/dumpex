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
