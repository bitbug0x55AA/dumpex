"""
Layer 0 of dumpex.hunt.encoding — CS Sleep Mask XOR decode.

Algorithm adapted from cs-analyze-processdump.py by Didier Stevens
(public domain — https://DidierStevens.com).

Split out of encoding.py verbatim (see the package-split notes in
dumpex/hunt/encoding.py's own docstring) — no behavior change. Imported
back into dumpex.hunt.encoding, which is still the only public entry
point (_hunt_encoding).
"""
import struct

from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt._encoding.classification import _classify_decoded
from dumpex.hunt._encoding.config import EncodingConfig

# ── Sleep Mask tunables (mirroring cs-analyze-processdump.py defaults) ────
SLEEP_MASK_KEY_SIZE        = 13        # XOR key length used by default CS sleep mask
SLEEP_MASK_MIN_REPEAT      = 100       # key must repeat ≥ N times to be a candidate
SLEEP_MASK_MAX_BYTE_FREQ   = 3         # reject if any single byte appears ≥ N times
                                        # in the candidate key (monotonic key filter)
SLEEP_MASK_MIN_ACBD        = 20.0      # min average consecutive byte difference
                                        # (rejects keys like 01 02 03 … or 00 00 00)
SLEEP_MASK_MAX_CANDIDATES  = 10        # max candidates to try per region
SLEEP_MASK_REGION_MAX      = 10 * 1024 * 1024   # skip regions > 10 MB
SLEEP_MASK_VALIDATE_SAMPLE = 2 * 1024 * 1024    # search only the first N bytes of
                                        # each candidate x rotation combination for
                                        # the validation marker before committing to
                                        # a full-region decode. Unbounded, up to
                                        # MAX_CANDIDATES x KEY_SIZE x REGION_MAX
                                        # (10 x 13 x 10MB ~= 1.3GB) of XOR work is
                                        # done per region; mirrors the same
                                        # sample-then-full-decode pattern _scan_xor
                                        # already uses (XOR_SAMPLE_SIZE).
SLEEP_MASK_VALIDATION_MARKER = b'sha256\x00'    # always present in beacon memory
SLEEP_MASK_MAX_WINDOWS      = 200_000  # hard cap on windows counted per region, across
                                        # all key_size alignment offsets. Without this, a
                                        # ~10MB region produces ~10M dict entries (one per
                                        # non-overlapping window) — real sleep-mask keys
                                        # repeat densely enough that even sampling well
                                        # below that still surfaces them as the top
                                        # candidate, so this bounds memory/CPU without
                                        # meaningfully hurting detection.


def _sm_xor(data: bytes, key: bytes, offset: int) -> bytes:
    """
    XOR data with key starting at rotation offset.

    Mirrors Didier Stevens' Xor() from cs-analyze-processdump.py:
        key = key[offset:] + key[:offset]
        decoded[i] = data[i] ^ key[i % len(key)]

    Implemented as a big-integer XOR (C-level bignum op) rather than a
    per-byte Python loop — for a multi-MB region tried across ~130
    candidate/rotation combinations (_sm_validate_and_decode), the
    per-byte generator-expression version was the actual bottleneck
    behind the sleep-mask layer's worst-case cost, independent of any
    region-size cap: ~2MB took several seconds per call, not the
    microseconds a byte-XOR should take. int.from_bytes/to_bytes give
    identical output, verified byte-for-byte against the naive version.
    """
    if not data:
        return b""
    rotated = key[offset:] + key[:offset]
    klen = len(rotated)
    reps = (len(data) + klen - 1) // klen
    keystream = (rotated * reps)[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(len(data), "big")


def _sm_key_stats(key: bytes) -> list:
    """
    Return byte frequency table for key, sorted descending by count.
    Mirrors KeyStats() from cs-analyze-processdump.py.
    """
    stats = {}
    for b in key:
        stats[b] = stats.get(b, 0) + 1
    return sorted(stats.items(), key=lambda x: x[1], reverse=True)


def _sm_normalize_key(key: bytes) -> bytes:
    """
    Return the lexicographically smallest rotation of key (big-endian first 4 bytes).

    Mirrors NormalizeKey() from cs-analyze-processdump.py.
    Used to deduplicate candidate keys that are simply rotations of each other
    (e.g. the same 13-byte key found at offset 0 vs offset 3).
    """
    smallest = 0x1_0000_0000
    best = key
    for pos in range(len(key)):
        rot = key[pos:] + key[:pos]
        val = struct.unpack('>I', rot[:4])[0]
        if val < smallest:
            smallest = val
            best = rot
    return best


def _sm_avg_consec_diff(key: bytes) -> float:
    """
    Average absolute difference between consecutive bytes of key.

    Mirrors AverageDifferenceConsecutiveBytes() from cs-analyze-processdump.py.
    Rejects monotonic sequences like 00 01 02 03 (low ACBD) that are never
    real sleep mask keys.
    """
    if len(key) < 2:
        return 0.0
    return sum(abs(int(key[i]) - int(key[i-1])) for i in range(1, len(key))) / (len(key) - 1)


def _sm_recover_candidates(data: bytes,
                            key_size: int   = SLEEP_MASK_KEY_SIZE,
                            min_repeat: int = SLEEP_MASK_MIN_REPEAT,
                            max_candidates: int = SLEEP_MASK_MAX_CANDIDATES,
                            max_windows: int = SLEEP_MASK_MAX_WINDOWS,
                            max_byte_freq: int = SLEEP_MASK_MAX_BYTE_FREQ,
                            min_acbd: float = SLEEP_MASK_MIN_ACBD,
                            budget=None) -> list:
    """
    Recover candidate sleep mask XOR keys from a memory region via frequency
    analysis on overlapping key-sized windows.

    Algorithm (from cs-analyze-processdump.py ProcessBinaryFile):
      1. For each alignment offset 0..key_size-1, slide a non-overlapping
         key_size window across the data and count occurrences of each window.
      2. Filter candidates: count >= min_repeat, no single byte dominates
         (max byte freq < max_byte_freq), and the key is not monotonic
         (ACBD >= min_acbd).
      3. Deduplicate via NormalizeKey to avoid reporting the same key at
         different rotations.
      4. Return top max_candidates by occurrence count.

    Windows examined per offset are capped at max_windows // key_size: for a
    region large enough to exceed that, positions are strided evenly across
    the whole region (not just the head) rather than counting every single
    window — a real sleep-mask key repeats densely enough that sampling
    still surfaces it as the top candidate, while bounding memory/CPU on a
    huge or adversarially large region (unbounded, a 10MB region produces
    ~10M dict entries here).

    `budget` (default None -- skips polling, so this stays directly
    callable exactly as before for standalone/unit-test use) lets
    _scan_sleep_mask pass through the shared whole-hunt ScanBudget so a
    dump with many qualifying regions can't make the offset loop below
    run for unbounded total time across all of them combined, on top of
    the existing per-region window cap.

    Returns list of (key_bytes, occurrence_count).
    """
    key_counts: dict = {}
    windows_per_offset_budget = max(1, max_windows // key_size)
    for offset in range(key_size):
        if budget is not None and not budget.poll():
            break
        available = (len(data) - offset) // key_size
        if available <= 0:
            continue
        step = max(1, available // windows_per_offset_budget)
        pos = 0
        examined = 0
        while pos + offset + key_size <= len(data) and examined < windows_per_offset_budget:
            window = data[pos + offset: pos + offset + key_size]
            key_counts[window] = key_counts.get(window, 0) + 1
            pos += key_size * step
            examined += 1

    candidates = []
    seen_normalized: set = set()

    for key, count in sorted(key_counts.items(), key=lambda x: x[1], reverse=True):
        if count < min_repeat:
            break   # sorted descending — no point continuing

        stats     = _sm_key_stats(key)
        max_freq  = stats[0][1]
        acbd      = _sm_avg_consec_diff(key)

        if max_freq >= max_byte_freq:
            continue   # single byte dominates → not a real key
        if acbd < min_acbd:
            continue   # monotonic sequence → not a real key

        norm = _sm_normalize_key(key)
        if norm in seen_normalized:
            continue   # same key at a different rotation already accepted
        seen_normalized.add(norm)

        candidates.append((key, count))
        if len(candidates) >= max_candidates:
            break

    return candidates


def _sm_validate_and_decode(data: bytes, candidates: list,
                             key_size: int = SLEEP_MASK_KEY_SIZE,
                             validate_sample: int = SLEEP_MASK_VALIDATE_SAMPLE,
                             validation_marker: bytes = SLEEP_MASK_VALIDATION_MARKER,
                             budget=None) -> list:
    """
    Try each candidate key at each rotation offset and look for the validation
    marker sha256\\x00, which is always present in beacon process memory.

    Algorithm (from cs-analyze-processdump.py ProcessBinaryFile inner loop):
        for offset in range(key_size):
            decoded = Xor(data, key, offset)
            if b'sha256\\x00' in decoded:
                → confirmed hit

    Two-phase like _scan_xor's sample-then-full-decode: up to
    MAX_CANDIDATES x key_size XOR passes over the WHOLE region would be
    up to ~1.3GB of work for a 10MB region (10 candidates x 13 rotations).
    Each combination is first tried against only the first
    validate_sample bytes; the full-region decode (needed to return
    complete decoded content) only runs for combinations that actually
    found the marker in the sample — expected to be rare (at most a
    handful of real hits), not all ~130 combinations.

    `budget` (default None -- skips polling, so this stays directly
    callable exactly as before for standalone/unit-test use) lets
    _scan_sleep_mask pass through the shared whole-hunt ScanBudget,
    checked once per candidate key: this is the genuinely expensive loop
    (up to ~130 XOR-over-2MB combinations per region), so a single huge
    region shouldn't be able to run it unbounded even alone, on top of
    the per-region loop in _scan_sleep_mask bounding total REGION count.

    Returns list of (key_bytes, offset, decoded_bytes) for confirmed hits.
    """
    confirmed = []
    sample_len = min(len(data), validate_sample)
    marker_len = len(validation_marker)
    for key, _count in candidates:
        if budget is not None and not budget.poll():
            break
        for offset in range(key_size):
            # Sample includes marker_len extra bytes of overlap so a match
            # straddling the sample boundary isn't missed.
            sample = _sm_xor(data[:sample_len + marker_len], key, offset)
            if validation_marker not in sample:
                continue
            decoded = sample if sample_len >= len(data) else _sm_xor(data, key, offset)
            confirmed.append((key, offset, decoded))
            break   # one confirmed decode per key is sufficient
    return confirmed


def _scan_sleep_mask(regions, modules, mf, read_region, config: EncodingConfig = None, budget=None) -> tuple:
    """
    Returns (hits, coverage). Layer 0: scan PAGE_READWRITE MEM_PRIVATE
    regions for CS Sleep Mask XOR encoding and attempt key recovery +
    decode.

    Target region characteristics:
      - State  : MEM_COMMIT
      - Type   : MEM_PRIVATE   (beacon's own heap/stack, not backed by a file)
      - Protect: PAGE_READWRITE (beacon XOR-encodes its memory before sleeping,
                  leaving protection as RW — NOT execute)
      - Size   : ≤ SLEEP_MASK_REGION_MAX (10 MB)
      - Not backed by a known module

    `coverage` (dumpex.hunt._coverage.CoverageTracker) distinguishes "0
    candidate regions existed" from "candidates existed but every one was
    too big / failed to read / short-read" — see CoverageTracker's own
    docstring for why this layer's gap shape fits it directly rather than
    hand-rolling the same four counters this function used to keep
    separately.

    `read_region` and `config` are passed in explicitly (rather than
    imported/read here) because dumpex.hunt.encoding's tests monkeypatch
    `encoding.read_region`/`encoding.SLEEP_MASK_*` directly; _hunt_encoding
    passes its own (possibly-patched) module-level values through on
    every call, so this function always sees whatever the caller
    currently has bound rather than this module's own separate constants
    (see dumpex/hunt/_encoding/config.py). `config=None` defaults to this
    module's own constants.

    `budget` (default None -- no cross-region bound, matching this
    function's behavior before this parameter existed) is the SAME
    ScanBudget instance _hunt_encoding shares with layers 2-4: unlike
    entropy's cheap linear per-region scan, sleep-mask's candidate
    recovery + validation is genuinely expensive per region (up to ~130
    XOR-over-2MB combinations, see _sm_validate_and_decode), so a dump
    with many qualifying ≤10MB regions could otherwise make this layer's
    total running time grow unboundedly with region COUNT even though
    each region alone stays within its own caps. Checked once per region
    here, and threaded into _sm_recover_candidates/_sm_validate_and_decode
    so a single expensive region can't run unbounded either.

    Returns list of:
        {
          'region'  : MinidumpMemoryInfo,
          'key'     : bytes,          # recovered XOR key
          'offset'  : int,            # key rotation offset that decoded correctly
          'decoded' : bytes,          # fully decoded region content
          'cls'     : dict,           # _classify_decoded() result
        }
    """
    if config is None:
        config = EncodingConfig(
            sleep_mask_key_size=SLEEP_MASK_KEY_SIZE, sleep_mask_min_repeat=SLEEP_MASK_MIN_REPEAT,
            sleep_mask_max_byte_freq=SLEEP_MASK_MAX_BYTE_FREQ, sleep_mask_min_acbd=SLEEP_MASK_MIN_ACBD,
            sleep_mask_max_candidates=SLEEP_MASK_MAX_CANDIDATES, sleep_mask_region_max=SLEEP_MASK_REGION_MAX,
            sleep_mask_validate_sample=SLEEP_MASK_VALIDATE_SAMPLE,
            sleep_mask_validation_marker=SLEEP_MASK_VALIDATION_MARKER,
            sleep_mask_max_windows=SLEEP_MASK_MAX_WINDOWS,
        )
    hits = []
    coverage = CoverageTracker()
    for r in regions:
        if budget is not None and budget.exhausted():
            coverage.budget_exhausted = True
            break
        if prot_str(r.State)   != 'MEM_COMMIT':
            continue
        if prot_str(r.Type)    != 'MEM_PRIVATE':
            continue
        if prot_str(r.Protect) != 'PAGE_READWRITE':
            continue
        if r.RegionSize < config.sleep_mask_key_size * config.sleep_mask_min_repeat:
            continue   # region too small to ever contain enough key repetitions
        if addr_to_module(r.BaseAddress, modules):
            continue   # module-backed region — not the beacon's private heap
        if r.RegionSize > config.sleep_mask_region_max:
            coverage.note_skipped_oversize()
            continue

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed()
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read()
            if not data:
                continue
        coverage.note_scanned()

        candidates = _sm_recover_candidates(
            data, key_size=config.sleep_mask_key_size, min_repeat=config.sleep_mask_min_repeat,
            max_candidates=config.sleep_mask_max_candidates, max_windows=config.sleep_mask_max_windows,
            max_byte_freq=config.sleep_mask_max_byte_freq, min_acbd=config.sleep_mask_min_acbd,
            budget=budget)
        if not candidates:
            continue

        confirmed = _sm_validate_and_decode(
            data, candidates, key_size=config.sleep_mask_key_size,
            validate_sample=config.sleep_mask_validate_sample,
            validation_marker=config.sleep_mask_validation_marker, budget=budget)
        for key, offset, decoded in confirmed:
            cls = _classify_decoded(decoded)
            hits.append({
                'region':  r,
                'key':     key,
                'offset':  offset,
                'decoded': decoded,
                'cls':     cls,
            })

    return hits, coverage
