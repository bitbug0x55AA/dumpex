"""
Layer 0 of dumpex.hunt.encoding — CS Sleep Mask XOR decode.

Algorithm adapted from cs-analyze-processdump.py by Didier Stevens
(public domain — https://DidierStevens.com).

Returns a LayerResult, never prints, never decides score/status — see
dumpex/hunt/encoding/models.py and dumpex/hunt/encoding/aggregate.py.
"""
import dataclasses
import struct

from dumpex.core.memory import addr_to_module, prot_str, va_range_captured_bytes
from dumpex.hunt._coverage import CoverageTracker, region_scan_target
from dumpex.hunt._location import resolve_location
from dumpex.hunt.encoding.classification import _classify_decoded
from dumpex.hunt.encoding.config import (
    EncodingConfig, SLEEP_MASK_KEY_SIZE, SLEEP_MASK_MIN_REPEAT, SLEEP_MASK_MAX_BYTE_FREQ,
    SLEEP_MASK_MIN_ACBD, SLEEP_MASK_MAX_CANDIDATES, SLEEP_MASK_MAX_WINDOWS,
    SLEEP_MASK_REGION_MAX, SLEEP_MASK_VALIDATE_SAMPLE, SLEEP_MASK_VALIDATION_MARKER,
)
from dumpex.hunt.encoding.models import DecodedHit, LayerCoverage, LayerResult, region_ref


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


def _sm_marker_in_region(data: bytes, key: bytes, offset: int, key_size: int,
                          chunk_size: int, marker: bytes, budget=None):
    """
    Search the COMPLETE region for `marker` under one (key, offset)
    combination, decoding bounded chunks rather than the whole region at
    once. Returns True if found, False if the entire region was searched
    without a match, or None if the shared budget ran out before the
    search finished (the caller must NOT treat that as a confirmed
    negative -- it means coverage is partial, not clean).

    Chunk `pos` in the region is decoded with `_sm_xor(chunk, key,
    (offset + pos) % key_size)`: XOR-ing a slice starting at absolute
    position `pos` with rotation `(offset + pos) % key_size` produces
    exactly the same bytes a single whole-region `_sm_xor(data, key,
    offset)` would have produced at that slice — `_sm_xor`'s rotation
    math is modular, so splitting the region into chunks changes nothing
    about which key byte lines up with which data byte.

    Each chunk read extends `overlap = len(marker) - 1` bytes past
    `chunk_size` so a marker straddling a chunk boundary is still found
    whole in one of the two chunks that overlap it.
    """
    overlap = len(marker) - 1
    pos = 0
    while pos < len(data):
        if budget is not None and not budget.poll():
            return None
        end = min(pos + chunk_size + overlap, len(data))
        chunk = _sm_xor(data[pos:end], key, (offset + pos) % key_size)
        if marker in chunk:
            return True
        pos += chunk_size
    return False


def _sm_validate_and_decode(data: bytes, candidates: list,
                             key_size: int = SLEEP_MASK_KEY_SIZE,
                             validate_sample: int = SLEEP_MASK_VALIDATE_SAMPLE,
                             validation_marker: bytes = SLEEP_MASK_VALIDATION_MARKER,
                             budget=None) -> list:
    """
    Try each candidate key at each rotation offset and look for the validation
    marker sha256\\x00, which is always present in beacon process memory,
    ACROSS THE COMPLETE eligible region (up to SLEEP_MASK_REGION_MAX) --
    not just its first `validate_sample` bytes.

    Algorithm (from cs-analyze-processdump.py ProcessBinaryFile inner loop,
    adapted to stream in bounded chunks rather than decode-then-search):
        for offset in range(key_size):
            for chunk in region, in validate_sample-sized pieces:
                if b'sha256\\x00' in Xor(chunk, key, offset):
                    → confirmed hit

    Prior to this, each combination was checked only against the first
    validate_sample bytes: a recovered key whose decoded marker happened
    to sit beyond that prefix was silently rejected, even though the key
    was correct and the marker WAS present later in the same region (see
    https://github.com/bitbug0x55AA/dumpex/issues/25). `validate_sample`
    is now a per-chunk streaming size rather than a hard search
    boundary — `_sm_marker_in_region` walks the whole region in chunks of
    this size, so the total work per (candidate, rotation) is bounded the
    same way (one chunk decoded at a time) while actually covering
    everything up to SLEEP_MASK_REGION_MAX. The full-region decode
    (needed to return complete decoded content) still only runs for a
    combination that actually found the marker somewhere — expected to be
    rare (at most a handful of real hits), not all ~130 combinations.

    `budget` (default None -- skips polling, so this stays directly
    callable exactly as before for standalone/unit-test use) lets
    _scan_sleep_mask pass through the shared whole-hunt ScanBudget,
    polled once per CHUNK (not just once per candidate key): this is the
    genuinely expensive loop (now up to ~130 XOR-over-full-region
    combinations per region, worst case), so a single huge region can't
    run it unbounded even alone, on top of the per-region loop in
    _scan_sleep_mask bounding total REGION count. If the budget runs out
    mid-search, `_sm_marker_in_region` returns None and the candidate
    loop stops immediately -- the shared ScanBudget itself then reports
    exhausted() to _build_encoding_report, which is what turns into
    partial coverage on the final report; a candidate/rotation combo cut
    short this way is never treated as a confirmed negative.

    Returns list of (key_bytes, offset, decoded_bytes) for confirmed hits.
    """
    confirmed = []
    chunk_size = max(1, validate_sample)
    for key, _count in candidates:
        if budget is not None and not budget.poll():
            break
        hit_offset = None
        budget_ran_out = False
        for offset in range(key_size):
            result = _sm_marker_in_region(
                data, key, offset, key_size, chunk_size, validation_marker, budget)
            if result is None:
                budget_ran_out = True
                break
            if result:
                hit_offset = offset
                break   # one confirmed decode per key is sufficient
        if hit_offset is not None:
            decoded = _sm_xor(data, key, hit_offset)
            confirmed.append((key, hit_offset, decoded))
        if budget_ran_out:
            break
    return confirmed


def _scan_sleep_mask(regions, modules, mf, read_region, config: EncodingConfig = None, budget=None,
                      susp_prots=()) -> LayerResult:
    """
    Layer 0: scan PAGE_READWRITE MEM_PRIVATE regions for CS Sleep Mask
    XOR encoding and attempt key recovery + decode.

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
    docstring.

    `read_region` and `config` are passed in explicitly (rather than
    imported/read here) because dumpex.hunt.encoding's tests monkeypatch
    `encoding.read_region`/`encoding.SLEEP_MASK_*` directly; _hunt_encoding
    passes its own (possibly-patched) module-level values through on
    every call. `config=None` defaults to this module's own constants.

    `budget` (default None -- no cross-region bound, matching this
    function's behavior before this parameter existed) is the SAME
    ScanBudget instance _hunt_encoding shares with layers 2-4: unlike
    entropy's cheap linear per-region scan, sleep-mask's candidate
    recovery + validation is genuinely expensive per region (up to ~130
    candidate/rotation combinations, each now streamed in chunks across
    the COMPLETE region rather than just its first 2MB, see
    _sm_validate_and_decode / _sm_marker_in_region), so a dump with many
    qualifying ≤10MB regions could otherwise make this layer's total
    running time grow unboundedly with region COUNT even though each
    region alone stays within its own caps. Checked once per region here,
    and threaded into _sm_recover_candidates/_sm_validate_and_decode
    (polled once per chunk there) so a single expensive region can't run
    unbounded either.

    `susp_prots` (default `()`) is the rules-derived suspicious-protection
    string list, threaded through to `region_ref()` so each hit's
    `region.is_rwx` is resolved once here rather than by aggregate.py.

    Returns a LayerResult whose hits are DecodedHit objects carrying
    `key` (recovered XOR key) and `key_offset` (rotation offset that
    decoded correctly), in addition to the common region/location/
    decoded/classification fields.
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
    window_sampled = False
    candidate_cap_hit = False
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
        if r.RegionSize <= 0:
            # A zero-length region has nothing to read and no bytes anyone
            # could miss: a filter, not a coverage gap. It is also not
            # something a ScanTarget can identify -- a target has an
            # extent by definition.
            continue
        # Past every filter: this region is IN SCOPE, so every path out of
        # the iteration from here on owes the ledger a disposition.
        coverage.note_eligible(va_range_captured_bytes(mf, r.BaseAddress, r.RegionSize))
        if r.RegionSize > config.sleep_mask_region_max:
            coverage.note_skipped_oversize(
                region_scan_target(mf, r, config.sleep_mask_region_max))
            continue

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if not data:
            # Nothing came back at all -- a failed read, not a short one:
            # a short read annotates a region that WAS scanned.
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read(region_scan_target(mf, r), got=len(data))
        coverage.note_scanned()

        # SLEEP_MASK_MAX_WINDOWS strides the recovery scan over a sample of
        # windows once a region is large enough; SLEEP_MASK_MAX_CANDIDATES
        # truncates the recovered key list. Either bounds the search, so a
        # negative result over this region is not a full-search negative.
        per_offset = max(1, config.sleep_mask_max_windows // config.sleep_mask_key_size)
        if len(data) // config.sleep_mask_key_size > per_offset:
            window_sampled = True

        # Ask for one more candidate than the cap allows: a returned list
        # LONGER than the cap proves a real key was dropped, whereas a list
        # exactly AT the cap only proves that many qualified. Only the first
        # `max_candidates` are ever validated.
        recovered = _sm_recover_candidates(
            data, key_size=config.sleep_mask_key_size, min_repeat=config.sleep_mask_min_repeat,
            max_candidates=config.sleep_mask_max_candidates + 1,
            max_windows=config.sleep_mask_max_windows,
            max_byte_freq=config.sleep_mask_max_byte_freq, min_acbd=config.sleep_mask_min_acbd,
            budget=budget)
        if len(recovered) > config.sleep_mask_max_candidates:
            candidate_cap_hit = True
            recovered = recovered[:config.sleep_mask_max_candidates]
        candidates = recovered
        if not candidates:
            continue

        confirmed = _sm_validate_and_decode(
            data, candidates, key_size=config.sleep_mask_key_size,
            validate_sample=config.sleep_mask_validate_sample,
            validation_marker=config.sleep_mask_validation_marker, budget=budget)
        for key, offset, decoded in confirmed:
            classification = _classify_decoded(decoded)
            hits.append(DecodedHit(
                layer='sleep_mask', region=region_ref(r, susp_prots),
                location=resolve_location(mf, r.BaseAddress, r.BaseAddress, r.RegionSize),
                decoded=decoded, classification=classification,
                complete=True, key=key, key_offset=offset))

    return LayerResult(
        hits=hits,
        coverage=dataclasses.replace(
            LayerCoverage.from_tracker(coverage),
            window_sampled=window_sampled, candidate_cap_hit=candidate_cap_hit))
