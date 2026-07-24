"""
Encoded / obfuscated payload hunter.

Detection layers (applied per memory region):

  Layer 0: CS Sleep Mask XOR decode  — frequency-analysis key recovery for
                                       Cobalt Strike beacon memory encoded by
                                       the sleep mask (PAGE_READWRITE private
                                       regions). Adapted from cs-analyze-
                                       processdump.py by Didier Stevens
                                       (public domain, https://DidierStevens.com).

  Layer 1: Shannon entropy scan  — catches all encoding schemes including custom
                                   crypto, RC4, AES blobs, multi-byte XOR, etc.

  Layer 2: Base64 detection      — standard + URL-safe; minimum 48 chars (36
                                   decoded bytes)

  Layer 3: XOR single-byte BF    — MEM_PRIVATE regions ≤ 512 KB only;
                                   sample-first heuristic to avoid O(n×255)
                                   full-region cost

  Layer 4: GZIP / ZLIB           — magic-byte scan + decompress attempt

All decoded/decompressed content goes through a shared classifier:
  - MZ + PE\\x00\\x00     → PE payload → _hunt_hidden_pe logic applied
  - call-$+5 bootstrap    → likely shellcode
  - printable > 85 %      → IOC string scan (IP / URL / pipe names)
  - else                  → hex prefix reported

Address semantics: every hit reports VA (process) + .dmp file offset,
consistent with the rest of Dumpex.
"""

import re
import math
import time
import zlib
import struct
import os
from collections import Counter
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors   import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (
    get_modules, get_memory_regions, addr_to_module,
    va_to_file_offset, prot_str, read_region, _extract_strings_from_data,
)
from dumpex.hunt._ui    import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt.injection import _hunt_hidden_pe   # reuse for PE re-check

# ── Tunables ──────────────────────────────────────────────────────────────
ENTROPY_PRIVATE_THRESHOLD = 7.2   # MEM_PRIVATE: likely encrypted / packed
ENTROPY_RWX_THRESHOLD     = 6.5   # MEM_PRIVATE + RWX: lower bar (combo is critical)
ENTROPY_SCAN_MAX          = 10 * 1024 * 1024   # entropy scan: skip regions > 10 MB
DECODE_SCAN_MAX           =  2 * 1024 * 1024   # Base64 / XOR / GZIP: skip > 2 MB
XOR_SCAN_MAX              = 512 * 1024         # max region for single-byte XOR BF
XOR_SAMPLE_SIZE           = 4096               # bytes sampled before full decode
XOR_SCORE_MIN             = 0.68               # printable ratio to accept a key
B64_MIN_LEN               = 80                 # minimum Base64 string length

# Layers 2 (Base64) and 4 (GZIP/ZLIB) share ONE ScanBudget across the whole
# hunt (all regions combined) rather than each region getting its own
# independent "≤200 attempts per signature" allowance — a dump with many
# qualifying regions could otherwise turn a per-region cap into unbounded
# total decode attempts and retained memory. See dumpex/hunt/_budget.py.
ENCODING_BUDGET_MAX_ATTEMPTS  = 2000              # total decode/decompress
                                                   # attempts, whole hunt
ENCODING_BUDGET_MAX_RETAINED  = 32 * 1024 * 1024  # cumulative decoded bytes
                                                   # kept in findings, whole hunt
ENCODING_BUDGET_MAX_HITS      = 500               # cumulative hits retained
ENCODING_BUDGET_TIME_SECONDS  = 60.0              # wall-clock cap, layers 2-4 combined
ENCODING_PREVIEW_BYTES        = 4096              # bytes kept once the retained-bytes
                                                   # budget is tight, instead of the
                                                   # full decoded content

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

DECOMPRESS_MAX_OUTPUT = 8 * 1024 * 1024   # cap decompressed output per candidate; a small
                                           # compressed blob can expand enormously (zip
                                           # bomb), and input-size limits alone don't bound
                                           # output size — 8MB is far more than needed to
                                           # classify content (PE header, IOC strings, etc).


def _is_system_dll(module) -> bool:
    """True if module is a Microsoft system DLL under System32/SysWOW64/WinSxS."""
    if module is None:
        return False
    path = (module.name or "").replace("\\", "/").lower()
    return (
        "/windows/system32/"  in path or
        "/windows/syswow64/" in path or
        "/windows/winsxs/"   in path
    )

# IOC pattern for plaintext classification
_IOC_PAT = re.compile(
    r'https?://\S{4,}'
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?'
    r'|\\pipe\\[^\s\x00]+'
    r'|(?:cmd|powershell|mshta|wscript)\.exe',
    re.IGNORECASE,
)

def _is_plausible_ip(ip_str: str) -> bool:
    host = ip_str.split(':')[0]
    parts = host.split('.')
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    if all(o < 10 for o in octets):
        return False
    if octets[0] in (0, 127):
        return False
    if octets[0] == 169 and octets[1] == 254:
        return False
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False
    return True


_B64_PAT = re.compile(
    rb'(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    rb'|(?:[A-Za-z0-9\-_]{4}){12,}(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?'
)

_GZIP_SIG  = b'\x1f\x8b'
_ZLIB_SIGS = (b'\x78\x9c', b'\x78\xda', b'\x78\x01', b'\x78\x5e')


# ── Shared classifier ─────────────────────────────────────────────────────

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _classify_decoded(data: bytes) -> dict:
    result = {
        'type': 'binary',
        'is_pe': False,
        'is_shellcode': False,
        'ioc_strings': [],
        'hex_prefix': data[:16].hex() if data else '',
        'entropy': _shannon_entropy(data[:4096]),
    }
    if len(data) < 4:
        return result

    if data[:2] == b'MZ':
        pe_offset = struct.unpack_from('<I', data, 0x3c)[0] if len(data) > 0x40 else 0
        if pe_offset and pe_offset + 4 <= len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
            result.update({'type': 'pe', 'is_pe': True})
            return result

    if data[:6] in (b'\xe8\x00\x00\x00\x00\x58',
                    b'\xe8\x00\x00\x00\x00\x59',
                    b'\xe8\x00\x00\x00\x00\x5b',
                    b'\xe8\x00\x00\x00\x00\x5e'):
        result.update({'type': 'shellcode', 'is_shellcode': True})
        return result

    sample = data[:2048]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(sample)
    if ratio > 0.85:
        text = data[:8192].decode('ascii', errors='replace')
        raw_iocs = _IOC_PAT.findall(text)
        iocs = [s for s in raw_iocs
                if not re.match(r'^\d+\.\d+\.\d+\.\d+', s) or _is_plausible_ip(s)]
        if iocs:
            result.update({'type': 'ioc_text', 'ioc_strings': iocs[:10]})
        else:
            result['type'] = 'plaintext'
        return result

    if result['entropy'] > 7.2:
        result['type'] = 'high_entropy'

    return result


# ══════════════════════════════════════════════════════════════════════════
# LAYER 0 — CS Sleep Mask XOR decode
# Algorithm adapted from cs-analyze-processdump.py by Didier Stevens
# (public domain — https://DidierStevens.com)
# ══════════════════════════════════════════════════════════════════════════

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
                            max_windows: int = SLEEP_MASK_MAX_WINDOWS) -> list:
    """
    Recover candidate sleep mask XOR keys from a memory region via frequency
    analysis on overlapping key-sized windows.

    Algorithm (from cs-analyze-processdump.py ProcessBinaryFile):
      1. For each alignment offset 0..key_size-1, slide a non-overlapping
         key_size window across the data and count occurrences of each window.
      2. Filter candidates: count >= min_repeat, no single byte dominates
         (max byte freq < SLEEP_MASK_MAX_BYTE_FREQ), and the key is not
         monotonic (ACBD >= SLEEP_MASK_MIN_ACBD).
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

    Returns list of (key_bytes, occurrence_count).
    """
    key_counts: dict = {}
    windows_per_offset_budget = max(1, max_windows // key_size)
    for offset in range(key_size):
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

        if max_freq >= SLEEP_MASK_MAX_BYTE_FREQ:
            continue   # single byte dominates → not a real key
        if acbd < SLEEP_MASK_MIN_ACBD:
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
                             key_size: int = SLEEP_MASK_KEY_SIZE) -> list:
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
    SLEEP_MASK_VALIDATE_SAMPLE bytes; the full-region decode (needed to
    return complete decoded content) only runs for combinations that
    actually found the marker in the sample — expected to be rare (at
    most a handful of real hits), not all ~130 combinations.

    Returns list of (key_bytes, offset, decoded_bytes) for confirmed hits.
    """
    confirmed = []
    sample_len = min(len(data), SLEEP_MASK_VALIDATE_SAMPLE)
    marker_len = len(SLEEP_MASK_VALIDATION_MARKER)
    for key, _count in candidates:
        for offset in range(key_size):
            # Sample includes marker_len extra bytes of overlap so a match
            # straddling the sample boundary isn't missed.
            sample = _sm_xor(data[:sample_len + marker_len], key, offset)
            if SLEEP_MASK_VALIDATION_MARKER not in sample:
                continue
            decoded = sample if sample_len >= len(data) else _sm_xor(data, key, offset)
            confirmed.append((key, offset, decoded))
            break   # one confirmed decode per key is sufficient
    return confirmed


def _scan_sleep_mask(regions, modules, mf) -> tuple:
    """
    Returns (hits, scanned_count, size_skipped_count, read_failed_count).
    Layer 0: scan PAGE_READWRITE MEM_PRIVATE regions for CS Sleep Mask
    XOR encoding and attempt key recovery + decode.

    Target region characteristics:
      - State  : MEM_COMMIT
      - Type   : MEM_PRIVATE   (beacon's own heap/stack, not backed by a file)
      - Protect: PAGE_READWRITE (beacon XOR-encodes its memory before sleeping,
                  leaving protection as RW — NOT execute)
      - Size   : ≤ SLEEP_MASK_REGION_MAX (10 MB)
      - Not backed by a known module

    Returns list of:
        {
          'region'  : MinidumpMemoryInfo,
          'key'     : bytes,          # recovered XOR key
          'offset'  : int,            # key rotation offset that decoded correctly
          'decoded' : bytes,          # fully decoded region content
          'cls'     : dict,           # _classify_decoded() result
        }
    """
    hits        = []
    scanned     = 0   # regions actually read+analyzed, past all filters —
                       # distinguishes "0 candidate regions existed" from
                       # "candidates existed but every one was too big/wrong type"
    size_skipped = 0   # otherwise-eligible region skipped only for exceeding
                        # SLEEP_MASK_REGION_MAX — a real coverage gap, unlike
                        # a region that structurally doesn't match this layer
    read_failed  = 0
    for r in regions:
        if prot_str(r.State)   != 'MEM_COMMIT':
            continue
        if prot_str(r.Type)    != 'MEM_PRIVATE':
            continue
        if prot_str(r.Protect) != 'PAGE_READWRITE':
            continue
        if r.RegionSize < SLEEP_MASK_KEY_SIZE * SLEEP_MASK_MIN_REPEAT:
            continue   # region too small to ever contain enough key repetitions
        if addr_to_module(r.BaseAddress, modules):
            continue   # module-backed region — not the beacon's private heap
        if r.RegionSize > SLEEP_MASK_REGION_MAX:
            size_skipped += 1
            continue

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            read_failed += 1
            continue
        scanned += 1

        candidates = _sm_recover_candidates(data)
        if not candidates:
            continue

        confirmed = _sm_validate_and_decode(data, candidates)
        for key, offset, decoded in confirmed:
            cls = _classify_decoded(decoded)
            hits.append({
                'region':  r,
                'key':     key,
                'offset':  offset,
                'decoded': decoded,
                'cls':     cls,
            })

    return hits, scanned, size_skipped, read_failed


# ══════════════════════════════════════════════════════════════════════════
# LAYER 1 — Shannon entropy
# ══════════════════════════════════════════════════════════════════════════

def _scan_entropy(regions, modules, mf, susp_prots):
    hits        = []
    scanned     = 0
    size_skipped = 0
    read_failed  = 0
    for r in regions:
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) != 'MEM_PRIVATE':
            continue
        if addr_to_module(r.BaseAddress, modules):
            continue
        if r.RegionSize > ENTROPY_SCAN_MAX:
            size_skipped += 1
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            read_failed += 1
            continue
        if len(data) < 256:
            continue
        scanned += 1

        ent = _shannon_entropy(data)
        p      = prot_str(r.Protect)
        is_rwx = any(s in p for s in susp_prots)
        threshold = ENTROPY_RWX_THRESHOLD if is_rwx else ENTROPY_PRIVATE_THRESHOLD

        if ent >= threshold:
            hits.append((r, ent, threshold))
    return hits, scanned, size_skipped, read_failed


# ══════════════════════════════════════════════════════════════════════════
# LAYER 2 — Base64
# ══════════════════════════════════════════════════════════════════════════

def _scan_base64(data: bytes, region_base: int, budget: ScanBudget):
    for m in _B64_PAT.finditer(data):
        if budget.exhausted():
            return
        raw = m.group(0)
        if len(raw) < B64_MIN_LEN:
            continue
        if not budget.note_attempt():
            return
        try:
            normalised = raw.replace(b'-', b'+').replace(b'_', b'/')
            pad = len(normalised) % 4
            if pad:
                normalised += b'=' * (4 - pad)
            decoded = __import__('base64').b64decode(normalised)
        except Exception:
            continue
        if len(decoded) < 16:
            continue
        if not budget.seen_content(decoded):
            continue   # identical payload already seen elsewhere in this hunt
        cls = _classify_decoded(decoded)
        if cls['type'] == 'binary' and not cls['ioc_strings']:
            continue
        budget.note_bytes_read(len(decoded))
        kept = decoded if budget.note_retained(len(decoded)) else decoded[:ENCODING_PREVIEW_BYTES]
        yield m.start(), raw, kept, cls


# ══════════════════════════════════════════════════════════════════════════
# LAYER 3 — Single-byte XOR brute-force
# ══════════════════════════════════════════════════════════════════════════

def _score_xor_key(data: bytes, key: int) -> float:
    decoded  = bytes(b ^ key for b in data)
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(decoded)


def _scan_xor(data: bytes, region_base: int, budget: ScanBudget):
    # The key-scoring pass below is already tightly bounded (exactly 255
    # keys scored against a fixed 4KB sample, only for MEM_PRIVATE regions
    # <= XOR_SCAN_MAX) — it doesn't draw on the shared decode/decompress
    # attempt budget, only on the retained-bytes/dedup accounting shared
    # with the other layers once a candidate actually decodes.
    sample = data[:XOR_SAMPLE_SIZE]
    candidates = []
    for key in range(1, 256):
        score = _score_xor_key(sample, key)
        if score >= XOR_SCORE_MIN:
            decoded_sample = bytes(b ^ key for b in sample)
            text = decoded_sample.decode('ascii', errors='replace')
            if _IOC_PAT.search(text) or any(
                kw in text.lower() for kw in
                ('http', 'pipe', 'cmd', 'shellcode', 'beacon', 'rundll')
            ):
                candidates.append((key, score))

    for key, _ in sorted(candidates, key=lambda x: -x[1])[:5]:
        if budget.exhausted():
            return
        decoded = bytes(b ^ key for b in data)
        if not budget.seen_content(decoded):
            continue
        cls = _classify_decoded(decoded)
        if cls['is_pe'] or cls['is_shellcode'] or cls['ioc_strings']:
            budget.note_bytes_read(len(decoded))
            kept = decoded if budget.note_retained(len(decoded)) else decoded[:ENCODING_PREVIEW_BYTES]
            yield key, kept, cls


# ══════════════════════════════════════════════════════════════════════════
# LAYER 4 — GZIP / ZLIB
# ══════════════════════════════════════════════════════════════════════════

def _bounded_decompress(payload: bytes, wbits: int) -> bytes:
    """
    Decompress with a hard output-size cap. zlib.decompress() has no such
    cap — a small, even accidentally-truncated, compressed blob can expand
    to gigabytes (zip bomb), and the input-size limit callers apply
    upstream doesn't bound that. decompressobj().decompress(data,
    max_length=N) stops after N output bytes, which is all classification
    needs (PE header / IOC strings live in the first few KB anyway).
    """
    d = zlib.decompressobj(wbits)
    return d.decompress(payload, DECOMPRESS_MAX_OUTPUT)


def _scan_compressed(data: bytes, region_base: int, budget: ScanBudget):
    """
    Scan for GZIP/ZLIB magic bytes and attempt decompression at each one.

    Decompress attempts are bounded by the shared, whole-hunt `budget`
    (ENCODING_BUDGET_MAX_ATTEMPTS) rather than a fixed count per signature
    per region — a 2-byte magic sequence has no error-correction, so a
    region with many coincidental (or adversarially placed) occurrences
    could otherwise trigger unbounded decompressobj() attempts across a
    dump with many such regions, even though each individual attempt is
    itself output-capped (_bounded_decompress). Successful decodes are
    deduplicated by content hash and only retained up to
    ENCODING_BUDGET_MAX_RETAINED cumulative bytes — past that, a bounded
    preview is kept instead of the full decoded payload.
    """
    start = 0
    while True:
        if budget.exhausted():
            return
        idx = data.find(_GZIP_SIG, start)
        if idx == -1:
            break
        if not budget.note_attempt():
            return
        try:
            decoded = _bounded_decompress(data[idx:], wbits=47)
            if len(decoded) >= 64 and budget.seen_content(decoded):
                budget.note_bytes_read(len(decoded))
                kept = decoded if budget.note_retained(len(decoded)) else decoded[:ENCODING_PREVIEW_BYTES]
                yield idx, 'gzip', kept, _classify_decoded(decoded)
        except Exception:
            pass
        start = idx + 1

    for sig in _ZLIB_SIGS:
        start = 0
        while True:
            if budget.exhausted():
                return
            idx = data.find(sig, start)
            if idx == -1:
                break
            if not budget.note_attempt():
                return
            try:
                decoded = _bounded_decompress(data[idx:], wbits=zlib.MAX_WBITS)
                if len(decoded) >= 64 and budget.seen_content(decoded):
                    budget.note_bytes_read(len(decoded))
                    kept = decoded if budget.note_retained(len(decoded)) else decoded[:ENCODING_PREVIEW_BYTES]
                    yield idx, 'zlib', kept, _classify_decoded(decoded)
            except Exception:
                pass
            start = idx + 1


# ══════════════════════════════════════════════════════════════════════════
# MAIN HUNTER
# ══════════════════════════════════════════════════════════════════════════

def _hunt_encoding(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan process memory for encoded / obfuscated payloads.

    Runs five detection layers in sequence:

      Layer 0  CS Sleep Mask  — frequency-analysis XOR key recovery for
                                beacon memory encoded while sleeping
                                (adapted from Didier Stevens cs-analyze-
                                processdump.py, public domain)
      Layer 1  Entropy        — Shannon entropy on MEM_PRIVATE regions
      Layer 2  Base64         — standard + URL-safe alphabet
      Layer 3  XOR 1-byte BF  — brute-force single-byte XOR with IOC check
      Layer 4  GZIP / ZLIB    — magic byte + decompress attempt

    Decoded content from all layers passes through a shared classifier.
    PE payloads trigger a module-list cross-check (same as _hunt_injection).
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    SUSPICIOUS_PROTS = get_rules()["suspicious_protections"]
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)

    findings = {
        'sleep_mask': [],   # Layer 0: (hit_dict, ...)
        'entropy':    [],   # Layer 1: (region, entropy, threshold)
        'base64':     [],   # Layer 2: (region, offset, cls)
        'xor':        [],   # Layer 3: (region, key, cls)
        'compressed': [],   # Layer 4: (region, offset, algo, cls)
        'hidden_pe':  [],
        'score': 0,
    }

    _print_hunt_header("Obfuscation Detection")

    # ── Layer 0: CS Sleep Mask XOR ────────────────────────────────────────
    print(DIM("  [*] Layer 0: CS Sleep Mask XOR scan (frequency analysis) …"))
    sleep_mask_hits, sleep_mask_scanned, sleep_mask_size_skipped, sleep_mask_read_failed = \
        _scan_sleep_mask(regions, modules, mf)

    if sleep_mask_hits:
        detail = f"{len(sleep_mask_hits)} region(s) with confirmed CS Sleep Mask encoding"
        for hit in sleep_mask_hits:
            r      = hit['region']
            key    = hit['key']
            offset = hit['offset']
            cls    = hit['cls']
            fo     = va_to_file_offset(mf, r.BaseAddress)
            fo_str = f"0x{fo:x}" if fo else "(not captured)"
            ctype  = cls['type'].upper()
            color_fn = RED if cls['is_pe'] or cls['is_shellcode'] else YELLOW

            detail += (
                f"\n          VA (process)   0x{r.BaseAddress:016x}"
                f"\n          File offset    {fo_str}"
                f"\n          Region size    0x{r.RegionSize:x}  ({r.RegionSize // 1024} KB)"
                f"\n          XOR key        {key.hex()}  (rotation offset {offset})"
                f"\n          Decoded type   {color_fn(ctype)}"
            )
            if cls['ioc_strings']:
                detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:4])}"

            if cls['is_pe']:
                findings['hidden_pe'].append(('sleep_mask', r, 0, hit['decoded']))

        _print_check(
            "CS Sleep Mask XOR-encoded beacon memory",
            RED("SUSPICIOUS — beacon memory decoded via sleep mask key recovery"),
            detail,
        )
        findings['sleep_mask'] = sleep_mask_hits
        findings['score'] += 1
    else:
        _print_check(
            "CS Sleep Mask XOR-encoded beacon memory",
            GREEN("CLEAN — no sleep mask XOR encoding detected"),
        )

    # ── Layer 1: Entropy ──────────────────────────────────────────────────
    print(DIM("  [*] Layer 1: Shannon entropy scan …"))
    entropy_hits, entropy_scanned, entropy_size_skipped, entropy_read_failed = \
        _scan_entropy(regions, modules, mf, SUSPICIOUS_PROTS)

    if entropy_hits:
        detail = f"{len(entropy_hits)} high-entropy MEM_PRIVATE region(s)"
        if verbose:
            for r, ent, threshold in entropy_hits:
                p      = prot_str(r.Protect)
                fo     = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                rwx    = RED(" [RWX]") if any(s in p for s in SUSPICIOUS_PROTS) else ""
                detail += (
                    f"\n          VA (process)   0x{r.BaseAddress:016x}{rwx}"
                    f"\n          File offset    {fo_str}"
                    f"\n          Size           0x{r.RegionSize:x}"
                    f"\n          Entropy        {ent:.3f} bits  (threshold: {threshold})"
                    f"\n          Protection     {p}"
                )
        _print_check("High-entropy private memory (likely encrypted/packed)",
                     RED("SUSPICIOUS"), detail)
        findings['entropy'] = entropy_hits
        findings['score'] += 1
    else:
        _print_check("High-entropy private memory",
                     GREEN("CLEAN — no anomalous entropy in private regions"))

    # ── Layers 2–4: per-region decode ─────────────────────────────────────
    print(DIM("  [*] Layers 2-4: Base64 / XOR / GZIP scan …"))

    b64_hits, xor_hits, cmp_hits, pe_hits = [], [], [], []
    decode_scanned      = 0
    decode_size_skipped = 0
    decode_read_failed  = 0

    # One budget shared across every region for the rest of this hunt (see
    # dumpex/hunt/_budget.py) — bounds total decode/decompress attempts and
    # retained bytes across the WHOLE scan, not per-region.
    decode_budget = ScanBudget(
        max_bytes_read=ENCODING_BUDGET_MAX_RETAINED * 4,
        max_attempts=ENCODING_BUDGET_MAX_ATTEMPTS,
        max_retained_bytes=ENCODING_BUDGET_MAX_RETAINED,
        max_hits=ENCODING_BUDGET_MAX_HITS,
        deadline=time.monotonic() + ENCODING_BUDGET_TIME_SECONDS,
    )

    for r in regions:
        if decode_budget.exhausted():
            break
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) not in ('MEM_PRIVATE', 'MEM_IMAGE'):
            continue
        mod = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == 'MEM_IMAGE' and _is_system_dll(mod):
            continue
        if r.RegionSize > DECODE_SCAN_MAX:
            decode_size_skipped += 1
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            decode_read_failed += 1
            continue
        decode_scanned += 1

        for off, raw, decoded, cls in _scan_base64(data, r.BaseAddress, decode_budget):
            decode_budget.note_hit()
            b64_hits.append((r, off, cls, raw, decoded))
            if cls['is_pe']:
                pe_hits.append(('base64', r, off, decoded))

        if (prot_str(r.Type) == 'MEM_PRIVATE' and r.RegionSize <= XOR_SCAN_MAX):
            for key, decoded, cls in _scan_xor(data, r.BaseAddress, decode_budget):
                decode_budget.note_hit()
                xor_hits.append((r, key, cls, decoded))
                if cls['is_pe']:
                    pe_hits.append(('xor', r, 0, decoded))

        if not decode_budget.exhausted():
            for off, algo, decoded, cls in _scan_compressed(data, r.BaseAddress, decode_budget):
                decode_budget.note_hit()
                cmp_hits.append((r, off, algo, cls, decoded))
                if cls['is_pe']:
                    pe_hits.append((algo, r, off, decoded))

    # ── Report Base64 ─────────────────────────────────────────────────────
    seen_b64 = set()
    b64_unique = []
    for item in b64_hits:
        if item[0].BaseAddress not in seen_b64:
            seen_b64.add(item[0].BaseAddress)
            b64_unique.append(item)

    if b64_unique:
        detail = f"{len(b64_unique)} region(s) with Base64 payload(s)"
        if verbose:
            for r, off, cls, raw, decoded in b64_unique[:10]:
                abs_va = r.BaseAddress + off
                fo     = va_to_file_offset(mf, abs_va)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                ctype  = cls['type'].upper()
                color_fn = RED if cls['is_pe'] or cls['is_shellcode'] else YELLOW
                detail += (
                    f"\n          VA (process)   0x{abs_va:016x}"
                    f"\n          File offset    {fo_str}"
                    f"\n          Decoded type   {color_fn(ctype)}"
                    f"\n          Decoded size   {len(decoded)} bytes"
                    f"\n          B64 length     {len(raw)} chars"
                )
                if cls['ioc_strings']:
                    detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:3])}"
        severity = (RED("SUSPICIOUS — PE or shellcode in Base64")
                    if any(h[2]['is_pe'] or h[2]['is_shellcode'] for h in b64_unique)
                    else YELLOW("NOTABLE — Base64 encoded data in memory"))
        _print_check("Base64 encoded payloads", severity, detail)
        findings['base64'] = b64_unique
        findings['score'] += 1
    else:
        _print_check("Base64 encoded payloads",
                     GREEN("CLEAN — no significant Base64 payloads found"))

    # ── Report XOR ────────────────────────────────────────────────────────
    seen_xor = set()
    xor_unique = []
    for item in xor_hits:
        if item[0].BaseAddress not in seen_xor:
            seen_xor.add(item[0].BaseAddress)
            xor_unique.append(item)

    if xor_unique:
        detail = f"{len(xor_unique)} region(s) with single-byte XOR obfuscation"
        if verbose:
            for r, key, cls, decoded in xor_unique[:10]:
                fo     = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                ctype  = cls['type'].upper()
                detail += (
                    f"\n          VA (process)   0x{r.BaseAddress:016x}"
                    f"\n          File offset    {fo_str}"
                    f"\n          XOR key        0x{key:02x}"
                    f"\n          Decoded type   {RED(ctype) if cls['is_pe'] else YELLOW(ctype)}"
                )
                if cls['ioc_strings']:
                    detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:3])}"
        severity = (RED("SUSPICIOUS — PE or shellcode behind XOR obfuscation")
                    if any(h[2]['is_pe'] or h[2]['is_shellcode'] for h in xor_unique)
                    else YELLOW("NOTABLE — XOR-obfuscated data identified"))
        _print_check("XOR single-byte obfuscation", severity, detail)
        findings['xor'] = xor_unique
        findings['score'] += 1
    else:
        _print_check("XOR single-byte obfuscation",
                     GREEN("CLEAN — no single-byte XOR payloads identified"))

    # ── Report GZIP / ZLIB ────────────────────────────────────────────────
    seen_cmp = set()
    cmp_unique = []
    for item in cmp_hits:
        if item[0].BaseAddress not in seen_cmp:
            seen_cmp.add(item[0].BaseAddress)
            cmp_unique.append(item)

    if cmp_unique:
        detail = f"{len(cmp_unique)} region(s) with compressed data (GZIP/ZLIB)"
        if verbose:
            for r, off, algo, cls, decoded in cmp_unique[:10]:
                abs_va = r.BaseAddress + off
                fo     = va_to_file_offset(mf, abs_va)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                detail += (
                    f"\n          VA (process)   0x{abs_va:016x}"
                    f"\n          File offset    {fo_str}"
                    f"\n          Algorithm      {algo.upper()}"
                    f"\n          Decoded type   {cls['type'].upper()}"
                    f"\n          Decoded size   {len(decoded)} bytes"
                )
                if cls['ioc_strings']:
                    detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:3])}"
        severity = (RED("SUSPICIOUS — PE or shellcode in compressed data")
                    if any(h[3]['is_pe'] or h[3]['is_shellcode'] for h in cmp_unique)
                    else YELLOW("NOTABLE — compressed data blobs in memory"))
        _print_check("Compressed data (GZIP/ZLIB)", severity, detail)
        findings['compressed'] = cmp_unique
        findings['score'] += 1
    else:
        _print_check("Compressed data (GZIP/ZLIB)",
                     GREEN("CLEAN — no compressed payloads found"))

    # ── PE re-check ───────────────────────────────────────────────────────
    all_pe_hits = findings['hidden_pe'] + pe_hits
    if all_pe_hits:
        detail = f"{len(all_pe_hits)} PE payload(s) found inside encoded/compressed data"
        for enc, r, off, decoded in all_pe_hits:
            abs_va = r.BaseAddress + off
            known  = addr_to_module(abs_va, modules)
            reg_str = "registered" if known else RED("UNREGISTERED — hidden PE")
            detail += (
                f"\n          Encoding       {enc.upper()}"
                f"\n          Container VA   0x{abs_va:016x}"
                f"\n          Module status  {reg_str}"
                f"\n          Decoded PE     {len(decoded)} bytes"
                f"\n          PE header      {decoded[:8].hex()}"
            )
        _print_check("PE payloads inside encoded data",
                     RED("SUSPICIOUS — executable payload concealed by encoding"),
                     detail)
        findings['hidden_pe'] = all_pe_hits
        findings['score'] += 1

    # ── Verdict ───────────────────────────────────────────────────────────
    score  = findings['score']
    # Every layer has its own size/type filters (SLEEP_MASK_REGION_MAX,
    # ENTROPY_SCAN_MAX, DECODE_SCAN_MAX) — regions can exist (mem_info
    # available) while every single one gets filtered out by every layer
    # (e.g. a dump with only huge regions), meaning nothing was actually
    # read despite MemoryInfoListStream being present. A negative result
    # in that case is not the same claim as "scanned and clean". This must
    # catch partial gaps too, not just the all-skipped extreme: one region
    # scanned fine and a second one skipped/unreadable is still an
    # incomplete scope, even though *something* got scanned.
    any_region_scanned = bool(sleep_mask_scanned or entropy_scanned or decode_scanned)
    fully_skipped = mem_info_available and bool(regions) and not any_region_scanned
    total_size_skipped = sleep_mask_size_skipped + entropy_size_skipped + decode_size_skipped
    total_read_failed  = sleep_mask_read_failed + entropy_read_failed + decode_read_failed
    budget_exhausted = decode_budget.exhausted()
    findings['budget_exhausted'] = budget_exhausted
    coverage_gap = bool(total_size_skipped or total_read_failed or budget_exhausted)

    if not mem_info_available:
        status = NOT_EVALUATED
    elif fully_skipped or (score == 0 and coverage_gap):
        status = INCONCLUSIVE
    else:
        status = DETECTED if score > 0 else NOT_DETECTED_IN_SCANNED_SCOPE
    findings['status'] = status

    if not mem_info_available:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream missing from this dump")
    elif fully_skipped:
        verdict = _status_text(INCONCLUSIVE,
            f"all {len(regions)} region(s) filtered out by every layer's size/type limits "
            f"— nothing was actually scanned")
    elif status == INCONCLUSIVE:
        reason = ", ".join(filter(None, [
            f"{total_size_skipped} oversized region(s) skipped" if total_size_skipped else "",
            f"{total_read_failed} region(s) failed to read" if total_read_failed else "",
            f"decode budget exhausted ({decode_budget.exhausted_reason})" if budget_exhausted else "",
        ]))
        verdict = _status_text(INCONCLUSIVE, reason)
    else:
        verdict = (RED("HIGH CONFIDENCE — active payload obfuscation")    if score >= 3 else
                   YELLOW("LIKELY — encoding/obfuscation present")        if score >= 2 else
                   YELLOW("POSSIBLE — one obfuscation indicator")         if score == 1 else
                   GREEN("CLEAN — no encoding or obfuscation detected"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/6 checks flagged)\n")

    if not verbose and any([sleep_mask_hits, b64_unique, xor_unique,
                            cmp_unique, entropy_hits]):
        print(DIM("  Use --verbose to expand region addresses, decoded content, and IOC strings.\n"))

    return findings
