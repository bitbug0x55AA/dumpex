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
import zlib
import struct
import os
from collections import Counter
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors   import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.core.memory import (
    get_modules, get_memory_regions, addr_to_module,
    va_to_file_offset, prot_str, read_region, _extract_strings_from_data,
)
from dumpex.hunt._ui    import _print_hunt_header, _print_check
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

# ── Sleep Mask tunables (mirroring cs-analyze-processdump.py defaults) ────
SLEEP_MASK_KEY_SIZE        = 13        # XOR key length used by default CS sleep mask
SLEEP_MASK_MIN_REPEAT      = 100       # key must repeat ≥ N times to be a candidate
SLEEP_MASK_MAX_BYTE_FREQ   = 3         # reject if any single byte appears ≥ N times
                                        # in the candidate key (monotonic key filter)
SLEEP_MASK_MIN_ACBD        = 20.0      # min average consecutive byte difference
                                        # (rejects keys like 01 02 03 … or 00 00 00)
SLEEP_MASK_MAX_CANDIDATES  = 10        # max candidates to try per region
SLEEP_MASK_REGION_MAX      = 10 * 1024 * 1024   # skip regions > 10 MB
SLEEP_MASK_VALIDATION_MARKER = b'sha256\x00'    # always present in beacon memory


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
    """
    rotated = key[offset:] + key[:offset]
    klen = len(rotated)
    return bytes(data[i] ^ rotated[i % klen] for i in range(len(data)))


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
                            max_candidates: int = SLEEP_MASK_MAX_CANDIDATES) -> list:
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

    Returns list of (key_bytes, occurrence_count).
    """
    key_counts: dict = {}
    for offset in range(key_size):
        pos = 0
        while pos + offset + key_size <= len(data):
            window = data[pos + offset: pos + offset + key_size]
            key_counts[window] = key_counts.get(window, 0) + 1
            pos += key_size

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

    Returns list of (key_bytes, offset, decoded_bytes) for confirmed hits.
    """
    confirmed = []
    for key, _count in candidates:
        for offset in range(key_size):
            decoded = _sm_xor(data, key, offset)
            if SLEEP_MASK_VALIDATION_MARKER in decoded:
                confirmed.append((key, offset, decoded))
                break   # one confirmed decode per key is sufficient
    return confirmed


def _scan_sleep_mask(regions, modules, mf) -> list:
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

    Returns list of:
        {
          'region'  : MinidumpMemoryInfo,
          'key'     : bytes,          # recovered XOR key
          'offset'  : int,            # key rotation offset that decoded correctly
          'decoded' : bytes,          # fully decoded region content
          'cls'     : dict,           # _classify_decoded() result
        }
    """
    hits = []
    for r in regions:
        if prot_str(r.State)   != 'MEM_COMMIT':
            continue
        if prot_str(r.Type)    != 'MEM_PRIVATE':
            continue
        if prot_str(r.Protect) != 'PAGE_READWRITE':
            continue
        if r.RegionSize > SLEEP_MASK_REGION_MAX:
            continue
        if r.RegionSize < SLEEP_MASK_KEY_SIZE * SLEEP_MASK_MIN_REPEAT:
            continue   # region too small to ever contain enough key repetitions
        if addr_to_module(r.BaseAddress, modules):
            continue   # module-backed region — not the beacon's private heap

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

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

    return hits


# ══════════════════════════════════════════════════════════════════════════
# LAYER 1 — Shannon entropy
# ══════════════════════════════════════════════════════════════════════════

def _scan_entropy(regions, modules, mf):
    hits = []
    for r in regions:
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) != 'MEM_PRIVATE':
            continue
        if r.RegionSize > ENTROPY_SCAN_MAX:
            continue
        if addr_to_module(r.BaseAddress, modules):
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue
        if len(data) < 256:
            continue

        ent = _shannon_entropy(data)
        p      = prot_str(r.Protect)
        is_rwx = any(s in p for s in SUSPICIOUS_PROTS)
        threshold = ENTROPY_RWX_THRESHOLD if is_rwx else ENTROPY_PRIVATE_THRESHOLD

        if ent >= threshold:
            hits.append((r, ent, threshold))
    return hits


# ══════════════════════════════════════════════════════════════════════════
# LAYER 2 — Base64
# ══════════════════════════════════════════════════════════════════════════

def _scan_base64(data: bytes, region_base: int):
    for m in _B64_PAT.finditer(data):
        raw = m.group(0)
        if len(raw) < B64_MIN_LEN:
            continue
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
        cls = _classify_decoded(decoded)
        if cls['type'] == 'binary' and not cls['ioc_strings']:
            continue
        yield m.start(), raw, decoded, cls


# ══════════════════════════════════════════════════════════════════════════
# LAYER 3 — Single-byte XOR brute-force
# ══════════════════════════════════════════════════════════════════════════

def _score_xor_key(data: bytes, key: int) -> float:
    decoded  = bytes(b ^ key for b in data)
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(decoded)


def _scan_xor(data: bytes, region_base: int):
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
        decoded = bytes(b ^ key for b in data)
        cls = _classify_decoded(decoded)
        if cls['is_pe'] or cls['is_shellcode'] or cls['ioc_strings']:
            yield key, decoded, cls


# ══════════════════════════════════════════════════════════════════════════
# LAYER 4 — GZIP / ZLIB
# ══════════════════════════════════════════════════════════════════════════

def _scan_compressed(data: bytes, region_base: int):
    start = 0
    while True:
        idx = data.find(_GZIP_SIG, start)
        if idx == -1:
            break
        try:
            decoded = zlib.decompress(data[idx:], wbits=47)
            if len(decoded) >= 64:
                yield idx, 'gzip', decoded, _classify_decoded(decoded)
        except Exception:
            pass
        start = idx + 1

    for sig in _ZLIB_SIGS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            try:
                decoded = zlib.decompress(data[idx:])
                if len(decoded) >= 64:
                    yield idx, 'zlib', decoded, _classify_decoded(decoded)
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
    sleep_mask_hits = _scan_sleep_mask(regions, modules, mf)

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
    entropy_hits = _scan_entropy(regions, modules, mf)

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

    for r in regions:
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) not in ('MEM_PRIVATE', 'MEM_IMAGE'):
            continue
        if r.RegionSize > DECODE_SCAN_MAX:
            continue
        mod = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == 'MEM_IMAGE' and _is_system_dll(mod):
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        for off, raw, decoded, cls in _scan_base64(data, r.BaseAddress):
            b64_hits.append((r, off, cls, raw, decoded))
            if cls['is_pe']:
                pe_hits.append(('base64', r, off, decoded))

        if (prot_str(r.Type) == 'MEM_PRIVATE' and r.RegionSize <= XOR_SCAN_MAX):
            for key, decoded, cls in _scan_xor(data, r.BaseAddress):
                xor_hits.append((r, key, cls, decoded))
                if cls['is_pe']:
                    pe_hits.append(('xor', r, 0, decoded))

        for off, algo, decoded, cls in _scan_compressed(data, r.BaseAddress):
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
    score   = findings['score']
    verdict = (RED("HIGH CONFIDENCE — active payload obfuscation")    if score >= 3 else
               YELLOW("LIKELY — encoding/obfuscation present")        if score >= 2 else
               YELLOW("POSSIBLE — one obfuscation indicator")         if score == 1 else
               GREEN("CLEAN — no encoding or obfuscation detected"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/6 checks flagged)\n")

    if not verbose and any([sleep_mask_hits, b64_unique, xor_unique,
                            cmp_unique, entropy_hits]):
        print(DIM("  Use --verbose to expand region addresses, decoded content, and IOC strings.\n"))

    return findings
