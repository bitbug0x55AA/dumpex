"""
Encoded / obfuscated payload hunter.

Detection layers (applied per memory region):

  1. Shannon entropy scan  — catches all encoding schemes including custom
                             crypto, RC4, AES blobs, multi-byte XOR, etc.
  2. Base64 detection      — standard + URL-safe; minimum 48 chars (36 decoded bytes)
  3. XOR single-byte BF    — MEM_PRIVATE regions ≤ 512 KB only; sample-first
                             heuristic to avoid O(n×255) full-region cost
  4. GZIP / ZLIB           — magic-byte scan + decompress attempt

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
DECODE_SCAN_MAX           =  2 * 1024 * 1024   # Base64 / XOR / GZIP: skip regions > 2 MB
                                                # keeps per-region regex cost manageable
XOR_SCAN_MAX              = 512 * 1024         # max region for XOR brute-force
XOR_SAMPLE_SIZE           = 4096               # bytes sampled before full decode
XOR_SCORE_MIN             = 0.68               # printable ratio to accept a key
B64_MIN_LEN               = 80                 # minimum Base64 string length


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
    """
    Return True if the IP string looks like a real C2 address.
    Filters out:
      - IPs where every octet is a single digit (< 10) — version numbers,
        sequential patterns like 9.8.6.9 / 1.2.3.4 match the regex but are
        almost never real C2 addresses
      - Private / loopback / link-local / reserved ranges
      - Out-of-range octets
    """
    host = ip_str.split(':')[0]   # strip port if present
    parts = host.split('.')
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    # All single-digit octets → version number / coord pattern, not a real IP
    if all(o < 10 for o in octets):
        return False
    # Loopback / unspecified
    if octets[0] in (0, 127):
        return False
    # Link-local (169.254.x.x)
    if octets[0] == 169 and octets[1] == 254:
        return False
    # RFC 1918 private ranges
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

_GZIP_SIG = b'\x1f\x8b'
_ZLIB_SIGS = (b'\x78\x9c', b'\x78\xda', b'\x78\x01', b'\x78\x5e')


# ── Core helpers ──────────────────────────────────────────────────────────

def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _classify_decoded(data: bytes) -> dict:
    """
    Classify decoded / decompressed bytes.

    Returns:
        type        : 'pe' | 'shellcode' | 'ioc_text' | 'high_entropy' | 'binary'
        is_pe       : bool
        is_shellcode: bool
        ioc_strings : list[str]
        hex_prefix  : str  (first 16 bytes hex)
        entropy     : float
    """
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

    # PE check
    if data[:2] == b'MZ':
        pe_offset = struct.unpack_from('<I', data, 0x3c)[0] if len(data) > 0x40 else 0
        if pe_offset and pe_offset + 4 <= len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
            result.update({'type': 'pe', 'is_pe': True})
            return result

    # Shellcode bootstrap: call $+5 / pop r*
    if data[:6] in (b'\xe8\x00\x00\x00\x00\x58',   # call+pop rax
                    b'\xe8\x00\x00\x00\x00\x59',   # call+pop rcx
                    b'\xe8\x00\x00\x00\x00\x5b',   # call+pop rbx
                    b'\xe8\x00\x00\x00\x00\x5e'):  # call+pop rsi
        result.update({'type': 'shellcode', 'is_shellcode': True})
        return result

    # Printable / text check
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

    # High-entropy binary (likely still encrypted)
    if result['entropy'] > 7.2:
        result['type'] = 'high_entropy'

    return result


# ── Layer 1: Entropy ──────────────────────────────────────────────────────

def _scan_entropy(regions, modules, mf):
    """Return list of (region, entropy, threshold_used) for suspicious regions."""
    hits = []
    for r in regions:
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) != 'MEM_PRIVATE':
            continue
        if r.RegionSize > ENTROPY_SCAN_MAX:
            continue
        # Skip regions backed by known modules
        if addr_to_module(r.BaseAddress, modules):
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue
        if len(data) < 256:
            continue

        ent = _shannon_entropy(data)
        p   = prot_str(r.Protect)
        is_rwx = any(s in p for s in SUSPICIOUS_PROTS)
        threshold = ENTROPY_RWX_THRESHOLD if is_rwx else ENTROPY_PRIVATE_THRESHOLD

        if ent >= threshold:
            hits.append((r, ent, threshold))
    return hits


# ── Layer 2: Base64 ───────────────────────────────────────────────────────

def _scan_base64(data: bytes, region_base: int):
    """Yield (offset, b64_bytes, decoded_bytes, classification)."""
    for m in _B64_PAT.finditer(data):
        raw = m.group(0)
        if len(raw) < B64_MIN_LEN:
            continue
        try:
            # Normalise URL-safe alphabet
            normalised = raw.replace(b'-', b'+').replace(b'_', b'/')
            # Pad if needed
            pad = len(normalised) % 4
            if pad:
                normalised += b'=' * (4 - pad)
            decoded = __import__('base64').b64decode(normalised)
        except Exception:
            continue
        if len(decoded) < 16:
            continue
        # Skip decoded content that is purely binary with no IOC strings —
        # short random data commonly matches the Base64 alphabet by chance
        cls = _classify_decoded(decoded)
        if cls['type'] == 'binary' and not cls['ioc_strings']:
            continue
        yield m.start(), raw, decoded, cls


# ── Layer 3: XOR single-byte brute-force ─────────────────────────────────

def _score_xor_key(data: bytes, key: int) -> float:
    """Return printable-ratio for data XOR'd with key (fast sample scoring)."""
    decoded = bytes(b ^ key for b in data)
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(decoded)


def _scan_xor(data: bytes, region_base: int):
    """
    Brute-force single-byte XOR on a sample, then full-decode candidates.
    Yields (key, decoded_bytes, classification).
    """
    sample = data[:XOR_SAMPLE_SIZE]
    candidates = []
    for key in range(1, 256):
        score = _score_xor_key(sample, key)
        if score >= XOR_SCORE_MIN:
            # Secondary filter: decoded sample must contain ≥1 IOC keyword
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
        # Only yield if there is something actionable: PE, shellcode, or IOC strings
        # PLAINTEXT without IOC strings is almost always noise from low-entropy regions
        if cls['is_pe'] or cls['is_shellcode'] or cls['ioc_strings']:
            yield key, decoded, cls


# ── Layer 4: GZIP / ZLIB ─────────────────────────────────────────────────

def _scan_compressed(data: bytes, region_base: int):
    """Yield (offset, algo, decoded_bytes, classification)."""
    # GZIP
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

    # ZLIB
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


# ── Main hunter ───────────────────────────────────────────────────────────

def _hunt_encoding(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan process memory for encoded / obfuscated payloads.

    Runs four detection layers in sequence; decoded content from all layers
    is passed through a shared classifier. PE payloads trigger a re-check
    against the module list (same logic as _hunt_injection hidden-PE check).
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)

    findings = {
        'entropy':    [],   # (region, entropy, threshold)
        'base64':     [],   # (region, offset, cls)
        'xor':        [],   # (region, key, cls)
        'compressed': [],   # (region, offset, algo, cls)
        'hidden_pe':  [],   # re-detected PE payloads
        'score': 0,
    }

    _print_hunt_header("Obfuscation Detection")

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
        # Size gate: entropy scan handles large regions; decode scan is capped at 2 MB
        # to keep Base64 regex cost manageable across hundreds of segments
        if r.RegionSize > DECODE_SCAN_MAX:
            continue
        # Skip system DLLs for decode layers — they legitimately contain dense
        # binary data and Base64 strings (certs, resources) that are not payloads
        mod = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == 'MEM_IMAGE' and _is_system_dll(mod):
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        # ── Base64 ────────────────────────────────────────────────────────
        for off, raw, decoded, cls in _scan_base64(data, r.BaseAddress):
            hit = (r, off, cls, raw, decoded)
            b64_hits.append(hit)
            if cls['is_pe']:
                pe_hits.append(('base64', r, off, decoded))

        # ── XOR (MEM_PRIVATE ≤ 512 KB only) ──────────────────────────────
        if (prot_str(r.Type) == 'MEM_PRIVATE'
                and r.RegionSize <= XOR_SCAN_MAX):
            for key, decoded, cls in _scan_xor(data, r.BaseAddress):
                hit = (r, key, cls, decoded)
                xor_hits.append(hit)
                if cls['is_pe']:
                    pe_hits.append(('xor', r, 0, decoded))

        # ── GZIP / ZLIB ───────────────────────────────────────────────────
        for off, algo, decoded, cls in _scan_compressed(data, r.BaseAddress):
            hit = (r, off, algo, cls, decoded)
            cmp_hits.append(hit)
            if cls['is_pe']:
                pe_hits.append((algo, r, off, decoded))

    # ── Report Base64 ─────────────────────────────────────────────────────
    # Deduplicate by region base
    seen_b64 = set()
    b64_unique = []
    for item in b64_hits:
        r = item[0]
        if r.BaseAddress not in seen_b64:
            seen_b64.add(r.BaseAddress)
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
        r = item[0]
        if r.BaseAddress not in seen_xor:
            seen_xor.add(r.BaseAddress)
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
        r = item[0]
        if r.BaseAddress not in seen_cmp:
            seen_cmp.add(r.BaseAddress)
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
    if pe_hits:
        detail = f"{len(pe_hits)} PE payload(s) found inside encoded/compressed data"
        for enc, r, off, decoded in pe_hits:
            abs_va = r.BaseAddress + off
            # Check if this VA is already in module list
            known = addr_to_module(abs_va, modules)
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
        findings['hidden_pe'] = pe_hits
        findings['score'] += 1

    # ── Verdict ───────────────────────────────────────────────────────────
    score   = findings['score']
    verdict = (RED("HIGH CONFIDENCE — active payload obfuscation")    if score >= 3 else
               YELLOW("LIKELY — encoding/obfuscation present")        if score >= 2 else
               YELLOW("POSSIBLE — one obfuscation indicator")         if score == 1 else
               GREEN("CLEAN — no encoding or obfuscation detected"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/5 checks flagged)\n")

    if not verbose and (b64_unique or xor_unique or cmp_unique or entropy_hits):
        print(DIM("  Use --verbose to expand region addresses, decoded content, and IOC strings.\n"))

    return findings
