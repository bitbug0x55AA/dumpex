"""Cobalt Strike beacon config scanner (adapted from 1768.py by Didier Stevens).

Phase-three detection model
────────────────────────────
Brought onto the same evidence semantics as the phase-two hunters
(injection/stomping/pipe/obfuscation): explicit score/max_score/status/
verdict_level/confidence/coverage_status/coverage_reasons/findings,
instead of the config-count-as-score model this hunter used previously.
The `configs` field (per-hit raw data: VA, file offset, region, XOR key,
version estimate, parsed TLV fields) is kept as-is for existing
consumers — everything below is additive.

  score 0 — no structurally-valid (sanity-checked TLV, known BeaconType,
            ASN.1-shaped public key) config found in what was scanned.
  score 1 — at least one structurally-valid config found, with no
            independent memory-context corroboration. Finding MORE
            configs (even at distinct addresses) does NOT raise this —
            config count is a fact reported alongside the finding, not a
            confidence input. A beacon config surviving in memory is
            itself strong, hard-to-fake evidence (the TLV structure,
            field types, and a plausible ASN.1 public key all having to
            line up by chance is vanishingly unlikely) — this is why
            score 1 already maps to "likely", not "possible".
  score 2 — additionally corroborated by memory context independent of
            the config bytes themselves: either the enclosing region is
            executable, private memory (not an inert data-only mapping),
            or a thread's CURRENT RIP/EIP executes somewhere within the
            same allocation as the config hit — i.e. this isn't just an
            orphaned copy sitting in unused/freed memory.

Deliberately NOT reported: a DORMANT/INITIALIZED/LIVE activity label.
A decoded config proves a beacon payload exists (or existed) in this
process's memory — it says nothing about whether it is CURRENTLY
maintaining network callbacks at dump time, and claiming otherwise from
static memory content alone would be exactly the kind of over-attribution
this schema exists to avoid. CS version is an ESTIMATE from the highest
recognized field ID (see _cs_guess_version) and is reported as such, not
as a fingerprinted/confirmed build.
"""
import os
import struct
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.core.memory import (va_to_file_offset, get_memory_regions, _get_region_at,
    get_thread_contexts, prot_str)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._coverage import derive_status, derive_coverage_status, CoverageTracker
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_DETECTION, overall_confidence, verdict_level)

CS_BEACON_SIGNATURE  = b'\x00\x01\x00\x01\x00\x02'   # plaintext TLV start
CS_SIG_XOR69         = b'ihihik'                       # above ^ 0x69
CS_SIG_XOR2E         = b'././.,'                       # above ^ 0x2e
CS_MAX_SEG_SCAN      = 50 * 1024 * 1024               # skip segments > 50 MB

# Total resource budget for the WHOLE scan (across every segment), not a
# per-segment limit — a dump stuffed with thousands of decoy/duplicate
# markers (deliberately or by coincidence) must not be able to make this
# hunter run unbounded time/memory. When any cap is hit, the scan stops
# and the result is reported as coverage-partial rather than silently
# treating the unscanned remainder as "checked, nothing there".
CS_CONFIG_DECODE_MAX = 8192          # bytes decoded per candidate (real CS
                                       # configs are a few KB at most; only
                                       # decoding this much instead of a
                                       # fixed 64 KB avoids retaining a huge
                                       # buffer for markers that are never a
                                       # real config)
CS_MAX_CANDIDATES     = 20000        # marker matches examined, whole scan
CS_MAX_DECODED_BYTES  = 64 * 1024 * 1024   # total bytes XOR-decoded, whole scan
CS_MAX_HITS           = 100          # stop once this many configs are found
CS_SCAN_DEADLINE_SECONDS = 60         # wall-clock budget for the whole scan

# Field IDs from 1768.py dConfigIdentifiers
CS_FIELD_NAMES = {
    0x0001: 'BeaconType',
    0x0002: 'Port',
    0x0003: 'SleepTime',
    0x0004: 'MaxGetSize',
    0x0005: 'Jitter',
    0x0006: 'MaxDNS',
    0x0007: 'PublicKey',
    0x0008: 'C2Server',
    0x0009: 'UserAgent',
    0x000a: 'HTTP_PostURI',
    0x000b: 'MalleableC2',
    0x000c: 'HTTP_GetHeader',
    0x000d: 'HTTP_PostHeader',
    0x000e: 'SpawnTo',
    0x000f: 'PipeName',
    0x0010: 'KillDate_Year',
    0x0011: 'KillDate_Month',
    0x0012: 'KillDate_Day',
    0x0013: 'DNS_Idle',
    0x0014: 'DNS_Sleep',
    0x0015: 'SSH_Host',
    0x0016: 'SSH_Port',
    0x0017: 'SSH_Username',
    0x0018: 'SSH_Password',
    0x0019: 'SSH_PubKey',
    0x001a: 'HTTP_GetVerb',
    0x001b: 'HTTP_PostVerb',
    0x001c: 'HttpPostChunk',
    0x001d: 'SpawnTo_x86',
    0x001e: 'SpawnTo_x64',
    0x001f: 'CryptoScheme',
    0x0020: 'Proxy',
    0x0021: 'Proxy_Username',
    0x0022: 'Proxy_Password',
    0x0023: 'Proxy_Type',
    0x0025: 'LicenseID',
    0x0026: 'bStageCleanup',
    0x0027: 'bCFGCaution',
    0x0028: 'KillDate',
    0x002b: 'ProcInject_StartRWX',
    0x002c: 'ProcInject_UseRWX',
    0x002d: 'ProcInject_MinAlloc',
    0x002e: 'ProcInject_Transform_x86',
    0x002f: 'ProcInject_Transform_x64',
    0x0031: 'BindHost',
    0x0032: 'UsesCookies',
    0x0033: 'ProcInject_Execute',
    0x0034: 'ProcInject_AllocMethod',
    0x0035: 'ProcInject_Stub',
    0x0036: 'HostHeader',
    0x0037: 'EXIT_FUNK',
    0x0038: 'SSH_Banner',
    0x0039: 'SMB_FrameHeader',
    0x003a: 'TCP_FrameHeader',
    0x003b: 'HeadersToRemove',
    0x003c: 'DNS_Beacon',
    0x003d: 'DNS_A',
    0x003e: 'DNS_AAAA',
    0x003f: 'DNS_TXT',
    0x0040: 'DNS_Metadata',
    0x0041: 'DNS_Output',
    0x0042: 'DNS_Resolver',
    0x0043: 'DNS_Strategy',
    0x0044: 'DNS_StrategyRotateSecs',
    0x0045: 'DNS_StrategyFailX',
    0x0046: 'DNS_StrategyFailSecs',
    0x0047: 'MaxRetry_Attempts',
    0x0048: 'MaxRetry_Increase',
    0x0049: 'MaxRetry_Duration',
}

# From 1768.py LookupConfigValue
CS_BEACON_TYPES = {
    0:  'HTTP',
    1:  'DNS',
    2:  'SMB (bind pipe)',
    4:  'TCP (reverse)',
    8:  'HTTPS',
    16: 'TCP (bind)',
}
CS_PROXY_TYPES = {
    1: 'no proxy',
    2: 'IE settings',
    4: 'hardcoded proxy',
}
CS_INJECT_PERMS = {
    0x01: 'PAGE_NOACCESS',      0x02: 'PAGE_READONLY',
    0x04: 'PAGE_READWRITE',     0x08: 'PAGE_WRITECOPY',
    0x10: 'PAGE_EXECUTE',       0x20: 'PAGE_EXECUTE_READ',
    0x40: 'PAGE_EXECUTE_READWRITE',
    0x80: 'PAGE_EXECUTE_WRITECOPY',
}

# score -> verdict_level, owned by this hunter (see _finding.verdict_level).
# A structurally-valid config (score 1) already reflects strong evidence —
# see the module docstring — so it maps to "likely", not "possible".
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}

# Independent memory-context corroboration for a config hit (score 1 -> 2):
# a config's own bytes are inert DATA, so a beacon that is actually loaded
# and running typically has the config sitting in a private allocation
# that ALSO carries executable memory (the decrypted/decompressed payload)
# — as opposed to a bare, isolated copy of just the config bytes.
CS_SUSPICIOUS_PRIVATE_PROTECTIONS = frozenset({
    'PAGE_EXECUTE_READWRITE', 'PAGE_EXECUTE_READ', 'PAGE_EXECUTE',
    'PAGE_EXECUTE_WRITECOPY',
})


def _cs_xor_bytes(data: bytes, key: int) -> bytes:
    """Single-byte XOR decode. Mirrors 1768.py Xor() for single-byte keys."""
    kb = key & 0xff
    return bytes(b ^ kb for b in data)


def _cs_scan_segment(data: bytes, seg_va: int, seg_fo: int):
    """
    Locate candidate CS beacon config markers in one memory segment.

    Strategy (from 1768.py AnalyzeEmbeddedPEFileSub): for each XOR key
    (0x69, 0x2e), search for the pre-XOR'd marker bytes.

    A generator, not a list: a segment stuffed with thousands of decoy or
    duplicate marker bytes must not force building (and holding) one giant
    candidate list before the caller gets a chance to enforce the global
    scan budget (CS_MAX_CANDIDATES / CS_SCAN_DEADLINE_SECONDS below) — the
    caller can stop pulling from this generator the moment a cap is hit.

    Decoding is deliberately NOT done here — see _cs_decode_and_parse_tlv,
    which decodes only as many bytes as a candidate's TLV structure
    actually needs instead of eagerly XOR-decoding (and retaining) a large
    fixed window for every marker match, most of which are never a real
    config.

    Yields (xor_key, offset_in_data, hit_va, hit_file_offset).
    """
    for key, marker in ((0x69, CS_SIG_XOR69), (0x2e, CS_SIG_XOR2E)):
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            yield key, idx, seg_va + idx, seg_fo + idx
            start = idx + 1


def _cs_decode_and_parse_tlv(data: bytes, offset: int, key: int, max_len: int) -> dict:
    """
    XOR-decode and TLV-parse a CS beacon config candidate in-place,
    decoding only as many bytes as are actually needed field-by-field (up
    to `max_len`) instead of eagerly XOR-decoding a large fixed window
    up front (adapted from 1768.py AnalyzeEmbeddedPEFileSub2/
    SanityCheckExtractedConfig).

    Wire format (all big-endian), decoded plaintext:
        field_id  uint16    (0 = end of config)
        type      uint16    (1=uint16, 2=uint32, 3=bytes)
        length    uint16
        value     <length> bytes

    Returns {fields, complete, reason, consumed}:
      fields   -- field_id (int) -> {name, type, raw, value}, whatever was
                  parsed even if parsing stopped early.
      complete -- True ONLY if a legitimate fid=0 terminator was reached
                  with no truncation, no duplicate field ID, and no
                  illegal field type along the way. A blob that merely
                  "looks like fields" but never properly terminates is
                  NOT a legitimate config — it must not pass the sanity
                  check downstream.
      reason   -- short string explaining why complete is False, else None.
      consumed -- plaintext bytes consumed from `offset`, up to and
                  including the fid=0 terminator when complete, else up
                  to the point parsing stopped (used by the caller to
                  track the total-decoded-bytes budget).
    """
    kb = key & 0xff
    fields = {}
    pos = offset
    limit = min(offset + max_len, len(data))
    valid_types = (1, 2, 3)

    if pos + len(CS_BEACON_SIGNATURE) > limit:
        return {'fields': fields, 'complete': False,
                'reason': 'buffer too small for signature', 'consumed': 0}
    signature = bytes(b ^ kb for b in data[pos: pos + len(CS_BEACON_SIGNATURE)])
    if signature != CS_BEACON_SIGNATURE:
        return {'fields': fields, 'complete': False,
                'reason': 'plaintext signature mismatch', 'consumed': 0}

    while True:
        if pos + 6 > limit:
            return {'fields': fields, 'complete': False,
                    'reason': 'truncated before fid=0 terminator (ran out of '
                              'decode budget)',
                    'consumed': pos - offset}
        header = bytes(b ^ kb for b in data[pos: pos + 6])
        fid, ftype, flen = struct.unpack('>HHH', header)
        if fid == 0:
            return {'fields': fields, 'complete': True, 'reason': None,
                    'consumed': pos + 2 - offset}
        if ftype not in valid_types:
            return {'fields': fields, 'complete': False,
                    'reason': f'illegal field type 0x{ftype:04x} for field 0x{fid:04x}',
                    'consumed': pos - offset}
        if pos + 6 + flen > limit:
            return {'fields': fields, 'complete': False,
                    'reason': f'field 0x{fid:04x} declares length {flen} past '
                              f'end of decode budget',
                    'consumed': pos - offset}
        if fid in fields:
            return {'fields': fields, 'complete': False,
                    'reason': f'duplicate field id 0x{fid:04x}',
                    'consumed': pos - offset}
        raw = bytes(b ^ kb for b in data[pos + 6: pos + 6 + flen])

        value = None
        try:
            if ftype == 1 and flen == 2:
                value = struct.unpack('>H', raw)[0]
            elif ftype == 2 and flen == 4:
                value = struct.unpack('>I', raw)[0]
            elif ftype == 3:
                stripped = raw.rstrip(b'\x00')
                # Attempt clean UTF-8 decode; if the result contains non-printable
                # characters (common for inject payloads, transforms, stubs, etc.)
                # display as hex instead of mangled replacement characters.
                try:
                    candidate = stripped.decode('utf-8')
                    is_printable = all(
                        c.isprintable() or c in '\t\r\n' for c in candidate
                    )
                    value = candidate if is_printable else stripped.hex()
                except UnicodeDecodeError:
                    value = stripped.hex()
        except Exception:
            value = raw

        fields[fid] = {
            'name':  CS_FIELD_NAMES.get(fid, f'field_0x{fid:04x}'),
            'type':  ftype,
            'raw':   raw,
            'value': value,
        }
        pos += 6 + flen


def _cs_decode_instructions(raw: bytes, itype: int) -> list:
    """
    Decode a Malleable C2 instruction stream (adapted from 1768.py DecodeInstructions).

    itype: 1 = server→client (MalleableC2 field 0x000b)
           2 = GET  header transforms (field 0x000c)
           3 = POST header transforms (field 0x000d)

    Opcode semantics differ between itype==1 and itype==2/3:
      opcodes 1 & 2 carry an integer operand (remove N bytes) in itype==1,
      but a length-prefixed string operand (append/prepend data) in itype==2/3.
    """
    def _rint(buf, p):
        if p + 4 > len(buf): return None, p
        return struct.unpack_from('>I', buf, p)[0], p + 4

    def _rstr(buf, p):
        n, p = _rint(buf, p)
        if n is None or p + n > len(buf): return None, p
        return buf[p: p + n].decode('latin-1', errors='replace'), p + n

    MALLEABLE = 1
    instrs, pos = [], 0
    while pos + 4 <= len(raw):
        op = struct.unpack_from('>I', raw, pos)[0]; pos += 4
        if op == 0:   break
        if op == 1:   # APPEND / remove-from-end
            if itype == MALLEABLE:
                n, pos = _rint(raw, pos); instrs.append(f'Remove {n} bytes from end')
            else:
                s, pos = _rstr(raw, pos); instrs.append(f'Append {repr(s)}')
        elif op == 2: # PREPEND / remove-from-begin
            if itype == MALLEABLE:
                n, pos = _rint(raw, pos); instrs.append(f'Remove {n} bytes from begin')
            else:
                s, pos = _rstr(raw, pos); instrs.append(f'Prepend {repr(s)}')
        elif op == 3:  instrs.append('BASE64')
        elif op == 4:  instrs.append('Print')
        elif op == 5:  s, pos = _rstr(raw, pos); instrs.append(f'Parameter {repr(s)}')
        elif op == 6:  s, pos = _rstr(raw, pos); instrs.append(f'Header {repr(s)}')
        elif op == 7:  # BUILD
            n, pos = _rint(raw, pos)
            label = {0: 'SessionId', 1: 'Output'}.get(n, 'Metadata') if itype == 3 else 'Metadata'
            instrs.append(f'Build {label}')
        elif op == 8:  instrs.append('NETBIOS lowercase')
        elif op == 9:  s, pos = _rstr(raw, pos); instrs.append(f'Const_parameter {repr(s)}')
        elif op == 10: s, pos = _rstr(raw, pos); instrs.append(f'Const_header {repr(s)}')
        elif op == 11: instrs.append('NETBIOS uppercase')
        elif op == 12: instrs.append('Uri_append')
        elif op == 13: instrs.append('BASE64 URL')
        elif op == 14:
            s1, pos = _rstr(raw, pos); s2, pos = _rstr(raw, pos)
            instrs.append(f'STRREP {repr(s1)} -> {repr(s2)}')
        elif op == 15: instrs.append('XOR with 4-byte random key (mask)')
        elif op == 16: s, pos = _rstr(raw, pos); instrs.append(f'Const_host_header {repr(s)}')
        else:          instrs.append(f'Unknown(0x{op:02x})')
    return instrs


def _cs_guess_version(fields: dict) -> str:
    """Estimate CS version from highest field ID (mirrors 1768.py DetermineCSVersionFromConfig)."""
    if not fields: return 'unknown'
    m = max(fields.keys())
    if m < 55:  return '3.x'
    if m == 55: return '4.0'
    if m < 58:  return '4.1'
    if m == 58: return '4.2'
    if m == 70: return '4.3'
    return '4.4+'


# DER encoding of the rsaEncryption algorithm OID (1.2.840.113549.1.1.1):
# tag(0x06) + length(0x09) + the 9-byte OID value. Cobalt Strike embeds an
# RSA public key here (SubjectPublicKeyInfo), never any other algorithm.
CS_RSA_ENCRYPTION_OID = bytes.fromhex('06092a864886f70d010101')
CS_PUBLIC_KEY_MIN_LEN = 16   # short-form outer tag+length + minimal AlgorithmIdentifier


def _der_read_length(data: bytes, pos: int) -> "tuple[int, int] | None":
    """
    Read one DER length field (definite form only — BER indefinite-length
    encoding, 0x80, is not valid DER and is rejected) starting at `pos`.
    Returns (length, next_pos) or None if malformed/insufficient bytes.
    """
    if pos >= len(data):
        return None
    first = data[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    n = first & 0x7f
    if n == 0 or pos + 1 + n > len(data):
        return None
    return int.from_bytes(data[pos + 1: pos + 1 + n], 'big'), pos + 1 + n


def _cs_validate_public_key_der(raw: bytes) -> "tuple[bool, str]":
    """
    Validate the PublicKey field (0x0007) as a minimally plausible X.509
    SubjectPublicKeyInfo DER structure:

        SEQUENCE {                        -- SubjectPublicKeyInfo
          SEQUENCE {                      -- AlgorithmIdentifier
            OID  rsaEncryption (1.2.840.113549.1.1.1)
            ...                           -- (params, not checked here)
          }
          ...                             -- subjectPublicKey, not checked
        }

    A prior version only checked that the raw bytes' hex started with
    "308" — three hex nibbles that happen to match ANY DER SEQUENCE
    beginning with a plausible short/long-form length byte, regardless of
    whether the length is internally consistent or the structure has
    anything to do with an RSA key. This checks minimum length, that the
    outer SEQUENCE's declared DER length doesn't exceed the actual buffer,
    and that immediately inside it sits an AlgorithmIdentifier SEQUENCE
    whose OID is exactly rsaEncryption — cheap to spoof entirely, but no
    longer trivially satisfied by 3 fixed nibbles plus arbitrary bytes.

    Returns (valid, reason); reason is a short diagnostic string on
    failure, "" on success.
    """
    if len(raw) < CS_PUBLIC_KEY_MIN_LEN:
        return False, f"PublicKey field too short ({len(raw)} bytes) for a DER SEQUENCE"
    if raw[0] != 0x30:
        return False, "PublicKey field does not start with a DER SEQUENCE tag (0x30)"

    outer = _der_read_length(raw, 1)
    if outer is None:
        return False, "PublicKey field: malformed outer SEQUENCE length"
    outer_len, pos = outer
    if pos + outer_len > len(raw):
        return False, (f"PublicKey field: declared SEQUENCE length {outer_len} exceeds "
                        f"available {len(raw) - pos} byte(s)")

    if pos >= len(raw) or raw[pos] != 0x30:
        return False, "PublicKey field: AlgorithmIdentifier SEQUENCE tag not found"
    inner = _der_read_length(raw, pos + 1)
    if inner is None:
        return False, "PublicKey field: malformed AlgorithmIdentifier length"
    inner_len, alg_pos = inner
    if alg_pos + inner_len > len(raw):
        return False, "PublicKey field: AlgorithmIdentifier length exceeds buffer"

    if raw[alg_pos: alg_pos + len(CS_RSA_ENCRYPTION_OID)] != CS_RSA_ENCRYPTION_OID:
        return False, "PublicKey field: AlgorithmIdentifier OID is not rsaEncryption"

    return True, ""


def _cs_sanity_check(fields: dict) -> bool:
    """
    Validate extracted config (mirrors 1768.py SanityCheckExtractedConfig,
    hardened beyond it — see _cs_validate_public_key_der):
      - field 0x0001 (beacon type) must be present and a known value
      - field 0x0007 (public key) must be a structurally-consistent DER
        SubjectPublicKeyInfo carrying the rsaEncryption OID
    """
    if 0x0001 not in fields or 0x0007 not in fields:
        return False
    if fields[0x0001]['value'] not in CS_BEACON_TYPES:
        return False
    valid, _reason = _cs_validate_public_key_der(fields[0x0007]['raw'])
    return valid


def _cs_context_corroborates(hit_region, regions: list, thread_contexts: list) -> "tuple[bool, list]":
    """
    Independent memory-context corroboration for a single config hit —
    the score 1 -> 2 tier. Returns (corroborated, reasons).

    Two signals, either is sufficient:
      1. The config's enclosing MemoryInfo region is executable, private
         memory — a bare config copy sitting in ordinary (non-executable)
         data memory doesn't get this; a beacon with its payload actually
         mapped alongside its config does.
      2. A thread's CURRENT RIP/EIP (get_thread_contexts — the live
         register state at dump time, not just a thread's start address)
         executes somewhere within the SAME allocation as the hit —
         checked by AllocationBase, not the narrower single MemoryInfo
         sub-region, since one VirtualAlloc can be split into multiple
         sub-regions with different protections (mirrors how
         hunt/injection.py groups RWX+PE hits by allocation).

    hit_region may be None (VA not covered by MemoryInfoListStream) —
    both signals are then unavailable and this returns (False, []).
    """
    if hit_region is None:
        return False, []
    reasons = []
    if (prot_str(hit_region.Type) == 'MEM_PRIVATE'
            and prot_str(hit_region.Protect) in CS_SUSPICIOUS_PRIVATE_PROTECTIONS):
        reasons.append(f"enclosing region 0x{hit_region.BaseAddress:x} is executable, "
                        f"private memory ({prot_str(hit_region.Protect)})")
    alloc_base = hit_region.AllocationBase
    for tc in thread_contexts:
        r = _get_region_at(tc["ip"], regions)
        if r is not None and r.AllocationBase == alloc_base:
            reasons.append(f"thread {tc['ThreadId']} current {tc['ip_reg']}=0x{tc['ip']:x} "
                            f"executes within the same allocation (0x{alloc_base:x})")
            break
    return bool(reasons), reasons


def _hunt_cs_beacon(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan all captured memory segments for Cobalt Strike beacon configurations.

    Algorithm (adapted from 1768.py by Didier Stevens, public domain):
      1. Walk every captured memory segment in the minidump.
      2. Search each segment for the XOR-encoded TLV signature with keys
         0x69 (CS3) and 0x2E (CS4).
      3. On a hit: XOR-decode, parse TLV records, run sanity check.
      4. Extract and display: beacon type, C2 server/port/URI, User-Agent,
         pipe name, license ID, sleep/jitter, SpawnTo, Malleable C2 profile
         transforms, process injection settings, SSH/DNS transport fields.
      5. Report VA (process address) + file offset (.dmp byte position) +
         enclosing memory region (base/size/protection) for each hit,
         consistent with Dumpex address labeling conventions.

    Address note:
      hit VA         = segment.start_virtual_address + offset_within_segment
      hit file offset = segment.start_file_address   + offset_within_segment

      hit VA is a byte-precise address, not a region. Memory64ListStream
      (the segment table this scan walks) and MemoryInfoListStream (the
      VAD-style region table with Protect/State, used by --hunt injection
      for its RWX / hidden-PE region correlation) are independent streams.
      Resolving hit VA -> enclosing region base here is what lets a beacon
      config hit be cross-referenced against injection's region-based
      findings (same region_base means "same memory region").
    """
    _print_hunt_header("Cobalt Strike Beacon Config")
    findings = {'configs': [], 'score': 0, 'max_score': 2}
    findings_list = []   # Finding objects -> findings["findings"]

    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments

    if not segs:
        findings['status'] = NOT_EVALUATED
        findings['coverage_status'] = 'not_evaluated'
        findings['coverage_reasons'] = ['Memory64ListStream missing from this dump']
        findings['verdict_level'] = verdict_level(0, _VERDICT_LEVEL_BY_SCORE, status=NOT_EVALUATED)
        findings['confidence'] = overall_confidence([], 0)
        findings['findings'] = []
        print(YELLOW("  [~] No memory segments in dump — cannot scan for beacon config.\n"))
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(NOT_EVALUATED, 'Memory64ListStream missing from this dump')}\n")
        return findings

    # MemoryInfoListStream is only used for CONTEXT (region base/protect for
    # display, and the score 1 -> 2 corroboration check below) — its
    # absence must not block config DETECTION (a structurally-valid config
    # still scores at least 1), but it does mean the corroboration check
    # could not run to completion, which coverage_status must reflect
    # rather than silently claiming a fully-verified result.
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)

    # ThreadList/CONTEXT coverage — the same explicit counts injection.py
    # tracks (see its coverage["contexts_missing"]): a bare "did any thread
    # context parse" boolean can't distinguish "every thread's context
    # parsed" from "1 out of 200 did". Unlike injection.py, RIP/EIP is NOT
    # the only path to this hunter's top tier (score 2 also comes from
    # executable+private region protection alone — see
    # _cs_context_corroborates), so an incomplete thread-context picture
    # only actually matters for a hit that ISN'T already corroborated by
    # region protection — see the top_tier_uncertain check below.
    thread_list_stream_available = bool(mf.threads and mf.threads.threads)
    threads_total    = len(mf.threads.threads) if (mf.threads and mf.threads.threads) else 0
    contexts_parsed  = len(thread_contexts)
    contexts_missing = max(0, threads_total - contexts_parsed)
    thread_context_gap = (not thread_list_stream_available) or contexts_missing > 0
    findings['coverage'] = {
        "mem_info_stream":       mem_info_available,
        "thread_list_stream":    thread_list_stream_available,
        "threads_total":         threads_total,
        "contexts_parsed":       contexts_parsed,
        "contexts_missing":      contexts_missing,
    }

    coverage_counts = CoverageTracker()
    hits = []
    seen_hit_vas = set()   # O(1) dedup, not an O(n) scan of `hits` per candidate
    reader = mf.get_reader()

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) for beacon signature …"))

    total_candidates    = 0
    total_decoded_bytes = 0
    budget_exhausted     = False
    budget_reason         = None
    scan_deadline = time.monotonic() + CS_SCAN_DEADLINE_SECONDS

    for seg in segs:
        if budget_exhausted:
            break
        if seg.size > CS_MAX_SEG_SCAN:
            coverage_counts.note_skipped_oversize()
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            # A read failure means this segment was never actually looked
            # at — it must not be silently indistinguishable from "read
            # fine, no hit". Tracked separately from size-based skips so a
            # negative result can say exactly what coverage gap exists.
            coverage_counts.note_read_failed()
            continue

        if len(data) < seg.size:
            # A short read (fewer bytes back than the segment's own
            # declared size) is NOT the same as "read fine, no hit" —
            # whatever wasn't returned was never actually examined for a
            # signature. Still scan what WAS returned (a partial read can
            # still contain a hit), but this segment must not silently
            # count toward a "complete" scan.
            coverage_counts.note_short_read()
            if not data:
                continue

        for xor_key, idx, hit_va, hit_fo in _cs_scan_segment(
                data, seg.start_virtual_address, seg.start_file_address):
            total_candidates += 1
            if (total_candidates > CS_MAX_CANDIDATES
                    or total_decoded_bytes > CS_MAX_DECODED_BYTES
                    or time.monotonic() > scan_deadline):
                budget_exhausted = True
                budget_reason = (f"{total_candidates} candidate(s) examined, "
                                  f"{total_decoded_bytes} byte(s) decoded, "
                                  f"{len(hits)} hit(s) found before the scan "
                                  f"budget was exhausted")
                break
            parsed = _cs_decode_and_parse_tlv(data, idx, xor_key, CS_CONFIG_DECODE_MAX)
            total_decoded_bytes += parsed['consumed']
            if not parsed['complete'] or not _cs_sanity_check(parsed['fields']):
                continue
            if hit_va not in seen_hit_vas:
                seen_hit_vas.add(hit_va)
                hits.append((xor_key, hit_va, hit_fo, parsed['fields']))
                if len(hits) >= CS_MAX_HITS:
                    budget_exhausted = True
                    budget_reason = (f"{total_candidates} candidate(s) examined, "
                                      f"{total_decoded_bytes} byte(s) decoded, "
                                      f"{len(hits)} hit(s) found — hit cap reached")
                    break
        if budget_exhausted:
            break

    scan_note = (f" ({coverage_counts.skipped_oversize} segment(s) >50 MB skipped)"
                 if coverage_counts.skipped_oversize else "")
    if coverage_counts.read_failed:
        scan_note += f" ({coverage_counts.read_failed} segment(s) failed to read)"
    if coverage_counts.short_reads:
        scan_note += f" ({coverage_counts.short_reads} segment(s) short-read)"
    if budget_exhausted:
        scan_note += f" (scan budget exhausted: {budget_reason})"
    print(DIM(f"  [*] Scan complete{scan_note}."))

    # Coverage is uniform across the DETECTED/clean/INCONCLUSIVE outcomes
    # below — the same rule every phase-two hunter uses: MemoryInfoListStream
    # absence always makes coverage partial, since it's the region-context
    # corroboration check's own data source, regardless of whether this
    # scan happens to end up finding a config or not.
    complete = coverage_counts.complete and not budget_exhausted and mem_info_available
    coverage_reasons = coverage_counts.build_reasons(
        oversize_label="oversized segment(s) (>50 MB) skipped",
        read_failed_label="segment(s) failed to read",
        short_read_label="segment(s) returned fewer bytes than declared (short read) — "
                          "not fully scanned",
    )
    if budget_exhausted:
        coverage_reasons.append(f"scan resource budget exhausted ({budget_reason}) — "
                                 f"stopped before every segment/candidate was examined")
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump — region/"
                                 "execution-context corroboration for any config hit "
                                 "could not be verified")
    findings['coverage_status']  = derive_coverage_status(True, complete)
    findings['coverage_reasons'] = coverage_reasons

    if not hits:
        status = derive_status(True, False, complete)
        findings['status'] = status
        findings['verdict_level'] = verdict_level(0, _VERDICT_LEVEL_BY_SCORE, status=status)
        findings_list.append(Finding(
            check="cs_beacon.no_structural_config",
            facts=[f"{len(segs)} memory segment(s) scanned"
                   + (f" ({', '.join(coverage_reasons)})" if coverage_reasons else "")],
            inference="No structurally-valid (sanity-checked TLV, known BeaconType, "
                       "ASN.1-shaped public key) Cobalt Strike beacon configuration found "
                       "in what was scanned.",
            confidence=CONFIDENCE_LOW,
            rationale="Absence of a decodable config is weak evidence of absence — an "
                       "unscanned/skipped/unreadable segment, an unsupported XOR scheme, or "
                       "a config that never touched memory captured in this dump would all "
                       "look identical to this.",
            limitations=(["Coverage was incomplete — see coverage_reasons."] if not complete else []),
            tag=TAG_OBSERVATION,
        ))
        findings['findings']   = [f.to_dict() for f in findings_list]
        findings['confidence'] = overall_confidence(findings_list, 0)
        if status == INCONCLUSIVE:
            _print_check("Cobalt Strike beacon config",
                         _status_text(INCONCLUSIVE, "; ".join(coverage_reasons) or "partial coverage"))
        else:
            _print_check("Cobalt Strike beacon config",
                         GREEN("CLEAN — no beacon config found in memory"))
        print()
        return findings

    # ── Score: structural validity alone is 1 ("likely" — see module ──────
    # docstring for why); independent memory-context corroboration on AT
    # LEAST ONE hit raises it to 2. Deliberately NOT len(hits) — additional
    # (even distinct-address) config copies are a fact reported in
    # config_count, not a confidence multiplier.
    hit_records = []
    any_corroborated = False
    for xor_key, hit_va, hit_fo, fields in hits:
        region = _get_region_at(hit_va, regions)
        corroborated, corrob_reasons = _cs_context_corroborates(region, regions, thread_contexts)
        any_corroborated = any_corroborated or corroborated
        hit_records.append((xor_key, hit_va, hit_fo, fields, region, corroborated, corrob_reasons))

    score = 2 if any_corroborated else 1
    findings['score']         = score
    findings['config_count']  = len(hits)

    # No hit was corroborated by region protection, and thread-context
    # coverage was incomplete (or absent) — RIP/EIP corroboration could
    # not fully run, so a genuine top-tier (score 2) result cannot be
    # ruled out for these hits. This is a real coverage gap, not merely
    # "checked and found nothing", so it downgrades coverage_status the
    # same way a skipped/unreadable segment does.
    top_tier_uncertain = not any_corroborated and thread_context_gap
    if top_tier_uncertain:
        complete = False
        if not thread_list_stream_available:
            coverage_reasons.append("ThreadListStream missing from this dump — RIP/EIP-based "
                                     "context corroboration could not run for any uncorroborated hit")
        else:
            coverage_reasons.append(f"{contexts_missing}/{threads_total} thread(s) had no parsed "
                                     f"CONTEXT — RIP/EIP corroboration ran, but not for every "
                                     f"thread, for a hit not otherwise corroborated")
        findings['coverage_status']  = derive_coverage_status(True, complete)
        findings['coverage_reasons'] = coverage_reasons

    status = derive_status(True, True, complete)
    findings['status'] = status
    print()

    for idx, (xor_key, hit_va, hit_fo, fields, region, corroborated, corrob_reasons) in enumerate(hit_records, 1):
        cs_ver   = _cs_guess_version(fields)
        key_desc = {0x69: "0x69 'i'  (CS3 encoding)",
                    0x2e: "0x2E '.'  (CS4 encoding)"}.get(xor_key, f'0x{xor_key:02x}')

        print(RED(f"  [!] Beacon config #{idx}  ──────────────────────────────────────────────"))
        print(f"  {'VA (process)':<26} 0x{hit_va:016x}  {DIM('← virtual address in target process')}")
        print(f"  {'File offset (.dmp)':<26} 0x{hit_fo:016x}  {DIM('← byte offset inside .dmp file')}")
        if region is not None:
            print(f"  {'Region base (VA)':<26} 0x{region.BaseAddress:016x}  {DIM('← for cross-referencing with --hunt injection')}")
            print(f"  {'Region size':<26} 0x{region.RegionSize:x}")
            print(f"  {'Region protect':<26} {prot_str(region.Protect)}")
        else:
            print(f"  {'Region base (VA)':<26} {DIM('(not covered by MemoryInfoListStream)')}")
        print(f"  {'XOR key':<26} {key_desc}")
        print(f"  {'CS version (estimated)':<26} {YELLOW(cs_ver)}")
        if corroborated:
            print(f"  {'Context corroboration':<26} {RED('YES')}  — {'; '.join(corrob_reasons)}")
        else:
            print(f"  {'Context corroboration':<26} {DIM('none')}  — structural validity only")
        print()

        f = fields

        # ── C2 / Identity / Transport ──────────────────────────────────
        print(f"  {BOLD('── C2 / Identity / Transport ──────────────────────────────────────')}")

        if 0x0001 in f:
            btype     = f[0x0001]['value']
            btype_str = CS_BEACON_TYPES.get(btype, f'unknown ({btype})')
            color     = RED if btype in (1, 2) else YELLOW   # DNS/SMB = more covert
            print(f"  {'BeaconType':<26} {color(btype_str)}")

        if 0x0008 in f:
            c2raw = (f[0x0008]['value'] or '').strip('\x00')
            if ',' in c2raw:
                host, uri = c2raw.split(',', 1)
                print(f"  {'C2 Host':<26} {RED(host.strip())}")
                print(f"  {'C2 GET URI':<26} {uri.strip()}")
            else:
                print(f"  {'C2 Server':<26} {RED(c2raw)}")

        if 0x0002 in f:
            print(f"  {'Port':<26} {f[0x0002]['value']}")

        if 0x000a in f:
            v = (f[0x000a]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP POST URI':<26} {v}")

        if 0x0009 in f:
            ua = (f[0x0009]['value'] or '').strip('\x00')
            if ua: print(f"  {'UserAgent':<26} {ua}")

        if 0x0036 in f:
            hh = (f[0x0036]['value'] or '').strip('\x00')
            if hh: print(f"  {'HostHeader':<26} {hh}")

        if 0x000f in f:
            pipe = (f[0x000f]['value'] or '').strip('\x00')
            if pipe: print(f"  {'PipeName':<26} {RED(pipe)}")

        if 0x0025 in f:
            print(f"  {'LicenseID':<26} {YELLOW(str(f[0x0025]['value']))}")

        if 0x0003 in f:
            sleep_ms = f[0x0003]['value'] or 0
            jitter   = f[0x0005]['value'] if 0x0005 in f else 0
            print(f"  {'Sleep / Jitter':<26} {sleep_ms} ms / {jitter}%")

        if 0x0028 in f and f[0x0028]['value']:
            print(f"  {'KillDate':<26} {f[0x0028]['value']}")

        if 0x001a in f:
            v = (f[0x001a]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP GET Verb':<26} {v}")
        if 0x001b in f:
            v = (f[0x001b]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP POST Verb':<26} {v}")

        if 0x001d in f:
            v = (f[0x001d]['value'] or '').strip('\x00')
            if v: print(f"  {'SpawnTo x86':<26} {v}")
        if 0x001e in f:
            v = (f[0x001e]['value'] or '').strip('\x00')
            if v: print(f"  {'SpawnTo x64':<26} {v}")

        if 0x0020 in f:
            proxy = (f[0x0020]['value'] or '').strip('\x00')
            ptype = CS_PROXY_TYPES.get(f[0x0023]['value'] if 0x0023 in f else 0, '')
            if proxy: print(f"  {'Proxy':<26} {proxy}  [{ptype}]")

        # ── Process injection ──────────────────────────────────────────
        inj_ids = {0x002b, 0x002c, 0x002d, 0x002e, 0x002f, 0x0033, 0x0034, 0x0035}
        inj = {k: f[k] for k in inj_ids if k in f}
        if inj:
            print(f"\n  {BOLD('── Process Injection ──────────────────────────────────────────────')}")
            for fid in sorted(inj):
                rec = inj[fid]
                if fid in (0x002b, 0x002c):
                    val = CS_INJECT_PERMS.get(rec['value'], str(rec['value']))
                elif rec['type'] == 3:
                    val = (rec['value'] or '').strip('\x00') or rec['raw'].hex()[:60]
                else:
                    val = str(rec['value'])
                print(f"  {rec['name']:<26} {val}")

        # ── Malleable C2 / GET / POST transforms ───────────────────────
        for fid, label, itype in (
            (0x000b, 'Malleable C2  (server→client transform)', 1),
            (0x000c, 'HTTP GET  header transforms',             2),
            (0x000d, 'HTTP POST header transforms',             3),
        ):
            if fid in f and f[fid]['raw']:
                try:
                    instrs = _cs_decode_instructions(f[fid]['raw'], itype)
                    if instrs:
                        print(f"\n  {BOLD(f'── {label}')}")
                        for step in instrs:
                            print(f"    {DIM('›')} {step}")
                except Exception:
                    pass

        # ── SSH transport ──────────────────────────────────────────────
        ssh_ids = (0x0015, 0x0016, 0x0017, 0x0018, 0x0038)
        ssh = {k: f[k] for k in ssh_ids if k in f}
        if ssh:
            print(f"\n  {BOLD('── SSH Transport ──────────────────────────────────────────────────')}")
            for fid, rec in sorted(ssh.items()):
                val = (rec['value'] or '').strip('\x00') if rec['type'] == 3 else str(rec['value'])
                if val: print(f"  {rec['name']:<26} {val}")

        # ── DNS transport ──────────────────────────────────────────────
        dns_ids = range(0x003c, 0x0047)
        dns = {k: f[k] for k in dns_ids if k in f}
        if dns:
            print(f"\n  {BOLD('── DNS Transport ──────────────────────────────────────────────────')}")
            for fid, rec in sorted(dns.items()):
                val = (rec['value'] or '').strip('\x00') if rec['type'] == 3 else str(rec['value'])
                if val: print(f"  {rec['name']:<26} {val}")

        # ── Full field table (--verbose only) ──────────────────────────
        if verbose:
            print(f"\n  {BOLD('── Full Config Field Table ────────────────────────────────────────')}")
            w = max((len(v['name']) for v in f.values()), default=20)
            for fid in sorted(f.keys()):
                rec = f[fid]
                if rec['type'] == 3:
                    txt  = (rec['value'] or '').strip('\x00') if isinstance(rec['value'], str) else ''
                    hexs = rec['raw'].hex()
                    if txt:
                        display = f"{repr(txt)}  [{hexs[:48]}{'...' if len(hexs) > 48 else ''}]"
                    else:
                        display = f"[{hexs[:64]}{'...' if len(hexs) > 64 else ''}]"
                else:
                    display = str(rec['value'])
                print(f"    0x{fid:04x}  {rec['name']:<{w}}  {display}")

        print()
        findings['configs'].append({
            'va': hit_va, 'file_offset': hit_fo,
            'region_base':    region.BaseAddress if region is not None else None,
            'region_size':    region.RegionSize  if region is not None else None,
            'region_protect': prot_str(region.Protect) if region is not None else None,
            'xor_key': xor_key, 'cs_version': cs_ver,
            'cs_version_note': 'estimated from highest recognized field ID — not a '
                                'fingerprinted/confirmed build',
            'context_corroborated': corroborated,
            'fields': fields,
        })

        facts = [f"VA=0x{hit_va:x} file_offset=0x{hit_fo:x} xor_key=0x{xor_key:02x} "
                 f"cs_version_estimated={cs_ver} field_count={len(fields)}"]
        facts.append(f"region=0x{region.BaseAddress:x} size=0x{region.RegionSize:x} "
                      f"protect={prot_str(region.Protect)}"
                      if region is not None else
                      "enclosing region not covered by MemoryInfoListStream")

        hit_limitations = []
        if not mem_info_available:
            hit_limitations.append("Region/execution-context corroboration could not be "
                                    "verified — MemoryInfoListStream missing from this dump.")
        if not corroborated and thread_context_gap:
            hit_limitations.append(
                "RIP/EIP-based execution corroboration could not fully run — "
                + ("ThreadListStream missing from this dump" if not thread_list_stream_available
                   else f"{contexts_missing}/{threads_total} thread(s) had no parsed CONTEXT")
                + " — a live-execution corroboration for this hit cannot be ruled out.")

        findings_list.append(Finding(
            check="cs_beacon.structural_config",
            facts=facts,
            inference="Structurally-valid Cobalt Strike beacon configuration (TLV wire "
                       "format parsed, known BeaconType, ASN.1-shaped public key) found at "
                       "this address.",
            confidence=CONFIDENCE_HIGH if corroborated else CONFIDENCE_MEDIUM,
            rationale=("Corroborated by independent memory context: " + "; ".join(corrob_reasons)
                       if corroborated else
                       "The config's own structural validity — TLV wire format, known field "
                       "types, a recognized BeaconType, and an ASN.1-shaped public key all "
                       "lining up — is itself hard to produce by chance, but no independent "
                       "memory-context corroboration (executable private region, or a thread "
                       "executing within the same allocation) was found for this hit."),
            limitations=hit_limitations,
            tag=TAG_DETECTION,
        ))

    findings['findings']       = [f.to_dict() for f in findings_list]
    findings['confidence']     = overall_confidence(findings_list, score)
    findings['verdict_level']  = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)

    corrob_note = ("  (context-corroborated)" if any_corroborated else
                   "  (structural validity only — no independent memory-context corroboration)")
    print(f"  {BOLD('[ VERDICT ]')}  "
          f"{RED(f'COBALT STRIKE — {len(hits)} beacon config(s) found in memory')}{corrob_note}\n")
    if not verbose:
        print(DIM("  Use --verbose to dump all config fields.\n"))

    return findings

