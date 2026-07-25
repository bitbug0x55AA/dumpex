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
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.core.memory import (va_to_file_offset, get_memory_regions, _get_region_at,
    get_thread_contexts, prot_str)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_DETECTION, overall_confidence, verdict_level)

CS_BEACON_SIGNATURE  = b'\x00\x01\x00\x01\x00\x02'   # plaintext TLV start
CS_SIG_XOR69         = b'ihihik'                       # above ^ 0x69
CS_SIG_XOR2E         = b'././.,'                       # above ^ 0x2e
CS_MAX_SEG_SCAN      = 50 * 1024 * 1024               # skip segments > 50 MB

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


def _cs_scan_segment(data: bytes, seg_va: int, seg_fo: int) -> list:
    """
    Search one memory segment for CS beacon config signatures.

    Strategy (from 1768.py AnalyzeEmbeddedPEFileSub):
      For each XOR key (0x69, 0x2e), search for the pre-XOR'd marker.
      On hit: XOR-decode from that offset, verify the plaintext signature.

    Returns list of (xor_key, hit_va, hit_file_offset, decoded_config_bytes).
    """
    results = []
    for key, marker in ((0x69, CS_SIG_XOR69), (0x2e, CS_SIG_XOR2E)):
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            chunk = _cs_xor_bytes(data[idx: idx + 0x10000], key)
            if chunk.startswith(CS_BEACON_SIGNATURE):
                results.append((key, seg_va + idx, seg_fo + idx, chunk))
            start = idx + 1
    return results


def _cs_parse_tlv(data: bytes) -> dict:
    """
    Parse a CS TLV config block (adapted from 1768.py AnalyzeEmbeddedPEFileSub2).

    Wire format (all big-endian):
        field_id  uint16    (0 = end of config)
        type      uint16    (1=uint16, 2=uint32, 3=bytes)
        length    uint16
        value     <length> bytes

    Returns dict: field_id (int) -> {name, type, raw, value}.
    """
    fields = {}
    pos = 0
    while pos + 6 <= len(data):
        fid   = struct.unpack_from('>H', data, pos)[0]; pos += 2
        if fid == 0:
            break
        ftype = struct.unpack_from('>H', data, pos)[0]; pos += 2
        flen  = struct.unpack_from('>H', data, pos)[0]; pos += 2
        if pos + flen > len(data):
            break
        raw  = data[pos: pos + flen]; pos += flen

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
    return fields


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


def _cs_sanity_check(fields: dict) -> bool:
    """
    Validate extracted config (mirrors 1768.py SanityCheckExtractedConfig):
      - field 0x0001 (beacon type) must be present and a known value
      - field 0x0007 (public key) must start with ASN.1 SEQUENCE prefix 0x308...
    """
    if 0x0001 not in fields or 0x0007 not in fields:
        return False
    if fields[0x0001]['value'] not in CS_BEACON_TYPES:
        return False
    return fields[0x0007]['raw'].hex().startswith('308')


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
    skipped, read_failed, hits = 0, 0, []
    reader = mf.get_reader()

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) for beacon signature …"))

    for seg in segs:
        if seg.size > CS_MAX_SEG_SCAN:
            skipped += 1
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            # A read failure means this segment was never actually looked
            # at — it must not be silently indistinguishable from "read
            # fine, no hit". Tracked separately from size-based skips so a
            # negative result can say exactly what coverage gap exists.
            read_failed += 1
            continue

        for xor_key, hit_va, hit_fo, cfg_bytes in _cs_scan_segment(
                data, seg.start_virtual_address, seg.start_file_address):
            fields = _cs_parse_tlv(cfg_bytes)
            if not fields or not _cs_sanity_check(fields):
                continue
            if not any(h[1] == hit_va for h in hits):   # deduplicate by VA
                hits.append((xor_key, hit_va, hit_fo, fields))

    scan_note = f" ({skipped} segment(s) >50 MB skipped)" if skipped else ""
    if read_failed:
        scan_note += f" ({read_failed} segment(s) failed to read)"
    print(DIM(f"  [*] Scan complete{scan_note}."))

    # Coverage is uniform across the DETECTED/clean/INCONCLUSIVE outcomes
    # below — the same rule every phase-two hunter uses: MemoryInfoListStream
    # absence always makes coverage partial, since it's the region-context
    # corroboration check's own data source, regardless of whether this
    # scan happens to end up finding a config or not.
    complete = not (skipped or read_failed) and mem_info_available
    coverage_reasons = []
    if skipped:
        coverage_reasons.append(f"{skipped} oversized segment(s) (>50 MB) skipped")
    if read_failed:
        coverage_reasons.append(f"{read_failed} segment(s) failed to read")
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
            limitations=(["Region/execution-context corroboration could not be verified — "
                          "MemoryInfoListStream missing from this dump."]
                         if not mem_info_available else []),
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

