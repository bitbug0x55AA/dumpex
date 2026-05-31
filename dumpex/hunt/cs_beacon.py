"""Cobalt Strike beacon config scanner (adapted from 1768.py by Didier Stevens)."""
import os
import struct
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.core.memory import va_to_file_offset
from dumpex.hunt._ui import _print_hunt_header, _print_check

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
      5. Report VA (process address) + file offset (.dmp byte position) for
         each hit, consistent with Dumpex address labeling conventions.

    Address note:
      hit VA         = segment.start_virtual_address + offset_within_segment
      hit file offset = segment.start_file_address   + offset_within_segment
    """
    _print_hunt_header("Cobalt Strike Beacon Config")
    findings = {'configs': [], 'score': 0}

    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments

    if not segs:
        print(YELLOW("  [~] No memory segments in dump — cannot scan for beacon config.\n"))
        return findings

    skipped, hits = 0, []
    reader = mf.get_reader()

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) for beacon signature …"))

    for seg in segs:
        if seg.size > CS_MAX_SEG_SCAN:
            skipped += 1
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            continue

        for xor_key, hit_va, hit_fo, cfg_bytes in _cs_scan_segment(
                data, seg.start_virtual_address, seg.start_file_address):
            fields = _cs_parse_tlv(cfg_bytes)
            if not fields or not _cs_sanity_check(fields):
                continue
            if not any(h[1] == hit_va for h in hits):   # deduplicate by VA
                hits.append((xor_key, hit_va, hit_fo, fields))

    scan_note = f" ({skipped} segment(s) >50 MB skipped)" if skipped else ""
    print(DIM(f"  [*] Scan complete{scan_note}."))

    if not hits:
        _print_check("Cobalt Strike beacon config",
                     GREEN("CLEAN — no beacon config found in memory"))
        print()
        return findings

    findings['score'] = len(hits)
    print()

    for idx, (xor_key, hit_va, hit_fo, fields) in enumerate(hits, 1):
        cs_ver   = _cs_guess_version(fields)
        key_desc = {0x69: "0x69 'i'  (CS3 encoding)",
                    0x2e: "0x2E '.'  (CS4 encoding)"}.get(xor_key, f'0x{xor_key:02x}')

        print(RED(f"  [!] Beacon config #{idx}  ──────────────────────────────────────────────"))
        print(f"  {'VA (process)':<26} 0x{hit_va:016x}  {DIM('← virtual address in target process')}")
        print(f"  {'File offset (.dmp)':<26} 0x{hit_fo:016x}  {DIM('← byte offset inside .dmp file')}")
        print(f"  {'XOR key':<26} {key_desc}")
        print(f"  {'CS version (estimated)':<26} {YELLOW(cs_ver)}")
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
            'xor_key': xor_key, 'cs_version': cs_ver, 'fields': fields,
        })

    print(f"  {BOLD('[ VERDICT ]')}  "
          f"{RED(f'COBALT STRIKE — {len(hits)} beacon config(s) found in memory')}\n")
    if not verbose:
        print(DIM("  Use --verbose to dump all config fields.\n"))

    return findings

