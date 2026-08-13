"""XOR decode, TLV parsing, Malleable C2 instruction decoding, version
estimation, and the config sanity check — everything needed to turn one
raw marker-match candidate into either a rejected blob or a fully-parsed
config `fields` dict.

Adapted from 1768.py by Didier Stevens (public domain) — see CREDITS.
"""
import struct

from dumpex.hunt.cs_beacon.config import CS_BEACON_SIGNATURE
from dumpex.hunt.cs_beacon.der import _cs_validate_public_key_der
from dumpex.hunt.cs_beacon.schema import CS_FIELD_NAMES, CS_BEACON_TYPES


def _cs_xor_bytes(data: bytes, key: int) -> bytes:
    """Single-byte XOR decode. Mirrors 1768.py Xor() for single-byte keys."""
    kb = key & 0xff
    return bytes(b ^ kb for b in data)


def _cs_decode_type3_value(raw: bytes) -> "tuple":
    """Decode one type-3 (bytes) TLV field's raw payload into
    `(value, is_text)` -- the ONE place this decision is made, so
    `_cs_decode_and_parse_tlv()` (building the field's own `value`) and
    `presentation.py` (deciding how to render it under `--verbose`) can
    never disagree about whether a given field's payload is genuine
    printable text or an opaque binary blob.

    `is_text` True only when `raw`, after stripping trailing NUL padding,
    decodes as UTF-8 and every character is printable (or one of
    tab/CR/LF, which count as printable text here -- a Malleable C2
    header block or SpawnTo path can legitimately contain those). In that
    case `value` IS the decoded text. Otherwise `value` is the
    NUL-stripped bytes' own hex string -- note this is NOT the same
    string as `raw.hex()` (trailing NUL bytes are stripped first), so a
    caller that wants the field's FULL raw bytes as hex (e.g. a console
    display showing "the actual bytes on disk/in memory") must hex-encode
    `raw` itself, not reuse this `value`."""
    stripped = raw.rstrip(b'\x00')
    try:
        candidate = stripped.decode('utf-8')
        is_text = all(c.isprintable() or c in '\t\r\n' for c in candidate)
        return (candidate if is_text else stripped.hex()), is_text
    except UnicodeDecodeError:
        return stripped.hex(), False


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
        # The fid=0 terminator is exactly 2 bytes (no type/length follows
        # it) — checked on its own BEFORE demanding a full 6-byte header,
        # so a legitimately-terminated config whose terminator happens to
        # sit in the last 2-5 bytes of the available buffer (no trailing
        # padding) isn't misreported as truncated. Only a non-terminator
        # field actually needs the full type+length header.
        if pos + 2 > limit:
            return {'fields': fields, 'complete': False,
                    'reason': 'truncated before fid=0 terminator (ran out of '
                              'decode budget)',
                    'consumed': pos - offset}
        fid = struct.unpack('>H', bytes(b ^ kb for b in data[pos: pos + 2]))[0]
        if fid == 0:
            return {'fields': fields, 'complete': True, 'reason': None,
                    'consumed': pos + 2 - offset}
        if pos + 6 > limit:
            return {'fields': fields, 'complete': False,
                    'reason': f'truncated before terminator (field 0x{fid:04x} '
                              f'header incomplete)',
                    'consumed': pos - offset}
        header = bytes(b ^ kb for b in data[pos: pos + 6])
        fid, ftype, flen = struct.unpack('>HHH', header)
        if ftype not in valid_types:
            return {'fields': fields, 'complete': False,
                    'reason': f'illegal field type 0x{ftype:04x} for field 0x{fid:04x}',
                    'consumed': pos - offset}
        # A type-1 (uint16) field must declare exactly 2 bytes and a
        # type-2 (uint32) field exactly 4 -- anything else is not a
        # legitimate config, however plausible the rest of the blob looks.
        # Rejected HERE, at the header, rather than left to fall through
        # the value-decode below: with neither branch of that decode
        # matching, `value` stayed `None` and was still stored as a real
        # field -- silently producing a NON-scalar value for a type the
        # wire format promises is always an int, which crashed
        # models.ConfigField's own type validation (int|str only) the
        # first time this candidate reached the frozen evidence boundary
        # instead of being rejected as the malformed blob it is.
        if (ftype == 1 and flen != 2) or (ftype == 2 and flen != 4):
            return {'fields': fields, 'complete': False,
                    'reason': f'field 0x{fid:04x} declares type 0x{ftype:04x} with invalid '
                              f'length {flen} (expected {2 if ftype == 1 else 4})',
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
                # Attempt clean UTF-8 decode; if the result contains non-printable
                # characters (common for inject payloads, transforms, stubs, etc.)
                # display as hex instead of mangled replacement characters. See
                # _cs_decode_type3_value's own docstring for why this is a shared
                # function rather than inlined here -- presentation.py's console
                # rendering needs the identical decision.
                value, _is_text = _cs_decode_type3_value(raw)
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


def _cs_sanity_check(fields: dict) -> bool:
    """
    Validate extracted config (mirrors 1768.py SanityCheckExtractedConfig,
    hardened beyond it — see der._cs_validate_public_key_der):
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
