"""
Shared classifier for decoded/decompressed content — used by every
content-producing layer (sleep_mask, decoding) to answer "what IS this
data, once decoded":
  - MZ + PE\\x00\\x00     → PE payload
  - call-$+5 bootstrap    → likely shellcode
  - printable > 85 %      → IOC string scan (IP / URL / pipe names)
  - else                  → hex prefix reported
"""
import re

from dumpex.core.pe_utils import parse_pe_header
from dumpex.hunt.encoding.entropy import _shannon_entropy

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
        pe = parse_pe_header(data)
        if pe['valid']:
            result.update({'type': 'pe', 'is_pe': True, 'pe_info': pe})
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


def _structural_note(has_pe: bool, has_shellcode: bool) -> str:
    """
    One-line pointer to WHICH downstream Finding a layer's structural
    content actually landed in — PE payloads are scored
    (obfuscation.structural_payload); a bare shellcode-bootstrap prefix is
    a lead only (obfuscation.shellcode_bootstrap_lead) and must not be
    described the same way, or a reader would assume it scores too.
    """
    if has_pe and has_shellcode:
        return ("PE payload(s) found — see obfuscation.structural_payload below "
                "(scored); shellcode-bootstrap prefix match(es) also found — see "
                "obfuscation.shellcode_bootstrap_lead (lead only, not scored)")
    if has_pe:
        return "PE payload(s) found — see obfuscation.structural_payload below (scored)"
    if has_shellcode:
        return ("shellcode-bootstrap prefix match(es) found — see "
                "obfuscation.shellcode_bootstrap_lead (lead only, not scored)")
    return "no structural or IOC content found in decoded data"
