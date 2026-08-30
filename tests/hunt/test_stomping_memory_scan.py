"""Direct unit tests for dumpex.hunt.stomping.memory_scan.

read_module_header() -- pinning that a short module-header read reaches
dumpex.core.pe_utils.parse_pe_header()'s current wording, so a future
change to that wording (issue #40 changed the < 0x40-byte case from
'no MZ signature' to 'truncated DOS header') is caught here rather than
relying on no other test happening to assert the old text.

_classify_ioc_hits() -- pinning that a hit's offset is a BYTE offset into
the region for every encoding an extracted string can carry.
"""
import re

from tests.fixtures.fakes import FakeMF, Module, mem_reader

from dumpex.core.memory import IOC_STRING_ENCODING_WIDTHS, _extract_ioc_strings
from dumpex.hunt.stomping.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.stomping.memory_scan import _classify_ioc_hits, read_module_header


def test_short_mz_header_reason_is_truncated_dos_header():
    """A module header short-read (< 0x40 bytes, but starting with the
    real 'MZ' signature) reaches stomping's own ParseFailedEvidence.reason
    -- pinned to parse_pe_header()'s current wording and insufficient_data
    signal."""
    module_base = 0x7ff600000000
    module = Module(module_base, 0x10, r"C:\Windows\System32\legit.dll")
    read_region = mem_reader({module_base: b"MZ" + b"\x00" * 8})   # 10 bytes, real MZ prefix

    pe, read_failed = read_module_header(FakeMF(), read_region, module, PE_VALIDATE_READ_MAX)
    assert read_failed is False
    assert pe["valid"] is False
    assert pe["reason"] == "truncated DOS header"
    assert pe["insufficient_data"] is True


def test_short_non_mz_header_reason_is_no_mz_signature():
    """A short read whose first two bytes are already conclusively NOT
    'MZ' is a deterministic rejection, not a capture-length gap -- reason
    stays 'no MZ signature' and insufficient_data is False regardless of
    how short the read was."""
    module_base = 0x7ff600000000
    module = Module(module_base, 0x10, r"C:\Windows\System32\legit.dll")
    read_region = mem_reader({module_base: b"XX" + b"\x00" * 8})

    pe, read_failed = read_module_header(FakeMF(), read_region, module, PE_VALIDATE_READ_MAX)
    assert read_failed is False
    assert pe["valid"] is False
    assert pe["reason"] == "no MZ signature"
    assert pe["insufficient_data"] is False


# ── _classify_ioc_hits: character index vs byte offset ────────────────────
#
# `_extract_ioc_strings` reports each run's BYTE offset in the region and its
# DECODED text. A pattern match inside that text carries a CHARACTER index, so
# the two units only coincide for a single-byte encoding -- and an IOC hit's
# `offset`/`va` are the address an investigator extracts or pivots on.

_REGION_BASE = 0x10000000
_PATTERNS = (re.compile(r"meterpreter"),)


def _all_three_strategies() -> bytes:
    """A buffer that exercises every one of `_extract_ioc_strings`' three
    extraction strategies: a plain printable-ASCII run, a URL the
    anchor-and-extend pass picks up, and a UTF-16LE run.

    The URL is preceded by printable padding on purpose. Strategy 2 skips any
    anchor whose offset a strategy-1 run already starts at, so a URL sitting at
    the head of its own run is only ever tagged ASCII -- the padding is what
    makes the run start earlier and leaves the anchor reachable."""
    data = bytearray(b"\x00" * 0x400)
    plain = b"PADPADPADPADPADPmeterpreter"
    data[0x00:0x00 + len(plain)] = plain
    url_run = b"XXXXXXXXhttp://host00.example/x"
    data[0x40:0x40 + len(url_run)] = url_run
    utf16 = "PADPADPADmeterpreter".encode("utf-16-le")
    data[0x100:0x100 + len(utf16)] = utf16
    return bytes(data)


def test_every_encoding_the_extractor_emits_has_a_declared_byte_width():
    """`_classify_ioc_hits` indexes `IOC_STRING_ENCODING_WIDTHS` directly, so a
    tag the extractor mints without a width there is a KeyError mid-scan rather
    than a wrong address -- but only if the two actually stay in step. Derived
    from the extractor's real output rather than a restated tag list, so a
    renamed or added encoding fails here instead of in the field."""
    emitted = {enc for _off, enc, _s in _extract_ioc_strings(_all_three_strategies(), 0)}

    assert emitted, "the fixture exercised none of the extraction strategies"
    assert emitted <= set(IOC_STRING_ENCODING_WIDTHS), (
        f"{sorted(emitted - set(IOC_STRING_ENCODING_WIDTHS))} carry no declared byte "
        f"width -- add them to IOC_STRING_ENCODING_WIDTHS beside the tags")
    assert set(IOC_STRING_ENCODING_WIDTHS) == emitted, (
        f"{sorted(set(IOC_STRING_ENCODING_WIDTHS) - emitted)} declare a width but are "
        f"never emitted -- the map and the extractor have drifted apart")


def test_an_ascii_token_offset_is_the_run_offset_plus_its_index():
    strings = [(0x200, "ASCII", "PADPADPADPADPADPmeterpreter")]
    hit = _classify_ioc_hits(strings, _PATTERNS, _REGION_BASE)[0]

    assert hit.offset == 0x200 + 16
    assert hit.va == _REGION_BASE + 0x200 + 16


def test_a_utf16_token_offset_scales_its_character_index_to_bytes():
    strings = [(0x200, "UTF16", "PADPADPADPADPADPmeterpreter")]
    hit = _classify_ioc_hits(strings, _PATTERNS, _REGION_BASE)[0]

    assert hit.encoding == "UTF16"
    assert hit.offset == 0x200 + 16 * 2
    assert hit.va == _REGION_BASE + 0x200 + 16 * 2


def test_a_token_at_a_run_start_is_unaffected_by_the_encoding_width():
    """The scaling applies to the index INSIDE the run, never to the run's own
    byte offset -- a token at index 0 lands on the run offset for every declared
    encoding. Iterates the declared map rather than a restated tag list, so a
    new encoding is covered the moment it is declared."""
    for enc in sorted(IOC_STRING_ENCODING_WIDTHS):
        hit = _classify_ioc_hits([(0x200, enc, "meterpreter")], _PATTERNS, _REGION_BASE)[0]
        assert hit.offset == 0x200, enc
