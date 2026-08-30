"""Absolute IOC token addressing on the FULL-SCOPE stomping path.

`_classify_ioc_hits` is shared by the ordinary `--hunt stomping` scan and the
targeted rescan, so its offset arithmetic is one behaviour with two consumers.
A token's `offset` is a BYTE offset into its region and its `va` the absolute
address an investigator extracts or pivots on -- for every encoding an
extracted string can carry, whatever that encoding's character/byte ratio is.

`_extract_ioc_strings` reports each run's BYTE offset and its DECODED text, so a
pattern match's position inside that text is a CHARACTER index; the two units
coincide only for a single-byte encoding. These tests drive `scan_ioc_strings`
itself with the shipped rule set -- the ordinary full-scope entry point, not the
classifier in isolation -- so the addresses asserted here are the ones a real
run reports, and the console projection is checked to carry them through.
"""
from tests.fixtures.fakes import (
    FakeMF, FakeStream, Module, Region, Segment, mem_reader,
)

from dumpex.hunt.stomping.memory_scan import scan_ioc_strings
from dumpex.hunt.stomping.report_console import _ioc_verbose_fact
from dumpex.output.records import hex_address
from dumpex.rules_pkg.loader import get_rules

_BASE = 0x7ff600000000
_SIZE = 0x1000
_FILE_OFFSET = 0x5000

_RULES = get_rules(announce=False)

# One IOC term from the shipped pattern set, and padding in front of it so the
# token's index inside its run is nonzero -- a token at index 0 lands on the run
# offset for every width and would pin nothing.
_TOKEN = "meterpreter"
_PAD = "PADPADPAD"
_ASCII_RUN = (_PAD + _TOKEN).encode("ascii")
_UTF16_RUN = (_PAD + _TOKEN).encode("utf-16-le")

# A URL inside a longer printable run. The leading padding is what makes the
# printable-ASCII pass start the run EARLIER than the URL anchor, so the
# anchor-and-extend pass still emits its own `ASCII-URL` string for the same
# bytes: two runs, two offsets, two character indices, one token.
_URL_RUN = b"XXXXXXXXhttp://host.example/" + _TOKEN.encode("ascii")
_URL_TOKEN_INDEX = _URL_RUN.index(_TOKEN.encode("ascii"))


def _region():
    return Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")


def _mf():
    class MF(FakeMF):
        pass
    MF.memory_segments_64 = FakeStream(
        [Segment(_BASE, _FILE_OFFSET, _SIZE)], "memory_segments")
    return MF()


def _buf(*placements) -> bytes:
    data = bytearray(b"\x00" * _SIZE)
    for offset, blob in placements:
        data[offset:offset + len(blob)] = blob
    return bytes(data)


def _scan(data, name=r"C:\app\payload.dll", whitelist=frozenset()):
    """One full-scope `scan_ioc_strings` over one executable MEM_IMAGE region
    holding `data`, with the shipped IOC and network-IOC pattern sets."""
    return scan_ioc_strings(
        _mf(), mem_reader({_BASE: data}), [_region()], [Module(_BASE, _SIZE, name)],
        whitelist, _RULES["stomping_ioc_patterns"], _RULES["stomping_net_ioc_patterns"])


def _tokens(result, encoding=None) -> list:
    """Every hit for `_TOKEN` itself. The network pattern set also matches the
    URL in `_URL_RUN`; that hit is a different token and is filtered out here so
    an assertion about the IOC term's address stays about that address."""
    return [token for ev in result.hits for token in ev.tokens
            if token.token.casefold() == _TOKEN
            and (encoding is None or token.encoding == encoding)]


def _token_offsets(result, encoding=None) -> list:
    return sorted({token.offset for token in _tokens(result, encoding)})


def test_a_utf16_ioc_token_reports_its_true_byte_address():
    """A match sits `m.start()` CHARACTERS into a UTF-16LE run, which is twice
    as many bytes. Taking that index as a byte offset would report the token
    nine bytes early -- inside the padding that precedes it."""
    result = _scan(_buf((0x300, _UTF16_RUN)))

    hits = _tokens(result, "UTF16")
    assert hits, "the UTF-16LE run produced no IOC hit"
    for hit in hits:
        assert hit.offset == 0x300 + len(_PAD) * 2
        assert hit.va == _BASE + 0x300 + len(_PAD) * 2


def test_an_ascii_ioc_token_address_is_the_run_offset_plus_its_index():
    """Single-byte encodings are frozen: width 1 makes the scaling the
    identity, so an ASCII token's address is exactly the run offset plus the
    character index."""
    result = _scan(_buf((0x100, _ASCII_RUN)))

    hits = _tokens(result, "ASCII")
    assert hits, "the ASCII run produced no IOC hit"
    for hit in hits:
        assert hit.offset == 0x100 + len(_PAD)
        assert hit.va == _BASE + 0x100 + len(_PAD)


def test_the_two_single_byte_encodings_agree_on_one_address():
    """The same bytes are extracted twice -- by the printable-ASCII pass as
    `ASCII` and by the anchor-and-extend pass as `ASCII-URL` -- at two run
    offsets with two character indices for one token. Both encodings are width
    1, so both resolve to the single absolute address those bytes have."""
    result = _scan(_buf((0x100, _URL_RUN)))

    assert {hit.encoding for hit in _tokens(result)} == {"ASCII", "ASCII-URL"}
    assert _token_offsets(result) == [0x100 + _URL_TOKEN_INDEX]
    assert all(hit.va == _BASE + 0x100 + _URL_TOKEN_INDEX for hit in _tokens(result))


def test_two_encodings_in_one_region_each_scale_by_their_own_width():
    """One region, two runs, one token text: each address is resolved with the
    width of the run the token was found in, never one width per region."""
    result = _scan(_buf((0x100, _ASCII_RUN), (0x300, _UTF16_RUN)))

    assert _token_offsets(result, "ASCII") == [0x100 + len(_PAD)]
    assert _token_offsets(result, "UTF16") == [0x300 + len(_PAD) * 2]


def test_only_the_address_moves_never_the_hit_itself():
    """The width scaling is address arithmetic and nothing more. Which tokens
    match, how many hits a region yields, the token text, the weak/strong
    classification, and the weak-only region count are all independent of the
    encoding's byte width."""
    ascii_scan = _scan(_buf((0x100, _ASCII_RUN)))
    utf16_scan = _scan(_buf((0x100, _UTF16_RUN)))

    def _shape(result):
        return [(token.token, token.is_weak)
                for ev in result.hits for token in ev.tokens]

    assert _shape(ascii_scan) == _shape(utf16_scan) == [(_TOKEN, False)]
    assert len(ascii_scan.hits) == len(utf16_scan.hits) == 1
    assert ascii_scan.weak_only_regions == utf16_scan.weak_only_regions == 0
    assert ascii_scan.coverage.scanned == utf16_scan.coverage.scanned == 1


def test_the_console_verbose_fact_carries_the_corrected_address():
    """The one projection that renders a per-token address. The wire-shaped
    `--json` fact dedupes to a single entry per REGION with a capped term list
    and carries no token address at all, so there is nothing there for this
    arithmetic to reach."""
    result = _scan(_buf((0x300, _UTF16_RUN)))
    facts = [fact for ev in result.hits for fact in _ioc_verbose_fact(ev)]

    assert facts, "the UTF-16LE hit reached no verbose fact"
    for fact in facts:
        assert f"VA={hex_address(_BASE + 0x300 + len(_PAD) * 2)}" in fact
        assert "encoding=UTF16" in fact
        assert f"token={_TOKEN}" in fact
