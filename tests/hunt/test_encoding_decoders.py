"""
Unit/hunter-level tests for dumpex.hunt.encoding's classification helpers
(_classify_decoded, _is_plausible_ip, _bounded_decompress) and the
Base64/XOR/GZIP/ZLIB decode layers -- legitimate structural content,
plain non-IOC content (observation only, never scored), false-positive
avoidance, and truncated/corrupted compressed data.
"""
import base64
import gzip
import re
import struct
import zlib

import pytest

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding
import dumpex.hunt.encoding.classification as classification
import dumpex.hunt.encoding.decoding as decoding
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt.encoding.config import EncodingConfig


# ── _classify_decoded ──────────────────────────────────────────────────────

def test_classify_decoded_recognizes_valid_pe():
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    cls = classification._classify_decoded(pe_bytes)
    assert cls.kind == "pe"
    assert cls.is_pe is True


def test_classify_decoded_recognizes_shellcode_bootstrap():
    data = b'\xe8\x00\x00\x00\x00\x58' + b'\x90' * 100
    cls = classification._classify_decoded(data)
    assert cls.kind == "shellcode"
    assert cls.is_shellcode is True


def test_classify_decoded_finds_ioc_text():
    data = b"beacon check-in: http://185.220.101.5:8080/gate.php" + b" " * 50
    cls = classification._classify_decoded(data)
    assert cls.kind == "ioc_text"
    assert cls.ioc_strings


def test_classify_decoded_plain_text_has_no_ioc():
    data = b"the quick brown fox jumps over the lazy dog, nothing suspicious here at all" * 3
    cls = classification._classify_decoded(data)
    assert cls.kind == "plaintext"
    assert cls.ioc_strings == ()
    assert cls.is_pe is False
    assert cls.is_shellcode is False


def test_classify_decoded_high_entropy_binary():
    import random
    random.seed(3)
    data = bytes(random.getrandbits(8) for _ in range(4096))
    cls = classification._classify_decoded(data)
    assert cls.kind in ("high_entropy", "binary")
    assert cls.is_pe is False


def test_classify_decoded_too_short_is_binary():
    cls = classification._classify_decoded(b'\x01\x02')
    assert cls.kind == "binary"


# ── _is_plausible_ip ────────────────────────────────────────────────────────

def test_is_plausible_ip_accepts_public_address():
    assert classification._is_plausible_ip("185.220.101.5") is True
    assert classification._is_plausible_ip("185.220.101.5:8080") is True


def test_is_plausible_ip_rejects_private_ranges():
    assert classification._is_plausible_ip("10.0.0.1") is False
    assert classification._is_plausible_ip("172.16.0.1") is False
    assert classification._is_plausible_ip("172.31.255.255") is False
    assert classification._is_plausible_ip("192.168.1.1") is False
    assert classification._is_plausible_ip("169.254.1.1") is False
    assert classification._is_plausible_ip("127.0.0.1") is False
    assert classification._is_plausible_ip("0.0.0.5") is False


def test_is_plausible_ip_rejects_malformed():
    assert classification._is_plausible_ip("not.an.ip.address") is False
    assert classification._is_plausible_ip("1.2.3") is False
    assert classification._is_plausible_ip("1.2.3.4.5") is False
    assert classification._is_plausible_ip("300.1.1.1") is False
    assert classification._is_plausible_ip("1.1.1.1") is False   # all octets < 10


# ── _bounded_decompress ─────────────────────────────────────────────────────

def test_bounded_decompress_normal_payload():
    payload = zlib.compress(b"hello world" * 100)
    out, complete = decoding._bounded_decompress(payload, wbits=zlib.MAX_WBITS)
    assert out == b"hello world" * 100
    assert complete is True   # fully verified end-to-end (eof reached)


def test_bounded_decompress_caps_oversized_output():
    huge = b"\x00" * (encoding.DECOMPRESS_MAX_OUTPUT * 4)
    payload = zlib.compress(huge)
    out, complete = decoding._bounded_decompress(payload, wbits=zlib.MAX_WBITS)
    assert len(out) <= encoding.DECOMPRESS_MAX_OUTPUT
    assert complete is False   # cap hit before eof -- never verified end-to-end


def test_bounded_decompress_raises_on_truncated_payload():
    payload = zlib.compress(b"hello world" * 100)
    truncated = payload[:len(payload) // 2]
    with pytest.raises(zlib.error):
        decoding._bounded_decompress(truncated, wbits=zlib.MAX_WBITS)


def test_bounded_decompress_raises_when_only_trailing_checksum_missing():
    # Dropping just the last byte still leaves decompressobj able to emit
    # the FULL decoded output with no exception by default -- only the
    # eof check catches this. A truncated compressed PE must not be able
    # to pass through as if it were a complete, valid stream.
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    payload = zlib.compress(pe_bytes)
    truncated = payload[:-1]
    with pytest.raises(zlib.error):
        decoding._bounded_decompress(truncated, wbits=zlib.MAX_WBITS)


def test_bounded_decompress_does_not_raise_when_output_cap_hit_on_valid_stream():
    # A legitimately large (not truncated) payload that exceeds the output
    # cap must still be accepted, truncated at the cap -- only genuine
    # truncation should raise. It must still be reported as incomplete
    # (complete=False) since the checksum/end-of-stream was never reached --
    # callers must be able to tell this apart from a verified decode.
    huge = b"\x00" * (encoding.DECOMPRESS_MAX_OUTPUT * 4)
    payload = zlib.compress(huge)
    out, complete = decoding._bounded_decompress(payload, wbits=zlib.MAX_WBITS)
    assert len(out) == encoding.DECOMPRESS_MAX_OUTPUT
    assert complete is False


def test_bounded_decompress_incomplete_when_cap_hit_even_with_trailing_truncation():
    # The exact gap this test closes: a stream large enough to hit the
    # output cap, ADDITIONALLY truncated by its last byte far beyond the
    # cap. eof=False and unconsumed_tail is non-empty (more unexamined
    # input remains) either way, so this can't be distinguished from the
    # "merely capped, fully intact" case above by design -- what MUST hold
    # is that both report complete=False, so a caller never treats either
    # as a verified, fully end-to-end-checked decode.
    huge = b"\x00" * (encoding.DECOMPRESS_MAX_OUTPUT * 4)
    payload = zlib.compress(huge)
    truncated = payload[:-1]
    out, complete = decoding._bounded_decompress(truncated, wbits=zlib.MAX_WBITS)
    assert len(out) == encoding.DECOMPRESS_MAX_OUTPUT
    assert complete is False


# ── Base64 layer: plain text is observation-only, never scores ────────────

def test_base64_plaintext_no_ioc_is_observation_never_scored():
    plaintext = b"the quick brown fox jumps over the lazy dog repeatedly for padding purposes here"
    b64_payload = base64.b64encode(plaintext)
    region_base = 0x500000
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    tags = {finding["check"]: finding["tag"] for finding in f["findings"]}
    assert tags.get("obfuscation.base64_observation") == "observation"


def test_base64_ioc_text_is_lead_never_scored():
    plaintext = b"c2 callback: http://185.220.101.5:8080/gate.php more padding text follows here"
    b64_payload = base64.b64encode(plaintext)
    region_base = 0x510000
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    tags = {finding["check"]: finding["tag"] for finding in f["findings"]}
    assert tags.get("obfuscation.base64_observation") == "lead"


# ── XOR layer: random data without IOC/structural content never even ──────
# becomes a candidate (false-positive avoidance at the key-scoring stage)

def test_xor_random_data_produces_no_candidates():
    import random
    random.seed(11)
    region_base = 0x520000
    payload = bytes(random.getrandbits(8) for _ in range(0x1000))
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: payload})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    checks = {finding["check"] for finding in f["findings"]}
    assert "obfuscation.xor_observation" not in checks


def test_xor_decoded_ioc_content_is_observation_or_lead():
    key = 0x42
    plaintext = b"beacon http://185.220.101.5/submit.php callback data padding here for length"
    encoded = bytes(b ^ key for b in plaintext)
    region_base = 0x530000
    regions = [Region(region_base, region_base, len(encoded), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: encoded})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0   # XOR content alone never scores -- only structural payload does
    tags = {finding["check"]: finding["tag"] for finding in f["findings"]}
    assert tags.get("obfuscation.xor_observation") in ("observation", "lead")


def _basic_pe(**overrides):
    kwargs = dict(size_of_image=0x2000, trailing_padding=0x300)
    kwargs.update(overrides)
    return build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        **kwargs)


def _fresh_budget():
    return ScanBudget(max_bytes_read=10 ** 7, max_attempts=1000,
                       max_retained_bytes=10 ** 7, max_hits=100)


# ── XOR structural path: offset-independent key derivation (issue #27) ─────
# A binary PE payload must reach obfuscation.structural_payload regardless
# of WHERE in the region it sits, whether its sample looks printable, or
# whether it contains any configured IOC keyword -- none of which the old
# sample+printable/keyword heuristic (_scan_xor, tested above) could ever
# guarantee. See decoding._scan_xor_structural's own docstring.

def test_xor_structural_finds_pe_at_offset_zero_without_score_or_keywords():
    pe_bytes = _basic_pe()
    key = 0x37
    encoded = bytes(b ^ key for b in pe_bytes)

    # Prove this PE genuinely would NOT have passed the old prefix
    # heuristic -- a real PE header is mostly zero/binary, not printable.
    assert decoding._score_xor_key(encoded[:4096], key) < 0.68

    budget = _fresh_budget()
    hits = list(decoding._scan_xor_structural(encoded, 0x400000, budget))
    assert len(hits) == 1
    offset, found_key, decoded, cls = hits[0]
    assert offset == 0
    assert found_key == key
    assert cls.is_pe is True


def test_xor_structural_finds_pe_after_sample_window():
    # Non-printable padding, deliberately longer than XOR_SAMPLE_SIZE
    # (4096) -- the old sample-only heuristic never even looks this far
    # into the region.
    prefix = bytes((i * 37) % 256 for i in range(5000))
    pe_bytes = _basic_pe()
    key = 0x5A
    encoded = bytes(b ^ key for b in prefix + pe_bytes)

    budget = _fresh_budget()
    hits = list(decoding._scan_xor_structural(encoded, 0x500000, budget))
    assert len(hits) == 1
    offset, found_key, decoded, cls = hits[0]
    assert offset == 5000
    assert found_key == key
    assert cls.is_pe is True


def test_xor_structural_pe_not_displaced_by_full_text_candidate_cap(monkeypatch):
    """
    Reproduces the exact issue #27 failure mode: relax _scan_xor's gate to
    its most permissive form (xor_score_min=0.0, and an IOC pattern that
    matches any byte) so its 255-key candidate pool is entirely full --
    then verify a genuine XOR-encoded PE, placed where the SAME single-
    byte key also decodes the rest of the region, is found by the
    structural path regardless of what _scan_xor's own top-5 selection
    picked. `prefix` is built from every byte value in equal proportion
    (bytes(range(256)) repeated), so single-byte XOR gives every key the
    SAME printable-ratio score against it -- with all scores tied,
    Python's stable sort keeps candidates in ascending key order, so
    _scan_xor's top-5 is deterministically keys 1-5, never `real_key`.
    """
    monkeypatch.setattr(decoding, "_IOC_PAT", re.compile(r"."))

    real_key = 0x3C
    assert real_key not in (1, 2, 3, 4, 5)
    prefix = bytes(range(256)) * 2   # 512 bytes, uniform byte distribution
    pe_bytes = _basic_pe()
    data = prefix + pe_bytes
    encoded = bytes(b ^ real_key for b in data)

    config = EncodingConfig(xor_sample_size=len(prefix), xor_score_min=0.0)

    text_hits = list(decoding._scan_xor(encoded, 0x600000, _fresh_budget(), config))
    assert not any(cls.is_pe for _, _, _, cls in text_hits)
    assert real_key not in (key for _, key, _, _ in text_hits)

    struct_hits = list(decoding._scan_xor_structural(encoded, 0x600000, _fresh_budget(), config))
    assert any(key == real_key and cls.is_pe for _, key, _, cls in struct_hits)


def test_xor_structural_invalid_mz_decoy_does_not_score_and_does_not_block_later_candidate():
    # A decoy with a correct MZ + e_lfanew + PE\0\0 signature (so it passes
    # the cheap pre-filter) but an unrecognized Machine field, so full
    # structural validation (parse_pe_header) rejects it -- must not score,
    # and must not prevent a LATER, genuinely valid PE elsewhere in the
    # same region from being found.
    decoy = bytearray(_basic_pe())
    struct.pack_into('<H', decoy, 0x80 + 4, 0xDEAD)   # coff Machine field -> unrecognized
    decoy_key = 0x11
    encoded_decoy = bytes(b ^ decoy_key for b in decoy)

    real_pe = _basic_pe()
    real_key = 0x22
    encoded_real = bytes(b ^ real_key for b in real_pe)

    data = encoded_decoy + encoded_real
    budget = _fresh_budget()
    hits = list(decoding._scan_xor_structural(data, 0x700000, budget, EncodingConfig()))

    assert not any(key == decoy_key for _, key, _, _ in hits)
    real_hits = [(off, key, cls) for off, key, _, cls in hits if key == real_key]
    assert len(real_hits) == 1
    offset, key, cls = real_hits[0]
    assert offset == len(encoded_decoy)
    assert cls.is_pe is True


def test_xor_structural_many_low_key_decoys_do_not_block_later_real_candidate():
    """
    Regression for a follow-up report against the fix above: an earlier
    version of _scan_xor_structural discovered candidates KEY-BY-KEY
    (`for key in range(1, 256)`, searching the whole buffer per key) and
    capped the TOTAL yielded across ALL keys at a fixed per-region limit.
    Since the outer loop visited keys in ascending numeric order, 64+
    pre-filter-passing decoys sharing one (numerically low) key alone
    could exhaust that cap before a genuinely valid PE under a
    DIFFERENT, higher-numbered key was ever reached -- silently: 0 hits,
    budget.exhausted() still False, no coverage limitation recorded.
    Candidates are now discovered in a single OFFSET-ordered pass with no
    per-region cap at all (see decoding.py's own docstring), so this must
    find the real PE regardless of how many same-key decoys preceded it.
    """
    decoy_key = 0x01
    decoy = bytearray(_basic_pe())
    struct.pack_into('<H', decoy, 0x80 + 4, 0xDEAD)   # unrecognized Machine -> invalid PE
    encoded_decoy = bytes(b ^ decoy_key for b in decoy)
    decoys = encoded_decoy * 64   # 64 pre-filter-passing, structurally-invalid decoys

    real_key = 0xFE   # numerically later than decoy_key in the old per-key iteration order
    encoded_real = bytes(b ^ real_key for b in _basic_pe())

    data = decoys + encoded_real
    budget = _fresh_budget()
    hits = list(decoding._scan_xor_structural(data, 0x720000, budget, EncodingConfig()))

    assert not any(key == decoy_key for _, key, _, _ in hits)
    real_hits = [(off, cls) for off, key, _, cls in hits if key == real_key]
    assert len(real_hits) == 1
    offset, cls = real_hits[0]
    assert offset == len(decoys)
    assert cls.is_pe is True
    assert not budget.exhausted()


def test_xor_structural_budget_exhaustion_reports_partial_not_silent_miss(monkeypatch):
    """
    Unlike the region-local cap removed above, the shared whole-hunt
    ScanBudget genuinely running out partway through the candidate scan
    MUST be visible to the caller: coverage_status becomes "partial" with
    a reason naming the budget, never a clean 0-hit report that reads the
    same as "nothing was there."
    """
    monkeypatch.setattr(encoding, "ENCODING_BUDGET_MAX_ATTEMPTS", 5)

    decoy_key = 0x01
    decoy = bytearray(_basic_pe())
    struct.pack_into('<H', decoy, 0x80 + 4, 0xDEAD)
    encoded_decoy = bytes(b ^ decoy_key for b in decoy)
    decoys = encoded_decoy * 10   # more decoys than the (monkeypatched) attempt budget

    real_key = 0xFE
    encoded_real = bytes(b ^ real_key for b in _basic_pe())

    data = decoys + encoded_real
    region_base = 0x730000
    regions = [Region(region_base, region_base, len(data), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: data})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0   # attempt budget ran out before the real PE, past all 10 decoys
    assert f["coverage_status"] == "partial"
    assert any("budget" in r.lower() for r in f["coverage_reasons"])


def test_xor_structural_reports_correct_va_and_file_offset(capsys, monkeypatch):
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: 0x9000 + va)

    padding = bytes((i * 13) % 256 for i in range(4300))   # past XOR_SAMPLE_SIZE
    pe_bytes = _basic_pe()
    key = 0x66
    region_base = 0x710000
    encoded = bytes(b ^ key for b in padding + pe_bytes)
    regions = [Region(region_base, region_base, len(encoded), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: encoded})

    f = encoding._hunt_encoding(MF(), verbose=True)
    assert f["score"] == 1
    assert len(f["hidden_pe"]) == 1
    hit = f["hidden_pe"][0]
    assert hit["key"] == key
    assert hit["offset"] == len(padding)   # region-relative offset of the actual candidate, not 0
    assert hit["region"]["BaseAddress"] == region_base

    expected_va = region_base + len(padding)
    expected_file_offset = 0x9000 + expected_va
    out = capsys.readouterr().out
    assert f"container_VA=0x{expected_va:016x}" in out   # structural_payload's own fact
    assert f"VA=0x{expected_va:016x}" in out             # xor_observation's verbose fact (same hit)
    assert f"File_offset=0x{expected_file_offset:x}" in out
    assert f"XOR_key=0x{key:02x}" in out


# ── GZIP/ZLIB layer ─────────────────────────────────────────────────────────

def test_gzip_plaintext_payload_is_observation_never_scored():
    plaintext = b"ordinary log text, nothing structural or IOC-bearing in here at all, just filler"
    payload = gzip.compress(plaintext)
    region_base = 0x540000
    regions = [Region(region_base, region_base, len(payload) + 0x100, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: payload.ljust(len(payload) + 0x100, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0


def test_gzip_containing_pe_scores():
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    payload = gzip.compress(pe_bytes)
    region_base = 0x550000
    regions = [Region(region_base, region_base, len(payload) + 0x100, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: payload.ljust(len(payload) + 0x100, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 1
    assert f["confidence"] == "high"


def test_gzip_pe_truncated_beyond_output_cap_scores_at_reduced_confidence():
    # A decompressed stream far larger than DECOMPRESS_MAX_OUTPUT, containing
    # a valid PE at the very start, truncated by its last byte -- the
    # truncation sits well past the point _bounded_decompress stops (the
    # output cap), so the PE prefix genuinely decodes and is a real
    # detection. But the source stream was never verified end-to-end (eof
    # never reached), so this must NOT read as the same HIGH confidence as
    # a fully-verified decode.
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    huge = pe_bytes + b"\x00" * (encoding.DECOMPRESS_MAX_OUTPUT * 4)
    payload = gzip.compress(huge)[:-1]   # drop the last byte (well past the cap)
    region_base = 0x565000
    regions = [Region(region_base, region_base, len(payload) + 0x100, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: payload.ljust(len(payload) + 0x100, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 1
    pe_finding = next(fd for fd in f["findings"] if fd["check"] == "obfuscation.structural_payload")
    assert pe_finding["confidence"] == "medium"
    assert any("output cap" in lim or "output-cap" in lim for lim in pe_finding["limitations"])


def test_mixed_complete_and_incomplete_pe_hits_stay_high_confidence():
    # One region with a small, fully-verified (complete=True) compressed PE
    # and a SEPARATE region with a huge, output-cap-truncated (complete=
    # False) one -- both land in the same obfuscation.structural_payload
    # finding. The fully-verified hit alone is enough to justify HIGH
    # confidence; a single additional unverified hit must not drag the
    # whole finding down to MEDIUM (only an ALL-incomplete batch should).
    small_pe = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    complete_payload = gzip.compress(small_pe)
    complete_base = 0x566000
    complete_region = Region(complete_base, complete_base, len(complete_payload) + 0x100,
                              "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")

    huge_pe = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                 "rawptr": 0x400, "rawsize": 0x200,
                                 "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                               size_of_image=0x2000, trailing_padding=0x300)
    huge_pe += b"\x00" * (encoding.DECOMPRESS_MAX_OUTPUT * 4)
    incomplete_payload = gzip.compress(huge_pe)[:-1]
    incomplete_base = 0x567000
    incomplete_region = Region(incomplete_base, incomplete_base, len(incomplete_payload) + 0x100,
                                "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")

    regions = [complete_region, incomplete_region]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({
        complete_base:   complete_payload.ljust(len(complete_payload) + 0x100, b'\x00'),
        incomplete_base: incomplete_payload.ljust(len(incomplete_payload) + 0x100, b'\x00'),
    })

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 1
    pe_finding = next(fd for fd in f["findings"] if fd["check"] == "obfuscation.structural_payload")
    assert pe_finding["confidence"] == "high"
    # Still disclosed even though confidence wasn't downgraded.
    assert any("output cap" in lim or "output-cap" in lim for lim in pe_finding["limitations"])


def test_truncated_gzip_magic_does_not_crash_or_score():
    # Real GZIP magic bytes, but the stream is corrupted/truncated right
    # after -- must be caught (zlib.error) and skipped, not propagate a
    # crash or a false-positive score.
    corrupted = b'\x1f\x8b\x08\x00' + b'\xff' * 200   # magic + bogus flags + garbage
    region_base = 0x560000
    regions = [Region(region_base, region_base, len(corrupted), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: corrupted})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0   # must not crash, must not falsely score


# ── high entropy alone (legitimate compressed/packed data) never scores ───

def test_high_entropy_private_region_never_scores_alone():
    import random
    random.seed(5)
    region_base = 0x570000
    data = bytes(random.getrandbits(8) for _ in range(0x2000))   # near-max entropy
    regions = [Region(region_base, region_base, len(data), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: data})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    tags = {finding["check"]: finding["tag"] for finding in f["findings"]}
    if "obfuscation.entropy_observation" in tags:
        assert tags["obfuscation.entropy_observation"] == "observation"
