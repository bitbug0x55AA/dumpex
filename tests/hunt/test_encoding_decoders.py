"""
Unit/hunter-level tests for dumpex.hunt.encoding's classification helpers
(_classify_decoded, _is_plausible_ip, _bounded_decompress) and the
Base64/XOR/GZIP/ZLIB decode layers -- legitimate structural content,
plain non-IOC content (observation only, never scored), false-positive
avoidance, and truncated/corrupted compressed data.
"""
import base64
import gzip
import zlib

import pytest

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding
import dumpex.hunt.encoding.classification as classification
import dumpex.hunt.encoding.decoding as decoding


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
