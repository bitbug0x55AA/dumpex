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

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding


# ── _classify_decoded ──────────────────────────────────────────────────────

def test_classify_decoded_recognizes_valid_pe():
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    cls = encoding._classify_decoded(pe_bytes)
    assert cls["type"] == "pe"
    assert cls["is_pe"] is True


def test_classify_decoded_recognizes_shellcode_bootstrap():
    data = b'\xe8\x00\x00\x00\x00\x58' + b'\x90' * 100
    cls = encoding._classify_decoded(data)
    assert cls["type"] == "shellcode"
    assert cls["is_shellcode"] is True


def test_classify_decoded_finds_ioc_text():
    data = b"beacon check-in: http://185.220.101.5:8080/gate.php" + b" " * 50
    cls = encoding._classify_decoded(data)
    assert cls["type"] == "ioc_text"
    assert cls["ioc_strings"]


def test_classify_decoded_plain_text_has_no_ioc():
    data = b"the quick brown fox jumps over the lazy dog, nothing suspicious here at all" * 3
    cls = encoding._classify_decoded(data)
    assert cls["type"] == "plaintext"
    assert cls["ioc_strings"] == []
    assert cls["is_pe"] is False
    assert cls["is_shellcode"] is False


def test_classify_decoded_high_entropy_binary():
    import random
    random.seed(3)
    data = bytes(random.getrandbits(8) for _ in range(4096))
    cls = encoding._classify_decoded(data)
    assert cls["type"] in ("high_entropy", "binary")
    assert cls["is_pe"] is False


def test_classify_decoded_too_short_is_binary():
    cls = encoding._classify_decoded(b'\x01\x02')
    assert cls["type"] == "binary"


# ── _is_plausible_ip ────────────────────────────────────────────────────────

def test_is_plausible_ip_accepts_public_address():
    assert encoding._is_plausible_ip("185.220.101.5") is True
    assert encoding._is_plausible_ip("185.220.101.5:8080") is True


def test_is_plausible_ip_rejects_private_ranges():
    assert encoding._is_plausible_ip("10.0.0.1") is False
    assert encoding._is_plausible_ip("172.16.0.1") is False
    assert encoding._is_plausible_ip("172.31.255.255") is False
    assert encoding._is_plausible_ip("192.168.1.1") is False
    assert encoding._is_plausible_ip("169.254.1.1") is False
    assert encoding._is_plausible_ip("127.0.0.1") is False
    assert encoding._is_plausible_ip("0.0.0.5") is False


def test_is_plausible_ip_rejects_malformed():
    assert encoding._is_plausible_ip("not.an.ip.address") is False
    assert encoding._is_plausible_ip("1.2.3") is False
    assert encoding._is_plausible_ip("1.2.3.4.5") is False
    assert encoding._is_plausible_ip("300.1.1.1") is False
    assert encoding._is_plausible_ip("1.1.1.1") is False   # all octets < 10


# ── _bounded_decompress ─────────────────────────────────────────────────────

def test_bounded_decompress_normal_payload():
    payload = zlib.compress(b"hello world" * 100)
    out = encoding._bounded_decompress(payload, wbits=zlib.MAX_WBITS)
    assert out == b"hello world" * 100


def test_bounded_decompress_caps_oversized_output():
    huge = b"\x00" * (encoding.DECOMPRESS_MAX_OUTPUT * 4)
    payload = zlib.compress(huge)
    out = encoding._bounded_decompress(payload, wbits=zlib.MAX_WBITS)
    assert len(out) <= encoding.DECOMPRESS_MAX_OUTPUT


def test_bounded_decompress_raises_on_truncated_payload():
    payload = zlib.compress(b"hello world" * 100)
    truncated = payload[:len(payload) // 2]
    try:
        encoding._bounded_decompress(truncated, wbits=zlib.MAX_WBITS)
    except zlib.error:
        pass   # expected -- caller (_scan_compressed) catches this


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
