"""Hunter-level tests for dumpex.hunt.encoding (obfuscation/entropy/Base64/GZIP)."""
import base64
import random

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding


# ── arbitrary data starting with call/pop -> never scored ─────────────────

def test_call_pop_prefix_never_scores():
    random.seed(2)
    region_base = 0x400000
    shellcode_prefix = b'\xe8\x00\x00\x00\x00\x58'
    payload = shellcode_prefix + bytes(random.getrandbits(8) for _ in range(200))
    b64_payload = base64.b64encode(payload)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert f["score"] == 0
    assert tags.get("obfuscation.shellcode_bootstrap_lead") == ("lead", "low")
    assert "obfuscation.structural_payload" not in tags


# ── same shellcode-bootstrap prefix, but the containing region is ─────────
# ALSO executable+private (MEM_PRIVATE + PAGE_EXECUTE_READWRITE) -- the
# combination is a stronger lead than the bare pattern match above, so
# confidence is raised to medium, but it still must never score.

def test_call_pop_prefix_in_rwx_private_region_raises_lead_confidence():
    random.seed(2)
    region_base = 0x410000
    shellcode_prefix = b'\xe8\x00\x00\x00\x00\x58'
    payload = shellcode_prefix + bytes(random.getrandbits(8) for _ in range(200))
    b64_payload = base64.b64encode(payload)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert f["score"] == 0
    assert tags.get("obfuscation.shellcode_bootstrap_lead") == ("lead", "medium")
    assert "obfuscation.structural_payload" not in tags


# ── Bonus: a validated PE payload (even Base64-wrapped) still scores ──────

def test_validated_pe_still_scores():
    region_base = 0x300000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_pe.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 1
    assert f["confidence"] == "high"


# ── a short read in ANY of the three region-scanning layers (sleep-mask, ──
# entropy, decode) must not be silently treated as a complete scan — the
# unread tail could hide a real payload. Each test below isolates ONE
# layer via its own filter differences (region size vs. the other layers'
# thresholds, or MEM_IMAGE vs MEM_PRIVATE) so a regression in only one
# layer's short-read counting would be caught precisely.

def test_sleep_mask_layer_short_read_makes_result_inconclusive():
    region_base = 0x500000
    declared_size = 0x2000   # passes sleep-mask's own size floor (1300 bytes)
    actual_bytes  = b'\x00' * 0x400   # far short of declared_size
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: actual_bytes})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])


def test_entropy_layer_short_read_makes_result_inconclusive():
    region_base = 0x600000
    # Between DECODE_SCAN_MAX (2 MB) and ENTROPY_SCAN_MAX (10 MB), and not
    # PAGE_READWRITE -- decode is size-skipped and sleep-mask is protect-
    # filtered before either ever attempts a read, isolating this short
    # read to the entropy layer alone.
    declared_size = 3 * 1024 * 1024
    actual_bytes  = b'\x00' * 0x400
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READONLY", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: actual_bytes})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])


def test_decode_layer_short_read_makes_result_inconclusive():
    region_base = 0x700000
    # MEM_IMAGE -- both sleep-mask and entropy require MEM_PRIVATE and
    # skip this before ever reading, isolating this short read to the
    # decode layer alone (decode accepts MEM_PRIVATE or MEM_IMAGE).
    declared_size = 0x2000
    actual_bytes  = b'\x00' * 0x400
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")   # no modules -> not classified as a system DLL
    encoding.read_region = mem_reader({region_base: actual_bytes})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])
