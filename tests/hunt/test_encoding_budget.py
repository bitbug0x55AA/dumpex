"""
Tests for dumpex.hunt.encoding's shared decode budget (ENCODING_BUDGET_*)
and cross-layer partial-failure combinations -- a scan-budget exhaustion
or a single layer's read failure must show up as coverage_status=partial/
INCONCLUSIVE with a specific reason, and must never silently suppress a
detection an OTHER layer still found (DETECTED + partial must be allowed
to coexist, matching dumpex/schemas/dumpex-output-v1.0.schema.json's own
DETECTED+partial invariant).
"""
import base64

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding


def _b64_region(region_base, payload, pad_to=0x1000):
    return {region_base: base64.b64encode(payload).ljust(pad_to, b'\x00')}


# ── decode attempt budget exhaustion -> partial coverage ──────────────────

def test_decode_attempt_budget_exhaustion_is_partial(monkeypatch):
    monkeypatch.setattr(encoding, "ENCODING_BUDGET_MAX_ATTEMPTS", 1)
    region_base_1 = 0x600000
    region_base_2 = 0x610000
    # Two separate Base64 candidates in two separate regions -- the second
    # attempt should never happen once the 1-attempt budget is spent on
    # the first.
    payload = b"IOC text with http://185.220.101.5/x padding padding padding padding"
    regions = [
        Region(region_base_1, region_base_1, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(region_base_2, region_base_2, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    read_map = {}
    read_map.update(_b64_region(region_base_1, payload))
    read_map.update(_b64_region(region_base_2, payload))
    encoding.read_region = mem_reader(read_map)

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["coverage_status"] == "partial"
    assert any("budget" in r.lower() for r in f["coverage_reasons"])


# ── a read failure in one region must not suppress a detection found ──────
# in a DIFFERENT region -- DETECTED + partial coverage must coexist.

def test_one_region_read_failure_does_not_suppress_other_regions_detection():
    good_base = 0x620000
    bad_base  = 0x630000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [
        Region(good_base, good_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(bad_base, bad_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]

    def flaky_reader(mf, addr, size):
        if addr == bad_base:
            raise OSError("simulated read failure")
        return b64_pe.ljust(0x1000, b'\x00')

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = flaky_reader

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "partial"
    assert any("failed to read" in r for r in f["coverage_reasons"])


# ── retained-bytes budget: a huge decoded payload must not silently ───────
# exceed the cumulative retention cap without being reflected in coverage

def test_retained_bytes_budget_limits_hits(monkeypatch):
    monkeypatch.setattr(encoding, "ENCODING_BUDGET_MAX_RETAINED", 32)
    region_base = 0x640000
    payload = b"IOC text with http://185.220.101.5/gate padding padding padding padding padding"
    assert len(payload) > 32   # decoded size must exceed the cap for this test to be meaningful
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader(_b64_region(region_base, payload))

    f = encoding._hunt_encoding(MF(), verbose=False)
    # The decoded candidate (len(payload) bytes) cannot fit under a 32-byte
    # retention cap, so take_hit() must reject it deterministically: no
    # base64 finding at all, and coverage must say why -- not silently
    # claim complete coverage while dropping a candidate.
    assert not f.get("base64")
    assert f["coverage_status"] == "partial"
    assert f["budget_exhausted"] is True
    assert any("max_retained_bytes" in r for r in f["coverage_reasons"])
