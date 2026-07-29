"""Unit and end-to-end tests for dumpex.hunt.yara_hunt.context — the
PE_In_Private_Memory suppression/classification policy that decides
whether a hit is suppressed (legitimate module), a confirmed private-
memory detection, or context_unverified (can't be confidently classified
either way). A regression here can directly cause a DFIR false positive
(a legitimate module's PE header reported as a hidden PE) or a false
negative (a genuinely hidden PE silently suppressed).
"""
import os
import tempfile

import pytest

from tests.fixtures.fakes import Region, Module, Segment, FakeReader, FakeStream, FakeMF

import dumpex.hunt.yara_hunt.context as context
import dumpex.hunt.yara_hunt as yara_hunt


def _write_rule(d, name, body):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(body)


# ── classify_pe_in_private_memory_hit: all six MemoryContext outcomes ────

def test_classify_image_via_module_match_is_suppressed():
    addr = 0x1000
    modules = [Module(0x1000, 0x2000, r"C:\Windows\System32\ntdll.dll")]
    suppressed, unverified, ctx_value = context.classify_pe_in_private_memory_hit(
        addr, modules, [], modules_available=True, mem_info_available=False)
    assert suppressed is True
    assert unverified is False
    assert ctx_value == "image"


def test_classify_image_via_mem_image_region_is_suppressed():
    addr = 0x2000
    regions = [Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]
    suppressed, unverified, ctx_value = context.classify_pe_in_private_memory_hit(
        addr, [], regions, modules_available=False, mem_info_available=True)
    assert suppressed is True
    assert unverified is False
    assert ctx_value == "image"


def test_classify_mem_private_is_confirmed_detection():
    addr = 0x3000
    regions = [Region(0x3000, 0x3000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    suppressed, unverified, ctx_value = context.classify_pe_in_private_memory_hit(
        addr, [], regions, modules_available=False, mem_info_available=True)
    assert suppressed is False
    assert unverified is False
    assert ctx_value == "private"


def test_classify_unregistered_is_confirmed_detection():
    # ModuleList IS available (so a negative answer means something) but no
    # module covers this address, and MemoryInfo has no region for it either.
    addr = 0x4000
    modules = [Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    suppressed, unverified, ctx_value = context.classify_pe_in_private_memory_hit(
        addr, modules, [], modules_available=True, mem_info_available=False)
    assert suppressed is False
    assert unverified is False
    assert ctx_value == "unregistered"


def test_classify_mem_mapped_is_unverified_other():
    addr = 0x5000
    regions = [Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]
    suppressed, unverified, ctx_value = context.classify_pe_in_private_memory_hit(
        addr, [], regions, modules_available=False, mem_info_available=True)
    assert suppressed is False
    assert unverified is True
    assert ctx_value == "other"


def test_classify_unknown_when_no_context_source_available():
    addr = 0x6000
    suppressed, unverified, ctx_value = context.classify_pe_in_private_memory_hit(
        addr, [], [], modules_available=False, mem_info_available=False)
    assert suppressed is False
    assert unverified is True
    assert ctx_value == "unknown"


# ── context_unverified_reason: unknown / other / mixed / empty ───────────

def test_context_unverified_reason_unknown_only():
    reason = context.context_unverified_reason({"unknown"})
    assert reason == "no ModuleList/MemoryInfo available to classify"


def test_context_unverified_reason_other_only():
    reason = context.context_unverified_reason({"other"})
    assert reason == "region type is neither MEM_IMAGE nor MEM_PRIVATE, e.g. MEM_MAPPED"


def test_context_unverified_reason_mixed():
    reason = context.context_unverified_reason({"unknown", "other"})
    assert "no ModuleList/MemoryInfo available to classify" in reason
    assert "region type is neither MEM_IMAGE nor MEM_PRIVATE, e.g. MEM_MAPPED" in reason
    assert reason.count(";") == 1


def test_context_unverified_reason_empty_set_has_fallback():
    assert context.context_unverified_reason(set()) == "context could not be verified"


# ── end-to-end _hunt_yara: MEM_IMAGE suppression / MEM_PRIVATE detection / ──
# MEM_MAPPED downgrade to context_unverified
#
# yara-python is an optional ("full") dependency -- a module-level
# `pytest.importorskip("yara")` would skip the whole FILE, including the
# ten pure classify_pe_in_private_memory_hit/context_unverified_reason
# tests above that need no YARA engine at all. Only these three genuine
# end-to-end tests (which compile and run a real rule) are skipped when
# it's missing.

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

_needs_yara = pytest.mark.skipif(not _HAS_YARA, reason="yara-python not installed")

_PE_RULE = ('rule PE_In_Private_Memory { strings: $mz = "MZ" $pe = "PE\\x00\\x00" '
            'condition: $mz at 0 and $pe }')


def _pe_like_data() -> bytes:
    # 'MZ' at offset 0, 'PE\x00\x00' somewhere after -- enough to satisfy
    # the rule's condition regardless of real PE header validity (YARA
    # itself does no structural PE validation).
    return b'MZ' + b'\x00' * 60 + b'PE\x00\x00' + b'\x00' * 200


@_needs_yara
def test_pe_hit_in_mem_image_region_is_suppressed_end_to_end():
    seg_va, seg_fo = 0x70000, 0x7000
    data = _pe_like_data()
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "pe.yar", _PE_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            modules               = None
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["matches"] == []


@_needs_yara
def test_pe_hit_in_mem_private_region_is_detected_end_to_end():
    seg_va, seg_fo = 0x80000, 0x8000
    data = _pe_like_data()
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "pe.yar", _PE_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            modules               = None
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert "PE_In_Private_Memory" in f["rules_hit"]
    assert f["matches"][0]["context_unverified"] is False
    assert f["matches"][0]["memory_context"] == "private"


@_needs_yara
def test_pe_hit_in_mem_mapped_region_is_context_unverified_end_to_end():
    seg_va, seg_fo = 0x90000, 0x9000
    data = _pe_like_data()
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "pe.yar", _PE_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            modules               = None
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert len(f["matches"]) == 1
    assert f["matches"][0]["context_unverified"] is True
    assert f["matches"][0]["memory_context"] == "other"
    assert "PE_In_Private_Memory" not in f["rules_hit"]
