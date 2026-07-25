"""Hunter-level tests for dumpex.hunt.stomping (Module Stomping detection)."""
import os
import tempfile

from fakes import (Region, Module, FakeStream, FakeMF, build_pe_header,
                    TEXT_SECTION_RX, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                    mem_reader, matching_module_and_ref)

import dumpex.hunt.stomping as stomping


# ── normal DLL + PAGE_EXECUTE_WRITECOPY, matching reference -> CLEAN ──────

def test_normal_writecopy_is_clean():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["coverage_status"] == "complete"


# ── no --ref-dir at all -> INCONCLUSIVE/partial, never a bare CLEAN ───────

def test_no_ref_dir_is_inconclusive_partial():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"


# ── --ref-dir given but empty (no matching file) -> INCONCLUSIVE/partial ──

def test_empty_ref_dir_is_inconclusive_partial():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)   # empty dir, no legit.dll in it
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_counts"]["reference_missing"] >= 1


# ── relocation-only difference (ASLR-relocated, content unchanged) must ───
# NOT be detected once normalized, end to end through the hunter ──────────

def test_relocation_only_diff_not_detected():
    import struct
    from dumpex.core.pe_utils import parse_pe_header, IMAGE_REL_BASED_DIR64, apply_base_relocations

    preferred_base = 0x140000000
    actual_base    = 0x140050000   # loaded 0x50000 above preferred -> real ASLR-style delta
    text_vaddr, text_size = 0x1000, 0x2000
    reloc_vaddr = 0x4000

    text_bytes = bytearray((i * 3) % 251 for i in range(text_size))
    abs_ptr_off = 0x40
    struct.pack_into('<Q', text_bytes, abs_ptr_off, preferred_base + 0x2000)

    page_rva = text_vaddr & ~0xFFF
    offset_in_page = (text_vaddr + abs_ptr_off) - page_rva
    entry = (IMAGE_REL_BASED_DIR64 << 12) | offset_in_page
    reloc_data = struct.pack('<II', page_rva, 8 + 2) + struct.pack('<H', entry)

    sections = [
        {"name": b".text", "vaddr": text_vaddr, "vsize": text_size, "rawptr": 0x400,
         "rawsize": text_size, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ},
        {"name": b".reloc", "vaddr": reloc_vaddr, "vsize": len(reloc_data),
         "rawptr": 0x400 + text_size, "rawsize": len(reloc_data), "chars": IMAGE_SCN_MEM_READ},
    ]
    header = build_pe_header(sections, timestamp=0x33333333, size_of_image=0x6000,
                              image_base=preferred_base)
    header = bytearray(header)
    opt_off = header.index(b'PE\x00\x00') + 24  # e_lfanew is fixed at 0x80 in build_pe_header
    struct.pack_into('<I', header, opt_off + 108, 16)
    struct.pack_into('<II', header, opt_off + 112 + 5 * 8, reloc_vaddr, len(reloc_data))
    header = bytes(header)

    ref_file = bytearray(header)
    ref_file += b'\x00' * (sections[0]["rawptr"] - len(ref_file))
    ref_file += bytes(text_bytes)
    ref_file += reloc_data

    # Memory content: SAME as disk, except the one absolute pointer is
    # relocated by (actual_base - preferred_base), exactly as the real
    # Windows loader would do — i.e. genuinely unmodified content.
    mem_text = bytearray(text_bytes)
    struct.pack_into('<Q', mem_text, abs_ptr_off, preferred_base + 0x2000 + (actual_base - preferred_base))

    module_base = actual_base
    mods = [Module(module_base, 0x6000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + text_vaddr, module_base, text_size,
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + text_vaddr: bytes(mem_text)})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))
        f = stomping._hunt_stomping(MF(), verbose=True, ref_dir=d)

    assert f["score"] == 0, "relocation-only difference must normalize away"


# ── all module headers invalid -> PARTIAL, not clean-complete ─────────────

def test_all_headers_invalid_is_partial_not_clean():
    module_base = 0x7ff600000000
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: b'NOTMZHEADERGARBAGE' + b'\x00' * 100})

    f = stomping._hunt_stomping(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] != "NOT_DETECTED_IN_SCANNED_SCOPE", \
        "must not silently claim clean-complete when every module header failed to parse"
    assert f["coverage_status"] == "partial"


# ── same-name, different-version reference DLL -> must not escalate ───────

def test_version_mismatched_reference_does_not_escalate():
    module_base = 0x7ff600000000
    mem_header = build_pe_header([TEXT_SECTION_RX], timestamp=0x11111111, size_of_image=0x5000)
    ref_header = bytearray(build_pe_header([TEXT_SECTION_RX], timestamp=0x22222222, size_of_image=0x5000))
    ref_header[0x400:0x400 + 0x2000] = os.urandom(0x2000)   # different build's .text, deliberately

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_IMAGE")]   # protection anomaly too

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: mem_header})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_header))
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["score"] == 0, "version-mismatched reference must not produce a score"


# ── RIP inside the 21st+ differing range still scores 2 ───────────────────

def test_rip_in_deep_diff_range_still_scores():
    module_base = 0x7ff600000000
    section = dict(TEXT_SECTION_RX)
    section["vsize"] = section["rawsize"] = 0x4000   # room for many small diffs
    timestamp = 0x44444444
    header = build_pe_header([section], timestamp=timestamp, size_of_image=0x6000,
                              image_base=module_base)
    text_original = bytes((i * 5) % 251 for i in range(section["vsize"]))

    # 25 separated single-byte diffs (indices > MAX_DIFF_RANGES=20), each
    # its own contiguous range so the 21st..25th are only reachable if the
    # RIP scan looks past the first 20.
    mem_text = bytearray(text_original)
    diff_positions = [64 * i for i in range(25)]   # far enough apart to stay separate ranges
    for pos in diff_positions:
        mem_text[pos] ^= 0xFF

    ref_file = bytearray(header)
    ref_file += b'\x00' * (section["rawptr"] - len(ref_file))
    ref_file += text_original

    mods = [Module(module_base, 0x6000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: bytes(mem_text)})

    # RIP lands exactly on the 25th (last, well past MAX_DIFF_RANGES=20) diff.
    rip_pos = diff_positions[-1]
    rip_va  = module_base + section["vaddr"] + rip_pos
    stomping.get_thread_contexts = lambda mf: [{"ThreadId": 1, "ip": rip_va,
                                                  "ip_reg": "RIP", "is_wow64": False}]

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))
        f = stomping._hunt_stomping(MF(), verbose=True, ref_dir=d)

    vc = f["verified_changes"][0]
    assert vc["total_ranges"] >= 21
    assert len(vc["diff_ranges"]) <= 20   # display-capped
    assert f["score"] == 2, "RIP in a range beyond the display cap must still score"


# ── short memory read must not be miscounted as a full comparison ─────────

def test_short_read_not_counted_as_compared():
    module_base = 0x7ff600000000
    header, mem_text_full, ref_file, section = matching_module_and_ref(module_base)
    # Only half the section's declared size_of_raw_data is actually
    # readable from memory (e.g. a partially-paged-out/truncated region).
    # This must be a coverage gap (short_reads), never a "clean" comparison
    # over whatever partial bytes happened to be readable -- silently
    # shrinking the comparison window could hide a real diff sitting past
    # the truncation point.
    truncated_mem = mem_text_full[:len(mem_text_full) // 2]
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header,
                                        module_base + section["vaddr"]: truncated_mem})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["score"] == 0
    assert f["coverage_counts"]["short_reads"] >= 1
    assert f["coverage_counts"]["sections_compared"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"


# ── relocation normalization failure must gate the diff, not fall back ────
# to comparing un-normalized bytes (which would misreport every
# relocation-touched instruction as "modified").

def test_relocation_failure_gates_comparison():
    module_base    = 0x7ff600000000
    preferred_base = 0x140000000        # != module_base -> delta != 0
    ARM64_MACHINE  = 0xaa64             # recognized, but not in
                                         # _RELOCATION_SUPPORTED_MACHINES
    section = dict(TEXT_SECTION_RX)
    header = build_pe_header([section], machine=ARM64_MACHINE, timestamp=0x22222222,
                              size_of_image=0x5000, image_base=preferred_base)
    text_bytes = bytes((i * 7) % 251 for i in range(section["vsize"]))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (section["rawptr"] - len(ref_file))
    ref_file += text_bytes

    # Memory content actually DIFFERS from disk. If the relocation gate
    # were bypassed, this would misreport as a verified content change
    # purely from the unnormalized ASLR delta, not real tampering.
    mem_text = bytearray(text_bytes)
    mem_text[0x10:0x14] = b'\xAA\xAA\xAA\xAA'

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header,
                                        module_base + section["vaddr"]: bytes(mem_text)})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["score"] == 0
    assert f["coverage_counts"]["relocation_failed"] >= 1
    assert f["coverage_counts"]["sections_compared"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"


# ── verdict_level must not say "clean" under NOT_EVALUATED/INCONCLUSIVE ───

def test_verdict_level_not_clean_when_inconclusive():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    assert f["status"] == "INCONCLUSIVE"
    assert f["verdict_level"] == "inconclusive"


def test_verdict_level_not_evaluated_when_streams_missing():
    class MF(FakeMF):
        memory_info = None
        modules      = None

    f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    assert f["status"] == "NOT_EVALUATED"
    assert f["verdict_level"] == "not_evaluated"


# ── Bonus: genuine-detection paths must still work (no false negatives) ───

def test_verified_change_scores_1_then_2_with_rip():
    module_base = 0x7ff600000000
    timestamp = 0x11111111
    sections = [{"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
                 "rawsize": 0x2000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}]
    # image_base matches module_base -> delta == 0, so this test exercises
    # the content-diff/RIP-corroboration path in isolation, without also
    # depending on relocation normalization (covered separately above and
    # in tests/unit/test_pe_utils.py).
    header = build_pe_header(sections, timestamp=timestamp, size_of_image=0x5000,
                              image_base=module_base)

    text_original = bytes((i * 7) % 251 for i in range(0x2000))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (sections[0]["rawptr"] - len(ref_file))
    ref_file += text_original

    mem_text = bytearray(text_original)
    mem_text[0x100:0x110] = b'\xCC' * 0x10   # simulated stomp

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]
    read_map = {module_base: header, module_base + 0x1000: bytes(mem_text)}

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))

        stomping.read_region = mem_reader(read_map)
        stomping.get_thread_contexts = lambda mf: []
        f1 = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        assert f1["score"] == 1

        changed_va = module_base + 0x1000 + 0x100
        stomping.get_thread_contexts = lambda mf: [{"ThreadId": 1, "ip": changed_va + 2,
                                                      "ip_reg": "RIP", "is_wow64": False}]
        f2 = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        assert f2["score"] == 2
