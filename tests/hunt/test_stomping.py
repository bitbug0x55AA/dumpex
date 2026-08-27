"""Hunter-level tests for dumpex.hunt.stomping (Module Stomping detection)."""
import os
import tempfile

from tests.fixtures.fakes import (Region, Module, FakeStream, FakeMF, build_pe_header,
                                   TEXT_SECTION_RX, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader, matching_module_and_ref)

import dumpex.hunt.stomping as stomping
from dumpex.hunt.stomping.config import IOC_SCAN_MAX


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


# ── --ref-dir="" (empty string, not None) must behave exactly like no ─────
# --ref-dir at all: `ref_dir_supplied` must normalize on truthiness, not on
# `is not None`, or coverage_status comes back "partial" with an EMPTY
# coverage_reasons (nothing explains the gap, and the console's COVERAGE
# section silently never renders at all).

def test_ref_dir_empty_string_matches_ref_dir_none():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    f_none  = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    f_empty = stomping._hunt_stomping(MF(), verbose=False, ref_dir="")

    assert f_empty["coverage_status"] == "partial"
    assert f_empty["status"] == "INCONCLUSIVE"
    # The whole point: a "partial" result must always carry a non-empty
    # explanation, and ref_dir="" must give the SAME one ref_dir=None does.
    assert f_empty["coverage_reasons"]
    assert f_empty["coverage_reasons"] == f_none["coverage_reasons"]
    assert f_empty["coverage_counts"] == f_none["coverage_counts"]


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
    padding_entry = 0   # IMAGE_REL_BASED_ABSOLUTE -- pads block_size to a
                        # multiple of 4 (apply_base_relocations rejects
                        # unaligned block sizes as malformed, so this must
                        # actually reach "applied" for the test to mean
                        # anything)
    reloc_data = struct.pack('<II', page_rva, 8 + 4) + struct.pack('<HH', entry, padding_entry)

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
    # A relocation-normalization FAILURE also produces score 0 (the diff
    # is gated, not compared) — assert the section was actually compared
    # and matched, not that normalization silently failed to run at all.
    assert f["coverage_counts"]["relocation_failed"] == 0, f["coverage_counts"]
    assert f["coverage_counts"]["sections_compared"] == 1, f["coverage_counts"]


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


# ── a read failure in the (unscored) IOC-string lead scan must be counted, ─
# not silently dropped -- it can't affect score/status (that lead never
# scores), but it must still be visible rather than quietly under-reporting
# IOC hits.

def test_ioc_lead_scan_read_failure_is_counted(capsys):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    section_region = Region(module_base + section["vaddr"], module_base, section["vsize"],
                             "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")
    # A second MEM_IMAGE/executable region the IOC-string lead scan will
    # also try to read (that scan iterates ALL regions, not just declared
    # sections) -- its read is made to fail.
    unreadable_base = module_base + 0x100000
    unreadable_region = Region(unreadable_base, module_base, 0x1000,
                                "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")
    regions = [section_region, unreadable_region]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    base_reader = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    def flaky_reader(mf, addr, size):
        if addr == unreadable_base:
            raise OSError("simulated unreadable region")
        return base_reader(mf, addr, size)

    stomping.read_region = flaky_reader

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    # The read failure can't invent a score -- that lead never scores --
    # but an eligible region this hunter never read is a coverage gap, so
    # the run must not report a complete, clean scan either. It used to
    # report exactly that (status NOT_DETECTED_IN_SCANNED_SCOPE,
    # coverage_status "complete"); see dumpex/hunt/stomping/aggregate.py's
    # own comment on why coverage_status and status move together here.
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("failed to read and were not scanned for IOC strings" in reason
               for reason in f["coverage_reasons"]), f["coverage_reasons"]

    # The read failure must be surfaced, not silently dropped like a plain
    # `except Exception: continue` would (that was the actual bug: this
    # region's read failure previously vanished with no trace anywhere).
    out = capsys.readouterr().out
    assert "1 region(s) failed to read" in out
    assert "CLEAN — no IOC patterns in executable module memory" not in out


# ── oversized executable MEM_IMAGE regions: recorded before they are ──────
# skipped, never silently dropped. The IOC-string scan skips any eligible
# region over IOC_SCAN_MAX (5 MiB) because string extraction over a huge
# mapping is expensive and can never score — but a skip nobody records is a
# region an analyst never learns to go re-scan, while the check line still
# reads "CLEAN — no IOC patterns in executable module memory".

_OVERSIZED = IOC_SCAN_MAX + 0x100000   # 6 MiB: over the cap, never read at
                                        # all (so no 6 MiB fixture is needed)


def _oversized_exec_image_region(base, module_base, size=_OVERSIZED):
    return Region(base, module_base, size, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")


def test_only_oversized_ioc_region_is_incomplete_not_clean(capsys):
    """The one case the old code got most wrong: nothing was found because
    nothing eligible was ever read, and it still rendered CLEAN."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    oversized_base = module_base + 0x100000
    regions = [_oversized_exec_image_region(oversized_base, module_base)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header,
                                        module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    # The oversized region can't produce a score -- this lead never scores
    # -- and the verified content diff itself did compare every eligible
    # section...
    assert f["score"] == 0
    assert f["coverage_counts"]["sections_compared"] == 1
    # ...but 5 MiB+ of eligible executable module memory was never
    # examined, so neither coverage nor the verdict may read as clean, and
    # the reason names the region and the cap it exceeded.
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert f["verdict_level"] == "inconclusive"
    reason = next(r for r in f["coverage_reasons"] if "never scanned for IOC strings" in r)
    assert f"0x{oversized_base:016x}" in reason
    assert "6 MB > 5 MB limit" in reason

    out = capsys.readouterr().out
    # The verdict-first console (issue #8) renders this in the unified
    # COVERAGE section rather than as a separate pre-verdict check line --
    # the claim itself is unchanged: nothing may read as clean.
    assert "CLEAN" not in out
    assert "COVERAGE" in out and "PARTIAL" in out
    # The investigator is told WHICH region needs targeted follow-up, in
    # the coverage reason and its accompanying impact line.
    assert f"0x{oversized_base:016x}" in out
    assert "--extract" in out and "--strings" in out
    # The cap itself is named too -- asserted on the tail fragment only,
    # since COVERAGE reasons word-wrap to the terminal width and this
    # preview can legitimately break between "(6" and "MB > 5 MB limit)".
    # The unwrapped, exact text is asserted on `coverage_reasons` above.
    assert "5 MB limit" in out


def test_mixed_scanned_and_oversized_regions_keeps_hits_and_the_gap(capsys):
    """A scanned region's IOC hit and an unscanned oversized region are not
    mutually exclusive: the hit list is a floor, not a total, so both the
    lead and the coverage gap have to survive."""
    filler = bytearray((i * 7) % 251 for i in range(0x2000))
    filler[0x40:0x40 + 8] = b"mimikatz"
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(
        module_base=module_base, text_bytes=bytes(filler))
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    scanned_base   = module_base + section["vaddr"]
    oversized_base = module_base + 0x100000
    regions = [Region(scanned_base, module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
               _oversized_exec_image_region(oversized_base, module_base)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, scanned_base: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    ioc_lead = next(x for x in f["findings"] if x["check"] == "stomping.ioc_string_lead")
    assert "mimikatz" in ioc_lead["facts"][0]
    # The lead itself carries the unexamined remainder -- a --json consumer
    # reading only this finding still learns the hit list is incomplete.
    assert any("never scanned for IOC strings" in lim for lim in ioc_lead["limitations"]), \
        ioc_lead["limitations"]
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"

    out = capsys.readouterr().out
    assert "COVERAGE" in out and "PARTIAL" in out
    assert f"0x{oversized_base:016x}" in out
    assert "CLEAN" not in out


def test_oversized_ioc_region_alongside_a_detection(capsys):
    """An oversized IOC region must neither suppress nor be suppressed by a
    real stomping detection: score/status stay DETECTED, and the gap is
    still reported next to it (a detected dump is exactly when an analyst
    most wants the addresses that were NOT examined)."""
    module_base = 0x7ff600000000
    sections = [{"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
                 "rawsize": 0x2000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}]
    header = build_pe_header(sections, timestamp=0x11111111, size_of_image=0x5000,
                              image_base=module_base)
    text_original = bytes((i * 7) % 251 for i in range(0x2000))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (sections[0]["rawptr"] - len(ref_file))
    ref_file += text_original
    mem_text = bytearray(text_original)
    mem_text[0x100:0x110] = b'\xCC' * 0x10   # simulated stomp

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    oversized_base = module_base + 0x100000
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE"),
               _oversized_exec_image_region(oversized_base, module_base)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header,
                                        module_base + 0x1000: bytes(mem_text)})
    stomping.get_thread_contexts = lambda mf: []

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["verdict_level"] == "possible"
    assert f["coverage_status"] == "partial"
    out = capsys.readouterr().out
    assert "Coverage incomplete despite a detection" in out
    assert f"0x{oversized_base:016x}" in out


def test_oversized_region_below_the_cap_is_scanned_normally():
    """Guard on the boundary itself: a region exactly AT IOC_SCAN_MAX is
    eligible and scanned (the check is `>`, not `>=`), so the cap can't
    quietly start reporting coverage gaps for regions it does examine."""
    module_base = 0x7ff600000000
    filler = bytearray((i * 7) % 251 for i in range(0x2000))
    header, mem_text, ref_file, section = matching_module_and_ref(
        module_base=module_base, text_bytes=bytes(filler))
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    at_cap_base = module_base + 0x100000
    regions = [_oversized_exec_image_region(at_cap_base, module_base, size=IOC_SCAN_MAX)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header,
                                        module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    assert f["coverage_status"] == "complete"
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert not [r for r in f["coverage_reasons"] if "IOC strings" in r]


# ── a short read (fewer bytes than RegionSize) must be a coverage gap, ────
# not silently miscounted as CLEAN, while a real hit in the readable
# prefix still gets reported.

def test_short_read_ioc_region_is_incomplete_and_keeps_hit_in_prefix(capsys):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]

    filler = bytearray((i * 7) % 251 for i in range(0x1000))
    filler[0x40:0x40 + 8] = b"mimikatz"   # strong IOC token, inside the readable prefix
    short_read_base = module_base + 0x100000
    full_size = 0x1000
    truncated_size = 0x800   # only half comes back -- the token at 0x40 is still included
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
               Region(short_read_base, module_base, full_size,
                      "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    base_reader = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text,
                               short_read_base: bytes(filler)})

    def short_reader(mf, addr, size):
        if addr == short_read_base:
            return base_reader(mf, addr, size)[:truncated_size]
        return base_reader(mf, addr, size)
    stomping.read_region = short_reader

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    # The scored signal is unaffected (the content diff compared its own
    # eligible section fully) -- this is purely about the unscored IOC
    # scan's own coverage over a DIFFERENT region.
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    # Unlike an oversized skip, a short read carries no per-target VA (the
    # shared CoverageTracker only counts short reads -- see
    # dumpex.hunt._coverage.CoverageTracker.build_reasons -- matching every
    # other hunter's read_failed/short_reads reasons, which are count-only
    # too; only skipped_oversize keeps full ScanTarget identity).
    reason = next(r for r in f["coverage_reasons"]
                  if "partially scanned for IOC strings" in r)
    assert "1 region(s)" in reason

    ioc_lead = next(x for x in f["findings"] if x["check"] == "stomping.ioc_string_lead")
    assert "mimikatz" in ioc_lead["facts"][0]
    assert any("partially scanned for IOC strings" in lim for lim in ioc_lead["limitations"])

    out = capsys.readouterr().out
    assert "CLEAN" not in out
    assert "COVERAGE" in out and "PARTIAL" in out
    assert "mimikatz" in out or "1 strong" in out   # the readable-prefix hit still shows up


# ── ModuleListStream absent: hunter-level NOT_EVALUATED, but a real IOC ───
# oversized-region gap (found by a sub-scan that only needs
# MemoryInfoListStream) must still show up in coverage_reasons, not be
# swallowed because the WHOLE hunter never evaluated for an unrelated reason.

def test_oversized_ioc_region_survives_not_evaluated_when_module_list_absent():
    module_base = 0x7ff600000000
    oversized_base = module_base + 0x100000
    oversized_size = IOC_SCAN_MAX + 0x100000
    regions = [_oversized_exec_image_region(oversized_base, module_base, size=oversized_size)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        # `modules` stays the FakeMF default (None).

    stomping.read_region = mem_reader({})

    f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)

    assert f["status"] == "NOT_EVALUATED"
    assert f["coverage_status"] == "not_evaluated"
    assert any("ModuleListStream" in r for r in f["coverage_reasons"])
    assert any("never scanned for IOC strings" in r for r in f["coverage_reasons"])


def test_ioc_lead_finding_printed_exactly_once(capsys):
    """Regression test for a console-rendering bug: presentation.py used to
    hand-render a summary line for stomping.ioc_string_lead AND ALSO print
    every Finding in report.findings_list unconditionally -- when
    ioc_scan.ioc_hits fired, that same Finding got printed twice (once as
    an ad-hoc summary, once again via Finding.print()). Nothing exercised
    a non-empty ioc_hits case before, so this shipped unnoticed. Fixed by
    dropping the ad-hoc summary block entirely -- report_console.py's
    single KEY SIGNALS loop is now the only thing that renders this check.

    Counted on the check's human TITLE rather than its raw check id: the
    verdict-first console (issue #8) prints the id only under --verbose,
    so a count of "stomping.ioc_string_lead" would read 0 in normal mode
    and prove nothing."""
    filler = bytearray((i * 7) % 251 for i in range(0x2000))
    filler[0x40:0x40 + 8] = b"mimikatz"   # strong (non-weak) IOC token, >= 8 printable chars
    header, mem_text, ref_file, section = matching_module_and_ref(module_base=0x7ff600000000,
                                                                    text_bytes=bytes(filler))
    module_base = 0x7ff600000000
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    stomping.read_region = mem_reader(
        {module_base: header, module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)

    ioc_findings = [x for x in f["findings"] if x["check"] == "stomping.ioc_string_lead"]
    assert len(ioc_findings) == 1
    assert "mimikatz" in ioc_findings[0]["facts"][0]

    out = capsys.readouterr().out
    assert out.count("IOC strings in module code regions") == 1
    assert out.count("stomping.ioc_string_lead") <= 1
    # The bug: a hand-rendered "(lead)" summary line for this exact check,
    # printed unconditionally alongside (not instead of) the Finding block
    # below it -- must not come back.
    assert "IOC strings in module code regions (lead)" not in out


def test_verbose_shows_per_token_va_encoding_and_weak_flag(capsys):
    """stomping.ioc_string_lead's Finding.facts (built for --json)
    hold only a deduped, capped list of matched TERMS per region -- no
    per-token absolute VA, no string encoding, no weak/common-API
    classification. That detail used to come from presentation.py's own
    uncapped hand-written --verbose expansion before rendering was
    centralized on Finding.print(); regression test for it being silently
    dropped."""
    filler = bytearray((i * 7) % 251 for i in range(0x2000))
    filler[0x40:0x40 + 8] = b"mimikatz"
    filler[0x80:0x80 + len(b"VirtualAlloc")] = b"VirtualAlloc"   # weak/common-API term
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base=module_base,
                                                                    text_bytes=bytes(filler))
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    stomping.read_region = mem_reader(
        {module_base: header, module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        normal_out = capsys.readouterr().out
        assert "weak/common API" not in normal_out
        assert f"0x{module_base + section['vaddr'] + 0x40:016x}" not in normal_out

        stomping._hunt_stomping(MF(), verbose=True, ref_dir=d)
        # Collapse the console's word-wrap/indent so content checks below do
        # not depend on where a line happens to break.
        verbose_out = " ".join(capsys.readouterr().out.split())

    mimikatz_va = module_base + section["vaddr"] + 0x40
    valloc_va = module_base + section["vaddr"] + 0x80
    assert f"VA=0x{mimikatz_va:016x} encoding=ASCII token=mimikatz" in verbose_out
    assert f"VA=0x{valloc_va:016x} encoding=ASCII token=VirtualAlloc (weak/common API)" in verbose_out


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


# ── no --ref-dir: a protection anomaly ALONE stays a plain lead, but one ──
# with a thread's live RIP inside that exact section gets a second,
# distinct medium-confidence lead calling out the correlation — still
# never scored, never "confirmed stomping" (that requires --ref-dir).

def test_rip_in_anomalous_section_without_ref_dir_is_medium_lead():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    # RWX deviates from the section's declared RX -- WRITECOPY (the
    # "normal" loader state) is deliberately NOT used here.
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_IMAGE")]
    section_va = module_base + section["vaddr"]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, section_va: mem_text})
    stomping.get_thread_contexts = lambda mf: [{"ThreadId": 0x42, "ip": section_va + 0x10,
                                                  "ip_reg": "RIP", "is_wow64": False}]

    f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)

    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    tags = {finding["check"]: finding for finding in f["findings"]}
    assert "stomping.rip_in_anomalous_section_lead" in tags
    lead = tags["stomping.rip_in_anomalous_section_lead"]
    assert lead["tag"] == "lead"
    assert lead["confidence"] == "medium"


def test_no_rip_in_anomalous_section_omits_correlation_lead():
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})
    stomping.get_thread_contexts = lambda mf: []   # no thread executing anywhere

    f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)

    checks = {finding["check"] for finding in f["findings"]}
    assert "stomping.protection_deviation_lead" in checks
    assert "stomping.rip_in_anomalous_section_lead" not in checks
