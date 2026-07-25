"""Hunter-level tests for dumpex.hunt.injection (Process Injection detection)."""
from tests.fixtures.fakes import (Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader)

import dumpex.hunt.injection as injection


# ── embedded PE inside a loaded module's own range -> NOT hidden PE ───────

def test_embedded_pe_inside_module_not_hidden():
    mod_base = 0x7ffe10000000
    module = Module(mod_base, 0x10000, r"C:\Windows\System32\legit.dll")
    embedded_base = mod_base + 0x2000  # inside the module, not at its exact base

    regions = [
        Region(mod_base, mod_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
        Region(embedded_base, mod_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE"),
    ]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([module], "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({embedded_base: b'MZ' + b'\x90' * 0x1000})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert len(f["hidden_pe_validated"]) == 0
    assert len(f["hidden_pe_unvalidated"]) == 0
    assert len(f["rwx"]) == 0, "WRITECOPY on MEM_IMAGE must not count as suspicious RWX"


# ── no thread context at all -> partial coverage ───────────────────────────

def test_no_thread_context_is_partial():
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None   # no ThreadListStream at all -> no contexts possible

    injection.read_region = mem_reader({})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert f["verdict_level"] == "inconclusive"


# ── Bonus: full correlation (RWX + validated PE + live RIP) still detects ─

def test_full_correlation_still_detects():
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    injection.read_region = mem_reader({alloc_base + 0x2000: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 3
    assert f["confidence"] == "high"
