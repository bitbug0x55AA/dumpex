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


# ── MZ prefix read succeeds but the deeper PE-validation read fails ───────
# must not be silently treated as a completed check: the MZ observation is
# still reported (parse_pe_header falls back to the 2-byte prefix), but
# pe_read_failed must count it, coverage must go partial, and with nothing
# else to score, the overall result must be INCONCLUSIVE.

def test_mz_prefix_ok_deep_read_fails_is_inconclusive():
    region_base = 0x8000000
    dummy_regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    def flaky_reader(mf, addr, size):
        if addr == region_base and size <= 2:
            return b'MZ'
        raise OSError("simulated deep-read failure")

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = flaky_reader

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["pe_read_failed"] == 1
    assert len(f["hidden_pe_unvalidated"]) == 1, "MZ observation must still be reported"
    assert len(f["hidden_pe_validated"]) == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("failed to read" in r for r in f["coverage_reasons"])


# ── MZ prefix read succeeds and the deeper PE-validation read succeeds ────
# but SHORT-reads (returns fewer bytes than requested, no exception) —
# must not be silently treated as a completed check either: pe_read_failed
# stays 0 in this scenario, but pe_short_reads must count it, and coverage
# must still go partial/INCONCLUSIVE, not silently claim full coverage.

def test_mz_prefix_ok_deep_read_short_reads_is_inconclusive():
    region_base = 0x9000000
    dummy_regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    def short_reader(mf, addr, size):
        # Prefix read (size<=2) succeeds fully; the deep validation read
        # (size > 2) returns fewer bytes than requested WITHOUT raising —
        # exactly what a real short read from a partially-paged-out or
        # truncated capture looks like.
        if addr == region_base and size <= 2:
            return b'MZ'
        return b'MZ'   # deep read: only 2 bytes back, even though more were requested

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = short_reader

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["pe_read_failed"] == 0, "no exception was raised, so this must stay 0"
    assert f["pe_short_reads"] == 1
    assert len(f["hidden_pe_unvalidated"]) == 1, "MZ observation must still be reported"
    assert len(f["hidden_pe_validated"]) == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r.lower() or "fewer bytes" in r for r in f["coverage_reasons"])


# ── context-only (informational) validated PE hits must not drive score ───
# See dumpex/hunt/injection/memory_scan.py's pe_hit_is_context_scoreable and
# aggregate.py's _split_scoreable_pe_hits: a structurally-valid PE header
# that sits in read-only/non-executable, uncorrelated memory is real
# evidence worth keeping visible, but must not by itself produce a
# DETECTED/score>0 result — this is exactly the clean-Notepad false
# positive (7 PAGE_READONLY MEM_MAPPED/MEM_IMAGE PE headers, none RWX, none
# thread-correlated, previously still scored 1/POSSIBLE).

def test_valid_pe_in_readonly_mem_mapped_is_observation_not_scored():
    region_base = 0xA0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert len(f["hidden_pe_validated"]) == 1, "compat: full validated list unchanged"
    assert len(f["suspicious_validated_pe_hits"]) == 0
    assert len(f["informational_validated_pe_hits"]) == 1
    obs = [x for x in f["findings"]
           if x["check"] == "injection.hidden_pe_validated_context_only"]
    assert obs and obs[0]["tag"] == "observation"
    leads = [x for x in f["findings"] if x["check"] == "injection.hidden_pe_validated"]
    assert not leads, "no scoreable-lead finding should be emitted when only context-only PE exists"


def test_valid_pe_in_unbacked_mem_image_readonly_is_observation_not_scored():
    region_base = 0xB0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert len(f["suspicious_validated_pe_hits"]) == 0
    assert len(f["informational_validated_pe_hits"]) == 1


def test_valid_pe_in_mem_private_is_lead_score_1():
    region_base = 0xC0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 1
    assert len(f["suspicious_validated_pe_hits"]) == 1
    assert len(f["informational_validated_pe_hits"]) == 0
    leads = [x for x in f["findings"]
             if x["check"] == "injection.hidden_pe_validated" and x["tag"] == "lead"]
    assert leads


def test_rwx_and_pe_same_allocation_without_rip_still_scores_2():
    # Same-allocation RWX + validated PE, but no thread context at all (no
    # RIP correlation possible) — must still reach score 2 via
    # rwx_and_pe_alloc_bases, exactly as before this change.
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

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({alloc_base + 0x2000: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 2


def test_only_informational_pe_with_partial_coverage_is_inconclusive_not_detected():
    region_base = 0xD0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")   # present but empty -> partial coverage
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["status"] != "DETECTED"
    assert f["coverage_status"] == "partial"
