"""Hunter-level tests for dumpex.hunt.hollowing (Process Hollowing detection)."""
from tests.fixtures.fakes import Region, Module, Peb, FakeStream, FakeMF, mem_reader

import dumpex.hunt.hollowing as hollowing


# ── no PEB stream at all -> NOT_EVALUATED ──────────────────────────────────

def test_no_peb_is_not_evaluated():
    class MF(FakeMF):
        peb = None
    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_EVALUATED"
    assert f["verdict_level"] == "not_evaluated"
    assert f["lead_count"] == 0
    assert f["review_priority"] == "none"


# ── image base region entirely missing from the dump -> INCONCLUSIVE ──────

def test_image_base_region_not_captured_is_inconclusive():
    image_base = 0x140000000
    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")
        memory_info = FakeStream([], "infos")   # no regions at all
    hollowing.read_region = mem_reader({})
    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"


# ── image base region present, but reading its MZ header fails ───────────
# (the region metadata existing must not be conflated with the MZ-header
# check actually having run -- a read failure there is a real coverage
# gap, not a silent "complete" scan)

def test_mz_read_failure_makes_result_inconclusive_partial():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")

    def flaky_reader(mf, addr, size):
        raise OSError("simulated read failure")
    hollowing.read_region = flaky_reader

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert any("MZ header" in r for r in f["coverage_reasons"])


# ── MZ header read returns fewer than 2 bytes -> coverage gap, NOT a false ─
# "MZ wiped" finding (a short read is not evidence the header is missing --
# combined with MEM_PRIVATE this previously reached a false DETECTED)

def test_mz_header_short_read_is_coverage_gap_not_false_detection():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_READONLY", "MEM_PRIVATE")]   # MEM_PRIVATE anchor also present

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")

    def short_reader(mf, addr, size):
        return b"M"   # 1 byte back -- not even enough to check the MZ magic
    hollowing.read_region = short_reader

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["status"] != "DETECTED"
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.mz_header_missing" not in checks
    assert any("MZ header" in r for r in f["coverage_reasons"])


# ── ModuleList missing/empty -> coverage gap, not a silent "complete" scan ─
# (check 4 can never actually run without it -- main_mod is always None
# either way, so this must not be conflated with "genuinely not listed")

def test_module_list_unavailable_is_coverage_gap():
    image_base = 0x140000000
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")   # ModuleList missing/empty
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.peb_module_name_mismatch" not in checks
    assert any("ModuleList" in r for r in f["coverage_reasons"])


# ── fully clean: MEM_IMAGE, MZ present, non-RWX, module name matches ──────

def test_fully_clean_scores_0():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["lead_count"] == 0
    assert f["review_priority"] == "none"


# ── single anomaly alone -> lead only, NOT DETECTED ────────────────────────
# (this is the exact behavior the correlation requirement exists to fix:
# a lone weak/ambiguous signal must not by itself claim hollowing.)

def test_mem_private_alone_is_lead_not_detected():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    checks = {finding["check"]: finding for finding in f["findings"]}
    assert checks["hollowing.mem_private_at_image_base"]["tag"] == "lead"
    assert "hollowing.structural_correlation" not in checks
    assert f["lead_count"] == 1
    assert f["review_priority"] == "medium"


def test_zeroed_mz_header_alone_is_lead_not_detected():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.mz_header_missing" in checks
    assert "hollowing.structural_correlation" not in checks


def test_rwx_alone_is_lead_not_detected():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.rwx_at_image_base" in checks
    assert "hollowing.structural_correlation" not in checks


def test_module_name_mismatch_alone_is_lead_not_detected():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\different.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.peb_module_name_mismatch" in checks
    assert "hollowing.structural_correlation" not in checks
    # A bare name mismatch alone is the weakest signal -- low priority, not medium.
    assert f["review_priority"] == "low"


# ── MEM_PRIVATE + MZ wiped correlate -> DETECTED (score 1) ────────────────

def test_mem_private_plus_mz_wiped_correlates_detected():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["verdict_level"] == "likely"
    checks = {finding["check"]: finding for finding in f["findings"]}
    assert checks["hollowing.structural_correlation"]["tag"] == "detection"
    assert checks["hollowing.structural_correlation"]["confidence"] == "medium"


# ── MEM_PRIVATE + RWX correlate (MZ present) -> DETECTED (score 1) ────────

def test_mem_private_plus_rwx_correlates_detected():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 1
    assert f["status"] == "DETECTED"


# ── everything wrong at once -> full correlation, score 2, HIGH ───────────

def test_all_signals_correlate_scores_2_high_confidence():
    image_base = 0x140000000
    other_base = 0x150000000   # ModuleList IS available, just doesn't list image_base
    other_module = Module(other_base, 0x5000, r"C:\Windows\System32\other.dll")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([other_module], "modules")   # available, but not in module list
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})   # zeroed MZ

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 2
    assert f["status"] == "DETECTED"
    assert f["verdict_level"] == "high"
    assert f["confidence"] == "high"
    # the uncorrelated name-mismatch lead still shows up alongside the detection
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.peb_module_name_mismatch" in checks
    assert f["lead_count"] >= 1
    assert f["review_priority"] == "high"
