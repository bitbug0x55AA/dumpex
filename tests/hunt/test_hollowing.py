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


# ── MEM_PRIVATE at image base (hollowed) -> +1 ─────────────────────────────

def test_mem_private_image_base_scores_1():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 1
    assert f["status"] == "DETECTED"


# ── MZ header zeroed out -> +1 ─────────────────────────────────────────────

def test_zeroed_mz_header_scores_1():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 1


# ── RWX protection at image base -> +1 ─────────────────────────────────────

def test_rwx_image_base_scores_1():
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
    assert f["score"] == 1


# ── PEB image name vs module list mismatch -> +1 ───────────────────────────

def test_module_name_mismatch_scores_1():
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\different.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 1


# ── image base not covered by any module -> +1 ─────────────────────────────

def test_image_base_not_in_module_list_scores_1():
    image_base = 0x140000000
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'MZ' + b'\x90' * 0x100})

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 1


# ── everything wrong at once -> high score, still DETECTED ────────────────

def test_all_indicators_present_scores_high():
    image_base = 0x140000000
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")   # not in module list
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})   # zeroed MZ

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    assert f["score"] == 4   # MEM_PRIVATE + zeroed MZ + RWX + not-in-module-list
    assert f["status"] == "DETECTED"
