"""
Tests for dumpex.core.pe_utils.parse_iat() -- the bounded, in-memory
Import Address Table parser (issue #39).

Most tests hand-construct the `pe` dict parse_iat() consumes directly
(data_directories/declared_directory_count/is_pe32_plus) rather than
routing through parse_pe_header() and a full byte-buffer PE header --
parse_iat() only ever reads those three keys, so this keeps each test
focused on the IAT walk itself. `test_parse_pe_header_directory_fields`
and `test_end_to_end_via_parse_pe_header` cover the parse_pe_header()
integration explicitly.
"""
import struct

import pytest

from dumpex.core.pe_utils import (
    parse_pe_header, parse_iat,
    ImportEntry, IatTruncation, IatDiagnostic, IatParseResult,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64,
    MAX_IAT_NAME_LENGTH,
)

IMAGE_BASE = 0x140000000


class FakeImage:
    """A sparse virtual-address-space fake for parse_iat()'s `read`
    callback. `.write(va, data)` stores one contiguous region;
    `.read(addr, size)` slices whatever region covers `addr`, returning
    b"" if none does, or fewer bytes than asked if the region runs out
    partway through -- this is how short-read scenarios are built."""

    def __init__(self):
        self.regions = []
        self.read_log = []

    def write(self, va, data):
        self.regions.append((va, bytes(data)))
        return va

    def read(self, addr, size):
        self.read_log.append((addr, size))
        for va, data in self.regions:
            if va <= addr < va + len(data):
                off = addr - va
                return data[off:off + size]
        return b""


def descriptor(original_first_thunk, name_rva, first_thunk, timestamp=0, fwd=0):
    return struct.pack('<IIIII', original_first_thunk, timestamp, fwd, name_rva, first_thunk)


TERMINATOR = descriptor(0, 0, 0)


def cstr(name: str) -> bytes:
    return name.encode('ascii') + b'\x00'


def hint_name(name: str, hint: int = 0) -> bytes:
    return struct.pack('<H', hint) + cstr(name)


def thunk32(value: int) -> bytes:
    return struct.pack('<I', value)


def thunk64(value: int) -> bytes:
    return struct.pack('<Q', value)


def make_pe(*, is_pe32_plus=True, directories=None):
    directories = dict(directories or {})
    max_index = max(directories, default=-1)
    data_directories = [directories.get(i, (0, 0)) for i in range(max_index + 1)]
    return {
        "data_directories": data_directories,
        "declared_directory_count": max_index + 1,
        "is_pe32_plus": is_pe32_plus,
    }


# ── §3.5.2 presence resolution ───────────────────────────────────────────

def test_no_import_directory_declared_is_complete_empty():
    pe = make_pe(directories={0: (0, 0), 1: (0, 0)})
    result = parse_iat(lambda a, s: b"", IMAGE_BASE, pe)
    assert result.import_directory_present is False
    assert result.table_present is False
    assert result.has_entries is False
    assert result.dll_count == 0
    assert result.entry_count == 0
    assert result.entries == ()
    assert result.directory_table_incomplete is False
    assert result.directory_incomplete_affected_count is None
    assert result.table_va is None and result.table_size is None


def test_declared_directory_count_none_is_fully_undetermined():
    pe = {"data_directories": [], "declared_directory_count": None, "is_pe32_plus": True}
    result = parse_iat(lambda a, s: b"", IMAGE_BASE, pe)
    assert result.import_directory_present is None
    assert result.table_present is None
    assert result.has_entries is False
    assert result.directory_table_incomplete is True
    assert result.directory_incomplete_affected_count is None


def test_declared_but_uncaptured_directory_is_undetermined_with_count():
    # declared_directory_count says 5 directories exist, but only index 0
    # was actually captured -- index 1 (imports) is "declared but bytes
    # not captured", i.e. undetermined, not "absent".
    pe = {"data_directories": [(0, 0)], "declared_directory_count": 5, "is_pe32_plus": True}
    result = parse_iat(lambda a, s: b"", IMAGE_BASE, pe)
    assert result.import_directory_present is None
    assert result.directory_table_incomplete is True
    assert result.directory_incomplete_affected_count == 5 - 1


def test_table_present_false_when_import_present_true_emits_bounds_diagnostic():
    # Import Directory (index 1) present, IAT Directory (index 12) absent
    # -- contract row "true | false": entries ARE reported, but
    # slot_in_bounds is null on every one and IAT_BOUNDS_CHECK_UNAVAILABLE
    # fires instead of a coverage-affecting limitation.
    img = FakeImage()
    dll_rva = 0x2000
    name_rva = 0x2100
    int_rva = 0x2200
    iat_rva = 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("KERNEL32.dll"))
    img.write(IMAGE_BASE + int_rva, thunk64(name_rva) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0xDEADBEEF) + thunk64(0))
    img.write(IMAGE_BASE + name_rva, hint_name("CreateFileW"))

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.import_directory_present is True
    assert result.table_present is False
    assert result.directory_table_incomplete is False
    assert result.has_entries is True
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.slot_in_bounds is None
    assert result.table_va is None and result.table_size is None
    assert any(d.code == "IAT_BOUNDS_CHECK_UNAVAILABLE" for d in result.diagnostics)


# ── happy path: names, ordinals, multiple DLLs, ordering ────────────────

def test_name_and_ordinal_imports_pe32_plus():
    img = FakeImage()
    dll_rva, name_rva = 0x2000, 0x2100
    int_rva, iat_rva = 0x2200, 0x2300

    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("KERNEL32.dll"))
    img.write(IMAGE_BASE + name_rva, hint_name("CreateFileW"))
    img.write(IMAGE_BASE + int_rva,
              thunk64(name_rva) + thunk64(IMAGE_ORDINAL_FLAG64 | 42) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva,
              thunk64(0x7FFB00001111) + thunk64(0x7FFB00002222) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 20), 12: (iat_rva, 24)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.import_directory_present is True
    assert result.table_present is True
    assert result.dll_count == 1
    assert result.entry_count == 2
    assert result.has_entries is True

    name_entry, ord_entry = result.entries
    assert name_entry == ImportEntry(
        dll="KERNEL32.dll", import_by="name", symbol="CreateFileW", ordinal=None,
        iat_slot_va=IMAGE_BASE + iat_rva, resolved_target_va=0x7FFB00001111, slot_in_bounds=True)
    assert ord_entry == ImportEntry(
        dll="KERNEL32.dll", import_by="ordinal", symbol=None, ordinal=42,
        iat_slot_va=IMAGE_BASE + iat_rva + 8, resolved_target_va=0x7FFB00002222, slot_in_bounds=True)
    assert result.diagnostics == ()


def test_multiple_dlls_stable_ordering():
    img = FakeImage()
    d0_int, d0_iat, d0_name, d0_sym = 0x3000, 0x3100, 0x3200, 0x3300
    d1_int, d1_iat, d1_name, d1_sym = 0x4000, 0x4100, 0x4200, 0x4300

    descriptors = (
        descriptor(d0_int, d0_name, d0_iat)
        + descriptor(d1_int, d1_name, d1_iat)
        + TERMINATOR
    )
    img.write(IMAGE_BASE + 0x1000, descriptors)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))
    img.write(IMAGE_BASE + d0_int, thunk64(d0_sym) + thunk64(0))
    img.write(IMAGE_BASE + d0_iat, thunk64(0x1111) + thunk64(0))
    img.write(IMAGE_BASE + d0_sym, hint_name("Func0"))

    img.write(IMAGE_BASE + d1_name, cstr("B.dll"))
    img.write(IMAGE_BASE + d1_int, thunk64(d1_sym) + thunk64(0))
    img.write(IMAGE_BASE + d1_iat, thunk64(0x2222) + thunk64(0))
    img.write(IMAGE_BASE + d1_sym, hint_name("Func1"))

    pe = make_pe(directories={1: (0x1000, 40)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 2
    assert [e.dll for e in result.entries] == ["A.dll", "B.dll"]
    assert [e.symbol for e in result.entries] == ["Func0", "Func1"]


def test_pe32_thunk_width_and_ordinal_flag():
    img = FakeImage()
    dll_rva, name_rva, int_rva, iat_rva = 0x2000, 0x2100, 0x2200, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("USER32.dll"))
    img.write(IMAGE_BASE + int_rva,
              thunk32(IMAGE_ORDINAL_FLAG32 | 7) + thunk32(name_rva) + thunk32(0))
    img.write(IMAGE_BASE + iat_rva, thunk32(0x111) + thunk32(0x222) + thunk32(0))
    img.write(IMAGE_BASE + name_rva, hint_name("MessageBoxW"))

    pe = make_pe(is_pe32_plus=False, directories={1: (0x1000, 20)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entry_count == 2
    assert result.entries[0].import_by == "ordinal"
    assert result.entries[0].ordinal == 7
    assert result.entries[1].import_by == "name"
    assert result.entries[1].symbol == "MessageBoxW"


# ── OriginalFirstThunk == 0 ───────────────────────────────────────────────

def test_original_first_thunk_zero_marks_unavailable_not_invented():
    img = FakeImage()
    dll_rva, iat_rva = 0x2000, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(0, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("NTDLL.dll"))
    img.write(IMAGE_BASE + iat_rva, thunk64(0x7FFB00003333) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entry_count == 1
    e = result.entries[0]
    assert e.dll == "NTDLL.dll"
    assert e.import_by == "unavailable"
    assert e.symbol is None
    assert e.ordinal is None
    assert e.resolved_target_va == 0x7FFB00003333
    assert e.iat_slot_va == IMAGE_BASE + iat_rva


def test_original_first_thunk_and_first_thunk_both_zero_is_empty_dll():
    img = FakeImage()
    dll_rva = 0x2000
    img.write(IMAGE_BASE + 0x1000, descriptor(0, dll_rva, 0) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("EMPTY.dll"))

    pe = make_pe(directories={1: (0x1000, 40)})   # one descriptor + terminator
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 1
    assert result.entry_count == 0
    assert result.unterminated_table is False


# ── captured targets preserved on partial failure ────────────────────────

def test_missing_dll_name_bytes_preserves_the_rest_of_the_entry():
    img = FakeImage()
    name_rva, int_rva, iat_rva = 0x2100, 0x2200, 0x2300
    # dll_rva points at unmapped memory -- name read fails independently
    # of everything else in the descriptor.
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, 0x9999, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + int_rva, thunk64(name_rva) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0xABCD) + thunk64(0))
    img.write(IMAGE_BASE + name_rva, hint_name("Foo"))

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.name_read_failed_count == 1
    assert result.entry_count == 1
    e = result.entries[0]
    assert e.dll is None
    assert e.symbol == "Foo"
    assert e.resolved_target_va == 0xABCD


def test_first_descriptor_read_failure_is_directory_level():
    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(lambda a, s: b"", IMAGE_BASE, pe)   # nothing mapped anywhere
    assert result.directory_read_failed is True
    assert result.descriptor_read_failed_count == 0
    assert result.unterminated_table is True
    assert result.entries == ()


def test_second_descriptor_read_failure_is_per_descriptor():
    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    # First descriptor is fully readable and terminated; the SECOND
    # descriptor's own 20 bytes are simply never mapped. The declared
    # Size (40) has room for both descriptor slots, so this exercises the
    # unmapped-memory read failure itself, not the declared-size bound.
    img.write(IMAGE_BASE + 0x1000, descriptor(0, dll_rva, iat_rva))
    img.write(IMAGE_BASE + dll_rva, cstr("A.dll"))
    img.write(IMAGE_BASE + iat_rva, thunk64(0x111) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 40)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.directory_read_failed is False
    assert result.descriptor_read_failed_count == 1
    assert result.dll_count == 1
    assert result.unterminated_table is True


def test_short_thunk_read_stops_only_that_descriptors_walk():
    img = FakeImage()
    d0_int, d0_iat, d0_name = 0x3000, 0x3100, 0x3200
    d1_int, d1_iat, d1_name, d1_sym = 0x4000, 0x4100, 0x4200, 0x4300

    descriptors = descriptor(d0_int, d0_name, d0_iat) + descriptor(d1_int, d1_name, d1_iat) + TERMINATOR
    img.write(IMAGE_BASE + 0x1000, descriptors)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))
    # d0's INT thunk is truncated to 3 bytes -- less than the 8 a PE32+
    # thunk needs.
    img.write(IMAGE_BASE + d0_int, b"\x01\x02\x03")
    img.write(IMAGE_BASE + d0_iat, thunk64(0x111) + thunk64(0))

    img.write(IMAGE_BASE + d1_name, cstr("B.dll"))
    img.write(IMAGE_BASE + d1_int, thunk64(d1_sym) + thunk64(0))
    img.write(IMAGE_BASE + d1_iat, thunk64(0x222) + thunk64(0))
    img.write(IMAGE_BASE + d1_sym, hint_name("Func1"))

    pe = make_pe(directories={1: (0x1000, 40)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.thunk_short_read_count == 1
    assert result.unterminated_table is True
    assert result.dll_count == 2
    assert result.entry_count == 1
    assert result.entries[0].dll == "B.dll"
    assert result.truncation is None   # a short read is not a budget truncation


# ── corrupt directory sizes ───────────────────────────────────────────────

def test_zero_size_iat_directory_makes_every_slot_out_of_bounds():
    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("A.dll"))
    img.write(IMAGE_BASE + int_rva, thunk64(0x9000) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0xAAA) + thunk64(0))
    img.write(IMAGE_BASE + 0x9000, hint_name("Foo"))

    # table_present resolves True (rva != 0) even though size is 0 --
    # Size is never a presence discriminator (§3.5.2).
    pe = make_pe(directories={1: (0x1000, 20), 12: (iat_rva, 0)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.table_present is True
    assert result.entries[0].slot_in_bounds is False
    diag = [d for d in result.diagnostics if d.code == "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS"][0]
    assert diag.affected_count == 1
    assert diag.details["first_out_of_bounds_slot_va"] == IMAGE_BASE + iat_rva


# ── unterminated table / cap reached ───────────────────────────────────────

def test_unterminated_descriptor_array_hits_dll_cap(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_DLLS", 3)

    img = FakeImage()
    # Four descriptors -- OriginalFirstThunk and FirstThunk both 0 (an
    # empty-imports DLL, so no thunk array needs to be mapped), none of
    # them the all-zero terminator. The FOURTH one is what proves this
    # is a genuine cap truncation rather than an unrelated read failure:
    # it is fully readable, real, and non-terminator, but sits past
    # MAX_IAT_DLLS.
    blob = b"".join(descriptor(0, 0x9000 + i, 0, timestamp=1) for i in range(4))
    img.write(IMAGE_BASE + 0x1000, blob)
    for i in range(4):
        img.write(IMAGE_BASE + 0x9000 + i, cstr("A"))

    pe = make_pe(directories={1: (0x1000, 80)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 3
    assert result.unterminated_table is True
    assert result.truncation == IatTruncation("iat_dlls", 3, 3)


def test_unterminated_thunk_array_hits_entries_per_dll_cap(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_ENTRIES_PER_DLL", 2)

    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("A.dll"))
    # Three non-zero ordinal thunks -- never a terminator within the cap.
    img.write(IMAGE_BASE + int_rva,
              thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(IMAGE_ORDINAL_FLAG64 | 2)
              + thunk64(IMAGE_ORDINAL_FLAG64 | 3) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0x1) + thunk64(0x2) + thunk64(0x3) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entry_count == 2
    assert result.unterminated_table is True
    assert result.truncation == IatTruncation("iat_entries_per_dll", 2, 2)


def test_total_entries_budget_stops_the_whole_walk(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_TOTAL_ENTRIES", 3)

    img = FakeImage()
    d0_int, d0_iat, d0_name = 0x3000, 0x3100, 0x3200
    d1_int, d1_iat, d1_name = 0x4000, 0x4100, 0x4200

    img.write(IMAGE_BASE + 0x1000, descriptor(d0_int, d0_name, d0_iat) + descriptor(d1_int, d1_name, d1_iat) + TERMINATOR)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))
    img.write(IMAGE_BASE + d0_int,
              thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(IMAGE_ORDINAL_FLAG64 | 2) + thunk64(0))
    img.write(IMAGE_BASE + d0_iat, thunk64(0x1) + thunk64(0x2) + thunk64(0))

    img.write(IMAGE_BASE + d1_name, cstr("B.dll"))
    img.write(IMAGE_BASE + d1_int,
              thunk64(IMAGE_ORDINAL_FLAG64 | 3) + thunk64(IMAGE_ORDINAL_FLAG64 | 4) + thunk64(0))
    img.write(IMAGE_BASE + d1_iat, thunk64(0x3) + thunk64(0x4) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 40)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entry_count == 3
    assert result.truncation == IatTruncation("iat_total_entries", 3, 3)
    assert result.unterminated_table is True


def test_name_length_cap_marks_name_unavailable(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_NAME_LENGTH", 4)

    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("ThisNameIsWayTooLong.dll"))
    img.write(IMAGE_BASE + int_rva, thunk64(0) + thunk64(0))   # unused (OFT terminates immediately below)

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entries == ()   # the descriptor's own thunk array is empty (terminator immediately)
    assert result.dll_count == 1
    assert result.name_read_failed_count == 1


# ── budgets: bytes and read operations ────────────────────────────────────

def test_bytes_budget_truncates_walk(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_BYTES_READ", 20)   # exactly one descriptor

    img = FakeImage()
    blob = b"".join(descriptor(0, 0x9000 + i, 0x9100 + i, timestamp=1) for i in range(5))
    img.write(IMAGE_BASE + 0x1000, blob)

    pe = make_pe(directories={1: (0x1000, 100)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.truncation is not None
    assert result.truncation.scope == "iat_bytes_read"
    assert result.truncation.budget_limit == 20


def test_read_operations_budget_truncates_walk(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_READ_OPERATIONS", 2)

    img = FakeImage()
    blob = b"".join(descriptor(0, 0x9000 + i, 0x9100 + i, timestamp=1) for i in range(5))
    img.write(IMAGE_BASE + 0x1000, blob)

    pe = make_pe(directories={1: (0x1000, 100)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.truncation is not None
    assert result.truncation.scope == "iat_read_operations"
    assert result.truncation.budget_limit == 2


# ── overflow / bounds / cycles ────────────────────────────────────────────

def test_rva_arithmetic_overflow_is_bounded_not_wrapped():
    huge_base = 0xFFFFFFFFFFFFFFF0
    img = FakeImage()
    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(img.read, huge_base, pe)

    # image_base + import_directory_rva overflows a real 64-bit address --
    # the walk must refuse it, not silently wrap around.
    assert result.bounds_exceeded is True
    assert result.entries == ()


def test_duplicate_thunk_arrays_across_descriptors_flagged_as_cycle():
    img = FakeImage()
    shared_int, shared_iat = 0x5000, 0x5100
    d0_name, d1_name = 0x2000, 0x2100

    img.write(IMAGE_BASE + 0x1000,
              descriptor(shared_int, d0_name, shared_iat) + descriptor(shared_int, d1_name, shared_iat) + TERMINATOR)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))
    img.write(IMAGE_BASE + d1_name, cstr("B.dll"))
    img.write(IMAGE_BASE + shared_int, thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(0))
    img.write(IMAGE_BASE + shared_iat, thunk64(0x111) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 40)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.cycle_detected is True
    # The cycle is found DURING the second descriptor's thunk walk, but
    # its OWN name was already read before the cycle was hit -- dll_count
    # (descriptors the loop actually reached) is 2, while entry_count
    # (thunks successfully appended) stops at 1: the first descriptor's
    # single entry is captured; the second descriptor's identical thunk
    # array is recognized as already-visited and the walk stops there.
    assert result.dll_count == 2
    assert result.entry_count == 1


def test_cycle_detection_stops_the_entire_walk_not_just_one_descriptor():
    # A regression test for a real bug: cycle detection previously only
    # broke the CURRENT descriptor's thunk loop, so a THIRD descriptor
    # with perfectly legitimate, freshly-readable data would still be
    # walked and reported as if the table were trustworthy. Once a
    # repeated/looping address is found anywhere, nothing read
    # afterward -- including a later, otherwise-clean descriptor -- may
    # be reported.
    img = FakeImage()
    shared_int, shared_iat = 0x5000, 0x5100
    d0_name, d1_name, d2_name = 0x2000, 0x2100, 0x2200
    d2_int, d2_iat = 0x6000, 0x6100

    img.write(IMAGE_BASE + 0x1000,
              descriptor(shared_int, d0_name, shared_iat)
              + descriptor(shared_int, d1_name, shared_iat)   # triggers the cycle
              + descriptor(d2_int, d2_name, d2_iat)             # legitimate, must NOT be parsed
              + TERMINATOR)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))
    img.write(IMAGE_BASE + d1_name, cstr("B.dll"))
    img.write(IMAGE_BASE + shared_int, thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(0))
    img.write(IMAGE_BASE + shared_iat, thunk64(0x111) + thunk64(0))
    img.write(IMAGE_BASE + d2_name, cstr("LEGIT.dll"))
    img.write(IMAGE_BASE + d2_int, thunk64(IMAGE_ORDINAL_FLAG64 | 99) + thunk64(0))
    img.write(IMAGE_BASE + d2_iat, thunk64(0x999) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 60)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.cycle_detected is True
    assert result.dll_count == 2   # the third (legitimate) descriptor is never reached
    assert result.entry_count == 1
    assert not any(e.dll == "LEGIT.dll" or e.ordinal == 99 for e in result.entries)


def test_reader_returning_more_bytes_than_requested_never_raises():
    # A regression test for a real bug: struct.unpack() requires an
    # EXACT-width buffer, so a `read` callback that hands back more than
    # was asked for (a plausible bug in any real caller, or deliberately
    # adversarial) used to propagate a bare struct.error out of
    # parse_iat() the moment the oversized descriptor bytes reached
    # _DESCRIPTOR_STRUCT.unpack().
    def oversized_read(addr, size):
        return b"\xff" * (size + 100)

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(oversized_read, IMAGE_BASE, pe)   # must not raise
    # 0xff-filled bytes decode to a non-terminator descriptor whose
    # thunks are also never 0 -- the walk correctly runs until its own
    # per-descriptor cap, rather than raising partway through.
    assert result.entry_count > 0
    assert result.truncation is not None
    assert result.truncation.scope in ("iat_entries_per_dll", "iat_read_operations", "iat_bytes_read")


def test_reader_returning_non_bytes_like_never_raises():
    def stringy_read(addr, size):
        return "not bytes"   # bytes("not bytes") raises TypeError

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(stringy_read, IMAGE_BASE, pe)   # must not raise
    assert result.directory_read_failed is True
    assert result.entries == ()


def test_import_directory_walk_is_bounded_by_its_own_declared_size():
    # A regression test for a real bug: the descriptor walk previously
    # ignored the header's OWN declared import_directory_size entirely,
    # so a directory declared as only 20 bytes (room for exactly one
    # descriptor, no terminator) would still walk straight into whatever
    # adjacent memory followed it and report that as more imports.
    img = FakeImage()
    d0_name = 0x2000
    # A second, fully "well-formed-looking" descriptor sits immediately
    # after the first in memory -- but the declared Import Directory Size
    # (20 bytes) only has room for the FIRST one.
    img.write(IMAGE_BASE + 0x1000,
              descriptor(0, d0_name, 0) + descriptor(0, 0x9999, 0))
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))

    pe = make_pe(directories={1: (0x1000, 20)})   # Size == exactly one descriptor
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 1
    assert result.bounds_exceeded is True
    assert result.unterminated_table is True


def test_import_directory_size_never_reads_even_one_byte_past_it():
    # A regression test for a real bug: the declared-size bound used to
    # be checked AFTER the out-of-range descriptor was already read (a
    # "peek one slot past to confirm a legitimate terminator" approach,
    # copied from the MAX_IAT_DLLS cap). That is wrong for a header-
    # declared Size specifically: unlike MAX_IAT_DLLS (dumpex's own
    # arbitrary cap, where the peeked byte is still unambiguously part of
    # the same image), reading past import_directory_size at all means
    # reading memory the Import Directory never claimed. Here the
    # adjacent memory happens to be all zero -- exactly what a
    # peek-then-accept approach would misread as a legitimate terminator
    # and report as a clean, complete table. The read must never be
    # attempted at all.
    img = FakeImage()
    d0_name = 0x2000
    img.write(IMAGE_BASE + 0x1000, descriptor(0, d0_name, 0))   # one real descriptor
    img.write(IMAGE_BASE + 0x1014, b"\x00" * 20)                # looks like a terminator
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))

    pe = make_pe(directories={1: (0x1000, 20)})   # Size == exactly one descriptor
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 1
    assert result.bounds_exceeded is True
    assert result.unterminated_table is True
    # The zero-filled "terminator" must never have been read: the walk
    # stopped strictly at the declared boundary.
    assert all(addr != IMAGE_BASE + 0x1014 for addr, _size in img.read_log)


def test_import_directory_size_boundary_terminator_is_not_flagged():
    # A Size that genuinely accounts for the terminator's own slot (one
    # real descriptor + one terminator == 40 bytes) must not be falsely
    # reported as a bounds violation.
    img = FakeImage()
    d0_name = 0x2000
    img.write(IMAGE_BASE + 0x1000, descriptor(0, d0_name, 0) + TERMINATOR)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))

    pe = make_pe(directories={1: (0x1000, 40)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 1
    assert result.bounds_exceeded is False
    assert result.unterminated_table is False


def test_table_va_overflow_detected_even_when_import_walk_never_runs():
    # A regression test for a real bug: table_va/table_end (index 12,
    # the IAT directory) were computed with plain unchecked addition,
    # bypassing the overflow-checked _addr() helper entirely. When
    # import_directory_present is falsy the descriptor walk never runs
    # at all, so nothing downstream ever re-validated that arithmetic --
    # bounds_exceeded stayed False even though table_va/table_end were
    # not real 64-bit addresses.
    huge_base = 0xFFFFFFFFFFFFFFF0
    pe = make_pe(directories={1: (0, 0), 12: (0x1000, 0x100)})  # no imports, but IAT dir present
    result = parse_iat(lambda a, s: b"", huge_base, pe)

    assert result.import_directory_present is False
    assert result.table_present is True
    assert result.bounds_exceeded is True
    assert result.table_va is None
    assert result.table_size is None


def test_slot_in_bounds_does_not_crash_when_table_end_overflows_with_real_entries():
    # A regression test for a real bug: slot_in_bounds's guard checked
    # only `table_present` (a structural fact about the RVA being
    # nonzero -- §3.5.2), not whether table_va/table_end themselves
    # actually ended up usable. table_present can be True even when
    # table_va/table_end overflowed to None (see the table_va
    # construction above) -- when that happens alongside a real,
    # successfully-walked import entry, the old code executed
    # `None <= iat_slot_va < None` and raised TypeError.
    huge_base = 0xFFFFFFFFFFFF0000   # leaves just enough headroom below
                                      # UINT64_MAX for the import walk's
                                      # own small RVAs, but not enough
                                      # for the IAT directory's own huge
                                      # declared RVA below.
    int_rva, name_rva, first_thunk_rva = 0x1100, 0x1200, 0x1300

    img = FakeImage()
    img.write(huge_base + 0x1000, descriptor(int_rva, name_rva, first_thunk_rva) + TERMINATOR)
    img.write(huge_base + name_rva, cstr("A.dll"))
    img.write(huge_base + int_rva, thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(0))
    img.write(huge_base + first_thunk_rva, thunk64(0x999) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 40), 12: (0xFFFFFFFF, 0x100)})
    result = parse_iat(img.read, huge_base, pe)   # must not raise

    assert result.table_present is True
    assert result.table_va is None
    assert result.bounds_exceeded is True
    assert result.entry_count == 1
    assert result.entries[0].slot_in_bounds is None


def test_reader_returning_integer_is_rejected_not_coerced():
    # A regression test for a real bug: bytes(20) does NOT raise -- it
    # silently produces 20 zero bytes. A `read` callback that (by bug or
    # adversarially) returns a plain int used to be indistinguishable
    # from a genuine, successful all-zero read, which for the very first
    # descriptor reads as a well-formed terminator -- reporting "valid
    # PE, zero imports, complete" instead of "the reader is broken". A
    # large enough int would also make bytes(data) itself allocate an
    # unbounded buffer, defeating the read budget entirely.
    def integer_read(addr, size):
        return size   # e.g. 20 -- NOT bytes, but bytes(20) == b'\x00' * 20

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(integer_read, IMAGE_BASE, pe)   # must not raise
    assert result.directory_read_failed is True
    assert result.entries == ()


def test_reader_returning_released_memoryview_never_raises():
    # A regression test for a real bug: the isinstance(..., (bytes,
    # bytearray, memoryview)) check alone is not enough -- a memoryview
    # can pass that check while being unusable. Once a memoryview's
    # underlying buffer has been released(), essentially every operation
    # on it (including a bare bytes()/memoryview() call) raises
    # ValueError("operation forbidden on released memoryview object").
    # That conversion used to happen OUTSIDE _bounded_read()'s own
    # try/except, so this propagated straight out of parse_iat().
    def released_memoryview_read(addr, size):
        mv = memoryview(b"\x00" * size)
        mv.release()
        return mv

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(released_memoryview_read, IMAGE_BASE, pe)   # must not raise
    assert result.directory_read_failed is True
    assert result.entries == ()

    assert result.directory_read_failed is True
    assert result.entries == ()


def test_reader_that_always_raises_never_propagates():
    def angry_read(addr, size):
        raise RuntimeError("simulated unmapped page fault")

    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(angry_read, IMAGE_BASE, pe)
    assert result.directory_read_failed is True
    assert result.entries == ()


def test_import_present_but_no_image_base_read_capability_is_safe():
    # image_base itself is 0 -- a degenerate case a caller should never
    # pass (process_info.normalize_image_base() already refuses 0), but
    # parse_iat() must not crash on it either.
    pe = make_pe(directories={1: (0x1000, 20)})
    result = parse_iat(lambda a, s: b"", 0, pe)
    assert result.entries == ()


def test_dll_cap_boundary_exact_terminator_is_not_truncated(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_DLLS", 2)

    img = FakeImage()
    blob = descriptor(0, 0x9000, 0, timestamp=1) + descriptor(0, 0x9001, 0, timestamp=1) + TERMINATOR
    img.write(IMAGE_BASE + 0x1000, blob)
    img.write(IMAGE_BASE + 0x9000, cstr("A"))
    img.write(IMAGE_BASE + 0x9001, cstr("B"))

    pe = make_pe(directories={1: (0x1000, 60)})
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.dll_count == 2
    assert result.truncation is None
    assert result.unterminated_table is False


def test_entries_per_dll_boundary_exact_terminator_is_not_truncated(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_ENTRIES_PER_DLL", 2)

    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("A.dll"))
    # Exactly 2 real thunks, then the terminator -- sitting exactly at
    # the cap boundary.
    img.write(IMAGE_BASE + int_rva,
              thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(IMAGE_ORDINAL_FLAG64 | 2) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0x1) + thunk64(0x2) + thunk64(0))

    pe = make_pe(directories={1: (0x1000, 40)})   # one descriptor + terminator
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entry_count == 2
    assert result.truncation is None
    assert result.unterminated_table is False


def test_total_entries_boundary_exact_terminator_is_not_truncated(monkeypatch):
    import dumpex.core.pe_utils as pe_utils
    monkeypatch.setattr(pe_utils, "MAX_IAT_TOTAL_ENTRIES", 2)

    img = FakeImage()
    d0_int, d0_iat, d0_name = 0x3000, 0x3100, 0x3200
    d1_int, d1_iat, d1_name = 0x4000, 0x4100, 0x4200

    # d0 contributes exactly 2 entries (hitting the global cap exactly at
    # a clean per-descriptor terminator); d1 is itself immediately
    # terminated (0 entries) -- the whole table is legitimately complete
    # at exactly the cap and must not be reported as truncated.
    img.write(IMAGE_BASE + 0x1000,
              descriptor(d0_int, d0_name, d0_iat) + descriptor(d1_int, d1_name, d1_iat) + TERMINATOR)
    img.write(IMAGE_BASE + d0_name, cstr("A.dll"))
    img.write(IMAGE_BASE + d0_int,
              thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(IMAGE_ORDINAL_FLAG64 | 2) + thunk64(0))
    img.write(IMAGE_BASE + d0_iat, thunk64(0x1) + thunk64(0x2) + thunk64(0))
    img.write(IMAGE_BASE + d1_name, cstr("B.dll"))
    img.write(IMAGE_BASE + d1_int, thunk64(0))
    img.write(IMAGE_BASE + d1_iat, thunk64(0))

    pe = make_pe(directories={1: (0x1000, 60)})   # two descriptors + terminator
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.entry_count == 2
    assert result.dll_count == 2
    assert result.truncation is None
    assert result.unterminated_table is False


def test_import_present_true_table_present_null_reports_entries_without_bounds():
    # Import Directory (index 1) is captured and non-zero; the IAT
    # Directory (index 12) is declared (declared_directory_count > 12)
    # but its own bytes were never captured -- contract row "true | null":
    # entries ARE walked, but slot_in_bounds is null (undetermined, not a
    # diagnostic) and directory_table_incomplete fires instead.
    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("A.dll"))
    img.write(IMAGE_BASE + int_rva, thunk64(IMAGE_ORDINAL_FLAG64 | 1) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0x1) + thunk64(0))

    pe = {
        "data_directories": [(0, 0), (0x1000, 20)],   # only indices 0,1 captured
        "declared_directory_count": 16,                # but 16 were declared
        "is_pe32_plus": True,
    }
    result = parse_iat(img.read, IMAGE_BASE, pe)

    assert result.import_directory_present is True
    assert result.table_present is None
    assert result.directory_table_incomplete is True
    assert result.directory_incomplete_affected_count == 16 - 2
    assert result.entry_count == 1
    assert result.entries[0].slot_in_bounds is None
    assert result.table_va is None and result.table_size is None
    assert not any(d.code == "IAT_BOUNDS_CHECK_UNAVAILABLE" for d in result.diagnostics)


# ── relocated image base ──────────────────────────────────────────────────

def test_reads_use_the_actual_load_base_not_the_headers_declared_base():
    declared_base = 0x140000000
    actual_base = 0x7FF612340000   # ASLR-relocated load address

    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x2000, 0x2200, 0x2300
    img.write(actual_base + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(actual_base + dll_rva, cstr("RELOC.dll"))
    img.write(actual_base + int_rva, thunk64(IMAGE_ORDINAL_FLAG64 | 99) + thunk64(0))
    img.write(actual_base + iat_rva, thunk64(0x1234) + thunk64(0))
    # Nothing at all is mapped at the header's own declared preferred base.

    pe = make_pe(directories={1: (0x1000, 20)})
    pe["image_base"] = declared_base   # present in a real parse_pe_header() result; must be ignored
    result = parse_iat(img.read, actual_base, pe)

    assert result.entry_count == 1
    assert result.entries[0].dll == "RELOC.dll"
    assert result.entries[0].iat_slot_va == actual_base + iat_rva


# ── parse_pe_header() integration ─────────────────────────────────────────

def test_parse_pe_header_directory_fields():
    from tests.fixtures.fakes import build_pe_header, TEXT_SECTION_RX
    header = build_pe_header([TEXT_SECTION_RX])   # no explicit directories -> all zero
    result = parse_pe_header(header)
    assert result["valid"] is True
    assert result["declared_directory_count"] == 0
    assert result["directories_complete"] is True
    assert result["data_directories"] == []


def test_parse_pe_header_declared_directory_count_none_on_truncated_header():
    truncated = b"MZ" + b"\x00" * 0x3E  # not even e_lfanew is fully present
    result = parse_pe_header(truncated)
    assert result["valid"] is False
    assert result["declared_directory_count"] is None
    assert result["directories_complete"] is False


def test_end_to_end_via_parse_pe_header():
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, e_lfanew)
    buf = bytearray(dos) + b'PE\x00\x00'
    opt_hdr_size = 240
    buf += struct.pack('<HHIIIHH', 0x8664, 1, 0x11111111, 0, 0, opt_hdr_size, 0x0102)

    opt = bytearray(opt_hdr_size)
    struct.pack_into('<H', opt, 0, 0x20b)
    struct.pack_into('<I', opt, 16, 0x1000)
    struct.pack_into('<Q', opt, 24, IMAGE_BASE)
    struct.pack_into('<I', opt, 56, 0x10000)
    struct.pack_into('<I', opt, 108, 13)   # NumberOfRvaAndSizes
    struct.pack_into('<II', opt, 112 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, 0x1000, 40)
    struct.pack_into('<II', opt, 112 + IMAGE_DIRECTORY_ENTRY_IAT * 8, 0x1300, 16)
    buf += opt

    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    struct.pack_into('<IIII', section, 8, 0x1000, 0x1000, 0x1000, 0x400)
    buf += section

    pe = parse_pe_header(bytes(buf))
    assert pe["valid"] is True
    assert pe["declared_directory_count"] == 13
    assert pe["directories_complete"] is True

    img = FakeImage()
    dll_rva, int_rva, iat_rva = 0x1100, 0x1200, 0x1300
    img.write(IMAGE_BASE + 0x1000, descriptor(int_rva, dll_rva, iat_rva) + TERMINATOR)
    img.write(IMAGE_BASE + dll_rva, cstr("KERNEL32.dll"))
    img.write(IMAGE_BASE + int_rva, thunk64(IMAGE_ORDINAL_FLAG64 | 5) + thunk64(0))
    img.write(IMAGE_BASE + iat_rva, thunk64(0x999) + thunk64(0))

    result = parse_iat(img.read, IMAGE_BASE, pe)
    assert result.import_directory_present is True
    assert result.table_present is True
    assert result.entry_count == 1
    assert result.entries[0].slot_in_bounds is True
